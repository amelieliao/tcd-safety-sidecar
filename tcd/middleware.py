# FILE: tcd/middleware.py
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

from prometheus_client import Counter, Histogram
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


# --------------------------------
# Shared helpers
# --------------------------------


def _default_path_normalizer(path: str) -> str:
    """
    Best-effort path normalizer to keep label cardinality under control.
    """
    # Collapse UUID-like segments.
    p = re.sub(
        r"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[1-5][0-9a-fA-F]{3}\b-[89abAB][0-9a-fA-F]{3}\b-[0-9a-fA-F]{12}",
        ":uuid",
        path,
    )
    # Collapse long numeric IDs.
    p = re.sub(r"/\d{4,}", "/:id", p)
    return p


# --------------------------------
# Request context middleware
# --------------------------------


@dataclass
class RequestContextConfig:
    """
    Configuration for RequestContextMiddleware.

    This layer is responsible for assigning and propagating a request id
    and a session id. It avoids logging or exposing any payload data and
    can be tuned for different security profiles.
    """

    # Header names for request / session identifiers.
    request_id_header: str = "X-Request-Id"
    session_id_header: str = "X-Session-Id"
    # Header used to carry the multi-hop request chain.
    request_chain_header: str = "X-Request-Chain"
    # Cookie name used as a fallback for the session id.
    session_cookie_name: str = "sid"

    # Profile describing how strict the behavior should be.
    # Typical values: "DEV", "PROD", "HIGH_SECURITY".
    trust_profile: str = "PROD"

    # ID generation strategy.
    id_entropy_bits: int = 128
    id_length: int = 32  # number of hex characters
    # "uuid4" → use uuid.uuid4(); "prf" → use provided PRF.
    id_source: str = "uuid4"
    # Label used when invoking a PRF-based generator.
    id_namespace_label: str = "tcd/request"

    # Optional PRF for ID generation: fn(data_bytes, label) -> hex-string or bytes.
    prf: Optional[Callable[[bytes, str], Any]] = None

    # Upstream request-id trust.
    accept_upstream_request_id: bool = True
    # If non-empty, only IDs from these header names are considered as upstream IDs.
    upstream_request_id_header_whitelist: Tuple[str, ...] = ()
    # If True, upstream IDs are validated against id_format_regex; invalid ones are dropped.
    sanitize_upstream_ids: bool = True
    # Optional regex to constrain ID format (e.g. r"^[0-9a-f]{16,32}$").
    id_format_regex: Optional[str] = r"^[0-9a-fA-F]{8,64}$"

    # Session semantics.
    # Max lifetime for a session id; None disables TTL checks.
    session_ttl_seconds: Optional[float] = None
    # Whether to rotate session on sensitive paths.
    session_rotation_on_sensitive_action: bool = False
    # Paths considered sensitive for optional session rotation.
    sensitive_paths: Tuple[str, ...] = (r"^/admin", r"^/keys", r"^/config")
    # Preferred sources for session ids: "header", "cookie".
    session_source_priority: Tuple[str, ...] = ("header", "cookie")

    # Whether to attach IDs to request.state.
    attach_ids_to_state: bool = True
    # Whether to expose IDs to downstream responses as headers.
    expose_ids_to_downstream_headers: bool = True
    # If True, do not overwrite existing response header values.
    preserve_existing_response_header: bool = True


class RequestContextMiddleware(BaseHTTPMiddleware):
    """
    Injects a request id and session id and, optionally, a multi-hop
    request chain. IDs can be generated locally or derived via an
    injected PRF, and upstream IDs can be accepted or sanitized based
    on configuration.
    """

    def __init__(self, app, *, config: Optional[RequestContextConfig] = None):
        super().__init__(app)
        self._cfg = config or RequestContextConfig()
        self._id_pattern = (
            re.compile(self._cfg.id_format_regex) if self._cfg.id_format_regex else None
        )
        self._sensitive_path_re = [re.compile(p) for p in self._cfg.sensitive_paths]
        self._session_lock = threading.Lock()
        # session_id -> first_seen timestamp
        self._session_first_seen: Dict[str, float] = {}

    # ------- helpers -------

    def _generate_id(self, kind: str, request: Request, client_ip: str, path: str) -> str:
        """
        Generate a new identifier for the given kind ("request" or "session").
        """
        length = max(8, min(self._cfg.id_length, self._cfg.id_entropy_bits // 4 or self._cfg.id_length))
        if self._cfg.id_source == "prf" and self._cfg.prf is not None:
            seed = f"{time.time_ns()}:{client_ip}:{path}:{kind}".encode("utf-8")
            label = f"{self._cfg.id_namespace_label}/{kind}"
            raw = self._cfg.prf(seed, label)
            if isinstance(raw, bytes):
                s = raw.hex()
            else:
                s = str(raw)
        else:
            # Fallback: uuid4 hex.
            s = uuid.uuid4().hex
        s = s.replace("-", "")
        return s[:length]

    def _extract_upstream_id(self, request: Request) -> Tuple[Optional[str], bool]:
        """
        Optionally extract a request id provided by upstream components.
        Returns (id, trusted_flag).
        """
        if not self._cfg.accept_upstream_request_id:
            return None, False

        header_names: Tuple[str, ...]
        if self._cfg.upstream_request_id_header_whitelist:
            header_names = self._cfg.upstream_request_id_header_whitelist
        else:
            header_names = (self._cfg.request_id_header,)

        for name in header_names:
            v = request.headers.get(name) or request.headers.get(name.lower())
            if not v:
                continue
            v = v.strip()
            if not v:
                continue
            if self._cfg.sanitize_upstream_ids and self._id_pattern is not None:
                if not self._id_pattern.fullmatch(v):
                    return None, False
            return v[: self._cfg.id_length], True

        return None, False

    def _is_sensitive_path(self, path: str) -> bool:
        return any(p.search(path) for p in self._sensitive_path_re)

    def _apply_session_ttl(self, sid: str) -> Tuple[str, bool]:
        """
        Apply session TTL and rotate if expired. Returns (session_id, rotated_flag).
        """
        ttl = self._cfg.session_ttl_seconds
        if ttl is None or ttl <= 0:
            return sid, False
        now = time.time()
        rotated = False
        with self._session_lock:
            first = self._session_first_seen.get(sid)
            if first is None:
                self._session_first_seen[sid] = now
            else:
                if now - first > ttl:
                    # Mark expired and rotate.
                    self._session_first_seen.pop(sid, None)
                    rotated = True
        return sid, rotated

    async def dispatch(self, request: Request, call_next):
        h_req = self._cfg.request_id_header
        h_sess = self._cfg.session_id_header
        chain_header = self._cfg.request_chain_header

        client_ip = request.client.host if request.client else ""
        path = request.url.path

        # Upstream request id (optional).
        upstream_id, upstream_trusted = self._extract_upstream_id(request)
        if upstream_id is not None:
            rid = upstream_id
        else:
            rid = self._generate_id("request", request, client_ip, path)

        # Build or extend the request chain.
        upstream_chain = request.headers.get(chain_header) or ""
        if upstream_chain:
            chain = f"{upstream_chain},{rid}"
        else:
            chain = rid

        # Session id from configured sources.
        sid: Optional[str] = None
        for src in self._cfg.session_source_priority:
            v: Optional[str]
            if src == "header":
                v = request.headers.get(h_sess) or request.headers.get(h_sess.lower())
            elif src == "cookie":
                v = request.cookies.get(self._cfg.session_cookie_name)
            else:
                v = None
            if v:
                sid = v.strip()
                if sid:
                    break

        if not sid:
            sid = self._generate_id("session", request, client_ip, path)

        # Apply TTL and optional rotation on sensitive paths.
        sid, ttl_rotated = self._apply_session_ttl(sid)
        rotated = ttl_rotated
        if (
            not rotated
            and self._cfg.session_rotation_on_sensitive_action
            and self._is_sensitive_path(path)
        ):
            sid = self._generate_id("session", request, client_ip, path)
            with self._session_lock:
                self._session_first_seen[sid] = time.time()
            rotated = True

        # Attach to request.state for downstream components.
        if self._cfg.attach_ids_to_state:
            request.state.request_id = rid
            request.state.session_id = sid
            request.state.request_chain = chain
            request.state.session_rotated = rotated
            request.state.request_context = {
                "request_id": rid,
                "session_id": sid,
                "request_chain": chain,
                "trust_profile": self._cfg.trust_profile,
                "upstream_id_trusted": upstream_trusted,
            }

        response = await call_next(request)

        # Propagate as response headers; optionally preserve existing values.
        if self._cfg.expose_ids_to_downstream_headers:
            if rid is not None:
                if self._cfg.preserve_existing_response_header:
                    response.headers.setdefault(h_req, rid)
                else:
                    response.headers[h_req] = rid

            if sid is not None:
                if self._cfg.preserve_existing_response_header:
                    response.headers.setdefault(h_sess, sid)
                else:
                    response.headers[h_sess] = sid

            # Propagate chain as a header as well.
            if chain:
                if self._cfg.preserve_existing_response_header:
                    response.headers.setdefault(chain_header, chain)
                else:
                    response.headers[chain_header] = chain

        return response


# --------------------------------
# IP-level rate limit middleware
# --------------------------------


@dataclass
class RateLimitConfig:
    """
    Lightweight IP-level rate limiter.

    This is a best-effort guard, typically deployed at the outer edge or
    in development environments. For tenant-aware and policy-aware rate
    limiting, use the dedicated limiter in TCDRequestMiddleware.
    """

    rate_per_sec: float = 10.0
    burst: float = 20.0
    # Maximum number of IP buckets to retain.
    max_entries: int = 50_000
    # Idle buckets older than this many seconds may be evicted.
    idle_ttl_seconds: float = 10.0 * 60.0
    # Paths that skip this limiter (e.g. health and metrics).
    skip_paths: Tuple[str, ...] = (r"^/healthz$", r"^/metrics$", r"^/version$")
    # If True, the middleware emits a small JSON error body; otherwise a
    # plain text body is used.
    json_error: bool = True
    # Optional static reason string for responses.
    error_reason: str = "rate_limited"

    # Trust zones: name -> per-zone settings.
    # Example value:
    # {
    #   "default": {"rate_per_sec": 10.0, "burst": 20.0, "max_entries": 50000},
    #   "internal": {"rate_per_sec": 50.0, "burst": 100.0}
    # }
    trust_zones: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # Classifier: ip -> zone name.
    ip_trust_classifier: Optional[Callable[[str], str]] = None

    # Upstream address handling.
    respect_xff: bool = False
    trusted_proxies: Tuple[str, ...] = ()
    xff_depth_limit: int = 3

    # Audit / multivariate integration.
    emit_audit_log: bool = False
    audit_log_fn: Optional[Callable[[Dict[str, Any]], None]] = None
    link_to_multivar: bool = True

    # Temporary block when repeated denials occur.
    block_after_consecutive_denies: int = 0  # 0 = disabled
    temp_block_ttl_seconds: float = 60.0
    # Optional hard cap hook; currently not enforced here but kept for config completeness.
    max_tokens_per_ip_per_window: Optional[float] = None

    # Whether to expose simple rate-limit headers on errors.
    expose_headers: bool = False
    # If True and the trust profile is "HIGH_SECURITY", do not expose
    # detailed rate-limit information in headers.
    hide_details_in_high_security: bool = True


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token-bucket per IP. rate_per_sec tokens/sec, with burst bucket.

    This middleware implements an in-memory, best-effort guard layer. It
    is not a replacement for upstream gateways or distributed limiting.
    """

    def __init__(
        self,
        app,
        rate_per_sec: float = 10.0,
        burst: float = 20.0,
        *,
        config: Optional[RateLimitConfig] = None,
    ):
        super().__init__(app)
        if config is not None:
            self._cfg = config
            # Preserve backwards compatibility for legacy arguments if provided.
            if rate_per_sec is not None:
                self._cfg.rate_per_sec = float(rate_per_sec)
            if burst is not None:
                self._cfg.burst = float(burst)
        else:
            self._cfg = RateLimitConfig(rate_per_sec=rate_per_sec, burst=burst)

        self._rate = float(self._cfg.rate_per_sec)
        self._burst = float(self._cfg.burst)
        self._lock = threading.Lock()
        # Legacy single-level buckets (kept for compatibility, not used directly).
        self._buckets: Dict[str, Dict[str, float]] = {}
        # zone -> ip -> bucket_state
        self._zone_buckets: Dict[str, Dict[str, Dict[str, float]]] = {}
        # ip -> (consecutive_denies, last_ts)
        self._deny_counters: Dict[str, Tuple[int, float]] = {}
        # ip -> blocked_until_monotonic
        self._temp_blocks: Dict[str, float] = {}
        self._skip = [re.compile(p) for p in self._cfg.skip_paths]

    # ------- helpers -------

    def _path_match(self, path: str) -> bool:
        return any(p.search(path) for p in self._skip)

    def _zone_for_ip(self, ip: str) -> str:
        if self._cfg.ip_trust_classifier:
            try:
                zone = self._cfg.ip_trust_classifier(ip) or "default"
            except Exception:
                zone = "default"
            return zone
        return "default"

    def _ip_from_request(self, request: Request) -> str:
        """
        Determine client IP, optionally honoring X-Forwarded-For from
        trusted proxies.
        """
        ip = request.client.host if request.client else "unknown"
        if not self._cfg.respect_xff:
            return ip

        if ip not in self._cfg.trusted_proxies:
            return ip

        xff = request.headers.get("x-forwarded-for") or request.headers.get("X-Forwarded-For")
        if not xff:
            return ip

        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if not parts:
            return ip

        # Take the first address, up to the configured depth.
        depth = max(1, self._cfg.xff_depth_limit)
        return parts[min(len(parts) - 1, depth - 1)]

    def _get_zone_settings(self, zone: str) -> Tuple[float, float, int, float]:
        """
        Returns (rate_per_sec, burst, max_entries, idle_ttl) for a zone.
        """
        cfg = self._cfg.trust_zones.get(zone) or {}
        rate = float(cfg.get("rate_per_sec", self._cfg.rate_per_sec))
        burst = float(cfg.get("burst", self._cfg.burst))
        max_entries = int(cfg.get("max_entries", self._cfg.max_entries))
        idle_ttl = float(cfg.get("idle_ttl_seconds", self._cfg.idle_ttl_seconds))
        return rate, burst, max_entries, idle_ttl

    def _take(self, zone: str, key: str, tokens: float = 1.0) -> bool:
        now = time.monotonic()
        with self._lock:
            # Temporary block check.
            blocked_until = self._temp_blocks.get(key)
            if blocked_until is not None and now < blocked_until:
                return False

            rate, burst, max_entries, idle_ttl = self._get_zone_settings(zone)
            zone_map = self._zone_buckets.setdefault(zone, {})

            # Idle eviction for the zone.
            if len(zone_map) > max_entries:
                cutoff = now - idle_ttl
                for k, v in list(zone_map.items()):
                    if v.get("t", now) < cutoff:
                        zone_map.pop(k, None)

            b = zone_map.get(key)
            if not b:
                b = {"t": now, "tokens": burst}
            else:
                elapsed = max(0.0, now - b["t"])
                b["tokens"] = min(burst, b["tokens"] + elapsed * rate)
                b["t"] = now

            if b["tokens"] >= tokens:
                b["tokens"] -= tokens
                zone_map[key] = b
                # Reset deny counter on success.
                if key in self._deny_counters:
                    self._deny_counters.pop(key, None)
                return True

            zone_map[key] = b

            # Deny and possibly escalate to temporary block.
            c, last_ts = self._deny_counters.get(key, (0, now))
            if now - last_ts > self._cfg.temp_block_ttl_seconds:
                c = 0
            c += 1
            self._deny_counters[key] = (c, now)
            if (
                self._cfg.block_after_consecutive_denies > 0
                and c >= self._cfg.block_after_consecutive_denies
            ):
                self._temp_blocks[key] = now + self._cfg.temp_block_ttl_seconds

            return False

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if self._path_match(path):
            return await call_next(request)

        ip = self._ip_from_request(request)
        zone = self._zone_for_ip(ip)
        ok = self._take(zone, ip, 1.0)

        if ok:
            return await call_next(request)

        # Mark state for downstream detectors if requested.
        if self._cfg.link_to_multivar:
            try:
                request.state.edge_rate_limited = True
                request.state.edge_rate_zone = zone
            except Exception:
                pass

        # Audit log (best-effort).
        if self._cfg.emit_audit_log:
            try:
                rid = getattr(request.state, "request_id", None)
                sid = getattr(request.state, "session_id", None)
                audit_rec: Dict[str, Any] = {
                    "event": "edge_rate_limited",
                    "ip": ip,
                    "zone": zone,
                    "path": path,
                    "method": request.method,
                    "request_id": rid,
                    "session_id": sid,
                    "ts": time.time(),
                }
                if self._cfg.audit_log_fn is not None:
                    self._cfg.audit_log_fn(audit_rec)
            except Exception:
                pass

        # Build a minimal, structured error while avoiding any sensitive data.
        rid = getattr(request.state, "request_id", None)
        ctx = getattr(request.state, "request_context", None)
        trust_profile = None
        if isinstance(ctx, dict):
            trust_profile = ctx.get("trust_profile")

        headers: Dict[str, str] = {}
        if rid is not None:
            headers["X-Request-Id"] = str(rid)

        if self._cfg.expose_headers:
            # Optionally hide details when in the highest security profile.
            if not (
                self._cfg.hide_details_in_high_security
                and trust_profile == "HIGH_SECURITY"
            ):
                headers["X-RateLimit-Policy"] = "edge-ip"

        if self._cfg.json_error:
            body = {"error": self._cfg.error_reason}
            return Response(
                content=json.dumps(body),
                status_code=429,
                media_type="application/json",
                headers=headers,
            )

        return Response("rate limited", status_code=429, headers=headers)


# --------------------------------
# Metrics middleware
# --------------------------------


@dataclass
class MetricsConfig:
    """
    Metrics and logging configuration.

    This middleware is intentionally conservative: it records only
    high-level metadata (path, status, latency, identifiers) and avoids
    request payloads or sensitive fields.
    """

    counter: Counter
    histogram: Histogram
    # Optional path normalizer for label cardinality.
    path_normalizer: Callable[[str], str] = _default_path_normalizer
    # If True, also log a JSON line record to stdout (or log_fn).
    enable_json_log: bool = True
    # Optional function for emitting structured logs; defaults to print().
    log_fn: Optional[Callable[[str], None]] = None
    # Optional mapping of special-case path suffixes to logical route names.
    route_aliases: Dict[str, str] = field(default_factory=lambda: {"/diagnose": "diagnose"})
    # Logging levels to use.
    error_level: str = "error"
    ok_level: str = "info"

    # Field policy: name -> "required" | "optional" | "forbid".
    field_policy: Dict[str, str] = field(
        default_factory=lambda: {
            "path": "required",
            "method": "required",
            "client_ip": "forbid",
            "tenant": "optional",
        }
    )
    # Compliance profile for log shaping: "GENERIC", "FINREG", "HIGH_SECURITY".
    compliance_profile: str = "GENERIC"

    # Identifier inclusion controls.
    include_request_ids: bool = True
    include_chain_ids: bool = False
    link_to_receipt_id: bool = True

    # Header and query fields that must never be logged verbatim.
    forbidden_headers: Tuple[str, ...] = ("authorization", "cookie", "set-cookie")
    forbidden_query_params: Tuple[str, ...] = ()

    # Hashing controls for sensitive identifiers.
    include_client_ip_hash: bool = False
    include_tenant_hash: bool = False
    ip_hash_salt_label: str = "metrics/ip"
    tenant_hash_salt_label: str = "metrics/tenant"
    # Hash function: fn(value, label) -> hex-string.
    hash_fn: Optional[Callable[[str, str], str]] = None


class MetricsMiddleware(BaseHTTPMiddleware):
    """
    Prometheus counter + histogram + JSONL structured log.

    Metrics:
      - Counter:   tcd_requests_total{route, status}
      - Histogram: tcd_request_latency_seconds{route}

    Logging:
      - One JSON line per request with coarse-grained metadata.
    """

    def __init__(
        self,
        app,
        counter: Counter,
        histogram: Histogram,
        *,
        config: Optional[MetricsConfig] = None,
    ):
        if config is None:
            cfg = MetricsConfig(counter=counter, histogram=histogram)
        else:
            # Ensure provided counter/histogram are used even if config
            # was constructed externally.
            config.counter = counter
            config.histogram = histogram
            cfg = config

        super().__init__(app)
        self._cfg = cfg
        self.counter = cfg.counter
        self.hist = cfg.histogram
        self._log_fn = cfg.log_fn or print

    # ------- helpers -------

    def _route_label(self, path: str) -> str:
        for suffix, alias in self._cfg.route_aliases.items():
            if path.endswith(suffix):
                return alias
        return self._cfg.path_normalizer(path)

    def _field_policy(self, name: str) -> str:
        """
        Resolve the effective policy for a field, taking into account the
        compliance profile.
        """
        pol = self._cfg.field_policy.get(name, "optional")
        if self._cfg.compliance_profile == "HIGH_SECURITY" and pol != "required":
            return "forbid"
        return pol

    def _hash_value(self, value: str, label: str) -> str:
        """
        Hash a value with a label. Uses the configured hash_fn if present,
        otherwise falls back to SHA-256.
        """
        if self._cfg.hash_fn is not None:
            try:
                h = self._cfg.hash_fn(value, label)
                if isinstance(h, bytes):
                    return h.hex()
                return str(h)
            except Exception:
                pass
        # Fallback: SHA-256 of (label || value).
        m = hashlib.sha256()
        m.update(label.encode("utf-8"))
        m.update(b":")
        m.update(value.encode("utf-8"))
        return m.hexdigest()

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        route_label = self._route_label(path)
        t0 = time.perf_counter()
        status_label = "ok"
        status_code: Optional[int] = None

        try:
            response = await call_next(request)
            status_code = int(response.status_code)
            status_label = "ok" if 200 <= status_code < 400 else "err"
            return response
        except Exception:
            status_label = "err"
            # Let upstream exception handlers produce the response; we still
            # record metrics and logs in the finally block.
            raise
        finally:
            dt = time.perf_counter() - t0
            # Prometheus metrics (best-effort).
            try:
                self.counter.labels(route=route_label, status=status_label).inc()
                self.hist.labels(route=route_label).observe(dt)
            except Exception:
                # Metrics failures must not affect request handling.
                pass

            if not self._cfg.enable_json_log:
                return

            # JSONL structured log: avoid payloads or sensitive details.
            try:
                # Basic fields.
                rec: Dict[str, Any] = {
                    "level": self._cfg.ok_level if status_label == "ok" else self._cfg.error_level,
                    "ts_wall": time.time(),
                    "ts_mono_offset": round(dt, 6),
                    "route": route_label,
                    "status": status_label,
                    "latency_ms": round(dt * 1000.0, 3),
                }

                # Method and path (subject to policy).
                if self._field_policy("method") != "forbid":
                    rec["method"] = request.method
                if self._field_policy("path") != "forbid":
                    rec["path"] = path

                # Request / session / chain / receipt ids.
                if self._cfg.include_request_ids:
                    rid = getattr(request.state, "request_id", None)
                    sid = getattr(request.state, "session_id", None)
                    if rid is not None:
                        rec["request_id"] = rid
                    if sid is not None:
                        rec["session_id"] = sid
                if self._cfg.include_chain_ids:
                    chain = getattr(request.state, "request_chain", None)
                    if chain is not None:
                        rec["request_chain"] = chain
                if self._cfg.link_to_receipt_id:
                    receipt_id = getattr(request.state, "receipt_id", None)
                    if receipt_id is not None:
                        rec["receipt_id"] = receipt_id

                # Client IP hashing.
                client_ip = request.client.host if request.client else None
                client_ip_policy = self._field_policy("client_ip")
                if client_ip:
                    if (
                        client_ip_policy != "forbid"
                        and self._cfg.include_client_ip_hash
                    ):
                        rec["client_ip_hash"] = self._hash_value(
                            client_ip, self._cfg.ip_hash_salt_label
                        )
                    elif client_ip_policy == "required":
                        rec["client_ip"] = client_ip

                # Tenant hashing (if present on state).
                ctx = getattr(request.state, "tcd_ctx", None)
                tenant = ctx.get("tenant") if isinstance(ctx, dict) else None
                tenant_policy = self._field_policy("tenant")
                if tenant:
                    if (
                        tenant_policy != "forbid"
                        and self._cfg.include_tenant_hash
                    ):
                        rec["tenant_hash"] = self._hash_value(
                            str(tenant), self._cfg.tenant_hash_salt_label
                        )
                    elif tenant_policy == "required":
                        rec["tenant"] = tenant

                # Optional multivariate detector outputs.
                mv_verdict = getattr(request.state, "multivar_verdict", None)
                mv_risk = getattr(request.state, "multivar_risk_score", None)
                if mv_verdict is not None:
                    rec["multivar_verdict"] = mv_verdict
                if mv_risk is not None:
                    rec["multivar_risk_score"] = mv_risk

                # Simple error tag if available.
                if status_label == "err":
                    err_tag = getattr(request.state, "error_tag", None)
                    if err_tag is not None:
                        rec["error_tag"] = err_tag

                line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
                self._log_fn(line)
            except Exception:
                # Logging failures should not interfere with the main flow.
                pass