# FILE: tcd/middleware_request.py
from __future__ import annotations

import asyncio
import hmac
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Tuple, Mapping

from blake3 import blake3
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .policies import BoundPolicy, PolicyStore
from .ratelimit import RateLimiter

# Optional: reuse unified authenticator (HMAC v1 + skew window + replay resistance)
try:
    from .auth import Authenticator, build_authenticator_from_env, AuthResult  # type: ignore
    _HAS_AUTH = True
except Exception:  # pragma: no cover
    _HAS_AUTH = False


_logger = logging.getLogger(__name__)


# -------------------------
# Config & utilities
# -------------------------

@dataclass
class RequestAuthConfig:
    # Prefer the unified authenticator when available (recommended in production).
    use_authenticator: bool = True
    # Lightweight fallbacks (kept for compatibility when authenticator is off).
    enable_bearer: bool = False
    enable_hmac: bool = False
    bearer_token_env: str = "TCD_BEARER_TOKEN"
    hmac_secret_env: str = "TCD_HMAC_SECRET"
    # Fallback HMAC header (the unified authenticator uses X-TCD-Signature / X-TCD-Key-Id).
    signature_header: str = "X-TCD-Signature"
    # Paths that skip auth (health/metrics).
    auth_skip_paths: Tuple[str, ...] = (r"^/healthz$", r"^/metrics$", r"^/version$")


@dataclass
class RequestLimitConfig:
    # Soft cap when Content-Length is present.
    max_body_bytes: int = 1_000_000
    # Hard cap when Content-Length is missing or untrusted (streamed read).
    hard_read_cap_bytes: int = 2_000_000
    # Per-(tenant,user,session) token bucket.
    rl_capacity: float = 120.0
    rl_refill_per_s: float = 60.0
    # Default token cost divisor; policy may override.
    token_cost_divisor_default: float = 50.0
    # Optionally emit X-RateLimit-* response headers (best effort).
    emit_rate_headers: bool = True
    # Paths that skip rate limiting.
    rate_skip_paths: Tuple[str, ...] = (r"^/healthz$", r"^/metrics$", r"^/version$")


@dataclass
class IdempotencyConfig:
    enable: bool = True
    header: str = "Idempotency-Key"
    ttl_seconds: float = 15.0 * 60.0
    max_entries: int = 50_000
    # Cache only 2xx responses.
    store_only_2xx: bool = True
    # Avoid unbounded memory growth.
    max_store_bytes: int = 256_000
    # Include these headers in the key (to separate Accept/Content-Type variants).
    vary_on_headers: Tuple[str, ...] = ("accept", "content-type")
    # Paths that skip idempotency.
    skip_paths: Tuple[str, ...] = (r"^/verify$", r"^/metrics$", r"^/healthz$")


@dataclass
class PolicyBindConfig:
    # Header names to derive context; JSON body used as a fallback.
    h_tenant: str = "X-Tenant"
    h_user: str = "X-User"
    h_session: str = "X-Session"
    h_model: str = "X-Model-Id"
    h_gpu: str = "X-Gpu-Id"
    h_task: str = "X-Task"
    h_lang: str = "X-Lang"
    # Skip binding for these paths.
    bind_skip_paths: Tuple[str, ...] = (r"^/metrics$", r"^/healthz$", r"^/version$")


@dataclass
class MetricsConfig:
    # Histogram buckets in seconds.
    latency_buckets: Tuple[float, ...] = (0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2)
    enable: bool = True
    # Path normalizer to control label cardinality.
    path_normalizer: Callable[[str], str] = None  # injected later


@dataclass
class SecurityConfig:
    """
    High-level security profile configuration.

    This does not implement cryptography itself; it only controls how the
    middleware behaves in higher-security deployments.

    - profile:
        "DEV", "PROD", "HIGH_SEC" or other caller-defined profile names.
    - require_authenticator:
        If True, the unified Authenticator must be present; otherwise
        fallback auth logic is treated as a failure.
    - forbid_legacy_auth:
        If True, legacy Bearer/HMAC flows are not allowed even if configured.
    - idempotency_disallowed_classes:
        Classifications for which idempotency cache must not be used.
    - high_cost_classes:
        Classifications that apply a higher cost factor in rate limiting.
    """

    profile: str = "DEV"
    require_authenticator: bool = False
    forbid_legacy_auth: bool = False
    idempotency_disallowed_classes: Tuple[str, ...] = ("sensitive", "secret")
    high_cost_classes: Tuple[str, ...] = ("sensitive", "secret")


def _default_normalizer(path: str) -> str:
    # Replace UUIDs and long numeric IDs to reduce cardinality.
    p = re.sub(
        r"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[1-5][0-9a-fA-F]{3}\b-[89abAB][0-9a-fA-F]{3}\b-[0-9a-fA-F]{12}",
        ":uuid",
        path,
    )
    p = re.sub(r"/\d{4,}", "/:id", p)
    return p


# -------------------------
# Idempotency cache (in-memory, TTL, LRU)
# -------------------------

class _IdemCache:
    def __init__(self, ttl: float, max_entries: int):
        from collections import OrderedDict
        import threading

        self._ttl = float(ttl)
        self._max = int(max_entries)
        self._data: "OrderedDict[str, Tuple[float, int, Dict[str, str], bytes]]" = OrderedDict()
        self._g = threading.RLock()

    def _evict(self, now: float) -> None:
        keys = list(self._data.keys())
        for k in keys:
            ts, *_ = self._data.get(k, (0.0, 0, {}, b""))
            if now - ts > self._ttl:
                self._data.pop(k, None)
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    def get(self, key: str) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        now = time.time()
        with self._g:
            self._evict(now)
            v = self._data.get(key)
            if not v:
                return None
            ts, code, headers, body = v
            # LRU touch
            self._data.pop(key, None)
            self._data[key] = (ts, code, headers, body)
            return code, headers, body

    def set(self, key: str, code: int, headers: Dict[str, str], body: bytes) -> None:
        now = time.time()
        with self._g:
            self._evict(now)
            self._data[key] = (now, int(code), dict(headers), bytes(body))


# -------------------------
# Prometheus metrics (lazy)
# -------------------------

class _Metrics:
    def __init__(self, cfg: MetricsConfig):
        self.enabled = bool(cfg.enable)
        if not self.enabled:
            # No-op placeholders
            self.req_ctr = self.req_reject = self.req_bytes = self.resp_bytes = None
            self.latency = self.idem_ctr = self.rate_block = self.auth_sig = None
            self.auth_sig_fail_reason = None
            self.req_sec = None
            return
        from prometheus_client import Counter, Histogram, Gauge, REGISTRY

        self._reg = REGISTRY

        self.req_ctr = Counter(
            "tcd_http_requests_total", "HTTP requests", ["method", "path", "code"], registry=self._reg
        )
        self.req_reject = Counter(
            "tcd_http_reject_total", "Rejected requests", ["reason", "path"], registry=self._reg
        )
        self.req_bytes = Counter(
            "tcd_http_request_bytes_total", "Request bytes", ["method", "path"], registry=self._reg
        )
        self.resp_bytes = Counter(
            "tcd_http_response_bytes_total", "Response bytes", ["method", "path", "code"], registry=self._reg
        )
        self.latency = Histogram(
            "tcd_http_latency_seconds", "End-to-end request latency", buckets=cfg.latency_buckets, registry=self._reg
        )
        self.idem_ctr = Counter(
            "tcd_http_idempotency_total", "Idempotency outcomes", ["status", "path"], registry=self._reg
        )
        self.rate_block = Counter(
            "tcd_http_rate_limit_total", "Rate-limit blocks", ["path"], registry=self._reg
        )
        self.auth_sig = Counter(
            "tcd_http_signature_total", "Signature verification", ["status", "path"], registry=self._reg
        )
        self.auth_sig_fail_reason = Counter(
            "tcd_http_signature_fail_total", "Signature failures", ["reason", "path"], registry=self._reg
        )
        self.req_sec = Counter(
            "tcd_http_requests_security_total",
            "HTTP requests by coarse security level",
            ["sec_level", "path"],
            registry=self._reg,
        )


# -------------------------
# Middleware
# -------------------------

@dataclass
class TCDRequestMiddlewareConfig:
    auth: RequestAuthConfig = field(default_factory=RequestAuthConfig)
    limits: RequestLimitConfig = field(default_factory=RequestLimitConfig)
    idempotency: IdempotencyConfig = field(default_factory=IdempotencyConfig)
    policies: PolicyBindConfig = field(default_factory=PolicyBindConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    # Paths that fully bypass this middleware (early return).
    bypass_paths: Tuple[str, ...] = (r"^/metrics$",)
    # Response header to propagate a request id.
    request_id_header: str = "X-Request-Id"


class TCDRequestMiddleware(BaseHTTPMiddleware):
    """
    Request middleware that provides:
      - Optional unified Authenticator (preferred), or simple Bearer/HMAC fallback
      - Body size limits with hard cap when Content-Length is missing
      - Idempotency-Key caching for POST/PUT/PATCH (with safety guards)
      - Policy binding to request.state.tcd_policy and derived ctx
      - Per-tenant rate limiting
      - Prometheus metrics with path normalization
      - Request-id propagation
      - Light-weight security context propagation for downstream logic
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        cfg: Optional[TCDRequestMiddlewareConfig] = None,
        policy_store: Optional[PolicyStore] = None,
        rate_limiter: Optional[RateLimiter] = None,
        authenticator: Optional[Authenticator] = None,
    ):
        super().__init__(app)
        self._cfg = cfg or TCDRequestMiddlewareConfig()
        if self._cfg.metrics.path_normalizer is None:
            self._cfg.metrics.path_normalizer = _default_normalizer
        self._metrics = _Metrics(self._cfg.metrics)
        self._store = policy_store
        self._rl = rate_limiter or RateLimiter(
            capacity=self._cfg.limits.rl_capacity,
            refill_per_s=self._cfg.limits.rl_refill_per_s,
        )
        # Authenticator wiring (optional)
        self._authenticator: Optional[Authenticator] = None
        if self._cfg.auth.use_authenticator and _HAS_AUTH:
            self._authenticator = authenticator or build_authenticator_from_env()
        if self._cfg.security.require_authenticator and self._authenticator is None:
            _logger.warning(
                "Security profile requires authenticator, but no Authenticator is available. "
                "All requests will be treated as unauthenticated."
            )

        self._idem = _IdemCache(self._cfg.idempotency.ttl_seconds, self._cfg.idempotency.max_entries)

        # Precompile regexes
        self._skip_auth = [re.compile(p) for p in self._cfg.auth.auth_skip_paths]
        self._skip_rate = [re.compile(p) for p in self._cfg.limits.rate_skip_paths]
        self._skip_bind = [re.compile(p) for p in self._cfg.policies.bind_skip_paths]
        self._bypass = [re.compile(p) for p in self._cfg.bypass_paths]
        self._skip_idem = [re.compile(p) for p in self._cfg.idempotency.skip_paths]

    # ------------- helpers -------------

    def _path_match(self, path: str, pats: Iterable[re.Pattern]) -> bool:
        return any(p.search(path) for p in pats)

    def _derive_classification(self, req: Request) -> str:
        """
        Derive a coarse classification label from security context or headers.

        This is intentionally simple and non-binding; it is used only for
        routing decisions inside this middleware (e.g. idempotency eligibility).
        """
        # Prefer security_ctx.classification if available.
        try:
            sec_ctx = getattr(req.state, "security_ctx", None)
        except Exception:
            sec_ctx = None
        if isinstance(sec_ctx, Mapping):
            val = sec_ctx.get("classification") or sec_ctx.get("class") or sec_ctx.get("level")
            if isinstance(val, str) and val.strip():
                return val.strip()

        # Fallback: header, if caller wants to hint classification.
        h_val = (req.headers.get("X-Classification") or "").strip()
        if h_val:
            return h_val

        return "unclassified"

    def _coarse_security_level(self, classification: str) -> str:
        """
        Map fine-grained classification strings to a coarse security level.

        Used only for metrics labeling and local decisions; it is not a
        formal access-control mechanism.
        """
        if not classification:
            return "public"
        v = classification.lower()
        if v in ("sensitive", "secret", "high", "critical", "restricted"):
            return "restricted"
        if v in ("internal", "confidential", "medium"):
            return "internal"
        return "public"

    def _should_use_idempotency(self, classification: str) -> bool:
        """
        Decide whether idempotency caching is allowed under the given classification.
        """
        deny = tuple(x.lower() for x in self._cfg.security.idempotency_disallowed_classes)
        if not classification:
            return True
        return classification.lower() not in deny

    def _filter_idem_headers(self, headers: List[Tuple[bytes, bytes]]) -> Dict[str, str]:
        """
        Filter response headers before storing in idempotency cache.

        This removes headers that may carry credentials or other sensitive
        values, keeping only a minimal, safe subset.
        """
        deny = {
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
            "x-internal-token",
            "x-internal-auth",
        }
        try:
            deny.add(self._cfg.auth.signature_header.lower())
        except Exception:
            pass

        safe: Dict[str, str] = {}
        for k_b, v_b in headers:
            try:
                k = k_b.decode().lower()
                v = v_b.decode()
            except Exception:
                continue
            if k in deny:
                continue
            safe[k] = v
        return safe

    async def _auth_ok(self, req: Request, raw_body: bytes, norm_path: str) -> bool:
        # Skip auth if path matches allowlist.
        if self._path_match(req.url.path, self._skip_auth):
            # Ensure there is at least a default security context object for downstream.
            try:
                if not hasattr(req.state, "security_ctx"):
                    req.state.security_ctx = {}
            except Exception:
                pass
            return True

        # If security profile requires authenticator but none is available, fail early.
        if self._cfg.security.require_authenticator and self._authenticator is None:
            if self._metrics.enabled:
                self._metrics.auth_sig.labels("fail", norm_path).inc()
                if self._metrics.auth_sig_fail_reason:
                    self._metrics.auth_sig_fail_reason.labels("authenticator_missing", norm_path).inc()
            _logger.error("Authenticator required by security profile, but not configured.")
            return False

        # Preferred: unified authenticator
        if self._authenticator is not None:
            res: AuthResult = await self._authenticator.verify(req)
            ok = bool(res.ok and res.ctx)
            sec_ctx: Dict[str, Any] = {}
            raw_ctx = getattr(res, "ctx", None)
            if isinstance(raw_ctx, Mapping):
                sec_ctx = dict(raw_ctx)
            elif raw_ctx is not None:
                sec_ctx = {"raw": raw_ctx}
            try:
                req.state.security_ctx = sec_ctx
            except Exception:
                _logger.debug("Failed to attach security_ctx to request.state", exc_info=True)

            if self._metrics.enabled:
                self._metrics.auth_sig.labels("ok" if ok else "fail", norm_path).inc()
                if not ok and self._metrics.auth_sig_fail_reason:
                    reason = (getattr(res, "reason", None) or "denied").lower()
                    self._metrics.auth_sig_fail_reason.labels(reason, norm_path).inc()
            return ok

        # If legacy auth is forbidden under current security profile, deny.
        if self._cfg.security.forbid_legacy_auth:
            if self._metrics.enabled:
                self._metrics.auth_sig.labels("fail", norm_path).inc()
                if self._metrics.auth_sig_fail_reason:
                    self._metrics.auth_sig_fail_reason.labels("legacy_auth_forbidden", norm_path).inc()
            _logger.warning("Legacy auth is forbidden by security profile, but no Authenticator is configured.")
            return False

        # Fallback: Bearer/HMAC (basic)
        if not (self._cfg.auth.enable_bearer or self._cfg.auth.enable_hmac):
            # No auth configured: treat as anonymous / public.
            try:
                if not hasattr(req.state, "security_ctx"):
                    req.state.security_ctx = {"authn_method": "none", "classification": "unclassified"}
            except Exception:
                pass
            return True

        ok = True
        reason = None
        authn_method = "legacy"

        if self._cfg.auth.enable_bearer:
            want = (os.getenv(self._cfg.auth.bearer_token_env) or "").strip()
            have = (req.headers.get("authorization") or "").strip()
            if want:
                if not have.lower().startswith("bearer "):
                    ok = False
                    reason = "missing_bearer"
                else:
                    token = have[7:].strip()
                    if not hmac.compare_digest(token, want):
                        ok = False
                        reason = "bearer_mismatch"
                authn_method = "bearer"
            # If want is empty, bearer is effectively disabled.

        if ok and self._cfg.auth.enable_hmac:
            secret = os.getenv(self._cfg.auth.hmac_secret_env)
            sig_hex = req.headers.get(self._cfg.auth.signature_header, "")
            if secret:
                msg = f"{req.method}\n{req.url.path}\n".encode("utf-8") + raw_body
                calc = hmac.new(secret.encode("utf-8"), msg, "sha256").hexdigest()
                if not hmac.compare_digest(calc, sig_hex):
                    ok = False
                    reason = "hmac_mismatch"
                authn_method = "hmac"

        if ok:
            # Attach a minimal security context for downstream usage.
            try:
                req.state.security_ctx = {"authn_method": authn_method, "classification": "unclassified"}
            except Exception:
                _logger.debug("Failed to attach security_ctx for legacy auth", exc_info=True)

        if self._metrics.enabled:
            self._metrics.auth_sig.labels("ok" if ok else "fail", norm_path).inc()
            if not ok and self._metrics.auth_sig_fail_reason:
                self._metrics.auth_sig_fail_reason.labels(reason or "denied", norm_path).inc()
        return ok

    async def _read_body_with_limit(self, req: Request) -> bytes:
        # If Content-Length is present, enforce soft cap.
        cl = req.headers.get("content-length")
        if cl is not None:
            try:
                n = int(cl)
            except Exception:
                n = -1
            if n < 0 or n > self._cfg.limits.max_body_bytes:
                raise _Reject(413, "payload too large")
            body = await req.body()
            # Double-check actual size (in case of wrong Content-Length).
            if len(body) > self._cfg.limits.max_body_bytes:
                raise _Reject(413, "payload too large")
            return body

        # No Content-Length: stream with a hard cap.
        chunks: List[bytes] = []
        total = 0
        async for chunk in req.stream():
            if not chunk:
                continue
            chunks.append(bytes(chunk))
            total += len(chunk)
            if total > self._cfg.limits.hard_read_cap_bytes:
                raise _Reject(413, "payload too large")
        return b"".join(chunks)

    def _extract_ctx(self, req: Request, body_json: Optional[Dict[str, Any]]) -> Dict[str, str]:
        h = req.headers
        ctx = {
            "tenant": h.get(self._cfg.policies.h_tenant) or (body_json or {}).get("tenant") or "*",
            "user": h.get(self._cfg.policies.h_user) or (body_json or {}).get("user") or "*",
            "session": h.get(self._cfg.policies.h_session) or (body_json or {}).get("session") or "*",
            "model_id": h.get(self._cfg.policies.h_model) or (body_json or {}).get("model_id") or "*",
            "gpu_id": h.get(self._cfg.policies.h_gpu) or (body_json or {}).get("gpu_id") or "*",
            "task": h.get(self._cfg.policies.h_task) or (body_json or {}).get("task") or "*",
            "lang": h.get(self._cfg.policies.h_lang) or (body_json or {}).get("lang") or "*",
        }
        return {k: (str(v) if v is not None else "*") for k, v in ctx.items()}

    def _rate_check(
        self,
        ctx: Dict[str, str],
        body_json: Optional[Dict[str, Any]],
        norm_path: str,
    ) -> Tuple[bool, Optional[float], Optional[float]]:
        if self._path_match(ctx.get("_path", ""), self._skip_rate):
            return True, None, None
        # Token cost from tokens_delta if present; else 1.
        tokens_delta = 1.0
        if isinstance(body_json, dict) and "tokens_delta" in body_json:
            try:
                tokens_delta = float(body_json["tokens_delta"])
            except Exception:
                tokens_delta = 1.0
        divisor = float(ctx.get("_token_cost_divisor", self._cfg.limits.token_cost_divisor_default))
        cost = max(1.0, tokens_delta / max(1.0, divisor))

        # Optional: adjust cost based on classification for stricter environments.
        cls_name = (ctx.get("_classification") or "").lower()
        try:
            high_cost = tuple(x.lower() for x in self._cfg.security.high_cost_classes)
        except Exception:
            high_cost = ()
        if cls_name and cls_name in high_cost:
            cost = max(1.0, cost * 2.0)

        key = (ctx.get("tenant", "*"), ctx.get("user", "*"), ctx.get("session", "*"))

        # Best-effort introspection of remaining tokens (optional).
        remaining_before: Optional[float] = None
        capacity: Optional[float] = None
        if hasattr(self._rl, "peek"):
            try:
                remaining_before = float(self._rl.peek(key))  # type: ignore[attr-defined]
            except Exception:
                remaining_before = None
        if hasattr(self._rl, "capacity"):
            try:
                capacity = float(getattr(self._rl, "capacity"))
            except Exception:
                capacity = None

        ok = self._rl.consume(key, cost=cost)
        if not ok and self._metrics.enabled:
            self._metrics.rate_block.labels(norm_path).inc()
        return ok, remaining_before, capacity

    def _hash_body(self, b: bytes) -> str:
        return blake3(b).hexdigest()

    def _idem_key(self, req: Request, norm_path: str, idem_val: str, body_hash: str) -> str:
        vary_parts = []
        for hname in self._cfg.idempotency.vary_on_headers:
            v = (req.headers.get(hname) or req.headers.get(hname.title()) or "").strip().lower()
            vary_parts.append(f"{hname}={v}")
        base = f"{req.method}:{norm_path}:{idem_val}:{';'.join(vary_parts)}:{body_hash}"
        return blake3(base.encode("utf-8")).hexdigest()

    @staticmethod
    def _ensure_request_id(request: Request, header: str) -> str:
        rid = request.headers.get(header) or request.headers.get(header.lower()) or ""
        if not rid:
            # short stable id
            rid = blake3(f"{time.time_ns()}:{id(request)}".encode("utf-8")).hexdigest()[:16]
        return rid

    # ------------- dispatch -------------

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        path = request.url.path
        if self._path_match(path, self._bypass):
            return await call_next(request)

        t0 = time.perf_counter()
        norm_path = self._cfg.metrics.path_normalizer(path)
        raw_body = b""
        body_json: Optional[Dict[str, Any]] = None
        bound: Optional[BoundPolicy] = None
        req_id_header = self._cfg.request_id_header
        req_id = self._ensure_request_id(request, req_id_header)
        classification = "unclassified"
        sec_level = "public"

        try:
            # Body read with limits; then re-attach downstream.
            raw_body = await self._read_body_with_limit(request)
            if raw_body:
                try:
                    body_json = json.loads(raw_body.decode("utf-8"))
                    # Canonicalize to compact JSON for signature & idempotency stability.
                    raw_body = json.dumps(body_json, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                except Exception:
                    body_json = None

            # Auth
            if not await self._auth_ok(request, raw_body, norm_path):
                raise _Reject(403, "forbidden")

            # Derive classification & coarse security level from security context.
            classification = self._derive_classification(request)
            sec_level = self._coarse_security_level(classification)

            # Policy bind
            if self._store and not self._path_match(path, self._skip_bind):
                ctx = self._extract_ctx(request, body_json)
                ctx["_classification"] = classification
                bound = self._store.bind(ctx)
                # Derived values for rate limiting.
                ctx["_token_cost_divisor"] = str(bound.token_cost_divisor)
                ctx["_path"] = path
                # Expose to handlers.
                request.state.tcd_policy = bound
                request.state.tcd_ctx = ctx

            # Rate limit
            if bound:
                ctx_local = request.state.tcd_ctx
            else:
                ctx_local = self._extract_ctx(request, body_json)
                ctx_local["_path"] = path
                ctx_local["_token_cost_divisor"] = str(self._cfg.limits.token_cost_divisor_default)
                ctx_local["_classification"] = classification
            ok, remaining_before, capacity = self._rate_check(ctx_local, body_json, norm_path)
            if not ok:
                raise _Reject(429, "rate limited")

            # Idempotency
            idem_header = request.headers.get(self._cfg.idempotency.header)
            use_idem = (
                self._cfg.idempotency.enable
                and idem_header
                and not self._path_match(path, self._skip_idem)
                and request.method.upper() in ("POST", "PUT", "PATCH")
                and self._should_use_idempotency(classification)
            )
            cache_key = None
            if use_idem:
                cache_key = self._idem_key(request, norm_path, idem_header, self._hash_body(raw_body))
                hit = self._idem.get(cache_key)
                if hit is not None:
                    code, hdrs, body = hit
                    if self._metrics.enabled:
                        self._metrics.idem_ctr.labels("hit", norm_path).inc()
                        if self._metrics.req_sec is not None:
                            try:
                                self._metrics.req_sec.labels(sec_level, norm_path).inc()
                            except Exception:
                                pass
                    headers = {k: v for k, v in hdrs.items() if k.lower() not in ("content-length",)}
                    # Ensure we propagate a request id in the response.
                    headers.setdefault(req_id_header, req_id)
                    return Response(content=body, status_code=code, headers=headers, media_type=hdrs.get("content-type"))

            # Rebuild request body for downstream.
            async def receive_gen():
                yield {"type": "http.request", "body": raw_body, "more_body": False}

            request._receive = _iterable_as_receive(receive_gen())  # type: ignore[attr-defined]

            # Call downstream
            resp = await call_next(request)

            # Capture body for idempotency/metrics and add request id header.
            captured, resp2 = await _capture_response(resp)
            try:
                resp2.headers.setdefault(req_id_header, req_id)
            except Exception:
                pass

            # Optionally emit X-RateLimit-* headers (best effort).
            if self._cfg.limits.emit_rate_headers and capacity is not None and remaining_before is not None:
                try:
                    # Remaining is approximate: before - cost (never negative).
                    # We cannot know exact server-side refill across the request duration.
                    resp2.headers.setdefault("X-RateLimit-Limit", str(int(capacity)))
                    resp2.headers.setdefault("X-RateLimit-Remaining", str(max(0, int(remaining_before - 1))))
                except Exception:
                    pass

            # Store idempotent outcome (guarded).
            if use_idem and cache_key:
                st = captured.status_code
                if (not self._cfg.idempotency.store_only_2xx) or (200 <= st < 300):
                    if len(captured.body) <= self._cfg.idempotency.max_store_bytes:
                        filtered_headers = self._filter_idem_headers(captured.headers)
                        self._idem.set(cache_key, st, filtered_headers, captured.body)
                        if self._metrics.enabled:
                            self._metrics.idem_ctr.labels("store", norm_path).inc()
                    else:
                        if self._metrics.enabled:
                            self._metrics.idem_ctr.labels("skip_oversize", norm_path).inc()

            # Metrics
            if self._metrics.enabled:
                self._metrics.req_bytes.labels(request.method, norm_path).inc(len(raw_body))
                self._metrics.resp_bytes.labels(request.method, norm_path, str(resp2.status_code)).inc(len(captured.body))
                self._metrics.req_ctr.labels(request.method, norm_path, str(resp2.status_code)).inc()
                self._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
                if self._metrics.req_sec is not None:
                    try:
                        self._metrics.req_sec.labels(sec_level, norm_path).inc()
                    except Exception:
                        pass

            return resp2

        except _Reject as rj:
            if self._metrics.enabled:
                self._metrics.req_reject.labels(rj.reason, norm_path).inc()
                self._metrics.req_ctr.labels(request.method, norm_path, str(rj.code)).inc()
                self._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
                if self._metrics.req_sec is not None:
                    try:
                        self._metrics.req_sec.labels(sec_level, norm_path).inc()
                    except Exception:
                        pass
            return Response(
                content=json.dumps({"error": rj.reason}),
                status_code=rj.code,
                media_type="application/json",
                headers={req_id_header: req_id},
            )
        except Exception:
            _logger.exception("Unhandled exception in TCDRequestMiddleware.dispatch")
            if self._metrics.enabled:
                self._metrics.req_reject.labels("exception", norm_path).inc()
                self._metrics.req_ctr.labels(request.method, norm_path, "500").inc()
                self._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
                if self._metrics.req_sec is not None:
                    try:
                        self._metrics.req_sec.labels(sec_level, norm_path).inc()
                    except Exception:
                        pass
            return Response(
                content=json.dumps({"error": "internal"}),
                status_code=500,
                media_type="application/json",
                headers={req_id_header: req_id},
            )


# -------------------------
# Internal helpers (ASGI)
# -------------------------

class _Reject(Exception):
    def __init__(self, code: int, reason: str):
        self.code = int(code)
        self.reason = str(reason)
        super().__init__(reason)


def _iterable_as_receive(iterable: Iterable[Dict[str, Any]]) -> Callable[[], Awaitable[Dict[str, Any]]]:
    iterator = iter(iterable)

    async def receive() -> Dict[str, Any]:
        try:
            return next(iterator)
        except StopIteration:
            await asyncio.sleep(0)  # cooperative yield
            return {"type": "http.request"}

    return receive


@dataclass
class _Captured:
    status_code: int
    headers: List[Tuple[bytes, bytes]]
    body: bytes


async def _capture_response(resp: Response) -> Tuple[_Captured, Response]:
    # Starlette Response may stream via body_iterator; consume it.
    body_chunks: List[bytes] = []
    if hasattr(resp, "body_iterator") and resp.body_iterator is not None:
        async for chunk in resp.body_iterator:
            if isinstance(chunk, (bytes, bytearray)):
                body_chunks.append(bytes(chunk))
            elif isinstance(chunk, memoryview):
                body_chunks.append(chunk.tobytes())
            elif isinstance(chunk, str):
                body_chunks.append(chunk.encode("utf-8"))
            else:
                body_chunks.append(bytes(chunk))
        body = b"".join(body_chunks)
        headers = list(getattr(resp, "raw_headers", []) or [])
        media_type = getattr(resp, "media_type", None)
        status = resp.status_code
        new_resp = Response(
            content=body,
            status_code=status,
            headers={k.decode(): v.decode() for k, v in headers},
            media_type=media_type,
        )
        return _Captured(status, headers, body), new_resp

    # Non-streaming: resp.body should be available.
    body = resp.body if hasattr(resp, "body") else b""
    headers = list(getattr(resp, "raw_headers", []) or [])
    status = resp.status_code
    return _Captured(status, headers, body), resp


# -------------------------
# Wiring helper
# -------------------------

def add_request_middleware(
    app: ASGIApp,
    *,
    config: Optional[TCDRequestMiddlewareConfig] = None,
    policy_store: Optional[PolicyStore] = None,
    rate_limiter: Optional[RateLimiter] = None,
    authenticator: Optional[Authenticator] = None,
) -> None:
    """
    Install TCDRequestMiddleware with the given configuration.
    """
    app.add_middleware(
        TCDRequestMiddleware,
        cfg=config or TCDRequestMiddlewareConfig(),
        policy_store=policy_store,
        rate_limiter=rate_limiter,
        authenticator=authenticator,
    )