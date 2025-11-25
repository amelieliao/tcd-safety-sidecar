# FILE: tcd/middleware_security.py
from __future__ import annotations

import json
import logging
import threading
import time
import ipaddress
from typing import Optional, Iterable, Dict, Any, Set, Mapping, List

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import Headers
from starlette.responses import Response
from starlette.requests import Request

_logger = logging.getLogger(__name__)


class _IpBucket:
    """
    Simple token bucket for per-IP limiting.

    This is intentionally local to the process; it acts as a fast, close-to-edge
    safeguard, and can be complemented by upstream gateways or shared limiters.
    """

    def __init__(self, capacity: float, refill_per_s: float):
        self.capacity = float(capacity)
        self.refill = float(refill_per_s)
        self.tokens = float(capacity)
        self.ts = time.time()
        self.lock = threading.Lock()

    def take(self, n: float = 1.0) -> bool:
        with self.lock:
            now = time.time()
            self.tokens = min(self.capacity, self.tokens + (now - self.ts) * self.refill)
            self.ts = now
            if self.tokens >= n:
                self.tokens -= n
                return True
            return False


def _anonymize_ip(ip: str) -> str:
    """
    Best-effort IP anonymization for security logging.

    Keeps only a coarse prefix and masks the rest. This avoids storing full
    addresses while still giving operators enough information to reason
    about patterns.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return "*"

    if addr.version == 4:
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3] + ["x"])
        return "*"
    # IPv6
    compressed = addr.compressed
    # Keep a short prefix, mask the tail.
    pieces = compressed.split(":")
    if len(pieces) >= 3:
        return ":".join(pieces[:3]) + ":*"
    return "*"


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Edge security middleware.

    This layer is intended to act as the first application-level gate after TLS:
      - per-IP rate limiting with light profiling and eviction
      - IP allow/block/suspicious lists
      - origin / CORS hygiene and preflight handling
      - browser security headers (CSP, HSTS, COOP/COEP/CORP)
      - structured security events for audit
      - lightweight edge_security context for inner middleware

    It does not implement any cryptography; it only enforces process-local
    policies and prepares consistent security signals for downstream logic.
    """

    # Global threat indicator, optional. Can be adjusted by external control
    # plane if the deployment decides to tighten or relax edge behaviour.
    _global_threat_level: int = 0
    _global_threat_lock = threading.Lock()

    @classmethod
    def set_global_threat_level(cls, level: int) -> None:
        """
        Set a coarse global threat level.

        Higher values allow the middleware to apply tighter edge decisions
        (for example, more aggressive limiting for non-allowlisted IPs).
        """
        with cls._global_threat_lock:
            cls._global_threat_level = int(max(0, level))

    @classmethod
    def get_global_threat_level(cls) -> int:
        with cls._global_threat_lock:
            return cls._global_threat_level

    def __init__(
        self,
        app,
        *,
        allow_origins: Iterable[str],
        ip_capacity: float = 30.0,
        ip_refill_per_s: float = 15.0,
        # High-level profile: "DEV", "PROD", "HIGH_SEC", or caller-defined.
        security_profile: str = "DEV",
        # Optional IP lists. Entries can be single addresses or CIDR ranges.
        ip_allowlist: Optional[Iterable[str]] = None,
        ip_blocklist: Optional[Iterable[str]] = None,
        ip_suspicious: Optional[Iterable[str]] = None,
        # Bucket controls to avoid unbounded memory usage.
        ip_bucket_limit: int = 10_000,
        ip_bucket_idle_seconds: float = 600.0,
        # CORS behaviour:
        # - "disabled": block all cross-origin browser access
        # - "strict_allowlist": only allow configured origins
        # - "internal_only": only allow origins matching internal suffixes
        # - "classified": for specific paths, disallow CORS entirely
        cors_mode: str = "strict_allowlist",
        classified_path_patterns: Optional[Iterable[str]] = None,
        internal_origin_suffixes: Optional[Iterable[str]] = None,
        # Browser security headers configuration.
        enable_hsts: bool = False,
        hsts_max_age: int = 31536000,
        hsts_include_subdomains: bool = False,
        hsts_preload: bool = False,
        enable_coop_coep: bool = True,
    ):
        super().__init__(app)
        self.allow: Set[str] = set(o.strip() for o in allow_origins)
        self.buckets: Dict[str, _IpBucket] = {}
        self.cap = float(ip_capacity)
        self.refill = float(ip_refill_per_s)
        self._buckets_lock = threading.Lock()

        self.security_profile = str(security_profile).upper()
        self.ip_bucket_limit = int(max(0, ip_bucket_limit))
        self.ip_bucket_idle_seconds = float(max(0.0, ip_bucket_idle_seconds))

        # IP lists: exact strings + parsed networks.
        self._ip_allow_exact: Set[str] = set()
        self._ip_allow_nets: List[ipaddress._BaseNetwork] = []
        self._ip_block_exact: Set[str] = set()
        self._ip_block_nets: List[ipaddress._BaseNetwork] = []
        self._ip_suspicious_exact: Set[str] = set()
        self._ip_suspicious_nets: List[ipaddress._BaseNetwork] = []

        self._load_ip_list(ip_allowlist or (), self._ip_allow_exact, self._ip_allow_nets)
        self._load_ip_list(ip_blocklist or (), self._ip_block_exact, self._ip_block_nets)
        self._load_ip_list(ip_suspicious or (), self._ip_suspicious_exact, self._ip_suspicious_nets)

        # CORS configuration
        self.cors_mode = cors_mode
        self._classified_path_patterns = tuple(classified_path_patterns or ())
        self._internal_origin_suffixes = tuple(internal_origin_suffixes or ())

        # Security headers configuration
        self.enable_hsts = bool(enable_hsts)
        self.hsts_max_age = int(max(0, hsts_max_age))
        self.hsts_include_subdomains = bool(hsts_include_subdomains)
        self.hsts_preload = bool(hsts_preload)
        self.enable_coop_coep = bool(enable_coop_coep)

    # ----------------- IP lists & buckets -----------------

    def _load_ip_list(
        self,
        entries: Iterable[str],
        exact: Set[str],
        nets: List[ipaddress._BaseNetwork],
    ) -> None:
        for raw in entries:
            val = (raw or "").strip()
            if not val:
                continue
            try:
                if "/" in val:
                    nets.append(ipaddress.ip_network(val, strict=False))
                else:
                    exact.add(val)
            except Exception:
                # Invalid entry is ignored but logged for operators.
                _logger.warning("Invalid IP list entry ignored: %r", val)

    def _ip_matches(self, ip: str, exact: Set[str], nets: List[ipaddress._BaseNetwork]) -> bool:
        if ip in exact:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        for net in nets:
            if addr in net:
                return True
        return False

    def _ip_is_allowlisted(self, ip: str) -> bool:
        return self._ip_matches(ip, self._ip_allow_exact, self._ip_allow_nets)

    def _ip_is_blocklisted(self, ip: str) -> bool:
        return self._ip_matches(ip, self._ip_block_exact, self._ip_block_nets)

    def _ip_is_suspicious(self, ip: str) -> bool:
        return self._ip_matches(ip, self._ip_suspicious_exact, self._ip_suspicious_nets)

    def _evict_buckets(self, now: float) -> None:
        """
        Best-effort eviction of idle or excess IP buckets.

        This prevents unbounded growth in self.buckets. It is intentionally
        simple and local.
        """
        if self.ip_bucket_limit <= 0:
            return

        idle_limit = self.ip_bucket_idle_seconds
        to_delete: List[str] = []
        # First pass: remove idle buckets.
        for ip, bucket in self.buckets.items():
            try:
                last_ts = float(bucket.ts)
            except Exception:
                continue
            if idle_limit > 0 and (now - last_ts) > idle_limit:
                to_delete.append(ip)
        for ip in to_delete:
            self.buckets.pop(ip, None)

        # Second pass: if still above limit, drop oldest ones.
        if len(self.buckets) > self.ip_bucket_limit:
            # Sort by last timestamp ascending.
            ordered = sorted(
                self.buckets.items(),
                key=lambda item: getattr(item[1], "ts", 0.0),
            )
            excess = len(self.buckets) - self.ip_bucket_limit
            for i in range(excess):
                ip, _ = ordered[i]
                self.buckets.pop(ip, None)
            if excess > 0:
                _logger.warning(
                    "IP bucket limit reached; evicted %d oldest entries", excess
                )

    def _bucket(self, ip: str) -> _IpBucket:
        now = time.time()
        with self._buckets_lock:
            self._evict_buckets(now)
            b = self.buckets.get(ip)
            if b is None:
                b = _IpBucket(self.cap, self.refill)
                self.buckets[ip] = b
        return b

    # ----------------- Origin / CORS -----------------

    def _origin_matches_internal(self, origin: str) -> bool:
        if not origin:
            return False
        for suffix in self._internal_origin_suffixes:
            s = (suffix or "").strip()
            if not s:
                continue
            if origin.endswith(s):
                return True
        return False

    def _origin_ok(self, request: Request) -> bool:
        """
        Check whether the request Origin is acceptable under configured CORS mode.

        This only governs browser-visible cross-origin behaviour and does not
        replace authentication or deeper policy checks.
        """
        headers: Headers = request.headers
        origin = headers.get("origin")
        path = request.url.path

        # No Origin: treat as non-browser / same-origin.
        if origin is None:
            return True

        mode = (self.cors_mode or "").lower()

        # For high-sensitivity paths under "classified" mode, block CORS.
        if mode == "classified":
            for pattern in self._classified_path_patterns:
                try:
                    if pattern and pattern in path:
                        return False
                except Exception:
                    # If pattern is not a simple substring, ignore it safely.
                    continue
            # For non-classified paths, fall back to allowlist logic.
            return origin in self.allow

        if mode == "disabled":
            return False

        if mode == "internal_only":
            return self._origin_matches_internal(origin)

        # Default: strict allowlist.
        return origin in self.allow

    # ----------------- Security events & responses -----------------

    def _build_error_response(
        self,
        request: Request,
        status_code: int,
        error: str,
        edge_reason: Optional[str] = None,
    ) -> Response:
        body: Dict[str, Any] = {"error": error}
        if edge_reason:
            body["edge_reason"] = edge_reason
        payload = json.dumps(body, separators=(",", ":"))
        headers: Dict[str, str] = {"content-type": "application/json"}
        # Preserve request id header if present so that logs and responses
        # can be correlated across layers.
        req_id = request.headers.get("X-Request-Id") or request.headers.get("x-request-id")
        if req_id:
            headers["X-Request-Id"] = req_id
        return Response(content=payload, status_code=status_code, headers=headers)

    def _log_security_event(
        self,
        event_type: str,
        request: Request,
        client_ip: str,
        edge_info: Mapping[str, Any],
        reason: str,
    ) -> None:
        """
        Emit a structured edge-security event log.

        Only coarse metadata is recorded; request bodies and sensitive
        headers are intentionally excluded.
        """
        record: Dict[str, Any] = {
            "event": event_type,
            "reason": reason,
            "request_path": request.url.path,
            "request_method": request.method,
            "client_ip": _anonymize_ip(client_ip),
            "security_profile": self.security_profile,
            "threat_level": self.get_global_threat_level(),
        }
        req_id = request.headers.get("X-Request-Id") or request.headers.get("x-request-id")
        if req_id:
            record["request_id"] = req_id
        try:
            record["edge_security"] = dict(edge_info)
        except Exception:
            pass
        try:
            _logger.warning("edge_security_event: %s", json.dumps(record, separators=(",", ":")))
        except Exception:
            # Logging failures must not affect edge decision behaviour.
            _logger.warning("edge_security_event (fallback): %s", record)

    # ----------------- Dispatch -----------------

    async def dispatch(self, request: Request, call_next):
        client_ip = (request.client.host if request.client else "0.0.0.0")
        # Initialize a small state object to share with inner middleware layers.
        edge_info: Dict[str, Any] = {
            "client_ip": client_ip,
            "ip_limited": False,
            "ip_blocked": False,
            "ip_suspicious": False,
            "origin_ok": True,
            "cors_mode": self.cors_mode,
            "security_profile": self.security_profile,
            "threat_level": self.get_global_threat_level(),
        }
        try:
            request.state.edge_security = edge_info
        except Exception:
            # If attaching state fails, proceed without it.
            pass

        try:
            # Hard block for explicitly blocked IPs.
            if self._ip_is_blocklisted(client_ip):
                edge_info["ip_blocked"] = True
                self._log_security_event("ip_block", request, client_ip, edge_info, "ip_blocklist")
                return self._build_error_response(request, 403, "forbidden", "ip_blocklist")

            # Respect a global threat level; in higher levels, non-allowlisted
            # clients may be handled more strictly.
            threat_level = self.get_global_threat_level()
            if threat_level >= 2 and not self._ip_is_allowlisted(client_ip):
                edge_info["ip_limited"] = True
                edge_info["threat_level"] = threat_level
                self._log_security_event("edge_overload", request, client_ip, edge_info, "global_threat_level")
                return self._build_error_response(request, 503, "unavailable", "edge_overload")

            # Suspicious IPs can be charged a higher token cost to slow them down.
            is_suspicious = self._ip_is_suspicious(client_ip)
            if is_suspicious:
                edge_info["ip_suspicious"] = True
                token_cost = 2.0
            else:
                token_cost = 1.0

            bucket = self._bucket(client_ip)
            if not bucket.take(token_cost):
                edge_info["ip_limited"] = True
                self._log_security_event("rate_limited", request, client_ip, edge_info, "ip_bucket_exhausted")
                return self._build_error_response(request, 429, "rate_limited", "ip_bucket_exhausted")

            # Origin / CORS checks.
            origin_ok = self._origin_ok(request)
            edge_info["origin_ok"] = bool(origin_ok)
            if not origin_ok:
                self._log_security_event("cors_block", request, client_ip, edge_info, "origin_not_allowed")
                return self._build_error_response(request, 403, "cors_blocked", "origin_not_allowed")

            # Preflight handling: allow a clean OPTIONS response when origin passes.
            if request.method.upper() == "OPTIONS":
                origin = request.headers.get("origin")
                resp = Response(status_code=204)
                if origin:
                    resp.headers.setdefault("Access-Control-Allow-Origin", origin)
                    resp.headers.setdefault("Vary", "Origin")
                    resp.headers.setdefault(
                        "Access-Control-Allow-Headers",
                        "authorization,content-type,x-request-id",
                    )
                    resp.headers.setdefault("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
                    resp.headers.setdefault("Access-Control-Max-Age", "600")
                self._apply_security_headers(resp)
                return resp

            # Call downstream application.
            resp: Response = await call_next(request)

            # Apply security headers.
            self._apply_security_headers(resp)

            # Basic CORS echo for allowed origins.
            origin = request.headers.get("origin")
            if origin:
                resp.headers.setdefault("Access-Control-Allow-Origin", origin)
                # It is common to have multiple Vary values; here we set a base one.
                existing_vary = resp.headers.get("Vary")
                if existing_vary:
                    if "Origin" not in existing_vary:
                        resp.headers["Vary"] = existing_vary + ", Origin"
                else:
                    resp.headers.setdefault("Vary", "Origin")
                resp.headers.setdefault(
                    "Access-Control-Allow-Headers",
                    "authorization,content-type,x-request-id",
                )
                resp.headers.setdefault("Access-Control-Allow-Methods", "GET,POST,OPTIONS")

            return resp

        except Exception:
            # Fail-closed: unexpected errors at the edge should not silently
            # bypass security decisions.
            _logger.exception("Unhandled exception in SecurityMiddleware.dispatch")
            self._log_security_event("edge_exception", request, client_ip, edge_info, "exception")
            return self._build_error_response(request, 503, "internal_edge_error", "exception")

    # ----------------- Security headers -----------------

    def _apply_security_headers(self, resp: Response) -> None:
        """
        Attach browser-oriented security headers.

        These headers are defensive by default. Callers can adjust behaviour
        via middleware configuration.
        """
        # Basic hardening.
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Permissions-Policy", "geolocation=()")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )

        # HSTS: only meaningful when the service is behind HTTPS.
        if self.enable_hsts:
            parts = [f"max-age={self.hsts_max_age}"]
            if self.hsts_include_subdomains:
                parts.append("includeSubDomains")
            if self.hsts_preload:
                parts.append("preload")
            resp.headers.setdefault("Strict-Transport-Security", "; ".join(parts))

        # COOP/COEP/CORP: isolate browsing context and cross-origin embedding.
        if self.enable_coop_coep:
            resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
            resp.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
            resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-site")
            # Modern browsers ignore this header for new protections, but
            # explicitly disabling legacy behaviour keeps things predictable.
            resp.headers.setdefault("X-XSS-Protection", "0")