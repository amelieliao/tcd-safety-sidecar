# FILE: tcd/middleware.py
import time
import uuid
import threading
from typing import Dict

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from prometheus_client import Counter, Histogram


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Injects request_id/session_id; exposes them as headers and request.state.*"""
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        sid = request.headers.get("x-session-id") or request.cookies.get("sid") or uuid.uuid4().hex[:16]
        request.state.request_id = rid
        request.state.session_id = sid
        response = await call_next(request)
        response.headers["X-Request-Id"] = rid
        response.headers["X-Session-Id"] = sid
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Token-bucket per IP. rate_per_sec tokens/sec, with burst bucket.
    In-memory, best-effort guard.
    """
    def __init__(self, app, rate_per_sec: float = 10.0, burst: float = 20.0):
        super().__init__(app)
        self.rate = float(rate_per_sec)
        self.burst = float(burst)
        self._lock = threading.Lock()
        self._buckets: Dict[str, Dict[str, float]] = {}

    def _take(self, key: str, tokens: float = 1.0) -> bool:
        now = time.time()
        with self._lock:
            b = self._buckets.get(key)
            if not b:
                b = {"t": now, "tokens": self.burst}
            else:
                elapsed = max(0.0, now - b["t"])
                b["tokens"] = min(self.burst, b["tokens"] + elapsed * self.rate)
                b["t"] = now
            if b["tokens"] >= tokens:
                b["tokens"] -= tokens
                self._buckets[key] = b
                return True
            self._buckets[key] = b
            return False

    async def dispatch(self, request: Request, call_next):
        ip = request.client.host if request.client else "unknown"
        if not self._take(ip, 1.0):
            return Response("rate limited", status_code=429)
        return await call_next(request)


class MetricsMiddleware(BaseHTTPMiddleware):
    """
    Prometheus counter + histogram + JSONL structured log.
    Counter:  tcd_requests_total{route, status}
    Histogram: tcd_request_latency_seconds{route}
    """
    def __init__(self, app, counter: Counter, histogram: Histogram):
        super().__init__(app)
        self.counter = counter
        self.hist = histogram

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        route_label = "diagnose" if path.endswith("/diagnose") else path
        t0 = time.perf_counter()
        status_label = "ok"
        try:
            response = await call_next(request)
            status_label = "ok" if 200 <= int(response.status_code) < 400 else "err"
            return response
        except Exception:
            status_label = "err"
            raise
        finally:
            dt = time.perf_counter() - t0
            # prometheus
            self.counter.labels(route=route_label, status=status_label).inc()
            self.hist.labels(route=route_label).observe(dt)
            # jsonl
            try:
                rec = {
                    "level": "info" if status_label == "ok" else "error",
                    "ts": time.time(),
                    "route": route_label,
                    "status": status_label,
                    "latency_ms": round(dt * 1000.0, 3),
                    "request_id": getattr(request.state, "request_id", None),
                    "session_id": getattr(request.state, "session_id", None),
                }
                print(__import__("json").dumps(rec, ensure_ascii=False))
            except Exception:
                pass