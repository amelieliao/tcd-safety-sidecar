# FILE: tcd/middleware_security.py
from __future__ import annotations
import time, threading
from typing import Optional, Iterable
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.datastructures import Headers
from starlette.responses import Response
from starlette.requests import Request

class _IpBucket:
    def __init__(self, capacity: float, refill_per_s: float):
        self.capacity = capacity
        self.refill = refill_per_s
        self.tokens = capacity
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

class SecurityMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, allow_origins: Iterable[str], ip_capacity: float = 30.0, ip_refill_per_s: float = 15.0):
        super().__init__(app)
        self.allow = set(o.strip() for o in allow_origins)
        self.buckets: dict[str, _IpBucket] = {}
        self.cap = ip_capacity
        self.refill = ip_refill_per_s

    def _origin_ok(self, headers: Headers) -> bool:
        o = headers.get("origin")
        return (o is None) or (o in self.allow)

    def _bucket(self, ip: str) -> _IpBucket:
        b = self.buckets.get(ip)
        if b is None:
            b = self.buckets[ip] = _IpBucket(self.cap, self.refill)
        return b

    async def dispatch(self, request: Request, call_next):
        client_ip = (request.client.host if request.client else "0.0.0.0")
        if not self._bucket(client_ip).take(1.0):
            return Response("Too Many Requests", status_code=429)

        if not self._origin_ok(request.headers):
            return Response("CORS blocked", status_code=403)

        resp: Response = await call_next(request)

        # security headers
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("Permissions-Policy", "geolocation=()")
        resp.headers.setdefault("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        # basic CORS echo 
        origin = request.headers.get("origin")
        if origin:
            resp.headers.setdefault("Access-Control-Allow-Origin", origin)
            resp.headers.setdefault("Vary", "Origin")
            resp.headers.setdefault("Access-Control-Allow-Headers", "authorization,content-type,x-request-id")
            resp.headers.setdefault("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        return resp