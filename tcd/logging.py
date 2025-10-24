# FILE: tcd/logging.py
from __future__ import annotations

import contextvars
import datetime as _dt
import json
import logging
import os
import sys
import time
import traceback
import types
import uuid
from typing import Any, Dict, Iterable, Optional, Tuple, Callable

# ---------- Optional OpenTelemetry ----------
try:
    from opentelemetry import trace as _otel_trace  # type: ignore
    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

# ---------- Module-level config (env-driven, safe defaults) ----------
_LOG_SCHEMA = os.environ.get("TCD_LOG_SCHEMA", "tcd.log.v1")
_LOG_SERVICE = os.environ.get("TCD_SERVICE", "tcd")
_LOG_VERSION = os.environ.get("TCD_BUILD_VERSION", os.environ.get("TCD_VERSION", "0.0.0"))
_LOG_ENV = os.environ.get("TCD_ENV", os.environ.get("ENV", "dev"))
_LOG_INSTANCE = os.environ.get("TCD_INSTANCE", os.uname().nodename if hasattr(os, "uname") else "unknown")

# Sampling (0.0~1.0). 1.0 = log all
try:
    _SAMPLE = float(os.environ.get("TCD_LOG_SAMPLE", "1.0"))
    _SAMPLE = 1.0 if _SAMPLE > 1 else (0.0 if _SAMPLE < 0 else _SAMPLE)
except Exception:
    _SAMPLE = 1.0

# Simple token-bucket rate limit per key (msgs/sec); 0=disable
try:
    _RATE_LIMIT = float(os.environ.get("TCD_LOG_RATE_LIMIT", "0"))
except Exception:
    _RATE_LIMIT = 0.0

# Max bytes per field (truncate to keep JSON small)
try:
    _MAX_FIELD = int(os.environ.get("TCD_LOG_MAX_FIELD", "8192"))
    _MAX_FIELD = max(512, _MAX_FIELD)
except Exception:
    _MAX_FIELD = 8192

# Stack emission toggle
_INCLUDE_STACK = os.environ.get("TCD_LOG_INCLUDE_STACK", "1") == "1"

# Redaction keys (case-insensitive)
_DEFAULT_REDACT = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-tcd-signature",
    "x-tcd-key-id",
    "x-auth-token",
    "x-access-token",
}
_REDACT_KEYS = {k.strip().lower() for k in os.environ.get("TCD_LOG_REDACT", "").split(",") if k.strip()} or _DEFAULT_REDACT

# ---------- Context management ----------
_log_ctx: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("tcd_log_ctx", default={})

def bind(**fields: Any) -> None:
    """Merge fields into the current logging context (per-coroutine)."""
    cur = dict(_log_ctx.get())
    for k, v in fields.items():
        if v is None:
            continue
        cur[str(k)] = v
    _log_ctx.set(cur)

def unbind(*keys: str) -> None:
    cur = dict(_log_ctx.get())
    for k in keys:
        cur.pop(k, None)
    _log_ctx.set(cur)

def reset() -> None:
    _log_ctx.set({})

def context() -> Dict[str, Any]:
    return dict(_log_ctx.get())

# ---------- Helpers ----------
def _otel_ids() -> Tuple[Optional[str], Optional[str]]:
    if not _HAS_OTEL:
        return None, None
    try:
        span = _otel_trace.get_current_span()
        ctx = span.get_span_context()
        if not ctx or not ctx.is_valid:
            return None, None
        return (format(ctx.trace_id, "032x"), format(ctx.span_id, "016x"))
    except Exception:  # pragma: no cover
        return None, None

def _ts_iso() -> str:
    # RFC3339 with milliseconds, UTC Z (deterministic format for AE)
    now = _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc)
    ms = int(now.microsecond / 1000)
    base = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return f"{base[:-1]}.{ms:03d}Z"

def _compact_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

def _truncate(v: Any) -> Any:
    if isinstance(v, str) and len(v) > _MAX_FIELD:
        return v[:_MAX_FIELD] + "...<truncated>"
    return v

def _finite_float(x: Any) -> Optional[float]:
    try:
        xf = float(x)
        if xf != xf or xf == float("inf") or xf == float("-inf"):
            return None
        return xf
    except Exception:
        return None

def _redact_key(k: str) -> bool:
    return k.lower() in _REDACT_KEYS

def scrub_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """Scrub sensitive keys (headers etc.)."""
    out: Dict[str, Any] = {}
    for k, v in (d or {}).items():
        if _redact_key(k):
            out[k] = "***"
        else:
            out[k] = v if not isinstance(v, dict) else scrub_dict(v)
    return out

# ---------- Very small rate limiter ----------
# token bucket per key (key defaults to logger name). granularity: second
_rate_state: Dict[str, Tuple[int, float]] = {}  # key -> (count_in_sec, sec_epoch)

def _rate_ok(key: str) -> bool:
    if _RATE_LIMIT <= 0:
        return True
    now = int(time.time())
    cnt, sec = _rate_state.get(key, (0, now))
    if sec != now:
        cnt, sec = 0, now
    if cnt >= _RATE_LIMIT:
        return False
    _rate_state[key] = (cnt + 1, sec)
    return True

# ---------- JSON formatter ----------
def _merge_optional(dst: Dict[str, Any], **kvs: Any) -> None:
    for k, v in kvs.items():
        if v is None:
            continue
        if isinstance(v, float):
            vv = _finite_float(v)
            if vv is None:
                continue
            dst[k] = vv
        else:
            dst[k] = _truncate(v)

class JSONFormatter(logging.Formatter):
    """
    Minimal-allocation JSON formatter with stable schema.
    Core fields:
      - schema, service, version, env, instance
      - ts, lvl, msg, logger
      - req_id, trace_id, span_id
      - tenant, model_id, verdict, e_value, a_alloc, score
      - path, method, status, route
    """

    def __init__(self, *, include_stack: bool = True, sample: float = _SAMPLE, rate_key_fn: Optional[Callable[[logging.LogRecord], str]] = None):
        super().__init__()
        self.include_stack = include_stack
        self.sample = float(sample)
        self.rate_key_fn = rate_key_fn

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        # sampling
        if self.sample < 1.0:
            # lightweight LCG-ish hash of message+name for deterministic sampling
            s = f"{record.name}|{getattr(record, 'msg', '')}"
            hv = 0x811C9DC5
            for ch in s:
                hv = ((hv ^ ord(ch)) * 0x01000193) & 0xFFFFFFFF
            frac = (hv % 10000) / 10000.0
            if frac > self.sample:
                return ""  # drop

        # rate limit
        key = self.rate_key_fn(record) if self.rate_key_fn else record.name
        if not _rate_ok(key):
            return ""

        ctx = context()
        trace_id, span_id = _otel_ids()

        # Envelope
        evt: Dict[str, Any] = {
            "schema": _LOG_SCHEMA,
            "service": _LOG_SERVICE,
            "version": _LOG_VERSION,
            "env": _LOG_ENV,
            "instance": _LOG_INSTANCE,
            "ts": _ts_iso(),
            "lvl": record.levelname,
            "logger": record.name,
            "msg": str(record.getMessage()),
        }

        # Context picks (prefer bound ctx -> record.<attr>)
        def _pick(*names: str) -> Optional[Any]:
            for n in names:
                if n in ctx:
                    return ctx[n]
                v = getattr(record, n, None)
                if v is not None:
                    return v
            return None

        _merge_optional(
            evt,
            req_id=_pick("req_id"),
            trace_id=trace_id or _pick("trace_id"),
            span_id=span_id or _pick("span_id"),
            tenant=_pick("tenant"),
            user=_pick("user"),
            session=_pick("session"),
            model_id=_pick("model_id"),
            gpu_id=_pick("gpu_id"),
            task=_pick("task"),
            lang=_pick("lang"),
            verdict=_pick("verdict"),
            e_value=_pick("e_value"),
            a_alloc=_pick("a_alloc"),
            score=_pick("score"),
            route=_pick("route"),
            path=_pick("path"),
            method=_pick("method"),
            status=_pick("status") or _pick("status_code"),
            latency_ms=_pick("latency_ms"),
            bytes_in=_pick("bytes_in"),
            bytes_out=_pick("bytes_out"),
        )

        # Exception info
        if record.exc_info and self.include_stack:
            exc_type, exc_val, exc_tb = record.exc_info
            evt["exc_type"] = getattr(exc_type, "__name__", str(exc_type))
            evt["exc_message"] = str(exc_val)[:_MAX_FIELD]
            evt["stack"] = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))[:_MAX_FIELD]

        return _compact_json(evt)

# ---------- Uvicorn/Root integration ----------
def _clear_handlers(logger: logging.Logger) -> None:
    for h in list(logger.handlers):
        logger.removeHandler(h)

def configure_json_logging(
    level: str = "INFO",
    *,
    include_uvicorn: bool = True,
    stream: Any = None,
    include_stack: bool = _INCLUDE_STACK,
    sample: float = _SAMPLE,
    rate_key_fn: Optional[Callable[[logging.LogRecord], str]] = None,
) -> logging.Logger:
    """
    Configure root (+ optionally uvicorn) for JSON output.
    """
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)
    stream = stream or sys.stderr

    fmt = JSONFormatter(include_stack=include_stack, sample=sample, rate_key_fn=rate_key_fn)
    h = logging.StreamHandler(stream=stream)
    h.setFormatter(fmt)
    h.setLevel(lvl)

    root = logging.getLogger()
    root.setLevel(lvl)
    _clear_handlers(root)
    root.addHandler(h)

    if include_uvicorn:
        for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
            lg = logging.getLogger(name)
            lg.setLevel(lvl)
            _clear_handlers(lg)
            lg.addHandler(h)
            lg.propagate = False

    return root

# ---------- Request helpers ----------
def ensure_request_id(headers: Optional[Dict[str, str]] = None) -> str:
    """
    Get or create a stable request id; bind into context immediately.
    """
    rid = None
    if headers:
        # header keys may vary in case
        for k in ("x-request-id", "X-Request-Id", "x-amzn-trace-id"):
            if k in headers:
                rid = headers[k]
                break
    if not rid:
        rid = uuid.uuid4().hex[:16]
    bind(req_id=rid)
    return rid

def bind_request_meta(
    *,
    tenant: Optional[str] = None,
    user: Optional[str] = None,
    session: Optional[str] = None,
    model_id: Optional[str] = None,
    gpu_id: Optional[str] = None,
    task: Optional[str] = None,
    lang: Optional[str] = None,
    path: Optional[str] = None,
    method: Optional[str] = None,
) -> None:
    bind(
        tenant=tenant,
        user=user,
        session=session,
        model_id=model_id,
        gpu_id=gpu_id,
        task=task,
        lang=lang,
        path=path,
        method=method,
    )

def log_decision(
    logger: logging.Logger,
    *,
    verdict: bool,
    score: Optional[float] = None,
    e_value: Optional[float] = None,
    alpha_alloc: Optional[float] = None,
    message: str = "decision",
    extra: Optional[Dict[str, Any]] = None,
    level: int = logging.INFO,
) -> None:
    extra_dict: Dict[str, Any] = {
        "verdict": bool(verdict),
        "e_value": _finite_float(e_value),
        "a_alloc": _finite_float(alpha_alloc),
        "score": _finite_float(score),
    }
    if extra:
        for k, v in extra.items():
            if v is not None:
                extra_dict[k] = _truncate(v)
    logger.log(level, message, extra=extra_dict)

# ---------- ASGI middleware (structured request logs, no uvicorn deps) ----------
class RequestLogMiddleware:
    """
    Lightweight ASGI middleware that emits JSON request start/finish lines with:
      req_id, method, path, status, latency_ms, bytes_in/out, and scrubbed headers (optional).
    Usage:
        app.add_middleware(RequestLogMiddleware, log_headers=False)
    """

    def __init__(self, app, *, logger_name: str = "tcd.http", log_headers: bool = False):
        self.app = app
        self.log = logging.getLogger(logger_name)
        self.log_headers = bool(log_headers)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # extract minimal info
        method = scope.get("method", "")
        path = scope.get("path", "")
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in (scope.get("headers") or [])}
        rid = ensure_request_id(headers)

        # bind request meta
        bind_request_meta(path=path, method=method)

        if self.log_headers:
            self.log.info("http.start", extra={"headers": scrub_dict(headers)})

        t0 = time.perf_counter()
        status_holder = {"code": None}
        bytes_out_holder = {"n": 0}

        async def _send_wrapper(message):
            if message["type"] == "http.response.start":
                status_holder["code"] = message.get("status")
            if message["type"] == "http.response.body":
                body = message.get("body", b"") or b""
                bytes_out_holder["n"] += len(body)
            await send(message)

        # bytes_in estimation (best-effort)
        bytes_in = 0
        try:
            async def _recv_wrapper():
                nonlocal bytes_in
                msg = await receive()
                if msg["type"] == "http.request":
                    body = msg.get("body", b"") or b""
                    bytes_in += len(body)
                return msg

            await self.app(scope, _recv_wrapper, _send_wrapper)
        finally:
            dt_ms = (time.perf_counter() - t0) * 1000.0
            extra = {
                "req_id": rid,
                "path": path,
                "method": method,
                "status": status_holder["code"],
                "latency_ms": round(dt_ms, 3),
                "bytes_in": bytes_in,
                "bytes_out": bytes_out_holder["n"],
            }
            self.log.info("http.finish", extra=extra)
            # clear request-scoped keys to avoid leakage across coroutines
            unbind("path", "method", "status", "bytes_in", "bytes_out")

# ---------- Convenience: module-level logger ----------
_logger = None  # type: Optional[logging.Logger]

def get_logger(name: str = "tcd") -> logging.Logger:
    """
    Return a module-level logger configured for JSON output.
    First call initializes root+uvicorn setup if not configured.
    """
    global _logger
    if _logger is None:
        lvl = os.environ.get("TCD_LOG_LEVEL", "INFO")
        _logger = configure_json_logging(level=lvl, include_uvicorn=True)
    return logging.getLogger(name)

# ---------- Public API (what users are expected to import) ----------
__all__ = [
    "bind", "unbind", "reset", "context",
    "configure_json_logging", "get_logger",
    "ensure_request_id", "bind_request_meta", "log_decision",
    "JSONFormatter", "RequestLogMiddleware",
    "scrub_dict",
]