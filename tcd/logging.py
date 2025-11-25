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
import uuid
from typing import Any, Dict, Optional, Tuple, Callable, Mapping, Set

# ---------- Optional OpenTelemetry ----------
try:
    from opentelemetry import trace as _otel_trace  # type: ignore

    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

# ---------- Module-level config (env-driven, safe defaults) ----------
_LOG_SCHEMA = os.environ.get("TCD_LOG_SCHEMA", "tcd.log.v1")
_LOG_SERVICE = os.environ.get("TCD_SERVICE", "tcd")
_LOG_VERSION = os.environ.get(
    "TCD_BUILD_VERSION", os.environ.get("TCD_VERSION", "0.0.0")
)
_LOG_ENV = os.environ.get("TCD_ENV", os.environ.get("ENV", "dev"))
_LOG_INSTANCE = os.environ.get(
    "TCD_INSTANCE", os.uname().nodename if hasattr(os, "uname") else "unknown"
)

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

# Optional metadata sanitization / PII stripping for log extras
_LOG_SANITIZE_META = os.environ.get("TCD_LOG_SANITIZE_META", "1") == "1"
_LOG_STRIP_PII = os.environ.get("TCD_LOG_STRIP_PII", "1") == "1"

# Redaction keys (case-insensitive, for headers / obvious secrets)
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
_REDACT_KEYS = {
    k.strip().lower()
    for k in os.environ.get("TCD_LOG_REDACT", "").split(",")
    if k.strip()
} or _DEFAULT_REDACT

# Metadata keys that must not carry raw content in logs (content-agnostic guard)
_FORBIDDEN_META_KEYS = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "messages",
    "content",
    "raw",
    "body",
}

# Whether to enable hard whitelist mode for meta (only allow a small safe set)
_LOG_META_WHITELIST_MODE = os.environ.get("TCD_LOG_META_WHITELIST", "0") == "1"

# Allowed meta keys when whitelist mode is enabled (all lowercased)
_ALLOWED_META_KEYS = {
    "req_id",
    "tenant",
    "user",
    "session",
    "model_id",
    "gpu_id",
    "task",
    "lang",
    "path",
    "method",
    "status",
    "latency_ms",
    "bytes_in",
    "bytes_out",
    "threat_label",
    "threat_vector",
    "chain_id",
    "pq_scheme",
    "pq_required",
    "pq_ok",
    "pq_chain_id",
    "supply_chain_ref",
    "override_applied",
    "override_actor",
    "override_level",
    "policy_ref",
    "lockdown_level",
}

# Vocab constraints for trust / routing / override / PQ posture (shared across stack)
_ALLOWED_TRUST_ZONES = {
    "internet",
    "internal",
    "partner",
    "admin",
    "ops",
}

_ALLOWED_ROUTE_PROFILES = {
    "inference",
    "admin",
    "control",
    "metrics",
    "health",
}

_ALLOWED_OVERRIDE_LEVELS = {
    "none",
    "break_glass",
    "maintenance",
}

_ALLOWED_PQ_SCHEMES = {
    "",
    "dilithium2",
    "dilithium3",
    "falcon",
    "sphincs+",
}

# Standard LogRecord attributes that are not treated as dynamic meta
_LOG_RECORD_STD_ATTRS: Set[str] = {
    "name",
    "msg",
    "args",
    "levelname",
    "levelno",
    "pathname",
    "filename",
    "module",
    "exc_info",
    "exc_text",
    "stack_info",
    "lineno",
    "funcName",
    "created",
    "msecs",
    "relativeCreated",
    "thread",
    "threadName",
    "processName",
    "process",
}

# ---------- Structured metadata sanitization (reuses utils) ----------
from .utils import (  # noqa: E402
    SanitizeConfig,
    sanitize_metadata_for_receipt,
    blake2s_hex,
)

# ---------- Context management ----------
_log_ctx: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar(
    "tcd_log_ctx", default={}
)


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
    # RFC3339 with milliseconds, UTC Z (deterministic format for analysis)
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


def _looks_like_pii(value: str) -> bool:
    """
    Very coarse PII-like detection for tags (tenant/user/session/actor).

    This is intentionally conservative and only used to decide whether to hash
    tag strings. It is not a full PII detector.
    """
    v = value.strip()
    if not v:
        return False
    # Contains '@' → likely an email-style identifier
    if "@" in v:
        return True
    # Contains visible spaces → likely a display name or phrase
    if " " in v or "\u3000" in v:
        return True
    # Long token-like IDs are usually safe to log as-is
    if len(v) > 96:
        return False
    return False


def _hash_if_pii(value: Any, *, label: str) -> Any:
    """
    If a tag looks PII-like, replace it with a non-reversible hash tagged
    with `label`. Used for tenant/user/session/override_actor.
    """
    if not isinstance(value, str):
        return value
    if not _looks_like_pii(value):
        return value
    try:
        digest = blake2s_hex(value, canonical=False)[:16]
        return f"{label}-h-{digest}"
    except Exception:
        return f"{label}-h-anon"


def scrub_dict(d: Dict[str, Any]) -> Dict[str, Any]:
    """
    Scrub obvious secrets from a dict (typically HTTP headers).

    Keys listed in `_REDACT_KEYS` get replaced by "***". Nested dictionaries
    are scrubbed recursively.
    """
    out: Dict[str, Any] = {}
    for k, v in (d or {}).items():
        if _redact_key(k):
            out[k] = "***"
        else:
            out[k] = v if not isinstance(v, dict) else scrub_dict(v)
    return out


def _sanitize_meta_from_record(
    record: logging.LogRecord, evt_keys: Optional[Set[str]] = None
) -> Optional[Dict[str, Any]]:
    """
    Collect and sanitize dynamic metadata from a LogRecord.

    This collects attributes that:
      - are not part of the standard LogRecord API,
      - are not already present as top-level fields in the event,
      - do not start with "_".

    Then it applies:
      - key-level filtering (forbidden meta keys),
      - optional structural sanitization (depth/size limits),
      - optional PII stripping (via utils SanitizeConfig),
      - recursive string truncation,
      - optional hard whitelist filtering.
    """
    evt_keys = evt_keys or set()
    raw_meta: Dict[str, Any] = {}
    for k, v in record.__dict__.items():
        if k in _LOG_RECORD_STD_ATTRS:
            continue
        if k in evt_keys:
            continue
        if k.startswith("_"):
            continue
        # Avoid duplicating the core "msg" (LogRecord stores both msg and message)
        if k == "message":
            continue
        raw_meta[k] = v

    if not raw_meta:
        return None

    # First, drop hard-forbidden keys at the top level
    filtered: Dict[str, Any] = {}
    for k, v in raw_meta.items():
        if k.lower() in _FORBIDDEN_META_KEYS:
            # Completely drop fields that look like raw content carriers
            continue
        filtered[k] = v

    if not filtered:
        return None

    # Apply structured sanitization and PII stripping via utils, if enabled
    meta: Dict[str, Any]
    if _LOG_SANITIZE_META:
        try:
            cfg = SanitizeConfig(
                sanitize_nan=True,
                prune_large=True,
                strip_pii=_LOG_STRIP_PII,
                forbid_keys=tuple(_FORBIDDEN_META_KEYS),
            )
            sanitized = sanitize_metadata_for_receipt(filtered, config=cfg)
            if isinstance(sanitized, Mapping):
                meta = dict(sanitized)
            else:
                # Fall back to the filtered dict if the shape changed unexpectedly
                meta = dict(filtered)
        except Exception:
            meta = dict(filtered)
    else:
        meta = dict(filtered)

    # Finally, truncate strings recursively to keep logs compact
    def _apply_trunc(v: Any) -> Any:
        if isinstance(v, str):
            return _truncate(v)
        if isinstance(v, dict):
            return {kk: _apply_trunc(vv) for kk, vv in v.items()}
        if isinstance(v, list):
            return [_apply_trunc(x) for x in v]
        if isinstance(v, tuple):
            return tuple(_apply_trunc(x) for x in v)
        return v

    meta_trunc = {k: _apply_trunc(v) for k, v in meta.items()}

    # Hard whitelist mode: only keep a small set of safe keys
    if _LOG_META_WHITELIST_MODE:
        filtered_meta: Dict[str, Any] = {}
        for k, v in meta_trunc.items():
            if k.lower() in _ALLOWED_META_KEYS:
                filtered_meta[k] = v
        if not filtered_meta:
            return None
        return filtered_meta

    return meta_trunc


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
    Minimal-allocation JSON formatter with a stable schema and content-agnostic fields.

    Core envelope fields:
      - schema, service, version, env, instance
      - ts, lvl, msg, logger
      - req_id, trace_id, span_id
      - tenant, user, session, principal_type, model_id
      - trust_zone, route_profile, lockdown_level
      - verdict, e_value, a_alloc, score
      - path, method, status, route, latency_ms
      - PQ / supply-chain posture: pq_scheme, pq_required, pq_ok, pq_chain_id, supply_chain_ref
      - override / insider posture: override_applied, override_actor, override_level
    """

    def __init__(
        self,
        *,
        include_stack: bool = True,
        sample: float = _SAMPLE,
        rate_key_fn: Optional[Callable[[logging.LogRecord], str]] = None,
    ):
        super().__init__()
        self.include_stack = include_stack
        self.sample = float(sample)
        self.rate_key_fn = rate_key_fn

    def _normalize_envelope(self, evt: Dict[str, Any]) -> None:
        """
        Normalize and harden envelope fields:

          - tenant/user/session/override_actor: hash if PII-like;
          - trust_zone / route_profile / override_level / pq_scheme: vocab constraints;
          - e_value / a_alloc / score: numeric constraints.
        """
        # 1) PII-like tag hashing
        for fld in ("tenant", "user", "session", "override_actor"):
            if fld in evt:
                evt[fld] = _hash_if_pii(evt[fld], label=fld)

        # 2) vocab constraints
        tz = evt.get("trust_zone")
        if tz is not None and isinstance(tz, str):
            if tz not in _ALLOWED_TRUST_ZONES:
                # Drop invalid values to keep downstream analysis clean
                evt.pop("trust_zone", None)

        rp = evt.get("route_profile")
        if rp is not None and isinstance(rp, str):
            if rp not in _ALLOWED_ROUTE_PROFILES:
                evt.pop("route_profile", None)

        ovl = evt.get("override_level")
        if ovl is not None and isinstance(ovl, str):
            if ovl not in _ALLOWED_OVERRIDE_LEVELS:
                evt.pop("override_level", None)

        pqs = evt.get("pq_scheme")
        if pqs is not None and isinstance(pqs, str):
            if pqs not in _ALLOWED_PQ_SCHEMES:
                evt.pop("pq_scheme", None)

        # 3) e-process related numeric constraints
        for fld in ("e_value", "a_alloc", "score"):
            if fld not in evt:
                continue
            v = _finite_float(evt.get(fld))
            if v is None:
                evt.pop(fld, None)
                continue
            if fld == "e_value":
                # e-value >= 0
                if v < 0.0:
                    evt.pop(fld, None)
            elif fld == "a_alloc":
                # alpha allocation in [0, 1]
                if not (0.0 <= v <= 1.0):
                    evt[fld] = max(0.0, min(1.0, v))
                else:
                    evt[fld] = v
            elif fld == "score":
                # normalized score in [0, 1]
                evt[fld] = max(0.0, min(1.0, v))

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        # Sampling
        if self.sample < 1.0:
            # Lightweight LCG-ish hash of message+name for deterministic sampling
            s = f"{record.name}|{getattr(record, 'msg', '')}"
            hv = 0x811C9DC5
            for ch in s:
                hv = ((hv ^ ord(ch)) * 0x01000193) & 0xFFFFFFFF
            frac = (hv % 10000) / 10000.0
            if frac > self.sample:
                return ""  # drop

        # Rate limit
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
            principal_type=_pick("principal_type"),
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
            trust_zone=_pick("trust_zone"),
            route_profile=_pick("route_profile"),
            lockdown_level=_pick("lockdown_level"),
            threat_label=_pick("threat_label"),
            threat_vector=_pick("threat_vector"),
            chain_id=_pick("chain_id"),
            pq_scheme=_pick("pq_scheme"),
            pq_required=_pick("pq_required"),
            pq_ok=_pick("pq_ok"),
            pq_chain_id=_pick("pq_chain_id"),
            supply_chain_ref=_pick("supply_chain_ref"),
            override_applied=_pick("override_applied"),
            override_actor=_pick("override_actor"),
            override_level=_pick("override_level"),
            policy_ref=_pick("policy_ref"),
        )

        # Exception info
        if record.exc_info and self.include_stack:
            exc_type, exc_val, exc_tb = record.exc_info
            evt["exc_type"] = getattr(exc_type, "__name__", str(exc_type))
            evt["exc_message"] = str(exc_val)[:_MAX_FIELD]
            evt["stack"] = "".join(
                traceback.format_exception(exc_type, exc_val, exc_tb)
            )[:_MAX_FIELD]

        # Normalize envelope and enforce vocab/PII/numeric constraints
        self._normalize_envelope(evt)

        # Collect remaining metadata from record.__dict__ into a sanitized "meta" field
        meta = _sanitize_meta_from_record(record, evt_keys=set(evt.keys()))
        if meta:
            evt["meta"] = meta

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
    Configure root (+ optionally uvicorn) for JSON output with content-agnostic fields.
    """
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)
    stream = stream or sys.stderr

    fmt = JSONFormatter(
        include_stack=include_stack, sample=sample, rate_key_fn=rate_key_fn
    )
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

    Only uses header values as opaque IDs; does not log or inspect request bodies.
    """
    rid = None
    if headers:
        # header keys may vary in case
        for k in ("x-request-id", "X-Request-Id", "x-amzn-trace-id"):
            if k.lower() in headers:
                rid = headers[k.lower()]
                break
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
    principal_type: Optional[str] = None,
    trust_zone: Optional[str] = None,
    route_profile: Optional[str] = None,
) -> None:
    """
    Bind request-scoped metadata into the logging context.

    All fields are treated as short identifiers or tags. Request/response
    bodies must never be bound here.
    """
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
        principal_type=principal_type,
        trust_zone=trust_zone,
        route_profile=route_profile,
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
    """
    Convenience helper for logging TCD / e-process decisions.

    This function is content-agnostic:
      - It only logs numeric signals and small tags.
      - It does not log prompts, completions, or any raw request bodies.
    """
    ev = _finite_float(e_value)
    if ev is not None and ev < 0.0:
        ev = None

    aa = _finite_float(alpha_alloc)
    if aa is not None:
        if aa < 0.0 or aa > 1.0:
            aa = max(0.0, min(1.0, aa))

    sc = _finite_float(score)
    if sc is not None:
        sc = max(0.0, min(1.0, sc))

    extra_dict: Dict[str, Any] = {
        "verdict": bool(verdict),
        "e_value": ev,
        "a_alloc": aa,
        "score": sc,
    }
    if extra:
        for k, v in extra.items():
            if v is None:
                continue
            key = str(k)
            if key.lower() in _FORBIDDEN_META_KEYS:
                # Drop any extra fields that look like raw content carriers
                continue
            extra_dict[key] = _truncate(v)

    # Optionally run structured sanitization for decision extras
    if _LOG_SANITIZE_META:
        try:
            cfg = SanitizeConfig(
                sanitize_nan=True,
                prune_large=True,
                strip_pii=_LOG_STRIP_PII,
                forbid_keys=tuple(_FORBIDDEN_META_KEYS),
            )
            sanitized = sanitize_metadata_for_receipt(extra_dict, config=cfg)
            if isinstance(sanitized, Mapping):
                extra_dict = dict(sanitized)
        except Exception:
            # If sanitization fails, keep already filtered/truncated extras
            pass

    logger.log(level, message, extra=extra_dict)


def log_security_event(
    logger: logging.Logger,
    *,
    threat_label: str,
    threat_vector: Optional[str] = None,
    severity: Optional[float] = None,
    supply_chain_ref: Optional[str] = None,
    override_applied: Optional[bool] = None,
    override_actor: Optional[str] = None,
    override_level: Optional[str] = None,
    pq_scheme: Optional[str] = None,
    pq_ok: Optional[bool] = None,
    chain_id: Optional[str] = None,
    message: str = "security_event",
    extra: Optional[Dict[str, Any]] = None,
    level: int = logging.WARNING,
) -> None:
    """
    Unified security event logger for threat / override / supply-chain / PQ events.

    All fields are small tags or numeric signals; no raw content is logged.
    """
    sev = _finite_float(severity)
    if sev is not None:
        sev = max(0.0, min(1.0, sev))

    extra_dict: Dict[str, Any] = {
        "threat_label": threat_label,
        "threat_vector": threat_vector,
        "severity": sev,
        "supply_chain_ref": supply_chain_ref,
        "override_applied": override_applied,
        "override_actor": override_actor,
        "override_level": override_level,
        "pq_scheme": pq_scheme,
        "pq_ok": pq_ok,
        "chain_id": chain_id,
    }

    if extra:
        for k, v in extra.items():
            if v is None:
                continue
            key = str(k)
            if key.lower() in _FORBIDDEN_META_KEYS:
                continue
            extra_dict[key] = _truncate(v)

    # Run metadata sanitization to align with receipt / trust-graph posture
    if _LOG_SANITIZE_META:
        try:
            cfg = SanitizeConfig(
                sanitize_nan=True,
                prune_large=True,
                strip_pii=_LOG_STRIP_PII,
                forbid_keys=tuple(_FORBIDDEN_META_KEYS),
            )
            sanitized = sanitize_metadata_for_receipt(extra_dict, config=cfg)
            if isinstance(sanitized, Mapping):
                extra_dict = dict(sanitized)
        except Exception:
            pass

    logger.log(level, message, extra=extra_dict)


# ---------- ASGI middleware (structured request logs, no uvicorn deps) ----------
class RequestLogMiddleware:
    """
    Lightweight ASGI middleware that emits JSON request start/finish lines with:
      req_id, method, path, status, latency_ms, bytes_in/out, and scrubbed headers (optional).

    It never logs request or response bodies, only sizes. Headers are scrubbed
    via `scrub_dict` to avoid leaking obvious secrets.
    Usage:
        app.add_middleware(RequestLogMiddleware, log_headers=False)
    """

    def __init__(
        self,
        app,
        *,
        logger_name: str = "tcd.http",
        log_headers: bool = False,
    ):
        self.app = app
        self.log = logging.getLogger(logger_name)
        self.log_headers = bool(log_headers)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        # Extract minimal info
        method = scope.get("method", "")
        path = scope.get("path", "")
        headers = {
            k.decode("latin1").lower(): v.decode("latin1")
            for k, v in (scope.get("headers") or [])
        }
        rid = ensure_request_id(headers)

        # Bind request meta (no bodies), default to internet + inference
        bind_request_meta(
            path=path,
            method=method,
            trust_zone=headers.get("x-tcd-trust-zone") or "internet",
            route_profile=headers.get("x-tcd-route-profile") or "inference",
        )

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

        # bytes_in estimation (best-effort, no body logging)
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
            # Clear request-scoped keys to avoid leakage across coroutines
            unbind("path", "method", "status", "bytes_in", "bytes_out")


# ---------- Convenience: module-level logger ----------
_logger: Optional[logging.Logger] = None


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
    "bind",
    "unbind",
    "reset",
    "context",
    "configure_json_logging",
    "get_logger",
    "ensure_request_id",
    "bind_request_meta",
    "log_decision",
    "log_security_event",
    "JSONFormatter",
    "RequestLogMiddleware",
    "scrub_dict",
]