# FILE: tcd/logging.py
from __future__ import annotations

"""
TCD Structured Logging (L7++ hardened)

This file applies the user's full checklist upgrades on top of the prior L7+ version.

Key upgrades (mapped to the checklist):

A) Hard logic bugs / behavior mismatches
  - A.1: True token-bucket rate limiter (float rate supported; monotonic clock).
  - A.2: RequestLogMiddleware(log_headers=True) now actually logs scrubbed headers:
        uses key "http_hdrs" (NOT "headers") so it is not dropped by forbidden-key scan.
  - A.3: log_decision/log_security_event now reject LogRecord reserved keys in extra
        to prevent KeyError crashes.
  - A.4: Unicode surrogate (Cs) + Zl/Zp + U+2028/U+2029 removed; PII hashing is fail-safe.
  - A.5: bind() normalizes values to small JSON-safe scalars to avoid context bloat.

B) PII / secrets / high-card governance
  - B.1: pre-hash detection tightened (no base64url “token-like” pass-through).
  - B.2: PII digest includes key name (domain separation per-field).
  - B.3: optional pii_key_id added (safe tag-like id).
  - B.4: external profile normalizes path/route/task/lang (drop or normalize; strip query).
  - B.5: secret-like value redaction for msg/exc/path/meta strings (strong patterns).

C) Unicode/log-forgery hardening
  - C.1: strips Cc/Cf/Cs/Zl/Zp + explicit U+2028/U+2029
  - C.2: meta keys normalized to lowercase; collisions handled deterministically.

D) Schema discipline
  - D.1: strong envelope schema: method/status/path/bytes/latency normalization.
  - D.2: env-driven cfg fields sanitized/tag-guarded (external stricter).
  - D.3: config sets are immutable (frozenset).

E) Sampling/rate-limit robustness
  - E.1: rate limiter key-space cap + TTL cleanup.
  - E.2: monotonic clock, not time.time().
  - E.3: sampling hash includes req_id/trace_id when available (no msg str()).

F) Meta strategy
  - F.1: if caller uses extra={"meta": {...}}, merge its mapping into meta (no double nesting).
  - F.2: value-side content/secret guard for strings (external stricter).
  - F.3: meta whitelist outputs normalized lowercase keys.

G) Never-crash guarantee
  - G.1: normalize-envelopes wrapped in try/except with fail-closed drop + flag.
  - G.2: minimal fallback is fully sanitized.

H) Perf
  - H.1: unicode scans only on non-ascii strings.
  - H.2: config snapshot cached with short TTL (no import-time latching).
  - H.3: meta shrink avoids O(n^2) json.dumps loops.

I) Middleware semantics
  - I.1: http.finish includes error + exc_type (low-card) and inferred status handling.
  - I.2: clamps bytes/latency with *_clamped flags (low-card).

J) Self-reporting + drop/redact counters
  - J.1: optional one-time "logging.config" line at configure (knobbed).
  - J.2: optional Prometheus counters (no-op when prometheus_client absent).

NOTE:
  - Standard logging contract: record.getMessage() may call str() on record.msg/args.
    Everything else is hardened to avoid calling str()/repr() on arbitrary objects.
"""

import contextvars
import datetime as _dt
import json
import logging
import os
import sys
import time
import traceback
import uuid
import hmac
import hashlib
import math
import re
import unicodedata
import threading
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple, Callable, Mapping, FrozenSet, Set, Iterable

# ---------- Optional OpenTelemetry ----------
try:
    from opentelemetry import trace as _otel_trace  # type: ignore

    _HAS_OTEL = True
except Exception:  # pragma: no cover
    _HAS_OTEL = False

# ---------- Optional Prometheus metrics (no-op if missing) ----------
try:
    from prometheus_client import Counter  # type: ignore

    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False


class _NopMetric:
    def labels(self, *_, **__):
        return self

    def inc(self, *_, **__):
        pass


if _HAS_PROM:
    _LOG_DROPPED = Counter("tcd_log_dropped_total", "Dropped log lines", ["reason"])
    _LOG_REDACTED = Counter("tcd_log_redacted_total", "Redactions applied", ["reason"])
    _LOG_META_DROPPED = Counter("tcd_log_meta_dropped_total", "Meta fields dropped", ["reason"])
else:  # pragma: no cover
    _LOG_DROPPED = _NopMetric()
    _LOG_REDACTED = _NopMetric()
    _LOG_META_DROPPED = _NopMetric()

# ---------- Structured metadata sanitization (reuses utils) ----------
from .utils import (  # noqa: E402
    SanitizeConfig,
    sanitize_metadata_for_receipt,
)

# ---------------------------------------------------------------------------
# Env helpers + config snapshot
# ---------------------------------------------------------------------------

Profile = str  # "internal" | "external"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    s = str(raw).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = int(str(raw).strip())
    except Exception:
        return default
    if v < min_v:
        return min_v
    if v > max_v:
        return max_v
    return v


def _env_float(name: str, default: float, *, min_v: float, max_v: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = float(str(raw).strip())
    except Exception:
        return default
    if not math.isfinite(v):
        return default
    if v < min_v:
        return min_v
    if v > max_v:
        return max_v
    return v


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip()


def _parse_key_material(s: str) -> Optional[bytes]:
    """
    Parse secret key material from env:
      - hex (even length) OR
      - base64/url-safe base64 OR
      - raw utf-8 string (last resort)
    """
    if not s:
        return None
    ss = s.strip()
    if not ss:
        return None

    hexd = re.fullmatch(r"[0-9a-fA-F]+", ss)
    if hexd and len(ss) % 2 == 0:
        try:
            return bytes.fromhex(ss)
        except Exception:
            pass

    try:
        import base64

        padded = ss + "=" * ((4 - (len(ss) % 4)) % 4)
        b = base64.urlsafe_b64decode(padded.encode("ascii", errors="strict"))
        if b:
            return b
    except Exception:
        pass

    try:
        return ss.encode("utf-8", errors="strict")
    except Exception:
        return None


# --- token-based forbidden key scan (camelCase aware) ---
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ALPHA_DIGIT_BOUNDARY_RE = re.compile(r"(?<=[a-zA-Z])(?=\d)|(?<=\d)(?=[a-zA-Z])")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")
_ASCII_CTRL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")

# Tag-like (identifiers)
_TAGLIKE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_META_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,63}$")
_REQID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,63}$")
_HASHED_TAG_PREFIX_RE = re.compile(r"^(tenant|user|session|override_actor)-h-[0-9a-f]{16}$")

# Amazon trace header: Root=...; (extract Root token)
_AMZN_ROOT_RE = re.compile(r"(?:^|;)\s*Root=([A-Za-z0-9._:-]{8,128})\s*(?:;|$)")

# Strong secret markers (value-side redaction)
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b", re.IGNORECASE)
_AUTHZ_RE = re.compile(r"\bAuthorization\s*:\s*\S+", re.IGNORECASE)

# Text-like heuristic for meta values (external): likely content, not an identifier
_TEXTLIKE_RE = re.compile(r"\s{2,}|\n|\r|\t")

# Forbidden meta keys (content-bearing)
_DEFAULT_FORBIDDEN_META_KEYS: FrozenSet[str] = frozenset(
    {
        "prompt",
        "completion",
        "input_text",
        "output_text",
        "messages",
        "message",
        "content",
        "raw",
        "body",
        "payload",
        "request",
        "response",
        "headers",
        "header",
        "cookies",
        "cookie",
        "authorization",
        "auth",
        "bearer",
        "api_key",
        "apikey",
        "secret",
        "private_key",
        "password",
        "token",
    }
)

# Redaction keys (case-insensitive, for headers / obvious secrets)
_DEFAULT_REDACT: FrozenSet[str] = frozenset(
    {
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
)

# Allowed meta keys when whitelist mode is enabled (all lowercased)
# NOTE: includes "http_hdrs" to allow middleware header logging (A.2).
_DEFAULT_ALLOWED_META_KEYS: FrozenSet[str] = frozenset(
    {
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
        "status_code",
        "status_inferred",
        "latency_ms",
        "latency_clamped",
        "bytes_in",
        "bytes_out",
        "bytes_in_clamped",
        "bytes_out_clamped",
        "error",
        "exc_type",
        "threat_label",
        "threat_vector",
        "severity",
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
        "trust_zone",
        "route_profile",
        "route",
        "verdict",
        "e_value",
        "a_alloc",
        "score",
        "http_hdrs",
        "pii_key_id",
    }
)

# Vocab constraints for trust / routing / override / PQ posture
_ALLOWED_TRUST_ZONES: FrozenSet[str] = frozenset({"internet", "internal", "partner", "admin", "ops"})
_ALLOWED_ROUTE_PROFILES: FrozenSet[str] = frozenset({"inference", "admin", "control", "metrics", "health"})
_ALLOWED_OVERRIDE_LEVELS: FrozenSet[str] = frozenset({"none", "break_glass", "maintenance"})
_ALLOWED_PQ_SCHEMES: FrozenSet[str] = frozenset({"", "dilithium2", "dilithium3", "falcon", "sphincs+"})

# HTTP method allowlist
_ALLOWED_HTTP_METHODS: FrozenSet[str] = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

# Standard LogRecord attributes that must NOT be set via extra (A.3)
_LOG_RECORD_STD_ATTRS: FrozenSet[str] = frozenset(
    {
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
)


def _key_tokens(s: str) -> Tuple[str, ...]:
    if not s:
        return ()
    t = _CAMEL_BOUNDARY_RE.sub("_", s)
    t = _ALPHA_DIGIT_BOUNDARY_RE.sub("_", t)
    t = t.strip().lower()
    toks = [x for x in _TOKEN_SPLIT_RE.split(t) if x]
    return tuple(toks)


def _has_unsafe_unicode(s: str) -> bool:
    # Only used on non-ascii strings (perf).
    for ch in s:
        # Explicit line/paragraph separators
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        # Cc: control, Cf: format/invisible, Cs: surrogate, Zl/Zp: line/paragraph sep
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False


def _strip_unsafe_text(s: str, *, max_len: int) -> str:
    """
    Remove ASCII control + Unicode Cc/Cf/Cs/Zl/Zp + U+2028/U+2029.
    Perf: ascii-only strings do not pay unicode-category scan.
    """
    if not s:
        return ""
    if len(s) > max_len:
        s = s[:max_len]

    if s.isascii():
        if _ASCII_CTRL_RE.search(s):
            s = _ASCII_CTRL_RE.sub("", s)
        return s

    # non-ascii fast check
    if not _ASCII_CTRL_RE.search(s) and not _has_unsafe_unicode(s):
        return s

    out_chars: list[str] = []
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            continue
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            continue
        out_chars.append(ch)
    return "".join(out_chars)


def _looks_like_secret_strong(s: str) -> bool:
    if not s:
        return False
    if _JWT_RE.search(s):
        return True
    if _PRIVKEY_RE.search(s):
        return True
    if _BEARER_RE.search(s):
        return True
    if _AUTHZ_RE.search(s):
        return True
    return False


def _redact_if_secret(s: str, *, cfg: "LoggingConfig", reason: str) -> str:
    if not cfg.redact_secrets:
        return s
    if _looks_like_secret_strong(s):
        _LOG_REDACTED.labels(reason=reason).inc()
        return "<redacted>"
    return s


def _guard_cfg_tag(value: str, *, profile: Profile, fallback: str) -> str:
    """
    Sanitize env-provided static cfg fields (schema/service/version/env/instance/key_id).
    external: require taglike; internal: allow broader but still safe and bounded.
    """
    v = _strip_unsafe_text(str(value or ""), max_len=128).strip()
    if not v:
        return fallback
    if profile == "external":
        if not _TAGLIKE_RE.fullmatch(v):
            return fallback
    # hard cap anyway
    return v[:128]


@dataclass(frozen=True, slots=True)
class LoggingConfig:
    profile: Profile

    schema: str
    service: str
    version: str
    env: str
    instance: str

    # sampling & rate limit
    sample: float
    rate_limit_per_key_per_sec: float
    rate_limit_burst: float
    rate_limit_state_max_keys: int
    rate_limit_state_ttl_s: float
    always_log_errors: bool

    # sanitization & PII
    include_stack: bool
    sanitize_meta: bool
    strip_pii: bool
    meta_whitelist_mode: bool
    allowed_meta_keys: FrozenSet[str]

    hash_pii_tags: bool
    external_hash_all_pii_tags: bool
    pii_hmac_key: Optional[bytes]
    pii_hmac_min_bytes: int
    pii_key_id: str

    redact_keys: FrozenSet[str]
    forbidden_keys_exact_lower: FrozenSet[str]
    forbidden_key_token_seqs: Tuple[Tuple[str, ...], ...]

    redact_secrets: bool

    # sizing
    max_field_chars: int
    max_meta_items: int
    max_meta_depth: int
    max_meta_nodes: int
    max_event_bytes: int
    max_bytes_value: int
    max_latency_ms: float

    emit_config_line: bool

    @staticmethod
    def from_env() -> "LoggingConfig":
        # Profile alignment across stack: prefer explicit TCD_LOG_PROFILE, else TCD_PROFILE, else ledger profile.
        prof_raw = (
            _env_str("TCD_LOG_PROFILE", "")
            or _env_str("TCD_PROFILE", "")
            or _env_str("TCD_LEDGER_PROFILE", "internal")
        ).lower()
        profile: Profile = "external" if prof_raw == "external" else "internal"

        schema = _guard_cfg_tag(_env_str("TCD_LOG_SCHEMA", "tcd.log.v1"), profile=profile, fallback="tcd.log.v1")
        service = _guard_cfg_tag(_env_str("TCD_SERVICE", "tcd"), profile=profile, fallback="tcd")
        version = _guard_cfg_tag(
            _env_str("TCD_BUILD_VERSION", _env_str("TCD_VERSION", "0.0.0")),
            profile=profile,
            fallback="0.0.0",
        )
        env = _guard_cfg_tag(_env_str("TCD_ENV", _env_str("ENV", "dev")), profile=profile, fallback="dev")

        # Hostname leakage control: external defaults to "unknown" unless explicitly set.
        instance_env = os.getenv("TCD_INSTANCE")
        if instance_env is not None and instance_env.strip():
            instance = _guard_cfg_tag(instance_env.strip(), profile=profile, fallback="unknown")
        else:
            if profile == "external":
                instance = "unknown"
            else:
                try:
                    instance = _guard_cfg_tag(os.uname().nodename, profile=profile, fallback="unknown")  # type: ignore[attr-defined]
                except Exception:
                    instance = "unknown"

        sample = _env_float("TCD_LOG_SAMPLE", 1.0, min_v=0.0, max_v=1.0)

        # A.1: float rates supported; token bucket uses burst capacity.
        rate_limit = _env_float("TCD_LOG_RATE_LIMIT", 0.0, min_v=0.0, max_v=1_000_000.0)
        rate_burst = _env_float(
            "TCD_LOG_RATE_LIMIT_BURST",
            5.0 if profile == "external" else 20.0,
            min_v=1.0,
            max_v=10_000.0,
        )

        # E.1: key-space cap + TTL
        rl_max_keys = _env_int("TCD_LOG_RATE_STATE_MAX_KEYS", 10_000, min_v=256, max_v=1_000_000)
        rl_ttl = _env_float("TCD_LOG_RATE_STATE_TTL_S", 300.0, min_v=10.0, max_v=86_400.0)

        always_log_errors = _env_bool("TCD_LOG_ALWAYS_LOG_ERRORS", True)

        include_stack_default = True if profile == "internal" else False
        include_stack = _env_bool("TCD_LOG_INCLUDE_STACK", include_stack_default)

        sanitize_meta = _env_bool("TCD_LOG_SANITIZE_META", True)
        strip_pii_default = True if profile == "external" else _env_bool("TCD_LOG_STRIP_PII", True)
        strip_pii = _env_bool("TCD_LOG_STRIP_PII", strip_pii_default)

        meta_whitelist_mode = _env_bool("TCD_LOG_META_WHITELIST", False if profile == "internal" else True)
        allowed_meta_keys_raw = {
            k.strip().lower()
            for k in _env_str("TCD_LOG_ALLOWED_META_KEYS", "").split(",")
            if k.strip()
        }
        allowed_meta_keys = frozenset(allowed_meta_keys_raw) if allowed_meta_keys_raw else _DEFAULT_ALLOWED_META_KEYS

        hash_pii_tags = _env_bool("TCD_LOG_HASH_PII_TAGS", True)
        external_hash_all = _env_bool("TCD_LOG_EXTERNAL_HASH_ALL_PII_TAGS", True)

        pii_key_raw = _env_str("TCD_LOG_PII_HMAC_KEY", _env_str("TCD_LEDGER_PII_HMAC_KEY", ""))
        pii_hmac_key = _parse_key_material(pii_key_raw)
        pii_hmac_min_bytes = _env_int("TCD_LOG_PII_HMAC_MIN_BYTES", 16, min_v=8, max_v=4096)

        pii_key_id = _guard_cfg_tag(_env_str("TCD_LOG_PII_HMAC_KEY_ID", ""), profile=profile, fallback="")

        redact_keys_raw = {k.strip().lower() for k in _env_str("TCD_LOG_REDACT", "").split(",") if k.strip()}
        redact_keys = frozenset(redact_keys_raw) if redact_keys_raw else _DEFAULT_REDACT

        # forbidden key detection: exact + token sequences
        forbidden_exact = frozenset({k.strip().lower() for k in _DEFAULT_FORBIDDEN_META_KEYS if k})
        token_seqs: list[Tuple[str, ...]] = []
        for fk in _DEFAULT_FORBIDDEN_META_KEYS:
            toks = _key_tokens(fk)
            if toks:
                token_seqs.append(toks)
        token_seqs = list({ts: None for ts in token_seqs}.keys())

        max_field_chars = _env_int("TCD_LOG_MAX_FIELD", 8192, min_v=512, max_v=1_000_000)
        max_meta_items = _env_int("TCD_LOG_MAX_META_ITEMS", 64, min_v=8, max_v=4096)
        max_meta_depth = _env_int("TCD_LOG_MAX_META_DEPTH", 6 if profile == "external" else 10, min_v=2, max_v=64)
        max_meta_nodes = _env_int(
            "TCD_LOG_MAX_META_NODES", 2048 if profile == "external" else 8192, min_v=128, max_v=1_000_000
        )
        max_event_bytes = _env_int(
            "TCD_LOG_MAX_EVENT_BYTES", 32_768 if profile == "external" else 131_072, min_v=4096, max_v=5_000_000
        )

        # I.2: clamp bytes/latency
        max_bytes_value = _env_int("TCD_LOG_MAX_BYTES_VALUE", 1_000_000_000, min_v=1_000_000, max_v=10_000_000_000)
        max_latency_ms = _env_float("TCD_LOG_MAX_LATENCY_MS", 86_400_000.0, min_v=1_000.0, max_v=604_800_000.0)

        # B.5: redact secret-like values (external default True; internal default False unless enabled)
        redact_secrets_default = True if profile == "external" else False
        redact_secrets = _env_bool("TCD_LOG_REDACT_SECRETS", redact_secrets_default)

        # J.1: emit config line once at configure
        emit_config_line_default = True if profile == "internal" else False
        emit_config_line = _env_bool("TCD_LOG_EMIT_CONFIG_LINE", emit_config_line_default)

        return LoggingConfig(
            profile=profile,
            schema=schema,
            service=service,
            version=version,
            env=env,
            instance=instance,
            sample=sample,
            rate_limit_per_key_per_sec=rate_limit,
            rate_limit_burst=rate_burst,
            rate_limit_state_max_keys=rl_max_keys,
            rate_limit_state_ttl_s=rl_ttl,
            always_log_errors=always_log_errors,
            include_stack=include_stack,
            sanitize_meta=sanitize_meta,
            strip_pii=strip_pii,
            meta_whitelist_mode=meta_whitelist_mode,
            allowed_meta_keys=allowed_meta_keys,
            hash_pii_tags=hash_pii_tags,
            external_hash_all_pii_tags=external_hash_all,
            pii_hmac_key=pii_hmac_key,
            pii_hmac_min_bytes=pii_hmac_min_bytes,
            pii_key_id=pii_key_id,
            redact_keys=redact_keys,
            forbidden_keys_exact_lower=forbidden_exact,
            forbidden_key_token_seqs=tuple(token_seqs),
            redact_secrets=redact_secrets,
            max_field_chars=max_field_chars,
            max_meta_items=max_meta_items,
            max_meta_depth=max_meta_depth,
            max_meta_nodes=max_meta_nodes,
            max_event_bytes=max_event_bytes,
            max_bytes_value=max_bytes_value,
            max_latency_ms=max_latency_ms,
            emit_config_line=emit_config_line,
        )


# ---------------------------------------------------------------------------
# Config cache (H.2): no import-time latching, short TTL snapshot cache
# ---------------------------------------------------------------------------

_CFG_CACHE_LOCK = threading.Lock()
_CFG_CACHE: Optional[Tuple[LoggingConfig, float]] = None  # (cfg, monotonic_ts)
_CFG_TTL_S = 1.0  # short TTL; still “call-time”, but avoids per-log env parsing.


def get_config() -> LoggingConfig:
    now = time.monotonic()
    with _CFG_CACHE_LOCK:
        global _CFG_CACHE
        if _CFG_CACHE is not None:
            cfg, ts = _CFG_CACHE
            if (now - ts) <= _CFG_TTL_S:
                return cfg
        cfg2 = LoggingConfig.from_env()
        _CFG_CACHE = (cfg2, now)
        return cfg2


# ---------------------------------------------------------------------------
# Context management (A.5 bind normalization)
# ---------------------------------------------------------------------------

_log_ctx: contextvars.ContextVar[Dict[str, Any]] = contextvars.ContextVar("tcd_log_ctx", default={})


def _bind_coerce_value(v: Any, cfg: LoggingConfig) -> Any:
    """
    Keep context light-weight: do not store large/complex objects across async boundaries.
    Only store JSON scalars + short safe strings; everything else becomes a short type tag.
    """
    if v is None:
        return None
    if isinstance(v, bool):
        return bool(v)
    if isinstance(v, int) and not isinstance(v, bool):
        if v.bit_length() > 256:
            return None
        return int(v)
    if isinstance(v, float):
        if not math.isfinite(v):
            return None
        return float(v)
    if isinstance(v, str):
        s = _strip_unsafe_text(v, max_len=min(cfg.max_field_chars, 256)).strip()
        s = _redact_if_secret(s, cfg=cfg, reason="bind")
        if len(s) > 256:
            s = s[:256] + "...<truncated>"
        return s
    if isinstance(v, (bytes, bytearray, memoryview)):
        try:
            n = len(v)
        except Exception:
            n = 0
        return f"<{type(v).__name__}:{n}B>"
    # Unknown objects: no str/repr
    return f"<{type(v).__name__}>"


def bind(**fields: Any) -> None:
    """Merge fields into the current logging context (per-coroutine)."""
    cfg = get_config()
    cur = dict(_log_ctx.get())
    for k, v in fields.items():
        if v is None:
            continue
        if not isinstance(k, str):
            continue
        if not k or k.startswith("_"):
            continue
        if len(k) > 64:
            continue
        vv = _bind_coerce_value(v, cfg)
        if vv is None:
            continue
        cur[k] = vv
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


# ---------------------------------------------------------------------------
# OpenTelemetry helpers
# ---------------------------------------------------------------------------


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
    now = _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc)
    ms = int(now.microsecond / 1000)
    base = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return f"{base[:-1]}.{ms:03d}Z"


# ---------------------------------------------------------------------------
# JSON-safe coercion (no str()/repr() on arbitrary objects)
# ---------------------------------------------------------------------------


def _finite_float(x: Any) -> Optional[float]:
    try:
        xf = float(x)
    except Exception:
        return None
    if not math.isfinite(xf):
        return None
    return xf


def _json_safe_value(v: Any, cfg: LoggingConfig, *, depth: int = 0, nodes: int = 0, key_hint: str = "") -> Tuple[Any, int]:
    """
    Convert any value to something json.dumps can serialize, without calling
    str()/repr() on arbitrary objects.
    Returns (safe_value_or_None, updated_node_count).

    key_hint is used only for value-side redaction decisions (F.2/B.5) without leaking content.
    """
    nodes += 1
    if nodes > cfg.max_meta_nodes:
        _LOG_META_DROPPED.labels(reason="meta_nodes_limit").inc()
        return ("<truncated>", nodes)
    if depth > cfg.max_meta_depth:
        _LOG_META_DROPPED.labels(reason="meta_depth_limit").inc()
        return ("<truncated>", nodes)

    if v is None or isinstance(v, bool):
        return (v, nodes)

    if isinstance(v, int) and not isinstance(v, bool):
        if v.bit_length() > 256:
            _LOG_META_DROPPED.labels(reason="int_too_large").inc()
            return (None, nodes)
        return (v, nodes)

    if isinstance(v, float):
        if not math.isfinite(v):
            _LOG_META_DROPPED.labels(reason="non_finite_float").inc()
            return (None, nodes)
        return (v, nodes)

    if isinstance(v, str):
        s = _strip_unsafe_text(v, max_len=cfg.max_field_chars).strip()
        # Value-side secret redaction (strong patterns)
        s = _redact_if_secret(s, cfg=cfg, reason="string_value")
        # External: drop text-like meta strings (content-ish)
        if cfg.profile == "external":
            if _TEXTLIKE_RE.search(s):
                _LOG_META_DROPPED.labels(reason="textlike_string").inc()
                return (None, nodes)
        if len(s) > cfg.max_field_chars:
            s = s[: cfg.max_field_chars] + "...<truncated>"
        return (s, nodes)

    if isinstance(v, (bytes, bytearray, memoryview)):
        try:
            n = len(v)
        except Exception:
            n = 0
        return (f"<{type(v).__name__}:{n}B>", nodes)

    if isinstance(v, Mapping):
        out: Dict[str, Any] = {}
        items = 0
        for kk, vv in v.items():
            if items >= cfg.max_meta_items:
                out["<truncated>"] = True
                break
            if not isinstance(kk, str):
                continue
            kks = _strip_unsafe_text(kk, max_len=64).strip().lower()
            if not kks or not _META_KEY_RE.fullmatch(kks):
                _LOG_META_DROPPED.labels(reason="bad_meta_key").inc()
                continue
            safe_v, nodes = _json_safe_value(vv, cfg, depth=depth + 1, nodes=nodes, key_hint=kks)
            if safe_v is None:
                continue
            # collision: keep first deterministically
            if kks in out:
                _LOG_META_DROPPED.labels(reason="key_collision").inc()
                continue
            out[kks] = safe_v
            items += 1
        return (out, nodes)

    if isinstance(v, (list, tuple, set)):
        out_list: list[Any] = []
        items = 0
        for it in v:
            if items >= cfg.max_meta_items:
                out_list.append("<truncated>")
                break
            safe_it, nodes = _json_safe_value(it, cfg, depth=depth + 1, nodes=nodes, key_hint=key_hint)
            if safe_it is None:
                continue
            out_list.append(safe_it)
            items += 1
        return (out_list, nodes)

    return (f"<{type(v).__name__}>", nodes)


def _compact_json(evt: Dict[str, Any]) -> str:
    return json.dumps(evt, ensure_ascii=False, separators=(",", ":"), sort_keys=False, allow_nan=False)


# ---------------------------------------------------------------------------
# Forbidden key detection (token-based)
# ---------------------------------------------------------------------------


def _is_forbidden_key_name(key: str, cfg: LoggingConfig) -> bool:
    k = (key or "").strip()
    if not k:
        return False
    kl = k.lower()
    if kl in cfg.forbidden_keys_exact_lower:
        return True

    toks = _key_tokens(k)
    if not toks:
        return False

    for seq in cfg.forbidden_key_token_seqs:
        if not seq:
            continue
        if len(seq) == 1:
            if seq[0] in toks:
                return True
            continue
        n = len(seq)
        for i in range(0, len(toks) - n + 1):
            if toks[i : i + n] == seq:
                return True
    return False


# ---------------------------------------------------------------------------
# PII tag hashing (domain-separated) — tightened prehash (B.1/B.2/A.4)
# ---------------------------------------------------------------------------

_PII_TAG_KEYS: Tuple[str, ...] = ("tenant", "user", "session", "override_actor")
_PII_PLACEHOLDERS: FrozenSet[str] = frozenset({"", "*", "unknown", "unk", "anon", "anonymous", "na", "n/a", "none"})
_HEX64_LOWER_RE = re.compile(r"^[0-9a-f]{64}$")


def _is_prehashed_identifier(v: str, *, cfg: LoggingConfig) -> bool:
    vv = (v or "").strip()
    if not vv:
        return False
    if _HASHED_TAG_PREFIX_RE.fullmatch(vv):
        return True
    # Tightened: only accept 64-char lowercase hex as "already hashed"
    if _HEX64_LOWER_RE.fullmatch(vv):
        return True
    # internal could optionally accept more, but we keep it tight to avoid token pass-through
    return False


def _pii_digest(value: str, *, cfg: LoggingConfig, key_name: str, domain: bytes) -> Optional[str]:
    """
    Domain-separated digest. Includes key_name in message (B.2).
    external: requires sufficiently long HMAC key; if absent -> None.
    """
    try:
        v = (value or "").strip()
        if not v:
            return None
        # Ensure no unsafe unicode before encoding
        v = _strip_unsafe_text(v, max_len=512)
        msg = domain + b"|" + key_name.encode("ascii", errors="ignore") + b"|" + v.encode("utf-8", errors="strict")

        if cfg.pii_hmac_key is not None and len(cfg.pii_hmac_key) >= cfg.pii_hmac_min_bytes:
            mac = hmac.new(cfg.pii_hmac_key, msg, hashlib.blake2s).hexdigest()
            return mac[:16]

        if cfg.profile == "external":
            return None

        return hashlib.blake2s(msg).hexdigest()[:16]
    except Exception:
        return None


def _hash_pii_tag_value(key: str, raw_value: Any, cfg: LoggingConfig) -> str:
    """
    external: hash-all (unless placeholder/prehashed) with HMAC key; else key-h-anon
    internal: heuristic (still strong), but we keep behavior safe.
    """
    # Coerce small ints into strings for hashing rather than leaking raw ints
    if isinstance(raw_value, int) and not isinstance(raw_value, bool):
        if raw_value.bit_length() <= 256:
            raw_value = str(int(raw_value))
        else:
            return f"{key}-h-anon" if cfg.profile == "external" else "anon"

    if not isinstance(raw_value, str):
        # Drop unsafe type: do not call str()
        return f"{key}-h-anon" if cfg.profile == "external" else "anon"

    v0 = _strip_unsafe_text(raw_value, max_len=cfg.max_field_chars).strip()
    if not v0:
        return ""
    if v0.lower() in _PII_PLACEHOLDERS:
        return v0
    if _is_prehashed_identifier(v0, cfg=cfg):
        return v0

    if cfg.profile == "external" and cfg.external_hash_all_pii_tags:
        d = _pii_digest(v0, cfg=cfg, key_name=key, domain=b"TCD|log|pii|tag|v2")
        if not d:
            _LOG_REDACTED.labels(reason="pii_hash_no_key").inc()
            return f"{key}-h-anon"
        return f"{key}-h-{d}"

    # internal: conservative heuristic
    looks_like_email = "@" in v0
    looks_like_name = (" " in v0) or ("\u3000" in v0)
    high_card = len(v0) >= 24
    if looks_like_email or looks_like_name or high_card:
        d = _pii_digest(v0, cfg=cfg, key_name=key, domain=b"TCD|log|pii|tag|v2")
        if not d:
            return f"{key}-h-anon"
        return f"{key}-h-{d}"

    return v0


# ---------------------------------------------------------------------------
# Header scrubbing (A.2 + B.5)
# ---------------------------------------------------------------------------


def scrub_dict(d: Dict[str, Any], *, cfg: Optional[LoggingConfig] = None) -> Dict[str, Any]:
    """
    Scrub obvious secrets from a dict (typically HTTP headers).

    - Keys in cfg.redact_keys dropped entirely (not just "***") to avoid forbidden-key triggers.
      (We still retain enough info via other headers, but never log Authorization-like keys.)
    - Values are sanitized + secret-redacted + truncated.
    """
    cfg = cfg or get_config()
    out: Dict[str, Any] = {}
    for k, v in (d or {}).items():
        if not isinstance(k, str):
            continue
        kl = _strip_unsafe_text(k, max_len=64).strip().lower()
        if not kl:
            continue
        if kl in cfg.redact_keys:
            continue
        if isinstance(v, dict):
            out[kl] = scrub_dict(v, cfg=cfg)
            continue
        sv, _ = _json_safe_value(v, cfg, depth=0, nodes=0, key_hint=kl)
        if sv is None:
            continue
        if isinstance(sv, str):
            sv = _redact_if_secret(sv, cfg=cfg, reason="header_value")
        out[kl] = sv
    return out


# ---------------------------------------------------------------------------
# Meta collection + sanitization (F.1/F.3/H.3)
# ---------------------------------------------------------------------------


def _sanitize_meta_from_record(
    record: logging.LogRecord,
    cfg: LoggingConfig,
    evt_keys: Optional[Set[str]] = None,
) -> Optional[Dict[str, Any]]:
    evt_keys = evt_keys or set()

    # Gather raw meta candidates
    raw_meta: Dict[str, Any] = {}
    meta_expanded: Dict[str, Any] = {}

    for k, v in record.__dict__.items():
        if k in _LOG_RECORD_STD_ATTRS:
            continue
        if k in evt_keys:
            continue
        if not isinstance(k, str):
            continue
        if k.startswith("_") or k == "message":
            continue

        # F.1: if caller uses extra={"meta": {...}}, merge mapping instead of nesting
        if k == "meta" and isinstance(v, Mapping):
            for mk, mv in v.items():
                if not isinstance(mk, str):
                    continue
                mkl = _strip_unsafe_text(mk, max_len=64).strip().lower()
                if not mkl or mkl in evt_keys:
                    continue
                meta_expanded[mkl] = mv
            continue

        raw_meta[k] = v

    # Merge expanded meta first (deterministic precedence: explicit meta mapping wins)
    merged_candidates: Dict[str, Any] = dict(meta_expanded)
    for k, v in raw_meta.items():
        kl = _strip_unsafe_text(k, max_len=64).strip().lower()
        if not kl:
            continue
        if kl in merged_candidates:
            continue
        merged_candidates[kl] = v

    if not merged_candidates:
        return None

    # 1) filter keys (forbidden + whitelist + key regex)
    filtered: Dict[str, Any] = {}
    for kl, v in merged_candidates.items():
        if not _META_KEY_RE.fullmatch(kl):
            _LOG_META_DROPPED.labels(reason="bad_meta_key").inc()
            continue
        if _is_forbidden_key_name(kl, cfg):
            _LOG_META_DROPPED.labels(reason="forbidden_key").inc()
            continue
        if cfg.meta_whitelist_mode and kl not in cfg.allowed_meta_keys:
            _LOG_META_DROPPED.labels(reason="whitelist").inc()
            continue
        filtered[kl] = v

    if not filtered:
        return None

    # 2) JSON-safe coercion
    safe_meta: Dict[str, Any] = {}
    items = 0
    nodes = 0
    for kl in sorted(filtered.keys()):
        if items >= cfg.max_meta_items:
            safe_meta["truncated"] = True
            _LOG_META_DROPPED.labels(reason="meta_items_limit").inc()
            break
        sv, nodes = _json_safe_value(filtered[kl], cfg, depth=0, nodes=nodes, key_hint=kl)
        if sv is None:
            continue
        safe_meta[kl] = sv
        items += 1

    if not safe_meta:
        return None

    # 3) Optional structured sanitization via utils (best-effort)
    if cfg.sanitize_meta:
        try:
            scfg = SanitizeConfig(
                sanitize_nan=True,
                prune_large=True,
                strip_pii=cfg.strip_pii,
                forbid_keys=tuple(_DEFAULT_FORBIDDEN_META_KEYS),
            )
            sanitized = sanitize_metadata_for_receipt(safe_meta, config=scfg)
            if isinstance(sanitized, Mapping):
                # normalize keys to lowercase again (in case sanitizer changed casing)
                tmp: Dict[str, Any] = {}
                for k, v in sanitized.items():
                    if not isinstance(k, str):
                        continue
                    kk = _strip_unsafe_text(k, max_len=64).strip().lower()
                    if not kk or not _META_KEY_RE.fullmatch(kk):
                        continue
                    if kk in tmp:
                        continue
                    tmp[kk] = v
                safe_meta = tmp
        except Exception:
            pass

    # 4) Budget clamp without O(n^2) dumps (H.3)
    budget = max(512, cfg.max_event_bytes // 2)

    def _rough_size(obj: Any) -> int:
        # very rough; good enough to stop runaway growth before json.dumps
        if obj is None:
            return 4
        if isinstance(obj, bool):
            return 5
        if isinstance(obj, int):
            return 24
        if isinstance(obj, float):
            return 24
        if isinstance(obj, str):
            return min(len(obj), 256) + 2
        if isinstance(obj, dict):
            return sum(_rough_size(k) + _rough_size(v) + 2 for k, v in obj.items())
        if isinstance(obj, list):
            return sum(_rough_size(x) + 1 for x in obj)
        return 16

    # Pre-shrink by rough size
    approx = 2
    shrunk: Dict[str, Any] = {}
    for k in sorted(safe_meta.keys()):
        v = safe_meta[k]
        add = _rough_size(k) + _rough_size(v) + 2
        if approx + add > budget:
            _LOG_META_DROPPED.labels(reason="meta_budget").inc()
            break
        shrunk[k] = v
        approx += add

    if not shrunk:
        return None

    # Verify with one json.dumps; if still too big, drop last keys until fits
    try:
        s = json.dumps(shrunk, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        b = s.encode("utf-8", errors="strict")
        while len(b) > budget and shrunk:
            # drop largest key deterministically (last in sorted order)
            last_k = sorted(shrunk.keys())[-1]
            shrunk.pop(last_k, None)
            _LOG_META_DROPPED.labels(reason="meta_budget").inc()
            s = json.dumps(shrunk, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
            b = s.encode("utf-8", errors="strict")
        if not shrunk:
            return None
    except Exception:
        return None

    return shrunk


# ---------------------------------------------------------------------------
# Filters (sampling + true token bucket rate limit)
# ---------------------------------------------------------------------------


class SamplingFilter(logging.Filter):
    def __init__(self, cfg: LoggingConfig):
        super().__init__()
        self.cfg = cfg

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        if self.cfg.always_log_errors and record.levelno >= logging.ERROR:
            return True
        if self.cfg.sample >= 1.0:
            return True
        if self.cfg.sample <= 0.0:
            _LOG_DROPPED.labels(reason="sample").inc()
            return False

        # E.3: include req_id/trace_id when available; do NOT call str(record.msg).
        rid = getattr(record, "req_id", None)
        if not isinstance(rid, str):
            rid = None
        tid = getattr(record, "trace_id", None)
        if not isinstance(tid, str):
            tid = None

        s = f"{record.name}|{record.levelno}|{rid or tid or ''}|{getattr(record, 'pathname', '')}|{getattr(record, 'lineno', 0)}"
        hv = 0x811C9DC5
        for ch in s:
            hv = ((hv ^ ord(ch)) * 0x01000193) & 0xFFFFFFFF
        frac = (hv % 10000) / 10000.0
        ok = frac <= self.cfg.sample
        if not ok:
            _LOG_DROPPED.labels(reason="sample").inc()
        return ok


class RateLimitFilter(logging.Filter):
    """
    True token-bucket per key (float rates supported), thread-safe, monotonic clock.

    E.1: caps key-state size + TTL cleanup to avoid unbounded growth.
    """
    def __init__(self, cfg: LoggingConfig, key_fn: Optional[Callable[[logging.LogRecord], str]] = None):
        super().__init__()
        self.cfg = cfg
        self.key_fn = key_fn
        self._lock = threading.Lock()
        # key -> (tokens, last_ts_mono, last_seen_mono)
        self._state: Dict[str, Tuple[float, float, float]] = {}
        self._last_cleanup = 0.0

    def _cleanup(self, now: float) -> None:
        ttl = float(self.cfg.rate_limit_state_ttl_s)
        max_keys = int(self.cfg.rate_limit_state_max_keys)

        if (now - self._last_cleanup) < 30.0:
            return
        self._last_cleanup = now

        # TTL prune
        if ttl > 0:
            dead = [k for k, (_t, _last, seen) in self._state.items() if (now - seen) > ttl]
            for k in dead:
                self._state.pop(k, None)

        # Hard cap prune: drop least recently seen deterministically
        if len(self._state) > max_keys:
            items = sorted(self._state.items(), key=lambda kv: kv[1][2])  # by last_seen
            for k, _ in items[: max(0, len(self._state) - max_keys)]:
                self._state.pop(k, None)

    def filter(self, record: logging.LogRecord) -> bool:  # type: ignore[override]
        if self.cfg.always_log_errors and record.levelno >= logging.ERROR:
            return True
        rate = float(self.cfg.rate_limit_per_key_per_sec)
        if rate <= 0.0:
            return True

        key = self.key_fn(record) if self.key_fn else record.name
        if not isinstance(key, str) or not key:
            key = record.name
        # keep key bounded
        if len(key) > 128:
            key = key[:128]

        now = time.monotonic()
        cap = float(max(1.0, self.cfg.rate_limit_burst))

        with self._lock:
            self._cleanup(now)

            tokens, last_ts, last_seen = self._state.get(key, (cap, now, now))
            dt = now - last_ts
            if dt < 0:
                dt = 0.0
            tokens = min(cap, tokens + rate * dt)

            if tokens < 1.0:
                self._state[key] = (tokens, now, now)
                _LOG_DROPPED.labels(reason="rate_limit").inc()
                return False

            tokens -= 1.0
            self._state[key] = (tokens, now, now)
            return True


# ---------------------------------------------------------------------------
# JSON formatter + envelope normalization (D.1/B.4/G.1)
# ---------------------------------------------------------------------------


def _safe_record_message(record: logging.LogRecord, cfg: LoggingConfig) -> str:
    try:
        msg = record.getMessage()
    except Exception:
        msg = "<unprintable log message>"
    if not isinstance(msg, str):
        msg = "<unprintable log message>"
    msg = _strip_unsafe_text(msg, max_len=cfg.max_field_chars).strip()
    msg = _redact_if_secret(msg, cfg=cfg, reason="msg")
    if len(msg) > cfg.max_field_chars:
        msg = msg[: cfg.max_field_chars] + "...<truncated>"
    return msg


def _merge_optional(evt: Dict[str, Any], cfg: LoggingConfig, **kvs: Any) -> None:
    for k, v in kvs.items():
        if v is None:
            continue
        sv, _ = _json_safe_value(v, cfg, depth=0, nodes=0, key_hint=str(k))
        if sv is None:
            continue
        evt[k] = sv


def _coerce_small_str(v: Any, *, cfg: LoggingConfig, max_len: int = 256) -> Optional[str]:
    if isinstance(v, str):
        s = _strip_unsafe_text(v, max_len=max_len).strip()
        if not s:
            return None
        return s
    if isinstance(v, int) and not isinstance(v, bool):
        if v.bit_length() <= 256:
            return str(int(v))
    return None


def _normalize_method(v: Any) -> Optional[str]:
    if not isinstance(v, str):
        return None
    m = v.strip().upper()
    if m in _ALLOWED_HTTP_METHODS:
        return m
    return None


_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEXLIKE_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_B64URLISH_RE = re.compile(r"^[A-Za-z0-9_-]{16,}$")


def _normalize_path_external(path: str) -> str:
    # strip query/fragment
    for sep in ("?", "#"):
        i = path.find(sep)
        if i >= 0:
            path = path[:i]
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path

    # segment normalization: replace id-like segments with "<id>"
    parts = [p for p in path.split("/") if p]
    norm: list[str] = []
    for p in parts[:64]:
        if len(p) >= 16 and (_UUID_RE.fullmatch(p) or _HEXLIKE_RE.fullmatch(p) or _B64URLISH_RE.fullmatch(p)):
            norm.append("<id>")
        elif len(p) >= 64 and _HEXLIKE_RE.fullmatch(p):
            norm.append("<hash>")
        else:
            # keep small safe segment
            seg = _strip_unsafe_text(p, max_len=64)
            if not seg or _TEXTLIKE_RE.search(seg):
                norm.append("<seg>")
            else:
                norm.append(seg)
    return "/" + "/".join(norm)


_LANG_RE = re.compile(r"^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})?$")


class JSONFormatter(logging.Formatter):
    """
    JSON formatter with stable envelope and content-agnostic meta.
    """

    def __init__(self, *, cfg: Optional[LoggingConfig] = None):
        super().__init__()
        self.cfg = cfg or get_config()

    def _normalize_envelope(self, evt: Dict[str, Any]) -> None:
        cfg = self.cfg

        # B.3: include pii_key_id (safe tag) if configured
        if cfg.pii_key_id:
            evt["pii_key_id"] = cfg.pii_key_id

        # PII tag hashing (accept ints too; drop others)
        if cfg.hash_pii_tags:
            for fld in _PII_TAG_KEYS:
                if fld in evt:
                    evt[fld] = _hash_pii_tag_value(fld, evt.get(fld), cfg)

        # vocab constraints
        tz = evt.get("trust_zone")
        if isinstance(tz, str) and tz not in _ALLOWED_TRUST_ZONES:
            evt.pop("trust_zone", None)

        rp = evt.get("route_profile")
        if isinstance(rp, str) and rp not in _ALLOWED_ROUTE_PROFILES:
            evt.pop("route_profile", None)

        ovl = evt.get("override_level")
        if isinstance(ovl, str) and ovl not in _ALLOWED_OVERRIDE_LEVELS:
            evt.pop("override_level", None)

        pqs = evt.get("pq_scheme")
        if isinstance(pqs, str) and pqs not in _ALLOWED_PQ_SCHEMES:
            evt.pop("pq_scheme", None)

        # method normalization
        m = _normalize_method(evt.get("method"))
        if m is None and "method" in evt:
            evt.pop("method", None)
        elif m is not None:
            evt["method"] = m

        # status normalization
        st = evt.get("status")
        st2: Optional[int] = None
        if isinstance(st, int) and 0 <= st <= 9999:
            st2 = st
        elif isinstance(st, str):
            ss = st.strip()
            if ss.isdigit():
                try:
                    st2 = int(ss)
                except Exception:
                    st2 = None
        if st2 is not None and 100 <= st2 <= 599:
            evt["status"] = st2
        else:
            if "status" in evt:
                evt.pop("status", None)

        # path normalization
        if "path" in evt:
            p = _coerce_small_str(evt.get("path"), cfg=cfg, max_len=1024)
            if p is None:
                evt.pop("path", None)
            else:
                p = _redact_if_secret(p, cfg=cfg, reason="path")
                if cfg.profile == "external":
                    p = _normalize_path_external(p)
                else:
                    # internal: strip query/fragment only
                    for sep in ("?", "#"):
                        i = p.find(sep)
                        if i >= 0:
                            p = p[:i]
                evt["path"] = p[:1024]

        # route/task/lang constraints (external stricter)
        for fld in ("route", "task", "chain_id", "pq_chain_id", "supply_chain_ref", "policy_ref", "model_id"):
            if fld not in evt:
                continue
            s = _coerce_small_str(evt.get(fld), cfg=cfg, max_len=256)
            if s is None:
                evt.pop(fld, None)
                continue
            s = _redact_if_secret(s, cfg=cfg, reason=fld)
            if cfg.profile == "external" and not _TAGLIKE_RE.fullmatch(s):
                evt.pop(fld, None)
                continue
            evt[fld] = s[:256]

        if "lang" in evt:
            s = _coerce_small_str(evt.get("lang"), cfg=cfg, max_len=32)
            if s is None:
                evt.pop("lang", None)
            else:
                if cfg.profile == "external" and not _LANG_RE.fullmatch(s.lower()):
                    evt.pop("lang", None)
                else:
                    evt["lang"] = s[:32]

        # numeric constraints
        for fld in ("e_value", "a_alloc", "score", "severity"):
            if fld not in evt:
                continue
            v = _finite_float(evt.get(fld))
            if v is None:
                evt.pop(fld, None)
                continue
            if fld == "e_value":
                if v < 0.0:
                    evt.pop(fld, None)
                else:
                    evt[fld] = v
            else:
                evt[fld] = max(0.0, min(1.0, v))

        # latency/bytes clamps (I.2)
        if "latency_ms" in evt:
            lv = _finite_float(evt.get("latency_ms"))
            if lv is None:
                evt.pop("latency_ms", None)
            else:
                if lv < 0:
                    lv = 0.0
                clamped = False
                if lv > cfg.max_latency_ms:
                    lv = cfg.max_latency_ms
                    clamped = True
                evt["latency_ms"] = round(float(lv), 3)
                if clamped:
                    evt["latency_clamped"] = True

        for fld, flag in (("bytes_in", "bytes_in_clamped"), ("bytes_out", "bytes_out_clamped")):
            if fld not in evt:
                continue
            bv = evt.get(fld)
            bvi: Optional[int] = None
            if isinstance(bv, int) and bv >= 0:
                bvi = bv
            else:
                fb = _finite_float(bv)
                if fb is not None and fb >= 0:
                    bvi = int(fb)
            if bvi is None:
                evt.pop(fld, None)
                continue
            if bvi > cfg.max_bytes_value:
                evt[fld] = int(cfg.max_bytes_value)
                evt[flag] = True
            else:
                evt[fld] = int(bvi)

        # request id: keep only safe tag-like; otherwise drop
        rid = evt.get("req_id")
        if isinstance(rid, str):
            rid2 = _strip_unsafe_text(rid, max_len=64).strip()
            if not _REQID_RE.fullmatch(rid2):
                evt.pop("req_id", None)
            else:
                evt["req_id"] = rid2

        # error flags (low-card) - ensure bool
        if "error" in evt and not isinstance(evt["error"], bool):
            evt["error"] = bool(evt["error"])

        # exc_type should be short and safe
        if "exc_type" in evt and isinstance(evt["exc_type"], str):
            et = _strip_unsafe_text(evt["exc_type"], max_len=64).strip()
            if not et or not _TAGLIKE_RE.fullmatch(et):
                evt.pop("exc_type", None)
            else:
                evt["exc_type"] = et

    def format(self, record: logging.LogRecord) -> str:  # type: ignore[override]
        cfg = self.cfg

        ctx = context()
        trace_id, span_id = _otel_ids()

        evt: Dict[str, Any] = {
            "schema": cfg.schema,
            "service": cfg.service,
            "version": cfg.version,
            "env": cfg.env,
            "instance": cfg.instance,
            "ts": _ts_iso(),
            "lvl": record.levelname,
            "logger": record.name,
            "msg": _safe_record_message(record, cfg),
        }

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
            cfg,
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
            status_inferred=_pick("status_inferred"),
            latency_ms=_pick("latency_ms"),
            bytes_in=_pick("bytes_in"),
            bytes_out=_pick("bytes_out"),
            bytes_in_clamped=_pick("bytes_in_clamped"),
            bytes_out_clamped=_pick("bytes_out_clamped"),
            latency_clamped=_pick("latency_clamped"),
            trust_zone=_pick("trust_zone"),
            route_profile=_pick("route_profile"),
            lockdown_level=_pick("lockdown_level"),
            threat_label=_pick("threat_label"),
            threat_vector=_pick("threat_vector"),
            severity=_pick("severity"),
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
            error=_pick("error"),
            exc_type=_pick("exc_type"),
            pii_key_id=cfg.pii_key_id or None,
        )

        # Exception info (external default disabled unless enabled)
        if record.exc_info and cfg.include_stack:
            try:
                exc_type, exc_val, exc_tb = record.exc_info
                et = getattr(exc_type, "__name__", "Exception")
                evt["exc_type"] = _strip_unsafe_text(str(et), max_len=64)
                try:
                    em = str(exc_val)
                except Exception:
                    em = "<unprintable exception>"
                em = _strip_unsafe_text(em, max_len=cfg.max_field_chars)
                em = _redact_if_secret(em, cfg=cfg, reason="exc_message")
                evt["exc_message"] = em[: cfg.max_field_chars]
                st = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
                st = _strip_unsafe_text(st, max_len=cfg.max_field_chars)
                evt["stack"] = st[: cfg.max_field_chars]
            except Exception:
                evt["exc_type"] = "Exception"
                evt["exc_message"] = "<exception formatting failed>"

        # G.1: normalize envelope fail-safe
        try:
            self._normalize_envelope(evt)
        except Exception:
            _LOG_META_DROPPED.labels(reason="normalize_error").inc()
            for k in ("tenant", "user", "session", "override_actor", "path", "route", "task"):
                evt.pop(k, None)
            evt["log_norm_error"] = True  # low-card

        # Meta from record
        meta = _sanitize_meta_from_record(record, cfg, evt_keys=set(evt.keys()))
        if meta:
            evt["meta"] = meta

        # Final event size clamp
        try:
            s = _compact_json(evt)
            b = s.encode("utf-8", errors="strict")
            if len(b) <= cfg.max_event_bytes:
                return s
        except Exception:
            pass

        # Oversize shrink (drop meta then stack)
        _LOG_DROPPED.labels(reason="oversize").inc()
        evt.pop("meta", None)
        evt.pop("stack", None)
        try:
            s2 = _compact_json(evt)
            if len(s2.encode("utf-8", errors="strict")) <= cfg.max_event_bytes:
                return s2
        except Exception:
            pass

        # Minimal fallback with fully sanitized cfg fields (G.2)
        minimal = {
            "schema": _guard_cfg_tag(cfg.schema, profile=cfg.profile, fallback="tcd.log.v1"),
            "service": _guard_cfg_tag(cfg.service, profile=cfg.profile, fallback="tcd"),
            "version": _guard_cfg_tag(cfg.version, profile=cfg.profile, fallback="0.0.0"),
            "env": _guard_cfg_tag(cfg.env, profile=cfg.profile, fallback="dev"),
            "ts": evt.get("ts", _ts_iso()),
            "lvl": evt.get("lvl", record.levelname),
            "logger": _strip_unsafe_text(str(getattr(record, "name", "tcd")), max_len=64),
            "msg": "<log event truncated>",
        }
        return _compact_json(minimal)


# ---------------------------------------------------------------------------
# Root/Uvicorn integration + optional config line (J.1)
# ---------------------------------------------------------------------------


def _clear_handlers(logger: logging.Logger) -> None:
    for h in list(logger.handlers):
        logger.removeHandler(h)


def configure_json_logging(
    level: str = "INFO",
    *,
    include_uvicorn: bool = True,
    stream: Any = None,
    cfg: Optional[LoggingConfig] = None,
    rate_key_fn: Optional[Callable[[logging.LogRecord], str]] = None,
) -> logging.Logger:
    cfg = cfg or get_config()
    lvl = getattr(logging, (level or "INFO").upper(), logging.INFO)
    stream = stream or sys.stderr

    fmt = JSONFormatter(cfg=cfg)
    h = logging.StreamHandler(stream=stream)
    h.setFormatter(fmt)
    h.setLevel(lvl)

    h.addFilter(SamplingFilter(cfg))
    h.addFilter(RateLimitFilter(cfg, key_fn=rate_key_fn))

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

    # J.1: emit a one-time config info line (low-card fields only)
    if cfg.emit_config_line:
        try:
            logging.getLogger("tcd.logging").info(
                "logging.config",
                extra={
                    "profile": cfg.profile,
                    "hash_pii_tags": bool(cfg.hash_pii_tags),
                    "external_hash_all_pii_tags": bool(cfg.external_hash_all_pii_tags),
                    "pii_key_present": bool(cfg.pii_hmac_key is not None and len(cfg.pii_hmac_key) >= cfg.pii_hmac_min_bytes),
                    "pii_key_id": cfg.pii_key_id or None,
                    "meta_whitelist_mode": bool(cfg.meta_whitelist_mode),
                    "sanitize_meta": bool(cfg.sanitize_meta),
                    "strip_pii": bool(cfg.strip_pii),
                    "sample": cfg.sample,
                    "rate_limit": cfg.rate_limit_per_key_per_sec,
                    "max_event_bytes": cfg.max_event_bytes,
                },
            )
        except Exception:
            pass

    return root


# ---------------------------------------------------------------------------
# Request helpers (A.2/I.1)
# ---------------------------------------------------------------------------


def _normalize_req_id(rid: str, cfg: LoggingConfig) -> Optional[str]:
    if not isinstance(rid, str):
        return None
    s = _strip_unsafe_text(rid, max_len=128).strip()
    if not s:
        return None
    if _REQID_RE.fullmatch(s):
        return s[:64]
    m = _AMZN_ROOT_RE.search(s)
    if m:
        root = _strip_unsafe_text(m.group(1), max_len=64).strip()
        if _REQID_RE.fullmatch(root):
            return root[:64]
    return None


def ensure_request_id(headers: Optional[Dict[str, str]] = None, *, cfg: Optional[LoggingConfig] = None) -> str:
    cfg = cfg or get_config()
    rid: Optional[str] = None

    if headers:
        candidates = ("x-request-id", "x-amzn-trace-id")
        for k in candidates:
            v = headers.get(k) if isinstance(headers.get(k), str) else headers.get(k.lower())
            if isinstance(v, str):
                rid = _normalize_req_id(v, cfg)
                if rid:
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
    chain_id: Optional[str] = None,
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
        principal_type=principal_type,
        trust_zone=trust_zone,
        route_profile=route_profile,
        chain_id=chain_id,
    )


# ---------------------------------------------------------------------------
# Convenience log helpers (A.3)
# ---------------------------------------------------------------------------


def _safe_extra_merge(dst: Dict[str, Any], extra: Optional[Dict[str, Any]], cfg: LoggingConfig) -> None:
    if not extra:
        return
    for k, v in extra.items():
        if v is None:
            continue
        if not isinstance(k, str):
            continue
        kl = _strip_unsafe_text(k, max_len=64).strip()
        if not kl or kl.startswith("_"):
            continue
        # A.3: never allow overriding standard LogRecord fields
        if kl in _LOG_RECORD_STD_ATTRS or kl == "message":
            continue
        if _is_forbidden_key_name(kl, cfg):
            continue
        dst[kl] = v


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
    cfg = get_config()

    ev = _finite_float(e_value)
    if ev is not None and ev < 0.0:
        ev = None

    aa = _finite_float(alpha_alloc)
    if aa is not None:
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

    _safe_extra_merge(extra_dict, extra, cfg)

    if cfg.sanitize_meta:
        try:
            scfg = SanitizeConfig(
                sanitize_nan=True,
                prune_large=True,
                strip_pii=cfg.strip_pii,
                forbid_keys=tuple(_DEFAULT_FORBIDDEN_META_KEYS),
            )
            sanitized = sanitize_metadata_for_receipt(extra_dict, config=scfg)
            if isinstance(sanitized, Mapping):
                extra_dict = dict(sanitized)
        except Exception:
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
    cfg = get_config()

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

    _safe_extra_merge(extra_dict, extra, cfg)

    if cfg.sanitize_meta:
        try:
            scfg = SanitizeConfig(
                sanitize_nan=True,
                prune_large=True,
                strip_pii=cfg.strip_pii,
                forbid_keys=tuple(_DEFAULT_FORBIDDEN_META_KEYS),
            )
            sanitized = sanitize_metadata_for_receipt(extra_dict, config=scfg)
            if isinstance(sanitized, Mapping):
                extra_dict = dict(sanitized)
        except Exception:
            pass

    logger.log(level, message, extra=extra_dict)


# ---------------------------------------------------------------------------
# ASGI middleware (A.2/I.1/I.2)
# ---------------------------------------------------------------------------


class RequestLogMiddleware:
    """
    Lightweight ASGI middleware that emits JSON request start/finish lines.

    It never logs request/response bodies, only sizes. If log_headers=True,
    it logs scrubbed headers under "http_hdrs" (not forbidden by key-scan).

    It also records:
      - error (bool)
      - exc_type (tag-like)
      - status_inferred (bool) when status is missing (defaults to 500)
      - clamps bytes/latency with *_clamped booleans
    """

    def __init__(
        self,
        app,
        *,
        logger_name: str = "tcd.http",
        log_headers: bool = False,
        cfg: Optional[LoggingConfig] = None,
    ):
        self.app = app
        self.log = logging.getLogger(logger_name)
        self.log_headers = bool(log_headers)
        self.cfg = cfg or get_config()

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        prior_ctx = context()
        cfg = self.cfg

        method = scope.get("method", "")
        path = scope.get("path", "")

        headers = {
            k.decode("latin1", errors="ignore").lower(): v.decode("latin1", errors="ignore")
            for k, v in (scope.get("headers") or [])
            if isinstance(k, (bytes, bytearray)) and isinstance(v, (bytes, bytearray))
        }

        rid = ensure_request_id(headers, cfg=cfg)

        bind_request_meta(
            path=_strip_unsafe_text(str(path or ""), max_len=min(cfg.max_field_chars, 1024)),
            method=_strip_unsafe_text(str(method or ""), max_len=16),
            trust_zone=_strip_unsafe_text(headers.get("x-tcd-trust-zone", "internet"), max_len=32),
            route_profile=_strip_unsafe_text(headers.get("x-tcd-route-profile", "inference"), max_len=32),
        )

        if self.log_headers:
            # A.2: use a non-forbidden key name: "http_hdrs"
            self.log.info("http.start", extra={"http_hdrs": scrub_dict(headers, cfg=cfg)})

        t0 = time.perf_counter()
        status_holder = {"code": None}
        bytes_out_holder = {"n": 0}
        bytes_in = 0
        error = False
        exc_type: Optional[str] = None
        status_inferred = False

        async def _send_wrapper(message):
            if message.get("type") == "http.response.start":
                status_holder["code"] = message.get("status")
            if message.get("type") == "http.response.body":
                body = message.get("body", b"") or b""
                if isinstance(body, (bytes, bytearray, memoryview)):
                    bytes_out_holder["n"] += len(body)
            await send(message)

        async def _recv_wrapper():
            nonlocal bytes_in
            msg = await receive()
            if msg.get("type") == "http.request":
                body = msg.get("body", b"") or b""
                if isinstance(body, (bytes, bytearray, memoryview)):
                    bytes_in += len(body)
            return msg

        try:
            await self.app(scope, _recv_wrapper, _send_wrapper)
        except Exception as e:
            error = True
            exc_type = getattr(type(e), "__name__", "Exception")
            # re-raise after logging in finally
            raise
        finally:
            dt_ms = (time.perf_counter() - t0) * 1000.0

            # I.2 clamps
            bytes_in_clamped = False
            bytes_out_clamped = False
            latency_clamped = False

            if bytes_in > cfg.max_bytes_value:
                bytes_in = cfg.max_bytes_value
                bytes_in_clamped = True
            if bytes_out_holder["n"] > cfg.max_bytes_value:
                bytes_out_holder["n"] = cfg.max_bytes_value
                bytes_out_clamped = True
            if dt_ms < 0:
                dt_ms = 0.0
            if dt_ms > cfg.max_latency_ms:
                dt_ms = cfg.max_latency_ms
                latency_clamped = True

            st = status_holder["code"]
            if st is None:
                st = 500
                status_inferred = True

            extra_evt = {
                "req_id": rid,
                "path": path,
                "method": method,
                "status": st,
                "status_inferred": status_inferred,
                "latency_ms": round(dt_ms, 3),
                "latency_clamped": latency_clamped or None,
                "bytes_in": int(bytes_in),
                "bytes_out": int(bytes_out_holder["n"]),
                "bytes_in_clamped": bytes_in_clamped or None,
                "bytes_out_clamped": bytes_out_clamped or None,
                "error": bool(error) or None,
                "exc_type": exc_type,
            }
            self.log.info("http.finish", extra=extra_evt)

            _log_ctx.set(prior_ctx)


# ---------------------------------------------------------------------------
# Convenience: module-level logger
# ---------------------------------------------------------------------------

_logger: Optional[logging.Logger] = None


def get_logger(name: str = "tcd") -> logging.Logger:
    global _logger
    if _logger is None:
        lvl = _env_str("TCD_LOG_LEVEL", "INFO")
        configure_json_logging(level=lvl, include_uvicorn=True, cfg=get_config())
        _logger = logging.getLogger("tcd")
    return logging.getLogger(name)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "bind",
    "unbind",
    "reset",
    "context",
    "get_config",
    "configure_json_logging",
    "get_logger",
    "ensure_request_id",
    "bind_request_meta",
    "log_decision",
    "log_security_event",
    "JSONFormatter",
    "RequestLogMiddleware",
    "scrub_dict",
    "LoggingConfig",
]