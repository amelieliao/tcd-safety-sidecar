from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import hashlib
import hmac
import inspect
import json
import logging
import math
import os
import queue
import re
import threading
import time
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Literal

try:  # optional fast hash
    from blake3 import blake3  # type: ignore
except Exception:  # pragma: no cover
    blake3 = None  # type: ignore[assignment]

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from .policies import BoundPolicy, PolicyStore
from .ratelimit import RateLimiter

try:  # optional richer rate key/config
    from .ratelimit import RateKey, RateLimitConfig, RateLimitZoneConfig  # type: ignore
except Exception:  # pragma: no cover
    RateKey = None  # type: ignore[assignment]
    RateLimitConfig = None  # type: ignore[assignment]
    RateLimitZoneConfig = None  # type: ignore[assignment]

try:  # optional unified authenticator
    from .auth import Authenticator, AuthResult, build_authenticator_from_env  # type: ignore
    _HAS_AUTH = True
except Exception:  # pragma: no cover
    Authenticator = Any  # type: ignore[misc,assignment]
    AuthResult = Any  # type: ignore[misc,assignment]
    build_authenticator_from_env = None  # type: ignore[assignment]
    _HAS_AUTH = False


__all__ = [
    "RequestAuthConfig",
    "RequestLimitConfig",
    "IdempotencyConfig",
    "PolicyBindConfig",
    "MetricsConfig",
    "SecurityConfig",
    "RequestAuditConfig",
    "TCDRequestMiddlewareConfig",
    "TCDRequestMiddleware",
    "TCDRequestASGIMiddleware",
    "add_request_middleware",
]

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Low-level hardening helpers
# ---------------------------------------------------------------------------

_ALLOWED_PROFILES = frozenset({"DEV", "PROD", "HIGH_SECURITY", "FINREG", "LOCKDOWN"})
_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")
_SAFE_TAGLIKE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,255}$")
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[1-5][0-9a-fA-F]{3}\b-[89abAB][0-9a-fA-F]{3}\b-[0-9a-fA-F]{12}"
)
_LONG_NUM_SEG_RE = re.compile(r"/\d{4,}")
_LONG_SEG_RE = re.compile(r"(?:(?<=/)|^)[A-Za-z0-9._-]{24,}(?=(?:/|$))")
_JSON_CT_RE = re.compile(r"^application/(?:json|[A-Za-z0-9.\-]+\+json)$", re.IGNORECASE)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b", re.IGNORECASE)
_BASIC_RE = re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{16,}\b", re.IGNORECASE)
_OPENAI_SK_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_AWS_AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GOOGLE_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]{8,})"
)


def _has_unsafe_unicode(s: str) -> bool:
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False


def _strip_unsafe_text(v: Any, *, max_len: int) -> str:
    if not isinstance(v, str):
        return ""
    s = unicodedata.normalize("NFC", v[:max_len])

    if s.isascii():
        if _ASCII_CTRL_RE.search(s):
            s = _ASCII_CTRL_RE.sub("", s)
        return s.strip()

    if not _ASCII_CTRL_RE.search(s) and not _has_unsafe_unicode(s):
        if any(0x80 <= ord(ch) <= 0x9F for ch in s):
            pass
        else:
            return s.strip()

    out: List[str] = []
    for ch in s:
        o = ord(ch)
        if ch in ("\u2028", "\u2029"):
            continue
        if o < 0x20 or o == 0x7F:
            continue
        if 0x80 <= o <= 0x9F:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            continue
        out.append(ch)
    return "".join(out).strip()


def _safe_text(v: Any, *, max_len: int = 256) -> str:
    if isinstance(v, str):
        return _strip_unsafe_text(v, max_len=max_len)
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "<bytes>"
    return f"<{type(v).__name__}>"


def _looks_like_secret(v: str) -> bool:
    if not v:
        return False
    if _JWT_RE.search(v):
        return True
    if _PRIVKEY_RE.search(v):
        return True
    if _BEARER_RE.search(v):
        return True
    if _BASIC_RE.search(v):
        return True
    if _OPENAI_SK_RE.search(v):
        return True
    if _AWS_AKIA_RE.search(v):
        return True
    if _GOOGLE_AIZA_RE.search(v):
        return True
    if _KV_SECRET_RE.search(v):
        return True
    return False


def _safe_taglike_id(raw: Any, *, max_len: int = 255, allow_truncate: bool = False) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    s = _strip_unsafe_text(raw, max_len=max_len + (16 if allow_truncate else 1)).strip()
    if not s:
        return None
    if _looks_like_secret(s):
        return None
    if len(s) > max_len:
        if not allow_truncate:
            return None
        s = s[:max_len]
    if not _SAFE_TAGLIKE_RE.fullmatch(s):
        return None
    return s


def _normalize_profile(v: Any) -> str:
    s = _safe_text(v, max_len=32).strip().upper()
    aliases = {
        "HIGHSEC": "HIGH_SECURITY",
        "HIGH_SEC": "HIGH_SECURITY",
        "HIGH-SECURITY": "HIGH_SECURITY",
    }
    s = aliases.get(s, s)
    return s if s in _ALLOWED_PROFILES else "PROD"


def _profile_is_high_security(profile: str) -> bool:
    return _normalize_profile(profile) in {"HIGH_SECURITY", "FINREG", "LOCKDOWN"}


def _finite_float(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    try:
        x = float(v)
    except Exception:
        return None
    return x if math.isfinite(x) else None


def _clamp_int(v: Any, *, default: int, lo: int, hi: int) -> int:
    try:
        x = int(v)
    except Exception:
        x = int(default)
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def _clamp_float(v: Any, *, default: float, lo: float, hi: float) -> float:
    x = _finite_float(v)
    if x is None:
        x = float(default)
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def _hash_hex(data: bytes) -> str:
    if blake3 is not None:
        try:
            return blake3(data).hexdigest()
        except Exception:
            pass
    return hashlib.blake2b(data, digest_size=32).hexdigest()


def _fold_id(prefix: str, raw: str, *, hex_len: int = 16) -> str:
    dig = _hash_hex(b"tcd:middleware_request:fold:" + raw.encode("utf-8", errors="ignore"))[: max(8, hex_len)]
    return f"{prefix}-h-{dig}"


def _default_normalizer(path: str) -> str:
    p = _strip_unsafe_text(path or "/", max_len=1024).strip() or "/"
    p = _UUID_RE.sub(":uuid", p)
    p = _LONG_NUM_SEG_RE.sub("/:id", p)
    p = _LONG_SEG_RE.sub(":tok", p)
    return p


def _headers_budget(scope: Mapping[str, Any]) -> Tuple[int, int]:
    raw_headers = scope.get("headers") or []
    if not isinstance(raw_headers, list):
        return 0, 0
    count = 0
    total = 0
    for item in raw_headers:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue
        k, v = item
        if isinstance(k, (bytes, bytearray)):
            total += len(k)
        if isinstance(v, (bytes, bytearray)):
            total += len(v)
        count += 1
    return count, total


def _json_depth_exceeds(raw: bytes, *, max_depth: int) -> bool:
    try:
        text = raw.decode("utf-8", errors="strict")
    except Exception:
        return True

    depth = 0
    in_str = False
    esc = False

    for ch in text:
        if in_str:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = False
            continue

        if ch == '"':
            in_str = True
            continue
        if ch in "{[":
            depth += 1
            if depth > max_depth:
                return True
        elif ch in "}]":
            depth = max(0, depth - 1)

    return False


def _parse_int_limited(max_digits: int) -> Callable[[str], int]:
    md = max(1, int(max_digits))

    def _parse(s: str) -> int:
        ss = s[1:] if s.startswith("-") else s
        if len(ss) > md:
            raise ValueError("json integer too large")
        return int(s, 10)

    return _parse


def _strict_json_loads(raw: bytes, *, max_depth: int, max_int_digits: int) -> Any:
    if _json_depth_exceeds(raw, max_depth=max_depth):
        raise ValueError("json_too_deep")

    def _bad_const(_: str) -> Any:
        raise ValueError("non_finite_json")

    return json.loads(
        raw.decode("utf-8", errors="strict"),
        parse_constant=_bad_const,
        parse_int=_parse_int_limited(max_int_digits),
    )


def _content_type_is_json(raw_ct: Optional[str]) -> bool:
    if not isinstance(raw_ct, str):
        return False
    ct = raw_ct.split(";", 1)[0].strip()
    if not ct:
        return False
    return bool(_JSON_CT_RE.fullmatch(ct))


def _guess_json_body(raw_body: bytes) -> bool:
    if not raw_body:
        return False
    b = raw_body.lstrip()
    return bool(b and b[:1] in (b"{", b"["))


def _stable_body_digest(body: bytes) -> str:
    return _hash_hex(b"tcd:middleware_request:body\x00" + body)


def _state_get(state: Any, key: str, default: Any = None) -> Any:
    try:
        if isinstance(state, dict):
            return state.get(key, default)
        return getattr(state, key, default)
    except Exception:
        return default


def _state_set(state: Any, key: str, value: Any) -> None:
    try:
        if isinstance(state, dict):
            state[key] = value
        else:
            setattr(state, key, value)
    except Exception:
        pass


def _request_id_from_state_or_headers(request: Request, header_name: str) -> str:
    rid = _state_get(request.state, "request_id", None)
    if isinstance(rid, str):
        ok = _safe_taglike_id(rid, max_len=255)
        if ok:
            return ok
    hdr = request.headers.get(header_name) or request.headers.get(header_name.lower())
    ok2 = _safe_taglike_id(hdr, max_len=255) if isinstance(hdr, str) else None
    if ok2:
        return ok2
    return _fold_id("rid", f"{time.time_ns()}:{id(request)}", hex_len=24)


def _trusted_profile_from_state_or_default(state: Any, default_profile: str) -> str:
    src = _state_get(state, "tcd_trust_profile_source", None)
    raw = _state_get(state, "tcd_trust_profile", None)
    if src == "trusted_local" and isinstance(raw, str):
        return _normalize_profile(raw)
    return _normalize_profile(default_profile)


def _coarse_security_level(classification: str) -> str:
    if not classification:
        return "public"
    v = classification.lower()
    if v in ("sensitive", "secret", "high", "critical", "restricted"):
        return "restricted"
    if v in ("internal", "confidential", "medium"):
        return "internal"
    return "public"


def _safe_ctx_value(raw: Any, *, field_name: str, max_len: int = 128) -> str:
    if raw is None:
        return "*"
    if isinstance(raw, (int, float, bool)):
        s = _safe_text(raw, max_len=max_len)
        return s or "*"
    if not isinstance(raw, str):
        return "*"

    s = _strip_unsafe_text(raw, max_len=max_len).strip()
    if not s:
        return "*"
    if _looks_like_secret(s):
        return _fold_id(field_name[:4] or "id", s)
    tag = _safe_taglike_id(s, max_len=max_len)
    if tag:
        return tag
    return _fold_id(field_name[:4] or "id", s)


def _mapping_from_obj(v: Any) -> Dict[str, Any]:
    if isinstance(v, Mapping):
        return dict(v)
    if dataclasses.is_dataclass(v):
        try:
            return dataclasses.asdict(v)
        except Exception:
            return {}
    out: Dict[str, Any] = {}
    for name in (
        "mode",
        "principal",
        "principal_id",
        "scopes",
        "key_id",
        "raw",
        "policy_digest",
        "issued_at",
        "authn_strength",
        "classification",
        "class",
        "level",
        "tenant",
        "user",
        "session",
    ):
        with contextlib.suppress(Exception):
            vv = getattr(v, name)
            if vv is not None:
                out[name] = vv
    return out


def _raw_headers_has(raw_headers: Sequence[Tuple[bytes, bytes]], name: bytes) -> bool:
    target = name.lower()
    return any(k.lower() == target for k, _ in raw_headers)


def _raw_headers_append_if_missing(raw_headers: List[Tuple[bytes, bytes]], name: bytes, value: bytes) -> None:
    if not _raw_headers_has(raw_headers, name):
        raw_headers.append((name, value))


def _extract_media_type_from_raw_headers(raw_headers: Sequence[Tuple[bytes, bytes]]) -> Optional[str]:
    for k, v in raw_headers:
        if k.lower() == b"content-type":
            with contextlib.suppress(Exception):
                return v.decode("latin1", errors="ignore")
    return None


def _json_error(
    *,
    status_code: int,
    reason: str,
    request_id: str,
    headers: Optional[Dict[str, str]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> JSONResponse:
    payload: Dict[str, Any] = {"error": reason, "request_id": request_id}
    if extra:
        for k, v in extra.items():
            kk = _safe_text(k, max_len=64).lower()
            if kk and kk not in payload:
                payload[kk] = _safe_text(v, max_len=256) if isinstance(v, str) else v
    hdrs = dict(headers or {})
    hdrs.setdefault("X-Request-Id", request_id)
    return JSONResponse(status_code=int(status_code), content=payload, headers=hdrs)


# ---------------------------------------------------------------------------
# JSON complexity guard
# ---------------------------------------------------------------------------

@dataclass
class _JsonComplexityBudget:
    max_nodes: int
    max_depth: int
    max_items: int
    max_key_bytes: int
    max_total_str_bytes: int
    max_string_bytes: int
    nodes: int = 0
    total_str_bytes: int = 0


def _walk_json_budget(value: Any, *, depth: int, budget: _JsonComplexityBudget) -> None:
    budget.nodes += 1
    if budget.nodes > budget.max_nodes:
        raise ValueError("json_too_complex")
    if depth > budget.max_depth:
        raise ValueError("json_too_deep")

    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if value.bit_length() > 4096:
            raise ValueError("json_number_too_large")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non_finite_json")
        return
    if isinstance(value, str):
        n = len(value.encode("utf-8", errors="strict"))
        if n > budget.max_string_bytes:
            raise ValueError("json_string_too_large")
        budget.total_str_bytes += n
        if budget.total_str_bytes > budget.max_total_str_bytes:
            raise ValueError("json_string_budget")
        return
    if isinstance(value, Mapping):
        if len(value) > budget.max_items:
            raise ValueError("json_too_many_items")
        for k, v in value.items():
            if not isinstance(k, str):
                raise ValueError("json_non_string_key")
            if len(k.encode("utf-8", errors="strict")) > budget.max_key_bytes:
                raise ValueError("json_key_too_large")
            budget.total_str_bytes += len(k.encode("utf-8", errors="strict"))
            if budget.total_str_bytes > budget.max_total_str_bytes:
                raise ValueError("json_string_budget")
            _walk_json_budget(v, depth=depth + 1, budget=budget)
        return
    if isinstance(value, (list, tuple)):
        if len(value) > budget.max_items:
            raise ValueError("json_too_many_items")
        for item in value:
            _walk_json_budget(item, depth=depth + 1, budget=budget)
        return
    raise ValueError("json_unsupported_type")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RequestAuthConfig:
    use_authenticator: bool = True
    enable_bearer: bool = False
    enable_hmac: bool = False
    legacy_require_all: bool = False
    bearer_token_env: str = "TCD_BEARER_TOKEN"
    hmac_secret_env: str = "TCD_HMAC_SECRET"
    signature_header: str = "X-TCD-Signature"
    auth_skip_paths: Tuple[str, ...] = (r"^/healthz$", r"^/metrics$", r"^/version$")
    max_auth_header_bytes: int = 8192


@dataclass(frozen=True)
class RequestLimitConfig:
    max_body_bytes: int = 1_000_000
    hard_read_cap_bytes: int = 2_000_000
    max_header_count: int = 128
    max_header_bytes: int = 32 * 1024
    max_path_bytes: int = 4096
    max_query_bytes: int = 32 * 1024
    max_json_depth: int = 16
    max_json_nodes: int = 4096
    max_json_items: int = 1024
    max_json_key_bytes: int = 1024
    max_json_string_bytes: int = 64 * 1024
    max_json_total_str_bytes: int = 256 * 1024
    max_json_int_digits: int = 2048
    enforce_json_content_type: bool = True
    reject_invalid_json_when_declared: bool = True
    body_methods: Tuple[str, ...] = ("POST", "PUT", "PATCH", "DELETE")
    content_type_skip_paths: Tuple[str, ...] = (r"^/healthz$", r"^/metrics$", r"^/version$")
    rl_capacity: float = 120.0
    rl_refill_per_s: float = 60.0
    token_cost_divisor_default: float = 50.0
    emit_rate_headers: bool = True
    rate_skip_paths: Tuple[str, ...] = (r"^/healthz$", r"^/metrics$", r"^/version$")


@dataclass(frozen=True)
class IdempotencyConfig:
    enable: bool = True
    header: str = "Idempotency-Key"
    ttl_seconds: float = 15.0 * 60.0
    max_entries: int = 50_000
    store_only_2xx: bool = True
    max_store_bytes: int = 256_000
    vary_on_headers: Tuple[str, ...] = ("accept", "content-type")
    wait_on_inflight: bool = True
    inflight_wait_timeout_s: float = 5.0
    methods: Tuple[str, ...] = ("POST", "PUT", "PATCH")
    skip_paths: Tuple[str, ...] = (r"^/verify$", r"^/metrics$", r"^/healthz$")
    include_subject_in_slot: bool = True
    reject_streaming_responses: bool = True


@dataclass(frozen=True)
class PolicyBindConfig:
    h_tenant: str = "X-Tenant"
    h_user: str = "X-User"
    h_session: str = "X-Session"
    h_model: str = "X-Model-Id"
    h_gpu: str = "X-Gpu-Id"
    h_task: str = "X-Task"
    h_lang: str = "X-Lang"
    h_trust_zone: str = "X-Trust-Zone"
    h_route_profile: str = "X-Route-Profile"
    bind_skip_paths: Tuple[str, ...] = (r"^/metrics$", r"^/healthz$", r"^/version$")
    include_request_context: bool = True


@dataclass(frozen=True)
class MetricsConfig:
    latency_buckets: Tuple[float, ...] = (0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0)
    enable: bool = True
    path_normalizer: Optional[Callable[[str], str]] = None


@dataclass(frozen=True)
class SecurityConfig:
    profile: str = "PROD"
    require_authenticator: bool = False
    forbid_legacy_auth: bool = False
    idempotency_disallowed_classes: Tuple[str, ...] = ("sensitive", "secret")
    high_cost_classes: Tuple[str, ...] = ("sensitive", "secret")
    allow_anonymous_if_unconfigured: bool = True
    hide_reject_reason_in_high_security: bool = False
    trust_profile_only_from_request_context: bool = True


@dataclass(frozen=True)
class RequestAuditConfig:
    enable: bool = False
    mode: Literal["disabled", "sync", "async"] = "disabled"
    audit_log_fn: Optional[Callable[[Dict[str, Any]], None]] = None
    queue_size: int = 4096
    drop_policy: Literal["drop_newest", "drop_oldest", "sync_fallback"] = "drop_newest"
    emit_success: bool = False
    hash_subject_fields: bool = True
    max_event_bytes: int = 4096


@dataclass(frozen=True)
class TCDRequestMiddlewareConfig:
    auth: RequestAuthConfig = field(default_factory=RequestAuthConfig)
    limits: RequestLimitConfig = field(default_factory=RequestLimitConfig)
    idempotency: IdempotencyConfig = field(default_factory=IdempotencyConfig)
    policies: PolicyBindConfig = field(default_factory=PolicyBindConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    audit: RequestAuditConfig = field(default_factory=RequestAuditConfig)
    bypass_paths: Tuple[str, ...] = (r"^/metrics$",)
    request_id_header: str = "X-Request-Id"

    def normalized_copy(self) -> "TCDRequestMiddlewareConfig":
        metrics_norm = MetricsConfig(
            latency_buckets=tuple(
                _clamp_float(x, default=0.1, lo=0.000001, hi=3600.0)
                for x in (self.metrics.latency_buckets or (0.001, 0.01, 0.1))
            ),
            enable=bool(self.metrics.enable),
            path_normalizer=self.metrics.path_normalizer or _default_normalizer,
        )

        audit_mode = _safe_text(self.audit.mode, max_len=16).lower() or "disabled"
        if audit_mode not in {"disabled", "sync", "async"}:
            audit_mode = "disabled"
        if not self.audit.enable or self.audit.audit_log_fn is None:
            audit_mode = "disabled"

        return TCDRequestMiddlewareConfig(
            auth=RequestAuthConfig(
                use_authenticator=bool(self.auth.use_authenticator),
                enable_bearer=bool(self.auth.enable_bearer),
                enable_hmac=bool(self.auth.enable_hmac),
                legacy_require_all=bool(self.auth.legacy_require_all),
                bearer_token_env=_safe_text(self.auth.bearer_token_env, max_len=128) or "TCD_BEARER_TOKEN",
                hmac_secret_env=_safe_text(self.auth.hmac_secret_env, max_len=128) or "TCD_HMAC_SECRET",
                signature_header=_safe_text(self.auth.signature_header, max_len=128) or "X-TCD-Signature",
                auth_skip_paths=tuple(str(x) for x in self.auth.auth_skip_paths),
                max_auth_header_bytes=_clamp_int(self.auth.max_auth_header_bytes, default=8192, lo=64, hi=1024 * 1024),
            ),
            limits=RequestLimitConfig(
                max_body_bytes=_clamp_int(self.limits.max_body_bytes, default=1_000_000, lo=1024, hi=64 * 1024 * 1024),
                hard_read_cap_bytes=_clamp_int(self.limits.hard_read_cap_bytes, default=2_000_000, lo=1024, hi=64 * 1024 * 1024),
                max_header_count=_clamp_int(self.limits.max_header_count, default=128, lo=8, hi=100_000),
                max_header_bytes=_clamp_int(self.limits.max_header_bytes, default=32 * 1024, lo=512, hi=16 * 1024 * 1024),
                max_path_bytes=_clamp_int(self.limits.max_path_bytes, default=4096, lo=64, hi=256 * 1024),
                max_query_bytes=_clamp_int(self.limits.max_query_bytes, default=32 * 1024, lo=0, hi=4 * 1024 * 1024),
                max_json_depth=_clamp_int(self.limits.max_json_depth, default=16, lo=1, hi=256),
                max_json_nodes=_clamp_int(self.limits.max_json_nodes, default=4096, lo=16, hi=1_000_000),
                max_json_items=_clamp_int(self.limits.max_json_items, default=1024, lo=8, hi=100_000),
                max_json_key_bytes=_clamp_int(self.limits.max_json_key_bytes, default=1024, lo=16, hi=64 * 1024),
                max_json_string_bytes=_clamp_int(self.limits.max_json_string_bytes, default=64 * 1024, lo=64, hi=4 * 1024 * 1024),
                max_json_total_str_bytes=_clamp_int(self.limits.max_json_total_str_bytes, default=256 * 1024, lo=256, hi=16 * 1024 * 1024),
                max_json_int_digits=_clamp_int(self.limits.max_json_int_digits, default=2048, lo=16, hi=100_000),
                enforce_json_content_type=bool(self.limits.enforce_json_content_type),
                reject_invalid_json_when_declared=bool(self.limits.reject_invalid_json_when_declared),
                body_methods=tuple(_safe_text(x, max_len=16).upper() for x in self.limits.body_methods if _safe_text(x, max_len=16)),
                content_type_skip_paths=tuple(str(x) for x in self.limits.content_type_skip_paths),
                rl_capacity=_clamp_float(self.limits.rl_capacity, default=120.0, lo=0.0, hi=10_000_000.0),
                rl_refill_per_s=_clamp_float(self.limits.rl_refill_per_s, default=60.0, lo=0.0, hi=10_000_000.0),
                token_cost_divisor_default=_clamp_float(self.limits.token_cost_divisor_default, default=50.0, lo=1.0, hi=1_000_000.0),
                emit_rate_headers=bool(self.limits.emit_rate_headers),
                rate_skip_paths=tuple(str(x) for x in self.limits.rate_skip_paths),
            ),
            idempotency=IdempotencyConfig(
                enable=bool(self.idempotency.enable),
                header=_safe_text(self.idempotency.header, max_len=128) or "Idempotency-Key",
                ttl_seconds=_clamp_float(self.idempotency.ttl_seconds, default=900.0, lo=1.0, hi=7 * 24 * 3600.0),
                max_entries=_clamp_int(self.idempotency.max_entries, default=50_000, lo=1, hi=2_000_000),
                store_only_2xx=bool(self.idempotency.store_only_2xx),
                max_store_bytes=_clamp_int(self.idempotency.max_store_bytes, default=256_000, lo=256, hi=32 * 1024 * 1024),
                vary_on_headers=tuple(_safe_text(x, max_len=64).lower() for x in self.idempotency.vary_on_headers if _safe_text(x, max_len=64)),
                wait_on_inflight=bool(self.idempotency.wait_on_inflight),
                inflight_wait_timeout_s=_clamp_float(self.idempotency.inflight_wait_timeout_s, default=5.0, lo=0.0, hi=3600.0),
                methods=tuple(_safe_text(x, max_len=16).upper() for x in self.idempotency.methods if _safe_text(x, max_len=16)),
                skip_paths=tuple(str(x) for x in self.idempotency.skip_paths),
                include_subject_in_slot=bool(self.idempotency.include_subject_in_slot),
                reject_streaming_responses=bool(self.idempotency.reject_streaming_responses),
            ),
            policies=PolicyBindConfig(
                h_tenant=_safe_text(self.policies.h_tenant, max_len=128) or "X-Tenant",
                h_user=_safe_text(self.policies.h_user, max_len=128) or "X-User",
                h_session=_safe_text(self.policies.h_session, max_len=128) or "X-Session",
                h_model=_safe_text(self.policies.h_model, max_len=128) or "X-Model-Id",
                h_gpu=_safe_text(self.policies.h_gpu, max_len=128) or "X-Gpu-Id",
                h_task=_safe_text(self.policies.h_task, max_len=128) or "X-Task",
                h_lang=_safe_text(self.policies.h_lang, max_len=128) or "X-Lang",
                h_trust_zone=_safe_text(self.policies.h_trust_zone, max_len=128) or "X-Trust-Zone",
                h_route_profile=_safe_text(self.policies.h_route_profile, max_len=128) or "X-Route-Profile",
                bind_skip_paths=tuple(str(x) for x in self.policies.bind_skip_paths),
                include_request_context=bool(self.policies.include_request_context),
            ),
            metrics=metrics_norm,
            security=SecurityConfig(
                profile=_normalize_profile(self.security.profile),
                require_authenticator=bool(self.security.require_authenticator),
                forbid_legacy_auth=bool(self.security.forbid_legacy_auth),
                idempotency_disallowed_classes=tuple(_safe_text(x, max_len=64).lower() for x in self.security.idempotency_disallowed_classes if _safe_text(x, max_len=64)),
                high_cost_classes=tuple(_safe_text(x, max_len=64).lower() for x in self.security.high_cost_classes if _safe_text(x, max_len=64)),
                allow_anonymous_if_unconfigured=bool(self.security.allow_anonymous_if_unconfigured),
                hide_reject_reason_in_high_security=bool(self.security.hide_reject_reason_in_high_security),
                trust_profile_only_from_request_context=bool(self.security.trust_profile_only_from_request_context),
            ),
            audit=RequestAuditConfig(
                enable=bool(self.audit.enable),
                mode=audit_mode,  # type: ignore[arg-type]
                audit_log_fn=self.audit.audit_log_fn,
                queue_size=_clamp_int(self.audit.queue_size, default=4096, lo=1, hi=1_000_000),
                drop_policy=(
                    self.audit.drop_policy
                    if self.audit.drop_policy in {"drop_newest", "drop_oldest", "sync_fallback"}
                    else "drop_newest"
                ),
                emit_success=bool(self.audit.emit_success),
                hash_subject_fields=bool(self.audit.hash_subject_fields),
                max_event_bytes=_clamp_int(self.audit.max_event_bytes, default=4096, lo=256, hi=256 * 1024),
            ),
            bypass_paths=tuple(str(x) for x in self.bypass_paths),
            request_id_header=_safe_text(self.request_id_header, max_len=128) or "X-Request-Id",
        )


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

class _Metrics:
    def __init__(self, cfg: MetricsConfig):
        self.enabled = bool(cfg.enable)
        if not self.enabled:
            self.req_ctr = self.req_reject = self.req_bytes = self.resp_bytes = None
            self.latency = self.idem_ctr = self.rate_block = self.auth_sig = None
            self.auth_sig_fail_reason = self.req_sec = self.inflight = self.audit_drop = None
            return

        try:
            from prometheus_client import Counter, Gauge, Histogram, REGISTRY  # type: ignore
        except Exception:  # pragma: no cover
            self.enabled = False
            self.req_ctr = self.req_reject = self.req_bytes = self.resp_bytes = None
            self.latency = self.idem_ctr = self.rate_block = self.auth_sig = None
            self.auth_sig_fail_reason = self.req_sec = self.inflight = self.audit_drop = None
            return

        class _NopMetric:
            def labels(self, *_, **__):
                return self
            def inc(self, *_, **__):
                pass
            def observe(self, *_, **__):
                pass
            def set(self, *_, **__):
                pass
            def dec(self, *_, **__):
                pass

        def _metric(factory: Any, *args: Any, **kwargs: Any) -> Any:
            try:
                return factory(*args, **kwargs)
            except Exception:
                return _NopMetric()

        reg = REGISTRY
        self.req_ctr = _metric(Counter, "tcd_request_middleware_requests_total", "HTTP requests", ["method", "path", "code"], registry=reg)
        self.req_reject = _metric(Counter, "tcd_request_middleware_reject_total", "Rejected requests", ["reason", "path"], registry=reg)
        self.req_bytes = _metric(Counter, "tcd_request_middleware_request_bytes_total", "Request bytes", ["method", "path"], registry=reg)
        self.resp_bytes = _metric(Counter, "tcd_request_middleware_response_bytes_total", "Response bytes", ["method", "path", "code"], registry=reg)
        self.latency = _metric(Histogram, "tcd_request_middleware_latency_seconds", "End-to-end request latency", buckets=cfg.latency_buckets, registry=reg)
        self.idem_ctr = _metric(Counter, "tcd_request_middleware_idempotency_total", "Idempotency outcomes", ["status", "path"], registry=reg)
        self.rate_block = _metric(Counter, "tcd_request_middleware_rate_limit_total", "Rate-limit blocks", ["path"], registry=reg)
        self.auth_sig = _metric(Counter, "tcd_request_middleware_signature_total", "Signature verification", ["status", "path"], registry=reg)
        self.auth_sig_fail_reason = _metric(Counter, "tcd_request_middleware_signature_fail_total", "Signature failures", ["reason", "path"], registry=reg)
        self.req_sec = _metric(Counter, "tcd_request_middleware_requests_security_total", "HTTP requests by coarse security level", ["sec_level", "path"], registry=reg)
        self.inflight = _metric(Gauge, "tcd_request_middleware_inflight", "Current in-flight HTTP requests", ["path"], registry=reg)
        self.audit_drop = _metric(Counter, "tcd_request_middleware_audit_drop_total", "Dropped audit events", ["reason"], registry=reg)


# ---------------------------------------------------------------------------
# Audit dispatcher
# ---------------------------------------------------------------------------

class _AuditDispatcher:
    def __init__(self, cfg: RequestAuditConfig, metrics: _Metrics) -> None:
        self._cfg = cfg
        self._metrics = metrics
        self._q: Optional["queue.Queue[Dict[str, Any]]"] = None
        self._thr: Optional[threading.Thread] = None
        self._stop = threading.Event()

        if self._cfg.mode == "async" and self._cfg.audit_log_fn is not None:
            self._q = queue.Queue(maxsize=max(1, int(self._cfg.queue_size)))
            self._thr = threading.Thread(target=self._worker, name="tcd-request-audit", daemon=True)
            self._thr.start()

    def _record_drop(self, reason: str) -> None:
        if self._metrics.enabled and self._metrics.audit_drop is not None:
            with contextlib.suppress(Exception):
                self._metrics.audit_drop.labels(reason).inc()

    def _deliver_sync(self, record: Dict[str, Any]) -> None:
        fn = self._cfg.audit_log_fn
        if fn is None:
            return
        try:
            fn(record)
        except Exception:
            _logger.debug("request audit hook failed", exc_info=True)

    def _worker(self) -> None:
        assert self._q is not None
        while not self._stop.is_set():
            try:
                record = self._q.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self._deliver_sync(record)
            finally:
                self._q.task_done()

    def emit(self, record: Dict[str, Any]) -> None:
        if self._cfg.mode == "disabled" or self._cfg.audit_log_fn is None:
            return
        if self._cfg.mode == "sync" or self._q is None:
            self._deliver_sync(record)
            return
        try:
            self._q.put_nowait(record)
        except queue.Full:
            if self._cfg.drop_policy == "drop_oldest":
                try:
                    _ = self._q.get_nowait()
                    self._q.task_done()
                except Exception:
                    pass
                try:
                    self._q.put_nowait(record)
                    return
                except Exception:
                    self._record_drop("queue_full")
                    return
            if self._cfg.drop_policy == "sync_fallback":
                self._deliver_sync(record)
                return
            self._record_drop("queue_full")

    def close(self) -> None:
        self._stop.set()


# ---------------------------------------------------------------------------
# Idempotency cache
# ---------------------------------------------------------------------------

@dataclass
class _IdemEntry:
    ts: float
    fingerprint: str
    state: str  # inflight | done
    status_code: int = 0
    raw_headers: List[Tuple[bytes, bytes]] = field(default_factory=list)
    body: bytes = b""
    media_type: Optional[str] = None


class _IdemCache:
    def __init__(self, ttl: float, max_entries: int):
        self._ttl = float(ttl)
        self._max = int(max_entries)
        self._data: "OrderedDict[str, _IdemEntry]" = OrderedDict()
        self._g = threading.RLock()

    def _evict(self, now: float) -> None:
        while self._data:
            first_key = next(iter(self._data))
            ent = self._data[first_key]
            if (now - ent.ts) > self._ttl or len(self._data) > self._max:
                self._data.pop(first_key, None)
                continue
            break
        while len(self._data) > self._max:
            self._data.popitem(last=False)

    def reserve_or_check(self, slot_key: str, fingerprint: str) -> Tuple[str, Optional[_IdemEntry]]:
        now = time.time()
        with self._g:
            self._evict(now)
            ent = self._data.get(slot_key)
            if ent is None:
                self._data[slot_key] = _IdemEntry(ts=now, fingerprint=fingerprint, state="inflight")
                return "reserved", None

            self._data.move_to_end(slot_key, last=True)
            if ent.fingerprint != fingerprint:
                return "conflict", ent
            if ent.state == "done":
                return "hit", ent
            return "inflight", ent

    def get_done(self, slot_key: str, fingerprint: str) -> Optional[_IdemEntry]:
        now = time.time()
        with self._g:
            self._evict(now)
            ent = self._data.get(slot_key)
            if ent is None or ent.fingerprint != fingerprint or ent.state != "done":
                return None
            self._data.move_to_end(slot_key, last=True)
            return ent

    def set_done(
        self,
        slot_key: str,
        fingerprint: str,
        *,
        code: int,
        raw_headers: Sequence[Tuple[bytes, bytes]],
        body: bytes,
        media_type: Optional[str],
    ) -> None:
        now = time.time()
        with self._g:
            self._evict(now)
            self._data[slot_key] = _IdemEntry(
                ts=now,
                fingerprint=fingerprint,
                state="done",
                status_code=int(code),
                raw_headers=list(raw_headers),
                body=bytes(body),
                media_type=media_type,
            )
            self._data.move_to_end(slot_key, last=True)

    def abort(self, slot_key: str, fingerprint: Optional[str] = None) -> None:
        with self._g:
            ent = self._data.get(slot_key)
            if ent is None:
                return
            if ent.state != "inflight":
                return
            if fingerprint is not None and ent.fingerprint != fingerprint:
                return
            self._data.pop(slot_key, None)


# ---------------------------------------------------------------------------
# Rate limiter compatibility
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _ResolvedRatePolicy:
    token_cost_divisor: float
    capacity: float
    refill_per_s: float


class _LimiterPool:
    def __init__(self, fixed_limiter: Optional[Any], *, capacity: float, refill_per_s: float, divisor: float):
        self._fixed = fixed_limiter
        self._base = _ResolvedRatePolicy(
            token_cost_divisor=max(1.0, float(divisor)),
            capacity=max(0.0, float(capacity)),
            refill_per_s=max(0.0, float(refill_per_s)),
        )
        self._lock = threading.RLock()
        self._cache: Dict[Tuple[float, float], Any] = {}

    def _resolve_from_bound(self, bound: Optional[BoundPolicy]) -> _ResolvedRatePolicy:
        if bound is None:
            return self._base

        divisor = None
        capacity = None
        refill = None
        for name in ("token_cost_divisor", "tokens_divisor", "rate_token_cost_divisor"):
            if hasattr(bound, name):
                divisor = _finite_float(getattr(bound, name, None))
                if divisor is not None:
                    break
        for name in ("capacity", "rl_capacity", "rate_capacity", "subject_capacity"):
            if hasattr(bound, name):
                capacity = _finite_float(getattr(bound, name, None))
                if capacity is not None:
                    break
        for name in ("refill_per_s", "rl_refill_per_s", "rate_refill_per_s", "subject_refill_per_s"):
            if hasattr(bound, name):
                refill = _finite_float(getattr(bound, name, None))
                if refill is not None:
                    break

        return _ResolvedRatePolicy(
            token_cost_divisor=max(1.0, float(divisor if divisor is not None else self._base.token_cost_divisor)),
            capacity=max(0.0, float(capacity if capacity is not None else self._base.capacity)),
            refill_per_s=max(0.0, float(refill if refill is not None else self._base.refill_per_s)),
        )

    def _build(self, *, capacity: float, refill_per_s: float) -> Any:
        if self._fixed is not None:
            return self._fixed
        if RateLimitConfig is not None and RateLimitZoneConfig is not None:
            try:
                cfg = RateLimitConfig(
                    zones={"default": RateLimitZoneConfig(capacity=capacity, refill_per_s=refill_per_s)},
                    default_zone="default",
                    enable_audit=False,
                    enable_metrics=False,
                    allow_dynamic_zones=False,
                )
                return RateLimiter(cfg)
            except Exception:
                pass
        try:
            return RateLimiter(capacity=capacity, refill_per_s=refill_per_s)  # type: ignore[call-arg]
        except Exception:
            return RateLimiter()  # type: ignore[call-arg]

    def _get(self, policy: _ResolvedRatePolicy) -> Any:
        if self._fixed is not None:
            return self._fixed
        key = (float(policy.capacity), float(policy.refill_per_s))
        with self._lock:
            inst = self._cache.get(key)
            if inst is None:
                inst = self._build(capacity=policy.capacity, refill_per_s=policy.refill_per_s)
                self._cache[key] = inst
            return inst

    def _subject_rate_key(self, *, tenant: str, user: str, session: str, model_id: str) -> Any:
        if RateKey is not None:
            with contextlib.suppress(Exception):
                return RateKey(
                    tenant_id=tenant,
                    principal_id=user,
                    subject_id=f"tenant={tenant}|user={user}|session={session}|model={model_id}",
                    session_id=session,
                    resource_id=model_id,
                    route_id="http_subject",
                )
        return (tenant, user, session, model_id)

    def consume(
        self,
        *,
        tenant: str,
        user: str,
        session: str,
        model_id: str,
        cost: float,
        bound: Optional[BoundPolicy],
    ) -> Tuple[bool, Optional[Any], Optional[float], Optional[float]]:
        policy = self._resolve_from_bound(bound)
        if policy.capacity <= 0.0 or policy.refill_per_s <= 0.0:
            return True, None, None, policy.capacity

        limiter = self._get(policy)
        key = self._subject_rate_key(tenant=tenant, user=user, session=session, model_id=model_id)

        remaining_before: Optional[float] = None
        if hasattr(limiter, "peek"):
            with contextlib.suppress(Exception):
                remaining_before = float(limiter.peek(key))  # type: ignore[attr-defined]

        if hasattr(limiter, "consume_decision"):
            with contextlib.suppress(Exception):
                dec = limiter.consume_decision(key=key, cost=float(cost), zone="default")
                return bool(getattr(dec, "allowed", True)), dec, remaining_before, policy.capacity

        with contextlib.suppress(Exception):
            ok = bool(limiter.consume(key, cost=float(cost)))
            return ok, None, remaining_before, policy.capacity

        return True, None, remaining_before, policy.capacity


# ---------------------------------------------------------------------------
# Response replay helper
# ---------------------------------------------------------------------------

class _RawHeaderReplayResponse(Response):
    def __init__(
        self,
        *,
        content: bytes,
        status_code: int,
        raw_headers: Sequence[Tuple[bytes, bytes]],
        media_type: Optional[str] = None,
    ):
        super().__init__(content=content, status_code=int(status_code), media_type=media_type)
        merged = list(raw_headers)
        if not _raw_headers_has(merged, b"content-length"):
            merged.append((b"content-length", str(len(content)).encode("latin1")))
        if media_type and not _raw_headers_has(merged, b"content-type"):
            merged.append((b"content-type", media_type.encode("latin1", errors="ignore")))
        self.raw_headers = merged


# ---------------------------------------------------------------------------
# Internal engine
# ---------------------------------------------------------------------------

class _Reject(Exception):
    def __init__(self, code: int, reason: str, *, retry_after_s: Optional[float] = None):
        self.code = int(code)
        self.reason = str(reason)
        self.retry_after_s = retry_after_s
        super().__init__(reason)


class _RequestMiddlewareEngine:
    def __init__(
        self,
        *,
        cfg: TCDRequestMiddlewareConfig,
        policy_store: Optional[PolicyStore],
        rate_limiter: Optional[Any],
        authenticator: Optional[Any],
    ) -> None:
        self._cfg = cfg.normalized_copy()
        self._metrics = _Metrics(self._cfg.metrics)
        self._store = policy_store
        self._audit = _AuditDispatcher(self._cfg.audit, self._metrics)

        self._authenticator: Optional[Any] = None
        if self._cfg.auth.use_authenticator and _HAS_AUTH:
            self._authenticator = authenticator
            if self._authenticator is None and build_authenticator_from_env is not None:
                with contextlib.suppress(Exception):
                    self._authenticator = build_authenticator_from_env()

        self._rate_pool = _LimiterPool(
            rate_limiter,
            capacity=self._cfg.limits.rl_capacity,
            refill_per_s=self._cfg.limits.rl_refill_per_s,
            divisor=self._cfg.limits.token_cost_divisor_default,
        )
        self._idem = _IdemCache(self._cfg.idempotency.ttl_seconds, self._cfg.idempotency.max_entries)

        self._skip_auth = [re.compile(p) for p in self._cfg.auth.auth_skip_paths]
        self._skip_rate = [re.compile(p) for p in self._cfg.limits.rate_skip_paths]
        self._skip_bind = [re.compile(p) for p in self._cfg.policies.bind_skip_paths]
        self._skip_ct = [re.compile(p) for p in self._cfg.limits.content_type_skip_paths]
        self._skip_idem = [re.compile(p) for p in self._cfg.idempotency.skip_paths]
        self._bypass = [re.compile(p) for p in self._cfg.bypass_paths]

    def _path_match(self, path: str, pats: Iterable[re.Pattern[str]]) -> bool:
        return any(p.search(path) for p in pats)

    def _emit_audit(
        self,
        *,
        event: str,
        request_id: str,
        path: str,
        method: str,
        classification: str,
        sec_level: str,
        ctx: Optional[Mapping[str, str]] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> None:
        if self._cfg.audit.mode == "disabled":
            return
        subj: Dict[str, Any] = {}
        if ctx:
            if self._cfg.audit.hash_subject_fields:
                for k in ("tenant", "user", "session", "model_id"):
                    vv = ctx.get(k, "*")
                    subj[k] = _fold_id(k[:4] or "id", vv) if vv not in ("", "*") else "*"
            else:
                for k in ("tenant", "user", "session", "model_id"):
                    subj[k] = ctx.get(k, "*")
        record: Dict[str, Any] = {
            "schema": "tcd.request.audit.v2",
            "event": _safe_text(event, max_len=64),
            "request_id": request_id,
            "method": _safe_text(method, max_len=16).upper(),
            "path": _default_normalizer(path)[:256],
            "classification": _safe_text(classification, max_len=64) or "unclassified",
            "sec_level": _safe_text(sec_level, max_len=32) or "public",
            "subject": subj,
            "ts_unix_ms": int(time.time() * 1000),
        }
        if extra:
            small: Dict[str, Any] = {}
            for k, v in extra.items():
                kk = _safe_text(k, max_len=64).lower()
                if not kk:
                    continue
                if isinstance(v, str):
                    small[kk] = _safe_text(v, max_len=256)
                elif isinstance(v, (int, float, bool)) or v is None:
                    small[kk] = v
            if small:
                record["extra"] = small
        try:
            raw = json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8", errors="strict")
            if len(raw) > self._cfg.audit.max_event_bytes:
                record = {
                    "schema": record["schema"],
                    "event": record["event"],
                    "request_id": request_id,
                    "method": record["method"],
                    "path": record["path"],
                    "ts_unix_ms": record["ts_unix_ms"],
                    "truncated": True,
                }
            self._audit.emit(record)
        except Exception:
            _logger.debug("request audit emit failed", exc_info=True)

    def _derive_classification(self, sec_ctx: Mapping[str, Any]) -> str:
        val = sec_ctx.get("classification") or sec_ctx.get("class") or sec_ctx.get("level")
        if isinstance(val, str) and val.strip():
            return _safe_text(val, max_len=64) or "unclassified"
        return "unclassified"

    def _should_use_idempotency(self, classification: str) -> bool:
        deny = {x.lower() for x in self._cfg.security.idempotency_disallowed_classes}
        if not classification:
            return True
        return classification.lower() not in deny

    def _filter_idem_headers(self, raw_headers: Sequence[Tuple[bytes, bytes]]) -> List[Tuple[bytes, bytes]]:
        deny = {
            b"authorization",
            b"proxy-authorization",
            b"cookie",
            b"set-cookie",
            b"x-internal-token",
            b"x-internal-auth",
            b"transfer-encoding",
            b"connection",
            self._cfg.auth.signature_header.lower().encode("latin1", errors="ignore"),
        }
        out: List[Tuple[bytes, bytes]] = []
        for k, v in raw_headers:
            kl = k.lower()
            if kl in deny:
                continue
            out.append((k, v))
        return out

    def _ensure_request_context(self, req: Request, request_id: str) -> Dict[str, Any]:
        trust_profile = _trusted_profile_from_state_or_default(req.state, self._cfg.security.profile)
        _state_set(req.state, "request_id", request_id)
        ctx = {
            "request_id": request_id,
            "session_id": _state_get(req.state, "session_id", None),
            "request_chain": _state_get(req.state, "request_chain", None),
            "upstream_id_accepted": bool(_state_get(req.state, "upstream_id_accepted", False)),
            "upstream_id_trusted": bool(_state_get(req.state, "upstream_id_trusted", False)),
            "session_rotated": bool(_state_get(req.state, "session_rotated", False)),
            "session_source": _safe_text(_state_get(req.state, "session_source", None), max_len=32) or None,
            "chain_truncated": bool(_state_get(req.state, "chain_truncated", False)),
            "xff_ignored_reason": _safe_text(_state_get(req.state, "xff_ignored_reason", None), max_len=64) or None,
            "edge_rate_limited": bool(_state_get(req.state, "edge_rate_limited", False)),
            "edge_rate_zone": _safe_text(_state_get(req.state, "edge_rate_zone", None), max_len=64) or None,
            "trust_profile": trust_profile,
        }
        try:
            _state_set(req.state, "tcd_request_context", MappingProxyType(dict(ctx)))
        except Exception:
            pass
        return ctx

    async def _auth_ok(self, req: Request, raw_body: bytes, norm_path: str) -> Tuple[bool, Dict[str, Any], Optional[str], int]:
        if self._path_match(req.url.path, self._skip_auth):
            sec_ctx = {
                "authn_method": "none",
                "classification": "unclassified",
                "trusted": True,
                "principal": None,
                "scopes": (),
                "key_id": None,
                "policy_digest": None,
            }
            _state_set(req.state, "security_ctx", sec_ctx)
            return True, sec_ctx, None, 200

        if self._cfg.security.require_authenticator and self._authenticator is None:
            if self._metrics.enabled:
                self._metrics.auth_sig.labels("fail", norm_path).inc()
                if self._metrics.auth_sig_fail_reason is not None:
                    self._metrics.auth_sig_fail_reason.labels("authenticator_missing", norm_path).inc()
            sec_ctx = {"authn_method": "none", "classification": "unclassified", "trusted": False}
            _state_set(req.state, "security_ctx", sec_ctx)
            return False, sec_ctx, "authenticator_unavailable", 503

        if self._authenticator is not None:
            try:
                out = self._authenticator.verify(req)
                if inspect.isawaitable(out):
                    out = await out
                res = out
            except Exception:
                if self._metrics.enabled:
                    self._metrics.auth_sig.labels("fail", norm_path).inc()
                    if self._metrics.auth_sig_fail_reason is not None:
                        self._metrics.auth_sig_fail_reason.labels("authenticator_error", norm_path).inc()
                sec_ctx = {"authn_method": "authenticator", "classification": "unclassified", "trusted": False}
                _state_set(req.state, "security_ctx", sec_ctx)
                return False, sec_ctx, "authenticator_error", 503

            ok = bool(getattr(res, "ok", False))
            raw_ctx = _mapping_from_obj(getattr(res, "ctx", None))
            reason = _safe_text(getattr(res, "reason", None), max_len=64) or None
            scopes = raw_ctx.get("scopes") or ()
            if isinstance(scopes, str):
                scopes_out = tuple(x.strip() for x in scopes.split(",") if x.strip())[:16]
            elif isinstance(scopes, (list, tuple, set, frozenset)):
                scopes_out = tuple(_safe_text(x, max_len=64) for x in list(scopes)[:16] if _safe_text(x, max_len=64))
            else:
                scopes_out = ()

            sec_ctx: Dict[str, Any] = {
                "authn_method": _safe_text(raw_ctx.get("mode") or "authenticator", max_len=32) or "authenticator",
                "classification": _safe_text(raw_ctx.get("classification") or raw_ctx.get("class") or raw_ctx.get("level"), max_len=64) or "unclassified",
                "trusted": ok,
                "principal": _safe_text(raw_ctx.get("principal") or raw_ctx.get("principal_id"), max_len=128) or None,
                "scopes": scopes_out,
                "key_id": _safe_text(raw_ctx.get("key_id"), max_len=128) or None,
                "policy_digest": _safe_text(raw_ctx.get("policy_digest"), max_len=128) or None,
                "authn_strength": _safe_text(raw_ctx.get("authn_strength"), max_len=32),
                "tenant": _safe_text(raw_ctx.get("tenant"), max_len=128) or None,
                "user": _safe_text(raw_ctx.get("user"), max_len=128) or None,
                "session": _safe_text(raw_ctx.get("session"), max_len=128) or None,
            }
            _state_set(req.state, "security_ctx", sec_ctx)
            if self._metrics.enabled:
                self._metrics.auth_sig.labels("ok" if ok else "fail", norm_path).inc()
                if not ok and self._metrics.auth_sig_fail_reason is not None:
                    self._metrics.auth_sig_fail_reason.labels(reason or "denied", norm_path).inc()
            return ok, sec_ctx, reason, (200 if ok else 403)

        if self._cfg.security.forbid_legacy_auth:
            if self._metrics.enabled:
                self._metrics.auth_sig.labels("fail", norm_path).inc()
                if self._metrics.auth_sig_fail_reason is not None:
                    self._metrics.auth_sig_fail_reason.labels("legacy_auth_forbidden", norm_path).inc()
            sec_ctx = {"authn_method": "none", "classification": "unclassified", "trusted": False}
            _state_set(req.state, "security_ctx", sec_ctx)
            return False, sec_ctx, "legacy_auth_forbidden", 403

        # Legacy fallback
        bearer_secret = (os.getenv(self._cfg.auth.bearer_token_env) or "").strip() if self._cfg.auth.enable_bearer else ""
        hmac_secret = (os.getenv(self._cfg.auth.hmac_secret_env) or "").strip() if self._cfg.auth.enable_hmac else ""

        # No configured credentials at all
        if not bearer_secret and not hmac_secret:
            if self._cfg.security.allow_anonymous_if_unconfigured:
                sec_ctx = {
                    "authn_method": "none",
                    "classification": "unclassified",
                    "trusted": False,
                    "principal": None,
                    "scopes": (),
                    "key_id": None,
                    "policy_digest": None,
                }
                _state_set(req.state, "security_ctx", sec_ctx)
                return True, sec_ctx, None, 200
            sec_ctx = {"authn_method": "none", "classification": "unclassified", "trusted": False}
            _state_set(req.state, "security_ctx", sec_ctx)
            return False, sec_ctx, "auth_unconfigured", 503

        checks: List[Tuple[bool, str, Optional[str]]] = []

        if bearer_secret:
            have = (req.headers.get("authorization") or "").strip()
            ok_b = False
            reason_b = "missing_bearer"
            if len(have.encode("utf-8", errors="ignore")) > self._cfg.auth.max_auth_header_bytes:
                reason_b = "header_too_large"
            elif have.lower().startswith("bearer "):
                token = have[7:].strip()
                if hmac.compare_digest(token, bearer_secret):
                    ok_b = True
                    reason_b = "ok"
                else:
                    reason_b = "bearer_mismatch"
            checks.append((ok_b, reason_b, "legacy_bearer"))

        if hmac_secret:
            sig_val = (req.headers.get(self._cfg.auth.signature_header) or "").strip()
            ok_h = False
            reason_h = "hmac_missing"
            key_id = _safe_text(req.headers.get("X-TCD-Key-Id"), max_len=128) or None
            sig_hex = sig_val
            if "=" in sig_hex:
                sig_hex = sig_hex.split("=", 1)[-1].strip()
            if sig_hex.startswith(("0x", "0X")):
                sig_hex = sig_hex[2:]
            if sig_hex and _HEX_RE.fullmatch(sig_hex):
                canonical = (
                    req.method.upper().encode("utf-8")
                    + b"\n"
                    + req.url.path.encode("utf-8")
                    + b"\n"
                    + (req.url.query or "").encode("utf-8")
                    + b"\n"
                    + raw_body
                )
                calc = hmac.new(hmac_secret.encode("utf-8"), canonical, "sha256").hexdigest()
                if hmac.compare_digest(calc, sig_hex.lower()):
                    ok_h = True
                    reason_h = "ok"
                else:
                    reason_h = "hmac_mismatch"
            checks.append((ok_h, reason_h, "legacy_hmac" if key_id is None else key_id))

        passed = [c for c in checks if c[0]]
        ok = False
        principal = None
        authn_method = "legacy"
        reason = "denied"

        if self._cfg.auth.legacy_require_all:
            ok = bool(checks) and all(c[0] for c in checks)
            if ok:
                principal = "legacy_all"
                authn_method = "legacy"
                reason = "ok"
            else:
                reason = next((c[1] for c in checks if not c[0]), "denied")
        else:
            if passed:
                ok = True
                reason = "ok"
                principal = passed[0][2]
                authn_method = "bearer" if principal == "legacy_bearer" else "hmac"
            else:
                reason = checks[0][1] if checks else "denied"

        sec_ctx = {
            "authn_method": authn_method,
            "classification": "unclassified",
            "trusted": ok,
            "principal": principal,
            "scopes": (),
            "key_id": _safe_text(req.headers.get("X-TCD-Key-Id"), max_len=128) or None,
            "policy_digest": None,
        }
        _state_set(req.state, "security_ctx", sec_ctx)

        if self._metrics.enabled:
            self._metrics.auth_sig.labels("ok" if ok else "fail", norm_path).inc()
            if not ok and self._metrics.auth_sig_fail_reason is not None:
                self._metrics.auth_sig_fail_reason.labels(reason, norm_path).inc()
        return ok, sec_ctx, (None if ok else reason), (200 if ok else 403)

    async def _read_body_with_limit(self, req: Request, *, path: str, method: str) -> bytes:
        cl = req.headers.get("content-length")
        cl_val: Optional[int] = None
        if cl is not None:
            try:
                cl_val = int(cl)
            except Exception:
                cl_val = None
            if cl_val is None or cl_val < 0:
                raise _Reject(400, "invalid_content_length")
            if cl_val > self._cfg.limits.max_body_bytes:
                raise _Reject(413, "payload_too_large")

        if len(req.url.path.encode("utf-8", errors="ignore")) > self._cfg.limits.max_path_bytes:
            raise _Reject(414, "path_too_large")
        if len(req.url.query.encode("utf-8", errors="ignore")) > self._cfg.limits.max_query_bytes:
            raise _Reject(414, "query_too_large")

        wants_body = method in set(self._cfg.limits.body_methods)
        if not wants_body and (cl_val is None or cl_val == 0) and not req.headers.get("transfer-encoding"):
            return b""

        if self._cfg.limits.enforce_json_content_type and wants_body and not self._path_match(path, self._skip_ct):
            ct = req.headers.get("content-type")
            if raw := req.headers.get("content-type"):
                if len(raw.encode("utf-8", errors="ignore")) > 4096:
                    raise _Reject(400, "content_type_too_large")
            if not _content_type_is_json(ct):
                raise _Reject(415, "unsupported_media_type")

        if cl_val is not None:
            body = await req.body()
            if len(body) > self._cfg.limits.max_body_bytes:
                raise _Reject(413, "payload_too_large")
            try:
                setattr(req, "_body", body)
            except Exception:
                pass
            return body

        chunks: List[bytes] = []
        total = 0
        async for chunk in req.stream():
            if not chunk:
                continue
            b = bytes(chunk)
            total += len(b)
            if total > self._cfg.limits.hard_read_cap_bytes:
                raise _Reject(413, "payload_too_large")
            chunks.append(b)
        body = b"".join(chunks)
        try:
            setattr(req, "_body", body)
        except Exception:
            pass
        return body

    def _parse_body(self, *, raw_body: bytes, path: str, declared_json: bool) -> Tuple[bytes, Optional[Any]]:
        if not raw_body:
            return b"", None

        should_parse = declared_json or _guess_json_body(raw_body)
        if not should_parse:
            return raw_body, None

        try:
            obj = _strict_json_loads(
                raw_body,
                max_depth=self._cfg.limits.max_json_depth,
                max_int_digits=self._cfg.limits.max_json_int_digits,
            )
            budget = _JsonComplexityBudget(
                max_nodes=self._cfg.limits.max_json_nodes,
                max_depth=self._cfg.limits.max_json_depth,
                max_items=self._cfg.limits.max_json_items,
                max_key_bytes=self._cfg.limits.max_json_key_bytes,
                max_total_str_bytes=self._cfg.limits.max_json_total_str_bytes,
                max_string_bytes=self._cfg.limits.max_json_string_bytes,
            )
            _walk_json_budget(obj, depth=0, budget=budget)
        except ValueError as exc:
            reason = _safe_text(exc, max_len=64) or "invalid_json"
            if declared_json and self._cfg.limits.reject_invalid_json_when_declared:
                raise _Reject(400, reason)
            return raw_body, None

        try:
            canonical = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
        except Exception:
            canonical = raw_body
        return canonical, obj

    def _extract_ctx(self, req: Request, body_json: Optional[Any], classification: str) -> Dict[str, str]:
        body_map = body_json if isinstance(body_json, Mapping) else {}
        headers = req.headers
        sec_ctx = _state_get(req.state, "security_ctx", {})
        if not isinstance(sec_ctx, Mapping):
            sec_ctx = {}

        principal = _safe_ctx_value(sec_ctx.get("principal") or sec_ctx.get("principal_id"), field_name="principal")
        session_from_state = _safe_ctx_value(_state_get(req.state, "session_id", None), field_name="session")
        trust_profile = _trusted_profile_from_state_or_default(req.state, self._cfg.security.profile)

        ctx = {
            "tenant": _safe_ctx_value(sec_ctx.get("tenant") or headers.get(self._cfg.policies.h_tenant) or body_map.get("tenant"), field_name="tenant"),
            "user": principal if principal != "*" else _safe_ctx_value(sec_ctx.get("user") or headers.get(self._cfg.policies.h_user) or body_map.get("user"), field_name="user"),
            "session": session_from_state if session_from_state != "*" else _safe_ctx_value(sec_ctx.get("session") or headers.get(self._cfg.policies.h_session) or body_map.get("session"), field_name="session"),
            "model_id": _safe_ctx_value(headers.get(self._cfg.policies.h_model) or body_map.get("model_id"), field_name="model"),
            "gpu_id": _safe_ctx_value(headers.get(self._cfg.policies.h_gpu) or body_map.get("gpu_id"), field_name="gpu"),
            "task": _safe_ctx_value(headers.get(self._cfg.policies.h_task) or body_map.get("task"), field_name="task"),
            "lang": _safe_ctx_value(headers.get(self._cfg.policies.h_lang) or body_map.get("lang"), field_name="lang"),
            "trust_zone": _safe_ctx_value(
                headers.get(self._cfg.policies.h_trust_zone)
                or body_map.get("trust_zone")
                or _state_get(_state_get(req.state, "edge_security", {}), "trust_zone", None),
                field_name="zone",
            ),
            "route_profile": _safe_ctx_value(
                headers.get(self._cfg.policies.h_route_profile)
                or body_map.get("route_profile")
                or _state_get(_state_get(req.state, "edge_security", {}), "route_profile", None),
                field_name="route",
            ),
        }

        ctx["_classification"] = _safe_text(classification, max_len=64).lower() or "unclassified"
        ctx["_request_id"] = _request_id_from_state_or_headers(req, self._cfg.request_id_header)
        ctx["_trust_profile"] = trust_profile
        ctx["_trusted_principal"] = "true" if principal != "*" else "false"

        if self._cfg.policies.include_request_context:
            ctx["_session_source"] = _safe_text(_state_get(req.state, "session_source", None), max_len=32) or "unknown"
            ctx["_upstream_id_trusted"] = "true" if bool(_state_get(req.state, "upstream_id_trusted", False)) else "false"
            ctx["_edge_rate_zone"] = _safe_text(_state_get(req.state, "edge_rate_zone", None), max_len=64) or "unknown"
            ctx["_xff_reason"] = _safe_text(_state_get(req.state, "xff_ignored_reason", None), max_len=64) or ""
        return ctx

    def _policy_bind(self, req: Request, ctx: Dict[str, str]) -> Optional[BoundPolicy]:
        if self._store is None or self._path_match(req.url.path, self._skip_bind):
            _state_set(req.state, "tcd_ctx", MappingProxyType(dict(ctx)))
            return None
        try:
            bound = self._store.bind(ctx)
        except Exception as exc:
            raise _Reject(503, "policy_bind_failed") from exc
        _state_set(req.state, "tcd_policy", bound)
        _state_set(req.state, "tcd_ctx", MappingProxyType(dict(ctx)))
        return bound

    def _policy_ref(self, bound: Optional[BoundPolicy]) -> Optional[str]:
        if bound is None:
            return None
        for name in ("policy_ref", "rule_id", "policy_id", "name"):
            with contextlib.suppress(Exception):
                v = getattr(bound, name, None)
                if isinstance(v, str) and v.strip():
                    return _safe_text(v, max_len=128) or None
        return None

    def _rate_check(
        self,
        req: Request,
        *,
        ctx: Dict[str, str],
        body_json: Optional[Any],
        norm_path: str,
        bound: Optional[BoundPolicy],
    ) -> Tuple[bool, Optional[float], Optional[float], Optional[Any]]:
        if self._path_match(req.url.path, self._skip_rate):
            return True, None, None, None

        tokens_delta = 1.0
        if isinstance(body_json, Mapping) and "tokens_delta" in body_json:
            td = _finite_float(body_json.get("tokens_delta"))
            if td is not None:
                tokens_delta = max(0.0, td)

        divisor = self._rate_pool._resolve_from_bound(bound).token_cost_divisor
        cost = max(1.0, tokens_delta / max(1.0, float(divisor)))

        cls_name = (ctx.get("_classification") or "").lower()
        high_cost = {x.lower() for x in self._cfg.security.high_cost_classes}
        if cls_name and cls_name in high_cost:
            cost = max(1.0, cost * 2.0)

        sec_ctx = _state_get(req.state, "security_ctx", {})
        if not isinstance(sec_ctx, Mapping):
            sec_ctx = {}
        trusted_principal = _safe_ctx_value(sec_ctx.get("principal") or sec_ctx.get("principal_id"), field_name="principal")
        session_id = _safe_ctx_value(_state_get(req.state, "session_id", None), field_name="session")
        # Subject key must not be fully client-spoofable. Prefer authenticated principal
        # and middleware-issued session ids over header/body hints.
        rate_user = trusted_principal if trusted_principal != "*" else ctx.get("user", "*")
        rate_session = session_id if session_id != "*" else ctx.get("session", "*")

        allowed, dec, remaining_before, capacity = self._rate_pool.consume(
            tenant=ctx.get("tenant", "*"),
            user=rate_user,
            session=rate_session,
            model_id=ctx.get("model_id", "*"),
            cost=cost,
            bound=bound,
        )

        if not allowed and self._metrics.enabled:
            self._metrics.rate_block.labels(norm_path).inc()
        _state_set(req.state, "tcd_rate_limit_decision", dec)
        return allowed, remaining_before, capacity, dec

    def _rate_header_values(
        self,
        *,
        remaining_before: Optional[float],
        capacity: Optional[float],
        decision: Optional[Any],
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        limit = None
        remain = None
        retry = None

        if capacity is not None and math.isfinite(capacity):
            limit = str(max(0, int(capacity)))
        if remaining_before is not None and math.isfinite(remaining_before):
            remain = str(max(0, int(remaining_before)))

        if decision is not None:
            for attr in ("retry_after_s", "retry_after", "wait_s"):
                with contextlib.suppress(Exception):
                    rv = _finite_float(getattr(decision, attr))
                    if rv is not None and rv > 0:
                        retry = str(max(1, int(math.ceil(rv))))
                        break
            for attr in ("remaining", "remaining_tokens", "tokens_remaining"):
                with contextlib.suppress(Exception):
                    rv2 = _finite_float(getattr(decision, attr))
                    if rv2 is not None:
                        remain = str(max(0, int(rv2)))
                        break
            for attr in ("capacity", "limit", "bucket_capacity"):
                with contextlib.suppress(Exception):
                    lv = _finite_float(getattr(decision, attr))
                    if lv is not None:
                        limit = str(max(0, int(lv)))
                        break
        return limit, remain, retry

    def _idempotency_slot_key(self, req: Request, *, norm_path: str, idem_val: str, ctx: Mapping[str, str]) -> str:
        parts = [req.method.upper(), norm_path, idem_val]
        if self._cfg.idempotency.include_subject_in_slot:
            parts.extend([ctx.get("tenant", "*"), ctx.get("user", "*"), ctx.get("session", "*"), ctx.get("model_id", "*")])
        return _hash_hex("||".join(parts).encode("utf-8", errors="strict"))

    def _idempotency_fingerprint(
        self,
        req: Request,
        *,
        canonical_body: bytes,
    ) -> str:
        vary_parts: List[str] = []
        for hname in self._cfg.idempotency.vary_on_headers:
            v = (req.headers.get(hname) or req.headers.get(hname.title()) or "").strip().lower()
            vary_parts.append(f"{hname}={v}")
        payload = req.method.upper().encode("utf-8") + b"\n" + req.url.path.encode("utf-8") + b"\n" + ";".join(vary_parts).encode("utf-8") + b"\n" + canonical_body
        return _hash_hex(b"tcd:middleware_request:idemfp\x00" + payload)

    async def _wait_idem(self, slot_key: str, fingerprint: str, timeout_s: float) -> Optional[_IdemEntry]:
        deadline = time.monotonic() + max(0.0, timeout_s)
        while time.monotonic() < deadline:
            got = self._idem.get_done(slot_key, fingerprint)
            if got is not None:
                return got
            await asyncio.sleep(0.01)
        return None


# ---------------------------------------------------------------------------
# Internal helpers (ASGI/body/response)
# ---------------------------------------------------------------------------

def _iterable_as_receive(iterable: Iterable[Dict[str, Any]]) -> Callable[[], Awaitable[Dict[str, Any]]]:
    iterator = iter(iterable)

    async def receive() -> Dict[str, Any]:
        try:
            return next(iterator)
        except StopIteration:
            await asyncio.sleep(0)
            return {"type": "http.request", "body": b"", "more_body": False}

    return receive


def _make_body_receive(body: bytes) -> Receive:
    sent = False

    async def _receive() -> Message:
        nonlocal sent
        if sent:
            await asyncio.sleep(0)
            return {"type": "http.request", "body": b"", "more_body": False}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    return _receive


# ---------------------------------------------------------------------------
# BaseHTTPMiddleware implementation
# ---------------------------------------------------------------------------

class TCDRequestMiddleware(BaseHTTPMiddleware):
    """
    Request-governance middleware aligned with the stronger contracts in
    middleware.py and middleware_security.py:

      - respects request.state.request_id / session_id / request_chain /
        upstream_id_accepted / upstream_id_trusted / session_rotated /
        session_source / tcd_trust_profile
      - respects request.state.edge_security / edge_rate_limited / edge_rate_zone /
        xff_ignored_reason
      - strict body/header/json budgets
      - authenticator-first auth, guarded legacy fallback
      - policy binding + subject-aware rate limiting
      - idempotency with slot-vs-fingerprint conflict semantics
      - pure ASGI companion for streaming-safe production deployments
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
        self._engine = _RequestMiddlewareEngine(
            cfg=cfg or TCDRequestMiddlewareConfig(),
            policy_store=policy_store,
            rate_limiter=rate_limiter,
            authenticator=authenticator,
        )

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        path = request.url.path
        if self._engine._path_match(path, self._engine._bypass):
            return await call_next(request)

        t0 = time.perf_counter()
        norm_path = self._engine._cfg.metrics.path_normalizer(path)
        req_id = _request_id_from_state_or_headers(request, self._engine._cfg.request_id_header)
        trust_profile = _trusted_profile_from_state_or_default(request.state, self._engine._cfg.security.profile)
        classification = "unclassified"
        sec_level = "public"
        body_for_metrics = b""
        slot_key: Optional[str] = None
        idem_fp: Optional[str] = None

        if self._engine._metrics.enabled and self._engine._metrics.inflight is not None:
            self._engine._metrics.inflight.labels(norm_path).inc()

        try:
            hdr_count, hdr_bytes = _headers_budget(request.scope)
            if hdr_count > self._engine._cfg.limits.max_header_count:
                raise _Reject(431, "headers_too_many")
            if hdr_bytes > self._engine._cfg.limits.max_header_bytes:
                raise _Reject(431, "headers_too_large")

            self._engine._ensure_request_context(request, req_id)

            declared_json = _content_type_is_json(request.headers.get("content-type"))
            raw_body = await self._engine._read_body_with_limit(request, path=path, method=request.method.upper())
            body_for_metrics = raw_body
            try:
                setattr(request, "_body", raw_body)
            except Exception:
                pass

            ok_auth, sec_ctx, auth_reason, auth_status = await self._engine._auth_ok(request, raw_body, norm_path)
            _state_set(request.state, "auth_mode", _safe_text(sec_ctx.get("authn_method"), max_len=32) or "none")
            _state_set(request.state, "auth_trusted", bool(sec_ctx.get("trusted", False)))
            _state_set(request.state, "auth_principal", sec_ctx.get("principal"))
            _state_set(request.state, "auth_scopes", list(sec_ctx.get("scopes") or ()))
            _state_set(request.state, "auth_key_id", sec_ctx.get("key_id"))
            _state_set(request.state, "auth_policy_digest", sec_ctx.get("policy_digest"))
            _state_set(request.state, "auth_reason", auth_reason)
            if not ok_auth:
                raise _Reject(auth_status, "forbidden" if auth_status == 403 else auth_reason or "auth_failed")

            canonical_body, body_json = self._engine._parse_body(raw_body=raw_body, path=path, declared_json=declared_json)
            _state_set(request.state, "body_bytes", raw_body)
            _state_set(request.state, "body_digest_raw", _stable_body_digest(raw_body))
            _state_set(request.state, "body_digest_canonical", _stable_body_digest(canonical_body))
            _state_set(request.state, "body_json", body_json if isinstance(body_json, (dict, list)) else None)

            classification = self._engine._derive_classification(sec_ctx)
            sec_level = _coarse_security_level(classification)

            ctx = self._engine._extract_ctx(request, body_json, classification)
            bound = self._engine._policy_bind(request, ctx)
            if bound is not None:
                _state_set(request.state, "tcd_policy_ref", self._engine._policy_ref(bound))

            ok_rate, remaining_before, capacity, decision = self._engine._rate_check(
                request,
                ctx=ctx,
                body_json=body_json,
                norm_path=norm_path,
                bound=bound,
            )
            if not ok_rate:
                _, _, retry = self._engine._rate_header_values(
                    remaining_before=remaining_before,
                    capacity=capacity,
                    decision=decision,
                )
                raise _Reject(429, "rate_limited", retry_after_s=_finite_float(retry) if retry is not None else None)

            idem_header = request.headers.get(self._engine._cfg.idempotency.header)
            use_idem = (
                self._engine._cfg.idempotency.enable
                and isinstance(idem_header, str)
                and bool(_IDEMPOTENCY_KEY_RE.fullmatch(idem_header.strip()))
                and request.method.upper() in set(self._engine._cfg.idempotency.methods)
                and not self._engine._path_match(path, self._engine._skip_idem)
                and self._engine._should_use_idempotency(classification)
            )

            if use_idem and idem_header:
                slot_key = self._engine._idempotency_slot_key(
                    request,
                    norm_path=norm_path,
                    idem_val=idem_header.strip(),
                    ctx=ctx,
                )
                idem_fp = self._engine._idempotency_fingerprint(request, canonical_body=canonical_body)
                state, ent = self._engine._idem.reserve_or_check(slot_key, idem_fp)
                if state == "conflict":
                    if self._engine._metrics.enabled:
                        self._engine._metrics.idem_ctr.labels("conflict", norm_path).inc()
                    raise _Reject(409, "idempotency_conflict")
                if state == "hit" and ent is not None:
                    if self._engine._metrics.enabled:
                        self._engine._metrics.idem_ctr.labels("hit", norm_path).inc()
                    raw_headers = list(ent.raw_headers)
                    _raw_headers_append_if_missing(
                        raw_headers,
                        self._engine._cfg.request_id_header.encode("latin1", errors="ignore"),
                        req_id.encode("latin1", errors="ignore"),
                    )
                    self._engine._emit_audit(
                        event="idempotency_hit",
                        request_id=req_id,
                        path=path,
                        method=request.method,
                        classification=classification,
                        sec_level=sec_level,
                        ctx=ctx,
                    )
                    return _RawHeaderReplayResponse(
                        content=bytes(ent.body),
                        status_code=ent.status_code,
                        raw_headers=raw_headers,
                        media_type=ent.media_type,
                    )
                if state == "inflight":
                    if self._engine._cfg.idempotency.wait_on_inflight:
                        waited = await self._engine._wait_idem(slot_key, idem_fp, self._engine._cfg.idempotency.inflight_wait_timeout_s)
                        if waited is not None:
                            if self._engine._metrics.enabled:
                                self._engine._metrics.idem_ctr.labels("wait_hit", norm_path).inc()
                            raw_headers = list(waited.raw_headers)
                            _raw_headers_append_if_missing(
                                raw_headers,
                                self._engine._cfg.request_id_header.encode("latin1", errors="ignore"),
                                req_id.encode("latin1", errors="ignore"),
                            )
                            return _RawHeaderReplayResponse(
                                content=bytes(waited.body),
                                status_code=waited.status_code,
                                raw_headers=raw_headers,
                                media_type=waited.media_type,
                            )
                    raise _Reject(409, "idempotency_inflight")

            # replay original raw body to downstream
            request._receive = _iterable_as_receive([{"type": "http.request", "body": raw_body, "more_body": False}])  # type: ignore[attr-defined]

            resp = await call_next(request)

            try:
                resp.headers.setdefault(self._engine._cfg.request_id_header, req_id)
            except Exception:
                pass

            status_code = int(resp.status_code)
            raw_headers = list(getattr(resp, "raw_headers", []) or [])
            resp_body = b""
            can_store_idem = False

            body_attr = getattr(resp, "body", None)
            if isinstance(body_attr, (bytes, bytearray, memoryview)):
                resp_body = bytes(body_attr)
                can_store_idem = True

            if self._engine._cfg.limits.emit_rate_headers:
                limit, remain, retry = self._engine._rate_header_values(
                    remaining_before=remaining_before,
                    capacity=capacity,
                    decision=decision,
                )
                with contextlib.suppress(Exception):
                    if limit is not None and "X-RateLimit-Limit" not in resp.headers:
                        resp.headers["X-RateLimit-Limit"] = limit
                    if remain is not None and "X-RateLimit-Remaining" not in resp.headers:
                        resp.headers["X-RateLimit-Remaining"] = remain
                    if retry is not None and status_code == 429 and "Retry-After" not in resp.headers:
                        resp.headers["Retry-After"] = retry
                raw_headers = list(getattr(resp, "raw_headers", []) or [])

            if slot_key and idem_fp:
                if not can_store_idem and self._engine._cfg.idempotency.reject_streaming_responses:
                    self._engine._idem.abort(slot_key, idem_fp)
                    if self._engine._metrics.enabled:
                        self._engine._metrics.idem_ctr.labels("stream_skip", norm_path).inc()
                else:
                    if ((not self._engine._cfg.idempotency.store_only_2xx) or (200 <= status_code < 300)) and len(resp_body) <= self._engine._cfg.idempotency.max_store_bytes and can_store_idem:
                        media_type = _extract_media_type_from_raw_headers(raw_headers)
                        self._engine._idem.set_done(
                            slot_key,
                            idem_fp,
                            code=status_code,
                            raw_headers=self._engine._filter_idem_headers(raw_headers),
                            body=resp_body,
                            media_type=media_type,
                        )
                        if self._engine._metrics.enabled:
                            self._engine._metrics.idem_ctr.labels("store", norm_path).inc()
                    else:
                        self._engine._idem.abort(slot_key, idem_fp)
                        if self._engine._metrics.enabled:
                            self._engine._metrics.idem_ctr.labels("skip", norm_path).inc()

            if self._engine._cfg.audit.emit_success:
                self._engine._emit_audit(
                    event="request_ok",
                    request_id=req_id,
                    path=path,
                    method=request.method,
                    classification=classification,
                    sec_level=sec_level,
                    ctx=ctx,
                    extra={"code": status_code, "policy_ref": self._engine._policy_ref(bound) or ""},
                )

            if self._engine._metrics.enabled:
                self._engine._metrics.req_bytes.labels(request.method, norm_path).inc(len(body_for_metrics))
                self._engine._metrics.resp_bytes.labels(request.method, norm_path, str(status_code)).inc(len(resp_body))
                self._engine._metrics.req_ctr.labels(request.method, norm_path, str(status_code)).inc()
                self._engine._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
                if self._engine._metrics.req_sec is not None:
                    self._engine._metrics.req_sec.labels(sec_level, norm_path).inc()

            return resp

        except _Reject as rj:
            if slot_key and idem_fp:
                self._engine._idem.abort(slot_key, idem_fp)

            headers: Dict[str, str] = {}
            if rj.retry_after_s is not None and rj.retry_after_s > 0:
                headers["Retry-After"] = str(max(1, int(math.ceil(rj.retry_after_s))))
            if self._engine._cfg.security.hide_reject_reason_in_high_security and _profile_is_high_security(trust_profile):
                out_reason = "forbidden" if rj.code == 403 else ("rate_limited" if rj.code == 429 else "request_rejected")
            else:
                out_reason = rj.reason
            if self._engine._metrics.enabled:
                self._engine._metrics.req_reject.labels(rj.reason, norm_path).inc()
                self._engine._metrics.req_ctr.labels(request.method, norm_path, str(rj.code)).inc()
                self._engine._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
                if self._engine._metrics.req_sec is not None:
                    self._engine._metrics.req_sec.labels(sec_level, norm_path).inc()
            self._engine._emit_audit(
                event="request_reject",
                request_id=req_id,
                path=path,
                method=request.method,
                classification=classification,
                sec_level=sec_level,
                ctx=_state_get(request.state, "tcd_ctx", {}) if isinstance(_state_get(request.state, "tcd_ctx", {}), Mapping) else None,
                extra={"code": rj.code, "reason": rj.reason},
            )
            return _json_error(status_code=rj.code, reason=out_reason, request_id=req_id, headers=headers)
        except Exception:
            if slot_key and idem_fp:
                self._engine._idem.abort(slot_key, idem_fp)

            _logger.exception("Unhandled exception in TCDRequestMiddleware.dispatch")
            if self._engine._metrics.enabled:
                self._engine._metrics.req_reject.labels("exception", norm_path).inc()
                self._engine._metrics.req_ctr.labels(request.method, norm_path, "500").inc()
                self._engine._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
                if self._engine._metrics.req_sec is not None:
                    self._engine._metrics.req_sec.labels(sec_level, norm_path).inc()
            self._engine._emit_audit(
                event="request_exception",
                request_id=req_id,
                path=path,
                method=request.method,
                classification=classification,
                sec_level=sec_level,
                ctx=_state_get(request.state, "tcd_ctx", {}) if isinstance(_state_get(request.state, "tcd_ctx", {}), Mapping) else None,
            )
            return _json_error(status_code=500, reason="internal", request_id=req_id)
        finally:
            if self._engine._metrics.enabled and self._engine._metrics.inflight is not None:
                with contextlib.suppress(Exception):
                    self._engine._metrics.inflight.labels(norm_path).dec()


# ---------------------------------------------------------------------------
# Pure ASGI implementation
# ---------------------------------------------------------------------------

class TCDRequestASGIMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        cfg: Optional[TCDRequestMiddlewareConfig] = None,
        policy_store: Optional[PolicyStore] = None,
        rate_limiter: Optional[RateLimiter] = None,
        authenticator: Optional[Authenticator] = None,
    ):
        self.app = app
        self._engine = _RequestMiddlewareEngine(
            cfg=cfg or TCDRequestMiddlewareConfig(),
            policy_store=policy_store,
            rate_limiter=rate_limiter,
            authenticator=authenticator,
        )

    def diagnostics(self) -> Dict[str, Any]:
        return {
            "schema": "tcd.request.middleware.diag.v1",
            "profile": self._engine._cfg.security.profile,
            "idempotency_enabled": bool(self._engine._cfg.idempotency.enable),
            "authenticator_present": bool(self._engine._authenticator is not None),
        }

    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        path = _strip_unsafe_text(scope.get("path") or "/", max_len=2048).strip() or "/"
        if self._engine._path_match(path, self._engine._bypass):
            return await self.app(scope, receive, send)

        method = _safe_text(scope.get("method") or "GET", max_len=16).upper() or "GET"
        norm_path = self._engine._cfg.metrics.path_normalizer(path)
        state = scope.setdefault("state", {})
        headers_map: Dict[str, str] = {}
        for item in scope.get("headers") or []:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                continue
            k, v = item
            if not isinstance(k, (bytes, bytearray)) or not isinstance(v, (bytes, bytearray)):
                continue
            headers_map[k.decode("latin1", errors="ignore").lower()] = v.decode("latin1", errors="ignore")

        req_id = _safe_taglike_id(_state_get(state, "request_id", None), max_len=255) or _safe_taglike_id(headers_map.get(self._engine._cfg.request_id_header.lower()), max_len=255) or _fold_id("rid", f"{time.time_ns()}:{id(scope)}", hex_len=24)
        trust_profile = _trusted_profile_from_state_or_default(state, self._engine._cfg.security.profile)
        classification = "unclassified"
        sec_level = "public"
        body_for_metrics = b""
        slot_key: Optional[str] = None
        idem_fp: Optional[str] = None

        if self._engine._metrics.enabled and self._engine._metrics.inflight is not None:
            self._engine._metrics.inflight.labels(norm_path).inc()

        t0 = time.perf_counter()

        query_raw = scope.get("query_string", b"")
        if isinstance(query_raw, (bytes, bytearray)):
            query_len = len(query_raw)
        elif isinstance(query_raw, str):
            query_len = len(query_raw.encode("utf-8", errors="ignore"))
        else:
            query_len = 0

        async def _asgi_response(resp: Response) -> None:
            await resp(scope, _make_body_receive(b""), send)

        try:
            hdr_count, hdr_bytes = _headers_budget(scope)
            if hdr_count > self._engine._cfg.limits.max_header_count:
                raise _Reject(431, "headers_too_many")
            if hdr_bytes > self._engine._cfg.limits.max_header_bytes:
                raise _Reject(431, "headers_too_large")
            if query_len > self._engine._cfg.limits.max_query_bytes:
                raise _Reject(414, "query_too_large")

            req_for_state = Request(scope, receive=_make_body_receive(b""))
            self._engine._ensure_request_context(req_for_state, req_id)

            raw_body = await self._read_body_asgi(receive, method=method, path=path, headers=headers_map)
            body_for_metrics = raw_body
            _state_set(state, "body_bytes", raw_body)

            auth_req = Request(scope, receive=_make_body_receive(raw_body))
            ok_auth, sec_ctx, auth_reason, auth_status = await self._engine._auth_ok(auth_req, raw_body, norm_path)
            _state_set(state, "security_ctx", sec_ctx)
            _state_set(state, "auth_mode", _safe_text(sec_ctx.get("authn_method"), max_len=32) or "none")
            _state_set(state, "auth_trusted", bool(sec_ctx.get("trusted", False)))
            _state_set(state, "auth_principal", sec_ctx.get("principal"))
            _state_set(state, "auth_scopes", list(sec_ctx.get("scopes") or ()))
            _state_set(state, "auth_key_id", sec_ctx.get("key_id"))
            _state_set(state, "auth_policy_digest", sec_ctx.get("policy_digest"))
            _state_set(state, "auth_reason", auth_reason)
            if not ok_auth:
                raise _Reject(auth_status, "forbidden" if auth_status == 403 else auth_reason or "auth_failed")

            declared_json = _content_type_is_json(headers_map.get("content-type"))
            canonical_body, body_json = self._engine._parse_body(raw_body=raw_body, path=path, declared_json=declared_json)
            _state_set(state, "body_digest_raw", _stable_body_digest(raw_body))
            _state_set(state, "body_digest_canonical", _stable_body_digest(canonical_body))
            _state_set(state, "body_json", body_json if isinstance(body_json, (dict, list)) else None)

            classification = self._engine._derive_classification(sec_ctx)
            sec_level = _coarse_security_level(classification)

            req_for_bind = Request(scope, receive=_make_body_receive(raw_body))
            ctx = self._engine._extract_ctx(req_for_bind, body_json, classification)
            bound = self._engine._policy_bind(req_for_bind, ctx)
            if bound is not None:
                _state_set(state, "tcd_policy_ref", self._engine._policy_ref(bound))

            ok_rate, remaining_before, capacity, decision = self._engine._rate_check(
                req_for_bind,
                ctx=ctx,
                body_json=body_json,
                norm_path=norm_path,
                bound=bound,
            )
            if not ok_rate:
                _, _, retry = self._engine._rate_header_values(
                    remaining_before=remaining_before,
                    capacity=capacity,
                    decision=decision,
                )
                raise _Reject(429, "rate_limited", retry_after_s=_finite_float(retry) if retry is not None else None)

            idem_header = headers_map.get(self._engine._cfg.idempotency.header.lower())
            use_idem = (
                self._engine._cfg.idempotency.enable
                and isinstance(idem_header, str)
                and bool(_IDEMPOTENCY_KEY_RE.fullmatch(idem_header.strip()))
                and method in set(self._engine._cfg.idempotency.methods)
                and not self._engine._path_match(path, self._engine._skip_idem)
                and self._engine._should_use_idempotency(classification)
            )

            if use_idem and idem_header:
                req_for_idem = Request(scope, receive=_make_body_receive(raw_body))
                slot_key = self._engine._idempotency_slot_key(
                    req_for_idem,
                    norm_path=norm_path,
                    idem_val=idem_header.strip(),
                    ctx=ctx,
                )
                idem_fp = self._engine._idempotency_fingerprint(req_for_idem, canonical_body=canonical_body)
                state_name, ent = self._engine._idem.reserve_or_check(slot_key, idem_fp)
                if state_name == "conflict":
                    if self._engine._metrics.enabled:
                        self._engine._metrics.idem_ctr.labels("conflict", norm_path).inc()
                    raise _Reject(409, "idempotency_conflict")
                if state_name == "hit" and ent is not None:
                    if self._engine._metrics.enabled:
                        self._engine._metrics.idem_ctr.labels("hit", norm_path).inc()
                    raw_headers = list(ent.raw_headers)
                    _raw_headers_append_if_missing(
                        raw_headers,
                        self._engine._cfg.request_id_header.encode("latin1", errors="ignore"),
                        req_id.encode("latin1", errors="ignore"),
                    )
                    await _asgi_response(
                        _RawHeaderReplayResponse(
                            content=bytes(ent.body),
                            status_code=ent.status_code,
                            raw_headers=raw_headers,
                            media_type=ent.media_type,
                        )
                    )
                    return
                if state_name == "inflight":
                    if self._engine._cfg.idempotency.wait_on_inflight:
                        waited = await self._engine._wait_idem(slot_key, idem_fp, self._engine._cfg.idempotency.inflight_wait_timeout_s)
                        if waited is not None:
                            if self._engine._metrics.enabled:
                                self._engine._metrics.idem_ctr.labels("wait_hit", norm_path).inc()
                            raw_headers = list(waited.raw_headers)
                            _raw_headers_append_if_missing(
                                raw_headers,
                                self._engine._cfg.request_id_header.encode("latin1", errors="ignore"),
                                req_id.encode("latin1", errors="ignore"),
                            )
                            await _asgi_response(
                                _RawHeaderReplayResponse(
                                    content=bytes(waited.body),
                                    status_code=waited.status_code,
                                    raw_headers=raw_headers,
                                    media_type=waited.media_type,
                                )
                            )
                            return
                    raise _Reject(409, "idempotency_inflight")

            downstream_receive = _make_body_receive(raw_body)
            status_code = 200
            response_headers_raw: List[Tuple[bytes, bytes]] = []
            body_capture = bytearray()
            total_resp_bytes = 0

            async def send_wrapper(message: Message):
                nonlocal status_code, response_headers_raw, total_resp_bytes
                if message.get("type") == "http.response.start":
                    status_code = int(message.get("status", 200))
                    hdrs = list(message.get("headers") or [])
                    _raw_headers_append_if_missing(
                        hdrs,
                        self._engine._cfg.request_id_header.encode("latin1", errors="ignore"),
                        req_id.encode("latin1", errors="ignore"),
                    )

                    if self._engine._cfg.limits.emit_rate_headers:
                        limit, remain, retry = self._engine._rate_header_values(
                            remaining_before=remaining_before,
                            capacity=capacity,
                            decision=decision,
                        )
                        if limit is not None:
                            _raw_headers_append_if_missing(hdrs, b"x-ratelimit-limit", limit.encode("latin1", errors="ignore"))
                        if remain is not None:
                            _raw_headers_append_if_missing(hdrs, b"x-ratelimit-remaining", remain.encode("latin1", errors="ignore"))
                        if retry is not None and status_code == 429:
                            _raw_headers_append_if_missing(hdrs, b"retry-after", retry.encode("latin1", errors="ignore"))

                    response_headers_raw = list(hdrs)
                    message["headers"] = hdrs
                    await send(message)
                    return

                if message.get("type") == "http.response.body":
                    body = bytes(message.get("body") or b"")
                    total_resp_bytes += len(body)
                    if slot_key and idem_fp:
                        if len(body_capture) <= self._engine._cfg.idempotency.max_store_bytes:
                            room = self._engine._cfg.idempotency.max_store_bytes + 1 - len(body_capture)
                            if room > 0:
                                body_capture.extend(body[:room])
                    await send(message)
                    return

                await send(message)

            await self.app(scope, downstream_receive, send_wrapper)

            if slot_key and idem_fp:
                if ((not self._engine._cfg.idempotency.store_only_2xx) or (200 <= status_code < 300)) and len(body_capture) <= self._engine._cfg.idempotency.max_store_bytes:
                    self._engine._idem.set_done(
                        slot_key,
                        idem_fp,
                        code=status_code,
                        raw_headers=self._engine._filter_idem_headers(response_headers_raw),
                        body=bytes(body_capture),
                        media_type=_extract_media_type_from_raw_headers(response_headers_raw),
                    )
                    if self._engine._metrics.enabled:
                        self._engine._metrics.idem_ctr.labels("store", norm_path).inc()
                else:
                    self._engine._idem.abort(slot_key, idem_fp)
                    if self._engine._metrics.enabled:
                        self._engine._metrics.idem_ctr.labels("skip", norm_path).inc()

            if self._engine._cfg.audit.emit_success:
                self._engine._emit_audit(
                    event="request_ok",
                    request_id=req_id,
                    path=path,
                    method=method,
                    classification=classification,
                    sec_level=sec_level,
                    ctx=ctx,
                    extra={"code": status_code, "policy_ref": self._engine._policy_ref(bound) or ""},
                )

            if self._engine._metrics.enabled:
                self._engine._metrics.req_bytes.labels(method, norm_path).inc(len(body_for_metrics))
                self._engine._metrics.resp_bytes.labels(method, norm_path, str(status_code)).inc(total_resp_bytes)
                self._engine._metrics.req_ctr.labels(method, norm_path, str(status_code)).inc()
                self._engine._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
                if self._engine._metrics.req_sec is not None:
                    self._engine._metrics.req_sec.labels(sec_level, norm_path).inc()
            return

        except _Reject as rj:
            if slot_key and idem_fp:
                self._engine._idem.abort(slot_key, idem_fp)
            if self._engine._metrics.enabled:
                self._engine._metrics.req_reject.labels(rj.reason, norm_path).inc()
                self._engine._metrics.req_ctr.labels(method, norm_path, str(rj.code)).inc()
                self._engine._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
                if self._engine._metrics.req_sec is not None:
                    self._engine._metrics.req_sec.labels(sec_level, norm_path).inc()
            out_reason = "forbidden" if (self._engine._cfg.security.hide_reject_reason_in_high_security and _profile_is_high_security(trust_profile)) else rj.reason
            self._engine._emit_audit(
                event="request_reject",
                request_id=req_id,
                path=path,
                method=method,
                classification=classification,
                sec_level=sec_level,
                ctx=_state_get(state, "tcd_ctx", {}) if isinstance(_state_get(state, "tcd_ctx", {}), Mapping) else None,
                extra={"code": rj.code, "reason": rj.reason},
            )
            await _asgi_response(_json_error(status_code=rj.code, reason=out_reason, request_id=req_id))
            return
        except Exception:
            if slot_key and idem_fp:
                self._engine._idem.abort(slot_key, idem_fp)
            _logger.exception("Unhandled exception in TCDRequestASGIMiddleware.__call__")
            if self._engine._metrics.enabled:
                self._engine._metrics.req_reject.labels("exception", norm_path).inc()
                self._engine._metrics.req_ctr.labels(method, norm_path, "500").inc()
                self._engine._metrics.latency.observe(max(0.0, time.perf_counter() - t0))
                if self._engine._metrics.req_sec is not None:
                    self._engine._metrics.req_sec.labels(sec_level, norm_path).inc()
            self._engine._emit_audit(
                event="request_exception",
                request_id=req_id,
                path=path,
                method=method,
                classification=classification,
                sec_level=sec_level,
                ctx=_state_get(state, "tcd_ctx", {}) if isinstance(_state_get(state, "tcd_ctx", {}), Mapping) else None,
            )
            await _asgi_response(_json_error(status_code=500, reason="internal", request_id=req_id))
            return
        finally:
            if self._engine._metrics.enabled and self._engine._metrics.inflight is not None:
                with contextlib.suppress(Exception):
                    self._engine._metrics.inflight.labels(norm_path).dec()

    async def _read_body_asgi(self, receive: Receive, *, method: str, path: str, headers: Mapping[str, str]) -> bytes:
        cl = headers.get("content-length")
        cl_val: Optional[int] = None
        if cl is not None:
            try:
                cl_val = int(cl)
            except Exception:
                cl_val = None
            if cl_val is None or cl_val < 0:
                raise _Reject(400, "invalid_content_length")
            if cl_val > self._engine._cfg.limits.max_body_bytes:
                raise _Reject(413, "payload_too_large")

        if len(path.encode("utf-8", errors="ignore")) > self._engine._cfg.limits.max_path_bytes:
            raise _Reject(414, "path_too_large")
        if len((headers.get("query-string") or "").encode("utf-8", errors="ignore")) > self._engine._cfg.limits.max_query_bytes:
            pass  # scope query_string is not exposed here; handled by transport if needed

        wants_body = method in set(self._engine._cfg.limits.body_methods)
        if not wants_body and (cl_val is None or cl_val == 0) and not headers.get("transfer-encoding"):
            return b""

        if self._engine._cfg.limits.enforce_json_content_type and wants_body and not self._engine._path_match(path, self._engine._skip_ct):
            if not _content_type_is_json(headers.get("content-type")):
                raise _Reject(415, "unsupported_media_type")

        chunks: List[bytes] = []
        total = 0
        limit = self._engine._cfg.limits.max_body_bytes if cl_val is not None else self._engine._cfg.limits.hard_read_cap_bytes

        while True:
            message = await receive()
            if message.get("type") != "http.request":
                continue
            chunk = bytes(message.get("body") or b"")
            if chunk:
                total += len(chunk)
                if total > limit:
                    raise _Reject(413, "payload_too_large")
                chunks.append(chunk)
            if not bool(message.get("more_body")):
                break

        return b"".join(chunks)


# ---------------------------------------------------------------------------
# Wiring helper
# ---------------------------------------------------------------------------

def add_request_middleware(
    app: ASGIApp,
    *,
    config: Optional[TCDRequestMiddlewareConfig] = None,
    policy_store: Optional[PolicyStore] = None,
    rate_limiter: Optional[RateLimiter] = None,
    authenticator: Optional[Authenticator] = None,
    pure_asgi: bool = False,
) -> ASGIApp:
    """
    Install request middleware.

    - If `pure_asgi=False` and the app exposes `add_middleware`, the BaseHTTPMiddleware
      variant is installed in-place and the original app is returned.
    - Otherwise, returns a wrapped ASGI app using the pure ASGI variant.
    """
    cfg = config or TCDRequestMiddlewareConfig()

    if pure_asgi or not hasattr(app, "add_middleware"):
        return TCDRequestASGIMiddleware(
            app,
            cfg=cfg,
            policy_store=policy_store,
            rate_limiter=rate_limiter,
            authenticator=authenticator,
        )

    app.add_middleware(
        TCDRequestMiddleware,
        cfg=cfg,
        policy_store=policy_store,
        rate_limiter=rate_limiter,
        authenticator=authenticator,
    )
    return app