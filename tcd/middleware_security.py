from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import math
import queue
import re
import threading
import time
import unicodedata
from collections import OrderedDict
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union, Literal
from urllib.parse import urlsplit

from starlette.datastructures import MutableHeaders
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

__all__ = [
    "SecurityMiddlewareConfig",
    "SecurityMiddleware",
    "SecurityASGIMiddleware",
]

_logger = logging.getLogger(__name__)

IpNet = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
CostOverCapacityMode = Literal["deny_without_bucket", "audit_only", "cap_to_capacity"]
AuditMode = Literal["disabled", "sync", "async"]
AuditDropPolicy = Literal["drop_newest", "drop_oldest", "sync_fallback"]

_ALLOWED_SECURITY_PROFILES = frozenset({"DEV", "PROD", "HIGH_SECURITY", "FINREG", "LOCKDOWN"})
_ALLOWED_CORS_MODES = frozenset({"disabled", "strict_allowlist", "internal_only", "classified"})
_ALLOWED_CORP = frozenset({"same-site", "same-origin", "cross-origin"})
_ALLOWED_AUDIT_MODES = frozenset({"disabled", "sync", "async"})
_ALLOWED_AUDIT_DROP = frozenset({"drop_newest", "drop_oldest", "sync_fallback"})
_ALLOWED_COST_OVER_CAPACITY = frozenset({"deny_without_bucket", "audit_only", "cap_to_capacity"})

_ASCII_CTRL_FULL_RE = re.compile(r"[\x00-\x1F\x7F]")
_LONG_SEG_RE = re.compile(r"(?:(?<=/)|^)[A-Za-z0-9._-]{24,}(?=(?:/|$))")
_UUID_SEG_RE = re.compile(
    r"[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[1-5][0-9a-fA-F]{3}\b-[89abAB][0-9a-fA-F]{3}\b-[0-9a-fA-F]{12}"
)
_LONG_NUM_SEG_RE = re.compile(r"/\d{4,}")
_TAGLIKE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,255}$")

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
_LONG_B64URL_RE = re.compile(r"\b[A-Za-z0-9_-]{60,}\b")

_SAFE_ORIGIN_SCHEMES = frozenset({"http", "https"})
_MAX_AUDIT_EVENT_BYTES = 8 * 1024

_GLOBAL_THREAT_LEVEL = 0
_GLOBAL_THREAT_META: Dict[str, Any] = {"source": "init", "reason": "", "updated_at": time.time()}
_GLOBAL_THREAT_LOCK = threading.Lock()


def _set_global_threat_level(level: int, *, source: str = "local", reason: str = "") -> None:
    global _GLOBAL_THREAT_LEVEL
    with _GLOBAL_THREAT_LOCK:
        _GLOBAL_THREAT_LEVEL = int(max(0, level))
        _GLOBAL_THREAT_META["source"] = _strip_unsafe_text(source, max_len=64) or "local"
        _GLOBAL_THREAT_META["reason"] = _strip_unsafe_text(reason, max_len=256)
        _GLOBAL_THREAT_META["updated_at"] = time.time()


def _get_global_threat_level() -> int:
    with _GLOBAL_THREAT_LOCK:
        return int(_GLOBAL_THREAT_LEVEL)


def _get_global_threat_meta() -> Dict[str, Any]:
    with _GLOBAL_THREAT_LOCK:
        return dict(_GLOBAL_THREAT_META)


def _has_unsafe_unicode(s: str) -> bool:
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False


def _strip_unsafe_text(s: str, *, max_len: int) -> str:
    if not s:
        return ""
    if len(s) > max_len:
        s = s[:max_len]

    if s.isascii():
        if _ASCII_CTRL_FULL_RE.search(s):
            s = _ASCII_CTRL_FULL_RE.sub("", s)
        return s

    if not _ASCII_CTRL_FULL_RE.search(s) and not _has_unsafe_unicode(s):
        if any(0x80 <= ord(ch) <= 0x9F for ch in s):
            pass
        else:
            return s

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
    return "".join(out)


def _scalar_text(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        if not math.isfinite(v):
            return ""
        return f"{v:.12g}"
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "<bytes>"
    return f"<{type(v).__name__}>"


def _safe_text(v: Any, *, max_len: int = 256) -> str:
    s = _strip_unsafe_text(_scalar_text(v), max_len=max_len).strip()
    return s[:max_len] if s else ""


def _bounded_label(s: str, *, max_len: int = 128) -> str:
    s2 = _strip_unsafe_text(s or "", max_len=max_len).strip()
    if not s2:
        return "unknown"
    if len(s2) > max_len:
        s2 = s2[:max_len]
    return s2


def _looks_like_secret(s: str) -> bool:
    if not s:
        return False
    if _JWT_RE.search(s):
        return True
    if _PRIVKEY_RE.search(s):
        return True
    if _BEARER_RE.search(s):
        return True
    if _BASIC_RE.search(s):
        return True
    if _OPENAI_SK_RE.search(s):
        return True
    if _AWS_AKIA_RE.search(s):
        return True
    if _GOOGLE_AIZA_RE.search(s):
        return True
    if _KV_SECRET_RE.search(s):
        return True
    if _LONG_B64URL_RE.search(s):
        return True
    return False


def _finite_float(x: Any) -> Optional[float]:
    if isinstance(x, bool):
        return None
    try:
        v = float(x)
    except Exception:
        return None
    if not math.isfinite(v):
        return None
    return v


def _clamp_float(v: Any, lo: float, hi: float, *, default: float) -> float:
    x = _finite_float(v)
    if x is None:
        return float(default)
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def _clamp_int(v: Any, lo: int, hi: int, *, default: int) -> int:
    try:
        x = int(v)
    except Exception:
        return int(default)
    if x < lo:
        return lo
    if x > hi:
        return hi
    return x


def _safe_taglike_id(
    raw: Optional[str],
    *,
    max_len: int,
    reject_secrets: bool = True,
    allow_truncate: bool = False,
) -> Optional[str]:
    if not raw or not isinstance(raw, str):
        return None
    s = _strip_unsafe_text(raw, max_len=max_len + (1 if not allow_truncate else 16)).strip()
    if not s:
        return None
    if reject_secrets and _looks_like_secret(s):
        return None
    if len(s) > max_len:
        if not allow_truncate:
            return None
        s = s[:max_len]
    if not _TAGLIKE_ID_RE.fullmatch(s):
        return None
    return s


def _fold_id(prefix: str, value: str, *, digest_hex: int = 16) -> str:
    v = _strip_unsafe_text(value, max_len=2048).encode("utf-8", errors="ignore")
    d = hashlib.blake2s(b"TCD|edge|idfold|v2|" + v).hexdigest()[:digest_hex]
    return f"{prefix}-h-{d}"


def _stable_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int)):
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            return None
        s = f"{float(obj):.12f}".rstrip("0").rstrip(".")
        return s or "0"
    if isinstance(obj, str):
        return obj
    if isinstance(obj, Mapping):
        out: Dict[str, Any] = {}
        for k in sorted(obj.keys(), key=lambda x: str(x)):
            out[str(k)] = _stable_jsonable(obj[k])
        return out
    if isinstance(obj, (list, tuple)):
        return [_stable_jsonable(x) for x in obj]
    if isinstance(obj, (set, frozenset)):
        xs = [_stable_jsonable(x) for x in obj]
        try:
            return sorted(xs)
        except Exception:
            return xs
    return _safe_text(type(obj).__name__, max_len=64)


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        _stable_jsonable(obj),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def _parse_ip(s: str) -> Optional[str]:
    if not s:
        return None
    ss = _strip_unsafe_text(s, max_len=96).strip()
    if not ss:
        return None
    if ss.startswith("[") and ss.endswith("]"):
        ss = ss[1:-1]
    try:
        return str(ipaddress.ip_address(ss))
    except Exception:
        return None


def _parse_trusted_proxies(values: Iterable[str]) -> Tuple[IpNet, ...]:
    nets: List[IpNet] = []
    for raw in values:
        if not raw:
            continue
        s = _strip_unsafe_text(str(raw), max_len=128).strip()
        if not s:
            continue
        try:
            net = ipaddress.ip_network(s, strict=False)
            nets.append(net)
        except Exception:
            continue
    return tuple(nets)


def _ip_in_trusted(ip: str, nets: Tuple[IpNet, ...]) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for net in nets:
        try:
            if ip_obj in net:
                return True
        except Exception:
            continue
    return False


def _extract_client_ip_from_xff(
    *,
    remote_ip: str,
    xff: Optional[str],
    trusted_proxies: Tuple[IpNet, ...],
    max_xff_parts: int,
) -> Tuple[str, Optional[str]]:
    rip = _parse_ip(remote_ip) or "unknown"

    if not trusted_proxies:
        return rip, "xff_disabled"

    if not _ip_in_trusted(rip, trusted_proxies):
        return rip, "untrusted_proxy"

    if not xff:
        return rip, "no_xff"

    xff_s = _strip_unsafe_text(xff, max_len=2048).strip()
    if not xff_s:
        return rip, "empty_xff"

    parts_raw = [p.strip() for p in xff_s.split(",") if p.strip()]
    if not parts_raw:
        return rip, "empty_xff"

    max_parts = _clamp_int(max_xff_parts, 1, 128, default=16)
    if len(parts_raw) > max_parts:
        parts_raw = parts_raw[-max_parts:]

    ips: List[str] = []
    for p in parts_raw:
        ipn = _parse_ip(p)
        if ipn is not None:
            ips.append(ipn)

    if not ips:
        return rip, "invalid_xff"

    for cand in reversed(ips):
        if not _ip_in_trusted(cand, trusted_proxies):
            return cand, None

    return ips[0], "xff_all_proxies"


def _header_budget_from_scope(scope: Mapping[str, Any]) -> Tuple[int, int]:
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


def _headers_from_scope(scope: Mapping[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    raw_headers = scope.get("headers") or []
    if not isinstance(raw_headers, list):
        return out
    for item in raw_headers:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue
        k, v = item
        if not isinstance(k, (bytes, bytearray)) or not isinstance(v, (bytes, bytearray)):
            continue
        ks = _strip_unsafe_text(k.decode("latin-1", errors="ignore"), max_len=256).lower().strip()
        vs = _strip_unsafe_text(v.decode("latin-1", errors="ignore"), max_len=4096).strip()
        if not ks:
            continue
        if ks in out and vs:
            out[ks] = out[ks] + ", " + vs
        else:
            out[ks] = vs
    return out


def _normalize_profile(v: Any) -> str:
    s = _safe_text(v, max_len=32).strip().upper()
    aliases = {
        "HIGHSEC": "HIGH_SECURITY",
        "HIGH_SEC": "HIGH_SECURITY",
        "HIGH-SECURITY": "HIGH_SECURITY",
    }
    s = aliases.get(s, s)
    return s if s in _ALLOWED_SECURITY_PROFILES else "PROD"


def _profile_is_high_security(profile: str) -> bool:
    return str(profile).upper() in {"HIGH_SECURITY", "FINREG", "LOCKDOWN"}


def _trusted_profile_from_state_or_default(state: Any, default_profile: str) -> str:
    src = _state_get(state, "tcd_trust_profile_source", None)
    raw = _state_get(state, "tcd_trust_profile", None)
    if src == "trusted_local" and isinstance(raw, str):
        return _normalize_profile(raw)
    return _normalize_profile(default_profile)


def _request_id_from_state_or_headers(request: Request) -> Optional[str]:
    rid = None
    try:
        rid = getattr(request.state, "request_id", None)
    except Exception:
        rid = None
    if isinstance(rid, str):
        rid2 = _safe_taglike_id(rid, max_len=255)
        if rid2:
            return rid2
    hdr = request.headers.get("x-request-id") or request.headers.get("X-Request-Id")
    return _safe_taglike_id(hdr, max_len=255) if isinstance(hdr, str) else None


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


def _merge_vary(existing: Optional[str], item: str) -> str:
    cur = existing or ""
    parts = [p.strip() for p in cur.split(",") if p.strip()]
    seen = {p.lower() for p in parts}
    if item.lower() not in seen:
        parts.append(item)
    return ", ".join(parts)


def _normalize_origin(raw: Optional[str]) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    s = _strip_unsafe_text(raw, max_len=512).strip()
    if not s:
        return None
    if s.lower() == "null":
        return "null"
    try:
        split = urlsplit(s)
    except Exception:
        return None
    scheme = split.scheme.lower()
    if scheme not in _SAFE_ORIGIN_SCHEMES:
        return None
    if not split.netloc or split.username or split.password:
        return None
    if split.path not in ("", "/") or split.query or split.fragment:
        return None
    host = split.hostname
    if not host:
        return None
    try:
        host_idna = host.encode("idna").decode("ascii").lower()
    except Exception:
        return None
    try:
        port = split.port
    except Exception:
        return None
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    if ":" in host_idna and not host_idna.startswith("["):
        host_idna = f"[{host_idna}]"
    return f"{scheme}://{host_idna}{'' if port is None else f':{port}'}"


def _origin_host(normalized_origin: Optional[str]) -> Optional[str]:
    if not normalized_origin or normalized_origin == "null":
        return None
    try:
        sp = urlsplit(normalized_origin)
    except Exception:
        return None
    return (sp.hostname or "").lower() or None


def _normalize_logged_path(path: str) -> str:
    p = _strip_unsafe_text(path or "/", max_len=1024).strip() or "/"
    p = _UUID_SEG_RE.sub(":uuid", p)
    p = _LONG_NUM_SEG_RE.sub("/:id", p)
    p = _LONG_SEG_RE.sub(":tok", p)
    return p


@dataclass(frozen=True)
class SecurityMiddlewareConfig:
    allow_origins: Tuple[str, ...] = ()

    security_profile: str = "PROD"

    rate_limit_enabled: bool = True
    ip_capacity: float = 30.0
    ip_refill_per_s: float = 15.0
    suspicious_cost: float = 2.0
    cost_over_capacity_mode: CostOverCapacityMode = "cap_to_capacity"
    allowlisted_bypass_rate_limit: bool = False

    ip_allowlist: Tuple[str, ...] = ()
    ip_blocklist: Tuple[str, ...] = ()
    ip_suspicious: Tuple[str, ...] = ()

    respect_xff: bool = False
    trusted_proxies: Tuple[str, ...] = ()
    max_xff_parts: int = 16

    ip_bucket_limit: int = 10_000
    ip_bucket_idle_seconds: float = 600.0
    bucket_shards: int = 32

    temp_block_after_denies: int = 0
    temp_block_ttl_s: float = 0.0
    max_tokens_per_ip_per_window: float = 0.0
    max_tokens_window_s: float = 60.0

    max_inflight_global: int = 0
    max_inflight_per_ip: int = 0
    inflight_wait_timeout_s: float = 0.0

    max_header_count: int = 128
    max_header_bytes: int = 32 * 1024
    max_origin_bytes: int = 512
    max_xff_bytes: int = 2048
    max_path_bytes: int = 2048

    cors_mode: str = "strict_allowlist"
    classified_path_patterns: Tuple[str, ...] = ()
    internal_origin_suffixes: Tuple[str, ...] = ()
    allow_null_origin: bool = False
    allow_credentials: bool = False
    allow_methods: Tuple[str, ...] = ("GET", "POST", "OPTIONS")
    allow_headers: Tuple[str, ...] = ("authorization", "content-type", "x-request-id")
    expose_headers: Tuple[str, ...] = ("x-request-id",)
    max_preflight_age_s: int = 600
    allow_private_network: bool = False

    enable_hsts: bool = False
    hsts_max_age: int = 31_536_000
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False
    enable_coop_coep: bool = True
    cross_origin_resource_policy: str = "same-site"
    content_security_policy: str = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    referrer_policy: str = "no-referrer"
    permissions_policy: str = "geolocation=()"

    emit_audit_log: bool = True
    audit_log_fn: Optional[Callable[[Dict[str, Any]], None]] = None
    audit_mode: AuditMode = "async"
    audit_queue_size: int = 1024
    audit_drop_policy: AuditDropPolicy = "drop_newest"
    audit_hmac_key_hex: Optional[str] = None
    audit_hmac_key_id: Optional[str] = None

    json_error: bool = True
    expose_headers_on_errors: bool = True
    hide_details_in_high_security: bool = True
    link_to_multivar: bool = True
    minimize_state_context_dict: bool = True

    threat_level_overload_threshold: int = 2
    threat_level_hard_block_threshold: int = 4

    def normalized_copy(self) -> "SecurityMiddlewareConfig":
        profile = _normalize_profile(self.security_profile)

        cors_mode = _safe_text(self.cors_mode, max_len=64).strip().lower() or "strict_allowlist"
        if cors_mode not in _ALLOWED_CORS_MODES:
            cors_mode = "strict_allowlist"

        allow_origins: List[str] = []
        for raw in self.allow_origins:
            if not isinstance(raw, str):
                continue
            s = _strip_unsafe_text(raw, max_len=512).strip()
            if not s:
                continue
            if s == "*":
                allow_origins.append("*")
                continue
            norm = _normalize_origin(s)
            if norm:
                allow_origins.append(norm)

        methods = []
        for m in self.allow_methods:
            s = _safe_text(m, max_len=32).upper()
            if s:
                methods.append(s)
        if not methods:
            methods = ["GET", "POST", "OPTIONS"]

        headers = []
        for h in self.allow_headers:
            s = _safe_text(h, max_len=64).lower()
            if s:
                headers.append(s)
        if not headers:
            headers = ["authorization", "content-type", "x-request-id"]

        expose = []
        for h in self.expose_headers:
            s = _safe_text(h, max_len=64)
            if s:
                expose.append(s)
        if not expose:
            expose = ["x-request-id"]

        class_patterns = tuple(
            _strip_unsafe_text(x, max_len=256)
            for x in self.classified_path_patterns
            if _strip_unsafe_text(x, max_len=256)
        )
        internal_suffixes = tuple(
            _strip_unsafe_text(x, max_len=128).lower()
            for x in self.internal_origin_suffixes
            if _strip_unsafe_text(x, max_len=128)
        )

        corp = _safe_text(self.cross_origin_resource_policy, max_len=32).lower() or "same-site"
        if corp not in _ALLOWED_CORP:
            corp = "same-site"

        audit_mode = _safe_text(self.audit_mode, max_len=16).strip().lower() or "async"
        if audit_mode not in _ALLOWED_AUDIT_MODES:
            audit_mode = "async"

        audit_drop = _safe_text(self.audit_drop_policy, max_len=32).strip().lower() or "drop_newest"
        if audit_drop not in _ALLOWED_AUDIT_DROP:
            audit_drop = "drop_newest"

        cost_mode = _safe_text(self.cost_over_capacity_mode, max_len=32).strip().lower() or "cap_to_capacity"
        if cost_mode not in _ALLOWED_COST_OVER_CAPACITY:
            cost_mode = "cap_to_capacity"

        temp_block_after_denies = _clamp_int(self.temp_block_after_denies, 0, 1_000_000, default=0)
        temp_block_ttl_s = _clamp_float(self.temp_block_ttl_s, 0.0, 1_000_000_000.0, default=0.0)
        if temp_block_ttl_s <= 0.0:
            temp_block_after_denies = 0

        return SecurityMiddlewareConfig(
            allow_origins=tuple(sorted(set(allow_origins))),
            security_profile=profile,
            rate_limit_enabled=bool(self.rate_limit_enabled),
            ip_capacity=_clamp_float(self.ip_capacity, 0.0, 1_000_000_000.0, default=30.0),
            ip_refill_per_s=_clamp_float(self.ip_refill_per_s, 0.0, 1_000_000_000.0, default=15.0),
            suspicious_cost=_clamp_float(self.suspicious_cost, 0.1, 1_000_000.0, default=2.0),
            cost_over_capacity_mode=cost_mode,  # type: ignore[arg-type]
            allowlisted_bypass_rate_limit=bool(self.allowlisted_bypass_rate_limit),
            ip_allowlist=tuple(_strip_unsafe_text(x, max_len=128) for x in self.ip_allowlist if _strip_unsafe_text(x, max_len=128)),
            ip_blocklist=tuple(_strip_unsafe_text(x, max_len=128) for x in self.ip_blocklist if _strip_unsafe_text(x, max_len=128)),
            ip_suspicious=tuple(_strip_unsafe_text(x, max_len=128) for x in self.ip_suspicious if _strip_unsafe_text(x, max_len=128)),
            respect_xff=bool(self.respect_xff),
            trusted_proxies=tuple(_strip_unsafe_text(x, max_len=128) for x in self.trusted_proxies if _strip_unsafe_text(x, max_len=128)),
            max_xff_parts=_clamp_int(self.max_xff_parts, 1, 128, default=16),
            ip_bucket_limit=_clamp_int(self.ip_bucket_limit, 0, 1_000_000, default=10_000),
            ip_bucket_idle_seconds=_clamp_float(self.ip_bucket_idle_seconds, 0.0, 1_000_000_000.0, default=600.0),
            bucket_shards=_clamp_int(self.bucket_shards, 1, 1024, default=32),
            temp_block_after_denies=temp_block_after_denies,
            temp_block_ttl_s=temp_block_ttl_s,
            max_tokens_per_ip_per_window=_clamp_float(self.max_tokens_per_ip_per_window, 0.0, 1_000_000_000.0, default=0.0),
            max_tokens_window_s=_clamp_float(self.max_tokens_window_s, 1.0, 1_000_000_000.0, default=60.0),
            max_inflight_global=_clamp_int(self.max_inflight_global, 0, 1_000_000, default=0),
            max_inflight_per_ip=_clamp_int(self.max_inflight_per_ip, 0, 1_000_000, default=0),
            inflight_wait_timeout_s=_clamp_float(self.inflight_wait_timeout_s, 0.0, 3600.0, default=0.0),
            max_header_count=_clamp_int(self.max_header_count, 8, 100_000, default=128),
            max_header_bytes=_clamp_int(self.max_header_bytes, 512, 16 * 1024 * 1024, default=32 * 1024),
            max_origin_bytes=_clamp_int(self.max_origin_bytes, 64, 16 * 1024, default=512),
            max_xff_bytes=_clamp_int(self.max_xff_bytes, 64, 64 * 1024, default=2048),
            max_path_bytes=_clamp_int(self.max_path_bytes, 64, 64 * 1024, default=2048),
            cors_mode=cors_mode,
            classified_path_patterns=class_patterns,
            internal_origin_suffixes=internal_suffixes,
            allow_null_origin=bool(self.allow_null_origin),
            allow_credentials=bool(self.allow_credentials),
            allow_methods=tuple(sorted(set(methods))),
            allow_headers=tuple(sorted(set(headers))),
            expose_headers=tuple(sorted(set(expose))),
            max_preflight_age_s=_clamp_int(self.max_preflight_age_s, 0, 86_400, default=600),
            allow_private_network=bool(self.allow_private_network),
            enable_hsts=bool(self.enable_hsts),
            hsts_max_age=_clamp_int(self.hsts_max_age, 0, 10 * 365 * 24 * 3600, default=31_536_000),
            hsts_include_subdomains=bool(self.hsts_include_subdomains),
            hsts_preload=bool(self.hsts_preload),
            enable_coop_coep=bool(self.enable_coop_coep),
            cross_origin_resource_policy=corp,
            content_security_policy=_strip_unsafe_text(self.content_security_policy, max_len=1024) or "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
            referrer_policy=_strip_unsafe_text(self.referrer_policy, max_len=128) or "no-referrer",
            permissions_policy=_strip_unsafe_text(self.permissions_policy, max_len=256) or "geolocation=()",
            emit_audit_log=bool(self.emit_audit_log),
            audit_log_fn=self.audit_log_fn,
            audit_mode=audit_mode,  # type: ignore[arg-type]
            audit_queue_size=_clamp_int(self.audit_queue_size, 0, 1_000_000, default=1024),
            audit_drop_policy=audit_drop,  # type: ignore[arg-type]
            audit_hmac_key_hex=_strip_unsafe_text(self.audit_hmac_key_hex or "", max_len=8192) or None,
            audit_hmac_key_id=_safe_taglike_id(self.audit_hmac_key_id, max_len=64),
            json_error=bool(self.json_error),
            expose_headers_on_errors=bool(self.expose_headers_on_errors),
            hide_details_in_high_security=bool(self.hide_details_in_high_security),
            link_to_multivar=bool(self.link_to_multivar),
            minimize_state_context_dict=bool(self.minimize_state_context_dict),
            threat_level_overload_threshold=_clamp_int(self.threat_level_overload_threshold, 0, 1_000, default=2),
            threat_level_hard_block_threshold=_clamp_int(self.threat_level_hard_block_threshold, 0, 1_000, default=4),
        )

    def digest_material(self) -> Dict[str, Any]:
        return {
            "allow_origins": list(self.allow_origins),
            "security_profile": self.security_profile,
            "rate_limit_enabled": self.rate_limit_enabled,
            "ip_capacity": self.ip_capacity,
            "ip_refill_per_s": self.ip_refill_per_s,
            "suspicious_cost": self.suspicious_cost,
            "cost_over_capacity_mode": self.cost_over_capacity_mode,
            "allowlisted_bypass_rate_limit": self.allowlisted_bypass_rate_limit,
            "ip_allowlist": list(self.ip_allowlist),
            "ip_blocklist": list(self.ip_blocklist),
            "ip_suspicious": list(self.ip_suspicious),
            "respect_xff": self.respect_xff,
            "trusted_proxies": list(self.trusted_proxies),
            "max_xff_parts": self.max_xff_parts,
            "ip_bucket_limit": self.ip_bucket_limit,
            "ip_bucket_idle_seconds": self.ip_bucket_idle_seconds,
            "bucket_shards": self.bucket_shards,
            "temp_block_after_denies": self.temp_block_after_denies,
            "temp_block_ttl_s": self.temp_block_ttl_s,
            "max_tokens_per_ip_per_window": self.max_tokens_per_ip_per_window,
            "max_tokens_window_s": self.max_tokens_window_s,
            "max_inflight_global": self.max_inflight_global,
            "max_inflight_per_ip": self.max_inflight_per_ip,
            "inflight_wait_timeout_s": self.inflight_wait_timeout_s,
            "max_header_count": self.max_header_count,
            "max_header_bytes": self.max_header_bytes,
            "max_origin_bytes": self.max_origin_bytes,
            "max_xff_bytes": self.max_xff_bytes,
            "max_path_bytes": self.max_path_bytes,
            "cors_mode": self.cors_mode,
            "classified_path_patterns": list(self.classified_path_patterns),
            "internal_origin_suffixes": list(self.internal_origin_suffixes),
            "allow_null_origin": self.allow_null_origin,
            "allow_credentials": self.allow_credentials,
            "allow_methods": list(self.allow_methods),
            "allow_headers": list(self.allow_headers),
            "expose_headers": list(self.expose_headers),
            "max_preflight_age_s": self.max_preflight_age_s,
            "allow_private_network": self.allow_private_network,
            "enable_hsts": self.enable_hsts,
            "hsts_max_age": self.hsts_max_age,
            "hsts_include_subdomains": self.hsts_include_subdomains,
            "hsts_preload": self.hsts_preload,
            "enable_coop_coep": self.enable_coop_coep,
            "cross_origin_resource_policy": self.cross_origin_resource_policy,
            "content_security_policy": self.content_security_policy,
            "referrer_policy": self.referrer_policy,
            "permissions_policy": self.permissions_policy,
            "emit_audit_log": self.emit_audit_log,
            "audit_mode": self.audit_mode,
            "audit_queue_size": self.audit_queue_size,
            "audit_drop_policy": self.audit_drop_policy,
            "audit_hmac_key_present": bool(self.audit_hmac_key_hex),
            "audit_hmac_key_id": self.audit_hmac_key_id,
            "json_error": self.json_error,
            "expose_headers_on_errors": self.expose_headers_on_errors,
            "hide_details_in_high_security": self.hide_details_in_high_security,
            "link_to_multivar": self.link_to_multivar,
            "minimize_state_context_dict": self.minimize_state_context_dict,
            "threat_level_overload_threshold": self.threat_level_overload_threshold,
            "threat_level_hard_block_threshold": self.threat_level_hard_block_threshold,
        }


class _AuditDispatcher:
    def __init__(
        self,
        *,
        mode: AuditMode,
        queue_size: int,
        drop_policy: AuditDropPolicy,
        hook: Optional[Callable[[Dict[str, Any]], None]],
    ) -> None:
        self._mode = mode
        self._hook = hook
        self._queue_size = max(0, int(queue_size))
        self._drop_policy = drop_policy
        self._queue: Optional["queue.Queue[Dict[str, Any]]"] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._drop_count = 0
        self._processed_count = 0
        self._lock = threading.Lock()

        if self._mode == "async" and self._queue_size > 0:
            self._queue = queue.Queue(maxsize=self._queue_size)
            self._thread = threading.Thread(target=self._run, name="tcd-edge-audit", daemon=True)
            self._thread.start()

    def _deliver(self, record: Dict[str, Any]) -> None:
        try:
            if self._hook is not None:
                self._hook(record)
        except Exception:
            _logger.exception("Security audit hook failed")
        try:
            _logger.warning("edge_security_event: %s", json.dumps(record, ensure_ascii=False, separators=(",", ":"), allow_nan=False))
        except Exception:
            _logger.warning("edge_security_event (fallback): %s", record)

    def _run(self) -> None:
        assert self._queue is not None
        q = self._queue
        while not self._stop.is_set():
            try:
                item = q.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                self._deliver(item)
            finally:
                with self._lock:
                    self._processed_count += 1
                q.task_done()

    def emit(self, record: Dict[str, Any]) -> None:
        if self._mode == "disabled":
            return

        if self._mode == "sync" or self._queue is None:
            self._deliver(record)
            with self._lock:
                self._processed_count += 1
            return

        q = self._queue
        try:
            q.put_nowait(record)
            return
        except queue.Full:
            pass

        if self._drop_policy == "drop_oldest":
            try:
                _ = q.get_nowait()
                q.task_done()
            except Exception:
                pass
            try:
                q.put_nowait(record)
            except Exception:
                with self._lock:
                    self._drop_count += 1
            return

        if self._drop_policy == "sync_fallback":
            self._deliver(record)
            with self._lock:
                self._processed_count += 1
            return

        with self._lock:
            self._drop_count += 1

    def snapshot(self) -> Dict[str, Any]:
        qdepth = 0
        if self._queue is not None:
            try:
                qdepth = int(self._queue.qsize())
            except Exception:
                qdepth = 0
        with self._lock:
            return {
                "mode": self._mode,
                "queue_depth": qdepth,
                "dropped": int(self._drop_count),
                "processed": int(self._processed_count),
                "running": bool(self._thread is not None and self._thread.is_alive()),
            }


class _IpBucket:
    __slots__ = (
        "capacity",
        "refill",
        "tokens",
        "ts_mono",
        "last_seen_mono",
        "deny_count",
        "blocked_until_mono",
        "window_started_mono",
        "window_used",
        "lock",
    )

    def __init__(self, capacity: float, refill_per_s: float):
        now = time.monotonic()
        self.capacity = float(capacity)
        self.refill = float(refill_per_s)
        self.tokens = float(capacity)
        self.ts_mono = now
        self.last_seen_mono = now
        self.deny_count = 0
        self.blocked_until_mono = 0.0
        self.window_started_mono = now
        self.window_used = 0.0
        self.lock = threading.Lock()

    def take(
        self,
        n: float,
        *,
        temp_block_after_denies: int,
        temp_block_ttl_s: float,
        max_tokens_per_window: float,
        window_s: float,
    ) -> Tuple[bool, Optional[float], str]:
        with self.lock:
            now = time.monotonic()
            self.last_seen_mono = now

            if window_s > 0.0 and (now - self.window_started_mono) >= window_s:
                self.window_started_mono = now
                self.window_used = 0.0

            if self.blocked_until_mono > now:
                return False, max(0.0, self.blocked_until_mono - now), "temp_block"

            delta = max(0.0, now - self.ts_mono)
            if self.refill > 0.0 and delta > 0.0:
                self.tokens = min(self.capacity, self.tokens + delta * self.refill)
            self.ts_mono = now

            cost = max(0.000001, float(n))

            if max_tokens_per_window > 0.0 and (self.window_used + cost) > max_tokens_per_window:
                self.deny_count += 1
                if temp_block_after_denies > 0 and self.deny_count >= temp_block_after_denies and temp_block_ttl_s > 0.0:
                    self.blocked_until_mono = now + temp_block_ttl_s
                    self.deny_count = 0
                    return False, temp_block_ttl_s, "temp_block"
                retry = max(0.0, window_s - (now - self.window_started_mono))
                return False, retry, "window_cap"

            if self.tokens >= cost:
                self.tokens -= cost
                self.window_used += cost
                self.deny_count = 0
                return True, None, "ok"

            self.deny_count += 1
            if temp_block_after_denies > 0 and self.deny_count >= temp_block_after_denies and temp_block_ttl_s > 0.0:
                self.blocked_until_mono = now + temp_block_ttl_s
                self.deny_count = 0
                return False, temp_block_ttl_s, "temp_block"

            retry = None
            if self.refill > 0.0:
                retry = max(0.0, (cost - self.tokens) / self.refill)
            return False, retry, "ip_bucket_exhausted"


class _InflightGate:
    def __init__(self, *, max_global: int, max_per_ip: int, wait_timeout_s: float):
        self._max_global = max(0, int(max_global))
        self._max_per_ip = max(0, int(max_per_ip))
        self._wait_timeout_s = max(0.0, float(wait_timeout_s))
        self._cv = threading.Condition()
        self._global = 0
        self._per_ip: Dict[str, int] = {}

    def acquire(self, ip: str) -> Tuple[bool, str]:
        if self._max_global <= 0 and self._max_per_ip <= 0:
            return True, "disabled"

        deadline = time.monotonic() + self._wait_timeout_s if self._wait_timeout_s > 0 else None
        with self._cv:
            while True:
                g_ok = self._max_global <= 0 or self._global < self._max_global
                p_ok = self._max_per_ip <= 0 or self._per_ip.get(ip, 0) < self._max_per_ip
                if g_ok and p_ok:
                    self._global += 1
                    self._per_ip[ip] = self._per_ip.get(ip, 0) + 1
                    return True, "ok"

                if deadline is None:
                    return False, "inflight_reject"

                rem = deadline - time.monotonic()
                if rem <= 0.0:
                    return False, "inflight_timeout"
                self._cv.wait(timeout=rem)

    def release(self, ip: str) -> None:
        if self._max_global <= 0 and self._max_per_ip <= 0:
            return
        with self._cv:
            if self._global > 0:
                self._global -= 1
            c = self._per_ip.get(ip, 0)
            if c <= 1:
                self._per_ip.pop(ip, None)
            else:
                self._per_ip[ip] = c - 1
            self._cv.notify()

    def snapshot(self) -> Dict[str, Any]:
        with self._cv:
            return {
                "enabled": bool(self._max_global > 0 or self._max_per_ip > 0),
                "global_inflight": int(self._global),
                "distinct_ip_inflight": len(self._per_ip),
                "max_global": int(self._max_global),
                "max_per_ip": int(self._max_per_ip),
                "wait_timeout_s": float(self._wait_timeout_s),
            }


class _BucketShard:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.items: "OrderedDict[str, _IpBucket]" = OrderedDict()

    def get_or_create(self, ip: str, *, capacity: float, refill: float, limit: int, idle_s: float) -> _IpBucket:
        now = time.monotonic()
        with self.lock:
            while self.items:
                if limit > 0 and len(self.items) > limit:
                    self.items.popitem(last=False)
                    continue
                if idle_s > 0.0:
                    oldest_ip, oldest_bucket = next(iter(self.items.items()))
                    if (now - oldest_bucket.last_seen_mono) > idle_s:
                        self.items.pop(oldest_ip, None)
                        continue
                break

            bucket = self.items.get(ip)
            if bucket is None:
                bucket = _IpBucket(capacity, refill)
                self.items[ip] = bucket
            else:
                self.items.move_to_end(ip, last=True)
            return bucket

    def size(self) -> int:
        with self.lock:
            return len(self.items)


class _SecurityEngine:
    def __init__(self, config: SecurityMiddlewareConfig):
        self._cfg = config.normalized_copy()
        self._cfg_fp = "escfg2:" + hashlib.sha256(_canonical_json_bytes(self._cfg.digest_material())).hexdigest()[:32]
        self._allow: Set[str] = set(self._cfg.allow_origins)
        self._allow_all_origins = "*" in self._allow and not self._cfg.allow_credentials
        self._trusted_proxies = _parse_trusted_proxies(self._cfg.trusted_proxies)

        self._ip_allow_exact: Set[str] = set()
        self._ip_allow_nets: List[IpNet] = []
        self._ip_block_exact: Set[str] = set()
        self._ip_block_nets: List[IpNet] = []
        self._ip_suspicious_exact: Set[str] = set()
        self._ip_suspicious_nets: List[IpNet] = []

        self._load_ip_list(self._cfg.ip_allowlist, self._ip_allow_exact, self._ip_allow_nets)
        self._load_ip_list(self._cfg.ip_blocklist, self._ip_block_exact, self._ip_block_nets)
        self._load_ip_list(self._cfg.ip_suspicious, self._ip_suspicious_exact, self._ip_suspicious_nets)

        shard_count = max(1, int(self._cfg.bucket_shards))
        self._bucket_shards = tuple(_BucketShard() for _ in range(shard_count))
        self._per_shard_limit = 0 if self._cfg.ip_bucket_limit <= 0 else max(1, int(math.ceil(self._cfg.ip_bucket_limit / shard_count)))

        self._classified_matchers = [self._compile_path_matcher(x) for x in self._cfg.classified_path_patterns]
        self._audit_key = self._parse_hex_key(self._cfg.audit_hmac_key_hex)
        self._audit = _AuditDispatcher(
            mode=self._cfg.audit_mode,
            queue_size=self._cfg.audit_queue_size,
            drop_policy=self._cfg.audit_drop_policy,
            hook=self._cfg.audit_log_fn if self._cfg.emit_audit_log else None,
        )
        self._inflight = _InflightGate(
            max_global=self._cfg.max_inflight_global,
            max_per_ip=self._cfg.max_inflight_per_ip,
            wait_timeout_s=self._cfg.inflight_wait_timeout_s,
        )

    @staticmethod
    def _parse_hex_key(raw: Optional[str]) -> Optional[bytes]:
        if not raw or not isinstance(raw, str):
            return None
        s = _strip_unsafe_text(raw, max_len=8192).strip()
        if not s:
            return None
        if s.startswith(("0x", "0X")):
            s = s[2:]
        if len(s) % 2 == 1:
            return None
        if not re.fullmatch(r"[0-9a-fA-F]{16,8192}", s):
            return None
        try:
            return bytes.fromhex(s)
        except Exception:
            return None

    @staticmethod
    def _compile_path_matcher(pattern: str) -> Callable[[str], bool]:
        p = _strip_unsafe_text(pattern, max_len=256)
        if not p:
            return lambda _path: False
        try:
            cre = re.compile(p)
            return lambda path: bool(cre.search(path))
        except Exception:
            return lambda path: p in path

    def _load_ip_list(self, entries: Iterable[str], exact: Set[str], nets: List[IpNet]) -> None:
        for raw in entries:
            val = _strip_unsafe_text(raw, max_len=128).strip()
            if not val:
                continue
            try:
                if "/" in val:
                    nets.append(ipaddress.ip_network(val, strict=False))
                else:
                    ipn = _parse_ip(val)
                    if ipn:
                        exact.add(ipn)
            except Exception:
                _logger.warning("Invalid IP list entry ignored: %r", val)

    def _bucket_shard(self, ip: str) -> _BucketShard:
        idx = int.from_bytes(hashlib.blake2s(ip.encode("utf-8", errors="ignore"), digest_size=2).digest(), "big") % len(self._bucket_shards)
        return self._bucket_shards[idx]

    def _bucket(self, ip: str) -> _IpBucket:
        shard = self._bucket_shard(ip)
        return shard.get_or_create(
            ip,
            capacity=self._cfg.ip_capacity,
            refill=self._cfg.ip_refill_per_s,
            limit=self._per_shard_limit,
            idle_s=self._cfg.ip_bucket_idle_seconds,
        )

    def _ip_matches(self, ip: str, exact: Set[str], nets: List[IpNet]) -> bool:
        if ip in exact:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        for net in nets:
            try:
                if addr in net:
                    return True
            except Exception:
                continue
        return False

    def _ip_is_allowlisted(self, ip: str) -> bool:
        return self._ip_matches(ip, self._ip_allow_exact, self._ip_allow_nets)

    def _ip_is_blocklisted(self, ip: str) -> bool:
        return self._ip_matches(ip, self._ip_block_exact, self._ip_block_nets)

    def _ip_is_suspicious(self, ip: str) -> bool:
        return self._ip_matches(ip, self._ip_suspicious_exact, self._ip_suspicious_nets)

    def _resolve_client_ip(self, *, peer_ip: str, headers: Mapping[str, str]) -> Tuple[str, Optional[str]]:
        ip = _parse_ip(peer_ip) or "unknown"
        if not self._cfg.respect_xff:
            return ip, "xff_disabled"
        return _extract_client_ip_from_xff(
            remote_ip=ip,
            xff=headers.get("x-forwarded-for"),
            trusted_proxies=self._trusted_proxies,
            max_xff_parts=self._cfg.max_xff_parts,
        )

    def _path_is_classified(self, path: str) -> bool:
        for fn in self._classified_matchers:
            try:
                if fn(path):
                    return True
            except Exception:
                continue
        return False

    def _origin_matches_internal(self, normalized_origin: str) -> bool:
        host = _origin_host(normalized_origin)
        if not host:
            return False
        for suffix in self._cfg.internal_origin_suffixes:
            s = _strip_unsafe_text(suffix, max_len=128).lower().strip()
            if not s:
                continue
            if "://" in s:
                norm = _normalize_origin(s)
                if norm and normalized_origin == norm:
                    return True
                continue
            ss = s[1:] if s.startswith(".") else s
            if host == ss or host.endswith("." + ss):
                return True
        return False

    def _origin_ok(self, *, normalized_origin: Optional[str], path: str) -> Tuple[bool, Optional[str]]:
        if normalized_origin is None:
            return True, None
        if normalized_origin == "null":
            return (self._cfg.allow_null_origin, None if self._cfg.allow_null_origin else "null_origin_forbidden")

        mode = self._cfg.cors_mode
        if mode == "disabled":
            return False, "cors_disabled"
        if mode == "classified" and self._path_is_classified(path):
            return False, "classified_path"
        if mode == "internal_only":
            ok = self._origin_matches_internal(normalized_origin)
            return ok, None if ok else "origin_not_internal"
        if self._allow_all_origins:
            return True, None
        ok = normalized_origin in self._allow
        return ok, None if ok else "origin_not_allowed"

    def _audit_fingerprint(self, label: str, value: str) -> Optional[str]:
        if not value:
            return None
        data = b"tcd|edge|audit|" + _strip_unsafe_text(label, max_len=64).encode("utf-8", errors="ignore") + b"|" + value.encode("utf-8", errors="ignore")
        if self._audit_key:
            d = hmac.new(self._audit_key, data, hashlib.sha256).hexdigest()[:24]
            kid = _safe_taglike_id(self._cfg.audit_hmac_key_id, max_len=32) or "hmac"
            return f"{kid}:{d}"
        d = hashlib.blake2s(data).hexdigest()[:24]
        return f"anon:{d}"

    def _anonymize_ip(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return "*"
        if addr.version == 4:
            pieces = str(addr).split(".")
            if len(pieces) == 4:
                return ".".join(pieces[:3] + ["x"])
            return "*"
        parts = addr.compressed.split(":")
        if len(parts) >= 3:
            return ":".join(parts[:3]) + ":*"
        return "*"

    def _audit_ip_view(self, ip: str) -> Dict[str, Any]:
        return {
            "ip_prefix": self._anonymize_ip(ip),
            "ip_fp": self._audit_fingerprint("ip", ip),
        }

    def _should_hide_details(self, trust_profile: Optional[str]) -> bool:
        prof = _normalize_profile(trust_profile or self._cfg.security_profile)
        return bool(self._cfg.hide_details_in_high_security and _profile_is_high_security(prof))

    def _is_secure_transport(self, *, scheme: Optional[str], peer_ip: str, headers: Mapping[str, str]) -> bool:
        sch = (scheme or "").lower()
        if sch in {"https", "wss"}:
            return True
        xfproto = _strip_unsafe_text(headers.get("x-forwarded-proto") or "", max_len=32).lower().strip()
        if xfproto == "https" and _ip_in_trusted(_parse_ip(peer_ip) or "unknown", self._trusted_proxies):
            return True
        return False

    def _build_common_headers(
        self,
        *,
        request_id: Optional[str],
        edge_reason: Optional[str],
        trust_profile: Optional[str],
        retry_after_s: Optional[float],
        include_rate_policy: bool,
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        if request_id:
            headers["X-Request-Id"] = request_id
        if retry_after_s is not None and retry_after_s > 0.0:
            headers["Retry-After"] = str(max(1, int(math.ceil(retry_after_s))))
        if self._cfg.expose_headers_on_errors and not self._should_hide_details(trust_profile):
            headers["X-Edge-Security-Policy"] = "edge-security-v3"
            if include_rate_policy:
                headers["X-RateLimit-Policy"] = "edge-ip"
            if edge_reason:
                headers["X-TCD-Edge-Reason"] = _bounded_label(edge_reason, max_len=64)
        return headers

    def _apply_security_headers(self, headers: Any, *, trust_profile: Optional[str], is_secure_transport: bool) -> None:
        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", self._cfg.referrer_policy)
        headers.setdefault("Cache-Control", "no-store")
        headers.setdefault("Pragma", "no-cache")
        headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        headers.setdefault("Origin-Agent-Cluster", "?1")
        headers.setdefault("Permissions-Policy", self._cfg.permissions_policy)
        headers.setdefault("Content-Security-Policy", self._cfg.content_security_policy)

        if self._cfg.enable_hsts and is_secure_transport:
            parts = [f"max-age={self._cfg.hsts_max_age}"]
            if self._cfg.hsts_include_subdomains:
                parts.append("includeSubDomains")
            if self._cfg.hsts_preload:
                parts.append("preload")
            headers.setdefault("Strict-Transport-Security", "; ".join(parts))

        if self._cfg.enable_coop_coep:
            headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
            headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
            headers.setdefault("Cross-Origin-Resource-Policy", self._cfg.cross_origin_resource_policy)

        if not self._should_hide_details(trust_profile):
            headers.setdefault("X-Edge-Security-Policy", "edge-security-v3")

    def _apply_cors_headers(
        self,
        headers: Any,
        *,
        normalized_origin: Optional[str],
        origin_allowed: bool,
        is_preflight: bool,
        trust_profile: Optional[str],
        request_private_network: bool = False,
    ) -> None:
        if normalized_origin is None or not origin_allowed:
            return

        if self._allow_all_origins and not self._cfg.allow_credentials:
            headers.setdefault("Access-Control-Allow-Origin", "*")
        else:
            headers.setdefault("Access-Control-Allow-Origin", normalized_origin)

        headers["Vary"] = _merge_vary(headers.get("Vary"), "Origin")

        if self._cfg.allow_credentials:
            headers.setdefault("Access-Control-Allow-Credentials", "true")

        if is_preflight:
            headers["Vary"] = _merge_vary(headers.get("Vary"), "Access-Control-Request-Method")
            headers["Vary"] = _merge_vary(headers.get("Vary"), "Access-Control-Request-Headers")
            if request_private_network:
                headers["Vary"] = _merge_vary(headers.get("Vary"), "Access-Control-Request-Private-Network")
            headers.setdefault("Access-Control-Allow-Methods", ",".join(self._cfg.allow_methods))
            headers.setdefault("Access-Control-Allow-Headers", ",".join(self._cfg.allow_headers))
            headers.setdefault("Access-Control-Max-Age", str(self._cfg.max_preflight_age_s))
            if request_private_network and self._cfg.allow_private_network:
                headers["Access-Control-Allow-Private-Network"] = "true"
        else:
            if self._cfg.expose_headers and not self._should_hide_details(trust_profile):
                headers.setdefault("Access-Control-Expose-Headers", ",".join(self._cfg.expose_headers))

    def _build_error_response(
        self,
        *,
        request_id: Optional[str],
        status_code: int,
        error: str,
        edge_reason: Optional[str],
        trust_profile: Optional[str],
        normalized_origin: Optional[str],
        origin_allowed: bool,
        is_secure_transport: bool,
        retry_after_s: Optional[float] = None,
        request_private_network: bool = False,
    ) -> Response:
        body: Dict[str, Any] = {"error": error}
        if edge_reason and not self._should_hide_details(trust_profile):
            body["edge_reason"] = _bounded_label(edge_reason, max_len=64)

        try:
            payload = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        except Exception:
            payload = '{"error":"edge_error"}'

        headers = self._build_common_headers(
            request_id=request_id,
            edge_reason=edge_reason,
            trust_profile=trust_profile,
            retry_after_s=retry_after_s,
            include_rate_policy=(status_code in {429, 503}),
        )
        resp = Response(
            content=payload if self._cfg.json_error else _bounded_label(error, max_len=64),
            status_code=int(status_code),
            media_type="application/json" if self._cfg.json_error else "text/plain",
            headers=headers,
        )
        self._apply_security_headers(resp.headers, trust_profile=trust_profile, is_secure_transport=is_secure_transport)
        self._apply_cors_headers(
            resp.headers,
            normalized_origin=normalized_origin,
            origin_allowed=origin_allowed,
            is_preflight=False,
            trust_profile=trust_profile,
            request_private_network=request_private_network,
        )
        return resp

    def _public_edge_info(self, edge_info: Mapping[str, Any], *, client_ip: str, peer_ip: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "cfg_fp": edge_info.get("cfg_fp"),
            "ip_limited": bool(edge_info.get("ip_limited")),
            "ip_blocked": bool(edge_info.get("ip_blocked")),
            "ip_suspicious": bool(edge_info.get("ip_suspicious")),
            "origin_ok": bool(edge_info.get("origin_ok")),
            "cors_mode": _safe_text(edge_info.get("cors_mode"), max_len=32),
            "security_profile": _safe_text(edge_info.get("security_profile"), max_len=32),
            "threat_level": int(edge_info.get("threat_level", 0)),
            "edge_zone": _safe_text(edge_info.get("edge_zone"), max_len=32),
            "client_ip": self._audit_ip_view(client_ip),
            "peer_ip": self._audit_ip_view(peer_ip),
        }
        reason = edge_info.get("rate_limited_reason")
        if isinstance(reason, str) and reason:
            out["rate_limited_reason"] = _bounded_label(reason, max_len=64)
        if "xff_reason" in edge_info and edge_info.get("xff_reason"):
            out["xff_reason"] = _bounded_label(str(edge_info.get("xff_reason")), max_len=64)
        return out

    def _emit_audit(self, record: Dict[str, Any]) -> None:
        if not self._cfg.emit_audit_log:
            return
        try:
            raw = _canonical_json_bytes(record)
            if len(raw) > _MAX_AUDIT_EVENT_BYTES:
                record = {
                    "schema": record.get("schema"),
                    "event": record.get("event"),
                    "reason": record.get("reason"),
                    "cfg_fp": record.get("cfg_fp"),
                    "request_id": record.get("request_id"),
                    "ts_unix_ms": record.get("ts_unix_ms"),
                    "truncated": True,
                }
        except Exception:
            pass
        self._audit.emit(record)

    def _log_security_event(
        self,
        *,
        event_type: str,
        method: str,
        path: str,
        peer_ip: str,
        client_ip: str,
        xff_reason: Optional[str],
        request_id: Optional[str],
        origin: Optional[str],
        edge_info: Mapping[str, Any],
        reason: str,
        trust_profile: Optional[str],
    ) -> None:
        meta = _get_global_threat_meta()
        record: Dict[str, Any] = {
            "schema": "tcd.edge_security.audit.v3",
            "cfg_fp": self._cfg_fp,
            "event": _bounded_label(event_type, max_len=64),
            "reason": _bounded_label(reason, max_len=64),
            "request_method": _bounded_label(method, max_len=16),
            "request_path": _normalize_logged_path(path),
            "origin_host": _origin_host(origin),
            "security_profile": self._cfg.security_profile,
            "trust_profile": _normalize_profile(trust_profile or self._cfg.security_profile),
            "threat_level": _get_global_threat_level(),
            "threat_source": _safe_text(meta.get("source"), max_len=64) or None,
            "threat_reason": _safe_text(meta.get("reason"), max_len=128) or None,
            "ts_unix_ms": int(time.time() * 1000),
            "edge_security": self._public_edge_info(edge_info, client_ip=client_ip, peer_ip=peer_ip),
        }
        if xff_reason:
            record["xff_reason"] = _bounded_label(xff_reason, max_len=64)
        if request_id:
            record["request_id"] = request_id
        self._emit_audit(record)

    def _make_edge_info(
        self,
        *,
        peer_ip: str,
        client_ip: str,
        xff_reason: Optional[str],
        request_path: str,
        request_method: str,
    ) -> Dict[str, Any]:
        info: Dict[str, Any] = {
            "cfg_fp": self._cfg_fp,
            "client_ip": client_ip,
            "peer_ip": peer_ip,
            "client_ip_hash": self._audit_fingerprint("state_client_ip", client_ip),
            "peer_ip_hash": self._audit_fingerprint("state_peer_ip", peer_ip),
            "ip_limited": False,
            "ip_blocked": False,
            "ip_suspicious": False,
            "origin_ok": True,
            "cors_mode": self._cfg.cors_mode,
            "security_profile": self._cfg.security_profile,
            "threat_level": _get_global_threat_level(),
            "edge_zone": "edge-ip",
            "xff_reason": xff_reason,
        }
        if not self._cfg.minimize_state_context_dict:
            info["request_path"] = _normalize_logged_path(request_path)
            info["request_method"] = _bounded_label(request_method, max_len=16)
        return info

    def _prepare_state(
        self,
        *,
        state: Any,
        edge_info: Dict[str, Any],
        xff_reason: Optional[str],
        request_id: Optional[str],
    ) -> None:
        _state_set(state, "edge_security", edge_info)
        if _state_get(state, "tcd_trust_profile", None) is None:
            _state_set(state, "tcd_trust_profile", self._cfg.security_profile)
            _state_set(state, "tcd_trust_profile_source", "edge_security_default")
        if xff_reason:
            _state_set(state, "xff_ignored_reason", xff_reason)
        if request_id and _state_get(state, "request_id", None) is None:
            _state_set(state, "request_id", request_id)

    def _mark_rate_limited_state(self, *, state: Any, edge_info: Dict[str, Any], reason: str) -> None:
        edge_info["ip_limited"] = True
        edge_info["rate_limited_reason"] = reason
        if self._cfg.link_to_multivar:
            _state_set(state, "edge_rate_limited", True)
            _state_set(state, "edge_rate_zone", "edge-ip")
            _state_set(state, "edge_rejected_reason", reason)

    def _mark_blocked_state(self, *, state: Any, edge_info: Dict[str, Any], reason: str) -> None:
        edge_info["ip_blocked"] = True
        if self._cfg.link_to_multivar:
            _state_set(state, "edge_rejected_reason", reason)

    def _rate_limit(
        self,
        *,
        ip: str,
        is_allowlisted: bool,
        is_suspicious: bool,
    ) -> Tuple[bool, Optional[float], str]:
        if not self._cfg.rate_limit_enabled:
            return True, None, "disabled"
        if self._cfg.ip_capacity <= 0.0 or self._cfg.ip_refill_per_s <= 0.0:
            return True, None, "disabled"
        if self._cfg.allowlisted_bypass_rate_limit and is_allowlisted:
            return True, None, "allowlisted_bypass"

        bucket = self._bucket(ip)
        cost = self._cfg.suspicious_cost if is_suspicious else 1.0

        threat = _get_global_threat_level()
        if threat >= 1 and not is_allowlisted:
            cost *= 1.5
        if threat >= 3 and is_suspicious:
            cost *= 2.0

        cost = _clamp_float(cost, 0.000001, 1_000_000.0, default=1.0)
        if cost > bucket.capacity:
            mode = self._cfg.cost_over_capacity_mode
            if mode == "audit_only":
                return True, None, "cost_over_capacity_audit_only"
            if mode == "deny_without_bucket":
                return False, None, "cost_over_capacity"
            cost = bucket.capacity

        return bucket.take(
            cost,
            temp_block_after_denies=self._cfg.temp_block_after_denies,
            temp_block_ttl_s=self._cfg.temp_block_ttl_s,
            max_tokens_per_window=self._cfg.max_tokens_per_ip_per_window,
            window_s=self._cfg.max_tokens_window_s,
        )

    def _check_budgets(self, *, scope: Mapping[str, Any], headers: Mapping[str, str], path: str) -> Optional[Tuple[int, str]]:
        hcount, hbytes = _header_budget_from_scope(scope)
        if hcount > self._cfg.max_header_count:
            return 431, "headers_too_many"
        if hbytes > self._cfg.max_header_bytes:
            return 431, "headers_too_large"
        origin = headers.get("origin")
        if origin is not None and len(origin.encode("utf-8", errors="ignore")) > self._cfg.max_origin_bytes:
            return 400, "origin_too_large"
        xff = headers.get("x-forwarded-for")
        if xff is not None and len(xff.encode("utf-8", errors="ignore")) > self._cfg.max_xff_bytes:
            return 400, "xff_too_large"
        if len(path.encode("utf-8", errors="ignore")) > self._cfg.max_path_bytes:
            return 414, "path_too_large"
        return None

    def acquire_inflight(self, ip: str) -> Tuple[bool, str]:
        return self._inflight.acquire(ip)

    def release_inflight(self, ip: str) -> None:
        self._inflight.release(ip)

    def diagnostics(self) -> Dict[str, Any]:
        bucket_total = 0
        for shard in self._bucket_shards:
            bucket_total += shard.size()
        return {
            "schema": "tcd.edge_security.diag.v1",
            "cfg_fp": self._cfg_fp,
            "security_profile": self._cfg.security_profile,
            "bucket_total": int(bucket_total),
            "bucket_shards": len(self._bucket_shards),
            "trusted_proxy_count": len(self._trusted_proxies),
            "threat_level": _get_global_threat_level(),
            "audit": self._audit.snapshot(),
            "inflight": self._inflight.snapshot(),
        }


class SecurityMiddleware(BaseHTTPMiddleware):
    """
    Edge security middleware aligned to the main middleware contract:

      - trusted proxy / XFF aware client IP resolution
      - explicit rate-disable semantics when capacity/refill <= 0
      - bounded per-IP token buckets with optional temp block and window cap
      - optional global/per-IP inflight gates
      - blocklist / allowlist / suspicious tiers
      - CORS policy modes + safe preflight
      - browser security headers
      - request.state.edge_security + edge_rate_limited / edge_rate_zone / xff_ignored_reason
      - low-leak, structured audit events
      - pure ASGI companion for streaming correctness
    """

    @classmethod
    def set_global_threat_level(cls, level: int, *, source: str = "local", reason: str = "") -> None:
        _set_global_threat_level(level, source=source, reason=reason)

    @classmethod
    def get_global_threat_level(cls) -> int:
        return _get_global_threat_level()

    def __init__(
        self,
        app,
        *,
        config: Optional[SecurityMiddlewareConfig] = None,
        allow_origins: Iterable[str] = (),
        ip_capacity: float = 30.0,
        ip_refill_per_s: float = 15.0,
        security_profile: str = "DEV",
        ip_allowlist: Optional[Iterable[str]] = None,
        ip_blocklist: Optional[Iterable[str]] = None,
        ip_suspicious: Optional[Iterable[str]] = None,
        ip_bucket_limit: int = 10_000,
        ip_bucket_idle_seconds: float = 600.0,
        cors_mode: str = "strict_allowlist",
        classified_path_patterns: Optional[Iterable[str]] = None,
        internal_origin_suffixes: Optional[Iterable[str]] = None,
        enable_hsts: bool = False,
        hsts_max_age: int = 31_536_000,
        hsts_include_subdomains: bool = False,
        hsts_preload: bool = False,
        enable_coop_coep: bool = True,
        trusted_proxies: Optional[Iterable[str]] = None,
        respect_xff: bool = False,
        max_xff_parts: int = 16,
        suspicious_cost: float = 2.0,
        temp_block_after_denies: int = 0,
        temp_block_ttl_s: float = 0.0,
        max_tokens_per_ip_per_window: float = 0.0,
        max_tokens_window_s: float = 60.0,
        emit_audit_log: bool = True,
        audit_log_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
        allow_credentials: bool = False,
        allow_methods: Iterable[str] = ("GET", "POST", "OPTIONS"),
        allow_headers: Iterable[str] = ("authorization", "content-type", "x-request-id"),
        expose_headers: Iterable[str] = ("x-request-id",),
    ):
        super().__init__(app)
        if config is None:
            config = SecurityMiddlewareConfig(
                allow_origins=tuple(allow_origins),
                ip_capacity=ip_capacity,
                ip_refill_per_s=ip_refill_per_s,
                security_profile=security_profile,
                ip_allowlist=tuple(ip_allowlist or ()),
                ip_blocklist=tuple(ip_blocklist or ()),
                ip_suspicious=tuple(ip_suspicious or ()),
                ip_bucket_limit=ip_bucket_limit,
                ip_bucket_idle_seconds=ip_bucket_idle_seconds,
                cors_mode=cors_mode,
                classified_path_patterns=tuple(classified_path_patterns or ()),
                internal_origin_suffixes=tuple(internal_origin_suffixes or ()),
                enable_hsts=enable_hsts,
                hsts_max_age=hsts_max_age,
                hsts_include_subdomains=hsts_include_subdomains,
                hsts_preload=hsts_preload,
                enable_coop_coep=enable_coop_coep,
                trusted_proxies=tuple(trusted_proxies or ()),
                respect_xff=respect_xff,
                max_xff_parts=max_xff_parts,
                suspicious_cost=suspicious_cost,
                temp_block_after_denies=temp_block_after_denies,
                temp_block_ttl_s=temp_block_ttl_s,
                max_tokens_per_ip_per_window=max_tokens_per_ip_per_window,
                max_tokens_window_s=max_tokens_window_s,
                emit_audit_log=emit_audit_log,
                audit_log_fn=audit_log_fn,
                allow_credentials=allow_credentials,
                allow_methods=tuple(allow_methods),
                allow_headers=tuple(allow_headers),
                expose_headers=tuple(expose_headers),
            )
        self._engine = _SecurityEngine(config)

    def diagnostics(self) -> Dict[str, Any]:
        return self._engine.diagnostics()

    async def dispatch(self, request: Request, call_next):
        headers = {k.lower(): v for k, v in request.headers.items()}
        path = request.url.path
        method = request.method.upper()

        budget_fail = self._engine._check_budgets(scope=request.scope, headers=headers, path=path)
        peer_ip = _parse_ip(request.client.host if request.client else "") or "unknown"
        request_id = _request_id_from_state_or_headers(request)
        trust_profile = _trusted_profile_from_state_or_default(request.state, self._engine._cfg.security_profile)
        origin = _normalize_origin(headers.get("origin"))
        request_private_network = (headers.get("access-control-request-private-network") or "").strip().lower() == "true"
        is_secure_transport = self._engine._is_secure_transport(scheme=request.url.scheme, peer_ip=peer_ip, headers=headers)

        client_ip, xff_reason = self._engine._resolve_client_ip(peer_ip=peer_ip, headers=headers)
        origin_ok, origin_reason = self._engine._origin_ok(normalized_origin=origin, path=path)

        edge_info = self._engine._make_edge_info(
            peer_ip=peer_ip,
            client_ip=client_ip,
            xff_reason=xff_reason,
            request_path=path,
            request_method=method,
        )
        edge_info["origin_ok"] = bool(origin_ok)
        self._engine._prepare_state(
            state=request.state,
            edge_info=edge_info,
            xff_reason=xff_reason,
            request_id=request_id,
        )

        if budget_fail is not None:
            status_code, edge_reason = budget_fail
            self._engine._log_security_event(
                event_type="edge_reject",
                method=method,
                path=path,
                peer_ip=peer_ip,
                client_ip=client_ip,
                xff_reason=xff_reason,
                request_id=request_id,
                origin=origin,
                edge_info=edge_info,
                reason=edge_reason,
                trust_profile=trust_profile,
            )
            return self._engine._build_error_response(
                request_id=request_id,
                status_code=status_code,
                error="bad_request" if status_code < 500 else "unavailable",
                edge_reason=edge_reason,
                trust_profile=trust_profile,
                normalized_origin=origin,
                origin_allowed=origin_ok,
                is_secure_transport=is_secure_transport,
                request_private_network=request_private_network,
            )

        try:
            if self._engine._ip_is_blocklisted(client_ip):
                self._engine._mark_blocked_state(state=request.state, edge_info=edge_info, reason="ip_blocklist")
                self._engine._log_security_event(
                    event_type="ip_block",
                    method=method,
                    path=path,
                    peer_ip=peer_ip,
                    client_ip=client_ip,
                    xff_reason=xff_reason,
                    request_id=request_id,
                    origin=origin,
                    edge_info=edge_info,
                    reason="ip_blocklist",
                    trust_profile=trust_profile,
                )
                return self._engine._build_error_response(
                    request_id=request_id,
                    status_code=403,
                    error="forbidden",
                    edge_reason="ip_blocklist",
                    trust_profile=trust_profile,
                    normalized_origin=origin,
                    origin_allowed=origin_ok,
                    is_secure_transport=is_secure_transport,
                    request_private_network=request_private_network,
                )

            threat_level = _get_global_threat_level()
            is_allowlisted = self._engine._ip_is_allowlisted(client_ip)
            is_suspicious = self._engine._ip_is_suspicious(client_ip)
            if is_suspicious:
                edge_info["ip_suspicious"] = True

            if threat_level >= self._engine._cfg.threat_level_hard_block_threshold and not is_allowlisted:
                self._engine._mark_blocked_state(state=request.state, edge_info=edge_info, reason="global_threat_lockdown")
                self._engine._log_security_event(
                    event_type="edge_lockdown",
                    method=method,
                    path=path,
                    peer_ip=peer_ip,
                    client_ip=client_ip,
                    xff_reason=xff_reason,
                    request_id=request_id,
                    origin=origin,
                    edge_info=edge_info,
                    reason="global_threat_lockdown",
                    trust_profile=trust_profile,
                )
                return self._engine._build_error_response(
                    request_id=request_id,
                    status_code=403,
                    error="forbidden",
                    edge_reason="global_threat_lockdown",
                    trust_profile=trust_profile,
                    normalized_origin=origin,
                    origin_allowed=origin_ok,
                    is_secure_transport=is_secure_transport,
                    request_private_network=request_private_network,
                )

            if threat_level >= self._engine._cfg.threat_level_overload_threshold and not is_allowlisted:
                self._engine._mark_rate_limited_state(state=request.state, edge_info=edge_info, reason="edge_overload")
                self._engine._log_security_event(
                    event_type="edge_overload",
                    method=method,
                    path=path,
                    peer_ip=peer_ip,
                    client_ip=client_ip,
                    xff_reason=xff_reason,
                    request_id=request_id,
                    origin=origin,
                    edge_info=edge_info,
                    reason="global_threat_level",
                    trust_profile=trust_profile,
                )
                return self._engine._build_error_response(
                    request_id=request_id,
                    status_code=503,
                    error="unavailable",
                    edge_reason="edge_overload",
                    trust_profile=trust_profile,
                    normalized_origin=origin,
                    origin_allowed=origin_ok,
                    is_secure_transport=is_secure_transport,
                    retry_after_s=1.0,
                    request_private_network=request_private_network,
                )

            ok_inflight, inflight_reason = self._engine.acquire_inflight(client_ip)
            if not ok_inflight:
                self._engine._mark_rate_limited_state(state=request.state, edge_info=edge_info, reason=inflight_reason)
                self._engine._log_security_event(
                    event_type="inflight_reject",
                    method=method,
                    path=path,
                    peer_ip=peer_ip,
                    client_ip=client_ip,
                    xff_reason=xff_reason,
                    request_id=request_id,
                    origin=origin,
                    edge_info=edge_info,
                    reason=inflight_reason,
                    trust_profile=trust_profile,
                )
                return self._engine._build_error_response(
                    request_id=request_id,
                    status_code=503,
                    error="unavailable",
                    edge_reason=inflight_reason,
                    trust_profile=trust_profile,
                    normalized_origin=origin,
                    origin_allowed=origin_ok,
                    is_secure_transport=is_secure_transport,
                    request_private_network=request_private_network,
                )

            try:
                ok_rate, retry_after_s, rate_reason = self._engine._rate_limit(
                    ip=client_ip,
                    is_allowlisted=is_allowlisted,
                    is_suspicious=is_suspicious,
                )
                if not ok_rate:
                    self._engine._mark_rate_limited_state(state=request.state, edge_info=edge_info, reason=rate_reason)
                    self._engine._log_security_event(
                        event_type="rate_limited",
                        method=method,
                        path=path,
                        peer_ip=peer_ip,
                        client_ip=client_ip,
                        xff_reason=xff_reason,
                        request_id=request_id,
                        origin=origin,
                        edge_info=edge_info,
                        reason=rate_reason,
                        trust_profile=trust_profile,
                    )
                    return self._engine._build_error_response(
                        request_id=request_id,
                        status_code=429,
                        error="rate_limited",
                        edge_reason=rate_reason,
                        trust_profile=trust_profile,
                        normalized_origin=origin,
                        origin_allowed=origin_ok,
                        is_secure_transport=is_secure_transport,
                        retry_after_s=retry_after_s,
                        request_private_network=request_private_network,
                    )

                if not origin_ok:
                    self._engine._log_security_event(
                        event_type="cors_block",
                        method=method,
                        path=path,
                        peer_ip=peer_ip,
                        client_ip=client_ip,
                        xff_reason=xff_reason,
                        request_id=request_id,
                        origin=origin,
                        edge_info=edge_info,
                        reason=origin_reason or "origin_not_allowed",
                        trust_profile=trust_profile,
                    )
                    return self._engine._build_error_response(
                        request_id=request_id,
                        status_code=403,
                        error="cors_blocked",
                        edge_reason=origin_reason or "origin_not_allowed",
                        trust_profile=trust_profile,
                        normalized_origin=origin,
                        origin_allowed=False,
                        is_secure_transport=is_secure_transport,
                        request_private_network=request_private_network,
                    )

                if method == "OPTIONS" and origin is not None:
                    resp = Response(status_code=204)
                    self._engine._apply_security_headers(resp.headers, trust_profile=trust_profile, is_secure_transport=is_secure_transport)
                    self._engine._apply_cors_headers(
                        resp.headers,
                        normalized_origin=origin,
                        origin_allowed=True,
                        is_preflight=True,
                        trust_profile=trust_profile,
                        request_private_network=request_private_network,
                    )
                    if request_id:
                        resp.headers.setdefault("X-Request-Id", request_id)
                    return resp

                resp: Response = await call_next(request)
                self._engine._apply_security_headers(resp.headers, trust_profile=trust_profile, is_secure_transport=is_secure_transport)
                self._engine._apply_cors_headers(
                    resp.headers,
                    normalized_origin=origin,
                    origin_allowed=origin_ok,
                    is_preflight=False,
                    trust_profile=trust_profile,
                    request_private_network=request_private_network,
                )
                if request_id and ("X-Request-Id" not in resp.headers):
                    resp.headers["X-Request-Id"] = request_id
                return resp
            finally:
                self._engine.release_inflight(client_ip)

        except Exception:
            _logger.exception("Unhandled exception in SecurityMiddleware.dispatch")
            self._engine._log_security_event(
                event_type="edge_exception",
                method=method,
                path=path,
                peer_ip=peer_ip,
                client_ip=client_ip,
                xff_reason=xff_reason,
                request_id=request_id,
                origin=origin,
                edge_info=edge_info,
                reason="exception",
                trust_profile=trust_profile,
            )
            return self._engine._build_error_response(
                request_id=request_id,
                status_code=503,
                error="internal_edge_error",
                edge_reason="exception",
                trust_profile=trust_profile,
                normalized_origin=origin,
                origin_allowed=origin_ok,
                is_secure_transport=is_secure_transport,
                request_private_network=request_private_network,
            )


class SecurityASGIMiddleware:
    """
    Pure ASGI variant for production streaming correctness.

    Shares the same engine and behavioral contract as SecurityMiddleware:
      - XFF rightmost non-proxy extraction
      - bounded local IP rate limiting with explicit disable semantics
      - request.state edge_security / edge_rate_limited / edge_rate_zone / xff_ignored_reason
      - low-leak audit events
      - secure headers + CORS handling
    """

    @classmethod
    def set_global_threat_level(cls, level: int, *, source: str = "local", reason: str = "") -> None:
        _set_global_threat_level(level, source=source, reason=reason)

    @classmethod
    def get_global_threat_level(cls) -> int:
        return _get_global_threat_level()

    def __init__(
        self,
        app,
        *,
        config: Optional[SecurityMiddlewareConfig] = None,
        allow_origins: Iterable[str] = (),
        ip_capacity: float = 30.0,
        ip_refill_per_s: float = 15.0,
        security_profile: str = "DEV",
        ip_allowlist: Optional[Iterable[str]] = None,
        ip_blocklist: Optional[Iterable[str]] = None,
        ip_suspicious: Optional[Iterable[str]] = None,
        ip_bucket_limit: int = 10_000,
        ip_bucket_idle_seconds: float = 600.0,
        cors_mode: str = "strict_allowlist",
        classified_path_patterns: Optional[Iterable[str]] = None,
        internal_origin_suffixes: Optional[Iterable[str]] = None,
        enable_hsts: bool = False,
        hsts_max_age: int = 31_536_000,
        hsts_include_subdomains: bool = False,
        hsts_preload: bool = False,
        enable_coop_coep: bool = True,
        trusted_proxies: Optional[Iterable[str]] = None,
        respect_xff: bool = False,
        max_xff_parts: int = 16,
        suspicious_cost: float = 2.0,
        temp_block_after_denies: int = 0,
        temp_block_ttl_s: float = 0.0,
        max_tokens_per_ip_per_window: float = 0.0,
        max_tokens_window_s: float = 60.0,
        emit_audit_log: bool = True,
        audit_log_fn: Optional[Callable[[Dict[str, Any]], None]] = None,
        allow_credentials: bool = False,
        allow_methods: Iterable[str] = ("GET", "POST", "OPTIONS"),
        allow_headers: Iterable[str] = ("authorization", "content-type", "x-request-id"),
        expose_headers: Iterable[str] = ("x-request-id",),
    ):
        self.app = app
        if config is None:
            config = SecurityMiddlewareConfig(
                allow_origins=tuple(allow_origins),
                ip_capacity=ip_capacity,
                ip_refill_per_s=ip_refill_per_s,
                security_profile=security_profile,
                ip_allowlist=tuple(ip_allowlist or ()),
                ip_blocklist=tuple(ip_blocklist or ()),
                ip_suspicious=tuple(ip_suspicious or ()),
                ip_bucket_limit=ip_bucket_limit,
                ip_bucket_idle_seconds=ip_bucket_idle_seconds,
                cors_mode=cors_mode,
                classified_path_patterns=tuple(classified_path_patterns or ()),
                internal_origin_suffixes=tuple(internal_origin_suffixes or ()),
                enable_hsts=enable_hsts,
                hsts_max_age=hsts_max_age,
                hsts_include_subdomains=hsts_include_subdomains,
                hsts_preload=hsts_preload,
                enable_coop_coep=enable_coop_coep,
                trusted_proxies=tuple(trusted_proxies or ()),
                respect_xff=respect_xff,
                max_xff_parts=max_xff_parts,
                suspicious_cost=suspicious_cost,
                temp_block_after_denies=temp_block_after_denies,
                temp_block_ttl_s=temp_block_ttl_s,
                max_tokens_per_ip_per_window=max_tokens_per_ip_per_window,
                max_tokens_window_s=max_tokens_window_s,
                emit_audit_log=emit_audit_log,
                audit_log_fn=audit_log_fn,
                allow_credentials=allow_credentials,
                allow_methods=tuple(allow_methods),
                allow_headers=tuple(allow_headers),
                expose_headers=tuple(expose_headers),
            )
        self._engine = _SecurityEngine(config)

    def diagnostics(self) -> Dict[str, Any]:
        return self._engine.diagnostics()

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        headers = _headers_from_scope(scope)
        path = _strip_unsafe_text(scope.get("path") or "/", max_len=2048).strip() or "/"
        method = _safe_text(scope.get("method") or "GET", max_len=16).upper() or "GET"
        state = scope.setdefault("state", {})
        client = scope.get("client") or ("unknown", 0)
        peer_ip = _parse_ip(client[0] if isinstance(client, (list, tuple)) and client else "unknown") or "unknown"
        request_id = _safe_taglike_id(
            _state_get(state, "request_id", None) or headers.get("x-request-id"),
            max_len=255,
        )
        trust_profile = _trusted_profile_from_state_or_default(state, self._engine._cfg.security_profile)
        origin = _normalize_origin(headers.get("origin"))
        request_private_network = (headers.get("access-control-request-private-network") or "").strip().lower() == "true"
        is_secure_transport = self._engine._is_secure_transport(scheme=scope.get("scheme"), peer_ip=peer_ip, headers=headers)

        budget_fail = self._engine._check_budgets(scope=scope, headers=headers, path=path)
        client_ip, xff_reason = self._engine._resolve_client_ip(peer_ip=peer_ip, headers=headers)
        origin_ok, origin_reason = self._engine._origin_ok(normalized_origin=origin, path=path)

        edge_info = self._engine._make_edge_info(
            peer_ip=peer_ip,
            client_ip=client_ip,
            xff_reason=xff_reason,
            request_path=path,
            request_method=method,
        )
        edge_info["origin_ok"] = bool(origin_ok)
        self._engine._prepare_state(
            state=state,
            edge_info=edge_info,
            xff_reason=xff_reason,
            request_id=request_id,
        )

        def _asgi_response(resp: Response):
            return resp(scope, receive, send)

        if budget_fail is not None:
            status_code, edge_reason = budget_fail
            self._engine._log_security_event(
                event_type="edge_reject",
                method=method,
                path=path,
                peer_ip=peer_ip,
                client_ip=client_ip,
                xff_reason=xff_reason,
                request_id=request_id,
                origin=origin,
                edge_info=edge_info,
                reason=edge_reason,
                trust_profile=trust_profile,
            )
            return await _asgi_response(
                self._engine._build_error_response(
                    request_id=request_id,
                    status_code=status_code,
                    error="bad_request" if status_code < 500 else "unavailable",
                    edge_reason=edge_reason,
                    trust_profile=trust_profile,
                    normalized_origin=origin,
                    origin_allowed=origin_ok,
                    is_secure_transport=is_secure_transport,
                    request_private_network=request_private_network,
                )
            )

        try:
            if self._engine._ip_is_blocklisted(client_ip):
                self._engine._mark_blocked_state(state=state, edge_info=edge_info, reason="ip_blocklist")
                self._engine._log_security_event(
                    event_type="ip_block",
                    method=method,
                    path=path,
                    peer_ip=peer_ip,
                    client_ip=client_ip,
                    xff_reason=xff_reason,
                    request_id=request_id,
                    origin=origin,
                    edge_info=edge_info,
                    reason="ip_blocklist",
                    trust_profile=trust_profile,
                )
                return await _asgi_response(
                    self._engine._build_error_response(
                        request_id=request_id,
                        status_code=403,
                        error="forbidden",
                        edge_reason="ip_blocklist",
                        trust_profile=trust_profile,
                        normalized_origin=origin,
                        origin_allowed=origin_ok,
                        is_secure_transport=is_secure_transport,
                        request_private_network=request_private_network,
                    )
                )

            threat_level = _get_global_threat_level()
            is_allowlisted = self._engine._ip_is_allowlisted(client_ip)
            is_suspicious = self._engine._ip_is_suspicious(client_ip)
            if is_suspicious:
                edge_info["ip_suspicious"] = True

            if threat_level >= self._engine._cfg.threat_level_hard_block_threshold and not is_allowlisted:
                self._engine._mark_blocked_state(state=state, edge_info=edge_info, reason="global_threat_lockdown")
                self._engine._log_security_event(
                    event_type="edge_lockdown",
                    method=method,
                    path=path,
                    peer_ip=peer_ip,
                    client_ip=client_ip,
                    xff_reason=xff_reason,
                    request_id=request_id,
                    origin=origin,
                    edge_info=edge_info,
                    reason="global_threat_lockdown",
                    trust_profile=trust_profile,
                )
                return await _asgi_response(
                    self._engine._build_error_response(
                        request_id=request_id,
                        status_code=403,
                        error="forbidden",
                        edge_reason="global_threat_lockdown",
                        trust_profile=trust_profile,
                        normalized_origin=origin,
                        origin_allowed=origin_ok,
                        is_secure_transport=is_secure_transport,
                        request_private_network=request_private_network,
                    )
                )

            if threat_level >= self._engine._cfg.threat_level_overload_threshold and not is_allowlisted:
                self._engine._mark_rate_limited_state(state=state, edge_info=edge_info, reason="edge_overload")
                self._engine._log_security_event(
                    event_type="edge_overload",
                    method=method,
                    path=path,
                    peer_ip=peer_ip,
                    client_ip=client_ip,
                    xff_reason=xff_reason,
                    request_id=request_id,
                    origin=origin,
                    edge_info=edge_info,
                    reason="global_threat_level",
                    trust_profile=trust_profile,
                )
                return await _asgi_response(
                    self._engine._build_error_response(
                        request_id=request_id,
                        status_code=503,
                        error="unavailable",
                        edge_reason="edge_overload",
                        trust_profile=trust_profile,
                        normalized_origin=origin,
                        origin_allowed=origin_ok,
                        is_secure_transport=is_secure_transport,
                        retry_after_s=1.0,
                        request_private_network=request_private_network,
                    )
                )

            ok_inflight, inflight_reason = self._engine.acquire_inflight(client_ip)
            if not ok_inflight:
                self._engine._mark_rate_limited_state(state=state, edge_info=edge_info, reason=inflight_reason)
                self._engine._log_security_event(
                    event_type="inflight_reject",
                    method=method,
                    path=path,
                    peer_ip=peer_ip,
                    client_ip=client_ip,
                    xff_reason=xff_reason,
                    request_id=request_id,
                    origin=origin,
                    edge_info=edge_info,
                    reason=inflight_reason,
                    trust_profile=trust_profile,
                )
                return await _asgi_response(
                    self._engine._build_error_response(
                        request_id=request_id,
                        status_code=503,
                        error="unavailable",
                        edge_reason=inflight_reason,
                        trust_profile=trust_profile,
                        normalized_origin=origin,
                        origin_allowed=origin_ok,
                        is_secure_transport=is_secure_transport,
                        request_private_network=request_private_network,
                    )
                )

            try:
                ok_rate, retry_after_s, rate_reason = self._engine._rate_limit(
                    ip=client_ip,
                    is_allowlisted=is_allowlisted,
                    is_suspicious=is_suspicious,
                )
                if not ok_rate:
                    self._engine._mark_rate_limited_state(state=state, edge_info=edge_info, reason=rate_reason)
                    self._engine._log_security_event(
                        event_type="rate_limited",
                        method=method,
                        path=path,
                        peer_ip=peer_ip,
                        client_ip=client_ip,
                        xff_reason=xff_reason,
                        request_id=request_id,
                        origin=origin,
                        edge_info=edge_info,
                        reason=rate_reason,
                        trust_profile=trust_profile,
                    )
                    return await _asgi_response(
                        self._engine._build_error_response(
                            request_id=request_id,
                            status_code=429,
                            error="rate_limited",
                            edge_reason=rate_reason,
                            trust_profile=trust_profile,
                            normalized_origin=origin,
                            origin_allowed=origin_ok,
                            is_secure_transport=is_secure_transport,
                            retry_after_s=retry_after_s,
                            request_private_network=request_private_network,
                        )
                    )

                if not origin_ok:
                    self._engine._log_security_event(
                        event_type="cors_block",
                        method=method,
                        path=path,
                        peer_ip=peer_ip,
                        client_ip=client_ip,
                        xff_reason=xff_reason,
                        request_id=request_id,
                        origin=origin,
                        edge_info=edge_info,
                        reason=origin_reason or "origin_not_allowed",
                        trust_profile=trust_profile,
                    )
                    return await _asgi_response(
                        self._engine._build_error_response(
                            request_id=request_id,
                            status_code=403,
                            error="cors_blocked",
                            edge_reason=origin_reason or "origin_not_allowed",
                            trust_profile=trust_profile,
                            normalized_origin=origin,
                            origin_allowed=False,
                            is_secure_transport=is_secure_transport,
                            request_private_network=request_private_network,
                        )
                    )

                if method == "OPTIONS" and origin is not None:
                    resp = Response(status_code=204)
                    self._engine._apply_security_headers(resp.headers, trust_profile=trust_profile, is_secure_transport=is_secure_transport)
                    self._engine._apply_cors_headers(
                        resp.headers,
                        normalized_origin=origin,
                        origin_allowed=True,
                        is_preflight=True,
                        trust_profile=trust_profile,
                        request_private_network=request_private_network,
                    )
                    if request_id:
                        resp.headers.setdefault("X-Request-Id", request_id)
                    return await _asgi_response(resp)

                async def send_wrapper(message):
                    if message.get("type") == "http.response.start":
                        headers_mut = MutableHeaders(scope=message)
                        self._engine._apply_security_headers(headers_mut, trust_profile=trust_profile, is_secure_transport=is_secure_transport)
                        self._engine._apply_cors_headers(
                            headers_mut,
                            normalized_origin=origin,
                            origin_allowed=origin_ok,
                            is_preflight=False,
                            trust_profile=trust_profile,
                            request_private_network=request_private_network,
                        )
                        if request_id and "X-Request-Id" not in headers_mut:
                            headers_mut["X-Request-Id"] = request_id
                    await send(message)

                return await self.app(scope, receive, send_wrapper)
            finally:
                self._engine.release_inflight(client_ip)

        except Exception:
            _logger.exception("Unhandled exception in SecurityASGIMiddleware.__call__")
            self._engine._log_security_event(
                event_type="edge_exception",
                method=method,
                path=path,
                peer_ip=peer_ip,
                client_ip=client_ip,
                xff_reason=xff_reason,
                request_id=request_id,
                origin=origin,
                edge_info=edge_info,
                reason="exception",
                trust_profile=trust_profile,
            )
            return await _asgi_response(
                self._engine._build_error_response(
                    request_id=request_id,
                    status_code=503,
                    error="internal_edge_error",
                    edge_reason="exception",
                    trust_profile=trust_profile,
                    normalized_origin=origin,
                    origin_allowed=origin_ok,
                    is_secure_transport=is_secure_transport,
                    request_private_network=request_private_network,
                )
            )