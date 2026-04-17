from __future__ import annotations

"""
tcd/telemetry_gpu.py

GPU telemetry sampler for TCD.

This module is intentionally content-agnostic. It samples bounded hardware /
runtime telemetry only and is designed to align with stronger contracts already
present in storage.py, signals.py, schemas.py, risk_av.py, service_http.py, and
service_grpc.py.

Core properties
---------------
- Safe in production:
    Never hard-fails just because NVML is missing or partially broken.
- Contract-aware:
    Carries node/build/policy/state evidence fields that can be projected into
    signals / receipts / storage metadata.
- Privacy-aware:
    Device UUIDs can be exposed, hashed, or conditionally exposed by profile.
- Deterministic:
    Canonical JSON digests, explicit reason codes, bounded sanitization.
- Evidence-ready:
    Can emit stable public/audit/storage/receipt projections.
"""

import contextlib
import dataclasses
import hashlib
import hmac
import json
import math
import os
import re
import threading
import time
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Literal

logger = __import__("logging").getLogger(__name__)

try:
    import pynvml  # type: ignore[attr-defined]
    _NVML_AVAILABLE = True
except Exception:  # pragma: no cover
    pynvml = None  # type: ignore[assignment]
    _NVML_AVAILABLE = False

try:  # optional stronger hashing when available
    from .crypto import Blake3Hash  # type: ignore
except Exception:  # pragma: no cover
    Blake3Hash = None  # type: ignore[assignment]

try:  # optional view alignment
    from .schemas import ArtifactRefsView, EvidenceIdentityView  # type: ignore
except Exception:  # pragma: no cover
    ArtifactRefsView = None  # type: ignore[assignment]
    EvidenceIdentityView = None  # type: ignore[assignment]

__all__ = [
    "GpuTelemetryConfig",
    "GpuSamplerPolicy",
    "GpuSample",
    "GpuSamplerHealth",
    "GpuTelemetrySink",
    "GpuAuditSink",
    "BaseGpuSampler",
    "DummyGpuSampler",
    "NvmlGpuSampler",
    "GpuSampler",
    "now_ts",
    "now_unix_ns",
]

# ============================================================================
# Types / constants
# ============================================================================

Profile = Literal["DEV", "PROD", "FINREG", "LOCKDOWN"]
BackendPreference = Literal["auto", "nvml", "dummy"]
UuidExposureMode = Literal["clear", "hash", "clear_if_allowed"]
HealthState = Literal["ok", "degraded", "down", "unknown", "disabled"]
HwIntegrityState = Literal["ok", "mismatch", "unverified", "degraded"]

_SCHEMA = "tcd.telemetry.gpu.v2"
_CANONICALIZATION_VERSION = "canonjson_v1"
_EVENT_VERSION = "gtev2"
_PAYLOAD_VERSION = "gtpd1"
_UUID_HASH_VERSION = "gpuu1"

_ALLOWED_PROFILES = frozenset({"DEV", "PROD", "FINREG", "LOCKDOWN"})
_ALLOWED_TRUST_ZONES = frozenset({"internet", "internal", "partner", "admin", "ops", "unknown"})
_ALLOWED_ROUTE_PROFILES = frozenset({"inference", "batch", "admin", "control", "metrics", "health", "restricted", "unknown"})
_ALLOWED_CONTROLLER_MODES = frozenset(
    {"normal", "last_known_good", "fail_closed", "degraded_identity", "degraded_state_backend", "degraded_calibration"}
)
_ALLOWED_DECISION_MODES = frozenset({"strict_only", "controller_only", "prefer_current_strict", "dual_track"})
_ALLOWED_GUARANTEE_SCOPES = frozenset({"strict_direct_p", "predictable_calibrated_p", "heuristic_only", "none"})
_ALLOWED_HEALTH = frozenset({"ok", "degraded", "down", "unknown", "disabled"})
_ALLOWED_HW_INTEGRITY = frozenset({"ok", "mismatch", "unverified", "degraded"})
_ALLOWED_GPU_REASON_CODES = frozenset(
    {
        "GPU_FORCE_DUMMY",
        "GPU_BACKEND_DOWN",
        "GPU_PARTIAL_METRICS",
        "GPU_UUID_MISMATCH",
        "GPU_NAME_MISMATCH",
        "GPU_VENDOR_MISMATCH",
        "GPU_DRIVER_MISMATCH",
        "GPU_TEMP_ABOVE_THRESHOLD",
        "GPU_ECC_ERRORS_ABOVE_THRESHOLD",
        "GPU_POWER_ABOVE_THRESHOLD",
        "GPU_TOTAL_MEM_BELOW_THRESHOLD",
        "GPU_DEVICE_COUNT_OUT_OF_RANGE",
        "GPU_PQ_REQUIRED_NOT_OK",
        "GPU_UNVERIFIED",
        "GPU_DISABLED",
    }
)

_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")
_SAFE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#/+=]{0,255}$")
_SAFE_GPU_UUID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-/]{7,255}$")
_DIGEST_HEX_RE = re.compile(r"^[0-9a-f]{16,256}$")
_DIGEST_HEX_0X_RE = re.compile(r"^0x[0-9a-f]{16,256}$")
_DIGEST_ALG_HEX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,31}:[0-9a-f]{16,256}$")
_CFG_FP_RE = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256}|[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256})$"
)
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b", re.IGNORECASE)
_BASIC_RE = re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{16,}\b")
_OPENAI_SK_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_AWS_AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GOOGLE_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_KV_SECRET_RE = re.compile(r"(?i)\b(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]{8,})")
_ENTROPY_B64URL_RE = re.compile(r"\b[A-Za-z0-9_-]{60,}\b")

# ============================================================================
# Helpers
# ============================================================================


def now_ts() -> float:
    return float(time.time())


def now_unix_ns() -> int:
    return int(time.time_ns())


def _profile_is_strict(profile: str) -> bool:
    return str(profile).upper() in {"PROD", "FINREG", "LOCKDOWN"}


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


def _looks_like_secret_token(s: str) -> bool:
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
    return False


def _looks_like_high_entropy(s: str) -> bool:
    return bool(s) and (_ENTROPY_B64URL_RE.search(s) is not None)


def _safe_text(v: Any, *, max_len: int = 256, redact_mode: str = "none") -> str:
    s = _strip_unsafe_text(_scalar_text(v), max_len=max_len)
    if not s:
        return ""
    mode = (redact_mode or "none").lower()
    if mode in {"token", "log", "strict"} and _looks_like_secret_token(s):
        return "[redacted]"
    if mode == "strict" and _looks_like_high_entropy(s):
        return "[redacted]"
    return s[:max_len]


def _safe_text_or_none(v: Any, *, max_len: int = 256, redact_mode: str = "none") -> Optional[str]:
    s = _safe_text(v, max_len=max_len, redact_mode=redact_mode)
    return s or None


def _safe_label(v: Any, *, default: str) -> str:
    s = _safe_text(v, max_len=64).lower()
    if not s or not _SAFE_LABEL_RE.fullmatch(s):
        return default
    return s


def _safe_name(v: Any, *, default: str) -> str:
    s = _safe_text(v, max_len=128)
    if not s or not _SAFE_NAME_RE.fullmatch(s):
        return default
    return s


def _safe_id(v: Any, *, default: Optional[str] = None, max_len: int = 256) -> Optional[str]:
    s = _safe_text(v, max_len=max_len)
    if not s or not _SAFE_ID_RE.fullmatch(s):
        return default
    return s


def _safe_gpu_uuid(v: Any, *, default: Optional[str] = None, max_len: int = 256) -> Optional[str]:
    s = _safe_text(v, max_len=max_len, redact_mode="token")
    if not s or s == "[redacted]" or not _SAFE_GPU_UUID_RE.fullmatch(s):
        return default
    return s


def _coerce_float(v: Any) -> Optional[float]:
    if type(v) is bool:
        return None
    if isinstance(v, (int, float)):
        try:
            x = float(v)
        except Exception:
            return None
        return x if math.isfinite(x) else None
    if isinstance(v, str):
        s = v.strip()
        if not s or len(s) > 128:
            return None
        try:
            x = float(s)
        except Exception:
            return None
        return x if math.isfinite(x) else None
    return None


def _coerce_int(v: Any) -> Optional[int]:
    if type(v) is int:
        return int(v)
    if isinstance(v, str):
        s = v.strip()
        if not s or len(s) > 128:
            return None
        if s.startswith(("+", "-")):
            sign, digits = s[0], s[1:]
        else:
            sign, digits = "", s
        if not digits.isdigit():
            return None
        try:
            return int(sign + digits, 10)
        except Exception:
            return None
    return None


def _coerce_bool(v: Any) -> Optional[bool]:
    if type(v) is bool:
        return v
    if type(v) is int:
        if v == 0:
            return False
        if v == 1:
            return True
        return None
    if isinstance(v, str):
        s = v.strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "no", "n", "off"}:
            return False
    return None


def _clamp_float(v: Any, *, default: float, lo: float, hi: float) -> float:
    x = _coerce_float(v)
    if x is None:
        return float(default)
    if x < lo:
        return float(lo)
    if x > hi:
        return float(hi)
    return float(x)


def _clamp_int(v: Any, *, default: int, lo: int, hi: int) -> int:
    x = _coerce_int(v)
    if x is None:
        return int(default)
    if x < lo:
        return int(lo)
    if x > hi:
        return int(hi)
    return int(x)


def _stable_float(x: float) -> str:
    if not math.isfinite(float(x)):
        return "0"
    s = f"{float(x):.12f}".rstrip("0").rstrip(".")
    return s or "0"


def _stable_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int)):
        return obj
    if isinstance(obj, float):
        return _stable_float(obj)
    if isinstance(obj, str):
        return obj
    if isinstance(obj, Mapping):
        return {str(k): _stable_jsonable(obj[k]) for k in sorted(obj.keys(), key=lambda x: str(x))}
    if isinstance(obj, (list, tuple)):
        return [_stable_jsonable(x) for x in obj]
    if isinstance(obj, (set, frozenset)):
        xs = [_stable_jsonable(x) for x in obj]
        try:
            return sorted(xs)
        except Exception:
            return xs
    return _safe_name(type(obj).__name__, default="object")


def _canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        _stable_jsonable(obj),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def _canonical_json_str(obj: Any) -> str:
    return _canonical_json_bytes(obj).decode("utf-8", errors="strict")


def _hash_hex(*, ctx: str, payload: Mapping[str, Any], out_hex: int = 32) -> str:
    raw = ctx.encode("utf-8", errors="strict") + b"\x00" + _canonical_json_bytes(payload)
    if Blake3Hash is not None:
        with contextlib.suppress(Exception):
            return Blake3Hash().hex(raw, ctx=ctx)[:out_hex]
    return hashlib.sha256(raw).hexdigest()[:out_hex]


def _hash_bytes(*, ctx: str, payload: bytes, out_hex: int = 32) -> str:
    raw = ctx.encode("utf-8", errors="strict") + b"\x00" + payload
    if Blake3Hash is not None:
        with contextlib.suppress(Exception):
            return Blake3Hash().hex(raw, ctx=ctx)[:out_hex]
    return hashlib.sha256(raw).hexdigest()[:out_hex]


def _parse_key_material(v: Any) -> Optional[bytes]:
    if isinstance(v, bytes):
        return bytes(v) if 1 <= len(v) <= 4096 else None
    if not isinstance(v, str):
        return None
    s = _safe_text(v, max_len=4096)
    if not s:
        return None
    if s.lower().startswith("hex:"):
        hx = s[4:].strip()
        if len(hx) % 2 != 0 or not _HEX_RE.fullmatch(hx):
            return None
        with contextlib.suppress(Exception):
            return bytes.fromhex(hx)
        return None
    if s.lower().startswith("b64:"):
        raw = s[4:].strip()
        try:
            pad = "=" * ((4 - (len(raw) % 4)) % 4)
            return __import__("base64").urlsafe_b64decode((raw + pad).encode("utf-8", errors="strict"))
        except Exception:
            return None
    if s.lower().startswith("raw:"):
        return s[4:].encode("utf-8", errors="ignore")
    if _HEX_RE.fullmatch(s) and len(s) % 2 == 0:
        with contextlib.suppress(Exception):
            return bytes.fromhex(s)
    return None


def _normalize_digest_token(v: Any, *, kind: str = "any", default: Optional[str] = None) -> Optional[str]:
    s = _safe_text(v, max_len=1024, redact_mode="token")
    if not s or s == "[redacted]":
        return default
    if kind == "cfg_fp":
        return s if _CFG_FP_RE.fullmatch(s) else default
    if _DIGEST_HEX_RE.fullmatch(s):
        return s.lower()
    if _DIGEST_HEX_0X_RE.fullmatch(s):
        return s.lower()
    if _DIGEST_ALG_HEX_RE.fullmatch(s):
        algo, _, rest = s.partition(":")
        return f"{algo}:{rest.lower()}"
    return default


def _normalize_reason_codes(values: Any, *, max_items: int = 32) -> Tuple[str, ...]:
    if values is None:
        return tuple()
    if isinstance(values, str):
        seq: Sequence[Any] = [values]
    elif isinstance(values, (list, tuple, set, frozenset)):
        seq = list(values)
    else:
        return tuple()
    out: List[str] = []
    seen = set()
    for item in seq:
        if len(out) >= max_items:
            break
        s = _safe_text(item, max_len=64).upper()
        if not s or s not in _ALLOWED_GPU_REASON_CODES or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return tuple(out)


def _normalize_str_tuple(values: Any, *, max_len: int = 128, max_items: int = 32, lower: bool = False) -> Tuple[str, ...]:
    if values is None:
        return tuple()
    if isinstance(values, str):
        seq: Sequence[Any] = [values]
    elif isinstance(values, (list, tuple, set, frozenset)):
        seq = list(values)
    else:
        return tuple()
    out: List[str] = []
    seen = set()
    for item in seq:
        if len(out) >= max_items:
            break
        s = _safe_text(item, max_len=max_len)
        if lower:
            s = s.lower()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return tuple(out)


class _JsonBudget:
    __slots__ = ("max_nodes", "max_items", "max_depth", "max_str_total", "nodes", "str_used")
    def __init__(self, *, max_nodes: int, max_items: int, max_depth: int, max_str_total: int) -> None:
        self.max_nodes = max_nodes
        self.max_items = max_items
        self.max_depth = max_depth
        self.max_str_total = max_str_total
        self.nodes = 0
        self.str_used = 0
    def take_node(self) -> bool:
        self.nodes += 1
        return self.nodes <= self.max_nodes
    def take_str(self, n: int) -> bool:
        self.str_used += n
        return self.str_used <= self.max_str_total


def _key_tokens(k: str) -> Tuple[str, ...]:
    s = _strip_unsafe_text(k, max_len=128)
    if not s:
        return tuple()
    s = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)
    s = re.sub(r"(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])", " ", s)
    s = re.sub(r"[^A-Za-z0-9]+", " ", s).strip().lower()
    if not s:
        return tuple()
    parts = tuple(p for p in s.split(" ") if p)
    fused = "".join(parts)
    return parts + ((fused,) if fused and fused not in parts else tuple())


def _json_sanitize(obj: Any, *, budget: _JsonBudget, depth: int, max_str_len: int) -> Any:
    if not budget.take_node():
        return "[truncated]"
    t = type(obj)
    if obj is None:
        return None
    if t is bool:
        return bool(obj)
    if t is int:
        if obj.bit_length() > 256:
            return "[int:oversize]"
        return int(obj)
    if t is float:
        return float(obj) if math.isfinite(obj) else None
    if t is str:
        s = _safe_text(obj, max_len=max_str_len, redact_mode="strict")
        if not budget.take_str(len(s)):
            return "[truncated]"
        return s
    if t in (bytes, bytearray, memoryview):
        return f"[bytes:{len(obj)}]"
    if depth >= budget.max_depth:
        return "[truncated-depth]"
    if isinstance(obj, Mapping):
        out: Dict[str, Any] = {}
        n = 0
        for k, v in obj.items():
            if n >= budget.max_items:
                out["_truncated"] = True
                break
            if type(k) is not str:
                continue
            kk = _safe_id(k, default=None, max_len=64)
            if kk is None:
                continue
            toks = _key_tokens(kk)
            if any(tok in {"prompt", "completion", "content", "body", "request", "response", "secret", "token", "password", "auth"} for tok in toks):
                continue
            out[kk] = _json_sanitize(v, budget=budget, depth=depth + 1, max_str_len=max_str_len)
            n += 1
        return out
    if t in (list, tuple):
        out_list: List[Any] = []
        for i, item in enumerate(obj):
            if i >= budget.max_items:
                out_list.append("[truncated]")
                break
            out_list.append(_json_sanitize(item, budget=budget, depth=depth + 1, max_str_len=max_str_len))
        return out_list
    if t in (set, frozenset):
        xs = [_json_sanitize(x, budget=budget, depth=depth + 1, max_str_len=max_str_len) for x in list(obj)[:budget.max_items]]
        try:
            return sorted(xs, key=lambda x: _canonical_json_str(x))
        except Exception:
            return xs
    return f"[type:{t.__name__}]"


def _safe_json_mapping(v: Any, *, max_items: int, max_str_len: int) -> Dict[str, Any]:
    if not isinstance(v, Mapping):
        return {}
    budget = _JsonBudget(max_nodes=4096, max_items=max_items, max_depth=8, max_str_total=128_000)
    out = _json_sanitize(dict(v), budget=budget, depth=0, max_str_len=max_str_len)
    return out if isinstance(out, dict) else {}


# ============================================================================
# Sinks
# ============================================================================

class GpuTelemetrySink(Protocol):
    def record_metric(self, name: str, value: float, labels: Mapping[str, str]) -> None:
        ...
    def record_event(self, name: str, payload: Mapping[str, Any]) -> None:
        ...


class GpuAuditSink(Protocol):
    def emit(self, event_type: str, payload: Mapping[str, Any]) -> Optional[str]:
        ...


# ============================================================================
# Config / policy / sample models
# ============================================================================

@dataclass(frozen=True, slots=True)
class GpuTelemetryConfig:
    profile: Profile = "PROD"
    enable: bool = True
    backend_preference: BackendPreference = "auto"

    expose_uuid_mode: UuidExposureMode = "clear_if_allowed"
    allow_clear_uuid_profiles: Tuple[str, ...] = ("DEV",)
    uuid_hash_key: Optional[Any] = None
    uuid_hash_key_id: Optional[str] = None
    min_uuid_hash_key_bytes: int = 16
    uuid_hash_hex_chars: int = 24

    max_extra_items: int = 64
    max_extra_key_len: int = 64
    max_extra_str_len: int = 256
    max_batch_devices: int = 32

    enforce_expected_uuid_in_strict: bool = True
    enforce_expected_vendor_in_strict: bool = True
    driver_version_must_match_policy: bool = False

    body_schema: str = "tcd.gpu.sample.v2"
    event_id_namespace: str = "tcd.gpu"

    def __post_init__(self) -> None:
        prof = _safe_text(self.profile, max_len=32).upper() or "PROD"
        object.__setattr__(self, "profile", prof if prof in _ALLOWED_PROFILES else "PROD")
        pref = _safe_label(self.backend_preference, default="auto")
        if pref not in {"auto", "nvml", "dummy"}:
            pref = "auto"
        object.__setattr__(self, "backend_preference", pref)
        object.__setattr__(self, "enable", bool(self.enable))
        mode = _safe_label(self.expose_uuid_mode, default="clear_if_allowed")
        if mode not in {"clear", "hash", "clear_if_allowed"}:
            mode = "clear_if_allowed"
        object.__setattr__(self, "expose_uuid_mode", mode)
        allow_profiles = _normalize_str_tuple(self.allow_clear_uuid_profiles, max_len=16, max_items=8, lower=False)
        fixed_profiles: List[str] = []
        for p in allow_profiles:
            up = p.upper()
            if up in _ALLOWED_PROFILES and up not in fixed_profiles:
                fixed_profiles.append(up)
        object.__setattr__(self, "allow_clear_uuid_profiles", tuple(fixed_profiles) or ("DEV",))
        key = self.uuid_hash_key
        if isinstance(key, str):
            key = _parse_key_material(key)
        if key is not None and len(key) < max(8, int(self.min_uuid_hash_key_bytes)):
            key = None
        object.__setattr__(self, "uuid_hash_key", key)
        object.__setattr__(self, "uuid_hash_key_id", _safe_text_or_none(self.uuid_hash_key_id, max_len=16))
        object.__setattr__(self, "min_uuid_hash_key_bytes", max(8, min(4096, int(self.min_uuid_hash_key_bytes))))
        object.__setattr__(self, "uuid_hash_hex_chars", max(8, min(64, int(self.uuid_hash_hex_chars))))
        object.__setattr__(self, "max_extra_items", max(1, min(256, int(self.max_extra_items))))
        object.__setattr__(self, "max_extra_key_len", max(8, min(128, int(self.max_extra_key_len))))
        object.__setattr__(self, "max_extra_str_len", max(32, min(4096, int(self.max_extra_str_len))))
        object.__setattr__(self, "max_batch_devices", max(1, min(128, int(self.max_batch_devices))))
        object.__setattr__(self, "enforce_expected_uuid_in_strict", bool(self.enforce_expected_uuid_in_strict))
        object.__setattr__(self, "enforce_expected_vendor_in_strict", bool(self.enforce_expected_vendor_in_strict))
        object.__setattr__(self, "driver_version_must_match_policy", bool(self.driver_version_must_match_policy))
        object.__setattr__(self, "body_schema", _safe_text(self.body_schema, max_len=128) or "tcd.gpu.sample.v2")
        object.__setattr__(self, "event_id_namespace", _safe_text(self.event_id_namespace, max_len=64) or "tcd.gpu")


@dataclass(frozen=True, slots=True)
class GpuSamplerPolicy:
    node_id: str = ""
    build_id: str = ""
    image_digest: str = ""
    driver_version: str = ""
    runtime_env: str = ""

    trust_zone: str = "internet"
    route_profile: str = "inference"
    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    policy_digest: Optional[str] = None
    cfg_fp: Optional[str] = None

    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None
    selected_source: Optional[str] = "gpu_sampler"
    controller_mode: Optional[str] = None
    decision_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None
    activation_id: Optional[str] = None
    patch_id: Optional[str] = None

    expected_vendor: str = "nvidia"
    expected_uuids: Optional[Any] = None
    expected_name_prefixes: Optional[Any] = None
    min_device_count: Optional[int] = None
    max_device_count: Optional[int] = None

    max_temp_c: float = 90.0
    max_ecc_errors: int = 0
    max_power_w: Optional[float] = None
    min_total_mem_mb: Optional[float] = None

    pq_required: bool = False
    pq_ok: Optional[bool] = None
    pq_chain_id: str = ""
    pq_signature_required: Optional[bool] = None
    pq_signature_ok: Optional[bool] = None

    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None
    produced_by: Tuple[str, ...] = ("tcd.telemetry_gpu",)

    def normalized(self, *, cfg: Optional[GpuTelemetryConfig] = None) -> "GpuSamplerPolicy":
        cfg = cfg or GpuTelemetryConfig()
        expected_uuids: List[str] = []
        ev = self.expected_uuids
        if isinstance(ev, str):
            seq = [ev]
        elif isinstance(ev, (list, tuple, set, frozenset)):
            seq = list(ev)
        else:
            seq = []
        for item in seq:
            su = _safe_gpu_uuid(item, default=None, max_len=256)
            if not su:
                continue
            low = su.lower()
            if low not in expected_uuids:
                expected_uuids.append(low)

        expected_name_prefixes = []
        nv = self.expected_name_prefixes
        if isinstance(nv, str):
            nseq = [nv]
        elif isinstance(nv, (list, tuple, set, frozenset)):
            nseq = list(nv)
        else:
            nseq = []
        for item in nseq:
            s = _safe_text(item, max_len=128)
            if s and s not in expected_name_prefixes:
                expected_name_prefixes.append(s)

        cm = _safe_label(self.controller_mode, default="") or None if self.controller_mode is not None else None
        dm = _safe_label(self.decision_mode, default="") or None if self.decision_mode is not None else None
        gs = _safe_text_or_none(self.statistical_guarantee_scope, max_len=64)
        if cm is not None and cm not in _ALLOWED_CONTROLLER_MODES:
            cm = None
        if dm is not None and dm not in _ALLOWED_DECISION_MODES:
            dm = None
        if gs is not None and gs not in _ALLOWED_GUARANTEE_SCOPES:
            gs = None

        return GpuSamplerPolicy(
            node_id=_safe_id(self.node_id, default=None, max_len=128) or "",
            build_id=_safe_id(self.build_id, default=None, max_len=256) or "",
            image_digest=_safe_text(self.image_digest, max_len=256),
            driver_version=_safe_text(self.driver_version, max_len=128),
            runtime_env=_safe_label(self.runtime_env, default="") if self.runtime_env else "",
            trust_zone=_safe_label(self.trust_zone, default="internet"),
            route_profile=_safe_label(self.route_profile, default="inference"),
            policy_ref=_safe_id(self.policy_ref, default=None, max_len=128),
            policyset_ref=_safe_id(self.policyset_ref, default=None, max_len=128),
            policy_digest=_normalize_digest_token(self.policy_digest, kind="any", default=None),
            cfg_fp=_normalize_digest_token(self.cfg_fp, kind="cfg_fp", default=None),
            state_domain_id=_safe_id(self.state_domain_id, default=None, max_len=256),
            adapter_registry_fp=_safe_id(self.adapter_registry_fp, default=None, max_len=256),
            selected_source=_safe_label(self.selected_source, default="") or None if self.selected_source is not None else None,
            controller_mode=cm,
            decision_mode=dm,
            statistical_guarantee_scope=gs,
            activation_id=_safe_id(self.activation_id, default=None, max_len=256),
            patch_id=_safe_id(self.patch_id, default=None, max_len=256),
            expected_vendor=_safe_label(self.expected_vendor, default="nvidia"),
            expected_uuids=tuple(expected_uuids) if expected_uuids else None,
            expected_name_prefixes=tuple(expected_name_prefixes) if expected_name_prefixes else None,
            min_device_count=max(0, _coerce_int(self.min_device_count)) if _coerce_int(self.min_device_count) is not None else None,
            max_device_count=max(0, _coerce_int(self.max_device_count)) if _coerce_int(self.max_device_count) is not None else None,
            max_temp_c=max(0.0, _coerce_float(self.max_temp_c) or 90.0),
            max_ecc_errors=max(0, _coerce_int(self.max_ecc_errors) or 0),
            max_power_w=max(0.0, _coerce_float(self.max_power_w)) if _coerce_float(self.max_power_w) is not None else None,
            min_total_mem_mb=max(0.0, _coerce_float(self.min_total_mem_mb)) if _coerce_float(self.min_total_mem_mb) is not None else None,
            pq_required=bool(self.pq_required),
            pq_ok=_coerce_bool(self.pq_ok),
            pq_chain_id=_safe_text(self.pq_chain_id, max_len=128),
            pq_signature_required=_coerce_bool(self.pq_signature_required),
            pq_signature_ok=_coerce_bool(self.pq_signature_ok),
            audit_ref=_safe_id(self.audit_ref, default=None, max_len=256),
            receipt_ref=_safe_id(self.receipt_ref, default=None, max_len=256),
            produced_by=_normalize_str_tuple(self.produced_by, max_len=64, max_items=16),
        )


@dataclass(frozen=True, slots=True)
class GpuSample:
    schema: str
    schema_version: int
    canonicalization_version: str

    event_id: str
    event_type: str
    sample_fingerprint: str
    event_digest: str
    payload_digest: str

    index: int
    uuid: str
    uuid_hash: Optional[str]
    uuid_exposed: bool
    name: str

    ts: float
    ts_unix_ns: int
    ts_monotonic_ns: int

    util_pct: float
    mem_used_mb: float
    mem_total_mb: float
    mem_free_mb: float
    temp_c: float
    power_w: float
    power_limit_w: float
    fan_pct: float
    compute_mode: str
    ecc_errors_total: int

    backend: str
    health_state: str
    extra: Mapping[str, Any] = field(default_factory=dict)

    node_id: str = ""
    build_id: str = ""
    image_digest: str = ""
    driver_version: str = ""
    runtime_env: str = ""

    trust_zone: str = "internet"
    route_profile: str = "inference"
    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    policy_digest: Optional[str] = None
    cfg_fp: Optional[str] = None

    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None
    selected_source: Optional[str] = None
    controller_mode: Optional[str] = None
    decision_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None
    activation_id: Optional[str] = None
    patch_id: Optional[str] = None

    hw_integrity_state: str = "unverified"
    integrity_ok: bool = False
    integrity_reason_codes: Tuple[str, ...] = ()
    degraded_reason_codes: Tuple[str, ...] = ()
    normalization_warnings: Tuple[str, ...] = ()

    apt_suspect: bool = False
    apt_reason: str = ""

    insider_override: bool = False
    override_reason: str = ""

    pq_required: bool = False
    pq_ok: Optional[bool] = None
    pq_chain_id: str = ""
    pq_signature_required: Optional[bool] = None
    pq_signature_ok: Optional[bool] = None

    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None
    produced_by: Tuple[str, ...] = field(default_factory=tuple)
    provenance_path_digest: Optional[str] = None

    def to_dict(self, *, flatten_extra: bool = True, include_internal: bool = False) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "canonicalization_version": self.canonicalization_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "sample_fingerprint": self.sample_fingerprint,
            "event_digest": self.event_digest,
            "payload_digest": self.payload_digest,
            "index": self.index,
            "uuid": self.uuid,
            "uuid_hash": self.uuid_hash,
            "uuid_exposed": self.uuid_exposed,
            "name": self.name,
            "ts": self.ts,
            "ts_unix_ns": self.ts_unix_ns,
            "ts_monotonic_ns": self.ts_monotonic_ns,
            "util_pct": self.util_pct,
            "mem_used_mb": self.mem_used_mb,
            "mem_total_mb": self.mem_total_mb,
            "mem_free_mb": self.mem_free_mb,
            "temp_c": self.temp_c,
            "power_w": self.power_w,
            "power_limit_w": self.power_limit_w,
            "fan_pct": self.fan_pct,
            "compute_mode": self.compute_mode,
            "ecc_errors_total": self.ecc_errors_total,
            "backend": self.backend,
            "health_state": self.health_state,
            "node_id": self.node_id,
            "build_id": self.build_id,
            "image_digest": self.image_digest,
            "driver_version": self.driver_version,
            "runtime_env": self.runtime_env,
            "trust_zone": self.trust_zone,
            "route_profile": self.route_profile,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "cfg_fp": self.cfg_fp,
            "state_domain_id": self.state_domain_id,
            "adapter_registry_fp": self.adapter_registry_fp,
            "selected_source": self.selected_source,
            "controller_mode": self.controller_mode,
            "decision_mode": self.decision_mode,
            "statistical_guarantee_scope": self.statistical_guarantee_scope,
            "activation_id": self.activation_id,
            "patch_id": self.patch_id,
            "hw_integrity_state": self.hw_integrity_state,
            "integrity_ok": self.integrity_ok,
            "integrity_reason_codes": list(self.integrity_reason_codes),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "normalization_warnings": list(self.normalization_warnings),
            "apt_suspect": self.apt_suspect,
            "apt_reason": self.apt_reason,
            "insider_override": self.insider_override,
            "override_reason": self.override_reason,
            "pq_required": self.pq_required,
            "pq_ok": self.pq_ok,
            "pq_chain_id": self.pq_chain_id,
            "pq_signature_required": self.pq_signature_required,
            "pq_signature_ok": self.pq_signature_ok,
            "audit_ref": self.audit_ref,
            "receipt_ref": self.receipt_ref,
            "produced_by": list(self.produced_by),
            "provenance_path_digest": self.provenance_path_digest,
            "extra": dict(self.extra),
        }
        # compatibility aliases for existing HTTP / multivariate callers
        out["gpu_util"] = self.util_pct
        out["gpu_util_pct"] = self.util_pct
        out["gpu_mem_used_mib"] = self.mem_used_mb
        out["gpu_mem_total_mib"] = self.mem_total_mb
        out["gpu_mem_free_mib"] = self.mem_free_mb
        out["gpu_temp_c"] = self.temp_c
        out["gpu_power_w"] = self.power_w
        out["gpu_health_level"] = self.health_state

        if flatten_extra:
            for k, v in self.extra.items():
                if k not in out:
                    out[k] = v
        if not include_internal:
            out.pop("policy_digest", None)
            out.pop("cfg_fp", None)
        return out

    def to_public_dict(self) -> Dict[str, Any]:
        out = self.to_dict(flatten_extra=True, include_internal=False)
        return out

    def to_audit_dict(self) -> Dict[str, Any]:
        return self.to_dict(flatten_extra=False, include_internal=True)

    def to_storage_meta(self) -> Dict[str, Any]:
        return {
            "gpu_index": self.index,
            "gpu_uuid_hash": self.uuid_hash,
            "gpu_name": self.name,
            "gpu_backend": self.backend,
            "gpu_health_state": self.health_state,
            "gpu_hw_integrity_state": self.hw_integrity_state,
            "gpu_util_pct": self.util_pct,
            "gpu_mem_used_mb": self.mem_used_mb,
            "gpu_mem_total_mb": self.mem_total_mb,
            "gpu_temp_c": self.temp_c,
            "gpu_power_w": self.power_w,
            "gpu_power_limit_w": self.power_limit_w,
            "gpu_fan_pct": self.fan_pct,
            "gpu_compute_mode": self.compute_mode,
            "gpu_ecc_errors_total": self.ecc_errors_total,
            "gpu_apt_suspect": self.apt_suspect,
            "gpu_apt_reason": self.apt_reason,
            "backend_extra": dict(self.extra),
        }

    def to_evidence_identity_dict(self) -> Dict[str, Any]:
        payload = {
            "event_id": self.event_id,
            "event_id_kind": "event",
            "decision_id": None,
            "decision_id_kind": "decision",
            "route_plan_id": None,
            "route_id": None,
            "route_id_kind": "plan",
            "config_fingerprint": self.cfg_fp,
            "bundle_version": None,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "state_domain_id": self.state_domain_id,
            "activation_id": self.activation_id,
            "patch_id": self.patch_id,
            "change_ticket_id": None,
            "controller_mode": self.controller_mode,
            "statistical_guarantee_scope": self.statistical_guarantee_scope,
            "adapter_registry_fp": self.adapter_registry_fp,
            "selected_source": self.selected_source,
            "state_revision": None,
            "identity_status": self.health_state,
            "audit_ref": self.audit_ref,
            "receipt_ref": self.receipt_ref,
        }
        if EvidenceIdentityView is not None:
            with contextlib.suppress(Exception):
                obj = EvidenceIdentityView(**payload)
                if hasattr(obj, "model_dump"):
                    return dict(obj.model_dump())
        return payload

    def to_artifact_refs_dict(self) -> Dict[str, Any]:
        payload = {
            "audit_ref": self.audit_ref,
            "receipt_ref": self.receipt_ref,
            "ledger_ref": None,
            "attestation_ref": None,
            "event_digest": self.event_digest,
            "body_digest": self.payload_digest,
            "payload_digest": self.payload_digest,
            "prepare_ref": None,
            "commit_ref": None,
            "ledger_stage": None,
            "outbox_ref": None,
            "outbox_status": None,
            "outbox_dedupe_key": None,
            "delivery_attempts": None,
            "chain_id": None,
            "chain_head": None,
            "produced_by": list(self.produced_by),
            "provenance_path_digest": self.provenance_path_digest,
        }
        if ArtifactRefsView is not None:
            with contextlib.suppress(Exception):
                obj = ArtifactRefsView(**payload)
                if hasattr(obj, "model_dump"):
                    return dict(obj.model_dump())
        return payload

    def to_receipt_body(self, *, chain_namespace: str = "telemetry", chain_id: Optional[str] = None, prev_head_hex: Optional[str] = None) -> Dict[str, Any]:
        cid = _safe_id(chain_id, default=None, max_len=128) or (_safe_id(self.node_id, default=None, max_len=128) or "gpu")
        body = {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "canonicalization_version": self.canonicalization_version,
            "receipt_kind": "telemetry",
            "event_type": self.event_type,
            "event_id": self.event_id,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "cfg_fp": self.cfg_fp,
            "state_domain_id": self.state_domain_id,
            "adapter_registry_fp": self.adapter_registry_fp,
            "audit_ref": self.audit_ref,
            "receipt_ref": self.receipt_ref,
            "chain_namespace": _safe_id(chain_namespace, default="telemetry", max_len=128) or "telemetry",
            "chain_id": cid,
            "prev_head_hex": prev_head_hex,
            "selected_source": self.selected_source or "gpu_sampler",
            "statistical_guarantee_scope": self.statistical_guarantee_scope,
            "build_id": self.build_id or None,
            "image_digest": self.image_digest or None,
            "pq_required": self.pq_required,
            "pq_ok": self.pq_ok,
            "pq_signature_required": self.pq_signature_required,
            "pq_signature_ok": self.pq_signature_ok,
            "ts": self.ts,
            "ts_ns": self.ts_unix_ns,
            "ts_unix_ns": self.ts_unix_ns,
            "trigger": self.apt_suspect,
            "allowed": not self.apt_suspect,
            "reason": self.apt_reason or self.health_state,
            "produced_by": list(self.produced_by),
            "provenance_path_digest": self.provenance_path_digest,
            "payload_digest": self.payload_digest,
            "event_digest": self.event_digest,
            "meta": self.to_storage_meta(),
        }
        return body

    def to_receipt_body_json(self, *, chain_namespace: str = "telemetry", chain_id: Optional[str] = None, prev_head_hex: Optional[str] = None) -> str:
        return _canonical_json_str(self.to_receipt_body(chain_namespace=chain_namespace, chain_id=chain_id, prev_head_hex=prev_head_hex))


@dataclass(frozen=True, slots=True)
class GpuSamplerHealth:
    backend: str
    available: bool
    device_count: int
    driver_version: Optional[str]
    health_state: str
    warnings: Tuple[str, ...]
    cfg_fp: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ============================================================================
# Base samplers
# ============================================================================

class BaseGpuSampler(ABC):
    def __init__(self, *, policy: Optional[GpuSamplerPolicy] = None, config: Optional[GpuTelemetryConfig] = None) -> None:
        self._cfg = (config or GpuTelemetryConfig())
        self._policy = (policy or GpuSamplerPolicy()).normalized(cfg=self._cfg)

    @abstractmethod
    def sample(self) -> GpuSample:
        ...

    def sample_all(self) -> List[GpuSample]:
        return [self.sample()]

    def health(self) -> GpuSamplerHealth:
        return GpuSamplerHealth(
            backend="unknown",
            available=False,
            device_count=0,
            driver_version=self._policy.driver_version or None,
            health_state="unknown",
            warnings=tuple(),
            cfg_fp=self._policy.cfg_fp,
        )


class DummyGpuSampler(BaseGpuSampler):
    def __init__(
        self,
        index: int = 0,
        health_state: str = "unknown",
        *,
        policy: Optional[GpuSamplerPolicy] = None,
        config: Optional[GpuTelemetryConfig] = None,
        insider_override: bool = False,
        override_reason: str = "",
        backend_label: str = "dummy",
        reason_codes: Sequence[str] = (),
    ) -> None:
        super().__init__(policy=policy, config=config)
        self._index = int(index)
        self._health_state = health_state if health_state in _ALLOWED_HEALTH else "unknown"
        self._insider_override = bool(insider_override)
        self._override_reason = _safe_text(override_reason, max_len=128)
        self._backend_label = _safe_label(backend_label, default="dummy")
        self._reason_codes = _normalize_reason_codes(reason_codes)

    def _build_sample(self) -> GpuSample:
        ts = now_ts()
        ts_ns = now_unix_ns()
        mono_ns = time.monotonic_ns()
        p = self._policy

        event_core = {
            "index": self._index,
            "backend": self._backend_label,
            "health_state": self._health_state,
            "node_id": p.node_id,
            "build_id": p.build_id,
            "image_digest": p.image_digest,
            "cfg_fp": p.cfg_fp,
            "ts_unix_ns": ts_ns,
            "state_domain_id": p.state_domain_id,
        }
        event_id = f"{_EVENT_VERSION}:{_hash_hex(ctx='tcd:gpu:event', payload=event_core, out_hex=32)}"
        payload_obj = {
            "event_id": event_id,
            "index": self._index,
            "uuid": "",
            "uuid_hash": None,
            "uuid_exposed": False,
            "name": "",
            "ts": ts,
            "ts_unix_ns": ts_ns,
            "ts_monotonic_ns": mono_ns,
            "util_pct": 0.0,
            "mem_used_mb": 0.0,
            "mem_total_mb": 0.0,
            "mem_free_mb": 0.0,
            "temp_c": 0.0,
            "power_w": 0.0,
            "power_limit_w": 0.0,
            "fan_pct": 0.0,
            "compute_mode": "",
            "ecc_errors_total": 0,
            "backend": self._backend_label,
            "health_state": self._health_state,
            "node_id": p.node_id,
            "build_id": p.build_id,
            "image_digest": p.image_digest,
            "driver_version": p.driver_version,
            "runtime_env": p.runtime_env,
            "trust_zone": p.trust_zone,
            "route_profile": p.route_profile,
            "policy_ref": p.policy_ref,
            "policyset_ref": p.policyset_ref,
            "policy_digest": p.policy_digest,
            "cfg_fp": p.cfg_fp,
            "state_domain_id": p.state_domain_id,
            "adapter_registry_fp": p.adapter_registry_fp,
            "selected_source": p.selected_source,
            "controller_mode": p.controller_mode,
            "decision_mode": p.decision_mode,
            "statistical_guarantee_scope": p.statistical_guarantee_scope,
            "activation_id": p.activation_id,
            "patch_id": p.patch_id,
            "hw_integrity_state": "unverified",
            "integrity_ok": False,
            "integrity_reason_codes": list(self._reason_codes or ("GPU_UNVERIFIED",)),
            "degraded_reason_codes": list(self._reason_codes),
            "apt_suspect": False,
            "apt_reason": "",
            "insider_override": self._insider_override,
            "override_reason": self._override_reason,
            "pq_required": p.pq_required,
            "pq_ok": p.pq_ok,
            "pq_chain_id": p.pq_chain_id,
            "pq_signature_required": p.pq_signature_required,
            "pq_signature_ok": p.pq_signature_ok,
            "audit_ref": p.audit_ref,
            "receipt_ref": p.receipt_ref,
            "produced_by": list(p.produced_by or ("tcd.telemetry_gpu",)),
        }
        payload_digest = f"{_PAYLOAD_VERSION}:sha256:{hashlib.sha256(_canonical_json_bytes(payload_obj)).hexdigest()}"
        sample_fp = f"gpu1:{_hash_hex(ctx='tcd:gpu:sample', payload=payload_obj, out_hex=32)}"
        event_digest = f"gpued1:sha256:{_hash_hex(ctx='tcd:gpu:event_digest', payload=payload_obj, out_hex=32)}"
        produced_by = tuple(p.produced_by or ("tcd.telemetry_gpu",))
        prov = f"sha256:{_hash_hex(ctx='tcd:gpu:produced_by', payload={'produced_by': list(produced_by)}, out_hex=64)}"
        return GpuSample(
            schema=_SCHEMA,
            schema_version=2,
            canonicalization_version=_CANONICALIZATION_VERSION,
            event_id=event_id,
            event_type="gpu_telemetry",
            sample_fingerprint=sample_fp,
            event_digest=event_digest,
            payload_digest=payload_digest,
            index=self._index,
            uuid="",
            uuid_hash=None,
            uuid_exposed=False,
            name="",
            ts=ts,
            ts_unix_ns=ts_ns,
            ts_monotonic_ns=mono_ns,
            util_pct=0.0,
            mem_used_mb=0.0,
            mem_total_mb=0.0,
            mem_free_mb=0.0,
            temp_c=0.0,
            power_w=0.0,
            power_limit_w=0.0,
            fan_pct=0.0,
            compute_mode="",
            ecc_errors_total=0,
            backend=self._backend_label,
            health_state=self._health_state,
            extra=MappingProxyType({}),
            node_id=p.node_id,
            build_id=p.build_id,
            image_digest=p.image_digest,
            driver_version=p.driver_version,
            runtime_env=p.runtime_env,
            trust_zone=p.trust_zone,
            route_profile=p.route_profile,
            policy_ref=p.policy_ref,
            policyset_ref=p.policyset_ref,
            policy_digest=p.policy_digest,
            cfg_fp=p.cfg_fp,
            state_domain_id=p.state_domain_id,
            adapter_registry_fp=p.adapter_registry_fp,
            selected_source=p.selected_source,
            controller_mode=p.controller_mode,
            decision_mode=p.decision_mode,
            statistical_guarantee_scope=p.statistical_guarantee_scope,
            activation_id=p.activation_id,
            patch_id=p.patch_id,
            hw_integrity_state="unverified",
            integrity_ok=False,
            integrity_reason_codes=self._reason_codes or ("GPU_UNVERIFIED",),
            degraded_reason_codes=self._reason_codes,
            normalization_warnings=tuple(),
            apt_suspect=False,
            apt_reason="",
            insider_override=self._insider_override,
            override_reason=self._override_reason,
            pq_required=p.pq_required,
            pq_ok=p.pq_ok,
            pq_chain_id=p.pq_chain_id,
            pq_signature_required=p.pq_signature_required,
            pq_signature_ok=p.pq_signature_ok,
            audit_ref=p.audit_ref,
            receipt_ref=p.receipt_ref,
            produced_by=produced_by,
            provenance_path_digest=prov,
        )

    def sample(self) -> GpuSample:
        return self._build_sample()

    def sample_all(self) -> List[GpuSample]:
        return [self._build_sample()]

    def health(self) -> GpuSamplerHealth:
        return GpuSamplerHealth(
            backend=self._backend_label,
            available=(self._health_state in {"ok", "degraded"}),
            device_count=0,
            driver_version=self._policy.driver_version or None,
            health_state=self._health_state,
            warnings=self._reason_codes,
            cfg_fp=self._policy.cfg_fp,
        )


# ============================================================================
# NVML runtime
# ============================================================================

class _NvmlRuntime:
    _lock = threading.RLock()
    _initialized = False
    _init_failed = False
    _driver_version: Optional[str] = None
    _device_count: int = 0

    @classmethod
    def ensure_initialized(cls) -> bool:
        if not _NVML_AVAILABLE:
            return False
        with cls._lock:
            if cls._initialized:
                return True
            if cls._init_failed:
                return False
            try:
                pynvml.nvmlInit()  # type: ignore[union-attr]
                cls._initialized = True
            except Exception as exc:  # pragma: no cover
                cls._init_failed = True
                logger.warning("NVML initialization failed: %r", exc)
                return False

            try:
                dv = pynvml.nvmlSystemGetDriverVersion()  # type: ignore[union-attr]
                if isinstance(dv, bytes):
                    cls._driver_version = dv.decode("utf-8", errors="ignore")
                else:
                    cls._driver_version = str(dv)
            except Exception:
                cls._driver_version = None

            try:
                cls._device_count = int(pynvml.nvmlDeviceGetCount())  # type: ignore[union-attr]
            except Exception:
                cls._device_count = 0

            return True

    @classmethod
    def device_count(cls) -> int:
        if not cls.ensure_initialized():
            return 0
        with cls._lock:
            return max(0, int(cls._device_count))

    @classmethod
    def driver_version(cls) -> Optional[str]:
        if not cls.ensure_initialized():
            return None
        with cls._lock:
            return _safe_text_or_none(cls._driver_version, max_len=128)

    @classmethod
    def handle(cls, index: int) -> Any:
        if not cls.ensure_initialized():
            return None
        try:
            return pynvml.nvmlDeviceGetHandleByIndex(int(index))  # type: ignore[union-attr]
        except Exception:
            return None


class NvmlGpuSampler(BaseGpuSampler):
    def __init__(self, index: int = 0, *, policy: Optional[GpuSamplerPolicy] = None, config: Optional[GpuTelemetryConfig] = None) -> None:
        if not _NVML_AVAILABLE:
            raise RuntimeError("pynvml unavailable")
        super().__init__(policy=policy, config=config)
        self._index = int(index)

    def _public_uuid(self, raw_uuid: Optional[str]) -> Tuple[str, Optional[str], bool]:
        u = _safe_gpu_uuid(raw_uuid, default=None, max_len=256)
        if not u:
            return "", None, False
        key = self._cfg.uuid_hash_key
        if isinstance(key, str):
            key = _parse_key_material(key)
        if key is not None and len(key) < max(8, int(self._cfg.min_uuid_hash_key_bytes)):
            key = None

        if key is not None:
            kid = _safe_text_or_none(self._cfg.uuid_hash_key_id, max_len=16) or "hmac"
            dig = hmac.new(key, b"tcd:gpu:uuid\x00" + u.encode("utf-8", errors="ignore"), hashlib.sha256).hexdigest()[: self._cfg.uuid_hash_hex_chars]
            uuid_hash = f"{_UUID_HASH_VERSION}:{kid}:{dig}"
        else:
            dig = hashlib.sha256(b"tcd:gpu:uuid\x00" + u.encode("utf-8", errors="ignore")).hexdigest()[: self._cfg.uuid_hash_hex_chars]
            uuid_hash = f"{_UUID_HASH_VERSION}:sha256:{dig}"

        mode = self._cfg.expose_uuid_mode
        strict = _profile_is_strict(self._cfg.profile)
        clear_allowed = (self._cfg.profile in self._cfg.allow_clear_uuid_profiles)
        if mode == "clear":
            return u, uuid_hash, True
        if mode == "clear_if_allowed" and (clear_allowed and not strict):
            return u, uuid_hash, True
        return "", uuid_hash, False

    def _read_identity(self, handle: Any) -> Tuple[str, str]:
        uuid = ""
        name = ""
        with contextlib.suppress(Exception):
            uv = pynvml.nvmlDeviceGetUUID(handle)  # type: ignore[union-attr]
            uuid = uv.decode("utf-8", errors="ignore") if isinstance(uv, bytes) else str(uv)
        with contextlib.suppress(Exception):
            nv = pynvml.nvmlDeviceGetName(handle)  # type: ignore[union-attr]
            name = nv.decode("utf-8", errors="ignore") if isinstance(nv, bytes) else str(nv)
        return _safe_gpu_uuid(uuid, default="", max_len=256) or "", _safe_text(name, max_len=128)

    def _read_util(self, handle: Any) -> Tuple[float, float]:
        gpu = 0.0
        mem = 0.0
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)  # type: ignore[union-attr]
        gpu = _clamp_float(getattr(util, "gpu", 0.0), default=0.0, lo=0.0, hi=100.0)
        mem = _clamp_float(getattr(util, "memory", 0.0), default=0.0, lo=0.0, hi=100.0)
        return gpu, mem

    def _read_memory(self, handle: Any) -> Tuple[float, float, float]:
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)  # type: ignore[union-attr]
        used_b = max(0, int(getattr(mem, "used", 0)))
        total_b = max(0, int(getattr(mem, "total", 0)))
        free_b = max(0, int(getattr(mem, "free", max(0, total_b - used_b))))
        used = _clamp_float(used_b / (1024 * 1024), default=0.0, lo=0.0, hi=1_000_000_000.0)
        total = _clamp_float(total_b / (1024 * 1024), default=0.0, lo=0.0, hi=1_000_000_000.0)
        free = _clamp_float(free_b / (1024 * 1024), default=max(0.0, total - used), lo=0.0, hi=1_000_000_000.0)
        return used, total, free

    def _read_temp(self, handle: Any) -> float:
        return _clamp_float(
            pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU),  # type: ignore[union-attr]
            default=0.0,
            lo=0.0,
            hi=200.0,
        )

    def _read_power(self, handle: Any) -> Tuple[float, float]:
        usage = _clamp_float(pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0, default=0.0, lo=0.0, hi=1_000_000.0)  # type: ignore[union-attr]
        limit = _clamp_float(pynvml.nvmlDeviceGetEnforcedPowerLimit(handle) / 1000.0, default=0.0, lo=0.0, hi=1_000_000.0)  # type: ignore[union-attr]
        return usage, limit

    def _read_fan(self, handle: Any) -> float:
        return _clamp_float(pynvml.nvmlDeviceGetFanSpeed(handle), default=0.0, lo=0.0, hi=100.0)  # type: ignore[union-attr]

    def _read_compute_mode(self, handle: Any) -> str:
        with contextlib.suppress(Exception):
            mode = pynvml.nvmlDeviceGetComputeMode(handle)  # type: ignore[union-attr]
            return _safe_text(mode, max_len=64)
        return ""

    def _read_ecc(self, handle: Any) -> int:
        with contextlib.suppress(Exception):
            err = pynvml.nvmlDeviceGetTotalEccErrors(  # type: ignore[union-attr]
                handle,
                pynvml.NVML_MEMORY_ERROR_TYPE_UNCORRECTED,  # type: ignore[union-attr]
                pynvml.NVML_VOLATILE_ECC,  # type: ignore[union-attr]
            )
            return max(0, int(err))
        return 0

    def _read_extra(self, handle: Any) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        with contextlib.suppress(Exception):
            sm = pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_SM)  # type: ignore[union-attr]
            out["sm_clock_mhz"] = _clamp_float(sm, default=0.0, lo=0.0, hi=100_000.0)
        with contextlib.suppress(Exception):
            mc = pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_MEM)  # type: ignore[union-attr]
            out["mem_clock_mhz"] = _clamp_float(mc, default=0.0, lo=0.0, hi=100_000.0)
        with contextlib.suppress(Exception):
            gc = pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_GRAPHICS)  # type: ignore[union-attr]
            out["graphics_clock_mhz"] = _clamp_float(gc, default=0.0, lo=0.0, hi=100_000.0)
        with contextlib.suppress(Exception):
            temp_limit = pynvml.nvmlDeviceGetTemperatureThreshold(handle, pynvml.NVML_TEMPERATURE_THRESHOLD_SLOWDOWN)  # type: ignore[union-attr]
            out["temp_slowdown_c"] = _clamp_float(temp_limit, default=0.0, lo=0.0, hi=200.0)
        return out

    def _evaluate_integrity(
        self,
        *,
        raw_uuid: str,
        name: str,
        temp_c: float,
        ecc_errors_total: int,
        power_w: float,
        mem_total_mb: float,
        driver_version_observed: Optional[str],
        device_count: int,
    ) -> Tuple[str, Tuple[str, ...], Tuple[str, ...], bool, str]:
        p = self._policy
        integrity_codes: List[str] = []
        degraded_codes: List[str] = []
        apt_suspect = False

        strict = _profile_is_strict(self._cfg.profile)

        if p.expected_vendor and p.expected_vendor != "nvidia":
            integrity_codes.append("GPU_VENDOR_MISMATCH")

        if p.expected_uuids:
            allowed = {str(x).lower() for x in p.expected_uuids}
            if not raw_uuid or raw_uuid.lower() not in allowed:
                integrity_codes.append("GPU_UUID_MISMATCH")

        if p.expected_name_prefixes:
            if not any(name.startswith(pref) for pref in p.expected_name_prefixes):
                integrity_codes.append("GPU_NAME_MISMATCH")

        if self._cfg.driver_version_must_match_policy and p.driver_version and driver_version_observed and p.driver_version != driver_version_observed:
            integrity_codes.append("GPU_DRIVER_MISMATCH")

        if p.min_device_count is not None and device_count < p.min_device_count:
            integrity_codes.append("GPU_DEVICE_COUNT_OUT_OF_RANGE")
        if p.max_device_count is not None and device_count > p.max_device_count:
            integrity_codes.append("GPU_DEVICE_COUNT_OUT_OF_RANGE")

        if temp_c > p.max_temp_c:
            degraded_codes.append("GPU_TEMP_ABOVE_THRESHOLD")
            apt_suspect = True
        if ecc_errors_total > p.max_ecc_errors:
            degraded_codes.append("GPU_ECC_ERRORS_ABOVE_THRESHOLD")
            apt_suspect = True
        if p.max_power_w is not None and power_w > p.max_power_w:
            degraded_codes.append("GPU_POWER_ABOVE_THRESHOLD")
            apt_suspect = True
        if p.min_total_mem_mb is not None and mem_total_mb < p.min_total_mem_mb:
            degraded_codes.append("GPU_TOTAL_MEM_BELOW_THRESHOLD")
            apt_suspect = True
        if p.pq_required and p.pq_ok is False:
            degraded_codes.append("GPU_PQ_REQUIRED_NOT_OK")
            apt_suspect = True

        if not raw_uuid:
            degraded_codes.append("GPU_UNVERIFIED")

        if integrity_codes:
            hw = "mismatch"
        elif degraded_codes:
            hw = "degraded"
        else:
            hw = "ok"

        if strict and self._cfg.enforce_expected_uuid_in_strict and p.expected_uuids and "GPU_UUID_MISMATCH" in integrity_codes:
            apt_suspect = True
        if strict and self._cfg.enforce_expected_vendor_in_strict and "GPU_VENDOR_MISMATCH" in integrity_codes:
            apt_suspect = True

        reasons = integrity_codes + [c for c in degraded_codes if c not in integrity_codes]
        apt_reason = ";".join(reasons)
        return hw, tuple(integrity_codes), tuple(degraded_codes), apt_suspect, apt_reason

    def _make_sample(
        self,
        *,
        index: int,
        raw_uuid: str,
        name: str,
        util_pct: float,
        mem_util_pct: float,
        mem_used_mb: float,
        mem_total_mb: float,
        mem_free_mb: float,
        temp_c: float,
        power_w: float,
        power_limit_w: float,
        fan_pct: float,
        compute_mode: str,
        ecc_errors_total: int,
        extra: Mapping[str, Any],
        health_state: str,
        normalization_warnings: Sequence[str],
        degraded_reason_codes: Sequence[str],
    ) -> GpuSample:
        ts = now_ts()
        ts_ns = now_unix_ns()
        mono_ns = time.monotonic_ns()
        policy = self._policy
        driver_observed = _NvmlRuntime.driver_version() or policy.driver_version or ""
        uuid_public, uuid_hash, uuid_exposed = self._public_uuid(raw_uuid)
        device_count = _NvmlRuntime.device_count()
        hw_state, integrity_codes, policy_degraded_codes, apt_suspect, apt_reason = self._evaluate_integrity(
            raw_uuid=raw_uuid,
            name=name,
            temp_c=temp_c,
            ecc_errors_total=ecc_errors_total,
            power_w=power_w,
            mem_total_mb=mem_total_mb,
            driver_version_observed=driver_observed,
            device_count=device_count,
        )
        all_degraded = tuple(dict.fromkeys(list(degraded_reason_codes) + list(policy_degraded_codes)))
        produced_by = tuple(policy.produced_by or ("tcd.telemetry_gpu",))
        provenance_path_digest = f"sha256:{_hash_hex(ctx='tcd:gpu:produced_by', payload={'produced_by': list(produced_by)}, out_hex=64)}"

        extra_s = _safe_json_mapping(extra, max_items=self._cfg.max_extra_items, max_str_len=self._cfg.max_extra_str_len)
        if mem_util_pct >= 0.0 and "mem_util_pct" not in extra_s:
            extra_s["mem_util_pct"] = mem_util_pct

        event_core = {
            "index": index,
            "uuid_hash": uuid_hash,
            "name": name,
            "ts_unix_ns": ts_ns,
            "node_id": policy.node_id,
            "build_id": policy.build_id,
            "image_digest": policy.image_digest,
            "cfg_fp": policy.cfg_fp,
            "driver_version": driver_observed,
        }
        event_id = f"{_EVENT_VERSION}:{_hash_hex(ctx='tcd:gpu:event', payload=event_core, out_hex=32)}"
        sample_payload = {
            "event_id": event_id,
            "index": index,
            "uuid": uuid_public,
            "uuid_hash": uuid_hash,
            "uuid_exposed": uuid_exposed,
            "name": name,
            "ts": ts,
            "ts_unix_ns": ts_ns,
            "ts_monotonic_ns": mono_ns,
            "util_pct": util_pct,
            "mem_used_mb": mem_used_mb,
            "mem_total_mb": mem_total_mb,
            "mem_free_mb": mem_free_mb,
            "temp_c": temp_c,
            "power_w": power_w,
            "power_limit_w": power_limit_w,
            "fan_pct": fan_pct,
            "compute_mode": compute_mode,
            "ecc_errors_total": ecc_errors_total,
            "backend": "nvml",
            "health_state": health_state,
            "extra": extra_s,
            "node_id": policy.node_id,
            "build_id": policy.build_id,
            "image_digest": policy.image_digest,
            "driver_version": driver_observed,
            "runtime_env": policy.runtime_env,
            "trust_zone": policy.trust_zone,
            "route_profile": policy.route_profile,
            "policy_ref": policy.policy_ref,
            "policyset_ref": policy.policyset_ref,
            "policy_digest": policy.policy_digest,
            "cfg_fp": policy.cfg_fp,
            "state_domain_id": policy.state_domain_id,
            "adapter_registry_fp": policy.adapter_registry_fp,
            "selected_source": policy.selected_source,
            "controller_mode": policy.controller_mode,
            "decision_mode": policy.decision_mode,
            "statistical_guarantee_scope": policy.statistical_guarantee_scope,
            "activation_id": policy.activation_id,
            "patch_id": policy.patch_id,
            "hw_integrity_state": hw_state,
            "integrity_reason_codes": list(integrity_codes),
            "degraded_reason_codes": list(all_degraded),
            "normalization_warnings": list(normalization_warnings),
            "apt_suspect": apt_suspect,
            "apt_reason": apt_reason,
            "insider_override": False,
            "override_reason": "",
            "pq_required": policy.pq_required,
            "pq_ok": policy.pq_ok,
            "pq_chain_id": policy.pq_chain_id,
            "pq_signature_required": policy.pq_signature_required,
            "pq_signature_ok": policy.pq_signature_ok,
            "audit_ref": policy.audit_ref,
            "receipt_ref": policy.receipt_ref,
            "produced_by": list(produced_by),
            "provenance_path_digest": provenance_path_digest,
        }
        payload_digest = f"{_PAYLOAD_VERSION}:sha256:{hashlib.sha256(_canonical_json_bytes(sample_payload)).hexdigest()}"
        sample_fingerprint = f"gpu1:{_hash_hex(ctx='tcd:gpu:sample', payload=sample_payload, out_hex=32)}"
        event_digest = f"gpued1:sha256:{_hash_hex(ctx='tcd:gpu:event_digest', payload=sample_payload, out_hex=32)}"

        integrity_ok = (hw_state == "ok") and (health_state in {"ok", "degraded"})

        return GpuSample(
            schema=_SCHEMA,
            schema_version=2,
            canonicalization_version=_CANONICALIZATION_VERSION,
            event_id=event_id,
            event_type="gpu_telemetry",
            sample_fingerprint=sample_fingerprint,
            event_digest=event_digest,
            payload_digest=payload_digest,
            index=index,
            uuid=uuid_public,
            uuid_hash=uuid_hash,
            uuid_exposed=uuid_exposed,
            name=name,
            ts=ts,
            ts_unix_ns=ts_ns,
            ts_monotonic_ns=mono_ns,
            util_pct=util_pct,
            mem_used_mb=mem_used_mb,
            mem_total_mb=mem_total_mb,
            mem_free_mb=mem_free_mb,
            temp_c=temp_c,
            power_w=power_w,
            power_limit_w=power_limit_w,
            fan_pct=fan_pct,
            compute_mode=compute_mode,
            ecc_errors_total=ecc_errors_total,
            backend="nvml",
            health_state=health_state,
            extra=MappingProxyType(extra_s),
            node_id=policy.node_id,
            build_id=policy.build_id,
            image_digest=policy.image_digest,
            driver_version=driver_observed,
            runtime_env=policy.runtime_env,
            trust_zone=policy.trust_zone,
            route_profile=policy.route_profile,
            policy_ref=policy.policy_ref,
            policyset_ref=policy.policyset_ref,
            policy_digest=policy.policy_digest,
            cfg_fp=policy.cfg_fp,
            state_domain_id=policy.state_domain_id,
            adapter_registry_fp=policy.adapter_registry_fp,
            selected_source=policy.selected_source,
            controller_mode=policy.controller_mode,
            decision_mode=policy.decision_mode,
            statistical_guarantee_scope=policy.statistical_guarantee_scope,
            activation_id=policy.activation_id,
            patch_id=policy.patch_id,
            hw_integrity_state=hw_state,
            integrity_ok=integrity_ok,
            integrity_reason_codes=integrity_codes,
            degraded_reason_codes=all_degraded,
            normalization_warnings=tuple(_normalize_str_tuple(normalization_warnings, max_len=64, max_items=16)),
            apt_suspect=apt_suspect,
            apt_reason=_safe_text(apt_reason, max_len=256),
            insider_override=False,
            override_reason="",
            pq_required=policy.pq_required,
            pq_ok=policy.pq_ok,
            pq_chain_id=policy.pq_chain_id,
            pq_signature_required=policy.pq_signature_required,
            pq_signature_ok=policy.pq_signature_ok,
            audit_ref=policy.audit_ref,
            receipt_ref=policy.receipt_ref,
            produced_by=produced_by,
            provenance_path_digest=provenance_path_digest,
        )

    def _sample_index(self, index: int) -> GpuSample:
        policy = self._policy
        handle = _NvmlRuntime.handle(index)
        if handle is None:
            return DummyGpuSampler(
                index=index,
                health_state="down",
                policy=policy,
                config=self._cfg,
                insider_override=False,
                override_reason="",
                backend_label="nvml",
                reason_codes=("GPU_BACKEND_DOWN",),
            ).sample()

        uuid = ""
        name = ""
        util_pct = 0.0
        mem_util_pct = 0.0
        mem_used_mb = 0.0
        mem_total_mb = 0.0
        mem_free_mb = 0.0
        temp_c = 0.0
        power_w = 0.0
        power_limit_w = 0.0
        fan_pct = 0.0
        compute_mode = ""
        ecc_errors_total = 0
        extra: Dict[str, Any] = {}
        warnings: List[str] = []
        degraded: List[str] = []
        hard_down = False

        try:
            uuid, name = self._read_identity(handle)
        except Exception:
            warnings.append("identity_partial")

        try:
            util_pct, mem_util_pct = self._read_util(handle)
        except Exception:
            degraded.append("GPU_PARTIAL_METRICS")

        try:
            mem_used_mb, mem_total_mb, mem_free_mb = self._read_memory(handle)
        except Exception:
            degraded.append("GPU_PARTIAL_METRICS")

        try:
            temp_c = self._read_temp(handle)
        except Exception:
            degraded.append("GPU_PARTIAL_METRICS")

        try:
            power_w, power_limit_w = self._read_power(handle)
        except Exception:
            degraded.append("GPU_PARTIAL_METRICS")

        with contextlib.suppress(Exception):
            fan_pct = self._read_fan(handle)

        with contextlib.suppress(Exception):
            compute_mode = self._read_compute_mode(handle)

        with contextlib.suppress(Exception):
            ecc_errors_total = self._read_ecc(handle)

        try:
            extra = self._read_extra(handle)
        except Exception:
            extra = {}

        health = "ok"
        if hard_down:
            health = "down"
        elif degraded:
            health = "degraded"

        return self._make_sample(
            index=index,
            raw_uuid=uuid,
            name=name,
            util_pct=_clamp_float(util_pct, default=0.0, lo=0.0, hi=100.0),
            mem_util_pct=_clamp_float(mem_util_pct, default=0.0, lo=0.0, hi=100.0),
            mem_used_mb=_clamp_float(mem_used_mb, default=0.0, lo=0.0, hi=1_000_000_000.0),
            mem_total_mb=_clamp_float(mem_total_mb, default=0.0, lo=0.0, hi=1_000_000_000.0),
            mem_free_mb=_clamp_float(mem_free_mb, default=0.0, lo=0.0, hi=1_000_000_000.0),
            temp_c=_clamp_float(temp_c, default=0.0, lo=0.0, hi=200.0),
            power_w=_clamp_float(power_w, default=0.0, lo=0.0, hi=1_000_000.0),
            power_limit_w=_clamp_float(power_limit_w, default=0.0, lo=0.0, hi=1_000_000.0),
            fan_pct=_clamp_float(fan_pct, default=0.0, lo=0.0, hi=100.0),
            compute_mode=_safe_text(compute_mode, max_len=64),
            ecc_errors_total=max(0, int(ecc_errors_total)),
            extra=extra,
            health_state=health,
            normalization_warnings=warnings,
            degraded_reason_codes=degraded,
        )

    def sample(self) -> GpuSample:
        if not _NvmlRuntime.ensure_initialized():
            return DummyGpuSampler(
                index=self._index,
                health_state="down",
                policy=self._policy,
                config=self._cfg,
                insider_override=False,
                override_reason="",
                backend_label="nvml",
                reason_codes=("GPU_BACKEND_DOWN",),
            ).sample()
        return self._sample_index(self._index)

    def sample_all(self) -> List[GpuSample]:
        if not _NvmlRuntime.ensure_initialized():
            return []
        count = min(_NvmlRuntime.device_count(), self._cfg.max_batch_devices)
        return [self._sample_index(i) for i in range(count)]

    def health(self) -> GpuSamplerHealth:
        ok = _NvmlRuntime.ensure_initialized()
        count = _NvmlRuntime.device_count() if ok else 0
        driver = _NvmlRuntime.driver_version() or self._policy.driver_version or None
        state: str = "ok" if ok else "down"
        warnings: List[str] = []
        if not ok:
            warnings.append("GPU_BACKEND_DOWN")
        return GpuSamplerHealth(
            backend="nvml",
            available=ok,
            device_count=count,
            driver_version=driver,
            health_state=state,
            warnings=tuple(warnings),
            cfg_fp=self._policy.cfg_fp,
        )


# ============================================================================
# Facade
# ============================================================================

class GpuSampler:
    def __init__(
        self,
        index: int = 0,
        *,
        force_dummy: bool = False,
        policy: Optional[GpuSamplerPolicy] = None,
        override_reason: str = "",
        config: Optional[GpuTelemetryConfig] = None,
        telemetry_sink: Optional[GpuTelemetrySink] = None,
        audit_sink: Optional[GpuAuditSink] = None,
    ) -> None:
        self._cfg = (config or GpuTelemetryConfig())
        self._policy = (policy or GpuSamplerPolicy()).normalized(cfg=self._cfg)
        self._telemetry_sink = telemetry_sink
        self._audit_sink = audit_sink
        self._index = int(index)

        if not self._cfg.enable:
            self._impl: BaseGpuSampler = DummyGpuSampler(
                index=self._index,
                health_state="disabled",
                policy=self._policy,
                config=self._cfg,
                insider_override=True,
                override_reason=override_reason or "gpu_disabled",
                backend_label="dummy",
                reason_codes=("GPU_DISABLED",),
            )
            return

        pref = self._cfg.backend_preference
        if force_dummy or pref == "dummy":
            self._impl = DummyGpuSampler(
                index=self._index,
                health_state="unknown" if force_dummy else "disabled",
                policy=self._policy,
                config=self._cfg,
                insider_override=bool(force_dummy),
                override_reason=override_reason or ("force_dummy" if force_dummy else "backend_dummy"),
                backend_label="dummy",
                reason_codes=("GPU_FORCE_DUMMY",) if force_dummy else tuple(),
            )
            return

        if pref in {"auto", "nvml"} and _NVML_AVAILABLE:
            with contextlib.suppress(Exception):
                self._impl = NvmlGpuSampler(index=self._index, policy=self._policy, config=self._cfg)
                return

        self._impl = DummyGpuSampler(
            index=self._index,
            health_state="down",
            policy=self._policy,
            config=self._cfg,
            insider_override=False,
            override_reason=override_reason or "nvml_unavailable",
            backend_label="dummy",
            reason_codes=("GPU_BACKEND_DOWN",),
        )

    def _publish(self, sample: GpuSample) -> None:
        labels = {
            "backend": _safe_label(sample.backend, default="unknown"),
            "health_state": _safe_label(sample.health_state, default="unknown"),
            "trust_zone": _safe_label(sample.trust_zone, default="unknown"),
            "route_profile": _safe_label(sample.route_profile, default="unknown"),
            "policy_ref": _safe_label(sample.policy_ref, default="default") if sample.policy_ref else "default",
            "node": _safe_text(sample.node_id, max_len=64) or "default",
            "index": str(int(sample.index)),
        }
        if self._telemetry_sink is not None:
            with contextlib.suppress(Exception):
                self._telemetry_sink.record_metric("tcd_gpu_util_pct", float(sample.util_pct), labels)
            with contextlib.suppress(Exception):
                mem_ratio = (sample.mem_used_mb / sample.mem_total_mb) if sample.mem_total_mb > 0 else 0.0
                self._telemetry_sink.record_metric("tcd_gpu_mem_ratio", float(mem_ratio), labels)
            with contextlib.suppress(Exception):
                self._telemetry_sink.record_metric("tcd_gpu_temp_c", float(sample.temp_c), labels)
            with contextlib.suppress(Exception):
                self._telemetry_sink.record_event("gpu_sample", sample.to_public_dict())
            if sample.apt_suspect:
                with contextlib.suppress(Exception):
                    self._telemetry_sink.record_event("gpu_sample_anomaly", sample.to_audit_dict())

        if self._audit_sink is not None:
            evt = "GpuTelemetryAnomaly" if sample.apt_suspect else "GpuTelemetrySample"
            with contextlib.suppress(Exception):
                self._audit_sink.emit(evt, sample.to_audit_dict())

    def sample_struct(self) -> GpuSample:
        sample = self._impl.sample()
        self._publish(sample)
        return sample

    def sample(self) -> Dict[str, Any]:
        return self.sample_struct().to_public_dict()

    def sample_all_structs(self) -> List[GpuSample]:
        samples = self._impl.sample_all()
        for s in samples:
            self._publish(s)
        return samples

    def sample_all(self) -> List[Dict[str, Any]]:
        return [s.to_public_dict() for s in self.sample_all_structs()]

    def health(self) -> GpuSamplerHealth:
        return self._impl.health()

    def health_snapshot(self) -> Dict[str, Any]:
        return self.health().to_dict()