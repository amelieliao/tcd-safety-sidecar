from __future__ import annotations

"""
tcd/telemetry_gpu.py

Governed GPU telemetry boundary for TCD.

This module is intentionally content-agnostic. It samples bounded hardware /
runtime telemetry only and is designed to align with stronger contracts already
present in storage.py, signals.py, schemas.py, risk_av.py, service_http.py,
service_grpc.py, and attest.py.

Design goals
------------
1. Content-agnostic
   No prompts, completions, cookies, auth headers, or request/response bodies
   are ever read, stored, or emitted by this module.

2. Contract-aware
   Every sample carries node/build/policy/state evidence fields that can be
   projected into EvidenceIdentity / ArtifactRefs / storage metadata / receipt
   claims.

3. Deterministic
   Canonical JSON, bounded sanitization, stable digests, explicit assessment
   logic, and profile-aware privacy.

4. Production-safe
   No hard failure when NVML is missing or partially broken. Backend failures
   degrade into explicit negative evidence rather than silent emptiness.

5. Compatibility
   GpuSampler.sample() still returns a flat dict and GpuSampler.sample_struct()
   still returns a final typed sample object. New batch, projection and receipt-
   claim helpers are additive.
"""

import base64
import contextlib
import dataclasses
import hashlib
import hmac
import json
import logging
import math
import os
import re
import threading
import time
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Protocol, Sequence, Tuple, Literal

logger = logging.getLogger(__name__)

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

try:  # optional schema alignment
    from .schemas import ArtifactRefsView, EvidenceIdentityView  # type: ignore
except Exception:  # pragma: no cover
    ArtifactRefsView = None  # type: ignore[assignment]
    EvidenceIdentityView = None  # type: ignore[assignment]

try:  # optional attestor integration
    from .attest import Attestor  # type: ignore
except Exception:  # pragma: no cover
    Attestor = None  # type: ignore[assignment]

__all__ = [
    "GpuTelemetryConfig",
    "GpuSamplerPolicy",
    "GpuRawObservation",
    "GpuNormalizedObservation",
    "GpuPolicyAssessment",
    "GpuSample",
    "GpuHostSnapshot",
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

# =============================================================================
# Constants / types
# =============================================================================

Profile = Literal["DEV", "PROD", "FINREG", "LOCKDOWN"]
BackendPreference = Literal["auto", "nvml", "dummy"]
UuidExposureMode = Literal["clear", "hash", "clear_if_allowed"]
NameExposureMode = Literal["clear", "hash", "clear_if_allowed"]
HealthState = Literal["ok", "degraded", "down", "unknown", "disabled"]
HwIntegrityState = Literal["ok", "mismatch", "unverified", "degraded"]
CollectionState = Literal["ok", "partial", "backend_down", "disabled", "unknown"]

_SCHEMA = "tcd.telemetry.gpu.v3"
_COMPATIBILITY_EPOCH = "2026Q2"
_CANONICALIZATION_VERSION = "canonjson_v1"
_EVENT_VERSION = "gtev3"
_OBSERVATION_VERSION = "gtov1"
_ASSESSMENT_VERSION = "gtav1"
_PAYLOAD_VERSION = "gtpd2"
_UUID_HASH_VERSION = "gpuu2"
_NAME_HASH_VERSION = "gpun2"
_CFG_FP_VERSION = "gcfg1"

_ALLOWED_PROFILES = frozenset({"DEV", "PROD", "FINREG", "LOCKDOWN"})
_ALLOWED_TRUST_ZONES = frozenset({"internet", "internal", "partner", "admin", "ops", "unknown"})
_ALLOWED_ROUTE_PROFILES = frozenset({"inference", "batch", "admin", "control", "metrics", "health", "restricted", "unknown"})
_ALLOWED_CONTROLLER_MODES = frozenset(
    {"normal", "last_known_good", "fail_closed", "degraded_identity", "degraded_state_backend", "degraded_calibration"}
)
_ALLOWED_DECISION_MODES = frozenset({"strict_only", "controller_only", "prefer_current_strict", "dual_track"})
_ALLOWED_GUARANTEE_SCOPES = frozenset({"strict_direct_p", "predictable_calibrated_p", "heuristic_only", "none"})
_ALLOWED_HEALTH = frozenset({"ok", "degraded", "down", "unknown", "disabled"})
_ALLOWED_COLLECTION_STATE = frozenset({"ok", "partial", "backend_down", "disabled", "unknown"})
_ALLOWED_HW_INTEGRITY = frozenset({"ok", "mismatch", "unverified", "degraded"})
_ALLOWED_GPU_REASON_CODES = frozenset(
    {
        "GPU_FORCE_DUMMY",
        "GPU_BACKEND_DOWN",
        "GPU_BACKEND_INIT_FAILED",
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
        "GPU_CACHE_STALE",
        "GPU_MIG_PARTITION",
        "GPU_RETIRED_PAGES_PRESENT",
        "GPU_ROW_REMAP_FAILURE_PRESENT",
        "GPU_XID_PRESENT",
    }
)
_ALLOWED_COMPUTE_MODES = frozenset(
    {
        "default",
        "exclusive_thread",
        "prohibited",
        "exclusive_process",
        "unknown",
    }
)

_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")
_SAFE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#/+=]{0,255}$")
_SAFE_GPU_UUID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-/]{7,255}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_DIGEST_HEX_RE = re.compile(r"^[0-9a-f]{16,256}$")
_DIGEST_HEX_0X_RE = re.compile(r"^0x[0-9a-f]{16,256}$")
_DIGEST_ALG_HEX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,31}:[0-9a-f]{16,256}$")
_CFG_FP_RE = re.compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256}|[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256})$"
)

_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b", re.IGNORECASE)
_BASIC_RE = re.compile(r"\bBasic\s+[A-Za-z0-9+/=]{16,}\b")
_OPENAI_SK_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_AWS_AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GOOGLE_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_KV_SECRET_RE = re.compile(r"(?i)\b(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]{8,})")
_ENTROPY_B64URL_RE = re.compile(r"\b[A-Za-z0-9_-]{60,}\b")

_DEFAULT_EXTRA_ALLOWLIST = frozenset(
    {
        "mem_util_pct",
        "sm_clock_mhz",
        "mem_clock_mhz",
        "graphics_clock_mhz",
        "temp_slowdown_c",
        "pci_bus_id",
        "minor_number",
        "device_index",
        "nvml_device_count",
        "ecc_mode_enabled",
        "ecc_corrected_total",
        "ecc_uncorrected_total",
        "retired_pages_count",
        "row_remap_failure_count",
        "perf_state",
        "throttle_reasons",
        "power_state",
        "persistence_mode",
        "mig_mode",
        "mig_parent_uuid_hash",
        "mig_instance_id",
        "compute_capability",
        "xid_recent",
        "driver_version_observed",
        "driver_version_expected",
        "driver_version_match_state",
        "observed_vendor",
        "uuid_classification",
        "name_classification",
    }
)

# =============================================================================
# Low-level helpers
# =============================================================================


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
    s = _safe_text(v, max_len=64, redact_mode="token").lower()
    if not s or s == "[redacted]" or not _SAFE_LABEL_RE.fullmatch(s):
        return default
    return s


def _safe_name(v: Any, *, default: str) -> str:
    s = _safe_text(v, max_len=128, redact_mode="token")
    if not s or s == "[redacted]" or not _SAFE_NAME_RE.fullmatch(s):
        return default
    return s


def _safe_id(v: Any, *, default: Optional[str] = None, max_len: int = 256) -> Optional[str]:
    s = _safe_text(v, max_len=max_len, redact_mode="token")
    if not s or s == "[redacted]" or not _SAFE_ID_RE.fullmatch(s):
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
    return hashlib.sha256(raw).hexdigest()[:out_hex)


def _parse_key_material(v: Any) -> Optional[bytes]:
    if isinstance(v, bytes):
        return bytes(v) if 1 <= len(v) <= 4096 else None
    if not isinstance(v, str):
        return None
    s = _strip_unsafe_text(v, max_len=4096)
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
            return base64.urlsafe_b64decode((raw + pad).encode("utf-8", errors="strict"))
        except Exception:
            return None
    if s.lower().startswith("raw:"):
        return s[4:].encode("utf-8", errors="ignore")
    if _HEX_RE.fullmatch(s) and len(s) % 2 == 0:
        with contextlib.suppress(Exception):
            return bytes.fromhex(s)
    try:
        pad = "=" * ((4 - (len(s) % 4)) % 4)
        return base64.urlsafe_b64decode((s + pad).encode("utf-8", errors="strict"))
    except Exception:
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


class _JsonBudget:
    __slots__ = ("max_nodes", "max_items", "max_depth", "max_str_total", "nodes", "str_used")

    def __init__(self, *, max_nodes: int, max_items: int, max_depth: int, max_str_total: int):
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


def _json_sanitize(obj: Any, *, budget: _JsonBudget, depth: int, max_str_len: int, allowed_keys: Optional[set[str]] = None) -> Any:
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
            if allowed_keys is not None and kk not in allowed_keys:
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


def _safe_json_mapping(v: Any, *, max_items: int, max_str_len: int, allowed_keys: Optional[set[str]] = None) -> Dict[str, Any]:
    if not isinstance(v, Mapping):
        return {}
    budget = _JsonBudget(max_nodes=4096, max_items=max_items, max_depth=8, max_str_total=128_000)
    out = _json_sanitize(dict(v), budget=budget, depth=0, max_str_len=max_str_len, allowed_keys=allowed_keys)
    return out if isinstance(out, dict) else {}


# =============================================================================
# Protocols
# =============================================================================

class GpuTelemetrySink(Protocol):
    def record_metric(self, name: str, value: float, labels: Mapping[str, str]) -> None:
        ...
    def record_event(self, name: str, payload: Mapping[str, Any]) -> None:
        ...


class GpuAuditSink(Protocol):
    def emit(self, event_type: str, payload: Mapping[str, Any]) -> Optional[str]:
        ...


# =============================================================================
# Config / policy
# =============================================================================

@dataclass(frozen=True, slots=True)
class GpuTelemetryConfig:
    profile: Profile = "PROD"
    compatibility_epoch: str = _COMPATIBILITY_EPOCH
    enable: bool = True
    backend_preference: BackendPreference = "auto"

    expose_uuid_mode: UuidExposureMode = "clear_if_allowed"
    expose_name_mode: NameExposureMode = "clear_if_allowed"
    allow_clear_uuid_profiles: Tuple[str, ...] = ("DEV",)
    allow_clear_name_profiles: Tuple[str, ...] = ("DEV",)
    uuid_hash_key: Optional[Any] = None
    uuid_hash_key_id: Optional[str] = None
    name_hash_key: Optional[Any] = None
    name_hash_key_id: Optional[str] = None
    min_hash_key_bytes: int = 16
    uuid_hash_hex_chars: int = 24
    name_hash_hex_chars: int = 24

    cache_ttl_ms: int = 250
    max_staleness_ms: int = 3000
    cache_on_error: bool = True

    max_extra_items: int = 64
    max_extra_key_len: int = 64
    max_extra_str_len: int = 256
    max_batch_devices: int = 32
    allowed_extra_keys: Tuple[str, ...] = tuple(_DEFAULT_EXTRA_ALLOWLIST)

    enforce_expected_uuid_in_strict: bool = True
    enforce_expected_vendor_in_strict: bool = True
    driver_version_must_match_policy: bool = False

    enable_collection_negative_evidence: bool = True
    enable_attestor_bridge: bool = True

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
        nmode = _safe_label(self.expose_name_mode, default="clear_if_allowed")
        if nmode not in {"clear", "hash", "clear_if_allowed"}:
            nmode = "clear_if_allowed"
        object.__setattr__(self, "expose_name_mode", nmode)

        allow_profiles = _normalize_str_tuple(self.allow_clear_uuid_profiles, max_len=16, max_items=8, lower=False)
        fixed_profiles: List[str] = []
        for p in allow_profiles:
            up = p.upper()
            if up in _ALLOWED_PROFILES and up not in fixed_profiles:
                fixed_profiles.append(up)
        object.__setattr__(self, "allow_clear_uuid_profiles", tuple(fixed_profiles) or ("DEV",))

        allow_name_profiles = _normalize_str_tuple(self.allow_clear_name_profiles, max_len=16, max_items=8, lower=False)
        fixed_name_profiles: List[str] = []
        for p in allow_name_profiles:
            up = p.upper()
            if up in _ALLOWED_PROFILES and up not in fixed_name_profiles:
                fixed_name_profiles.append(up)
        object.__setattr__(self, "allow_clear_name_profiles", tuple(fixed_name_profiles) or ("DEV",))

        ukey = self.uuid_hash_key
        if isinstance(ukey, str):
            ukey = _parse_key_material(ukey)
        if ukey is not None and len(ukey) < max(8, int(self.min_hash_key_bytes)):
            ukey = None
        object.__setattr__(self, "uuid_hash_key", ukey)

        nkey = self.name_hash_key
        if isinstance(nkey, str):
            nkey = _parse_key_material(nkey)
        if nkey is not None and len(nkey) < max(8, int(self.min_hash_key_bytes)):
            nkey = None
        object.__setattr__(self, "name_hash_key", nkey)

        object.__setattr__(self, "uuid_hash_key_id", _safe_text_or_none(self.uuid_hash_key_id, max_len=16))
        object.__setattr__(self, "name_hash_key_id", _safe_text_or_none(self.name_hash_key_id, max_len=16))
        object.__setattr__(self, "min_hash_key_bytes", max(8, min(4096, int(self.min_hash_key_bytes))))
        object.__setattr__(self, "uuid_hash_hex_chars", max(8, min(64, int(self.uuid_hash_hex_chars))))
        object.__setattr__(self, "name_hash_hex_chars", max(8, min(64, int(self.name_hash_hex_chars))))
        object.__setattr__(self, "cache_ttl_ms", max(0, min(60_000, int(self.cache_ttl_ms))))
        object.__setattr__(self, "max_staleness_ms", max(0, min(600_000, int(self.max_staleness_ms))))
        object.__setattr__(self, "cache_on_error", bool(self.cache_on_error))
        object.__setattr__(self, "max_extra_items", max(1, min(256, int(self.max_extra_items))))
        object.__setattr__(self, "max_extra_key_len", max(8, min(128, int(self.max_extra_key_len))))
        object.__setattr__(self, "max_extra_str_len", max(32, min(4096, int(self.max_extra_str_len))))
        object.__setattr__(self, "max_batch_devices", max(1, min(128, int(self.max_batch_devices))))
        allow_extra = _normalize_str_tuple(self.allowed_extra_keys, max_len=64, max_items=256, lower=True)
        object.__setattr__(self, "allowed_extra_keys", allow_extra or tuple(_DEFAULT_EXTRA_ALLOWLIST))
        object.__setattr__(self, "enforce_expected_uuid_in_strict", bool(self.enforce_expected_uuid_in_strict))
        object.__setattr__(self, "enforce_expected_vendor_in_strict", bool(self.enforce_expected_vendor_in_strict))
        object.__setattr__(self, "driver_version_must_match_policy", bool(self.driver_version_must_match_policy))
        object.__setattr__(self, "enable_collection_negative_evidence", bool(self.enable_collection_negative_evidence))
        object.__setattr__(self, "enable_attestor_bridge", bool(self.enable_attestor_bridge))
        object.__setattr__(self, "compatibility_epoch", _safe_text(self.compatibility_epoch, max_len=32) or _COMPATIBILITY_EPOCH)

    @classmethod
    def from_env(cls) -> "GpuTelemetryConfig":
        def _env(name: str, default: str) -> str:
            raw = os.getenv(name)
            return default if raw is None else str(raw).strip()

        def _env_bool(name: str, default: bool) -> bool:
            raw = os.getenv(name)
            if raw is None:
                return default
            return str(raw).strip().lower() in {"1", "true", "yes", "y", "on"}

        def _env_int(name: str, default: int) -> int:
            raw = os.getenv(name)
            if raw is None:
                return default
            try:
                return int(str(raw).strip())
            except Exception:
                return default

        return cls(
            profile=_env("TCD_GPU_PROFILE", "PROD"),
            compatibility_epoch=_env("TCD_GPU_COMPATIBILITY_EPOCH", _COMPATIBILITY_EPOCH),
            enable=_env_bool("TCD_GPU_ENABLE", True),
            backend_preference=_env("TCD_GPU_BACKEND", "auto"),
            expose_uuid_mode=_env("TCD_GPU_EXPOSE_UUID_MODE", "clear_if_allowed"),
            expose_name_mode=_env("TCD_GPU_EXPOSE_NAME_MODE", "clear_if_allowed"),
            allow_clear_uuid_profiles=tuple(x for x in _env("TCD_GPU_ALLOW_CLEAR_UUID_PROFILES", "DEV").split(",") if x.strip()),
            allow_clear_name_profiles=tuple(x for x in _env("TCD_GPU_ALLOW_CLEAR_NAME_PROFILES", "DEV").split(",") if x.strip()),
            uuid_hash_key=_parse_key_material(_env("TCD_GPU_UUID_HASH_KEY", "")),
            uuid_hash_key_id=_env("TCD_GPU_UUID_HASH_KEY_ID", "") or None,
            name_hash_key=_parse_key_material(_env("TCD_GPU_NAME_HASH_KEY", "")),
            name_hash_key_id=_env("TCD_GPU_NAME_HASH_KEY_ID", "") or None,
            min_hash_key_bytes=_env_int("TCD_GPU_MIN_HASH_KEY_BYTES", 16),
            uuid_hash_hex_chars=_env_int("TCD_GPU_UUID_HASH_HEX_CHARS", 24),
            name_hash_hex_chars=_env_int("TCD_GPU_NAME_HASH_HEX_CHARS", 24),
            cache_ttl_ms=_env_int("TCD_GPU_CACHE_TTL_MS", 250),
            max_staleness_ms=_env_int("TCD_GPU_MAX_STALENESS_MS", 3000),
            max_extra_items=_env_int("TCD_GPU_MAX_EXTRA_ITEMS", 64),
            max_extra_key_len=_env_int("TCD_GPU_MAX_EXTRA_KEY_LEN", 64),
            max_extra_str_len=_env_int("TCD_GPU_MAX_EXTRA_STR_LEN", 256),
            max_batch_devices=_env_int("TCD_GPU_MAX_BATCH_DEVICES", 32),
            enforce_expected_uuid_in_strict=_env_bool("TCD_GPU_ENFORCE_EXPECTED_UUID_STRICT", True),
            enforce_expected_vendor_in_strict=_env_bool("TCD_GPU_ENFORCE_EXPECTED_VENDOR_STRICT", True),
            driver_version_must_match_policy=_env_bool("TCD_GPU_ENFORCE_DRIVER_MATCH", False),
            enable_collection_negative_evidence=_env_bool("TCD_GPU_ENABLE_NEGATIVE_EVIDENCE", True),
            enable_attestor_bridge=_env_bool("TCD_GPU_ENABLE_ATTESTOR_BRIDGE", True),
        )

    def cfg_fingerprint(self) -> str:
        payload = {
            "profile": self.profile,
            "compatibility_epoch": self.compatibility_epoch,
            "enable": self.enable,
            "backend_preference": self.backend_preference,
            "expose_uuid_mode": self.expose_uuid_mode,
            "expose_name_mode": self.expose_name_mode,
            "allow_clear_uuid_profiles": list(self.allow_clear_uuid_profiles),
            "allow_clear_name_profiles": list(self.allow_clear_name_profiles),
            "uuid_hash_key_id": self.uuid_hash_key_id,
            "uuid_hash_key_present": self.uuid_hash_key is not None,
            "name_hash_key_id": self.name_hash_key_id,
            "name_hash_key_present": self.name_hash_key is not None,
            "cache_ttl_ms": self.cache_ttl_ms,
            "max_staleness_ms": self.max_staleness_ms,
            "max_extra_items": self.max_extra_items,
            "max_extra_key_len": self.max_extra_key_len,
            "max_extra_str_len": self.max_extra_str_len,
            "max_batch_devices": self.max_batch_devices,
            "allowed_extra_keys": list(self.allowed_extra_keys),
            "enforce_expected_uuid_in_strict": self.enforce_expected_uuid_in_strict,
            "enforce_expected_vendor_in_strict": self.enforce_expected_vendor_in_strict,
            "driver_version_must_match_policy": self.driver_version_must_match_policy,
            "enable_collection_negative_evidence": self.enable_collection_negative_evidence,
            "enable_attestor_bridge": self.enable_attestor_bridge,
        }
        return f"{_CFG_FP_VERSION}:{_hash_hex(ctx='tcd:gpu:config', payload=payload, out_hex=32)}"


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
    bundle_version: Optional[int] = None

    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None
    selected_source: Optional[str] = "gpu_sampler"
    controller_mode: Optional[str] = None
    decision_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None
    activation_id: Optional[str] = None
    patch_id: Optional[str] = None
    change_ticket_id: Optional[str] = None

    expected_vendor: str = "nvidia"
    expected_uuids: Optional[Any] = None
    expected_name_prefixes: Optional[Any] = None
    min_device_count: Optional[int] = None
    max_device_count: Optional[int] = None

    max_temp_c: float = 90.0
    max_ecc_errors: int = 0
    max_power_w: Optional[float] = None
    min_total_mem_mib: Optional[float] = None

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

        expected_name_prefixes: List[str] = []
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
            bundle_version=max(0, _coerce_int(self.bundle_version)) if _coerce_int(self.bundle_version) is not None else None,
            state_domain_id=_safe_id(self.state_domain_id, default=None, max_len=256),
            adapter_registry_fp=_safe_id(self.adapter_registry_fp, default=None, max_len=256),
            selected_source=_safe_label(self.selected_source, default="") or None if self.selected_source is not None else None,
            controller_mode=cm,
            decision_mode=dm,
            statistical_guarantee_scope=gs,
            activation_id=_safe_id(self.activation_id, default=None, max_len=256),
            patch_id=_safe_id(self.patch_id, default=None, max_len=256),
            change_ticket_id=_safe_id(self.change_ticket_id, default=None, max_len=256),
            expected_vendor=_safe_label(self.expected_vendor, default="nvidia"),
            expected_uuids=tuple(expected_uuids) if expected_uuids else None,
            expected_name_prefixes=tuple(expected_name_prefixes) if expected_name_prefixes else None,
            min_device_count=max(0, _coerce_int(self.min_device_count)) if _coerce_int(self.min_device_count) is not None else None,
            max_device_count=max(0, _coerce_int(self.max_device_count)) if _coerce_int(self.max_device_count) is not None else None,
            max_temp_c=max(0.0, _coerce_float(self.max_temp_c) or 90.0),
            max_ecc_errors=max(0, _coerce_int(self.max_ecc_errors) or 0),
            max_power_w=max(0.0, _coerce_float(self.max_power_w)) if _coerce_float(self.max_power_w) is not None else None,
            min_total_mem_mib=max(0.0, _coerce_float(self.min_total_mem_mib)) if _coerce_float(self.min_total_mem_mib) is not None else None,
            pq_required=bool(self.pq_required),
            pq_ok=_coerce_bool(self.pq_ok),
            pq_chain_id=_safe_text(self.pq_chain_id, max_len=128),
            pq_signature_required=_coerce_bool(self.pq_signature_required),
            pq_signature_ok=_coerce_bool(self.pq_signature_ok),
            audit_ref=_safe_id(self.audit_ref, default=None, max_len=256),
            receipt_ref=_safe_id(self.receipt_ref, default=None, max_len=256),
            produced_by=_normalize_str_tuple(self.produced_by, max_len=64, max_items=16),
        )

    def policy_digest_or_derived(self) -> str:
        if self.policy_digest:
            return self.policy_digest
        payload = {
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "cfg_fp": self.cfg_fp,
            "state_domain_id": self.state_domain_id,
            "adapter_registry_fp": self.adapter_registry_fp,
            "selected_source": self.selected_source,
            "controller_mode": self.controller_mode,
            "decision_mode": self.decision_mode,
            "statistical_guarantee_scope": self.statistical_guarantee_scope,
            "trust_zone": self.trust_zone,
            "route_profile": self.route_profile,
        }
        return f"sha256:{_hash_hex(ctx='tcd:gpu:policy', payload=payload, out_hex=64)}"


# =============================================================================
# Observation / assessment / evidence objects
# =============================================================================

@dataclass(frozen=True, slots=True)
class GpuRawObservation:
    index: int
    ts: float
    ts_unix_ns: int
    ts_monotonic_ns: int

    backend: str
    backend_state: str

    observed_vendor: str
    driver_version_observed: Optional[str]

    uuid_raw: Optional[str]
    name_raw: Optional[str]
    pci_bus_id: Optional[str]
    minor_number: Optional[int]

    util_pct: Optional[float]
    mem_util_pct: Optional[float]
    mem_used_mib: Optional[float]
    mem_total_mib: Optional[float]
    mem_free_mib: Optional[float]
    temp_c: Optional[float]
    power_w: Optional[float]
    power_limit_w: Optional[float]
    fan_pct: Optional[float]
    compute_mode_raw: Optional[str]

    ecc_errors_total: Optional[int]
    ecc_corrected_total: Optional[int]
    ecc_uncorrected_total: Optional[int]
    ecc_mode_enabled: Optional[bool]

    retired_pages_count: Optional[int]
    row_remap_failure_count: Optional[int]
    perf_state: Optional[str]
    throttle_reasons: Tuple[str, ...]
    power_state: Optional[str]
    persistence_mode: Optional[bool]
    mig_mode: Optional[str]
    mig_parent_uuid_raw: Optional[str]
    mig_instance_id: Optional[str]
    compute_capability: Optional[str]
    xid_recent: Optional[str]

    partial_fields: Tuple[str, ...] = field(default_factory=tuple)
    read_errors: Tuple[str, ...] = field(default_factory=tuple)
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class GpuNormalizedObservation:
    index: int
    ts: float
    ts_unix_ns: int
    ts_monotonic_ns: int

    backend: str
    collection_state: str
    backend_state: str

    observed_vendor: str
    driver_version_observed: Optional[str]
    driver_version_expected: Optional[str]
    driver_version_match_state: str

    uuid_raw: Optional[str]
    name_raw: Optional[str]
    uuid_hash: Optional[str]
    uuid_public: str
    uuid_exposed: bool
    name_hash: Optional[str]
    name_public: str
    name_exposed: bool

    pci_bus_id: Optional[str]
    minor_number: Optional[int]
    mig_parent_uuid_hash: Optional[str]
    mig_instance_id: Optional[str]

    util_pct: float
    mem_util_pct: float
    mem_used_mib: float
    mem_total_mib: float
    mem_free_mib: float
    temp_c: float
    power_w: float
    power_limit_w: float
    fan_pct: float
    compute_mode: str

    ecc_errors_total: int
    ecc_corrected_total: int
    ecc_uncorrected_total: int
    ecc_mode_enabled: Optional[bool]

    retired_pages_count: int
    row_remap_failure_count: int
    perf_state: Optional[str]
    throttle_reasons: Tuple[str, ...]
    power_state: Optional[str]
    persistence_mode: Optional[bool]
    mig_mode: Optional[str]
    compute_capability: Optional[str]
    xid_recent: Optional[str]

    warnings: Tuple[str, ...] = field(default_factory=tuple)
    extra: Mapping[str, Any] = field(default_factory=dict)

    @property
    def mem_used_mb(self) -> float:
        return self.mem_used_mib

    @property
    def mem_total_mb(self) -> float:
        return self.mem_total_mib

    @property
    def mem_free_mb(self) -> float:
        return self.mem_free_mib


@dataclass(frozen=True, slots=True)
class GpuPolicyAssessment:
    assessment_version: str
    rulepack_fingerprint: str

    collection_integrity_ok: bool
    identity_integrity_ok: bool
    hardware_integrity_ok: bool
    policy_compliance_ok: bool
    overall_integrity_ok: bool

    collection_state: str
    health_state: str
    backend_state: str
    hw_integrity_state: str

    security_suspect: bool
    compliance_suspect: bool
    integrity_suspect: bool
    apt_suspect: bool
    apt_reason: str

    integrity_reason_codes: Tuple[str, ...]
    degraded_reason_codes: Tuple[str, ...]
    normalization_warnings: Tuple[str, ...]

    device_count_observed: int
    device_count_expected_min: Optional[int]
    device_count_expected_max: Optional[int]

    severity: str = "normal"

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class GpuSample:
    schema: str
    schema_version: int
    compatibility_epoch: str
    canonicalization_version: str

    event_id: str
    event_type: str
    sample_fingerprint: str
    observation_digest: str
    assessment_digest: str
    body_digest: str
    payload_digest: str
    event_digest: str

    index: int
    uuid: str
    uuid_hash: Optional[str]
    uuid_exposed: bool
    name: str
    name_hash: Optional[str]
    name_exposed: bool

    ts: float
    ts_unix_ns: int
    ts_monotonic_ns: int

    util_pct: float
    mem_used_mib: float
    mem_total_mib: float
    mem_free_mib: float
    mem_util_pct: float
    temp_c: float
    power_w: float
    power_limit_w: float
    fan_pct: float
    compute_mode: str
    ecc_errors_total: int

    backend: str
    collection_state: str
    health_state: str
    extra: Mapping[str, Any] = field(default_factory=dict)

    node_id: str = ""
    build_id: str = ""
    image_digest: str = ""
    driver_version_observed: str = ""
    driver_version_expected: Optional[str] = None
    driver_version_match_state: str = "unknown"
    runtime_env: str = ""

    trust_zone: str = "internet"
    route_profile: str = "inference"
    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    policy_digest: Optional[str] = None
    cfg_fp: Optional[str] = None
    bundle_version: Optional[int] = None

    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None
    selected_source: Optional[str] = None
    controller_mode: Optional[str] = None
    decision_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None
    activation_id: Optional[str] = None
    patch_id: Optional[str] = None
    change_ticket_id: Optional[str] = None

    observed_vendor: str = "unknown"
    hw_integrity_state: str = "unverified"
    collection_integrity_ok: bool = False
    identity_integrity_ok: bool = False
    hardware_integrity_ok: bool = False
    policy_compliance_ok: bool = False
    integrity_ok: bool = False
    integrity_reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    degraded_reason_codes: Tuple[str, ...] = field(default_factory=tuple)
    normalization_warnings: Tuple[str, ...] = field(default_factory=tuple)
    security_suspect: bool = False
    compliance_suspect: bool = False
    integrity_suspect: bool = False
    apt_suspect: bool = False
    apt_reason: str = ""
    severity: str = "normal"

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

    @property
    def mem_used_mb(self) -> float:
        return self.mem_used_mib

    @property
    def mem_total_mb(self) -> float:
        return self.mem_total_mib

    @property
    def mem_free_mb(self) -> float:
        return self.mem_free_mib

    def to_body_payload(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "compatibility_epoch": self.compatibility_epoch,
            "canonicalization_version": self.canonicalization_version,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "index": self.index,
            "uuid_hash": self.uuid_hash,
            "name_hash": self.name_hash,
            "uuid_exposed": self.uuid_exposed,
            "name_exposed": self.name_exposed,
            "uuid": self.uuid,
            "name": self.name,
            "ts": self.ts,
            "ts_unix_ns": self.ts_unix_ns,
            "ts_monotonic_ns": self.ts_monotonic_ns,
            "backend": self.backend,
            "collection_state": self.collection_state,
            "health_state": self.health_state,
            "util_pct": self.util_pct,
            "mem_used_mib": self.mem_used_mib,
            "mem_total_mib": self.mem_total_mib,
            "mem_free_mib": self.mem_free_mib,
            "mem_util_pct": self.mem_util_pct,
            "temp_c": self.temp_c,
            "power_w": self.power_w,
            "power_limit_w": self.power_limit_w,
            "fan_pct": self.fan_pct,
            "compute_mode": self.compute_mode,
            "ecc_errors_total": self.ecc_errors_total,
            "observed_vendor": self.observed_vendor,
            "driver_version_observed": self.driver_version_observed,
            "driver_version_expected": self.driver_version_expected,
            "driver_version_match_state": self.driver_version_match_state,
            "node_id": self.node_id,
            "build_id": self.build_id,
            "image_digest": self.image_digest,
            "runtime_env": self.runtime_env,
            "trust_zone": self.trust_zone,
            "route_profile": self.route_profile,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "cfg_fp": self.cfg_fp,
            "bundle_version": self.bundle_version,
            "state_domain_id": self.state_domain_id,
            "adapter_registry_fp": self.adapter_registry_fp,
            "selected_source": self.selected_source,
            "controller_mode": self.controller_mode,
            "decision_mode": self.decision_mode,
            "statistical_guarantee_scope": self.statistical_guarantee_scope,
            "activation_id": self.activation_id,
            "patch_id": self.patch_id,
            "change_ticket_id": self.change_ticket_id,
            "hw_integrity_state": self.hw_integrity_state,
            "collection_integrity_ok": self.collection_integrity_ok,
            "identity_integrity_ok": self.identity_integrity_ok,
            "hardware_integrity_ok": self.hardware_integrity_ok,
            "policy_compliance_ok": self.policy_compliance_ok,
            "integrity_ok": self.integrity_ok,
            "integrity_reason_codes": list(self.integrity_reason_codes),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "normalization_warnings": list(self.normalization_warnings),
            "security_suspect": self.security_suspect,
            "compliance_suspect": self.compliance_suspect,
            "integrity_suspect": self.integrity_suspect,
            "apt_suspect": self.apt_suspect,
            "apt_reason": self.apt_reason,
            "severity": self.severity,
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

    def to_dict(self, *, flatten_extra: bool = True, include_internal: bool = False) -> Dict[str, Any]:
        out = self.to_body_payload()
        out["gpu_util"] = self.util_pct
        out["gpu_util_pct"] = self.util_pct
        out["gpu_mem_used_mib"] = self.mem_used_mib
        out["gpu_mem_total_mib"] = self.mem_total_mib
        out["gpu_mem_free_mib"] = self.mem_free_mib
        out["gpu_mem_used_mb"] = self.mem_used_mib
        out["gpu_mem_total_mb"] = self.mem_total_mib
        out["gpu_mem_free_mb"] = self.mem_free_mib
        out["gpu_temp_c"] = self.temp_c
        out["gpu_power_w"] = self.power_w
        out["gpu_health_level"] = self.health_state
        out["observation_digest"] = self.observation_digest
        out["assessment_digest"] = self.assessment_digest
        out["body_digest"] = self.body_digest
        out["payload_digest"] = self.payload_digest
        out["event_digest"] = self.event_digest
        if flatten_extra:
            for k, v in self.extra.items():
                if k not in out:
                    out[k] = v
        if not include_internal:
            out.pop("policy_digest", None)
            out.pop("cfg_fp", None)
            out.pop("image_digest", None)
        return out

    def to_public_dict(self) -> Dict[str, Any]:
        return self.to_dict(flatten_extra=True, include_internal=False)

    def to_audit_dict(self) -> Dict[str, Any]:
        return self.to_dict(flatten_extra=False, include_internal=True)

    def to_storage_meta(self) -> Dict[str, Any]:
        return {
            "gpu_event_id": self.event_id,
            "gpu_index": self.index,
            "gpu_uuid_hash": self.uuid_hash,
            "gpu_name_hash": self.name_hash,
            "gpu_name": self.name if self.name_exposed else "",
            "gpu_backend": self.backend,
            "gpu_collection_state": self.collection_state,
            "gpu_health_state": self.health_state,
            "gpu_hw_integrity_state": self.hw_integrity_state,
            "gpu_util_pct": self.util_pct,
            "gpu_mem_used_mib": self.mem_used_mib,
            "gpu_mem_total_mib": self.mem_total_mib,
            "gpu_temp_c": self.temp_c,
            "gpu_power_w": self.power_w,
            "gpu_power_limit_w": self.power_limit_w,
            "gpu_fan_pct": self.fan_pct,
            "gpu_compute_mode": self.compute_mode,
            "gpu_ecc_errors_total": self.ecc_errors_total,
            "gpu_apt_suspect": self.apt_suspect,
            "gpu_apt_reason": self.apt_reason,
            "gpu_policy_ref": self.policy_ref,
            "gpu_state_domain_id": self.state_domain_id,
            "gpu_adapter_registry_fp": self.adapter_registry_fp,
            "gpu_selected_source": self.selected_source,
            "gpu_controller_mode": self.controller_mode,
            "gpu_statistical_guarantee_scope": self.statistical_guarantee_scope,
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
            "bundle_version": self.bundle_version,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "state_domain_id": self.state_domain_id,
            "activation_id": self.activation_id,
            "patch_id": self.patch_id,
            "change_ticket_id": self.change_ticket_id,
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
            "body_digest": self.body_digest,
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

    def to_receipt_claims(self, *, chain_namespace: str = "telemetry", chain_id: Optional[str] = None, prev_head_hex: Optional[str] = None) -> Dict[str, Any]:
        cid = _safe_id(chain_id, default=None, max_len=128) or (_safe_id(self.node_id, default=None, max_len=128) or "gpu")
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "compatibility_epoch": self.compatibility_epoch,
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
            "trigger": self.apt_suspect or self.integrity_suspect,
            "allowed": not (self.apt_suspect or self.integrity_suspect),
            "reason": self.apt_reason or self.health_state,
            "produced_by": list(self.produced_by),
            "provenance_path_digest": self.provenance_path_digest,
            "payload_digest": self.payload_digest,
            "event_digest": self.event_digest,
            "meta": self.to_storage_meta(),
        }

    def to_receipt_claims_json(self, *, chain_namespace: str = "telemetry", chain_id: Optional[str] = None, prev_head_hex: Optional[str] = None) -> str:
        return _canonical_json_str(self.to_receipt_claims(chain_namespace=chain_namespace, chain_id=chain_id, prev_head_hex=prev_head_hex))

    def issue_attestation(self, attestor: Any) -> Optional[Dict[str, Any]]:
        if attestor is None or not callable(getattr(attestor, "issue", None)):
            return None
        claims = self.to_receipt_claims()
        meta = {
            "_tcd_event_id": self.event_id,
            "_tcd_ts_ns": self.ts_unix_ns,
            "gpu_sample_fingerprint": self.sample_fingerprint,
            "body_digest": self.body_digest,
            "payload_digest": self.payload_digest,
        }
        with contextlib.suppress(Exception):
            return attestor.issue(
                req_obj={"event_id": self.event_id, "source": "gpu_sampler"},
                comp_obj=claims,
                e_obj=self.to_storage_meta(),
                witness_segments=None,
                witness_tags=("gpu", "telemetry"),
                meta=meta,
            )
        return None


@dataclass(frozen=True, slots=True)
class GpuHostSnapshot:
    schema: str
    schema_version: int
    compatibility_epoch: str
    collection_id: str
    ts_unix_ns: int
    node_id: str
    build_id: str
    image_digest: str
    device_count_observed: int
    device_count_expected_min: Optional[int]
    device_count_expected_max: Optional[int]
    collection_state: str
    backend_state: str
    warnings: Tuple[str, ...]
    collection_errors: Tuple[str, ...]
    batch_digest: str
    collection_latency_ms: float
    partial_collection: bool
    samples: Tuple[GpuSample, ...]

    def to_dict(self, *, include_samples: bool = True) -> Dict[str, Any]:
        out = {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "compatibility_epoch": self.compatibility_epoch,
            "collection_id": self.collection_id,
            "ts_unix_ns": self.ts_unix_ns,
            "node_id": self.node_id,
            "build_id": self.build_id,
            "image_digest": self.image_digest,
            "device_count_observed": self.device_count_observed,
            "device_count_expected_min": self.device_count_expected_min,
            "device_count_expected_max": self.device_count_expected_max,
            "collection_state": self.collection_state,
            "backend_state": self.backend_state,
            "warnings": list(self.warnings),
            "collection_errors": list(self.collection_errors),
            "batch_digest": self.batch_digest,
            "collection_latency_ms": self.collection_latency_ms,
            "partial_collection": self.partial_collection,
        }
        if include_samples:
            out["samples"] = [s.to_public_dict() for s in self.samples]
        return out

    def to_public_dict(self) -> Dict[str, Any]:
        return self.to_dict(include_samples=True)

    def to_audit_dict(self) -> Dict[str, Any]:
        return {
            **self.to_dict(include_samples=False),
            "samples": [s.to_audit_dict() for s in self.samples],
        }


@dataclass(frozen=True, slots=True)
class GpuSamplerHealth:
    backend: str
    available: bool
    device_count: int
    driver_version: Optional[str]
    health_state: str
    warnings: Tuple[str, ...]
    cfg_fp: Optional[str] = None
    capabilities: Mapping[str, bool] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "backend": self.backend,
            "available": self.available,
            "device_count": self.device_count,
            "driver_version": self.driver_version,
            "health_state": self.health_state,
            "warnings": list(self.warnings),
            "cfg_fp": self.cfg_fp,
            "capabilities": dict(self.capabilities),
        }


# =============================================================================
# Runtime / backend manager
# =============================================================================

class _NvmlRuntime:
    _lock = threading.RLock()
    _initialized = False
    _last_init_attempt = 0.0
    _last_init_error: Optional[str] = None
    _consecutive_failures = 0
    _driver_version: Optional[str] = None
    _device_count = 0
    _capabilities: Dict[str, bool] = {}
    _handles: Dict[int, Any] = {}
    _retry_backoff_s = 1.0

    @classmethod
    def ensure_initialized(cls, *, force_refresh: bool = False) -> bool:
        if not _NVML_AVAILABLE:
            with cls._lock:
                cls._last_init_error = "nvml_library_missing"
                cls._capabilities = {}
            return False

        now = time.monotonic()
        with cls._lock:
            if cls._initialized and not force_refresh:
                return True
            if (not force_refresh) and cls._last_init_attempt and (now - cls._last_init_attempt) < cls._retry_backoff_s:
                return cls._initialized
            cls._last_init_attempt = now

        try:
            pynvml.nvmlInit()  # type: ignore[union-attr]
            driver_version: Optional[str] = None
            with contextlib.suppress(Exception):
                dv = pynvml.nvmlSystemGetDriverVersion()  # type: ignore[union-attr]
                driver_version = dv.decode("utf-8", errors="ignore") if isinstance(dv, bytes) else str(dv)
            device_count = 0
            with contextlib.suppress(Exception):
                device_count = int(pynvml.nvmlDeviceGetCount())  # type: ignore[union-attr]

            caps = {
                "uuid": True,
                "name": True,
                "util": True,
                "memory": True,
                "temperature": True,
                "power": True,
                "fan": True,
                "ecc": True,
                "clock": True,
                "mig": True,
            }

            if device_count > 0:
                h0 = pynvml.nvmlDeviceGetHandleByIndex(0)  # type: ignore[union-attr]
                for name, fn in (
                    ("uuid", lambda: pynvml.nvmlDeviceGetUUID(h0)),  # type: ignore[union-attr]
                    ("name", lambda: pynvml.nvmlDeviceGetName(h0)),  # type: ignore[union-attr]
                    ("util", lambda: pynvml.nvmlDeviceGetUtilizationRates(h0)),  # type: ignore[union-attr]
                    ("memory", lambda: pynvml.nvmlDeviceGetMemoryInfo(h0)),  # type: ignore[union-attr]
                    ("temperature", lambda: pynvml.nvmlDeviceGetTemperature(h0, pynvml.NVML_TEMPERATURE_GPU)),  # type: ignore[union-attr]
                    ("power", lambda: pynvml.nvmlDeviceGetPowerUsage(h0)),  # type: ignore[union-attr]
                    ("fan", lambda: pynvml.nvmlDeviceGetFanSpeed(h0)),  # type: ignore[union-attr]
                ):
                    try:
                        fn()
                    except Exception:
                        caps[name] = False
                try:
                    pynvml.nvmlDeviceGetTotalEccErrors(  # type: ignore[union-attr]
                        h0,
                        pynvml.NVML_MEMORY_ERROR_TYPE_UNCORRECTED,  # type: ignore[union-attr]
                        pynvml.NVML_VOLATILE_ECC,  # type: ignore[union-attr]
                    )
                except Exception:
                    caps["ecc"] = False
                try:
                    pynvml.nvmlDeviceGetClockInfo(h0, pynvml.NVML_CLOCK_SM)  # type: ignore[union-attr]
                except Exception:
                    caps["clock"] = False

            with cls._lock:
                cls._initialized = True
                cls._driver_version = driver_version
                cls._device_count = max(0, int(device_count))
                cls._capabilities = caps
                cls._last_init_error = None
                cls._consecutive_failures = 0
                cls._retry_backoff_s = 1.0
                cls._handles = {}
            return True
        except Exception as exc:
            with cls._lock:
                cls._initialized = False
                cls._driver_version = None
                cls._device_count = 0
                cls._capabilities = {}
                cls._handles = {}
                cls._last_init_error = _safe_text(exc, max_len=128)
                cls._consecutive_failures += 1
                cls._retry_backoff_s = min(30.0, max(1.0, 2.0 ** min(cls._consecutive_failures, 4)))
            logger.warning("NVML initialization failed: %r", exc)
            return False

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
    def capabilities(cls) -> Dict[str, bool]:
        if not cls.ensure_initialized():
            return {}
        with cls._lock:
            return dict(cls._capabilities)

    @classmethod
    def last_init_error(cls) -> Optional[str]:
        with cls._lock:
            return cls._last_init_error

    @classmethod
    def handle(cls, index: int) -> Any:
        if not cls.ensure_initialized():
            return None
        idx = max(0, int(index))
        with cls._lock:
            if idx in cls._handles:
                return cls._handles[idx]
        try:
            h = pynvml.nvmlDeviceGetHandleByIndex(idx)  # type: ignore[union-attr]
        except Exception:
            return None
        with cls._lock:
            cls._handles[idx] = h
        return h


# =============================================================================
# Base sampler
# =============================================================================

class BaseGpuSampler(ABC):
    def __init__(self, *, policy: Optional[GpuSamplerPolicy] = None, config: Optional[GpuTelemetryConfig] = None) -> None:
        self._cfg = config or GpuTelemetryConfig()
        self._policy = (policy or GpuSamplerPolicy()).normalized(cfg=self._cfg)

    @abstractmethod
    def sample_raw(self) -> GpuRawObservation:
        ...

    def sample_raw_all(self) -> List[GpuRawObservation]:
        return [self.sample_raw()]

    def health(self) -> GpuSamplerHealth:
        return GpuSamplerHealth(
            backend="unknown",
            available=False,
            device_count=0,
            driver_version=self._policy.driver_version or None,
            health_state="unknown",
            warnings=tuple(),
            cfg_fp=self._policy.cfg_fp,
            capabilities={},
        )


# =============================================================================
# Dummy implementation
# =============================================================================

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

    def sample_raw(self) -> GpuRawObservation:
        ts = now_ts()
        ts_ns = now_unix_ns()
        mono_ns = time.monotonic_ns()
        partial = tuple(self._reason_codes)
        return GpuRawObservation(
            index=self._index,
            ts=ts,
            ts_unix_ns=ts_ns,
            ts_monotonic_ns=mono_ns,
            backend=self._backend_label,
            backend_state=self._health_state,
            observed_vendor="unknown" if self._backend_label == "dummy" else "nvidia",
            driver_version_observed=None,
            uuid_raw=None,
            name_raw=None,
            pci_bus_id=None,
            minor_number=None,
            util_pct=0.0,
            mem_util_pct=0.0,
            mem_used_mib=0.0,
            mem_total_mib=0.0,
            mem_free_mib=0.0,
            temp_c=0.0,
            power_w=0.0,
            power_limit_w=0.0,
            fan_pct=0.0,
            compute_mode_raw="unknown",
            ecc_errors_total=0,
            ecc_corrected_total=0,
            ecc_uncorrected_total=0,
            ecc_mode_enabled=None,
            retired_pages_count=0,
            row_remap_failure_count=0,
            perf_state=None,
            throttle_reasons=tuple(),
            power_state=None,
            persistence_mode=None,
            mig_mode=None,
            mig_parent_uuid_raw=None,
            mig_instance_id=None,
            compute_capability=None,
            xid_recent=None,
            partial_fields=partial,
            read_errors=partial,
            extra=MappingProxyType({}),
        )

    def sample_raw_all(self) -> List[GpuRawObservation]:
        return [self.sample_raw()]

    def health(self) -> GpuSamplerHealth:
        return GpuSamplerHealth(
            backend=self._backend_label,
            available=(self._health_state in {"ok", "degraded"}),
            device_count=0,
            driver_version=self._policy.driver_version or None,
            health_state=self._health_state,
            warnings=self._reason_codes,
            cfg_fp=self._policy.cfg_fp,
            capabilities={},
        )


# =============================================================================
# NVML implementation
# =============================================================================

_NVML_COMPUTE_MODE_MAP = {
    0: "default",
    1: "exclusive_thread",
    2: "prohibited",
    3: "exclusive_process",
}

class NvmlGpuSampler(BaseGpuSampler):
    def __init__(self, index: int = 0, *, policy: Optional[GpuSamplerPolicy] = None, config: Optional[GpuTelemetryConfig] = None) -> None:
        if not _NVML_AVAILABLE:
            raise RuntimeError("pynvml unavailable")
        super().__init__(policy=policy, config=config)
        self._index = int(index)

    def _read_identity(self, handle: Any) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        with contextlib.suppress(Exception):
            u = pynvml.nvmlDeviceGetUUID(handle)  # type: ignore[union-attr]
            out["uuid_raw"] = u.decode("utf-8", errors="ignore") if isinstance(u, bytes) else str(u)
        with contextlib.suppress(Exception):
            n = pynvml.nvmlDeviceGetName(handle)  # type: ignore[union-attr]
            out["name_raw"] = n.decode("utf-8", errors="ignore") if isinstance(n, bytes) else str(n)
        with contextlib.suppress(Exception):
            out["pci_bus_id"] = str(pynvml.nvmlDeviceGetPciInfo(handle).busId)  # type: ignore[union-attr]
        with contextlib.suppress(Exception):
            out["minor_number"] = int(pynvml.nvmlDeviceGetMinorNumber(handle))  # type: ignore[union-attr]
        return out

    def _read_util(self, handle: Any) -> Dict[str, Any]:
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)  # type: ignore[union-attr]
        return {
            "util_pct": _clamp_float(getattr(util, "gpu", 0.0), default=0.0, lo=0.0, hi=100.0),
            "mem_util_pct": _clamp_float(getattr(util, "memory", 0.0), default=0.0, lo=0.0, hi=100.0),
        }

    def _read_memory(self, handle: Any) -> Dict[str, Any]:
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)  # type: ignore[union-attr]
        used_b = max(0, int(getattr(mem, "used", 0)))
        total_b = max(0, int(getattr(mem, "total", 0)))
        free_b = max(0, int(getattr(mem, "free", max(0, total_b - used_b))))
        return {
            "mem_used_mib": _clamp_float(used_b / (1024 * 1024), default=0.0, lo=0.0, hi=1_000_000_000.0),
            "mem_total_mib": _clamp_float(total_b / (1024 * 1024), default=0.0, lo=0.0, hi=1_000_000_000.0),
            "mem_free_mib": _clamp_float(free_b / (1024 * 1024), default=0.0, lo=0.0, hi=1_000_000_000.0),
        }

    def _read_temperature(self, handle: Any) -> Dict[str, Any]:
        return {
            "temp_c": _clamp_float(
                pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU),  # type: ignore[union-attr]
                default=0.0,
                lo=0.0,
                hi=200.0,
            )
        }

    def _read_power(self, handle: Any) -> Dict[str, Any]:
        return {
            "power_w": _clamp_float(pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0, default=0.0, lo=0.0, hi=1_000_000.0),  # type: ignore[union-attr]
            "power_limit_w": _clamp_float(pynvml.nvmlDeviceGetEnforcedPowerLimit(handle) / 1000.0, default=0.0, lo=0.0, hi=1_000_000.0),  # type: ignore[union-attr]
        }

    def _read_fan(self, handle: Any) -> Dict[str, Any]:
        return {
            "fan_pct": _clamp_float(pynvml.nvmlDeviceGetFanSpeed(handle), default=0.0, lo=0.0, hi=100.0)  # type: ignore[union-attr]
        }

    def _read_compute_mode(self, handle: Any) -> Dict[str, Any]:
        try:
            mode = int(pynvml.nvmlDeviceGetComputeMode(handle))  # type: ignore[union-attr]
            return {"compute_mode_raw": _NVML_COMPUTE_MODE_MAP.get(mode, "unknown")}
        except Exception:
            return {"compute_mode_raw": "unknown"}

    def _read_ecc(self, handle: Any) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        try:
            unc = int(
                pynvml.nvmlDeviceGetTotalEccErrors(  # type: ignore[union-attr]
                    handle,
                    pynvml.NVML_MEMORY_ERROR_TYPE_UNCORRECTED,  # type: ignore[union-attr]
                    pynvml.NVML_VOLATILE_ECC,  # type: ignore[union-attr]
                )
            )
            out["ecc_uncorrected_total"] = max(0, unc)
        except Exception:
            out["ecc_uncorrected_total"] = 0
        try:
            cor = int(
                pynvml.nvmlDeviceGetTotalEccErrors(  # type: ignore[union-attr]
                    handle,
                    pynvml.NVML_MEMORY_ERROR_TYPE_CORRECTED,  # type: ignore[union-attr]
                    pynvml.NVML_VOLATILE_ECC,  # type: ignore[union-attr]
                )
            )
            out["ecc_corrected_total"] = max(0, cor)
        except Exception:
            out["ecc_corrected_total"] = 0
        out["ecc_errors_total"] = max(0, int(out["ecc_corrected_total"]) + int(out["ecc_uncorrected_total"]))
        try:
            curr, _pend = pynvml.nvmlDeviceGetEccMode(handle)  # type: ignore[union-attr]
            out["ecc_mode_enabled"] = bool(curr)
        except Exception:
            out["ecc_mode_enabled"] = None
        return out

    def _read_extra(self, handle: Any) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        with contextlib.suppress(Exception):
            out["sm_clock_mhz"] = _clamp_float(pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_SM), default=0.0, lo=0.0, hi=100_000.0)  # type: ignore[union-attr]
        with contextlib.suppress(Exception):
            out["mem_clock_mhz"] = _clamp_float(pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_MEM), default=0.0, lo=0.0, hi=100_000.0)  # type: ignore[union-attr]
        with contextlib.suppress(Exception):
            out["graphics_clock_mhz"] = _clamp_float(pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_GRAPHICS), default=0.0, lo=0.0, hi=100_000.0)  # type: ignore[union-attr]
        with contextlib.suppress(Exception):
            out["temp_slowdown_c"] = _clamp_float(
                pynvml.nvmlDeviceGetTemperatureThreshold(handle, pynvml.NVML_TEMPERATURE_THRESHOLD_SLOWDOWN),  # type: ignore[union-attr]
                default=0.0,
                lo=0.0,
                hi=200.0,
            )
        with contextlib.suppress(Exception):
            out["perf_state"] = _safe_text(pynvml.nvmlDeviceGetPerformanceState(handle), max_len=32)  # type: ignore[union-attr]
        with contextlib.suppress(Exception):
            out["persistence_mode"] = bool(pynvml.nvmlDeviceGetPersistenceMode(handle))  # type: ignore[union-attr]
        return out

    def sample_raw(self) -> GpuRawObservation:
        raws = self.sample_raw_all()
        return raws[0]

    def sample_raw_all(self) -> List[GpuRawObservation]:
        if not _NvmlAvailable_or_init():
            return [
                DummyGpuSampler(
                    index=self._index,
                    health_state="down",
                    policy=self._policy,
                    config=self._cfg,
                    insider_override=False,
                    override_reason="",
                    backend_label="nvml",
                    reason_codes=("GPU_BACKEND_INIT_FAILED", "GPU_BACKEND_DOWN"),
                ).sample_raw()
            ]

        device_count = min(_NvmlRuntime.device_count(), self._cfg.max_batch_devices)
        if device_count <= 0:
            return [
                DummyGpuSampler(
                    index=self._index,
                    health_state="down",
                    policy=self._policy,
                    config=self._cfg,
                    insider_override=False,
                    override_reason="",
                    backend_label="nvml",
                    reason_codes=("GPU_BACKEND_DOWN",),
                ).sample_raw()
            ]

        results: List[GpuRawObservation] = []
        driver_version = _NvmlRuntime.driver_version()
        for idx in range(device_count):
            ts = now_ts()
            ts_ns = now_unix_ns()
            mono_ns = time.monotonic_ns()
            handle = _NvmlRuntime.handle(idx)
            if handle is None:
                results.append(
                    DummyGpuSampler(
                        index=idx,
                        health_state="down",
                        policy=self._policy,
                        config=self._cfg,
                        insider_override=False,
                        override_reason="",
                        backend_label="nvml",
                        reason_codes=("GPU_BACKEND_DOWN",),
                    ).sample_raw()
                )
                continue

            partial_fields: List[str] = []
            read_errors: List[str] = []
            acc: Dict[str, Any] = {
                "index": idx,
                "ts": ts,
                "ts_unix_ns": ts_ns,
                "ts_monotonic_ns": mono_ns,
                "backend": "nvml",
                "backend_state": "ok",
                "observed_vendor": "nvidia",
                "driver_version_observed": driver_version,
                "uuid_raw": None,
                "name_raw": None,
                "pci_bus_id": None,
                "minor_number": None,
                "util_pct": None,
                "mem_util_pct": None,
                "mem_used_mib": None,
                "mem_total_mib": None,
                "mem_free_mib": None,
                "temp_c": None,
                "power_w": None,
                "power_limit_w": None,
                "fan_pct": None,
                "compute_mode_raw": None,
                "ecc_errors_total": None,
                "ecc_corrected_total": None,
                "ecc_uncorrected_total": None,
                "ecc_mode_enabled": None,
                "retired_pages_count": 0,
                "row_remap_failure_count": 0,
                "perf_state": None,
                "throttle_reasons": tuple(),
                "power_state": None,
                "persistence_mode": None,
                "mig_mode": None,
                "mig_parent_uuid_raw": None,
                "mig_instance_id": None,
                "compute_capability": None,
                "xid_recent": None,
                "extra": {},
            }

            for reader_name, fn in (
                ("identity", self._read_identity),
                ("util", self._read_util),
                ("memory", self._read_memory),
                ("temperature", self._read_temperature),
                ("power", self._read_power),
                ("fan", self._read_fan),
                ("compute_mode", self._read_compute_mode),
                ("ecc", self._read_ecc),
                ("extra", self._read_extra),
            ):
                try:
                    vals = fn(handle)
                    for k, v in vals.items():
                        if k == "extra":
                            acc["extra"] = dict(v)
                        else:
                            acc[k] = v
                except Exception:
                    partial_fields.append(reader_name)
                    read_errors.append("GPU_PARTIAL_METRICS")

            if partial_fields:
                acc["backend_state"] = "degraded"

            results.append(
                GpuRawObservation(
                    index=idx,
                    ts=acc["ts"],
                    ts_unix_ns=acc["ts_unix_ns"],
                    ts_monotonic_ns=acc["ts_monotonic_ns"],
                    backend="nvml",
                    backend_state=acc["backend_state"],
                    observed_vendor="nvidia",
                    driver_version_observed=acc["driver_version_observed"],
                    uuid_raw=acc["uuid_raw"],
                    name_raw=acc["name_raw"],
                    pci_bus_id=acc["pci_bus_id"],
                    minor_number=acc["minor_number"],
                    util_pct=acc["util_pct"],
                    mem_util_pct=acc["mem_util_pct"],
                    mem_used_mib=acc["mem_used_mib"],
                    mem_total_mib=acc["mem_total_mib"],
                    mem_free_mib=acc["mem_free_mib"],
                    temp_c=acc["temp_c"],
                    power_w=acc["power_w"],
                    power_limit_w=acc["power_limit_w"],
                    fan_pct=acc["fan_pct"],
                    compute_mode_raw=acc["compute_mode_raw"],
                    ecc_errors_total=acc["ecc_errors_total"],
                    ecc_corrected_total=acc["ecc_corrected_total"],
                    ecc_uncorrected_total=acc["ecc_uncorrected_total"],
                    ecc_mode_enabled=acc["ecc_mode_enabled"],
                    retired_pages_count=acc["retired_pages_count"],
                    row_remap_failure_count=acc["row_remap_failure_count"],
                    perf_state=acc["perf_state"],
                    throttle_reasons=tuple(acc["throttle_reasons"]),
                    power_state=acc["power_state"],
                    persistence_mode=acc["persistence_mode"],
                    mig_mode=acc["mig_mode"],
                    mig_parent_uuid_raw=acc["mig_parent_uuid_raw"],
                    mig_instance_id=acc["mig_instance_id"],
                    compute_capability=acc["compute_capability"],
                    xid_recent=acc["xid_recent"],
                    partial_fields=tuple(sorted(set(partial_fields))),
                    read_errors=tuple(sorted(set(read_errors))),
                    extra=MappingProxyType(dict(acc["extra"])),
                )
            )
        return results

    def health(self) -> GpuSamplerHealth:
        ok = _NvmlAvailable_or_init()
        count = _NvmlRuntime.device_count() if ok else 0
        driver = _NvmlRuntime.driver_version() or self._policy.driver_version or None
        state: str = "ok" if ok else "down"
        warnings: List[str] = []
        if not ok:
            warnings.append("GPU_BACKEND_DOWN")
        err = _NvmlRuntime.last_init_error()
        if err:
            warnings.append("GPU_BACKEND_INIT_FAILED")
        return GpuSamplerHealth(
            backend="nvml",
            available=ok,
            device_count=count,
            driver_version=driver,
            health_state=state,
            warnings=tuple(dict.fromkeys(warnings)),
            cfg_fp=self._policy.cfg_fp,
            capabilities=_NvmlRuntime.capabilities(),
        )


def _NvmlAvailable_or_init() -> bool:
    return _NvmlRuntime.ensure_initialized()


# =============================================================================
# Normalize / assess / project
# =============================================================================

def _hash_identifier(value: Optional[str], *, key: Optional[bytes], key_id: Optional[str], ctx: str, version: str, out_hex: int) -> Optional[str]:
    if not value:
        return None
    raw = value.encode("utf-8", errors="ignore")
    if key is not None:
        dig = hmac.new(key, ctx.encode("utf-8", errors="strict") + b"\x00" + raw, hashlib.sha256).hexdigest()[:out_hex]
        kid = key_id or "hmac"
        return f"{version}:{kid}:{dig}"
    dig = hashlib.sha256(ctx.encode("utf-8", errors="strict") + b"\x00" + raw).hexdigest()[:out_hex]
    return f"{version}:sha256:{dig}"


def _expose_identifier(raw: Optional[str], *, mode: str, profile: str, allowed_clear_profiles: Tuple[str, ...], key: Optional[bytes], key_id: Optional[str], ctx: str, version: str, out_hex: int) -> Tuple[str, Optional[str], bool]:
    if not raw:
        return "", None, False
    public = ""
    exposed = False
    hashed = _hash_identifier(raw, key=key, key_id=key_id, ctx=ctx, version=version, out_hex=out_hex)
    strict = _profile_is_strict(profile)
    if mode == "clear":
        if not strict:
            public = raw
            exposed = True
    elif mode == "clear_if_allowed":
        if (profile in allowed_clear_profiles) and not strict:
            public = raw
            exposed = True
    return public, hashed, exposed


def normalize_observation(raw: GpuRawObservation, *, policy: GpuSamplerPolicy, config: GpuTelemetryConfig, collection_state: str) -> GpuNormalizedObservation:
    public_uuid, uuid_hash, uuid_exposed = _expose_identifier(
        raw.uuid_raw,
        mode=config.expose_uuid_mode,
        profile=config.profile,
        allowed_clear_profiles=config.allow_clear_uuid_profiles,
        key=config.uuid_hash_key if isinstance(config.uuid_hash_key, (bytes, bytearray)) else None,
        key_id=config.uuid_hash_key_id,
        ctx="tcd:gpu:uuid",
        version=_UUID_HASH_VERSION,
        out_hex=config.uuid_hash_hex_chars,
    )
    public_name, name_hash, name_exposed = _expose_identifier(
        raw.name_raw,
        mode=config.expose_name_mode,
        profile=config.profile,
        allowed_clear_profiles=config.allow_clear_name_profiles,
        key=config.name_hash_key if isinstance(config.name_hash_key, (bytes, bytearray)) else None,
        key_id=config.name_hash_key_id,
        ctx="tcd:gpu:name",
        version=_NAME_HASH_VERSION,
        out_hex=config.name_hash_hex_chars,
    )

    driver_obs = _safe_text_or_none(raw.driver_version_observed, max_len=128)
    driver_exp = _safe_text_or_none(policy.driver_version, max_len=128)
    if driver_obs and driver_exp:
        driver_match_state = "match" if driver_obs == driver_exp else "mismatch"
    elif driver_obs and not driver_exp:
        driver_match_state = "observed_only"
    elif (not driver_obs) and driver_exp:
        driver_match_state = "missing_observed"
    else:
        driver_match_state = "unknown"

    warnings: List[str] = list(raw.partial_fields)
    if raw.backend_state == "degraded" and "GPU_PARTIAL_METRICS" not in warnings:
        warnings.append("GPU_PARTIAL_METRICS")

    extra_safe = _safe_json_mapping(
        raw.extra,
        max_items=config.max_extra_items,
        max_str_len=config.max_extra_str_len,
        allowed_keys=set(config.allowed_extra_keys),
    )
    extra_safe.setdefault("driver_version_observed", driver_obs or "")
    extra_safe.setdefault("driver_version_expected", driver_exp or "")
    extra_safe.setdefault("driver_version_match_state", driver_match_state)
    extra_safe.setdefault("observed_vendor", _safe_label(raw.observed_vendor, default="unknown"))

    return GpuNormalizedObservation(
        index=max(0, int(raw.index)),
        ts=float(raw.ts) if math.isfinite(float(raw.ts)) else now_ts(),
        ts_unix_ns=max(0, int(raw.ts_unix_ns)),
        ts_monotonic_ns=max(0, int(raw.ts_monotonic_ns)),
        backend=_safe_label(raw.backend, default="unknown"),
        collection_state=collection_state if collection_state in _ALLOWED_COLLECTION_STATE else "unknown",
        backend_state=raw.backend_state if raw.backend_state in _ALLOWED_HEALTH else "unknown",
        observed_vendor=_safe_label(raw.observed_vendor, default="unknown"),
        driver_version_observed=driver_obs,
        driver_version_expected=driver_exp,
        driver_version_match_state=driver_match_state,
        uuid_raw=_safe_gpu_uuid(raw.uuid_raw, default=None, max_len=256),
        name_raw=_safe_text_or_none(raw.name_raw, max_len=128, redact_mode="token"),
        uuid_hash=uuid_hash,
        uuid_public=public_uuid,
        uuid_exposed=uuid_exposed,
        name_hash=name_hash,
        name_public=public_name,
        name_exposed=name_exposed,
        pci_bus_id=_safe_text_or_none(raw.pci_bus_id, max_len=64, redact_mode="token"),
        minor_number=max(0, _coerce_int(raw.minor_number)) if _coerce_int(raw.minor_number) is not None else None,
        mig_parent_uuid_hash=_hash_identifier(_safe_gpu_uuid(raw.mig_parent_uuid_raw, default=None, max_len=256), key=config.uuid_hash_key if isinstance(config.uuid_hash_key, (bytes, bytearray)) else None, key_id=config.uuid_hash_key_id, ctx="tcd:gpu:mig_parent_uuid", version=_UUID_HASH_VERSION, out_hex=config.uuid_hash_hex_chars),
        mig_instance_id=_safe_text_or_none(raw.mig_instance_id, max_len=64),
        util_pct=_clamp_float(raw.util_pct, default=0.0, lo=0.0, hi=100.0),
        mem_util_pct=_clamp_float(raw.mem_util_pct, default=0.0, lo=0.0, hi=100.0),
        mem_used_mib=_clamp_float(raw.mem_used_mib, default=0.0, lo=0.0, hi=1_000_000_000.0),
        mem_total_mib=_clamp_float(raw.mem_total_mib, default=0.0, lo=0.0, hi=1_000_000_000.0),
        mem_free_mib=_clamp_float(raw.mem_free_mib, default=0.0, lo=0.0, hi=1_000_000_000.0),
        temp_c=_clamp_float(raw.temp_c, default=0.0, lo=0.0, hi=200.0),
        power_w=_clamp_float(raw.power_w, default=0.0, lo=0.0, hi=1_000_000.0),
        power_limit_w=_clamp_float(raw.power_limit_w, default=0.0, lo=0.0, hi=1_000_000.0),
        fan_pct=_clamp_float(raw.fan_pct, default=0.0, lo=0.0, hi=100.0),
        compute_mode=(_safe_label(raw.compute_mode_raw, default="unknown") if raw.compute_mode_raw else "unknown") if (_safe_label(raw.compute_mode_raw, default="unknown") if raw.compute_mode_raw else "unknown") in _ALLOWED_COMPUTE_MODES else "unknown",
        ecc_errors_total=max(0, _coerce_int(raw.ecc_errors_total) or 0),
        ecc_corrected_total=max(0, _coerce_int(raw.ecc_corrected_total) or 0),
        ecc_uncorrected_total=max(0, _coerce_int(raw.ecc_uncorrected_total) or 0),
        ecc_mode_enabled=_coerce_bool(raw.ecc_mode_enabled),
        retired_pages_count=max(0, _coerce_int(raw.retired_pages_count) or 0),
        row_remap_failure_count=max(0, _coerce_int(raw.row_remap_failure_count) or 0),
        perf_state=_safe_text_or_none(raw.perf_state, max_len=32),
        throttle_reasons=_normalize_str_tuple(raw.throttle_reasons, max_len=64, max_items=16),
        power_state=_safe_text_or_none(raw.power_state, max_len=32),
        persistence_mode=_coerce_bool(raw.persistence_mode),
        mig_mode=_safe_text_or_none(raw.mig_mode, max_len=32),
        compute_capability=_safe_text_or_none(raw.compute_capability, max_len=32),
        xid_recent=_safe_text_or_none(raw.xid_recent, max_len=64),
        warnings=tuple(sorted(set(warnings))),
        extra=MappingProxyType(extra_safe),
    )


def assess_observation(obs: GpuNormalizedObservation, *, policy: GpuSamplerPolicy, config: GpuTelemetryConfig, device_count_observed: int) -> GpuPolicyAssessment:
    integrity_codes: List[str] = []
    degraded_codes: List[str] = list(_normalize_reason_codes(obs.warnings))
    security_suspect = False
    compliance_suspect = False
    integrity_suspect = False

    strict = _profile_is_strict(config.profile)

    if obs.collection_state == "backend_down":
        health_state = "down"
        degraded_codes.append("GPU_BACKEND_DOWN")
    elif obs.collection_state == "disabled":
        health_state = "disabled"
        degraded_codes.append("GPU_DISABLED")
    elif obs.backend_state == "degraded" or obs.warnings:
        health_state = "degraded"
        if "GPU_PARTIAL_METRICS" not in degraded_codes:
            degraded_codes.append("GPU_PARTIAL_METRICS")
    else:
        health_state = "ok"

    if policy.expected_vendor and obs.observed_vendor and obs.observed_vendor != policy.expected_vendor:
        integrity_codes.append("GPU_VENDOR_MISMATCH")
        integrity_suspect = True

    if policy.expected_uuids:
        allowed = {str(x).lower() for x in policy.expected_uuids}
        observed = (obs.uuid_raw or "").lower()
        if not observed or observed not in allowed:
            integrity_codes.append("GPU_UUID_MISMATCH")
            integrity_suspect = True
    elif not obs.uuid_hash:
        degraded_codes.append("GPU_UNVERIFIED")

    if policy.expected_name_prefixes:
        if not any((obs.name_raw or "").startswith(pref) for pref in policy.expected_name_prefixes):
            integrity_codes.append("GPU_NAME_MISMATCH")
            integrity_suspect = True

    if config.driver_version_must_match_policy and obs.driver_version_match_state == "mismatch":
        integrity_codes.append("GPU_DRIVER_MISMATCH")
        integrity_suspect = True

    if policy.min_device_count is not None and device_count_observed < policy.min_device_count:
        integrity_codes.append("GPU_DEVICE_COUNT_OUT_OF_RANGE")
        integrity_suspect = True
    if policy.max_device_count is not None and device_count_observed > policy.max_device_count:
        integrity_codes.append("GPU_DEVICE_COUNT_OUT_OF_RANGE")
        integrity_suspect = True

    if obs.temp_c > policy.max_temp_c:
        degraded_codes.append("GPU_TEMP_ABOVE_THRESHOLD")
        security_suspect = True
    if obs.ecc_errors_total > policy.max_ecc_errors:
        degraded_codes.append("GPU_ECC_ERRORS_ABOVE_THRESHOLD")
        security_suspect = True
    if policy.max_power_w is not None and obs.power_w > policy.max_power_w:
        degraded_codes.append("GPU_POWER_ABOVE_THRESHOLD")
        security_suspect = True
    if policy.min_total_mem_mib is not None and obs.mem_total_mib < policy.min_total_mem_mib:
        degraded_codes.append("GPU_TOTAL_MEM_BELOW_THRESHOLD")
        compliance_suspect = True
    if policy.pq_required and policy.pq_ok is False:
        degraded_codes.append("GPU_PQ_REQUIRED_NOT_OK")
        compliance_suspect = True
    if obs.retired_pages_count > 0:
        degraded_codes.append("GPU_RETIRED_PAGES_PRESENT")
        security_suspect = True
    if obs.row_remap_failure_count > 0:
        degraded_codes.append("GPU_ROW_REMAP_FAILURE_PRESENT")
        security_suspect = True
    if obs.xid_recent:
        degraded_codes.append("GPU_XID_PRESENT")
        security_suspect = True
    if obs.mig_instance_id:
        degraded_codes.append("GPU_MIG_PARTITION")

    if strict and config.enforce_expected_uuid_in_strict and policy.expected_uuids and "GPU_UUID_MISMATCH" in integrity_codes:
        security_suspect = True
    if strict and config.enforce_expected_vendor_in_strict and "GPU_VENDOR_MISMATCH" in integrity_codes:
        security_suspect = True

    identity_integrity_ok = not any(x in integrity_codes for x in ("GPU_UUID_MISMATCH", "GPU_NAME_MISMATCH", "GPU_VENDOR_MISMATCH", "GPU_DRIVER_MISMATCH"))
    hardware_integrity_ok = not any(x in degraded_codes for x in ("GPU_TEMP_ABOVE_THRESHOLD", "GPU_ECC_ERRORS_ABOVE_THRESHOLD", "GPU_POWER_ABOVE_THRESHOLD", "GPU_RETIRED_PAGES_PRESENT", "GPU_ROW_REMAP_FAILURE_PRESENT", "GPU_XID_PRESENT"))
    policy_compliance_ok = not any(x in integrity_codes or x in degraded_codes for x in ("GPU_DEVICE_COUNT_OUT_OF_RANGE", "GPU_PQ_REQUIRED_NOT_OK", "GPU_TOTAL_MEM_BELOW_THRESHOLD"))
    collection_integrity_ok = obs.collection_state in {"ok", "partial"} and health_state in {"ok", "degraded"}

    if integrity_codes:
        hw_state = "mismatch"
    elif health_state == "down":
        hw_state = "unverified"
    elif degraded_codes:
        hw_state = "degraded"
    else:
        hw_state = "ok"

    overall_integrity_ok = collection_integrity_ok and identity_integrity_ok and hardware_integrity_ok and policy_compliance_ok
    apt_suspect = security_suspect or integrity_suspect
    reasons = list(dict.fromkeys(integrity_codes + degraded_codes))
    apt_reason = ";".join(reasons)

    severity = "strict" if ("GPU_UUID_MISMATCH" in integrity_codes or "GPU_VENDOR_MISMATCH" in integrity_codes or "GPU_PQ_REQUIRED_NOT_OK" in degraded_codes) else ("elevated" if degraded_codes else "normal")

    rulepack_fp = f"{_ASSESSMENT_VERSION}:{_hash_hex(ctx='tcd:gpu:rulepack', payload={'policy': dataclasses.asdict(policy), 'config_fp': config.cfg_fingerprint()}, out_hex=32)}"

    return GpuPolicyAssessment(
        assessment_version=_ASSESSMENT_VERSION,
        rulepack_fingerprint=rulepack_fp,
        collection_integrity_ok=collection_integrity_ok,
        identity_integrity_ok=identity_integrity_ok,
        hardware_integrity_ok=hardware_integrity_ok,
        policy_compliance_ok=policy_compliance_ok,
        overall_integrity_ok=overall_integrity_ok,
        collection_state=obs.collection_state,
        health_state=health_state,
        backend_state=obs.backend_state,
        hw_integrity_state=hw_state,
        security_suspect=security_suspect,
        compliance_suspect=compliance_suspect,
        integrity_suspect=integrity_suspect,
        apt_suspect=apt_suspect,
        apt_reason=_safe_text(apt_reason, max_len=256),
        integrity_reason_codes=tuple(dict.fromkeys(integrity_codes)),
        degraded_reason_codes=tuple(dict.fromkeys(degraded_codes)),
        normalization_warnings=tuple(dict.fromkeys(obs.warnings)),
        device_count_observed=max(0, int(device_count_observed)),
        device_count_expected_min=policy.min_device_count,
        device_count_expected_max=policy.max_device_count,
        severity=severity,
    )


def build_gpu_sample(
    obs: GpuNormalizedObservation,
    assessment: GpuPolicyAssessment,
    *,
    policy: GpuSamplerPolicy,
    config: GpuTelemetryConfig,
    insider_override: bool = False,
    override_reason: str = "",
) -> GpuSample:
    produced_by = tuple(policy.produced_by or ("tcd.telemetry_gpu",))
    provenance_path_digest = f"sha256:{_hash_hex(ctx='tcd:gpu:produced_by', payload={'produced_by': list(produced_by)}, out_hex=64)}"

    observation_obj = {
        "index": obs.index,
        "backend": obs.backend,
        "collection_state": obs.collection_state,
        "backend_state": obs.backend_state,
        "observed_vendor": obs.observed_vendor,
        "driver_version_observed": obs.driver_version_observed,
        "driver_version_expected": obs.driver_version_expected,
        "driver_version_match_state": obs.driver_version_match_state,
        "uuid_hash": obs.uuid_hash,
        "name_hash": obs.name_hash,
        "pci_bus_id": obs.pci_bus_id,
        "minor_number": obs.minor_number,
        "mig_parent_uuid_hash": obs.mig_parent_uuid_hash,
        "mig_instance_id": obs.mig_instance_id,
        "util_pct": obs.util_pct,
        "mem_util_pct": obs.mem_util_pct,
        "mem_used_mib": obs.mem_used_mib,
        "mem_total_mib": obs.mem_total_mib,
        "mem_free_mib": obs.mem_free_mib,
        "temp_c": obs.temp_c,
        "power_w": obs.power_w,
        "power_limit_w": obs.power_limit_w,
        "fan_pct": obs.fan_pct,
        "compute_mode": obs.compute_mode,
        "ecc_errors_total": obs.ecc_errors_total,
        "ecc_corrected_total": obs.ecc_corrected_total,
        "ecc_uncorrected_total": obs.ecc_uncorrected_total,
        "ecc_mode_enabled": obs.ecc_mode_enabled,
        "retired_pages_count": obs.retired_pages_count,
        "row_remap_failure_count": obs.row_remap_failure_count,
        "perf_state": obs.perf_state,
        "throttle_reasons": list(obs.throttle_reasons),
        "power_state": obs.power_state,
        "persistence_mode": obs.persistence_mode,
        "mig_mode": obs.mig_mode,
        "compute_capability": obs.compute_capability,
        "xid_recent": obs.xid_recent,
        "warnings": list(obs.warnings),
        "extra": dict(obs.extra),
    }
    assessment_obj = assessment.to_dict()

    observation_digest = f"{_OBSERVATION_VERSION}:sha256:{_hash_hex(ctx='tcd:gpu:observation', payload=observation_obj, out_hex=64)}"
    assessment_digest = f"{_ASSESSMENT_VERSION}:sha256:{_hash_hex(ctx='tcd:gpu:assessment', payload=assessment_obj, out_hex=64)}"

    event_core = {
        "index": obs.index,
        "node_id": policy.node_id,
        "build_id": policy.build_id,
        "cfg_fp": policy.cfg_fp or config.cfg_fingerprint(),
        "uuid_hash": obs.uuid_hash,
        "name_hash": obs.name_hash,
        "observation_digest": observation_digest,
        "assessment_digest": assessment_digest,
        "ts_unix_ns": obs.ts_unix_ns,
    }
    event_id = f"{_EVENT_VERSION}:{_hash_hex(ctx='tcd:gpu:event', payload=event_core, out_hex=32)}"

    sample = GpuSample(
        schema=_SCHEMA,
        schema_version=3,
        compatibility_epoch=config.compatibility_epoch,
        canonicalization_version=_CANONICALIZATION_VERSION,
        event_id=event_id,
        event_type="gpu_telemetry",
        sample_fingerprint="",
        observation_digest=observation_digest,
        assessment_digest=assessment_digest,
        body_digest="",
        payload_digest="",
        event_digest="",
        index=obs.index,
        uuid=obs.uuid_public,
        uuid_hash=obs.uuid_hash,
        uuid_exposed=obs.uuid_exposed,
        name=obs.name_public,
        name_hash=obs.name_hash,
        name_exposed=obs.name_exposed,
        ts=obs.ts,
        ts_unix_ns=obs.ts_unix_ns,
        ts_monotonic_ns=obs.ts_monotonic_ns,
        util_pct=obs.util_pct,
        mem_used_mib=obs.mem_used_mib,
        mem_total_mib=obs.mem_total_mib,
        mem_free_mib=obs.mem_free_mib,
        mem_util_pct=obs.mem_util_pct,
        temp_c=obs.temp_c,
        power_w=obs.power_w,
        power_limit_w=obs.power_limit_w,
        fan_pct=obs.fan_pct,
        compute_mode=obs.compute_mode,
        ecc_errors_total=obs.ecc_errors_total,
        backend=obs.backend,
        collection_state=assessment.collection_state,
        health_state=assessment.health_state,
        extra=obs.extra,
        node_id=policy.node_id,
        build_id=policy.build_id,
        image_digest=policy.image_digest,
        driver_version_observed=obs.driver_version_observed or "",
        driver_version_expected=obs.driver_version_expected,
        driver_version_match_state=obs.driver_version_match_state,
        runtime_env=policy.runtime_env,
        trust_zone=policy.trust_zone,
        route_profile=policy.route_profile,
        policy_ref=policy.policy_ref,
        policyset_ref=policy.policyset_ref,
        policy_digest=policy.policy_digest_or_derived(),
        cfg_fp=policy.cfg_fp or config.cfg_fingerprint(),
        bundle_version=policy.bundle_version,
        state_domain_id=policy.state_domain_id,
        adapter_registry_fp=policy.adapter_registry_fp,
        selected_source=policy.selected_source or "gpu_sampler",
        controller_mode=policy.controller_mode,
        decision_mode=policy.decision_mode,
        statistical_guarantee_scope=policy.statistical_guarantee_scope,
        activation_id=policy.activation_id,
        patch_id=policy.patch_id,
        change_ticket_id=policy.change_ticket_id,
        observed_vendor=obs.observed_vendor,
        hw_integrity_state=assessment.hw_integrity_state,
        collection_integrity_ok=assessment.collection_integrity_ok,
        identity_integrity_ok=assessment.identity_integrity_ok,
        hardware_integrity_ok=assessment.hardware_integrity_ok,
        policy_compliance_ok=assessment.policy_compliance_ok,
        integrity_ok=assessment.overall_integrity_ok,
        integrity_reason_codes=assessment.integrity_reason_codes,
        degraded_reason_codes=assessment.degraded_reason_codes,
        normalization_warnings=assessment.normalization_warnings,
        security_suspect=assessment.security_suspect,
        compliance_suspect=assessment.compliance_suspect,
        integrity_suspect=assessment.integrity_suspect,
        apt_suspect=assessment.apt_suspect,
        apt_reason=assessment.apt_reason,
        severity=assessment.severity,
        insider_override=bool(insider_override),
        override_reason=_safe_text(override_reason, max_len=128),
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

    body_payload = sample.to_body_payload()
    body_digest = f"{_PAYLOAD_VERSION}:sha256:{hashlib.sha256(_canonical_json_bytes(body_payload)).hexdigest()}"
    event_digest = f"gpued2:sha256:{_hash_hex(ctx='tcd:gpu:event_digest', payload={'event_id': event_id, 'state_domain_id': policy.state_domain_id, 'policy_ref': policy.policy_ref}, out_hex=64)}"
    payload_digest = f"{_PAYLOAD_VERSION}:sha256:{hashlib.sha256(_canonical_json_bytes(sample.to_public_dict())).hexdigest()}"
    sample_fp = f"gpu2:{_hash_hex(ctx='tcd:gpu:sample', payload={'event_id': event_id, 'body_digest': body_digest, 'assessment_digest': assessment_digest}, out_hex=32)}"

    return dataclasses.replace(
        sample,
        sample_fingerprint=sample_fp,
        body_digest=body_digest,
        payload_digest=payload_digest,
        event_digest=event_digest,
    )


def build_host_snapshot(
    samples: Sequence[GpuSample],
    *,
    policy: GpuSamplerPolicy,
    config: GpuTelemetryConfig,
    collection_started_mono: float,
    collection_finished_mono: float,
    collection_errors: Sequence[str],
    collection_state: str,
    backend_state: str,
) -> GpuHostSnapshot:
    ts_ns = now_unix_ns()
    samples_t = tuple(samples)
    warnings = tuple(dict.fromkeys([w for s in samples_t for w in s.normalization_warnings]))
    batch_payload = {
        "node_id": policy.node_id,
        "build_id": policy.build_id,
        "image_digest": policy.image_digest,
        "collection_state": collection_state,
        "backend_state": backend_state,
        "samples": [s.event_id for s in samples_t],
        "ts_unix_ns": ts_ns,
    }
    collection_id = f"gcol1:{_hash_hex(ctx='tcd:gpu:collection', payload=batch_payload, out_hex=32)}"
    batch_digest = f"sha256:{_hash_hex(ctx='tcd:gpu:batch', payload={'samples': [s.body_digest for s in samples_t], 'collection_id': collection_id}, out_hex=64)}"
    latency_ms = max(0.0, (float(collection_finished_mono) - float(collection_started_mono)) * 1000.0)
    partial = collection_state == "partial"
    return GpuHostSnapshot(
        schema=_SCHEMA,
        schema_version=3,
        compatibility_epoch=config.compatibility_epoch,
        collection_id=collection_id,
        ts_unix_ns=ts_ns,
        node_id=policy.node_id,
        build_id=policy.build_id,
        image_digest=policy.image_digest,
        device_count_observed=len(samples_t),
        device_count_expected_min=policy.min_device_count,
        device_count_expected_max=policy.max_device_count,
        collection_state=collection_state if collection_state in _ALLOWED_COLLECTION_STATE else "unknown",
        backend_state=backend_state if backend_state in _ALLOWED_HEALTH else "unknown",
        warnings=warnings,
        collection_errors=tuple(dict.fromkeys(_normalize_reason_codes(collection_errors))),
        batch_digest=batch_digest,
        collection_latency_ms=float(latency_ms),
        partial_collection=partial,
        samples=samples_t,
    )


# =============================================================================
# Facade
# =============================================================================

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
        attestor: Optional[Any] = None,
    ) -> None:
        self._cfg = config or GpuTelemetryConfig()
        self._policy = (policy or GpuSamplerPolicy()).normalized(cfg=self._cfg)
        self._telemetry_sink = telemetry_sink
        self._audit_sink = audit_sink
        self._attestor = attestor
        self._index = int(index)
        self._force_dummy = bool(force_dummy)
        self._override_reason = _safe_text(override_reason, max_len=128)
        self._cache_lock = threading.Lock()
        self._cached_batch: Optional[GpuHostSnapshot] = None
        self._cached_at_mono = 0.0

        pref = self._cfg.backend_preference
        if not self._cfg.enable:
            self._impl: BaseGpuSampler = DummyGpuSampler(
                index=self._index,
                health_state="disabled",
                policy=self._policy,
                config=self._cfg,
                insider_override=True,
                override_reason=self._override_reason or "gpu_disabled",
                backend_label="dummy",
                reason_codes=("GPU_DISABLED",),
            )
        elif self._force_dummy or pref == "dummy":
            self._impl = DummyGpuSampler(
                index=self._index,
                health_state="unknown" if self._force_dummy else "disabled",
                policy=self._policy,
                config=self._cfg,
                insider_override=bool(self._force_dummy),
                override_reason=self._override_reason or ("force_dummy" if self._force_dummy else "backend_dummy"),
                backend_label="dummy",
                reason_codes=("GPU_FORCE_DUMMY",) if self._force_dummy else tuple(),
            )
        elif pref in {"auto", "nvml"} and _NVML_AVAILABLE:
            try:
                self._impl = NvmlGpuSampler(index=self._index, policy=self._policy, config=self._cfg)
            except Exception:
                self._impl = DummyGpuSampler(
                    index=self._index,
                    health_state="down",
                    policy=self._policy,
                    config=self._cfg,
                    insider_override=False,
                    override_reason="nvml_ctor_failed",
                    backend_label="nvml",
                    reason_codes=("GPU_BACKEND_DOWN",),
                )
        else:
            self._impl = DummyGpuSampler(
                index=self._index,
                health_state="down",
                policy=self._policy,
                config=self._cfg,
                insider_override=False,
                override_reason="nvml_unavailable",
                backend_label="dummy",
                reason_codes=("GPU_BACKEND_DOWN",),
            )

    def _build_batch(self) -> GpuHostSnapshot:
        started = time.perf_counter()
        raws = self._impl.sample_raw_all()
        if not raws:
            raws = [
                DummyGpuSampler(
                    index=self._index,
                    health_state="down",
                    policy=self._policy,
                    config=self._cfg,
                    backend_label="dummy",
                    reason_codes=("GPU_BACKEND_DOWN",),
                ).sample_raw()
            ]
        observed_count = len(raws)

        if all(r.backend_state == "down" for r in raws):
            collection_state = "backend_down"
        elif any(r.backend_state == "degraded" for r in raws):
            collection_state = "partial"
        else:
            collection_state = "ok"

        backend_state = "down" if collection_state == "backend_down" else ("degraded" if collection_state == "partial" else "ok")

        samples: List[GpuSample] = []
        all_errors: List[str] = []
        for raw in raws:
            obs = normalize_observation(raw, policy=self._policy, config=self._cfg, collection_state=collection_state)
            assessment = assess_observation(obs, policy=self._policy, config=self._cfg, device_count_observed=observed_count)
            sample = build_gpu_sample(
                obs,
                assessment,
                policy=self._policy,
                config=self._cfg,
                insider_override=isinstance(self._impl, DummyGpuSampler) and self._force_dummy,
                override_reason=self._override_reason if self._force_dummy else "",
            )
            samples.append(sample)
            all_errors.extend(sample.integrity_reason_codes)
            all_errors.extend(sample.degraded_reason_codes)

        finished = time.perf_counter()
        return build_host_snapshot(
            samples,
            policy=self._policy,
            config=self._cfg,
            collection_started_mono=started,
            collection_finished_mono=finished,
            collection_errors=all_errors,
            collection_state=collection_state,
            backend_state=backend_state,
        )

    def _publish_sample(self, sample: GpuSample) -> None:
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
                mem_ratio = (sample.mem_used_mib / sample.mem_total_mib) if sample.mem_total_mib > 0 else 0.0
                self._telemetry_sink.record_metric("tcd_gpu_mem_ratio", float(mem_ratio), labels)
            with contextlib.suppress(Exception):
                self._telemetry_sink.record_metric("tcd_gpu_temp_c", float(sample.temp_c), labels)
            with contextlib.suppress(Exception):
                self._telemetry_sink.record_event("gpu_sample", sample.to_public_dict())
            if sample.apt_suspect or not sample.integrity_ok:
                with contextlib.suppress(Exception):
                    self._telemetry_sink.record_event("gpu_sample_anomaly", sample.to_audit_dict())

        if self._audit_sink is not None:
            evt = "GpuTelemetryAnomaly" if (sample.apt_suspect or not sample.integrity_ok) else "GpuTelemetrySample"
            with contextlib.suppress(Exception):
                self._audit_sink.emit(evt, sample.to_audit_dict())

    def _publish_batch(self, batch: GpuHostSnapshot) -> None:
        for s in batch.samples:
            self._publish_sample(s)
        if self._telemetry_sink is not None:
            labels = {
                "collection_state": _safe_label(batch.collection_state, default="unknown"),
                "backend_state": _safe_label(batch.backend_state, default="unknown"),
                "node": _safe_text(batch.node_id, max_len=64) or "default",
            }
            with contextlib.suppress(Exception):
                self._telemetry_sink.record_metric("tcd_gpu_collection_latency_ms", float(batch.collection_latency_ms), labels)
            with contextlib.suppress(Exception):
                self._telemetry_sink.record_metric("tcd_gpu_device_count", float(batch.device_count_observed), labels)
            with contextlib.suppress(Exception):
                self._telemetry_sink.record_event("gpu_batch", batch.to_public_dict())
        if self._audit_sink is not None and batch.collection_errors:
            with contextlib.suppress(Exception):
                self._audit_sink.emit("GpuTelemetryBatch", batch.to_audit_dict())

    def _get_batch(self, *, force_refresh: bool = False) -> GpuHostSnapshot:
        now_mono = time.monotonic()
        with self._cache_lock:
            if (
                not force_refresh
                and self._cached_batch is not None
                and self._cfg.cache_ttl_ms > 0
                and (now_mono - self._cached_at_mono) * 1000.0 <= float(self._cfg.cache_ttl_ms)
            ):
                return self._cached_batch

        try:
            batch = self._build_batch()
        except Exception:
            if self._cfg.cache_on_error:
                with self._cache_lock:
                    if self._cached_batch is not None and (now_mono - self._cached_at_mono) * 1000.0 <= float(self._cfg.max_staleness_ms):
                        stale_samples = tuple(
                            dataclasses.replace(
                                s,
                                collection_state="partial",
                                health_state="degraded" if s.health_state != "disabled" else s.health_state,
                                degraded_reason_codes=tuple(dict.fromkeys(list(s.degraded_reason_codes) + ["GPU_CACHE_STALE"])),
                            )
                            for s in self._cached_batch.samples
                        )
                        return dataclasses.replace(
                            self._cached_batch,
                            collection_state="partial",
                            backend_state=self._cached_batch.backend_state if self._cached_batch.backend_state != "ok" else "degraded",
                            warnings=tuple(dict.fromkeys(list(self._cached_batch.warnings) + ["GPU_CACHE_STALE"])),
                            collection_errors=tuple(dict.fromkeys(list(self._cached_batch.collection_errors) + ["GPU_CACHE_STALE"])),
                            samples=stale_samples,
                        )
            raise

        with self._cache_lock:
            self._cached_batch = batch
            self._cached_at_mono = now_mono
        self._publish_batch(batch)
        return batch

    def health(self) -> GpuSamplerHealth:
        return self._impl.health()

    def health_snapshot(self) -> Dict[str, Any]:
        return self.health().to_dict()

    def sample_batch_struct(self, *, force_refresh: bool = False) -> GpuHostSnapshot:
        return self._get_batch(force_refresh=force_refresh)

    def sample_batch(self, *, force_refresh: bool = False) -> Dict[str, Any]:
        return self.sample_batch_struct(force_refresh=force_refresh).to_public_dict()

    def sample_struct(self, *, force_refresh: bool = False) -> GpuSample:
        batch = self._get_batch(force_refresh=force_refresh)
        for s in batch.samples:
            if int(s.index) == int(self._index):
                return s
        return batch.samples[0]

    def sample(self, *, force_refresh: bool = False) -> Dict[str, Any]:
        return self.sample_struct(force_refresh=force_refresh).to_public_dict()

    def sample_all_structs(self, *, force_refresh: bool = False) -> List[GpuSample]:
        return list(self._get_batch(force_refresh=force_refresh).samples)

    def sample_all(self, *, force_refresh: bool = False) -> List[Dict[str, Any]]:
        return [s.to_public_dict() for s in self.sample_all_structs(force_refresh=force_refresh)]

    def issue_attestation(self, *, force_refresh: bool = False, attestor: Optional[Any] = None) -> Optional[Dict[str, Any]]:
        batch = self._get_batch(force_refresh=force_refresh)
        if not batch.samples:
            return None
        att = attestor or self._attestor
        if att is None or not self._cfg.enable_attestor_bridge:
            return None
        return batch.samples[0].issue_attestation(att)
