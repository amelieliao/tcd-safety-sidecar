from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import hmac
import json
import math
import os
import threading
import time
import unicodedata
from collections import OrderedDict, deque
from dataclasses import dataclass, field, fields as dataclass_fields
from enum import Enum
from types import MappingProxyType
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Literal

logger = __import__("logging").getLogger(__name__)

try:
    from .crypto import Blake3Hash  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    Blake3Hash = None  # type: ignore[assignment]

try:
    from .schemas import ArtifactRefsView, EvidenceIdentityView  # type: ignore
except Exception:  # pragma: no cover
    ArtifactRefsView = None  # type: ignore[assignment]
    EvidenceIdentityView = None  # type: ignore[assignment]

__all__ = [
    "TrustGraphConfig",
    "EvidenceType",
    "SubjectKey",
    "TrustEdge",
    "Evidence",
    "TrustState",
    "TrustGraphTelemetrySink",
    "TrustGraphAuditSink",
    "TrustGraphPublicConfigView",
    "TrustGraphDiagnosticsView",
    "TrustGraph",
]

Profile = Literal["DEV", "PROD", "FINREG", "LOCKDOWN"]
SubjectIdExposureMode = Literal["clear", "hash", "clear_if_allowed"]
SinkErrorMode = Literal["log_and_continue", "disable_sink", "raise"]

_SCHEMA = "tcd.trust_graph.v4"
_COMPATIBILITY_EPOCH = "2026Q2"
_CANONICALIZATION_VERSION = "canonjson_v1"
_EVENT_VERSION = "tge4"
_PAYLOAD_VERSION = "tgpd3"
_SUBJECT_HASH_VERSION = "subtg2"
_PROVENANCE_VERSION = "tgprov2"
_EDGE_VERSION = "tgedge1"

_ALLOWED_PROFILES = frozenset({"DEV", "PROD", "FINREG", "LOCKDOWN"})
_ALLOWED_LOCKDOWN_LEVELS = frozenset({"none", "monitor", "restrict", "lockdown"})
_ALLOWED_RISK_BANDS = frozenset({"high_risk", "elevated_risk", "neutral", "reliable", "high_trust"})
_ALLOWED_SOURCE_CLASSIFICATION = frozenset(
    {
        "control_plane_produced",
        "data_plane_observed",
        "reconstructed",
        "replayed",
        "imported",
        "synthetic",
        "degraded",
    }
)
_ALLOWED_PHASES = frozenset(
    {
        "observed",
        "normalized",
        "evaluated",
        "materialized",
        "prepared",
        "committed",
        "queued",
        "flushed",
        "verified",
        "replayed",
        "degraded",
    }
)
_ALLOWED_SIGNAL_TRUST = frozenset({"trusted", "advisory", "untrusted"})
_ALLOWED_SEVERITY_LABELS = frozenset({"low", "medium", "high", "critical", "normal"})
_ALLOWED_TRUST_ZONES = frozenset({"internet", "internal", "partner", "admin", "ops", "unknown"})
_ALLOWED_ROUTE_PROFILES = frozenset({"inference", "batch", "admin", "control", "metrics", "health", "restricted", "unknown"})
_ALLOWED_OUTBOX_STATUS = frozenset({"queued", "flushed", "dropped", "disabled", "none"})
_ALLOWED_LEDGER_STAGE = frozenset({"prepared", "committed", "outboxed", "skipped", "failed"})
_ALLOWED_EDGE_RELATIONS = frozenset(
    {
        "derived_from_event",
        "bound_to_decision",
        "bound_to_route_plan",
        "bound_to_route",
        "bound_to_receipt",
        "bound_to_resource",
        "caused_by_event",
        "caused_by_decision",
        "caused_by_route_plan",
    }
)
_ALLOWED_EVIDENCE_TYPES = frozenset(
    {
        "receipt",
        "decision",
        "action",
        "verification",
        "anomaly",
        "health",
        "supply_chain",
        "override",
        "route",
        "security",
        "pq",
        "rate_limit",
        "lifecycle",
    }
)

_ALLOWED_REASON_CODES = frozenset(
    {
        "RECEIPT_SAFE",
        "RECEIPT_UNSAFE",
        "DECISION_ALLOW",
        "DECISION_DEGRADE",
        "DECISION_BLOCK",
        "ACTION_SUCCESS",
        "ACTION_FAILURE",
        "VERIFY_OK",
        "VERIFY_FAIL",
        "ANOMALY_DETECTED",
        "HEALTH_OK",
        "HEALTH_FAIL",
        "SUPPLY_CHAIN_OK",
        "SUPPLY_CHAIN_FAIL",
        "OVERRIDE_APPLIED",
        "PQ_REQUIRED_OK",
        "PQ_REQUIRED_NOT_OK",
        "PQ_OPTIONAL",
        "ROUTE_ALLOW",
        "ROUTE_DEGRADE",
        "ROUTE_BLOCK",
        "RATE_ALLOW",
        "RATE_DENY",
        "LIFECYCLE_OK",
        "LIFECYCLE_FAIL",
        "SECURITY_DECISION",
        "SECURITY_DENY",
        "SECURITY_DEGRADE",
        "SECURITY_ALLOW",
        "REPLAY_SUPPRESSED",
        "IDEMPOTENCY_CONFLICT",
        "STATE_FROZEN",
        "COMPROMISED_FREEZE",
        "INVALID_PAYLOAD_SANITIZED",
    }
)

_ASCII_CTRL_RE = __import__("re").compile(r"[\x00-\x1F\x7F]")
_SAFE_LABEL_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = __import__("re").compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_ID_RE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#/+=]{0,255}$")
_SAFE_REASON_CODE_RE = __import__("re").compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_HEX_RE = __import__("re").compile(r"^[0-9a-fA-F]+$")
_DIGEST_HEX_RE = __import__("re").compile(r"^[0-9a-f]{16,256}$")
_DIGEST_HEX_0X_RE = __import__("re").compile(r"^0x[0-9a-f]{16,256}$")
_DIGEST_ALG_HEX_RE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,31}:[0-9a-f]{16,256}$")
_CFG_FP_RE = __import__("re").compile(
    r"^(?:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256}|[A-Za-z0-9][A-Za-z0-9_.-]{1,15}:[0-9a-f]{16,256})$"
)

_JWT_RE = __import__("re").compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = __import__("re").compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", __import__("re").IGNORECASE)
_BEARER_RE = __import__("re").compile(r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b", __import__("re").IGNORECASE)
_BASIC_RE = __import__("re").compile(r"\bBasic\s+[A-Za-z0-9+/=]{16,}\b", __import__("re").IGNORECASE)
_OPENAI_SK_RE = __import__("re").compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_AWS_AKIA_RE = __import__("re").compile(r"\bAKIA[0-9A-Z]{16}\b")
_GOOGLE_AIZA_RE = __import__("re").compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_KV_SECRET_RE = __import__("re").compile(r"(?i)\b(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]{8,})")
_ENTROPY_B64URL_RE = __import__("re").compile(r"\b[A-Za-z0-9_-]{60,}\b")

_FORBIDDEN_PAYLOAD_KEY_TOKENS = frozenset(
    {
        "prompt",
        "completion",
        "input",
        "output",
        "messages",
        "message",
        "content",
        "body",
        "payload",
        "request",
        "response",
        "headers",
        "header",
        "cookie",
        "cookies",
        "authorization",
        "auth",
        "secret",
        "password",
        "passwd",
        "pwd",
        "api",
        "apikey",
        "api_key",
        "private",
        "privatekey",
    }
)


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


def _safe_reason_code(v: Any, *, default: Optional[str] = None) -> Optional[str]:
    s = _safe_text(v, max_len=128, redact_mode="token").upper()
    if not s or s == "[REDACTED]" or not _SAFE_REASON_CODE_RE.fullmatch(s):
        return default
    return s if s in _ALLOWED_REASON_CODES else default


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
        s = _safe_reason_code(item, default=None)
        if not s or s in seen:
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
        s = _safe_text(item, max_len=max_len, redact_mode="token")
        if lower:
            s = s.lower()
        if not s or s == "[redacted]" or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return tuple(out)


def _key_tokens(k: str) -> Tuple[str, ...]:
    s = _strip_unsafe_text(k, max_len=128)
    if not s:
        return tuple()
    s = __import__("re").sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", s)
    s = __import__("re").sub(r"(?<=[A-Za-z])(?=\d)|(?<=\d)(?=[A-Za-z])", " ", s)
    s = __import__("re").sub(r"[^A-Za-z0-9]+", " ", s).strip().lower()
    if not s:
        return tuple()
    parts = tuple(p for p in s.split(" ") if p)
    fused = "".join(parts)
    return parts + ((fused,) if fused and fused not in parts else tuple())


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
            if any(tok in _FORBIDDEN_PAYLOAD_KEY_TOKENS for tok in _key_tokens(kk)):
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
        xs = [_json_sanitize(x, budget=budget, depth=depth + 1, max_str_len=max_str_len) for x in list(obj)[: budget.max_items]]
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


def _fit_payload_budget(payload: Dict[str, Any], *, max_bytes: int) -> Dict[str, Any]:
    try:
        raw = _canonical_json_bytes(payload)
        if len(raw) <= max_bytes:
            return payload
    except Exception:
        return {}
    if max_bytes <= 64:
        return {"_truncated": True}
    out: Dict[str, Any] = {}
    for k in sorted(payload.keys()):
        test = dict(out)
        test[k] = payload[k]
        test["_truncated"] = True
        try:
            if len(_canonical_json_bytes(test)) <= max_bytes:
                out = test
            else:
                break
        except Exception:
            break
    if not out:
        return {"_truncated": True}
    return out


def _pii_hash_hex(text: str, *, prefix: str) -> str:
    try:
        dig = hashlib.blake2s(text.encode("utf-8", errors="ignore"), digest_size=8).hexdigest()
    except Exception:
        dig = "anon"
    return f"{prefix}-{dig}"


def _sanitize_subject(subject: "SubjectKey") -> "SubjectKey":
    def _clean(value: str, placeholder_prefix: str) -> str:
        v = _strip_unsafe_text(value, max_len=128)
        if not v:
            return f"{placeholder_prefix}-anon"
        if "@" in v or " " in v or not _SAFE_ID_RE.fullmatch(v):
            return _pii_hash_hex(v, prefix=placeholder_prefix)
        return v

    return SubjectKey(
        tenant=_clean(subject.tenant, "tenant"),
        user=_clean(subject.user, "user"),
        session=_clean(subject.session, "session"),
        model_id=_clean(subject.model_id, "model"),
        principal_type=_safe_label(subject.principal_type, default="") if subject.principal_type else "",
    )


class TrustGraphTelemetrySink(Protocol):
    def record_metric(self, name: str, value: float, labels: Mapping[str, str]) -> None: ...
    def record_event(self, name: str, payload: Mapping[str, Any]) -> None: ...


class TrustGraphAuditSink(Protocol):
    def emit(self, event_type: str, payload: Mapping[str, Any]) -> Optional[str]: ...


class EvidenceType(str, Enum):
    RECEIPT = "receipt"
    DECISION = "decision"
    ACTION = "action"
    VERIFICATION = "verification"
    ANOMALY = "anomaly"
    HEALTH = "health"
    SUPPLY_CHAIN = "supply_chain"
    OVERRIDE = "override"
    ROUTE = "route"
    SECURITY = "security"
    PQ = "pq"
    RATE_LIMIT = "rate_limit"
    LIFECYCLE = "lifecycle"


@dataclass(frozen=True, slots=True)
class SubjectKey:
    tenant: str = ""
    user: str = ""
    session: str = ""
    model_id: str = ""
    principal_type: str = ""

    def normalized(self) -> "SubjectKey":
        return _sanitize_subject(self)

    def as_id(self) -> str:
        s = self.normalized()
        parts = [
            f"tenant={s.tenant or '*'}",
            f"user={s.user or '*'}",
            f"session={s.session or '*'}",
            f"model={s.model_id or '*'}",
        ]
        if s.principal_type:
            parts.append(f"ptype={s.principal_type}")
        return "|".join(parts)

    def to_labels(self) -> Dict[str, str]:
        s = self.normalized()
        return {
            "tenant": s.tenant or "",
            "user": s.user or "",
            "session": s.session or "",
            "model_id": s.model_id or "",
            "principal_type": s.principal_type or "",
        }


@dataclass(frozen=True, slots=True)
class TrustGraphConfig:
    profile: Profile = "PROD"
    compatibility_epoch: str = _COMPATIBILITY_EPOCH

    decay_half_life_sec: float = 3600.0
    trust_update_step: float = 0.08
    positive_cap: float = 2.0
    negative_cap: float = 2.0
    neutral_trust: float = 0.5

    freeze_on_compromise_sec: float = 0.0
    severe_negative_weight_threshold: float = 2.0
    recent_window_s: float = 3600.0

    max_evidence_per_subject: int = 1024
    max_total_evidence: int = 100_000
    max_subjects: int = 100_000
    max_edges_per_subject: int = 2048
    max_total_edges: int = 200_000
    idem_ttl_sec: float = 24.0 * 3600.0

    max_payload_items: int = 64
    max_payload_str_len: int = 512
    max_payload_bytes: int = 4096

    hash_subject_ids: bool = True
    subject_hash_key: Optional[Any] = None
    subject_hash_key_id: Optional[str] = None
    min_hash_key_bytes: int = 16
    subject_hash_hex_chars: int = 24

    public_subject_id_mode: SubjectIdExposureMode = "hash"
    allow_clear_subject_profiles: Tuple[str, ...] = ("DEV",)
    public_include_payload: bool = True
    public_include_internal_digests: bool = False

    default_phase: str = "evaluated"
    default_source_classification: str = "control_plane_produced"
    default_signal_trust_mode: str = "trusted"

    sink_error_mode: SinkErrorMode = "log_and_continue"

    def __post_init__(self) -> None:
        prof = _safe_text(self.profile, max_len=32).upper() or "PROD"
        object.__setattr__(self, "profile", prof if prof in _ALLOWED_PROFILES else "PROD")
        object.__setattr__(self, "compatibility_epoch", _safe_text(self.compatibility_epoch, max_len=32) or _COMPATIBILITY_EPOCH)
        object.__setattr__(self, "decay_half_life_sec", max(1.0, min(10_000_000.0, float(self.decay_half_life_sec))))
        object.__setattr__(self, "trust_update_step", max(0.0, min(1.0, float(self.trust_update_step))))
        object.__setattr__(self, "positive_cap", max(0.1, min(100.0, float(self.positive_cap))))
        object.__setattr__(self, "negative_cap", max(0.1, min(100.0, float(self.negative_cap))))
        nt = float(self.neutral_trust)
        if not math.isfinite(nt):
            nt = 0.5
        object.__setattr__(self, "neutral_trust", min(max(nt, 0.0), 1.0))
        object.__setattr__(self, "freeze_on_compromise_sec", max(0.0, min(31_536_000.0, float(self.freeze_on_compromise_sec))))
        object.__setattr__(self, "severe_negative_weight_threshold", max(0.1, min(100.0, float(self.severe_negative_weight_threshold))))
        object.__setattr__(self, "recent_window_s", max(60.0, min(31_536_000.0, float(self.recent_window_s))))
        object.__setattr__(self, "max_evidence_per_subject", max(1, min(100_000, int(self.max_evidence_per_subject))))
        object.__setattr__(self, "max_total_evidence", max(1, min(2_000_000, int(self.max_total_evidence))))
        object.__setattr__(self, "max_subjects", max(1, min(2_000_000, int(self.max_subjects))))
        object.__setattr__(self, "max_edges_per_subject", max(1, min(100_000, int(self.max_edges_per_subject))))
        object.__setattr__(self, "max_total_edges", max(1, min(4_000_000, int(self.max_total_edges))))
        object.__setattr__(self, "idem_ttl_sec", max(60.0, min(31_536_000.0, float(self.idem_ttl_sec))))
        object.__setattr__(self, "max_payload_items", max(1, min(512, int(self.max_payload_items))))
        object.__setattr__(self, "max_payload_str_len", max(32, min(4096, int(self.max_payload_str_len))))
        object.__setattr__(self, "max_payload_bytes", max(256, min(262_144, int(self.max_payload_bytes))))
        object.__setattr__(self, "hash_subject_ids", bool(self.hash_subject_ids))
        key = self.subject_hash_key
        if isinstance(key, str):
            key = _parse_key_material(key)
        if key is not None and len(key) < max(8, int(self.min_hash_key_bytes)):
            key = None
        object.__setattr__(self, "subject_hash_key", key)
        object.__setattr__(self, "subject_hash_key_id", _safe_text_or_none(self.subject_hash_key_id, max_len=16))
        object.__setattr__(self, "min_hash_key_bytes", max(8, min(4096, int(self.min_hash_key_bytes))))
        object.__setattr__(self, "subject_hash_hex_chars", max(8, min(64, int(self.subject_hash_hex_chars))))
        mode = _safe_label(self.public_subject_id_mode, default="hash")
        if mode not in {"clear", "hash", "clear_if_allowed"}:
            mode = "hash"
        if _profile_is_strict(prof) and mode == "clear":
            mode = "hash"
        object.__setattr__(self, "public_subject_id_mode", mode)
        allow_profiles = _normalize_str_tuple(self.allow_clear_subject_profiles, max_len=16, max_items=8, lower=False)
        fixed_profiles: List[str] = []
        for p in allow_profiles:
            up = p.upper()
            if up in _ALLOWED_PROFILES and up not in fixed_profiles:
                fixed_profiles.append(up)
        object.__setattr__(self, "allow_clear_subject_profiles", tuple(fixed_profiles) or ("DEV",))
        object.__setattr__(self, "public_include_payload", bool(self.public_include_payload))
        object.__setattr__(self, "public_include_internal_digests", bool(self.public_include_internal_digests))
        phase = _safe_label(self.default_phase, default="evaluated")
        if phase not in _ALLOWED_PHASES:
            phase = "evaluated"
        object.__setattr__(self, "default_phase", phase)
        src = _safe_label(self.default_source_classification, default="control_plane_produced")
        if src not in _ALLOWED_SOURCE_CLASSIFICATION:
            src = "control_plane_produced"
        object.__setattr__(self, "default_source_classification", src)
        stm = _safe_label(self.default_signal_trust_mode, default="trusted")
        if stm not in _ALLOWED_SIGNAL_TRUST:
            stm = "trusted"
        object.__setattr__(self, "default_signal_trust_mode", stm)
        sem = _safe_label(self.sink_error_mode, default="log_and_continue")
        if sem not in {"log_and_continue", "disable_sink", "raise"}:
            sem = "log_and_continue"
        object.__setattr__(self, "sink_error_mode", sem)

    def config_fingerprint(self) -> str:
        payload = {
            "profile": self.profile,
            "compatibility_epoch": self.compatibility_epoch,
            "decay_half_life_sec": self.decay_half_life_sec,
            "trust_update_step": self.trust_update_step,
            "positive_cap": self.positive_cap,
            "negative_cap": self.negative_cap,
            "neutral_trust": self.neutral_trust,
            "freeze_on_compromise_sec": self.freeze_on_compromise_sec,
            "severe_negative_weight_threshold": self.severe_negative_weight_threshold,
            "recent_window_s": self.recent_window_s,
            "max_evidence_per_subject": self.max_evidence_per_subject,
            "max_total_evidence": self.max_total_evidence,
            "max_subjects": self.max_subjects,
            "max_edges_per_subject": self.max_edges_per_subject,
            "max_total_edges": self.max_total_edges,
            "idem_ttl_sec": self.idem_ttl_sec,
            "max_payload_items": self.max_payload_items,
            "max_payload_str_len": self.max_payload_str_len,
            "max_payload_bytes": self.max_payload_bytes,
            "hash_subject_ids": self.hash_subject_ids,
            "subject_hash_key_present": self.subject_hash_key is not None,
            "subject_hash_key_id": self.subject_hash_key_id,
            "subject_hash_hex_chars": self.subject_hash_hex_chars,
            "public_subject_id_mode": self.public_subject_id_mode,
            "allow_clear_subject_profiles": list(self.allow_clear_subject_profiles),
            "public_include_payload": self.public_include_payload,
            "public_include_internal_digests": self.public_include_internal_digests,
            "default_phase": self.default_phase,
            "default_source_classification": self.default_source_classification,
            "default_signal_trust_mode": self.default_signal_trust_mode,
            "sink_error_mode": self.sink_error_mode,
        }
        return f"tgcfg2:{_hash_hex(ctx='tcd:trust_graph:config', payload=payload, out_hex=32)}"


@dataclass(frozen=True, slots=True)
class TrustGraphPublicConfigView:
    cfg_fp: str
    profile: str
    compatibility_epoch: str
    hash_subject_ids: bool
    public_subject_id_mode: str
    public_include_payload: bool
    max_evidence_per_subject: int
    max_total_evidence: int
    recent_window_s: float


@dataclass(frozen=True, slots=True)
class TrustGraphDiagnosticsView:
    cfg_fp: str
    profile: str
    active_subjects: int
    total_evidence: int
    total_edges: int
    seen_idempotency_keys: int
    telemetry_sink_enabled: bool
    audit_sink_enabled: bool
    last_error_kind: Optional[str]
    last_error_message: Optional[str]


@dataclass(frozen=True, slots=True)
class TrustEdge:
    schema: str
    schema_version: int
    compatibility_epoch: str
    edge_id: str
    from_event_id: str
    to_ref_id: str
    relation: str
    subject_hash: Optional[str]
    evidence_type: str
    route_plan_id: Optional[str] = None
    route_id: Optional[str] = None
    decision_id: Optional[str] = None
    resource_id: Optional[str] = None
    resource_kind: Optional[str] = None
    ts_unix_ns: int = 0
    payload_digest: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "compatibility_epoch": self.compatibility_epoch,
            "edge_id": self.edge_id,
            "from_event_id": self.from_event_id,
            "to_ref_id": self.to_ref_id,
            "relation": self.relation,
            "subject_hash": self.subject_hash,
            "evidence_type": self.evidence_type,
            "route_plan_id": self.route_plan_id,
            "route_id": self.route_id,
            "decision_id": self.decision_id,
            "resource_id": self.resource_id,
            "resource_kind": self.resource_kind,
            "ts_unix_ns": self.ts_unix_ns,
            "payload_digest": self.payload_digest,
        }


@dataclass(frozen=True, slots=True)
class Evidence:
    schema: str
    schema_version: int
    compatibility_epoch: str
    canonicalization_version: str

    evidence_id: str
    event_type: str
    evidence_fingerprint: str
    observation_digest: str
    assessment_digest: str
    payload_digest: str
    evidence_digest: str

    subject_id: str
    public_subject_id: Optional[str]
    subject_id_exposed: bool
    subject_hash: Optional[str]

    type: EvidenceType
    phase: str
    source_classification: str
    signal_trust_mode: str

    timestamp: float
    ts_unix_ns: int
    ts_monotonic_ns: int
    weight: float
    payload: Mapping[str, Any] = field(default_factory=dict)

    channel: str = "unknown"
    source_id: str = ""
    trust_zone: str = "unknown"
    route_profile: str = "unknown"
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

    route_plan_id: Optional[str] = None
    route_id: Optional[str] = None
    decision_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    parent_decision_id: Optional[str] = None
    parent_route_plan_id: Optional[str] = None
    resource_id: Optional[str] = None
    resource_kind: Optional[str] = None

    threat_label: str = ""
    threat_vector: str = ""
    severity_label: str = "normal"
    severity_score: float = 0.0
    reason_codes: Tuple[str, ...] = ()
    normalization_warnings: Tuple[str, ...] = ()

    override_applied: bool = False
    override_actor: str = ""
    override_reason: str = ""
    supply_chain_ref: str = ""
    pq_required: Optional[bool] = None
    pq_ok: Optional[bool] = None
    pq_chain_id: str = ""
    pq_signature_required: Optional[bool] = None
    pq_signature_ok: Optional[bool] = None
    risk_score_raw: Optional[float] = None

    idem_token: Optional[str] = None
    idem_scope: Optional[str] = None
    idem_fingerprint: Optional[str] = None
    replay_suppressed: bool = False
    idempotency_conflict: bool = False
    applied_to_state: bool = True
    freeze_suppressed: bool = False

    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None
    ledger_ref: Optional[str] = None
    attestation_ref: Optional[str] = None
    prepare_ref: Optional[str] = None
    commit_ref: Optional[str] = None
    outbox_ref: Optional[str] = None
    outbox_status: Optional[str] = None
    outbox_dedupe_key: Optional[str] = None
    delivery_attempts: Optional[int] = None
    ledger_stage: Optional[str] = None
    chain_id: Optional[str] = None
    chain_head: Optional[str] = None

    produced_by: Tuple[str, ...] = field(default_factory=lambda: ("tcd.trust_graph",))
    provenance_path_digest: Optional[str] = None

    public_payload_allowed: bool = True
    public_internal_digests_allowed: bool = False

    def to_dict(self, *, public: bool, include_internal: bool) -> Dict[str, Any]:
        payload_out: Any = dict(self.payload) if (not public or self.public_payload_allowed) else {}
        subject_id_out = self.public_subject_id if public else self.subject_id
        out: Dict[str, Any] = {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "compatibility_epoch": self.compatibility_epoch,
            "canonicalization_version": self.canonicalization_version,
            "evidence_id": self.evidence_id,
            "event_type": self.event_type,
            "subject_id": subject_id_out,
            "subject_hash": self.subject_hash,
            "subject_id_exposed": self.subject_id_exposed if public else True,
            "type": self.type.value,
            "phase": self.phase,
            "source_classification": self.source_classification,
            "signal_trust_mode": self.signal_trust_mode,
            "timestamp": self.timestamp,
            "ts_unix_ns": self.ts_unix_ns,
            "ts_monotonic_ns": self.ts_monotonic_ns,
            "weight": self.weight,
            "payload": payload_out,
            "channel": self.channel,
            "source_id": self.source_id,
            "trust_zone": self.trust_zone,
            "route_profile": self.route_profile,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
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
            "route_plan_id": self.route_plan_id,
            "route_id": self.route_id,
            "decision_id": self.decision_id,
            "parent_event_id": self.parent_event_id,
            "parent_decision_id": self.parent_decision_id,
            "parent_route_plan_id": self.parent_route_plan_id,
            "resource_id": self.resource_id,
            "resource_kind": self.resource_kind,
            "threat_label": self.threat_label,
            "threat_vector": self.threat_vector,
            "severity_label": self.severity_label,
            "severity_score": self.severity_score,
            "reason_codes": list(self.reason_codes),
            "normalization_warnings": list(self.normalization_warnings),
            "override_applied": self.override_applied,
            "override_actor": self.override_actor if not public else None,
            "override_reason": self.override_reason,
            "supply_chain_ref": self.supply_chain_ref,
            "pq_required": self.pq_required,
            "pq_ok": self.pq_ok,
            "pq_chain_id": self.pq_chain_id,
            "pq_signature_required": self.pq_signature_required,
            "pq_signature_ok": self.pq_signature_ok,
            "risk_score_raw": self.risk_score_raw,
            "replay_suppressed": self.replay_suppressed,
            "idempotency_conflict": self.idempotency_conflict,
            "applied_to_state": self.applied_to_state,
            "freeze_suppressed": self.freeze_suppressed,
            "audit_ref": self.audit_ref,
            "receipt_ref": self.receipt_ref,
            "ledger_ref": self.ledger_ref,
            "attestation_ref": self.attestation_ref,
            "prepare_ref": self.prepare_ref,
            "commit_ref": self.commit_ref,
            "outbox_ref": self.outbox_ref,
            "outbox_status": self.outbox_status,
            "outbox_dedupe_key": self.outbox_dedupe_key,
            "delivery_attempts": self.delivery_attempts,
            "ledger_stage": self.ledger_stage,
            "chain_id": self.chain_id,
            "chain_head": self.chain_head,
            "produced_by": list(self.produced_by),
            "provenance_path_digest": self.provenance_path_digest,
        }
        if include_internal:
            out.update(
                {
                    "evidence_fingerprint": self.evidence_fingerprint,
                    "observation_digest": self.observation_digest,
                    "assessment_digest": self.assessment_digest,
                    "payload_digest": self.payload_digest,
                    "evidence_digest": self.evidence_digest,
                    "policy_digest": self.policy_digest,
                    "cfg_fp": self.cfg_fp,
                    "idem_token": self.idem_token,
                    "idem_scope": self.idem_scope,
                    "idem_fingerprint": self.idem_fingerprint,
                    "public_subject_id": self.public_subject_id,
                    "public_payload_allowed": self.public_payload_allowed,
                    "public_internal_digests_allowed": self.public_internal_digests_allowed,
                }
            )
        elif public and self.public_internal_digests_allowed:
            out.update(
                {
                    "evidence_fingerprint": self.evidence_fingerprint,
                    "observation_digest": self.observation_digest,
                    "assessment_digest": self.assessment_digest,
                    "payload_digest": self.payload_digest,
                    "evidence_digest": self.evidence_digest,
                    "policy_digest": self.policy_digest,
                    "cfg_fp": self.cfg_fp,
                }
            )
        return out

    def to_public_dict(self) -> Dict[str, Any]:
        return self.to_dict(public=True, include_internal=False)

    def to_audit_dict(self) -> Dict[str, Any]:
        return self.to_dict(public=False, include_internal=True)

    def to_storage_meta(self) -> Dict[str, Any]:
        return {
            "trust_evidence_id": self.evidence_id,
            "trust_subject_hash": self.subject_hash,
            "trust_type": self.type.value,
            "trust_phase": self.phase,
            "trust_source_classification": self.source_classification,
            "trust_weight": self.weight,
            "trust_channel": self.channel,
            "trust_source_id": self.source_id,
            "trust_trust_zone": self.trust_zone,
            "trust_route_profile": self.route_profile,
            "trust_policy_ref": self.policy_ref,
            "trust_policyset_ref": self.policyset_ref,
            "trust_cfg_fp": self.cfg_fp,
            "trust_state_domain_id": self.state_domain_id,
            "trust_adapter_registry_fp": self.adapter_registry_fp,
            "trust_controller_mode": self.controller_mode,
            "trust_statistical_guarantee_scope": self.statistical_guarantee_scope,
            "trust_decision_id": self.decision_id,
            "trust_route_plan_id": self.route_plan_id,
            "trust_route_id": self.route_id,
            "trust_threat_vector": self.threat_vector,
            "trust_pq_required": self.pq_required,
            "trust_pq_ok": self.pq_ok,
            "trust_audit_ref": self.audit_ref,
            "trust_receipt_ref": self.receipt_ref,
            "trust_ledger_ref": self.ledger_ref,
            "trust_replay_suppressed": self.replay_suppressed,
            "trust_idempotency_conflict": self.idempotency_conflict,
            "trust_reason_codes": list(self.reason_codes),
        }

    def to_evidence_identity_dict(self) -> Dict[str, Any]:
        identity_status = "ok"
        if self.idempotency_conflict:
            identity_status = "idempotency_conflict"
        elif self.replay_suppressed:
            identity_status = "replay_suppressed"
        elif self.freeze_suppressed:
            identity_status = "frozen"
        elif not self.applied_to_state:
            identity_status = "suppressed"

        payload = {
            "event_id": self.evidence_id,
            "event_id_kind": "event",
            "decision_id": self.decision_id,
            "decision_id_kind": "decision",
            "route_plan_id": self.route_plan_id,
            "route_id": self.route_id or self.route_plan_id,
            "route_id_kind": "plan",
            "config_fingerprint": self.cfg_fp,
            "bundle_version": self.bundle_version,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "state_domain_id": self.state_domain_id,
            "activation_id": self.activation_id,
            "patch_id": self.patch_id,
            "change_ticket_id": self.change_ticket_id,
            "controller_mode": self.controller_mode,
            "statistical_guarantee_scope": self.statistical_guarantee_scope,
            "adapter_registry_fp": self.adapter_registry_fp,
            "selected_source": self.selected_source,
            "state_revision": None,
            "identity_status": identity_status,
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
            "ledger_ref": self.ledger_ref,
            "attestation_ref": self.attestation_ref,
            "event_digest": self.evidence_digest,
            "body_digest": self.assessment_digest,
            "payload_digest": self.payload_digest,
            "prepare_ref": self.prepare_ref,
            "commit_ref": self.commit_ref,
            "ledger_stage": self.ledger_stage,
            "outbox_ref": self.outbox_ref,
            "outbox_status": self.outbox_status,
            "outbox_dedupe_key": self.outbox_dedupe_key,
            "delivery_attempts": self.delivery_attempts,
            "chain_id": self.chain_id,
            "chain_head": self.chain_head,
            "produced_by": list(self.produced_by),
            "provenance_path_digest": self.provenance_path_digest,
        }
        if ArtifactRefsView is not None:
            with contextlib.suppress(Exception):
                obj = ArtifactRefsView(**payload)
                if hasattr(obj, "model_dump"):
                    return dict(obj.model_dump())
        return payload

    def to_receipt_claims(self, *, chain_namespace: str = "trust_graph", chain_id: Optional[str] = None, prev_head_hex: Optional[str] = None) -> Dict[str, Any]:
        cid = _safe_id(chain_id, default=None, max_len=128) or (self.subject_hash or "trust_subject")
        return {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "compatibility_epoch": self.compatibility_epoch,
            "canonicalization_version": self.canonicalization_version,
            "receipt_kind": "trust_graph",
            "event_type": self.event_type,
            "event_id": self.evidence_id,
            "decision_id": self.decision_id,
            "route_plan_id": self.route_plan_id,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "cfg_fp": self.cfg_fp,
            "state_domain_id": self.state_domain_id,
            "adapter_registry_fp": self.adapter_registry_fp,
            "audit_ref": self.audit_ref,
            "receipt_ref": self.receipt_ref,
            "chain_namespace": _safe_id(chain_namespace, default="trust_graph", max_len=128) or "trust_graph",
            "chain_id": cid,
            "prev_head_hex": prev_head_hex,
            "selected_source": self.selected_source or self.channel or "trust_graph",
            "statistical_guarantee_scope": self.statistical_guarantee_scope,
            "pq_required": self.pq_required,
            "pq_ok": self.pq_ok,
            "pq_signature_required": self.pq_signature_required,
            "pq_signature_ok": self.pq_signature_ok,
            "ts": self.timestamp,
            "ts_unix_ns": self.ts_unix_ns,
            "trigger": self.weight < 0 or self.threat_vector not in {"", "none"},
            "allowed": self.weight >= 0 and not self.idempotency_conflict,
            "reason": ";".join(self.reason_codes) if self.reason_codes else self.type.value,
            "produced_by": list(self.produced_by),
            "provenance_path_digest": self.provenance_path_digest,
            "payload_digest": self.payload_digest,
            "event_digest": self.evidence_digest,
            "meta": self.to_storage_meta(),
        }

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "Evidence":
        kwargs: Dict[str, Any] = {}
        field_names = {f.name for f in dataclass_fields(cls)}
        for k in field_names:
            if k not in data:
                continue
            kwargs[k] = data[k]
        t = kwargs.get("type", EvidenceType.DECISION.value)
        if not isinstance(t, EvidenceType):
            with contextlib.suppress(Exception):
                kwargs["type"] = EvidenceType(str(t))
        payload = kwargs.get("payload")
        if isinstance(payload, Mapping):
            kwargs["payload"] = MappingProxyType(dict(payload))
        for tk in (
            "reason_codes",
            "normalization_warnings",
            "produced_by",
        ):
            if tk in kwargs and isinstance(kwargs[tk], list):
                kwargs[tk] = tuple(kwargs[tk])
        return cls(**kwargs)


@dataclass(frozen=True, slots=True)
class TrustState:
    schema: str
    schema_version: int
    compatibility_epoch: str

    subject_id: str
    public_subject_id: Optional[str]
    subject_id_exposed: bool
    subject_hash: Optional[str]

    trust_score: float
    observations: int
    last_update_ts: float
    last_update_unix_ns: int
    last_evidence_id: Optional[str]
    last_evidence_type: Optional[str]

    risk_band: str
    flags: Tuple[str, ...]
    compromised: bool
    freeze_until_ts: Optional[float]
    lockdown_level: str

    last_pq_required: Optional[bool]
    last_pq_ok: Optional[bool]
    last_pq_chain_id: str
    last_supply_chain_ref: str

    threat_counters: Mapping[str, int]
    recent_threat_counters: Mapping[str, int]
    type_counters: Mapping[str, int]
    recent_type_counters: Mapping[str, int]

    last_policy_ref: Optional[str] = None
    last_policyset_ref: Optional[str] = None
    last_cfg_fp: Optional[str] = None
    last_state_domain_id: Optional[str] = None
    last_adapter_registry_fp: Optional[str] = None
    last_controller_mode: Optional[str] = None
    last_decision_mode: Optional[str] = None
    last_statistical_guarantee_scope: Optional[str] = None
    last_activation_id: Optional[str] = None
    last_patch_id: Optional[str] = None
    last_change_ticket_id: Optional[str] = None
    last_audit_ref: Optional[str] = None
    last_receipt_ref: Optional[str] = None
    last_decision_id: Optional[str] = None
    last_route_plan_id: Optional[str] = None
    last_route_id: Optional[str] = None

    recent_reason_codes: Tuple[str, ...] = ()
    decayed_positive_weight: float = 0.0
    decayed_negative_weight: float = 0.0
    recent_negative_events: int = 0
    recent_positive_events: int = 0

    def to_dict(self, *, public: bool = False) -> Dict[str, Any]:
        subject_id_out = self.public_subject_id if public else self.subject_id
        payload = {
            "schema": self.schema,
            "schema_version": self.schema_version,
            "compatibility_epoch": self.compatibility_epoch,
            "subject_id": subject_id_out,
            "subject_hash": self.subject_hash,
            "subject_id_exposed": self.subject_id_exposed if public else True,
            "trust_score": self.trust_score,
            "observations": self.observations,
            "last_update_ts": self.last_update_ts,
            "last_update_unix_ns": self.last_update_unix_ns,
            "last_evidence_id": self.last_evidence_id,
            "last_evidence_type": self.last_evidence_type,
            "risk_band": self.risk_band,
            "flags": list(self.flags),
            "compromised": self.compromised,
            "freeze_until_ts": self.freeze_until_ts,
            "lockdown_level": self.lockdown_level,
            "last_pq_required": self.last_pq_required,
            "last_pq_ok": self.last_pq_ok,
            "last_pq_chain_id": self.last_pq_chain_id,
            "last_supply_chain_ref": self.last_supply_chain_ref,
            "threat_counters": dict(self.threat_counters),
            "recent_threat_counters": dict(self.recent_threat_counters),
            "type_counters": dict(self.type_counters),
            "recent_type_counters": dict(self.recent_type_counters),
            "last_policy_ref": self.last_policy_ref,
            "last_policyset_ref": self.last_policyset_ref,
            "last_cfg_fp": self.last_cfg_fp,
            "last_state_domain_id": self.last_state_domain_id,
            "last_adapter_registry_fp": self.last_adapter_registry_fp,
            "last_controller_mode": self.last_controller_mode,
            "last_decision_mode": self.last_decision_mode,
            "last_statistical_guarantee_scope": self.last_statistical_guarantee_scope,
            "last_activation_id": self.last_activation_id,
            "last_patch_id": self.last_patch_id,
            "last_change_ticket_id": self.last_change_ticket_id,
            "last_audit_ref": self.last_audit_ref,
            "last_receipt_ref": self.last_receipt_ref,
            "last_decision_id": self.last_decision_id,
            "last_route_plan_id": self.last_route_plan_id,
            "last_route_id": self.last_route_id,
            "recent_reason_codes": list(self.recent_reason_codes),
            "decayed_positive_weight": self.decayed_positive_weight,
            "decayed_negative_weight": self.decayed_negative_weight,
            "recent_negative_events": self.recent_negative_events,
            "recent_positive_events": self.recent_positive_events,
        }
        payload["state_digest"] = f"tgst2:sha256:{_hash_hex(ctx='tcd:trust_graph:state', payload=payload, out_hex=64)}"
        return payload


@dataclass(frozen=True, slots=True)
class _SeenIdempotency:
    ts: float
    fingerprint: str
    subject_id: str
    evidence_type: str


class TrustGraph:
    def __init__(
        self,
        config: Optional[TrustGraphConfig] = None,
        *,
        telemetry_sink: Optional[TrustGraphTelemetrySink] = None,
        audit_sink: Optional[TrustGraphAuditSink] = None,
    ) -> None:
        self.config = config or TrustGraphConfig()
        self._telemetry_sink = telemetry_sink
        self._audit_sink = audit_sink
        self._lock = threading.RLock()

        self._states: Dict[str, TrustState] = {}
        self._subject_order: "OrderedDict[str, None]" = OrderedDict()
        self._evidence_by_subject: Dict[str, Deque[Evidence]] = {}
        self._edges_by_subject: Dict[str, Deque[TrustEdge]] = {}
        self._event_log: Deque[Evidence] = deque()
        self._edge_log: Deque[TrustEdge] = deque()
        self._seen_idem: Dict[str, _SeenIdempotency] = {}

        self._last_error_kind: Optional[str] = None
        self._last_error_message: Optional[str] = None

    # ------------------------------------------------------------------
    # Views / diagnostics
    # ------------------------------------------------------------------

    def public_config_view(self) -> TrustGraphPublicConfigView:
        return TrustGraphPublicConfigView(
            cfg_fp=self.config.config_fingerprint(),
            profile=self.config.profile,
            compatibility_epoch=self.config.compatibility_epoch,
            hash_subject_ids=self.config.hash_subject_ids,
            public_subject_id_mode=self.config.public_subject_id_mode,
            public_include_payload=self.config.public_include_payload,
            max_evidence_per_subject=self.config.max_evidence_per_subject,
            max_total_evidence=self.config.max_total_evidence,
            recent_window_s=self.config.recent_window_s,
        )

    def diagnostics_view(self) -> TrustGraphDiagnosticsView:
        with self._lock:
            return TrustGraphDiagnosticsView(
                cfg_fp=self.config.config_fingerprint(),
                profile=self.config.profile,
                active_subjects=len(self._states),
                total_evidence=len(self._event_log),
                total_edges=len(self._edge_log),
                seen_idempotency_keys=len(self._seen_idem),
                telemetry_sink_enabled=self._telemetry_sink is not None,
                audit_sink_enabled=self._audit_sink is not None,
                last_error_kind=self._last_error_kind,
                last_error_message=self._last_error_message,
            )

    # ------------------------------------------------------------------
    # Public read APIs
    # ------------------------------------------------------------------

    def get_state(self, subject: SubjectKey) -> TrustState:
        sid = _sanitize_subject(subject).as_id()
        return self.get_state_by_id(sid)

    def get_state_by_id(self, subject_id: str) -> TrustState:
        with self._lock:
            st = self._states.get(subject_id)
            if st is None:
                st = self._make_empty_state(subject_id)
                self._states[subject_id] = st
            self._touch_subject(subject_id)
            return st

    def list_subjects(self) -> List[str]:
        with self._lock:
            return list(self._states.keys())

    def get_recent_evidence(self, subject: SubjectKey, limit: int = 32) -> List[Evidence]:
        sid = _sanitize_subject(subject).as_id()
        return self.get_recent_evidence_by_id(sid, limit=limit)

    def get_recent_evidence_by_id(self, subject_id: str, limit: int = 32) -> List[Evidence]:
        lim = max(0, int(limit))
        with self._lock:
            return list(self._evidence_by_subject.get(subject_id, deque()))[-lim:]

    def get_recent_edges(self, subject: SubjectKey, limit: int = 32) -> List[TrustEdge]:
        sid = _sanitize_subject(subject).as_id()
        lim = max(0, int(limit))
        with self._lock:
            return list(self._edges_by_subject.get(sid, deque()))[-lim:]

    def snapshot(self, subject: SubjectKey, *, public: bool = False) -> Dict[str, Any]:
        return self.get_state(subject).to_dict(public=public)

    def snapshots(self, *, limit: int = 1000, public: bool = False) -> List[Dict[str, Any]]:
        lim = max(1, min(100000, int(limit)))
        with self._lock:
            ids = list(self._states.keys())[:lim]
            return [self._states[s].to_dict(public=public) for s in ids]

    def export_event_log(self, *, limit: Optional[int] = None, public: bool = False) -> List[Dict[str, Any]]:
        with self._lock:
            seq = list(self._event_log)
        if limit is not None:
            seq = seq[-max(0, int(limit)) :]
        if public:
            return [e.to_public_dict() for e in seq]
        return [e.to_audit_dict() for e in seq]

    def export_edge_log(self, *, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._lock:
            seq = list(self._edge_log)
        if limit is not None:
            seq = seq[-max(0, int(limit)) :]
        return [e.to_dict() for e in seq]

    # ------------------------------------------------------------------
    # Maintenance / replay
    # ------------------------------------------------------------------

    def clear(self) -> None:
        with self._lock:
            self._states.clear()
            self._subject_order.clear()
            self._evidence_by_subject.clear()
            self._edges_by_subject.clear()
            self._event_log.clear()
            self._edge_log.clear()
            self._seen_idem.clear()

    def rebuild_states_from_event_log(self) -> None:
        with self._lock:
            subject_ids = list(self._evidence_by_subject.keys())
            self._states = {}
            self._subject_order = OrderedDict()
            for sid in subject_ids:
                self._states[sid] = self._recompute_state_from_subject_events(sid, list(self._evidence_by_subject.get(sid, deque())))
                self._touch_subject(sid)

    def restore_from_export(self, records: Sequence[Mapping[str, Any]]) -> None:
        with self._lock:
            self.clear()
            for row in records:
                ev = Evidence.from_mapping(row)
                self._append_evidence_index_only(ev)
                for edge in self._build_edges_for_evidence(ev):
                    self._append_edge_index_only(edge)
            self.rebuild_states_from_event_log()

    # ------------------------------------------------------------------
    # Public write APIs
    # ------------------------------------------------------------------

    def add_evidence(self, evidence: Evidence) -> TrustState:
        return self._apply_evidence(evidence)

    def add_receipt_evidence(
        self,
        subject: SubjectKey,
        *,
        score: float,
        verdict: bool,
        e_value: Optional[float] = None,
        receipt_head_hex: Optional[str] = None,
        trust_hint: Optional[float] = None,
        extra: Optional[Mapping[str, Any]] = None,
        channel: str = "receipt",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        policyset_ref: Optional[str] = None,
        policy_digest: Optional[str] = None,
        cfg_fp: Optional[str] = None,
        bundle_version: Optional[int] = None,
        state_domain_id: Optional[str] = None,
        adapter_registry_fp: Optional[str] = None,
        selected_source: Optional[str] = None,
        controller_mode: Optional[str] = None,
        decision_mode: Optional[str] = None,
        statistical_guarantee_scope: Optional[str] = None,
        activation_id: Optional[str] = None,
        patch_id: Optional[str] = None,
        change_ticket_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        route_plan_id: Optional[str] = None,
        route_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        threat_label: str = "",
        threat_vector: str = "",
        override_applied: bool = False,
        override_actor: str = "",
        supply_chain_ref: str = "",
        pq_required: Optional[bool] = None,
        pq_ok: Optional[bool] = None,
        pq_chain_id: str = "",
        pq_signature_required: Optional[bool] = None,
        pq_signature_ok: Optional[bool] = None,
        audit_ref: Optional[str] = None,
        receipt_ref: Optional[str] = None,
        ledger_ref: Optional[str] = None,
        attestation_ref: Optional[str] = None,
        produced_by: Sequence[str] = ("tcd.trust_graph",),
        idem_token: Optional[str] = None,
    ) -> TrustState:
        payload: Dict[str, Any] = {
            "score": float(score),
            "verdict": bool(verdict),
            "e_value": float(e_value) if e_value is not None and math.isfinite(float(e_value)) else None,
            "receipt_head": _normalize_digest_token(receipt_head_hex, kind="any", default=None),
        }
        if extra:
            payload.update(dict(extra))
        weight = self._weight_from_risk(score=score, verdict=verdict, trust_hint=trust_hint)
        reason_codes = ("RECEIPT_UNSAFE",) if verdict else ("RECEIPT_SAFE",)
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.RECEIPT,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            policyset_ref=policyset_ref,
            policy_digest=policy_digest,
            cfg_fp=cfg_fp,
            bundle_version=bundle_version,
            state_domain_id=state_domain_id,
            adapter_registry_fp=adapter_registry_fp,
            selected_source=selected_source,
            controller_mode=controller_mode,
            decision_mode=decision_mode,
            statistical_guarantee_scope=statistical_guarantee_scope,
            activation_id=activation_id,
            patch_id=patch_id,
            change_ticket_id=change_ticket_id,
            decision_id=decision_id,
            route_plan_id=route_plan_id,
            route_id=route_id,
            parent_event_id=parent_event_id,
            threat_label=threat_label,
            threat_vector=threat_vector or threat_label or "",
            severity_score=min(1.0, abs(weight) / max(self.config.negative_cap, self.config.positive_cap)),
            override_applied=override_applied,
            override_actor=override_actor,
            supply_chain_ref=supply_chain_ref,
            pq_required=pq_required,
            pq_ok=pq_ok,
            pq_chain_id=pq_chain_id,
            pq_signature_required=pq_signature_required,
            pq_signature_ok=pq_signature_ok,
            risk_score_raw=float(score),
            idem_token=idem_token,
            reason_codes=reason_codes,
            audit_ref=audit_ref,
            receipt_ref=receipt_ref,
            ledger_ref=ledger_ref,
            attestation_ref=attestation_ref,
            produced_by=tuple(produced_by),
        )
        return self._apply_evidence(evidence)

    def add_decision_evidence(
        self,
        subject: SubjectKey,
        *,
        decision: str,
        score: float,
        trust_hint: Optional[float] = None,
        extra: Optional[Mapping[str, Any]] = None,
        channel: str = "decision",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        policyset_ref: Optional[str] = None,
        policy_digest: Optional[str] = None,
        cfg_fp: Optional[str] = None,
        bundle_version: Optional[int] = None,
        state_domain_id: Optional[str] = None,
        adapter_registry_fp: Optional[str] = None,
        selected_source: Optional[str] = None,
        controller_mode: Optional[str] = None,
        decision_mode: Optional[str] = None,
        statistical_guarantee_scope: Optional[str] = None,
        activation_id: Optional[str] = None,
        patch_id: Optional[str] = None,
        change_ticket_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        route_plan_id: Optional[str] = None,
        route_id: Optional[str] = None,
        threat_label: str = "",
        threat_vector: str = "",
        override_applied: bool = False,
        override_actor: str = "",
        pq_required: Optional[bool] = None,
        pq_ok: Optional[bool] = None,
        pq_chain_id: str = "",
        audit_ref: Optional[str] = None,
        idem_token: Optional[str] = None,
    ) -> TrustState:
        dec = _safe_text(decision, max_len=64).lower()
        payload: Dict[str, Any] = {"decision": dec, "score": float(score)}
        if extra:
            payload.update(dict(extra))
        negative = dec in {"block", "throttle", "escalate_to_human", "degrade"}
        weight = self._weight_from_risk(score=score, verdict=negative, trust_hint=trust_hint)
        if dec == "block":
            reason = "DECISION_BLOCK"
        elif dec == "degrade":
            reason = "DECISION_DEGRADE"
        else:
            reason = "DECISION_ALLOW"
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.DECISION,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            policyset_ref=policyset_ref,
            policy_digest=policy_digest,
            cfg_fp=cfg_fp,
            bundle_version=bundle_version,
            state_domain_id=state_domain_id,
            adapter_registry_fp=adapter_registry_fp,
            selected_source=selected_source,
            controller_mode=controller_mode,
            decision_mode=decision_mode,
            statistical_guarantee_scope=statistical_guarantee_scope,
            activation_id=activation_id,
            patch_id=patch_id,
            change_ticket_id=change_ticket_id,
            decision_id=decision_id,
            route_plan_id=route_plan_id,
            route_id=route_id,
            threat_label=threat_label,
            threat_vector=threat_vector or threat_label or "",
            severity_score=min(1.0, abs(weight) / max(self.config.negative_cap, self.config.positive_cap)),
            override_applied=override_applied,
            override_actor=override_actor,
            pq_required=pq_required,
            pq_ok=pq_ok,
            pq_chain_id=pq_chain_id,
            risk_score_raw=float(score),
            idem_token=idem_token,
            reason_codes=(reason,),
            audit_ref=audit_ref,
        )
        return self._apply_evidence(evidence)

    def add_action_evidence(
        self,
        subject: SubjectKey,
        *,
        action_result: Any,
        channel: str = "action",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        decision_id: Optional[str] = None,
        route_plan_id: Optional[str] = None,
        route_id: Optional[str] = None,
        idem_token: Optional[str] = None,
    ) -> TrustState:
        payload = {
            "action": _safe_text(getattr(action_result, "action", None), max_len=64),
            "mode": _safe_text(getattr(getattr(action_result, "mode", None), "value", getattr(action_result, "mode", None)), max_len=64),
            "ok": bool(getattr(action_result, "ok", False)),
            "duration_ms": self._action_duration_ms(action_result),
            "reason_code": _safe_reason_code(getattr(action_result, "reason_code", None), default=None),
            "error_kind": _safe_text(getattr(action_result, "error_kind", None), max_len=64),
        }
        details = getattr(action_result, "details", None)
        if isinstance(details, Mapping):
            payload["details"] = dict(details)
        weight = self._weight_from_action(action_result)
        reason = "ACTION_FAILURE" if weight < 0 else "ACTION_SUCCESS"
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.ACTION,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            decision_id=decision_id,
            route_plan_id=route_plan_id,
            route_id=route_id,
            severity_score=min(1.0, abs(weight) / max(self.config.negative_cap, self.config.positive_cap)),
            reason_codes=(reason,),
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    def add_verification_evidence(
        self,
        subject: SubjectKey,
        *,
        ok: bool,
        head_hex: Optional[str] = None,
        extra: Optional[Mapping[str, Any]] = None,
        channel: str = "verification",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        decision_id: Optional[str] = None,
        route_plan_id: Optional[str] = None,
        route_id: Optional[str] = None,
        supply_chain_ref: str = "",
        pq_required: Optional[bool] = None,
        pq_ok: Optional[bool] = None,
        pq_chain_id: str = "",
        threat_label: str = "",
        threat_vector: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        payload: Dict[str, Any] = {"ok": bool(ok), "head": _normalize_digest_token(head_hex, kind="any", default=None)}
        if extra:
            payload.update(dict(extra))
        weight = self._weight_from_verification(ok=ok)
        reason = "VERIFY_OK" if ok else "VERIFY_FAIL"
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.VERIFICATION,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            decision_id=decision_id,
            route_plan_id=route_plan_id,
            route_id=route_id,
            supply_chain_ref=supply_chain_ref,
            pq_required=pq_required,
            pq_ok=pq_ok,
            pq_chain_id=pq_chain_id,
            threat_label=threat_label,
            threat_vector=threat_vector or threat_label or "",
            severity_score=min(1.0, abs(weight) / max(self.config.negative_cap, self.config.positive_cap)),
            reason_codes=(reason,),
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    def add_anomaly_evidence(
        self,
        subject: SubjectKey,
        *,
        severity: float,
        label: str,
        extra: Optional[Mapping[str, Any]] = None,
        channel: str = "anomaly",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        decision_id: Optional[str] = None,
        route_plan_id: Optional[str] = None,
        route_id: Optional[str] = None,
        threat_label: str = "anomaly",
        threat_vector: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        sev = max(0.0, min(1.0, float(severity)))
        payload: Dict[str, Any] = {"severity": sev, "label": _safe_text(label, max_len=128)}
        if extra:
            payload.update(dict(extra))
        weight = -sev * self.config.negative_cap
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.ANOMALY,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            decision_id=decision_id,
            route_plan_id=route_plan_id,
            route_id=route_id,
            threat_label=threat_label,
            threat_vector=threat_vector or threat_label or "anomaly",
            severity_label="critical" if sev >= 0.9 else ("high" if sev >= 0.7 else ("medium" if sev >= 0.4 else "low")),
            severity_score=sev,
            reason_codes=("ANOMALY_DETECTED",),
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    def add_health_evidence(
        self,
        subject: SubjectKey,
        *,
        health_ok: bool,
        details: Mapping[str, Any],
        severity: float = 0.0,
        channel: str = "health",
        source_id: str = "gpu_probe",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        decision_id: Optional[str] = None,
        route_plan_id: Optional[str] = None,
        route_id: Optional[str] = None,
        supply_chain_ref: str = "",
        pq_required: Optional[bool] = None,
        pq_ok: Optional[bool] = None,
        pq_chain_id: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        sev = max(0.0, min(1.0, float(severity)))
        payload: Dict[str, Any] = {"health_ok": bool(health_ok), "severity": sev, "probe": dict(details)}
        weight = 0.2 * (1.0 - sev) if health_ok else -self.config.negative_cap * max(0.3, sev)
        threat_label = "" if health_ok else "health"
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.HEALTH,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            decision_id=decision_id,
            route_plan_id=route_plan_id,
            route_id=route_id,
            threat_label=threat_label,
            threat_vector="health" if threat_label else "",
            severity_label="high" if not health_ok and sev >= 0.6 else ("medium" if not health_ok else "low"),
            severity_score=sev,
            supply_chain_ref=supply_chain_ref or _safe_text(details.get("supply_chain_ref", ""), max_len=128),
            pq_required=pq_required,
            pq_ok=pq_ok,
            pq_chain_id=pq_chain_id,
            reason_codes=("HEALTH_FAIL",) if not health_ok else ("HEALTH_OK",),
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    def add_supply_chain_evidence(
        self,
        subject: SubjectKey,
        *,
        attested_ok: bool,
        build_id: str,
        image_digest: str,
        runtime_env: str,
        channel: str = "supply_chain",
        source_id: str = "supply_chain_attestor",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        pq_chain_id: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        payload: Dict[str, Any] = {
            "attested_ok": bool(attested_ok),
            "build_id": _safe_text(build_id, max_len=128),
            "image_digest": _safe_text(image_digest, max_len=256),
            "runtime_env": _safe_label(runtime_env, default="unknown"),
        }
        weight = 0.7 if attested_ok else -1.5
        threat_label = "" if attested_ok else "supply_chain"
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.SUPPLY_CHAIN,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label=threat_label,
            threat_vector="supply_chain" if threat_label else "",
            severity_label="high" if not attested_ok else "low",
            severity_score=1.0 if not attested_ok else 0.2,
            supply_chain_ref=_safe_text(image_digest or build_id, max_len=256),
            pq_chain_id=pq_chain_id,
            reason_codes=("SUPPLY_CHAIN_FAIL",) if not attested_ok else ("SUPPLY_CHAIN_OK",),
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    def add_override_evidence(
        self,
        subject: SubjectKey,
        *,
        reason: str,
        actor: str,
        channel: str = "override",
        source_id: str = "admin_console",
        trust_zone: str = "admin",
        route_profile: str = "control",
        policy_ref: str = "",
        change_ticket_id: Optional[str] = None,
        idem_token: Optional[str] = None,
    ) -> TrustState:
        payload = {"reason": _safe_text(reason, max_len=256), "actor": _safe_text(actor, max_len=128)}
        weight = -self.config.negative_cap
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.OVERRIDE,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            change_ticket_id=change_ticket_id,
            threat_label="insider",
            threat_vector="insider",
            severity_label="critical",
            severity_score=1.0,
            override_applied=True,
            override_actor=actor,
            override_reason=reason,
            reason_codes=("OVERRIDE_APPLIED",),
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    def add_pq_attestation_evidence(
        self,
        subject: SubjectKey,
        *,
        pq_required: bool,
        pq_ok: bool,
        detail: Optional[Mapping[str, Any]] = None,
        channel: str = "pq_attest",
        source_id: str = "pq_attestor",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        pq_chain_id: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        payload: Dict[str, Any] = {"pq_required": bool(pq_required), "pq_ok": bool(pq_ok)}
        if detail:
            payload.update(dict(detail))
        if pq_required and not pq_ok:
            weight = -1.5
            threat_label = "pq"
            reason = "PQ_REQUIRED_NOT_OK"
        elif pq_required and pq_ok:
            weight = 0.8
            threat_label = ""
            reason = "PQ_REQUIRED_OK"
        else:
            weight = 0.2 if pq_ok else 0.0
            threat_label = ""
            reason = "PQ_OPTIONAL"
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.PQ,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label=threat_label,
            threat_vector="pq" if threat_label else "",
            severity_label="high" if (pq_required and not pq_ok) else "low",
            severity_score=1.0 if (pq_required and not pq_ok) else 0.2,
            pq_required=pq_required,
            pq_ok=pq_ok,
            pq_chain_id=pq_chain_id,
            reason_codes=(reason,),
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    def add_route_evidence(
        self,
        subject: SubjectKey,
        *,
        required_action: str,
        enforcement_mode: str,
        safety_tier: str,
        score: float,
        route_plan_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        route_id: Optional[str] = None,
        policy_ref: str = "",
        policyset_ref: Optional[str] = None,
        cfg_fp: Optional[str] = None,
        state_domain_id: Optional[str] = None,
        adapter_registry_fp: Optional[str] = None,
        selected_source: Optional[str] = None,
        controller_mode: Optional[str] = None,
        decision_mode: Optional[str] = None,
        statistical_guarantee_scope: Optional[str] = None,
        channel: str = "route",
        source_id: str = "strategy_router",
        trust_zone: str = "",
        route_profile: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        ra = _safe_text(required_action, max_len=32).lower()
        em = _safe_text(enforcement_mode, max_len=32).lower()
        stier = _safe_text(safety_tier, max_len=32).lower()
        payload = {
            "required_action": ra,
            "enforcement_mode": em,
            "safety_tier": stier,
            "score": float(score),
            "route_plan_id": _safe_id(route_plan_id, default=None, max_len=128),
            "decision_id": _safe_id(decision_id, default=None, max_len=128),
            "route_id": _safe_id(route_id, default=None, max_len=128),
        }
        negative = ra in {"block", "degrade"} or em == "fail_closed"
        weight = self._weight_from_risk(score=score, verdict=negative, trust_hint=None)
        reason = "ROUTE_BLOCK" if ra == "block" else ("ROUTE_DEGRADE" if ra == "degrade" else "ROUTE_ALLOW")
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.ROUTE,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            policyset_ref=policyset_ref,
            cfg_fp=cfg_fp,
            state_domain_id=state_domain_id,
            adapter_registry_fp=adapter_registry_fp,
            selected_source=selected_source,
            controller_mode=controller_mode,
            decision_mode=decision_mode,
            statistical_guarantee_scope=statistical_guarantee_scope,
            decision_id=decision_id,
            route_plan_id=route_plan_id,
            route_id=route_id,
            severity_score=min(1.0, abs(weight) / max(self.config.negative_cap, self.config.positive_cap)),
            risk_score_raw=float(score),
            reason_codes=(reason,),
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    def add_security_decision_evidence(
        self,
        subject: SubjectKey,
        *,
        required_action: str,
        decision_fail: bool,
        score: float,
        reason_codes: Sequence[str],
        decision_id: Optional[str] = None,
        route_plan_id: Optional[str] = None,
        route_id: Optional[str] = None,
        channel: str = "security",
        source_id: str = "security_router",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        policyset_ref: Optional[str] = None,
        cfg_fp: Optional[str] = None,
        state_domain_id: Optional[str] = None,
        adapter_registry_fp: Optional[str] = None,
        selected_source: Optional[str] = None,
        controller_mode: Optional[str] = None,
        decision_mode: Optional[str] = None,
        statistical_guarantee_scope: Optional[str] = None,
        pq_required: Optional[bool] = None,
        pq_ok: Optional[bool] = None,
        pq_chain_id: str = "",
        audit_ref: Optional[str] = None,
        receipt_ref: Optional[str] = None,
        prepare_ref: Optional[str] = None,
        commit_ref: Optional[str] = None,
        ledger_stage: Optional[str] = None,
        outbox_ref: Optional[str] = None,
        outbox_status: Optional[str] = None,
        outbox_dedupe_key: Optional[str] = None,
        delivery_attempts: Optional[int] = None,
        idem_token: Optional[str] = None,
    ) -> TrustState:
        ra = _safe_text(required_action, max_len=32).lower() or "allow"
        payload = {
            "required_action": ra,
            "decision_fail": bool(decision_fail),
            "score": float(score),
            "reason_codes": list(reason_codes),
        }
        negative = decision_fail or ra in {"block", "degrade"}
        weight = self._weight_from_risk(score=score, verdict=negative, trust_hint=None)
        primary_reason = "SECURITY_DENY" if ra == "block" else ("SECURITY_DEGRADE" if ra == "degrade" else "SECURITY_ALLOW")
        merged_reasons = tuple(dict.fromkeys([primary_reason, "SECURITY_DECISION", *list(reason_codes)]))
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.SECURITY,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            policyset_ref=policyset_ref,
            cfg_fp=cfg_fp,
            state_domain_id=state_domain_id,
            adapter_registry_fp=adapter_registry_fp,
            selected_source=selected_source,
            controller_mode=controller_mode,
            decision_mode=decision_mode,
            statistical_guarantee_scope=statistical_guarantee_scope,
            decision_id=decision_id,
            route_plan_id=route_plan_id,
            route_id=route_id,
            pq_required=pq_required,
            pq_ok=pq_ok,
            pq_chain_id=pq_chain_id,
            severity_score=min(1.0, abs(weight) / max(self.config.negative_cap, self.config.positive_cap)),
            threat_label="security" if negative else "",
            threat_vector="security" if negative else "",
            risk_score_raw=float(score),
            reason_codes=merged_reasons,
            audit_ref=audit_ref,
            receipt_ref=receipt_ref,
            prepare_ref=prepare_ref,
            commit_ref=commit_ref,
            ledger_stage=ledger_stage,
            outbox_ref=outbox_ref,
            outbox_status=outbox_status,
            outbox_dedupe_key=outbox_dedupe_key,
            delivery_attempts=delivery_attempts,
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    def add_rate_limit_evidence(
        self,
        subject: SubjectKey,
        *,
        allowed: bool,
        zone: str,
        cost: float,
        reason_codes: Sequence[str] = (),
        channel: str = "rate_limit",
        source_id: str = "rate_limiter",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        decision_id: Optional[str] = None,
        route_plan_id: Optional[str] = None,
        route_id: Optional[str] = None,
        idem_token: Optional[str] = None,
    ) -> TrustState:
        payload = {
            "allowed": bool(allowed),
            "zone": _safe_label(zone, default="default"),
            "cost": float(cost),
        }
        weight = 0.1 if allowed else -0.8
        base_reasons = ("RATE_ALLOW",) if allowed else ("RATE_DENY",)
        merged = tuple(dict.fromkeys([*base_reasons, *list(reason_codes)]))
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.RATE_LIMIT,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            decision_id=decision_id,
            route_plan_id=route_plan_id,
            route_id=route_id,
            severity_score=min(1.0, abs(weight) / max(self.config.negative_cap, self.config.positive_cap)),
            reason_codes=merged,
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    def add_lifecycle_evidence(
        self,
        subject: SubjectKey,
        *,
        event_name: str,
        ok: bool,
        extra: Optional[Mapping[str, Any]] = None,
        channel: str = "lifecycle",
        source_id: str = "runtime",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        parent_event_id: Optional[str] = None,
        idem_token: Optional[str] = None,
    ) -> TrustState:
        payload = {"event_name": _safe_text(event_name, max_len=64), "ok": bool(ok)}
        if extra:
            payload.update(dict(extra))
        weight = 0.2 if ok else -0.4
        evidence = self._make_evidence(
            subject=subject,
            type_=EvidenceType.LIFECYCLE,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            parent_event_id=parent_event_id,
            severity_score=min(1.0, abs(weight) / max(self.config.negative_cap, self.config.positive_cap)),
            reason_codes=("LIFECYCLE_OK",) if ok else ("LIFECYCLE_FAIL",),
            idem_token=idem_token,
        )
        return self._apply_evidence(evidence)

    # ------------------------------------------------------------------
    # Internal core
    # ------------------------------------------------------------------

    def _subject_hash(self, subject_id: str) -> Optional[str]:
        if not self.config.hash_subject_ids:
            return None
        raw = subject_id.encode("utf-8", errors="ignore")
        key = self.config.subject_hash_key
        out_hex = self.config.subject_hash_hex_chars
        if key is not None:
            kid = self.config.subject_hash_key_id or "hmac"
            dig = hmac.new(key, b"tcd:trust_graph:subject\x00" + raw, hashlib.sha256).hexdigest()[:out_hex]
            return f"{_SUBJECT_HASH_VERSION}:{kid}:{dig}"
        dig2 = hashlib.sha256(b"tcd:trust_graph:subject\x00" + raw).hexdigest()[:out_hex]
        return f"{_SUBJECT_HASH_VERSION}:sha256:{dig2}"

    def _public_subject_id(self, subject_id: str, subject_hash: Optional[str]) -> Tuple[Optional[str], bool]:
        mode = self.config.public_subject_id_mode
        if mode == "clear":
            return subject_id, True
        if mode == "clear_if_allowed" and (self.config.profile in self.config.allow_clear_subject_profiles) and not _profile_is_strict(self.config.profile):
            return subject_id, True
        if subject_hash:
            return subject_hash, False
        dig = hashlib.sha256(b"tcd:trust_graph:subject_public\x00" + subject_id.encode("utf-8", errors="ignore")).hexdigest()[: self.config.subject_hash_hex_chars]
        return f"{_SUBJECT_HASH_VERSION}:sha256:{dig}", False

    def _make_empty_state(self, subject_id: str) -> TrustState:
        subject_hash = self._subject_hash(subject_id)
        public_subject_id, exposed = self._public_subject_id(subject_id, subject_hash)
        return TrustState(
            schema=_SCHEMA,
            schema_version=4,
            compatibility_epoch=self.config.compatibility_epoch,
            subject_id=subject_id,
            public_subject_id=public_subject_id,
            subject_id_exposed=exposed,
            subject_hash=subject_hash,
            trust_score=self.config.neutral_trust,
            observations=0,
            last_update_ts=now_ts(),
            last_update_unix_ns=now_unix_ns(),
            last_evidence_id=None,
            last_evidence_type=None,
            risk_band="neutral",
            flags=tuple(),
            compromised=False,
            freeze_until_ts=None,
            lockdown_level="none",
            last_pq_required=None,
            last_pq_ok=None,
            last_pq_chain_id="",
            last_supply_chain_ref="",
            threat_counters=MappingProxyType({}),
            recent_threat_counters=MappingProxyType({}),
            type_counters=MappingProxyType({}),
            recent_type_counters=MappingProxyType({}),
        )

    def _touch_subject(self, subject_id: str) -> None:
        self._subject_order.pop(subject_id, None)
        self._subject_order[subject_id] = None
        while len(self._subject_order) > self.config.max_subjects:
            old_sid, _ = self._subject_order.popitem(last=False)
            self._evict_subject(old_sid)

    def _evict_subject(self, subject_id: str) -> None:
        self._states.pop(subject_id, None)
        self._evidence_by_subject.pop(subject_id, None)
        self._edges_by_subject.pop(subject_id, None)
        if self._event_log:
            self._event_log = deque([e for e in self._event_log if e.subject_id != subject_id], maxlen=None)
        if self._edge_log:
            self._edge_log = deque([e for e in self._edge_log if e.subject_hash != self._subject_hash(subject_id)], maxlen=None)

    def _trim_idem(self, now_s: float) -> None:
        if not self._seen_idem:
            return
        cutoff = now_s - self.config.idem_ttl_sec
        if len(self._seen_idem) > max(1024, self.config.max_total_evidence * 2) or any(v.ts < cutoff for v in self._seen_idem.values()):
            self._seen_idem = {k: v for k, v in self._seen_idem.items() if v.ts >= cutoff}

    def _append_evidence_index_only(self, evidence: Evidence) -> None:
        sid = evidence.subject_id
        per_subject = self._evidence_by_subject.setdefault(sid, deque())
        per_subject.append(evidence)
        while len(per_subject) > self.config.max_evidence_per_subject:
            per_subject.popleft()
        self._event_log.append(evidence)
        while len(self._event_log) > self.config.max_total_evidence:
            dropped = self._event_log.popleft()
            dq = self._evidence_by_subject.get(dropped.subject_id)
            if dq is not None:
                if dq and dq[0].evidence_id == dropped.evidence_id:
                    dq.popleft()
                else:
                    self._evidence_by_subject[dropped.subject_id] = deque([x for x in dq if x.evidence_id != dropped.evidence_id])

    def _append_edge_index_only(self, edge: TrustEdge) -> None:
        sid = self._subject_id_from_hash(edge.subject_hash)
        if sid:
            per_subject = self._edges_by_subject.setdefault(sid, deque())
            per_subject.append(edge)
            while len(per_subject) > self.config.max_edges_per_subject:
                per_subject.popleft()
        self._edge_log.append(edge)
        while len(self._edge_log) > self.config.max_total_edges:
            dropped = self._edge_log.popleft()
            sid2 = self._subject_id_from_hash(dropped.subject_hash)
            if sid2 and sid2 in self._edges_by_subject:
                dq = self._edges_by_subject[sid2]
                if dq and dq[0].edge_id == dropped.edge_id:
                    dq.popleft()
                else:
                    self._edges_by_subject[sid2] = deque([x for x in dq if x.edge_id != dropped.edge_id])

    def _subject_id_from_hash(self, subject_hash: Optional[str]) -> Optional[str]:
        if subject_hash is None:
            return None
        for sid, st in self._states.items():
            if st.subject_hash == subject_hash:
                return sid
        return None

    def _effective_signal_trust_mode(self, signal_trust_mode: Optional[str]) -> str:
        stm = _safe_label(signal_trust_mode, default=self.config.default_signal_trust_mode)
        if stm not in _ALLOWED_SIGNAL_TRUST:
            stm = self.config.default_signal_trust_mode
        return stm

    def _make_evidence(
        self,
        *,
        subject: SubjectKey,
        type_: EvidenceType,
        weight: float,
        payload: Mapping[str, Any],
        channel: str = "unknown",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        policyset_ref: Optional[str] = None,
        policy_digest: Optional[str] = None,
        cfg_fp: Optional[str] = None,
        bundle_version: Optional[int] = None,
        state_domain_id: Optional[str] = None,
        adapter_registry_fp: Optional[str] = None,
        selected_source: Optional[str] = None,
        controller_mode: Optional[str] = None,
        decision_mode: Optional[str] = None,
        statistical_guarantee_scope: Optional[str] = None,
        activation_id: Optional[str] = None,
        patch_id: Optional[str] = None,
        change_ticket_id: Optional[str] = None,
        decision_id: Optional[str] = None,
        route_plan_id: Optional[str] = None,
        route_id: Optional[str] = None,
        parent_event_id: Optional[str] = None,
        parent_decision_id: Optional[str] = None,
        parent_route_plan_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        resource_kind: Optional[str] = None,
        threat_label: str = "",
        threat_vector: str = "",
        severity_label: str = "normal",
        severity_score: float = 0.0,
        reason_codes: Sequence[str] = (),
        normalization_warnings: Sequence[str] = (),
        override_applied: bool = False,
        override_actor: str = "",
        override_reason: str = "",
        supply_chain_ref: str = "",
        pq_required: Optional[bool] = None,
        pq_ok: Optional[bool] = None,
        pq_chain_id: str = "",
        pq_signature_required: Optional[bool] = None,
        pq_signature_ok: Optional[bool] = None,
        risk_score_raw: Optional[float] = None,
        idem_token: Optional[str] = None,
        audit_ref: Optional[str] = None,
        receipt_ref: Optional[str] = None,
        ledger_ref: Optional[str] = None,
        attestation_ref: Optional[str] = None,
        prepare_ref: Optional[str] = None,
        commit_ref: Optional[str] = None,
        outbox_ref: Optional[str] = None,
        outbox_status: Optional[str] = None,
        outbox_dedupe_key: Optional[str] = None,
        delivery_attempts: Optional[int] = None,
        ledger_stage: Optional[str] = None,
        chain_id: Optional[str] = None,
        chain_head: Optional[str] = None,
        produced_by: Sequence[str] = ("tcd.trust_graph",),
        phase: Optional[str] = None,
        source_classification: Optional[str] = None,
        signal_trust_mode: Optional[str] = None,
    ) -> Evidence:
        subj = _sanitize_subject(subject)
        sid = subj.as_id()
        subject_hash = self._subject_hash(sid)
        public_subject_id, exposed = self._public_subject_id(sid, subject_hash)

        sanitized_payload = _safe_json_mapping(payload, max_items=self.config.max_payload_items, max_str_len=self.config.max_payload_str_len)
        sanitized_payload = _fit_payload_budget(sanitized_payload, max_bytes=self.config.max_payload_bytes)

        ts = now_ts()
        ts_ns = now_unix_ns()
        mono_ns = time.monotonic_ns()

        phase_norm = _safe_label(phase or self.config.default_phase, default=self.config.default_phase)
        if phase_norm not in _ALLOWED_PHASES:
            phase_norm = self.config.default_phase
        src_class = _safe_label(source_classification or self.config.default_source_classification, default=self.config.default_source_classification)
        if src_class not in _ALLOWED_SOURCE_CLASSIFICATION:
            src_class = self.config.default_source_classification
        trust_mode = self._effective_signal_trust_mode(signal_trust_mode)

        payload_digest = f"{_PAYLOAD_VERSION}:sha256:{hashlib.sha256(_canonical_json_bytes(sanitized_payload)).hexdigest()}"
        observation_payload = {
            "subject_hash": subject_hash,
            "type": type_.value,
            "payload": sanitized_payload,
            "channel": _safe_label(channel, default="unknown"),
            "source_id": _safe_text(source_id, max_len=128),
            "trust_zone": _safe_label(trust_zone, default="unknown"),
            "route_profile": _safe_label(route_profile, default="unknown"),
            "signal_trust_mode": trust_mode,
        }
        observation_digest = f"tgobs1:sha256:{_hash_hex(ctx='tcd:trust_graph:observation', payload=observation_payload, out_hex=64)}"
        assessment_payload = {
            "weight": _stable_float(float(weight)),
            "severity_label": _safe_label(severity_label, default="normal"),
            "severity_score": _clamp_float(severity_score, default=0.0, lo=0.0, hi=1.0),
            "threat_label": _safe_label(threat_label, default=""),
            "threat_vector": _safe_label(threat_vector, default=""),
            "reason_codes": list(_normalize_reason_codes(reason_codes)),
            "policy_ref": _safe_id(policy_ref, default=None, max_len=128),
            "policyset_ref": _safe_id(policyset_ref, default=None, max_len=128),
            "policy_digest": _normalize_digest_token(policy_digest, kind="any", default=None),
            "cfg_fp": _normalize_digest_token(cfg_fp, kind="cfg_fp", default=self.config.config_fingerprint()),
            "decision_id": _safe_id(decision_id, default=None, max_len=128),
            "route_plan_id": _safe_id(route_plan_id, default=None, max_len=128),
            "route_id": _safe_id(route_id, default=None, max_len=128),
        }
        assessment_digest = f"tgass1:sha256:{_hash_hex(ctx='tcd:trust_graph:assessment', payload=assessment_payload, out_hex=64)}"
        evidence_fingerprint = f"tgfp2:{_hash_hex(ctx='tcd:trust_graph:evidence_fingerprint', payload={'observation_digest': observation_digest, 'assessment_digest': assessment_digest, 'subject_id': sid, 'type': type_.value}, out_hex=32)}"

        idem_tok = _safe_id(idem_token, default=None, max_len=128)
        idem_scope = None
        idem_fp = None
        if idem_tok:
            idem_scope = f"{sid}|{type_.value}|{idem_tok}"
            idem_fp = f"tgidem2:{_hash_hex(ctx='tcd:trust_graph:idem_fingerprint', payload={'idem_scope': idem_scope, 'evidence_fingerprint': evidence_fingerprint}, out_hex=32)}"
            evidence_id = f"{_EVENT_VERSION}:{_hash_hex(ctx='tcd:trust_graph:evidence_id:idem', payload={'idem_scope': idem_scope}, out_hex=32)}"
        else:
            evidence_id = f"{_EVENT_VERSION}:{_hash_hex(ctx='tcd:trust_graph:evidence_id', payload={'evidence_fingerprint': evidence_fingerprint, 'ts_unix_ns': ts_ns}, out_hex=32)}"

        evidence_digest = f"tged2:sha256:{_hash_hex(ctx='tcd:trust_graph:evidence_digest', payload={'evidence_id': evidence_id, 'evidence_fingerprint': evidence_fingerprint, 'payload_digest': payload_digest, 'observation_digest': observation_digest, 'assessment_digest': assessment_digest}, out_hex=64)}"

        produced_by_t = _normalize_str_tuple(produced_by, max_len=64, max_items=16)
        if not produced_by_t:
            produced_by_t = ("tcd.trust_graph",)
        provenance_path_digest = f"{_PROVENANCE_VERSION}:sha256:{_hash_hex(ctx='tcd:trust_graph:provenance', payload={'produced_by': list(produced_by_t), 'cfg_fp': _normalize_digest_token(cfg_fp, kind='cfg_fp', default=self.config.config_fingerprint())}, out_hex=64)}"

        sev_label = _safe_label(severity_label, default="normal")
        if sev_label not in _ALLOWED_SEVERITY_LABELS:
            sev_label = "normal"

        oz = _safe_label(trust_zone, default="unknown")
        if oz not in _ALLOWED_TRUST_ZONES:
            oz = "unknown"
        rp = _safe_label(route_profile, default="unknown")
        if rp not in _ALLOWED_ROUTE_PROFILES:
            rp = "unknown"

        return Evidence(
            schema=_SCHEMA,
            schema_version=4,
            compatibility_epoch=self.config.compatibility_epoch,
            canonicalization_version=_CANONICALIZATION_VERSION,
            evidence_id=evidence_id,
            event_type=f"trust_graph.{type_.value}",
            evidence_fingerprint=evidence_fingerprint,
            observation_digest=observation_digest,
            assessment_digest=assessment_digest,
            payload_digest=payload_digest,
            evidence_digest=evidence_digest,
            subject_id=sid,
            public_subject_id=public_subject_id,
            subject_id_exposed=exposed,
            subject_hash=subject_hash,
            type=type_,
            phase=phase_norm,
            source_classification=src_class,
            signal_trust_mode=trust_mode,
            timestamp=ts,
            ts_unix_ns=ts_ns,
            ts_monotonic_ns=mono_ns,
            weight=max(-self.config.negative_cap, min(self.config.positive_cap, float(weight))),
            payload=MappingProxyType(dict(sanitized_payload)),
            channel=_safe_label(channel, default="unknown"),
            source_id=_safe_text(source_id, max_len=128),
            trust_zone=oz,
            route_profile=rp,
            policy_ref=_safe_id(policy_ref, default=None, max_len=128),
            policyset_ref=_safe_id(policyset_ref, default=None, max_len=128),
            policy_digest=_normalize_digest_token(policy_digest, kind="any", default=None),
            cfg_fp=_normalize_digest_token(cfg_fp, kind="cfg_fp", default=self.config.config_fingerprint()),
            bundle_version=_coerce_int(bundle_version),
            state_domain_id=_safe_id(state_domain_id, default=None, max_len=256),
            adapter_registry_fp=_safe_id(adapter_registry_fp, default=None, max_len=256),
            selected_source=_safe_label(selected_source, default="") or None if selected_source is not None else None,
            controller_mode=_safe_label(controller_mode, default="") or None if controller_mode is not None else None,
            decision_mode=_safe_label(decision_mode, default="") or None if decision_mode is not None else None,
            statistical_guarantee_scope=_safe_text(statistical_guarantee_scope, max_len=64),
            activation_id=_safe_id(activation_id, default=None, max_len=256),
            patch_id=_safe_id(patch_id, default=None, max_len=256),
            change_ticket_id=_safe_id(change_ticket_id, default=None, max_len=256),
            route_plan_id=_safe_id(route_plan_id, default=None, max_len=128),
            route_id=_safe_id(route_id, default=None, max_len=128),
            decision_id=_safe_id(decision_id, default=None, max_len=128),
            parent_event_id=_safe_id(parent_event_id, default=None, max_len=128),
            parent_decision_id=_safe_id(parent_decision_id, default=None, max_len=128),
            parent_route_plan_id=_safe_id(parent_route_plan_id, default=None, max_len=128),
            resource_id=_safe_id(resource_id, default=None, max_len=128),
            resource_kind=_safe_label(resource_kind, default="") or None if resource_kind is not None else None,
            threat_label=_safe_label(threat_label, default=""),
            threat_vector=_safe_label(threat_vector, default=""),
            severity_label=sev_label,
            severity_score=_clamp_float(severity_score, default=0.0, lo=0.0, hi=1.0),
            reason_codes=_normalize_reason_codes(reason_codes),
            normalization_warnings=_normalize_str_tuple(normalization_warnings, max_len=64, max_items=16),
            override_applied=bool(override_applied),
            override_actor=_safe_text(override_actor, max_len=128),
            override_reason=_safe_text(override_reason, max_len=256),
            supply_chain_ref=_safe_text(supply_chain_ref, max_len=256),
            pq_required=_coerce_bool(pq_required),
            pq_ok=_coerce_bool(pq_ok),
            pq_chain_id=_safe_text(pq_chain_id, max_len=128),
            pq_signature_required=_coerce_bool(pq_signature_required),
            pq_signature_ok=_coerce_bool(pq_signature_ok),
            risk_score_raw=_coerce_float(risk_score_raw),
            idem_token=idem_tok,
            idem_scope=idem_scope,
            idem_fingerprint=idem_fp,
            audit_ref=_safe_id(audit_ref, default=None, max_len=256),
            receipt_ref=_safe_id(receipt_ref, default=None, max_len=256),
            ledger_ref=_safe_id(ledger_ref, default=None, max_len=256),
            attestation_ref=_safe_id(attestation_ref, default=None, max_len=256),
            prepare_ref=_safe_id(prepare_ref, default=None, max_len=256),
            commit_ref=_safe_id(commit_ref, default=None, max_len=256),
            outbox_ref=_safe_id(outbox_ref, default=None, max_len=256),
            outbox_status=_safe_label(outbox_status, default="") or None if outbox_status is not None else None,
            outbox_dedupe_key=_safe_id(outbox_dedupe_key, default=None, max_len=256),
            delivery_attempts=_coerce_int(delivery_attempts),
            ledger_stage=_safe_label(ledger_stage, default="") or None if ledger_stage is not None else None,
            chain_id=_safe_id(chain_id, default=None, max_len=128),
            chain_head=_normalize_digest_token(chain_head, kind="any", default=None),
            produced_by=produced_by_t,
            provenance_path_digest=provenance_path_digest,
            public_payload_allowed=self.config.public_include_payload,
            public_internal_digests_allowed=self.config.public_include_internal_digests,
        )

    def _build_edges_for_evidence(self, evidence: Evidence) -> List[TrustEdge]:
        edges: List[TrustEdge] = []
        specs: List[Tuple[str, Optional[str]]] = [
            ("derived_from_event", evidence.parent_event_id),
            ("caused_by_decision", evidence.parent_decision_id),
            ("caused_by_route_plan", evidence.parent_route_plan_id),
            ("bound_to_decision", evidence.decision_id),
            ("bound_to_route_plan", evidence.route_plan_id),
            ("bound_to_route", evidence.route_id),
            ("bound_to_receipt", evidence.receipt_ref),
            ("bound_to_resource", evidence.resource_id),
        ]
        for relation, to_ref in specs:
            if not to_ref:
                continue
            edge_id = f"{_EDGE_VERSION}:{_hash_hex(ctx='tcd:trust_graph:edge', payload={'from': evidence.evidence_id, 'to': to_ref, 'relation': relation}, out_hex=32)}"
            edges.append(
                TrustEdge(
                    schema=_SCHEMA,
                    schema_version=4,
                    compatibility_epoch=self.config.compatibility_epoch,
                    edge_id=edge_id,
                    from_event_id=evidence.evidence_id,
                    to_ref_id=to_ref,
                    relation=relation if relation in _ALLOWED_EDGE_RELATIONS else "derived_from_event",
                    subject_hash=evidence.subject_hash,
                    evidence_type=evidence.type.value,
                    route_plan_id=evidence.route_plan_id,
                    route_id=evidence.route_id,
                    decision_id=evidence.decision_id,
                    resource_id=evidence.resource_id,
                    resource_kind=evidence.resource_kind,
                    ts_unix_ns=evidence.ts_unix_ns,
                    payload_digest=evidence.payload_digest,
                )
            )
        return edges

    def _recent_window_view(self, subject_id: str, now_s: float, pending: Optional[Evidence] = None) -> Tuple[Dict[str, int], Dict[str, int], Tuple[str, ...], int, int]:
        events = list(self._evidence_by_subject.get(subject_id, deque()))
        if pending is not None:
            events.append(pending)

        recent_threats: Dict[str, int] = {}
        recent_types: Dict[str, int] = {}
        recent_reasons: List[str] = []
        neg = 0
        pos = 0

        for ev in events:
            if not ev.applied_to_state:
                continue
            if (now_s - ev.timestamp) > self.config.recent_window_s:
                continue
            recent_types[ev.type.value] = recent_types.get(ev.type.value, 0) + 1
            tv = ev.threat_vector or ev.threat_label
            if tv:
                recent_threats[tv] = recent_threats.get(tv, 0) + 1
            for rc in ev.reason_codes:
                if rc not in recent_reasons:
                    recent_reasons.append(rc)
                    if len(recent_reasons) >= 16:
                        break
            if ev.weight < 0:
                neg += 1
            elif ev.weight > 0:
                pos += 1
        return recent_threats, recent_types, tuple(recent_reasons[:16]), neg, pos

    def _decay_state(self, state: TrustState, now_s: float, now_ns: int) -> TrustState:
        hl = max(1.0, float(self.config.decay_half_life_sec))
        dt = max(0.0, now_s - float(state.last_update_ts))
        if dt <= 0.0:
            return state
        decay_factor = 0.5 ** (dt / hl)
        neutral = self.config.neutral_trust
        trust_score = neutral + (float(state.trust_score) - neutral) * decay_factor
        pos = float(state.decayed_positive_weight) * decay_factor
        neg = float(state.decayed_negative_weight) * decay_factor
        s = dataclasses.replace(
            state,
            trust_score=max(0.0, min(1.0, trust_score)),
            last_update_ts=now_s,
            last_update_unix_ns=now_ns,
            risk_band=self._risk_band_for_score(trust_score),
            decayed_positive_weight=pos,
            decayed_negative_weight=neg,
        )
        return dataclasses.replace(s, lockdown_level=self._lockdown_for_state(s))

    def _lockdown_for_state(self, state: TrustState) -> str:
        s = max(0.0, min(1.0, float(state.trust_score)))
        if state.compromised:
            return "lockdown"
        if state.freeze_until_ts is not None and state.freeze_until_ts > now_ts():
            return "restrict"
        if s <= 0.2:
            return "lockdown"
        if s <= 0.4:
            return "restrict"

        sensitive = (
            int(state.recent_threat_counters.get("apt", 0))
            + int(state.recent_threat_counters.get("insider", 0))
            + int(state.recent_threat_counters.get("supply_chain", 0))
            + int(state.recent_threat_counters.get("pq", 0))
            + int(state.recent_threat_counters.get("security", 0))
        )
        if sensitive >= 3:
            return "restrict"
        if sensitive > 0 or state.last_pq_ok is False or state.recent_negative_events >= 3:
            return "monitor"
        return "none"

    def _set_last_error(self, kind: str, message: str) -> None:
        self._last_error_kind = _safe_text(kind, max_len=64)
        self._last_error_message = _safe_text(message, max_len=256)

    def _publish(self, evidence: Evidence, state: TrustState) -> None:
        labels = {
            "type": evidence.type.value,
            "channel": _safe_label(evidence.channel, default="unknown"),
            "trust_zone": _safe_label(evidence.trust_zone, default="unknown"),
            "route_profile": _safe_label(evidence.route_profile, default="unknown"),
            "risk_band": _safe_label(state.risk_band, default="neutral"),
            "lockdown_level": _safe_label(state.lockdown_level, default="none"),
        }
        if self._telemetry_sink is not None:
            try:
                self._telemetry_sink.record_metric("tcd_trust_graph_trust_score", float(state.trust_score), labels)
                self._telemetry_sink.record_metric("tcd_trust_graph_weight", float(evidence.weight), labels)
                self._telemetry_sink.record_event("trust_graph_evidence", evidence.to_public_dict())
            except Exception as exc:
                self._set_last_error("telemetry_sink", str(exc))
                if self.config.sink_error_mode == "disable_sink":
                    self._telemetry_sink = None
                elif self.config.sink_error_mode == "raise":
                    raise
        if self._audit_sink is not None:
            evt = "TrustGraphEvidence"
            if evidence.idempotency_conflict:
                evt = "TrustGraphEvidenceConflict"
            elif evidence.replay_suppressed:
                evt = "TrustGraphReplaySuppressed"
            elif evidence.freeze_suppressed:
                evt = "TrustGraphFrozenSuppressed"
            try:
                self._audit_sink.emit(evt, evidence.to_audit_dict())
            except Exception as exc:
                self._set_last_error("audit_sink", str(exc))
                if self.config.sink_error_mode == "disable_sink":
                    self._audit_sink = None
                elif self.config.sink_error_mode == "raise":
                    raise

    def _apply_evidence(self, evidence: Evidence) -> TrustState:
        with self._lock:
            now_s = evidence.timestamp
            now_ns = evidence.ts_unix_ns
            self._trim_idem(now_s)

            state = self.get_state_by_id(evidence.subject_id)
            state = self._decay_state(state, now_s, now_ns)

            replay = False
            conflict = False
            if evidence.idem_token and evidence.idem_scope:
                seen = self._seen_idem.get(evidence.idem_scope)
                if seen is not None:
                    replay = True
                    if evidence.idem_fingerprint is not None and seen.fingerprint != evidence.idem_fingerprint:
                        conflict = True
                else:
                    self._seen_idem[evidence.idem_scope] = _SeenIdempotency(
                        ts=now_s,
                        fingerprint=evidence.idem_fingerprint or evidence.evidence_fingerprint,
                        subject_id=evidence.subject_id,
                        evidence_type=evidence.type.value,
                    )

            if replay:
                evidence = dataclasses.replace(
                    evidence,
                    replay_suppressed=True,
                    idempotency_conflict=conflict,
                    applied_to_state=False,
                    reason_codes=tuple(dict.fromkeys(list(evidence.reason_codes) + (["IDEMPOTENCY_CONFLICT"] if conflict else ["REPLAY_SUPPRESSED"]))),
                )
                self._append_evidence_index_only(evidence)
                for edge in self._build_edges_for_evidence(evidence):
                    self._append_edge_index_only(edge)
                self._publish(evidence, state)
                return state

            if state.freeze_until_ts is not None and evidence.timestamp < state.freeze_until_ts:
                evidence = dataclasses.replace(
                    evidence,
                    applied_to_state=False,
                    freeze_suppressed=True,
                    reason_codes=tuple(dict.fromkeys(list(evidence.reason_codes) + ["STATE_FROZEN"])),
                )
                self._append_evidence_index_only(evidence)
                for edge in self._build_edges_for_evidence(evidence):
                    self._append_edge_index_only(edge)
                self._publish(evidence, state)
                return state

            bounded_weight = max(-self.config.negative_cap, min(self.config.positive_cap, evidence.weight))
            trust_score = max(0.0, min(1.0, state.trust_score + self.config.trust_update_step * bounded_weight))
            pos = state.decayed_positive_weight + (bounded_weight if bounded_weight > 0 else 0.0)
            neg = state.decayed_negative_weight + (abs(bounded_weight) if bounded_weight < 0 else 0.0)

            compromised = state.compromised
            freeze_until = state.freeze_until_ts
            reason_codes = list(evidence.reason_codes)
            if bounded_weight <= -abs(self.config.severe_negative_weight_threshold) and self.config.freeze_on_compromise_sec > 0.0:
                compromised = True
                freeze_until = evidence.timestamp + float(self.config.freeze_on_compromise_sec)
                if "COMPROMISED_FREEZE" not in reason_codes:
                    reason_codes.append("COMPROMISED_FREEZE")

            threat_counters = dict(state.threat_counters)
            type_counters = dict(state.type_counters)
            type_counters[evidence.type.value] = type_counters.get(evidence.type.value, 0) + 1
            tv = evidence.threat_vector or evidence.threat_label
            if tv:
                threat_counters[tv] = threat_counters.get(tv, 0) + 1

            recent_threats, recent_types, recent_reasons, recent_neg, recent_pos = self._recent_window_view(
                evidence.subject_id,
                evidence.timestamp,
                pending=dataclasses.replace(evidence, reason_codes=tuple(dict.fromkeys(reason_codes)), applied_to_state=True),
            )

            flags = set(state.flags)
            if bounded_weight < 0:
                flags.add("recent_negative")
                flags.discard("recent_positive")
            elif bounded_weight > 0:
                flags.add("recent_positive")
                flags.discard("recent_negative")
            if compromised:
                flags.add("compromised")
            if freeze_until is not None and freeze_until > evidence.timestamp:
                flags.add("frozen")
            flags.discard("replay_suppressed")
            flags.discard("idempotency_conflict")

            evidence = dataclasses.replace(evidence, reason_codes=tuple(dict.fromkeys(reason_codes)))

            new_state = dataclasses.replace(
                state,
                trust_score=trust_score,
                observations=state.observations + 1,
                last_update_ts=evidence.timestamp,
                last_update_unix_ns=evidence.ts_unix_ns,
                last_evidence_id=evidence.evidence_id,
                last_evidence_type=evidence.type.value,
                risk_band=self._risk_band_for_score(trust_score),
                flags=tuple(sorted(flags)),
                compromised=compromised,
                freeze_until_ts=freeze_until,
                lockdown_level=state.lockdown_level,  # set below
                last_pq_required=evidence.pq_required if evidence.pq_required is not None else state.last_pq_required,
                last_pq_ok=evidence.pq_ok if evidence.pq_ok is not None else state.last_pq_ok,
                last_pq_chain_id=evidence.pq_chain_id or state.last_pq_chain_id,
                last_supply_chain_ref=evidence.supply_chain_ref or state.last_supply_chain_ref,
                threat_counters=MappingProxyType(threat_counters),
                recent_threat_counters=MappingProxyType(dict(recent_threats)),
                type_counters=MappingProxyType(type_counters),
                recent_type_counters=MappingProxyType(dict(recent_types)),
                last_policy_ref=evidence.policy_ref or state.last_policy_ref,
                last_policyset_ref=evidence.policyset_ref or state.last_policyset_ref,
                last_cfg_fp=evidence.cfg_fp or state.last_cfg_fp,
                last_state_domain_id=evidence.state_domain_id or state.last_state_domain_id,
                last_adapter_registry_fp=evidence.adapter_registry_fp or state.last_adapter_registry_fp,
                last_controller_mode=evidence.controller_mode or state.last_controller_mode,
                last_decision_mode=evidence.decision_mode or state.last_decision_mode,
                last_statistical_guarantee_scope=evidence.statistical_guarantee_scope or state.last_statistical_guarantee_scope,
                last_activation_id=evidence.activation_id or state.last_activation_id,
                last_patch_id=evidence.patch_id or state.last_patch_id,
                last_change_ticket_id=evidence.change_ticket_id or state.last_change_ticket_id,
                last_audit_ref=evidence.audit_ref or state.last_audit_ref,
                last_receipt_ref=evidence.receipt_ref or state.last_receipt_ref,
                last_decision_id=evidence.decision_id or state.last_decision_id,
                last_route_plan_id=evidence.route_plan_id or state.last_route_plan_id,
                last_route_id=evidence.route_id or state.last_route_id,
                recent_reason_codes=recent_reasons,
                decayed_positive_weight=pos,
                decayed_negative_weight=neg,
                recent_negative_events=recent_neg,
                recent_positive_events=recent_pos,
            )
            new_state = dataclasses.replace(new_state, lockdown_level=self._lockdown_for_state(new_state))

            self._states[evidence.subject_id] = new_state
            self._append_evidence_index_only(evidence)
            for edge in self._build_edges_for_evidence(evidence):
                self._append_edge_index_only(edge)
            self._touch_subject(evidence.subject_id)
            self._publish(evidence, new_state)
            return new_state

    def _recompute_state_from_subject_events(self, subject_id: str, events: List[Evidence]) -> TrustState:
        state = self._make_empty_state(subject_id)
        events = sorted(events, key=lambda e: (e.timestamp, e.ts_unix_ns, e.evidence_id))
        applied_events: List[Evidence] = []
        for ev in events:
            if not ev.applied_to_state:
                continue
            state = self._decay_state(state, ev.timestamp, ev.ts_unix_ns)
            bounded_weight = max(-self.config.negative_cap, min(self.config.positive_cap, ev.weight))
            trust_score = max(0.0, min(1.0, state.trust_score + self.config.trust_update_step * bounded_weight))
            pos = state.decayed_positive_weight + (bounded_weight if bounded_weight > 0 else 0.0)
            neg = state.decayed_negative_weight + (abs(bounded_weight) if bounded_weight < 0 else 0.0)

            compromised = state.compromised
            freeze_until = state.freeze_until_ts
            if bounded_weight <= -abs(self.config.severe_negative_weight_threshold) and self.config.freeze_on_compromise_sec > 0.0:
                compromised = True
                freeze_until = ev.timestamp + float(self.config.freeze_on_compromise_sec)

            applied_events.append(ev)
            recent_threats: Dict[str, int] = {}
            recent_types: Dict[str, int] = {}
            recent_reasons: List[str] = []
            recent_neg = 0
            recent_pos = 0
            for prev in applied_events:
                if (ev.timestamp - prev.timestamp) > self.config.recent_window_s:
                    continue
                recent_types[prev.type.value] = recent_types.get(prev.type.value, 0) + 1
                tv = prev.threat_vector or prev.threat_label
                if tv:
                    recent_threats[tv] = recent_threats.get(tv, 0) + 1
                for rc in prev.reason_codes:
                    if rc not in recent_reasons:
                        recent_reasons.append(rc)
                        if len(recent_reasons) >= 16:
                            break
                if prev.weight < 0:
                    recent_neg += 1
                elif prev.weight > 0:
                    recent_pos += 1

            threat_counters = dict(state.threat_counters)
            type_counters = dict(state.type_counters)
            type_counters[ev.type.value] = type_counters.get(ev.type.value, 0) + 1
            tv = ev.threat_vector or ev.threat_label
            if tv:
                threat_counters[tv] = threat_counters.get(tv, 0) + 1

            flags = set(state.flags)
            if bounded_weight < 0:
                flags.add("recent_negative")
                flags.discard("recent_positive")
            elif bounded_weight > 0:
                flags.add("recent_positive")
                flags.discard("recent_negative")
            if compromised:
                flags.add("compromised")
            if freeze_until is not None and freeze_until > ev.timestamp:
                flags.add("frozen")

            state = dataclasses.replace(
                state,
                trust_score=trust_score,
                observations=state.observations + 1,
                last_update_ts=ev.timestamp,
                last_update_unix_ns=ev.ts_unix_ns,
                last_evidence_id=ev.evidence_id,
                last_evidence_type=ev.type.value,
                risk_band=self._risk_band_for_score(trust_score),
                flags=tuple(sorted(flags)),
                compromised=compromised,
                freeze_until_ts=freeze_until,
                last_pq_required=ev.pq_required if ev.pq_required is not None else state.last_pq_required,
                last_pq_ok=ev.pq_ok if ev.pq_ok is not None else state.last_pq_ok,
                last_pq_chain_id=ev.pq_chain_id or state.last_pq_chain_id,
                last_supply_chain_ref=ev.supply_chain_ref or state.last_supply_chain_ref,
                threat_counters=MappingProxyType(threat_counters),
                recent_threat_counters=MappingProxyType(dict(recent_threats)),
                type_counters=MappingProxyType(type_counters),
                recent_type_counters=MappingProxyType(dict(recent_types)),
                last_policy_ref=ev.policy_ref or state.last_policy_ref,
                last_policyset_ref=ev.policyset_ref or state.last_policyset_ref,
                last_cfg_fp=ev.cfg_fp or state.last_cfg_fp,
                last_state_domain_id=ev.state_domain_id or state.last_state_domain_id,
                last_adapter_registry_fp=ev.adapter_registry_fp or state.last_adapter_registry_fp,
                last_controller_mode=ev.controller_mode or state.last_controller_mode,
                last_decision_mode=ev.decision_mode or state.last_decision_mode,
                last_statistical_guarantee_scope=ev.statistical_guarantee_scope or state.last_statistical_guarantee_scope,
                last_activation_id=ev.activation_id or state.last_activation_id,
                last_patch_id=ev.patch_id or state.last_patch_id,
                last_change_ticket_id=ev.change_ticket_id or state.last_change_ticket_id,
                last_audit_ref=ev.audit_ref or state.last_audit_ref,
                last_receipt_ref=ev.receipt_ref or state.last_receipt_ref,
                last_decision_id=ev.decision_id or state.last_decision_id,
                last_route_plan_id=ev.route_plan_id or state.last_route_plan_id,
                last_route_id=ev.route_id or state.last_route_id,
                recent_reason_codes=tuple(recent_reasons[:16]),
                decayed_positive_weight=pos,
                decayed_negative_weight=neg,
                recent_negative_events=recent_neg,
                recent_positive_events=recent_pos,
            )
            state = dataclasses.replace(state, lockdown_level=self._lockdown_for_state(state))
        return state

    def _weight_from_risk(self, *, score: float, verdict: bool, trust_hint: Optional[float]) -> float:
        s = max(0.0, min(1.0, float(score)))
        base = (0.5 - s)
        if verdict:
            base = -abs(base)
        else:
            base = abs(base)
        scale = 1.0 + (1.0 - s)
        weight = base * scale
        if trust_hint is not None and math.isfinite(float(trust_hint)):
            hint = max(0.0, min(1.0, float(trust_hint)))
            centered = (hint - 0.5) * 2.0
            weight += 0.25 * centered
        return max(-self.config.negative_cap, min(self.config.positive_cap, weight))

    def _action_duration_ms(self, action_result: Any) -> float:
        dm = getattr(action_result, "duration_ms", None)
        if callable(dm):
            with contextlib.suppress(Exception):
                v = _coerce_float(dm())
                if v is not None:
                    return max(0.0, float(v))
        v2 = _coerce_float(dm)
        if v2 is not None:
            return max(0.0, float(v2))
        ds = _coerce_float(getattr(action_result, "duration_s", None))
        if ds is not None:
            return max(0.0, float(ds) * 1000.0)
        return 0.0

    def _weight_from_action(self, action_result: Any) -> float:
        try:
            ok = bool(getattr(action_result, "ok", False))
            duration_ms = float(self._action_duration_ms(action_result))
            action_name = _safe_text(getattr(action_result, "action", None), max_len=64)
            mode = _safe_text(getattr(getattr(action_result, "mode", None), "value", getattr(action_result, "mode", None)), max_len=64).lower()
        except Exception:
            return 0.0
        if not ok:
            return -1.0
        base = 0.3
        if action_name in ("rollback", "rotate_keys", "update_policies", "reload_config"):
            base = 0.5
        if "canary" in mode:
            base *= 0.7
        elif "production" in mode or "prod" in mode:
            base *= 1.0
        else:
            base *= 0.4
        if duration_ms > 5000.0:
            base *= 0.5
        return max(-self.config.negative_cap, min(self.config.positive_cap, base))

    def _weight_from_verification(self, *, ok: bool) -> float:
        return 0.6 if ok else -1.2

    @staticmethod
    def _risk_band_for_score(score: float) -> str:
        s = max(0.0, min(1.0, float(score)))
        if s <= 0.2:
            return "high_risk"
        if s <= 0.4:
            return "elevated_risk"
        if s < 0.6:
            return "neutral"
        if s < 0.8:
            return "reliable"
        return "high_trust"