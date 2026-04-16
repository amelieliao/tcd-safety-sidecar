from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Literal

try:
    from .trust_graph import SubjectKey
except ImportError:  # pragma: no cover
    @dataclass(frozen=True)
    class SubjectKey:  # type: ignore[misc]
        tenant: str = ""
        user: str = ""
        session: str = ""
        model_id: str = ""

        def as_id(self) -> str:
            parts = [
                f"tenant={self.tenant or '*'}",
                f"user={self.user or '*'}",
                f"session={self.session or '*'}",
                f"model={self.model_id or '*'}",
            ]
            return "|".join(parts)

try:
    from .policies import PolicyStore, BoundPolicy
except ImportError:  # pragma: no cover
    PolicyStore = Any  # type: ignore[misc]
    BoundPolicy = Any  # type: ignore[misc]

try:
    from .ratelimit import RateLimiter, RateDecision, RateKey
except ImportError:  # pragma: no cover
    RateLimiter = Any  # type: ignore[misc]
    RateDecision = Any  # type: ignore[misc]

    @dataclass(frozen=True)
    class RateKey:  # type: ignore[misc]
        tenant_id: str
        principal_id: str
        subject_id: Optional[str] = None
        session_id: Optional[str] = None
        resource_id: Optional[str] = None
        route_id: Optional[str] = None

try:
    from .attest import Attestor
except ImportError:  # pragma: no cover
    Attestor = None  # type: ignore[misc,assignment]

try:
    from .detector import TCDDetectorRuntime  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    TCDDetectorRuntime = Any  # type: ignore[misc]

try:
    from .risk_av import AlwaysValidConfig
except ImportError:  # pragma: no cover
    @dataclass(frozen=True)
    class AlwaysValidConfig:  # type: ignore[misc]
        alpha_base: float = 1.0

try:
    from .routing import (
        StrategyRouter,
        StrategyRouteContext,
        StrategySignalEnvelope,
    )
except ImportError:  # pragma: no cover
    StrategyRouter = None  # type: ignore[assignment]
    StrategyRouteContext = Any  # type: ignore[misc]
    StrategySignalEnvelope = Any  # type: ignore[misc]

__all__ = [
    "SecuritySignalEnvelope",
    "SecurityAuthContext",
    "SecurityContext",
    "SecurityRouterConfig",
    "SecurityBundleActivation",
    "SecurityPublicConfigView",
    "SecurityBundleDiagnostics",
    "SecurityRouteContract",
    "SecurityDecision",
    "SecurityAuditSink",
    "SecurityTelemetrySink",
    "SecurityLedgerSink",
    "SecurityOutboxSink",
    "SecurityRouter",
]

# =============================================================================
# Constants / types
# =============================================================================

Profile = Literal["DEV", "PROD", "FINREG", "LOCKDOWN"]
OnConfigError = Literal["use_last_known_good", "fail_closed", "raise", "fallback"]
RequiredAction = Literal["allow", "degrade", "block"]
EnforcementMode = Literal["advisory", "must_enforce", "fail_closed"]
RouterMode = Literal["normal", "last_known_good", "fail_closed", "disabled", "degraded"]
RouteIdKind = Literal["plan"]
SignalTrustMode = Literal["trusted", "advisory", "untrusted"]

_SCHEMA = "tcd.security_router.v3"
_ROUTER_NAME = "tcd.security_router"
_ROUTER_VERSION = "3.0.0"

_CFG_FP_VERSION = "scfg1"
_ACTIVATION_ID_VERSION = "sact1"
_EVENT_ID_VERSION = "sev1"
_POLICY_DIGEST_VERSION = "sp1"
_SUBJECT_DIGEST_VERSION = "ss1"
_ROUTE_PLAN_ID_VERSION = "srp1"
_DECISION_ID_VERSION = "sd1"
_CONTEXT_DIGEST_VERSION = "scx1"
_SIGNAL_DIGEST_VERSION = "ssg1"
_ID_HASH_VERSION = "idh1"
_SAFE_DIGEST_ALG = "sha256"

_ALLOWED_PROFILES = frozenset({"DEV", "PROD", "FINREG", "LOCKDOWN"})
_ALLOWED_REQUIRED_ACTIONS = frozenset({"allow", "degrade", "block"})
_ALLOWED_ENFORCEMENT = frozenset({"advisory", "must_enforce", "fail_closed"})
_ALLOWED_KINDS = frozenset({"inference", "admin", "control", "batch", "metrics", "health"})
_ALLOWED_ROUTE_PROFILES = frozenset({"inference", "batch", "admin", "control", "metrics", "health", "restricted"})
_ALLOWED_TRUST_ZONES = frozenset({"internet", "partner", "internal", "admin", "ops"})
_ALLOWED_SIGNAL_TRUST = frozenset({"trusted", "advisory", "untrusted"})

_CTX_KEYS: Tuple[str, ...] = (
    "tenant",
    "user",
    "session",
    "model_id",
    "gpu_id",
    "task",
    "lang",
    "env",
    "trust_zone",
    "route",
    "data_class",
    "workload",
    "jurisdiction",
    "regulation",
    "client_app",
    "access_channel",
)

_CASEFOLD_CTX_KEYS = frozenset(
    {
        "env",
        "trust_zone",
        "route",
        "lang",
        "data_class",
        "workload",
        "jurisdiction",
        "regulation",
        "client_app",
        "access_channel",
    }
)

_DEFAULT_META_KEYS = frozenset(
    {
        "classification",
        "jurisdiction",
        "regulation",
        "client_app",
        "access_channel",
        "channel",
        "risk_source",
        "evidence_source",
        "workflow",
        "workload",
        "data_class",
        "model_family",
        "region",
        "cluster",
    }
)

_SENSITIVE_ROUTE_PROFILES = frozenset({"admin", "control", "restricted"})
_DEFAULT_ALLOWED_SENSITIVE_ROLES = frozenset({"admin", "ops", "security_admin", "control"})
_DEFAULT_ALLOWED_SENSITIVE_SCOPES = frozenset({"tcd:admin", "tcd:control", "write", "danger"})

_ASCII_CTRL_RE = __import__("re").compile(r"[\x00-\x1F\x7F]")
_SAFE_LABEL_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = __import__("re").compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_ID_RE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#]{0,255}$")

_ALLOWED_REASON_CODES = frozenset(
    {
        "DEFAULT_ALLOW",
        "POLICY_BIND_ERROR",
        "POLICY_DENY",
        "POLICY_BLOCK",
        "POLICY_DEGRADE",
        "AUTHZ_DENY",
        "AUTH_CONTEXT_MISSING",
        "AUTH_CONTEXT_UNTRUSTED",
        "RATE_IP_DENY",
        "RATE_TENANT_DENY",
        "RATE_USER_MODEL_DENY",
        "RATE_POLICY_DENY",
        "RATE_DEPENDENCY_ERROR",
        "DETECTOR_HIGH",
        "DETECTOR_CRITICAL",
        "DETECTOR_TRIGGER",
        "DETECTOR_ACTION_BLOCK",
        "DETECTOR_ACTION_DEGRADE",
        "DETECTOR_ERROR",
        "DETECTOR_PREVIEW_ONLY",
        "DETECTOR_SIGNAL_UNTRUSTED",
        "DETECTOR_SIGNAL_UNSIGNED",
        "DETECTOR_SIGNAL_STALE",
        "ROUTE_BLOCK",
        "ROUTE_DEGRADE",
        "ROUTE_UNAVAILABLE",
        "ROUTE_REQUIRED_MISSING",
        "ATTESTOR_REQUIRED_UNAVAILABLE",
        "ATTESTATION_FAILED",
        "RECEIPT_ISSUED",
        "RECEIPT_SKIPPED",
        "AUDIT_EMIT_FAIL",
        "LEDGER_PREPARE_FAILED",
        "LEDGER_COMMIT_FAILED",
        "OUTBOX_QUEUED",
        "OUTBOX_QUEUE_FAILED",
        "INTEGRITY_ERROR",
    }
)

_REASON_CODE_TO_ACTION: Mapping[str, RequiredAction] = MappingProxyType(
    {
        "DEFAULT_ALLOW": "allow",
        "POLICY_BIND_ERROR": "block",
        "POLICY_DENY": "block",
        "POLICY_BLOCK": "block",
        "POLICY_DEGRADE": "degrade",
        "AUTHZ_DENY": "block",
        "AUTH_CONTEXT_MISSING": "block",
        "AUTH_CONTEXT_UNTRUSTED": "block",
        "RATE_IP_DENY": "block",
        "RATE_TENANT_DENY": "block",
        "RATE_USER_MODEL_DENY": "block",
        "RATE_POLICY_DENY": "block",
        "RATE_DEPENDENCY_ERROR": "degrade",
        "DETECTOR_HIGH": "allow",
        "DETECTOR_CRITICAL": "allow",
        "DETECTOR_TRIGGER": "block",
        "DETECTOR_ACTION_BLOCK": "block",
        "DETECTOR_ACTION_DEGRADE": "degrade",
        "DETECTOR_ERROR": "degrade",
        "DETECTOR_PREVIEW_ONLY": "allow",
        "DETECTOR_SIGNAL_UNTRUSTED": "degrade",
        "DETECTOR_SIGNAL_UNSIGNED": "degrade",
        "DETECTOR_SIGNAL_STALE": "degrade",
        "ROUTE_BLOCK": "block",
        "ROUTE_DEGRADE": "degrade",
        "ROUTE_UNAVAILABLE": "degrade",
        "ROUTE_REQUIRED_MISSING": "block",
        "ATTESTOR_REQUIRED_UNAVAILABLE": "block",
        "ATTESTATION_FAILED": "block",
        "RECEIPT_ISSUED": "allow",
        "RECEIPT_SKIPPED": "allow",
        "AUDIT_EMIT_FAIL": "allow",
        "LEDGER_PREPARE_FAILED": "block",
        "LEDGER_COMMIT_FAILED": "block",
        "OUTBOX_QUEUED": "allow",
        "OUTBOX_QUEUE_FAILED": "allow",
        "INTEGRITY_ERROR": "block",
    }
)

# =============================================================================
# Helpers
# =============================================================================


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
    s = unicodedata.normalize("NFC", v)
    s = s[:max_len]
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


def _safe_label(v: Any, *, default: str) -> str:
    s = _strip_unsafe_text(v, max_len=64).lower()
    if not s or not _SAFE_LABEL_RE.fullmatch(s):
        return default
    return s


def _safe_name(v: Any, *, default: str) -> str:
    s = _strip_unsafe_text(v, max_len=128)
    if not s or not _SAFE_NAME_RE.fullmatch(s):
        return default
    return s


def _safe_id(v: Any, *, default: Optional[str], max_len: int = 256) -> Optional[str]:
    s = _strip_unsafe_text(v, max_len=max_len)
    if not s or not _SAFE_ID_RE.fullmatch(s):
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
    if type(v) is str:
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
    if type(v) is str:
        s = v.strip()
        if not s or len(s) > 128:
            return None
        if s.startswith(("+", "-")):
            sign = s[0]
            digits = s[1:]
        else:
            sign = ""
            digits = s
        if not digits.isdigit():
            return None
        try:
            return int(sign + digits, 10)
        except Exception:
            return None
    return None


def _coerce_bool(v: Any, *, default: bool = False) -> bool:
    if type(v) is bool:
        return v
    if type(v) is int:
        if v == 0:
            return False
        if v == 1:
            return True
        return default
    if type(v) is str:
        s = v.strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "no", "n", "off"}:
            return False
    return default


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


def _safe_score(v: Any) -> float:
    x = _coerce_float(v)
    if x is None:
        return 0.0
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return float(x)


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


def _canon_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        _stable_jsonable(obj),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def _safe_digest_hex(*, ctx: str, payload: Mapping[str, Any], out_hex: int = 32) -> str:
    raw = ctx.encode("utf-8", errors="strict") + b"\x00" + _canon_json_bytes(payload)
    return hashlib.sha256(raw).hexdigest()[:out_hex]


def _normalize_str_tuple(values: Iterable[str], *, max_items: int, lower: bool = True) -> Tuple[str, ...]:
    out: List[str] = []
    seen = set()
    for v in values:
        if len(out) >= max_items:
            break
        s = _strip_unsafe_text(v, max_len=128)
        if lower:
            s = s.lower()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return tuple(out)


def _normalize_reason_codes(codes: Iterable[str], *, max_items: int) -> Tuple[str, ...]:
    out: List[str] = []
    seen = set()
    for code in codes:
        c = _strip_unsafe_text(code, max_len=64).upper()
        if not c or c not in _ALLOWED_REASON_CODES or c in seen:
            continue
        seen.add(c)
        out.append(c)
        if len(out) >= max_items:
            break
    return tuple(out)


def _normalize_tags(tags: Iterable[str], *, max_items: int) -> Tuple[str, ...]:
    out: List[str] = []
    seen = set()
    for tag in tags:
        t = _strip_unsafe_text(tag, max_len=128)
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
        if len(out) >= max_items:
            break
    return tuple(out)


def _action_rank(action: str) -> int:
    if action == "block":
        return 2
    if action == "degrade":
        return 1
    return 0


def _action_max(a: RequiredAction, b: RequiredAction) -> RequiredAction:
    return a if _action_rank(a) >= _action_rank(b) else b


def _enforcement_rank(mode: str) -> int:
    if mode == "fail_closed":
        return 2
    if mode == "must_enforce":
        return 1
    return 0


def _enforcement_max(a: EnforcementMode, b: EnforcementMode) -> EnforcementMode:
    return a if _enforcement_rank(a) >= _enforcement_rank(b) else b


def _required_action_from_reason(code: str) -> RequiredAction:
    return _REASON_CODE_TO_ACTION.get(code, "allow")


def _policyset_ref(store: Any) -> Optional[str]:
    fn = getattr(store, "policyset_ref", None)
    if callable(fn):
        try:
            return _safe_id(fn(), default=None, max_len=128)
        except Exception:
            return None
    return _safe_id(getattr(store, "policyset_ref", None), default=None, max_len=128)


def _policy_digest(bp: Any, *, policyset_ref: Optional[str]) -> str:
    payload = {
        "policy_ref": _safe_id(getattr(bp, "policy_ref", None), default=None, max_len=128),
        "policyset_ref": _safe_id(policyset_ref or getattr(bp, "policyset_ref", None), default=None, max_len=128),
        "decision": _safe_label(getattr(bp, "decision", None), default="inherit"),
        "enforcement": _safe_label(getattr(bp, "enforcement", None), default=""),
        "route_profile": _safe_label(getattr(bp, "route_profile", None), default=""),
        "risk_label": _safe_label(getattr(bp, "risk_label", None), default=""),
        "compliance_profile": _safe_label(getattr(bp, "compliance_profile", None), default=""),
        "receipt_profile": _safe_id(getattr(bp, "receipt_profile", None), default=None, max_len=64),
        "receipt_crypto_profile": _safe_id(getattr(bp, "receipt_crypto_profile", None), default=None, max_len=64),
        "origin": _safe_id(getattr(bp, "origin", None), default=None, max_len=128),
        "policy_patch_id": _safe_id(getattr(bp, "policy_patch_id", None), default=None, max_len=128),
        "change_ticket_id": _safe_id(getattr(bp, "change_ticket_id", None), default=None, max_len=128),
        "audit_label": _safe_label(getattr(bp, "audit_label", None), default=""),
        "token_cost_divisor": _stable_float(float(_coerce_float(getattr(bp, "token_cost_divisor", None)) or 50.0)),
    }
    return f"{_POLICY_DIGEST_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:security:policy', payload=payload, out_hex=32)}"


@dataclass(frozen=True)
class _IdentityHasher:
    key: Optional[bytes]
    key_id: Optional[str]
    mode: str  # configured | ephemeral | none

    def digest(self, value: str, *, ctx: str, out_hex: int = 24) -> str:
        raw = ctx.encode("utf-8", errors="strict") + b"\x00" + value.encode("utf-8", errors="ignore")
        if self.key is not None:
            dig = hashlib.pbkdf2_hmac("sha256", raw, self.key, 1, dklen=max(8, out_hex // 2)).hex()[:out_hex]
        else:
            dig = hashlib.sha256(raw).hexdigest()[:out_hex]
        kid = self.key_id or self.mode
        return f"{_ID_HASH_VERSION}:{kid}:{dig}"


def _parse_key_material(v: Any) -> Optional[bytes]:
    if type(v) is bytes:
        if 1 <= len(v) <= 4096:
            return bytes(v)
        return None
    if type(v) is not str:
        return None
    s = _strip_unsafe_text(v, max_len=4096)
    if not s:
        return None
    if s.lower().startswith("hex:"):
        hx = s[4:].strip()
        if len(hx) % 2 != 0:
            return None
        try:
            return bytes.fromhex(hx)
        except Exception:
            return None
    if s.lower().startswith("b64:"):
        import base64
        raw = s[4:].strip()
        try:
            pad = "=" * ((4 - (len(raw) % 4)) % 4)
            out = base64.urlsafe_b64decode((raw + pad).encode("utf-8", errors="strict"))
            return out if out else None
        except Exception:
            return None
    if s.lower().startswith("raw:"):
        return s[4:].encode("utf-8", errors="ignore")
    try:
        if len(s) % 2 == 0:
            return bytes.fromhex(s)
    except Exception:
        pass
    return None


def _subject_digest(subject_id: str, hasher: _IdentityHasher) -> str:
    return hasher.digest(subject_id, ctx="tcd:security:subject", out_hex=24)


def _context_digest(ctx: "SecurityContext", hasher: _IdentityHasher) -> str:
    payload = {
        "subject_hash": _subject_digest(ctx.subject_id(), hasher),
        "tenant_id": ctx.tenant_id,
        "principal_hash": hasher.digest(ctx.principal_id, ctx="tcd:security:principal", out_hex=24) if ctx.principal_id else None,
        "kind": ctx.kind,
        "trust_zone": ctx.trust_zone,
        "route_profile": ctx.route_profile,
        "body_digest": ctx.body_digest,
        "binding_context": ctx.binding_context(),
        "meta_public": ctx.meta_public,
    }
    return f"{_CONTEXT_DIGEST_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:security:context', payload=payload, out_hex=32)}"


def _signal_digest(
    env: "SecuritySignalEnvelope",
    det: "_DetectorResult",
    *,
    ctx: "SecurityContext",
    hasher: _IdentityHasher,
) -> str:
    payload = {
        "source": env.source,
        "trusted": env.trusted,
        "signed": env.signed,
        "signer_kid": env.signer_kid,
        "source_cfg_fp": env.source_cfg_fp,
        "source_policy_ref": env.source_policy_ref,
        "freshness_ms": env.freshness_ms,
        "replay_checked": env.replay_checked,
        "risk_score": det.risk_score,
        "risk_label": det.risk_label,
        "detector_action": det.action,
        "trigger": det.trigger,
        "av_label": det.av_label,
        "av_trigger": det.av_trigger,
        "threat_tags": list(det.threat_tags),
        "subject_hash": _subject_digest(ctx.subject_id(), hasher),
    }
    return f"{_SIGNAL_DIGEST_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:security:signal', payload=payload, out_hex=32)}"


def _normalize_context_map(
    src: Any,
    *,
    allowed_keys: Iterable[str],
    max_items: int,
    max_value_len: int,
) -> Tuple[Dict[str, str], Tuple[str, ...], int]:
    out: Dict[str, str] = {}
    warnings: List[str] = []
    dropped = 0

    if type(src) is not dict:
        return out, tuple(), 0

    allow = set(allowed_keys)
    for k, v in src.items():
        if len(out) >= max_items:
            dropped += 1
            continue
        if type(k) is not str:
            dropped += 1
            continue
        kk = _strip_unsafe_text(k, max_len=64).strip()
        if kk not in allow:
            dropped += 1
            warnings.append("unknown_context_key_dropped")
            continue
        vv = _strip_unsafe_text(v, max_len=max_value_len) if isinstance(v, str) else ""
        if not vv:
            continue
        if kk in _CASEFOLD_CTX_KEYS:
            vv = vv.lower()
        out[kk] = vv
    return out, tuple(sorted(set(warnings))), dropped


def _normalize_meta_map(
    src: Any,
    *,
    allowed_keys: Iterable[str],
    max_items: int,
    max_value_len: int,
) -> Tuple[Dict[str, Any], Dict[str, Any], int, Tuple[str, ...]]:
    public: Dict[str, Any] = {}
    internal: Dict[str, Any] = {}
    dropped = 0
    warnings: List[str] = []

    if type(src) is not dict:
        return public, internal, 0, tuple()

    allow = set(allowed_keys)
    for k, v in src.items():
        if type(k) is not str:
            dropped += 1
            continue
        kk = _strip_unsafe_text(k, max_len=64).strip().lower()
        if not kk:
            dropped += 1
            continue
        if kk in allow:
            if isinstance(v, (str, int, float, bool)) or v is None:
                if isinstance(v, str):
                    public[kk] = _strip_unsafe_text(v, max_len=max_value_len)
                elif isinstance(v, float):
                    public[kk] = float(v) if math.isfinite(v) else None
                else:
                    public[kk] = v
            else:
                public[kk] = _safe_name(type(v).__name__, default="object")
            if len(public) >= max_items:
                break
        else:
            dropped += 1
            warnings.append("meta_extension_dropped")
            if len(internal) < max_items and isinstance(v, (str, int, float, bool)):
                internal[kk] = _strip_unsafe_text(v, max_len=max_value_len) if isinstance(v, str) else v
    return public, internal, dropped, tuple(sorted(set(warnings)))


# =============================================================================
# Protocols
# =============================================================================


class SecurityAuditSink(Protocol):
    def emit(self, event_type: str, payload: Mapping[str, Any]) -> Optional[str]:
        ...


class SecurityTelemetrySink(Protocol):
    def record_metric(self, name: str, value: float, labels: Mapping[str, str]) -> None:
        ...

    def record_event(self, name: str, payload: Mapping[str, Any]) -> None:
        ...


class SecurityLedgerSink(Protocol):
    def prepare(self, event_id: str, payload: Mapping[str, Any]) -> Optional[str]:
        ...

    def commit(self, event_id: str, payload: Mapping[str, Any]) -> Optional[str]:
        ...


class SecurityOutboxSink(Protocol):
    def enqueue(self, *, kind: str, dedupe_key: str, payload: Mapping[str, Any], payload_digest: str) -> Optional[str]:
        ...


# =============================================================================
# Public data models
# =============================================================================


@dataclass(frozen=True)
class SecuritySignalEnvelope:
    source: str = "legacy_implicit"
    trusted: bool = True
    signed: bool = False
    signer_kid: Optional[str] = None
    source_cfg_fp: Optional[str] = None
    source_policy_ref: Optional[str] = None
    freshness_ms: Optional[int] = None
    replay_checked: Optional[bool] = None

    def normalized(self) -> "SecuritySignalEnvelope":
        return SecuritySignalEnvelope(
            source=_safe_name(self.source, default="legacy_implicit"),
            trusted=bool(self.trusted),
            signed=bool(self.signed),
            signer_kid=_safe_id(self.signer_kid, default=None, max_len=64),
            source_cfg_fp=_safe_id(self.source_cfg_fp, default=None, max_len=128),
            source_policy_ref=_safe_id(self.source_policy_ref, default=None, max_len=128),
            freshness_ms=(
                _clamp_int(self.freshness_ms, default=0, lo=0, hi=86_400_000)
                if self.freshness_ms is not None
                else None
            ),
            replay_checked=None if self.replay_checked is None else bool(self.replay_checked),
        )

    def trust_mode(self) -> SignalTrustMode:
        return _signal_trust_mode(self)


@dataclass(frozen=True)
class SecurityAuthContext:
    principal_id: Optional[str] = None
    roles: Tuple[str, ...] = ()
    scopes: Tuple[str, ...] = ()
    access_channel: Optional[str] = None
    approval_id: Optional[str] = None
    approval_system: Optional[str] = None
    mfa_verified: bool = False
    trusted: bool = True
    auth_strength: Optional[str] = None

    def normalized(self) -> "SecurityAuthContext":
        return SecurityAuthContext(
            principal_id=_safe_id(self.principal_id, default=None, max_len=128),
            roles=_normalize_str_tuple((_safe_label(x, default="") for x in self.roles), max_items=32),
            scopes=_normalize_str_tuple((_safe_label(x, default="") for x in self.scopes), max_items=64),
            access_channel=_safe_label(self.access_channel, default="") or None if isinstance(self.access_channel, str) else None,
            approval_id=_safe_id(self.approval_id, default=None, max_len=128),
            approval_system=_safe_label(self.approval_system, default="") or None if isinstance(self.approval_system, str) else None,
            mfa_verified=bool(self.mfa_verified),
            trusted=bool(self.trusted),
            auth_strength=_safe_label(self.auth_strength, default="") or None if isinstance(self.auth_strength, str) else None,
        )


@dataclass(frozen=True)
class SecurityContext:
    subject: SubjectKey
    ctx: Dict[str, str]
    tokens_in: int
    tokens_out: int
    ip: Optional[str] = None
    kind: str = "inference"

    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    event_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    body_digest: Optional[str] = None
    tenant_id: Optional[str] = None
    principal_id: Optional[str] = None

    trust_zone: Optional[str] = None
    route_profile: Optional[str] = None

    base_temp: float = 1.0
    base_top_p: float = 1.0
    base_max_tokens: Optional[int] = None

    pq_required: Optional[bool] = None
    pq_unhealthy: bool = False
    signal_envelope: Optional[SecuritySignalEnvelope] = None
    auth_context: Optional[SecurityAuthContext] = None

    meta: Dict[str, Any] = field(default_factory=dict)
    meta_public: Dict[str, Any] = field(default_factory=dict)
    meta_internal: Dict[str, Any] = field(default_factory=dict)
    meta_dropped_count: int = 0
    normalization_warnings: Tuple[str, ...] = ()

    def normalized(
        self,
        *,
        allowed_context_keys: Iterable[str] = _CTX_KEYS,
        allowed_meta_keys: Iterable[str] = _DEFAULT_META_KEYS,
        max_context_items: int = 32,
        max_context_value_len: int = 128,
        max_meta_items: int = 32,
        max_meta_value_len: int = 256,
    ) -> "SecurityContext":
        ctx_norm, ctx_warn, ctx_dropped = _normalize_context_map(
            self.ctx,
            allowed_keys=allowed_context_keys,
            max_items=max_context_items,
            max_value_len=max_context_value_len,
        )
        meta_public, meta_internal, meta_dropped, meta_warn = _normalize_meta_map(
            self.meta,
            allowed_keys=allowed_meta_keys,
            max_items=max_meta_items,
            max_value_len=max_meta_value_len,
        )

        kind = _safe_label(self.kind, default="inference")
        if kind not in _ALLOWED_KINDS:
            kind = "inference"

        trust_zone = _safe_label(self.trust_zone, default="") or _safe_label(ctx_norm.get("trust_zone"), default="internet")
        if trust_zone not in _ALLOWED_TRUST_ZONES:
            trust_zone = "internet"

        route_profile = _safe_label(self.route_profile, default="") or _safe_label(ctx_norm.get("route"), default=kind)
        if route_profile not in _ALLOWED_ROUTE_PROFILES:
            route_profile = "inference"

        auth_ctx = (self.auth_context or SecurityAuthContext(
            principal_id=self.principal_id or ctx_norm.get("user"),
            access_channel=ctx_norm.get("access_channel"),
        )).normalized()

        tenant_id = _safe_id(self.tenant_id, default=None, max_len=128) or _safe_id(ctx_norm.get("tenant"), default=None, max_len=128)
        principal_id = auth_ctx.principal_id or _safe_id(self.principal_id, default=None, max_len=128) or _safe_id(ctx_norm.get("user"), default=None, max_len=128)

        warnings = tuple(sorted(set(ctx_warn + meta_warn)))
        total_dropped = int(ctx_dropped) + int(meta_dropped)

        return SecurityContext(
            subject=self.subject if isinstance(self.subject, SubjectKey) else SubjectKey(),
            ctx=ctx_norm,
            tokens_in=max(0, int(_coerce_int(self.tokens_in) or 0)),
            tokens_out=max(0, int(_coerce_int(self.tokens_out) or 0)),
            ip=_safe_id(self.ip, default=None, max_len=128),
            kind=kind,
            request_id=_safe_id(self.request_id, default=None, max_len=128),
            trace_id=_safe_id(self.trace_id, default=None, max_len=128),
            event_id=_safe_id(self.event_id, default=None, max_len=128),
            idempotency_key=_safe_id(self.idempotency_key, default=None, max_len=128),
            body_digest=_safe_id(self.body_digest, default=None, max_len=256),
            tenant_id=tenant_id,
            principal_id=principal_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            base_temp=_clamp_float(self.base_temp, default=1.0, lo=0.0, hi=10.0),
            base_top_p=_clamp_float(self.base_top_p, default=1.0, lo=0.0, hi=1.0),
            base_max_tokens=(
                _clamp_int(self.base_max_tokens, default=1, lo=1, hi=10_000_000)
                if self.base_max_tokens is not None
                else None
            ),
            pq_required=None if self.pq_required is None else bool(self.pq_required),
            pq_unhealthy=bool(self.pq_unhealthy),
            signal_envelope=(self.signal_envelope or SecuritySignalEnvelope()).normalized(),
            auth_context=auth_ctx,
            meta=meta_public,
            meta_public=meta_public,
            meta_internal=meta_internal,
            meta_dropped_count=total_dropped,
            normalization_warnings=warnings,
        )

    def subject_id(self) -> str:
        try:
            raw = self.subject.as_id()
        except Exception:
            raw = "tenant=*|user=*|session=*|model=*"
        return _strip_unsafe_text(raw, max_len=512) or "tenant=*|user=*|session=*|model=*"

    def binding_context(self) -> Dict[str, str]:
        out = dict(self.ctx)
        if self.tenant_id and "tenant" not in out:
            out["tenant"] = self.tenant_id
        if self.principal_id and "user" not in out:
            out["user"] = self.principal_id
        if self.trust_zone and "trust_zone" not in out:
            out["trust_zone"] = self.trust_zone
        if self.route_profile and "route" not in out:
            out["route"] = self.route_profile
        if self.auth_context and self.auth_context.access_channel and "access_channel" not in out:
            out["access_channel"] = self.auth_context.access_channel
        session = _safe_id(getattr(self.subject, "session", None), default=None, max_len=128)
        model_id = _safe_id(getattr(self.subject, "model_id", None), default=None, max_len=128)
        if session and "session" not in out:
            out["session"] = session
        if model_id and "model_id" not in out:
            out["model_id"] = model_id
        return out


@dataclass
class SecurityRouterConfig:
    schema_version: int = 1
    enabled: bool = True
    profile: Profile = "PROD"
    on_config_error: OnConfigError = "use_last_known_good"

    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    patch_id: Optional[str] = None
    change_ticket_id: Optional[str] = None
    activated_by: Optional[str] = None
    approved_by: Tuple[str, ...] = ()

    identity_hash_key_material: Optional[Any] = None
    identity_hash_key_id: Optional[str] = None
    auto_ephemeral_identity_key_if_missing: bool = True
    min_identity_key_bytes: int = 16

    allowed_context_keys: Tuple[str, ...] = _CTX_KEYS
    allowed_meta_keys: Tuple[str, ...] = tuple(_DEFAULT_META_KEYS)
    max_context_items: int = 32
    max_context_value_len: int = 128
    max_meta_items: int = 32
    max_meta_value_len: int = 256

    sensitive_route_profiles: Tuple[str, ...] = tuple(_SENSITIVE_ROUTE_PROFILES)
    allowed_sensitive_roles: Tuple[str, ...] = tuple(_DEFAULT_ALLOWED_SENSITIVE_ROLES)
    allowed_sensitive_scopes: Tuple[str, ...] = tuple(_DEFAULT_ALLOWED_SENSITIVE_SCOPES)
    require_trusted_auth_context_for_sensitive: bool = True
    allow_internal_principal_for_sensitive: bool = False

    bind_error_action: RequiredAction = "block"
    rate_error_action: RequiredAction = "degrade"
    detector_error_action: RequiredAction = "degrade"
    route_error_action: RequiredAction = "degrade"
    attestation_error_action: RequiredAction = "block"

    require_route_contract: bool = True
    synthetic_route_on_error: bool = True

    receipt_required_on_deny: bool = True
    ledger_required_on_deny: bool = False
    attestation_required_on_deny: bool = False
    require_attestor_when_required: bool = True
    require_ledger_when_required: bool = False

    audit_emit_all_decisions: bool = True
    outbox_enabled: bool = True
    outbox_on_required_sink_failure: bool = True

    event_id_bucket_s: int = 60

    max_signal_freshness_ms: Optional[int] = 300_000
    require_trusted_signal_for_block: bool = False
    require_signed_signal_for_block: bool = False

    strict_preview_requires_preview_method: bool = True

    def normalized_copy(self) -> "SecurityRouterConfig":
        c = SecurityRouterConfig()
        c.schema_version = _clamp_int(self.schema_version, default=1, lo=1, hi=1_000_000)

        prof = _safe_label(self.profile, default="prod").upper()
        if prof not in _ALLOWED_PROFILES:
            prof = "PROD"
        c.profile = prof  # type: ignore[assignment]

        on_err = self.on_config_error
        if on_err == "fallback":
            on_err = "use_last_known_good"
        if on_err not in {"use_last_known_good", "fail_closed", "raise"}:
            on_err = "fail_closed"
        c.on_config_error = on_err  # type: ignore[assignment]

        c.enabled = bool(self.enabled)

        c.policy_ref = _safe_id(self.policy_ref, default=None, max_len=128)
        c.policyset_ref = _safe_id(self.policyset_ref, default=None, max_len=128)
        c.patch_id = _safe_id(self.patch_id, default=None, max_len=128)
        c.change_ticket_id = _safe_id(self.change_ticket_id, default=None, max_len=128)
        c.activated_by = _safe_id(self.activated_by, default=None, max_len=128)
        c.approved_by = tuple(x for x in (_safe_id(v, default=None, max_len=128) for v in self.approved_by) if x is not None)[:16]

        c.identity_hash_key_material = self.identity_hash_key_material
        c.identity_hash_key_id = _safe_id(self.identity_hash_key_id, default=None, max_len=64)
        c.auto_ephemeral_identity_key_if_missing = bool(self.auto_ephemeral_identity_key_if_missing)
        c.min_identity_key_bytes = _clamp_int(self.min_identity_key_bytes, default=16, lo=1, hi=4096)

        c.allowed_context_keys = tuple(k for k in _CTX_KEYS if k in set(self.allowed_context_keys or _CTX_KEYS))
        if not c.allowed_context_keys:
            c.allowed_context_keys = _CTX_KEYS
        c.allowed_meta_keys = _normalize_str_tuple((str(x) for x in (self.allowed_meta_keys or tuple(_DEFAULT_META_KEYS))), max_items=64)
        if not c.allowed_meta_keys:
            c.allowed_meta_keys = tuple(_DEFAULT_META_KEYS)

        c.max_context_items = _clamp_int(self.max_context_items, default=32, lo=1, hi=256)
        c.max_context_value_len = _clamp_int(self.max_context_value_len, default=128, lo=16, hi=1024)
        c.max_meta_items = _clamp_int(self.max_meta_items, default=32, lo=1, hi=256)
        c.max_meta_value_len = _clamp_int(self.max_meta_value_len, default=256, lo=16, hi=4096)

        c.sensitive_route_profiles = _normalize_str_tuple((str(x) for x in self.sensitive_route_profiles), max_items=16)
        if not c.sensitive_route_profiles:
            c.sensitive_route_profiles = tuple(_SENSITIVE_ROUTE_PROFILES)
        c.allowed_sensitive_roles = _normalize_str_tuple((str(x) for x in self.allowed_sensitive_roles), max_items=64)
        if not c.allowed_sensitive_roles:
            c.allowed_sensitive_roles = tuple(_DEFAULT_ALLOWED_SENSITIVE_ROLES)
        c.allowed_sensitive_scopes = _normalize_str_tuple((str(x) for x in self.allowed_sensitive_scopes), max_items=128)
        if not c.allowed_sensitive_scopes:
            c.allowed_sensitive_scopes = tuple(_DEFAULT_ALLOWED_SENSITIVE_SCOPES)

        c.require_trusted_auth_context_for_sensitive = bool(self.require_trusted_auth_context_for_sensitive)
        c.allow_internal_principal_for_sensitive = bool(self.allow_internal_principal_for_sensitive)

        c.bind_error_action = _safe_label(self.bind_error_action, default="block")  # type: ignore[assignment]
        c.rate_error_action = _safe_label(self.rate_error_action, default="degrade")  # type: ignore[assignment]
        c.detector_error_action = _safe_label(self.detector_error_action, default="degrade")  # type: ignore[assignment]
        c.route_error_action = _safe_label(self.route_error_action, default="degrade")  # type: ignore[assignment]
        c.attestation_error_action = _safe_label(self.attestation_error_action, default="block")  # type: ignore[assignment]

        if c.bind_error_action not in _ALLOWED_REQUIRED_ACTIONS:
            c.bind_error_action = "block"
        if c.rate_error_action not in _ALLOWED_REQUIRED_ACTIONS:
            c.rate_error_action = "degrade"
        if c.detector_error_action not in _ALLOWED_REQUIRED_ACTIONS:
            c.detector_error_action = "degrade"
        if c.route_error_action not in _ALLOWED_REQUIRED_ACTIONS:
            c.route_error_action = "degrade"
        if c.attestation_error_action not in _ALLOWED_REQUIRED_ACTIONS:
            c.attestation_error_action = "block"

        c.require_route_contract = bool(self.require_route_contract)
        c.synthetic_route_on_error = bool(self.synthetic_route_on_error)

        c.receipt_required_on_deny = bool(self.receipt_required_on_deny)
        c.ledger_required_on_deny = bool(self.ledger_required_on_deny)
        c.attestation_required_on_deny = bool(self.attestation_required_on_deny)
        c.require_attestor_when_required = bool(self.require_attestor_when_required)
        c.require_ledger_when_required = bool(self.require_ledger_when_required)

        c.audit_emit_all_decisions = bool(self.audit_emit_all_decisions)
        c.outbox_enabled = bool(self.outbox_enabled)
        c.outbox_on_required_sink_failure = bool(self.outbox_on_required_sink_failure)

        c.event_id_bucket_s = _clamp_int(self.event_id_bucket_s, default=60, lo=1, hi=3600)

        c.max_signal_freshness_ms = (
            _clamp_int(self.max_signal_freshness_ms, default=300_000, lo=0, hi=86_400_000)
            if self.max_signal_freshness_ms is not None
            else None
        )
        c.require_trusted_signal_for_block = bool(self.require_trusted_signal_for_block)
        c.require_signed_signal_for_block = bool(self.require_signed_signal_for_block)
        c.strict_preview_requires_preview_method = bool(self.strict_preview_requires_preview_method)

        if c.profile in {"FINREG", "LOCKDOWN"}:
            c.bind_error_action = "block"
            c.rate_error_action = "block"
            c.detector_error_action = "block"
            c.route_error_action = "block"
            c.attestation_error_action = "block"
            c.require_route_contract = True
            c.synthetic_route_on_error = True
            c.receipt_required_on_deny = True
            c.ledger_required_on_deny = True
            c.attestation_required_on_deny = True
            c.require_attestor_when_required = True
            c.require_trusted_signal_for_block = True
            c.require_signed_signal_for_block = True
            c.max_meta_items = min(c.max_meta_items, 16)
            c.max_context_items = min(c.max_context_items, 16)

        return c

    def to_public_dict(self) -> Dict[str, Any]:
        c = self.normalized_copy()
        return {
            "schema_version": c.schema_version,
            "enabled": c.enabled,
            "profile": c.profile,
            "on_config_error": c.on_config_error,
            "policy_ref": c.policy_ref,
            "policyset_ref": c.policyset_ref,
            "patch_id": c.patch_id,
            "change_ticket_id": c.change_ticket_id,
            "activated_by": c.activated_by,
            "approved_by": list(c.approved_by),
            "identity_hash_key_id": c.identity_hash_key_id,
            "auto_ephemeral_identity_key_if_missing": c.auto_ephemeral_identity_key_if_missing,
            "min_identity_key_bytes": c.min_identity_key_bytes,
            "allowed_context_keys": list(c.allowed_context_keys),
            "allowed_meta_keys": list(c.allowed_meta_keys),
            "max_context_items": c.max_context_items,
            "max_context_value_len": c.max_context_value_len,
            "max_meta_items": c.max_meta_items,
            "max_meta_value_len": c.max_meta_value_len,
            "sensitive_route_profiles": list(c.sensitive_route_profiles),
            "allowed_sensitive_roles": list(c.allowed_sensitive_roles),
            "allowed_sensitive_scopes": list(c.allowed_sensitive_scopes),
            "require_trusted_auth_context_for_sensitive": c.require_trusted_auth_context_for_sensitive,
            "allow_internal_principal_for_sensitive": c.allow_internal_principal_for_sensitive,
            "bind_error_action": c.bind_error_action,
            "rate_error_action": c.rate_error_action,
            "detector_error_action": c.detector_error_action,
            "route_error_action": c.route_error_action,
            "attestation_error_action": c.attestation_error_action,
            "require_route_contract": c.require_route_contract,
            "synthetic_route_on_error": c.synthetic_route_on_error,
            "receipt_required_on_deny": c.receipt_required_on_deny,
            "ledger_required_on_deny": c.ledger_required_on_deny,
            "attestation_required_on_deny": c.attestation_required_on_deny,
            "require_attestor_when_required": c.require_attestor_when_required,
            "require_ledger_when_required": c.require_ledger_when_required,
            "audit_emit_all_decisions": c.audit_emit_all_decisions,
            "outbox_enabled": c.outbox_enabled,
            "outbox_on_required_sink_failure": c.outbox_on_required_sink_failure,
            "event_id_bucket_s": c.event_id_bucket_s,
            "max_signal_freshness_ms": c.max_signal_freshness_ms,
            "require_trusted_signal_for_block": c.require_trusted_signal_for_block,
            "require_signed_signal_for_block": c.require_signed_signal_for_block,
            "strict_preview_requires_preview_method": c.strict_preview_requires_preview_method,
        }

    def fingerprint(self) -> str:
        d = _safe_digest_hex(ctx="tcd:security_router:cfg", payload=self.to_public_dict(), out_hex=64)
        return f"{_CFG_FP_VERSION}:{_SAFE_DIGEST_ALG}:{d}"


@dataclass(frozen=True)
class SecurityBundleActivation:
    activation_id: str
    cfg_fp: str
    bundle_version: int
    policy_ref: Optional[str]
    policyset_ref: Optional[str]
    patch_id: Optional[str]
    change_ticket_id: Optional[str]
    activated_by: Optional[str]
    approved_by: Tuple[str, ...]
    activated_at_unix_ns: int
    previous_cfg_fp: Optional[str]
    activation_mode: str


@dataclass(frozen=True)
class SecurityPublicConfigView:
    cfg_fp: str
    bundle_version: int
    bundle_updated_at_unix_ns: int
    activation_id: str
    profile: Profile
    enabled: bool
    policy_ref: Optional[str]
    policyset_ref: Optional[str]
    identity_hash_mode: str
    identity_hash_key_id: Optional[str]
    has_errors: bool
    has_warnings: bool
    router_mode: RouterMode


@dataclass(frozen=True)
class SecurityBundleDiagnostics:
    active_cfg_fp: str
    active_bundle_version: int
    active_updated_at_unix_ns: int
    activation_id: str
    profile: Profile
    enabled: bool
    policy_ref: Optional[str]
    policyset_ref: Optional[str]
    identity_hash_mode: str
    identity_hash_key_id: Optional[str]
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    using_last_known_good: bool
    last_known_good_cfg_fp: Optional[str]
    last_rejected_cfg_fp: Optional[str]


@dataclass(frozen=True)
class SecurityRouteContract:
    schema: str
    router: str
    version: str

    instance_id: str
    activation_id: str
    config_fingerprint: str
    bundle_version: int
    bundle_updated_at_unix_ns: int

    policy_ref: Optional[str]
    policyset_ref: Optional[str]
    patch_id: Optional[str]
    change_ticket_id: Optional[str]
    activated_by: Optional[str]

    router_mode: RouterMode
    route_id_kind: RouteIdKind
    route_plan_id: str
    route_id: str
    decision_id: str
    decision_seq: int
    decision_ts_unix_ns: int
    decision_ts_mono_ns: int

    safety_tier: str
    required_action: RequiredAction
    action_hint: RequiredAction
    enforcement_mode: EnforcementMode

    temperature: float
    top_p: float
    decoder: str
    max_tokens: Optional[int]
    latency_hint: str

    tool_calls_allowed: bool
    retrieval_allowed: bool
    streaming_allowed: bool
    external_calls_allowed: bool
    response_policy: str
    receipt_required: bool
    ledger_required: bool
    attestation_required: bool

    trust_zone: str
    route_profile: str
    risk_label: str
    score: float
    decision_fail: bool
    e_triggered: bool
    pq_unhealthy: bool
    av_label: Optional[str]
    av_trigger: Optional[bool]
    threat_tags: Tuple[str, ...]
    controller_mode: Optional[str]
    guarantee_scope: Optional[str]

    signal_source: str
    signal_trust_mode: SignalTrustMode
    signal_signed: bool
    signal_signer_kid: Optional[str]
    signal_cfg_fp: Optional[str]
    signal_policy_ref: Optional[str]
    signal_freshness_ms: Optional[int]
    signal_replay_checked: Optional[bool]

    signal_digest: str
    context_digest: str

    primary_reason_code: str
    reason_codes: Tuple[str, ...]
    degraded_reason_codes: Tuple[str, ...]
    reason: str
    tags: Tuple[str, ...]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "router": self.router,
            "version": self.version,
            "instance_id": self.instance_id,
            "activation_id": self.activation_id,
            "config_fingerprint": self.config_fingerprint,
            "bundle_version": self.bundle_version,
            "bundle_updated_at_unix_ns": self.bundle_updated_at_unix_ns,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "patch_id": self.patch_id,
            "change_ticket_id": self.change_ticket_id,
            "activated_by": self.activated_by,
            "router_mode": self.router_mode,
            "route_id_kind": self.route_id_kind,
            "route_plan_id": self.route_plan_id,
            "route_id": self.route_id,
            "decision_id": self.decision_id,
            "decision_seq": self.decision_seq,
            "decision_ts_unix_ns": self.decision_ts_unix_ns,
            "decision_ts_mono_ns": self.decision_ts_mono_ns,
            "safety_tier": self.safety_tier,
            "required_action": self.required_action,
            "action_hint": self.action_hint,
            "enforcement_mode": self.enforcement_mode,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "decoder": self.decoder,
            "max_tokens": self.max_tokens,
            "latency_hint": self.latency_hint,
            "tool_calls_allowed": self.tool_calls_allowed,
            "retrieval_allowed": self.retrieval_allowed,
            "streaming_allowed": self.streaming_allowed,
            "external_calls_allowed": self.external_calls_allowed,
            "response_policy": self.response_policy,
            "receipt_required": self.receipt_required,
            "ledger_required": self.ledger_required,
            "attestation_required": self.attestation_required,
            "trust_zone": self.trust_zone,
            "route_profile": self.route_profile,
            "risk_label": self.risk_label,
            "score": self.score,
            "decision_fail": self.decision_fail,
            "e_triggered": self.e_triggered,
            "pq_unhealthy": self.pq_unhealthy,
            "av_label": self.av_label,
            "av_trigger": self.av_trigger,
            "threat_tags": list(self.threat_tags),
            "controller_mode": self.controller_mode,
            "guarantee_scope": self.guarantee_scope,
            "signal_source": self.signal_source,
            "signal_trust_mode": self.signal_trust_mode,
            "signal_signed": self.signal_signed,
            "signal_signer_kid": self.signal_signer_kid,
            "signal_cfg_fp": self.signal_cfg_fp,
            "signal_policy_ref": self.signal_policy_ref,
            "signal_freshness_ms": self.signal_freshness_ms,
            "signal_replay_checked": self.signal_replay_checked,
            "signal_digest": self.signal_digest,
            "context_digest": self.context_digest,
            "primary_reason_code": self.primary_reason_code,
            "reason_codes": list(self.reason_codes),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "reason": self.reason,
            "tags": list(self.tags),
        }

    def to_receipt_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "router": self.router,
            "version": self.version,
            "activation_id": self.activation_id,
            "config_fingerprint": self.config_fingerprint,
            "bundle_version": self.bundle_version,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "route_plan_id": self.route_plan_id,
            "decision_id": self.decision_id,
            "safety_tier": self.safety_tier,
            "required_action": self.required_action,
            "enforcement_mode": self.enforcement_mode,
            "decoder": self.decoder,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "max_tokens": self.max_tokens,
            "trust_zone": self.trust_zone,
            "route_profile": self.route_profile,
            "risk_label": self.risk_label,
            "score": self.score,
            "primary_reason_code": self.primary_reason_code,
            "reason_codes": list(self.reason_codes),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "signal_digest": self.signal_digest,
            "context_digest": self.context_digest,
            "receipt_required": self.receipt_required,
            "ledger_required": self.ledger_required,
            "attestation_required": self.attestation_required,
        }

    def to_audit_event(self) -> Dict[str, Any]:
        return {
            "type": "tcd.security_router.route",
            "decision_id": self.decision_id,
            "route_plan_id": self.route_plan_id,
            "decision_seq": self.decision_seq,
            "decision_ts_unix_ns": self.decision_ts_unix_ns,
            "router_mode": self.router_mode,
            "activation_id": self.activation_id,
            "config_fingerprint": self.config_fingerprint,
            "bundle_version": self.bundle_version,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "patch_id": self.patch_id,
            "change_ticket_id": self.change_ticket_id,
            "required_action": self.required_action,
            "enforcement_mode": self.enforcement_mode,
            "safety_tier": self.safety_tier,
            "primary_reason_code": self.primary_reason_code,
            "reason_codes": list(self.reason_codes),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "trust_zone": self.trust_zone,
            "route_profile": self.route_profile,
            "risk_label": self.risk_label,
            "score": self.score,
            "signal_digest": self.signal_digest,
            "context_digest": self.context_digest,
            "receipt_required": self.receipt_required,
            "ledger_required": self.ledger_required,
            "attestation_required": self.attestation_required,
        }


@dataclass(frozen=True)
class SecurityDecision:
    schema: str
    router: str
    version: str

    instance_id: str
    activation_id: str
    config_fingerprint: str
    bundle_version: int
    bundle_updated_at_unix_ns: int

    event_id: str
    decision_seq: int
    decision_ts_unix_ns: int
    decision_ts_mono_ns: int
    batch_id: Optional[str]

    allowed: bool
    action: RequiredAction
    action_taken: RequiredAction
    required_action: RequiredAction
    enforcement_mode: EnforcementMode

    primary_reason_code: str
    reason_codes: Tuple[str, ...]
    degraded_reason_codes: Tuple[str, ...]
    reason: str

    bound_policy: BoundPolicy
    policy_ref: Optional[str]
    policyset_ref: Optional[str]
    policy_digest: str

    route: Optional[Any]
    route_plan_id: Optional[str]
    decision_id: Optional[str]

    rate_decisions: Dict[str, Any]
    risk_score: Optional[float] = None
    risk_label: Optional[str] = None
    e_triggered: bool = False
    controller_mode: Optional[str] = None
    guarantee_scope: Optional[str] = None

    e_state: Optional[Dict[str, Any]] = None
    security: Dict[str, Any] = field(default_factory=dict)
    evidence_identity: Dict[str, Any] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)

    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None
    receipt: Optional[Dict[str, Any]] = None

    integrity_ok: bool = True
    integrity_errors: Tuple[str, ...] = ()
    normalization_warnings: Tuple[str, ...] = ()
    compat_warnings: Tuple[str, ...] = ()

    def to_dict(self) -> Dict[str, Any]:
        route_dict: Optional[Dict[str, Any]] = None
        if self.route is not None:
            try:
                route_dict = self.route.to_dict()
            except Exception:
                route_dict = None
        return {
            "schema": self.schema,
            "router": self.router,
            "version": self.version,
            "instance_id": self.instance_id,
            "activation_id": self.activation_id,
            "config_fingerprint": self.config_fingerprint,
            "bundle_version": self.bundle_version,
            "bundle_updated_at_unix_ns": self.bundle_updated_at_unix_ns,
            "event_id": self.event_id,
            "decision_seq": self.decision_seq,
            "decision_ts_unix_ns": self.decision_ts_unix_ns,
            "decision_ts_mono_ns": self.decision_ts_mono_ns,
            "batch_id": self.batch_id,
            "allowed": self.allowed,
            "action": self.action,
            "action_taken": self.action_taken,
            "required_action": self.required_action,
            "enforcement_mode": self.enforcement_mode,
            "primary_reason_code": self.primary_reason_code,
            "reason_codes": list(self.reason_codes),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "reason": self.reason,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "route_plan_id": self.route_plan_id,
            "decision_id": self.decision_id,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "e_triggered": self.e_triggered,
            "controller_mode": self.controller_mode,
            "guarantee_scope": self.guarantee_scope,
            "rate_decisions": {
                k: {
                    "zone": getattr(v, "zone", None),
                    "allowed": getattr(v, "allowed", None),
                    "reason": getattr(v, "reason", None),
                    "retry_after_s": getattr(v, "retry_after_s", None),
                    "cfg_fp": getattr(v, "cfg_fp", None),
                    "decision_seq": getattr(v, "decision_seq", None),
                    "bundle_version": getattr(v, "bundle_version", None),
                    "zone_resolution": getattr(v, "zone_resolution", None),
                    "requested_zone_hash": getattr(v, "requested_zone_hash", None),
                }
                for k, v in self.rate_decisions.items()
            },
            "route": route_dict,
            "e_state": self.e_state,
            "security": dict(self.security),
            "evidence_identity": dict(self.evidence_identity),
            "artifacts": dict(self.artifacts),
            "audit_ref": self.audit_ref,
            "receipt_ref": self.receipt_ref,
            "receipt": dict(self.receipt or {}),
            "integrity_ok": self.integrity_ok,
            "integrity_errors": list(self.integrity_errors),
            "normalization_warnings": list(self.normalization_warnings),
            "compat_warnings": list(self.compat_warnings),
        }

    def to_receipt_dict(self) -> Dict[str, Any]:
        route_receipt: Optional[Dict[str, Any]] = None
        if self.route is not None and hasattr(self.route, "to_receipt_dict"):
            try:
                route_receipt = self.route.to_receipt_dict()
            except Exception:
                route_receipt = None
        return {
            "schema": self.schema,
            "router": self.router,
            "version": self.version,
            "activation_id": self.activation_id,
            "config_fingerprint": self.config_fingerprint,
            "bundle_version": self.bundle_version,
            "event_id": self.event_id,
            "decision_seq": self.decision_seq,
            "allowed": self.allowed,
            "action": self.action,
            "required_action": self.required_action,
            "enforcement_mode": self.enforcement_mode,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "route_plan_id": self.route_plan_id,
            "decision_id": self.decision_id,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "e_triggered": self.e_triggered,
            "controller_mode": self.controller_mode,
            "statistical_guarantee_scope": self.guarantee_scope,
            "reason_codes": list(self.reason_codes),
            "route": route_receipt,
            "e_state": self.e_state,
            "evidence_identity": dict(self.evidence_identity),
            "artifacts": dict(self.artifacts),
            "security": dict(self.security),
            "receipt": dict(self.receipt or {}),
            "integrity_ok": self.integrity_ok,
            "integrity_errors": list(self.integrity_errors),
        }

    def to_audit_event(self) -> Dict[str, Any]:
        route_audit: Optional[Dict[str, Any]] = None
        if self.route is not None and hasattr(self.route, "to_audit_event"):
            try:
                route_audit = self.route.to_audit_event()
            except Exception:
                route_audit = None
        return {
            "type": "tcd.security_router.decision",
            "schema": self.schema,
            "router": self.router,
            "version": self.version,
            "instance_id": self.instance_id,
            "activation_id": self.activation_id,
            "config_fingerprint": self.config_fingerprint,
            "bundle_version": self.bundle_version,
            "event_id": self.event_id,
            "decision_seq": self.decision_seq,
            "decision_ts_unix_ns": self.decision_ts_unix_ns,
            "allowed": self.allowed,
            "action": self.action,
            "required_action": self.required_action,
            "enforcement_mode": self.enforcement_mode,
            "primary_reason_code": self.primary_reason_code,
            "reason_codes": list(self.reason_codes),
            "degraded_reason_codes": list(self.degraded_reason_codes),
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "policy_digest": self.policy_digest,
            "route_plan_id": self.route_plan_id,
            "decision_id": self.decision_id,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "controller_mode": self.controller_mode,
            "guarantee_scope": self.guarantee_scope,
            "route": route_audit,
            "security": dict(self.security),
            "evidence_identity": dict(self.evidence_identity),
            "artifacts": dict(self.artifacts),
            "integrity_ok": self.integrity_ok,
            "integrity_errors": list(self.integrity_errors),
        }

    def to_public_view(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "allowed": self.allowed,
            "action": self.action,
            "required_action": self.required_action,
            "enforcement_mode": self.enforcement_mode,
            "primary_reason_code": self.primary_reason_code,
            "reason_codes": list(self.reason_codes),
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "route_plan_id": self.route_plan_id,
            "decision_id": self.decision_id,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "controller_mode": self.controller_mode,
            "statistical_guarantee_scope": self.guarantee_scope,
            "evidence_identity": dict(self.evidence_identity),
            "artifacts": dict(self.artifacts),
            "integrity_ok": self.integrity_ok,
        }

    def to_diagnose_out(self) -> Dict[str, Any]:
        return {
            "verdict": bool(self.allowed),
            "decision": self.action,
            "cause": self.reason,
            "action": self.action,
            "score": float(self.risk_score if self.risk_score is not None else 0.0),
            "threshold": 0.0,
            "budget_remaining": 0.0,
            "step": int(self.decision_seq),
            "e_value": 1.0,
            "alpha_alloc": 0.0,
            "alpha_spent": 0.0,
            "components": {},
            "route": self.route.to_dict() if self.route is not None and hasattr(self.route, "to_dict") else None,
            "e_state": self.e_state,
            "trust_zone": self.security.get("trust_zone"),
            "route_profile": self.security.get("route_profile"),
            "threat_kind": None,
            "threat_confidence": None,
            "pq_required": bool(self.security.get("pq_required", False)),
            "pq_ok": self.security.get("pq_ok"),
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "config_fingerprint": self.config_fingerprint,
            "bundle_version": self.bundle_version,
            "decision_id": self.decision_id,
            "route_plan_id": self.route_plan_id,
            "event_id": self.event_id,
            "audit_ref": self.audit_ref,
            "receipt_ref": self.receipt_ref,
            "controller_mode": self.controller_mode,
            "statistical_guarantee_scope": self.guarantee_scope,
            "security": dict(self.security),
            "receipt": dict(self.receipt or {}),
            "evidence_identity": dict(self.evidence_identity),
            "artifacts": dict(self.artifacts),
            "integrity_ok": self.integrity_ok,
            "integrity_errors": list(self.integrity_errors),
            "normalization_warnings": list(self.normalization_warnings),
            "compat_warnings": list(self.compat_warnings),
        }


# =============================================================================
# Internal models
# =============================================================================


@dataclass(frozen=True)
class _SyntheticRateDecision:
    zone: str
    allowed: bool
    reason: str
    retry_after_s: Optional[float] = None
    cfg_fp: Optional[str] = None
    decision_seq: Optional[int] = None
    bundle_version: Optional[int] = None
    zone_resolution: str = "resolved"
    requested_zone_hash: Optional[str] = None


@dataclass(frozen=True)
class _DetectorResult:
    risk_score: Optional[float] = None
    risk_label: Optional[str] = None
    action: Optional[str] = None
    trigger: bool = False
    reason: Optional[str] = None
    controller_mode: Optional[str] = None
    guarantee_scope: Optional[str] = None
    av_label: Optional[str] = None
    av_trigger: Optional[bool] = None
    threat_tags: Tuple[str, ...] = ()
    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None
    e_state: Optional[Dict[str, Any]] = None
    security: Dict[str, Any] = field(default_factory=dict)
    error: bool = False
    preview_only: bool = False


@dataclass(frozen=True)
class _PolicyEvaluation:
    bound_policy: Any
    bind_error: bool
    policy_ref: Optional[str]
    policyset_ref: Optional[str]
    policy_digest: str
    required_action: RequiredAction
    receipt_required: bool
    ledger_required: bool
    attestation_required: bool
    route_profile: str
    risk_label: str
    compliance_profile: Optional[str]
    patch_id: Optional[str]
    change_ticket_id: Optional[str]


@dataclass(frozen=True)
class _RateEvaluation:
    decisions: Dict[str, Any]
    error: bool
    required_action: RequiredAction
    reason_codes: Tuple[str, ...]


@dataclass(frozen=True)
class _AuthEvaluation:
    allowed: bool
    required_action: RequiredAction
    reason_code: str
    reason_text: str


@dataclass(frozen=True)
class _RouteEvaluation:
    route: Any
    degraded: bool
    unavailable: bool
    required_action: RequiredAction
    enforcement_mode: EnforcementMode
    reason_codes: Tuple[str, ...]


@dataclass(frozen=True)
class _EvaluationSnapshot:
    ctx: SecurityContext
    bundle: "_CompiledSecurityBundle"
    policy: _PolicyEvaluation
    auth: _AuthEvaluation
    rate: _RateEvaluation
    detector: _DetectorResult
    route_eval: _RouteEvaluation
    event_id: str
    decision_seq: int
    decision_ts_unix_ns: int
    decision_ts_mono_ns: int
    batch_id: Optional[str]


@dataclass(frozen=True)
class _CompiledSecurityBundle:
    version: int
    updated_at_unix_ns: int
    cfg_fp: str
    config: SecurityRouterConfig
    activation: SecurityBundleActivation
    identity_hasher: _IdentityHasher
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]


@dataclass(frozen=True)
class _SyntheticBoundPolicy:
    name: str = "policy_error"
    version: str = "1"
    policy_ref: str = "policy_error@1#ffffffffffff"
    priority: int = 10**9
    detector_cfg: Optional[Any] = None
    av_cfg: Optional[Any] = None
    t_low: Optional[float] = None
    t_high: Optional[float] = None
    top_p_low: Optional[float] = None
    top_p_high: Optional[float] = None
    fallback_decoder: Optional[str] = None
    action_hint: Optional[str] = "block"
    route_profile: Optional[str] = "restricted"
    enable_receipts: bool = True
    enable_verify_metrics: bool = True
    attach_policy_refs: bool = True
    attach_match_context: bool = False
    receipt_profile: Optional[str] = "reg_strict"
    receipt_crypto_profile: Optional[str] = None
    receipt_match_context_level: Optional[str] = "coarse"
    slo_latency_ms: Optional[float] = None
    token_cost_divisor: float = 50.0
    error_budget_fraction: Optional[float] = 0.0
    probe_sample_rate: Optional[float] = 1.0
    alpha_budget_fraction: Optional[float] = None
    e_stream: Optional[str] = None
    compliance_profile: Optional[str] = "strict"
    risk_label: Optional[str] = "critical"
    audit_label: Optional[str] = "restricted"
    audit_sample_rate: Optional[float] = 1.0
    audit_log_level: Optional[str] = "error"
    audit_incident_class: Optional[str] = "security"
    audit_force_on_violation: Optional[bool] = True
    audit_require_full_trace: Optional[bool] = True
    match: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({k: "*" for k in _CTX_KEYS}))
    policyset_ref: Optional[str] = None
    origin: Optional[str] = "security_router"
    policy_patch_id: Optional[str] = None
    commit_hash: Optional[str] = None
    change_ticket_id: Optional[str] = None
    decision: str = "deny"
    enforcement: Optional[str] = "block"


# =============================================================================
# Security Router
# =============================================================================


class SecurityRouter:
    """
    Platform-grade security router and evidence orchestrator.

    This module is intentionally content-agnostic. It accepts only:
      - normalized identity/auth context,
      - coarse policy binding context,
      - token/cost estimates,
      - detector/risk outputs,
      - route contracts,
      - receipt/audit/ledger sinks.

    Design properties:
      - immutable compiled config bundle + atomic swap
      - deterministic event identity
      - no detector state mutation on explain/preview paths
      - no silent fail-open on rate-limit dependency failures
      - synthetic route contract when route layer is unavailable
      - evidence identity block + artifact refs + integrity report
      - optional ledger prepare/commit + outbox fallback
    """

    def __init__(
        self,
        policy_store: PolicyStore,
        rate_limiter: RateLimiter,
        attestor: Optional[Attestor] = None,
        detector_runtime: Optional[TCDDetectorRuntime] = None,
        *,
        base_av: Optional[AlwaysValidConfig] = None,
        strategy_router: Optional[StrategyRouter] = None,
        audit_sink: Optional[SecurityAuditSink] = None,
        telemetry_sink: Optional[SecurityTelemetrySink] = None,
        ledger_sink: Optional[SecurityLedgerSink] = None,
        outbox_sink: Optional[SecurityOutboxSink] = None,
        authorizer: Optional[Callable[[Any, SecurityContext, SecurityAuthContext], Any]] = None,
        config: Optional[SecurityRouterConfig] = None,
    ) -> None:
        self._policies = policy_store
        self._limiter = rate_limiter
        self._attestor = attestor
        self._detector = detector_runtime
        self._base_av = base_av or AlwaysValidConfig()
        self._strategy_router = strategy_router
        self._audit_sink = audit_sink
        self._telemetry_sink = telemetry_sink
        self._ledger_sink = ledger_sink
        self._outbox_sink = outbox_sink
        self._authorizer = authorizer

        self._instance_id = os.urandom(8).hex()
        self._seq_lock = threading.Lock()
        self._decision_seq = 0
        self._bundle_lock = threading.RLock()

        init_cfg = (config or SecurityRouterConfig()).normalized_copy()
        bundle = self._compile_bundle(init_cfg, previous=None)
        if bundle.errors and init_cfg.on_config_error == "raise":
            raise ValueError("invalid SecurityRouterConfig: " + "; ".join(bundle.errors[:3]))

        self._bundle = bundle
        self._last_known_good: Optional[_CompiledSecurityBundle] = None if bundle.errors else bundle
        self._rejected_bundle: Optional[_CompiledSecurityBundle] = None
        self._using_last_known_good = False

    # ------------------------------------------------------------------
    # Public config API
    # ------------------------------------------------------------------

    @property
    def cfg_fp(self) -> str:
        return self._bundle.cfg_fp

    @property
    def bundle_version(self) -> int:
        return self._bundle.version

    @property
    def config(self) -> SecurityRouterConfig:
        return self._bundle.config.normalized_copy()

    def public_config_snapshot(self) -> SecurityPublicConfigView:
        bundle, router_mode, _ = self._bundle_snapshot()
        return SecurityPublicConfigView(
            cfg_fp=bundle.cfg_fp,
            bundle_version=bundle.version,
            bundle_updated_at_unix_ns=bundle.updated_at_unix_ns,
            activation_id=bundle.activation.activation_id,
            profile=bundle.config.profile,
            enabled=bundle.config.enabled,
            policy_ref=bundle.config.policy_ref,
            policyset_ref=bundle.config.policyset_ref,
            identity_hash_mode=bundle.identity_hasher.mode,
            identity_hash_key_id=bundle.identity_hasher.key_id,
            has_errors=bool(bundle.errors),
            has_warnings=bool(bundle.warnings),
            router_mode=router_mode,
        )

    def bundle_diagnostics(self) -> SecurityBundleDiagnostics:
        with self._bundle_lock:
            active = self._bundle
            lkg = self._last_known_good
            rejected = self._rejected_bundle
            return SecurityBundleDiagnostics(
                active_cfg_fp=active.cfg_fp,
                active_bundle_version=active.version,
                active_updated_at_unix_ns=active.updated_at_unix_ns,
                activation_id=active.activation.activation_id,
                profile=active.config.profile,
                enabled=active.config.enabled,
                policy_ref=active.config.policy_ref,
                policyset_ref=active.config.policyset_ref,
                identity_hash_mode=active.identity_hasher.mode,
                identity_hash_key_id=active.identity_hasher.key_id,
                errors=active.errors,
                warnings=active.warnings,
                using_last_known_good=bool(self._using_last_known_good),
                last_known_good_cfg_fp=lkg.cfg_fp if lkg is not None else None,
                last_rejected_cfg_fp=rejected.cfg_fp if rejected is not None else None,
            )

    def diagnostics(self) -> Dict[str, Any]:
        d = self.bundle_diagnostics()
        return {
            "schema": _SCHEMA,
            "router": _ROUTER_NAME,
            "version": _ROUTER_VERSION,
            "instance_id": self._instance_id,
            "cfg_fp": d.active_cfg_fp,
            "bundle_version": d.active_bundle_version,
            "bundle_updated_at_unix_ns": d.active_updated_at_unix_ns,
            "activation_id": d.activation_id,
            "profile": d.profile,
            "enabled": d.enabled,
            "policy_ref": d.policy_ref,
            "policyset_ref": d.policyset_ref,
            "identity_hash_mode": d.identity_hash_mode,
            "identity_hash_key_id": d.identity_hash_key_id,
            "using_last_known_good": d.using_last_known_good,
            "last_known_good_cfg_fp": d.last_known_good_cfg_fp,
            "last_rejected_cfg_fp": d.last_rejected_cfg_fp,
            "error_count": len(d.errors),
            "warning_count": len(d.warnings),
            "errors": list(d.errors[:50]),
            "warnings": list(d.warnings[:50]),
        }

    def set_config(self, config: SecurityRouterConfig) -> None:
        cfg = config.normalized_copy()
        with self._bundle_lock:
            previous = self._bundle
            new_bundle = self._compile_bundle(cfg, previous=previous)
            if new_bundle.errors and cfg.on_config_error == "raise":
                raise ValueError("invalid SecurityRouterConfig: " + "; ".join(new_bundle.errors[:3]))

            if new_bundle.errors and cfg.on_config_error == "use_last_known_good" and self._last_known_good is not None:
                self._rejected_bundle = new_bundle
                self._using_last_known_good = True
                return

            self._bundle = new_bundle
            self._using_last_known_good = False
            self._rejected_bundle = new_bundle if new_bundle.errors else None
            if not new_bundle.errors:
                self._last_known_good = new_bundle

    # ------------------------------------------------------------------
    # Public decision API
    # ------------------------------------------------------------------

    def route(self, sctx: SecurityContext) -> SecurityDecision:
        bundle, router_mode, degraded_codes = self._bundle_snapshot()
        return self._route_internal(
            sctx=sctx,
            bundle=bundle,
            router_mode=router_mode,
            degraded_reason_codes=degraded_codes,
            batch_id=None,
            execute=True,
        )

    def route_many(self, contexts: Sequence[SecurityContext]) -> Tuple[SecurityDecision, ...]:
        bundle, router_mode, degraded_codes = self._bundle_snapshot()
        batch_ts = time.time_ns()
        batch_id = f"sb1:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:security:batch', payload={'cfg_fp': bundle.cfg_fp, 'bundle_version': bundle.version, 'ts_ns': batch_ts}, out_hex=24)}"
        out: List[SecurityDecision] = []
        for sctx in contexts:
            out.append(
                self._route_internal(
                    sctx=sctx,
                    bundle=bundle,
                    router_mode=router_mode,
                    degraded_reason_codes=degraded_codes,
                    batch_id=batch_id,
                    execute=True,
                )
            )
        return tuple(out)

    def route_explain(self, sctx: SecurityContext) -> Dict[str, Any]:
        bundle, router_mode, degraded_codes = self._bundle_snapshot()
        normalized = sctx.normalized(
            allowed_context_keys=bundle.config.allowed_context_keys,
            allowed_meta_keys=bundle.config.allowed_meta_keys,
            max_context_items=bundle.config.max_context_items,
            max_context_value_len=bundle.config.max_context_value_len,
            max_meta_items=bundle.config.max_meta_items,
            max_meta_value_len=bundle.config.max_meta_value_len,
        )
        decision_seq = self._next_decision_seq()
        decision_ts_unix_ns = time.time_ns()
        decision_ts_mono_ns = time.monotonic_ns()
        event_id = self._derive_event_id(normalized, decision_ts_unix_ns, decision_seq, bundle)

        snap = self._evaluate(
            ctx=normalized,
            bundle=bundle,
            decision_seq=decision_seq,
            decision_ts_unix_ns=decision_ts_unix_ns,
            decision_ts_mono_ns=decision_ts_mono_ns,
            event_id=event_id,
            batch_id=None,
            execute=False,
        )
        return {
            "schema": _SCHEMA,
            "router": _ROUTER_NAME,
            "version": _ROUTER_VERSION,
            "instance_id": self._instance_id,
            "activation_id": bundle.activation.activation_id,
            "config_fingerprint": bundle.cfg_fp,
            "bundle_version": bundle.version,
            "router_mode": router_mode,
            "degraded_reason_codes": list(degraded_codes),
            "normalization_warnings": list(normalized.normalization_warnings),
            "policy": {
                "policy_ref": snap.policy.policy_ref,
                "policyset_ref": snap.policy.policyset_ref,
                "policy_digest": snap.policy.policy_digest,
                "required_action": snap.policy.required_action,
                "receipt_required": snap.policy.receipt_required,
                "ledger_required": snap.policy.ledger_required,
                "attestation_required": snap.policy.attestation_required,
                "route_profile": snap.policy.route_profile,
                "risk_label": snap.policy.risk_label,
                "bind_error": snap.policy.bind_error,
            },
            "auth": {
                "allowed": snap.auth.allowed,
                "required_action": snap.auth.required_action,
                "reason_code": snap.auth.reason_code,
                "reason_text": snap.auth.reason_text,
            },
            "rate": {
                "required_action": snap.rate.required_action,
                "reason_codes": list(snap.rate.reason_codes),
                "decisions": {
                    k: {
                        "zone": getattr(v, "zone", None),
                        "allowed": getattr(v, "allowed", None),
                        "reason": getattr(v, "reason", None),
                        "retry_after_s": getattr(v, "retry_after_s", None),
                    }
                    for k, v in snap.rate.decisions.items()
                },
                "error": snap.rate.error,
            },
            "detector": {
                "risk_score": snap.detector.risk_score,
                "risk_label": snap.detector.risk_label,
                "action": snap.detector.action,
                "trigger": snap.detector.trigger,
                "reason": snap.detector.reason,
                "controller_mode": snap.detector.controller_mode,
                "guarantee_scope": snap.detector.guarantee_scope,
                "av_label": snap.detector.av_label,
                "av_trigger": snap.detector.av_trigger,
                "threat_tags": list(snap.detector.threat_tags),
                "preview_only": snap.detector.preview_only,
                "error": snap.detector.error,
            },
            "route": snap.route_eval.route.to_dict() if snap.route_eval.route is not None and hasattr(snap.route_eval.route, "to_dict") else None,
            "synthetic_route": bool(snap.route_eval.unavailable),
            "event_id": event_id,
            "decision_seq": decision_seq,
            "decision_ts_unix_ns": decision_ts_unix_ns,
            "decision_ts_mono_ns": decision_ts_mono_ns,
            "state_mutation": False,
            "receipt_issued": False,
            "audit_emitted": False,
        }

    # ------------------------------------------------------------------
    # Bundle compilation / selection
    # ------------------------------------------------------------------

    def _bundle_snapshot(self) -> Tuple[_CompiledSecurityBundle, RouterMode, Tuple[str, ...]]:
        with self._bundle_lock:
            bundle = self._bundle
            if not bundle.config.enabled:
                return bundle, "disabled", tuple()
            if self._using_last_known_good:
                return bundle, "last_known_good", ("CFG_ERROR_LKG",)
            if bundle.errors:
                return bundle, "fail_closed", ("CFG_ERROR",)
            if bundle.warnings:
                return bundle, "degraded", tuple()
            return bundle, "normal", tuple()

    def _compile_bundle(
        self,
        config: SecurityRouterConfig,
        *,
        previous: Optional[_CompiledSecurityBundle],
    ) -> _CompiledSecurityBundle:
        cfg = config.normalized_copy()
        errors: List[str] = []
        warnings: List[str] = []

        key_material = _parse_key_material(cfg.identity_hash_key_material)
        key_mode = "none"
        key_id = cfg.identity_hash_key_id
        if key_material is not None:
            if len(key_material) < cfg.min_identity_key_bytes:
                errors.append("identity_hash_key_too_short")
                key_material = None
            else:
                key_mode = "configured"
        elif cfg.auto_ephemeral_identity_key_if_missing:
            try:
                key_material = os.urandom(max(16, cfg.min_identity_key_bytes))
                key_mode = "ephemeral"
            except Exception:
                key_material = None
                warnings.append("identity_hash_ephemeral_key_generation_failed")

        if cfg.profile in {"FINREG", "LOCKDOWN"} and key_material is None:
            errors.append("identity_hash_key_required")

        if key_id is None and key_mode in {"configured", "ephemeral"}:
            key_id = "ephem" if key_mode == "ephemeral" else "cfg"

        hasher = _IdentityHasher(key=key_material, key_id=key_id, mode=key_mode)

        cfg_fp = cfg.fingerprint()
        updated_at_unix_ns = time.time_ns()
        version = 1 if previous is None else previous.version + 1
        activation_payload = {
            "cfg_fp": cfg_fp,
            "bundle_version": version,
            "ts_ns": updated_at_unix_ns,
            "policy_ref": cfg.policy_ref,
            "policyset_ref": cfg.policyset_ref,
            "patch_id": cfg.patch_id,
            "change_ticket_id": cfg.change_ticket_id,
        }
        activation_id = f"{_ACTIVATION_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:security:activation', payload=activation_payload, out_hex=24)}"
        activation = SecurityBundleActivation(
            activation_id=activation_id,
            cfg_fp=cfg_fp,
            bundle_version=version,
            policy_ref=cfg.policy_ref,
            policyset_ref=cfg.policyset_ref,
            patch_id=cfg.patch_id,
            change_ticket_id=cfg.change_ticket_id,
            activated_by=cfg.activated_by,
            approved_by=cfg.approved_by,
            activated_at_unix_ns=updated_at_unix_ns,
            previous_cfg_fp=(previous.cfg_fp if previous is not None else None),
            activation_mode="normal" if not errors else ("last_known_good" if cfg.on_config_error == "use_last_known_good" else "fail_closed"),
        )
        return _CompiledSecurityBundle(
            version=version,
            updated_at_unix_ns=updated_at_unix_ns,
            cfg_fp=cfg_fp,
            config=cfg,
            activation=activation,
            identity_hasher=hasher,
            errors=tuple(errors),
            warnings=tuple(warnings),
        )

    # ------------------------------------------------------------------
    # Core routing
    # ------------------------------------------------------------------

    def _route_internal(
        self,
        *,
        sctx: SecurityContext,
        bundle: _CompiledSecurityBundle,
        router_mode: RouterMode,
        degraded_reason_codes: Tuple[str, ...],
        batch_id: Optional[str],
        execute: bool,
    ) -> SecurityDecision:
        normalized = sctx.normalized(
            allowed_context_keys=bundle.config.allowed_context_keys,
            allowed_meta_keys=bundle.config.allowed_meta_keys,
            max_context_items=bundle.config.max_context_items,
            max_context_value_len=bundle.config.max_context_value_len,
            max_meta_items=bundle.config.max_meta_items,
            max_meta_value_len=bundle.config.max_meta_value_len,
        )

        decision_seq = self._next_decision_seq()
        decision_ts_unix_ns = time.time_ns()
        decision_ts_mono_ns = time.monotonic_ns()
        event_id = self._derive_event_id(normalized, decision_ts_unix_ns, decision_seq, bundle)

        snap = self._evaluate(
            ctx=normalized,
            bundle=bundle,
            decision_seq=decision_seq,
            decision_ts_unix_ns=decision_ts_unix_ns,
            decision_ts_mono_ns=decision_ts_mono_ns,
            event_id=event_id,
            batch_id=batch_id,
            execute=execute,
        )

        decision = self._compose_decision(snap, router_mode=router_mode, degraded_reason_codes=degraded_reason_codes)

        decision = self._finalize_with_artifacts(decision, snap)
        decision = self._finalize_integrity(decision, snap)

        return decision

    def _evaluate(
        self,
        *,
        ctx: SecurityContext,
        bundle: _CompiledSecurityBundle,
        decision_seq: int,
        decision_ts_unix_ns: int,
        decision_ts_mono_ns: int,
        event_id: str,
        batch_id: Optional[str],
        execute: bool,
    ) -> _EvaluationSnapshot:
        policy = self._evaluate_policy(ctx, bundle)
        auth = self._evaluate_auth(ctx, bundle, policy)
        rate = self._evaluate_rate_limits(ctx, bundle, policy, decision_seq, decision_ts_unix_ns, decision_ts_mono_ns)
        detector = self._evaluate_detector(ctx, bundle, policy, execute=execute)
        route_eval = self._evaluate_route(
            ctx=ctx,
            bundle=bundle,
            policy=policy,
            detector=detector,
            auth=auth,
            rate=rate,
            event_id=event_id,
            decision_seq=decision_seq,
            decision_ts_unix_ns=decision_ts_unix_ns,
            decision_ts_mono_ns=decision_ts_mono_ns,
        )
        return _EvaluationSnapshot(
            ctx=ctx,
            bundle=bundle,
            policy=policy,
            auth=auth,
            rate=rate,
            detector=detector,
            route_eval=route_eval,
            event_id=event_id,
            decision_seq=decision_seq,
            decision_ts_unix_ns=decision_ts_unix_ns,
            decision_ts_mono_ns=decision_ts_mono_ns,
            batch_id=batch_id,
        )

    # ------------------------------------------------------------------
    # Evaluation: policy / auth / rate / detector / route
    # ------------------------------------------------------------------

    def _evaluate_policy(self, ctx: SecurityContext, bundle: _CompiledSecurityBundle) -> _PolicyEvaluation:
        try:
            bp = self._policies.bind(ctx.binding_context())
            bind_error = False
        except Exception:
            bp = _SyntheticBoundPolicy(policyset_ref=_policyset_ref(self._policies))
            bind_error = True

        policy_ref = _safe_id(getattr(bp, "policy_ref", None), default=None, max_len=128)
        policyset_ref = _safe_id(getattr(bp, "policyset_ref", None), default=None, max_len=128) or _policyset_ref(self._policies)
        policy_digest = _policy_digest(bp, policyset_ref=policyset_ref)

        required_action = self._policy_required_action(bp)
        route_profile = self._policy_route_profile(bp, ctx)
        risk_label = self._policy_risk_label(bp)
        compliance_profile = _safe_label(getattr(bp, "compliance_profile", None), default="") or None

        receipt_required = bool(getattr(bp, "enable_receipts", False))
        ledger_required = bool(getattr(bp, "audit_require_full_trace", False))
        attestation_required = bool(getattr(bp, "audit_require_full_trace", False))

        if bundle.config.receipt_required_on_deny and required_action == "block":
            receipt_required = True
        if bundle.config.ledger_required_on_deny and required_action == "block":
            ledger_required = True
        if bundle.config.attestation_required_on_deny and required_action == "block":
            attestation_required = True

        return _PolicyEvaluation(
            bound_policy=bp,
            bind_error=bind_error,
            policy_ref=policy_ref,
            policyset_ref=policyset_ref,
            policy_digest=policy_digest,
            required_action=required_action,
            receipt_required=receipt_required,
            ledger_required=ledger_required,
            attestation_required=attestation_required,
            route_profile=route_profile,
            risk_label=risk_label,
            compliance_profile=compliance_profile,
            patch_id=_safe_id(getattr(bp, "policy_patch_id", None), default=None, max_len=128),
            change_ticket_id=_safe_id(getattr(bp, "change_ticket_id", None), default=None, max_len=128),
        )

    def _policy_required_action(self, bp: Any) -> RequiredAction:
        decision = _safe_label(getattr(bp, "decision", None), default="inherit")
        enforcement = _safe_label(getattr(bp, "enforcement", None), default="")
        action_hint = _safe_label(getattr(bp, "action_hint", None), default="")

        if decision in {"deny", "block"} or enforcement in {"block", "deny", "fail_closed"}:
            return "block"
        if decision == "degrade" or action_hint == "degrade":
            return "degrade"
        return "allow"

    def _policy_route_profile(self, bp: Any, ctx: SecurityContext) -> str:
        prof = _safe_label(getattr(bp, "route_profile", None), default="")
        if prof and prof in _ALLOWED_ROUTE_PROFILES:
            return prof
        if ctx.route_profile in _ALLOWED_ROUTE_PROFILES:
            return ctx.route_profile
        if ctx.kind in _ALLOWED_ROUTE_PROFILES:
            return ctx.kind
        return "inference"

    def _policy_risk_label(self, bp: Any) -> str:
        rl = _safe_label(getattr(bp, "risk_label", None), default="")
        if rl in {"low", "normal", "elevated", "high", "critical"}:
            return rl
        comp = _safe_label(getattr(bp, "compliance_profile", None), default="")
        if comp in {"strict", "high"}:
            return "critical"
        return "normal"

    def _evaluate_auth(self, ctx: SecurityContext, bundle: _CompiledSecurityBundle, policy: _PolicyEvaluation) -> _AuthEvaluation:
        auth_ctx = ctx.auth_context or SecurityAuthContext().normalized()
        route_profile = policy.route_profile
        kind = ctx.kind

        if self._authorizer is not None:
            try:
                out = self._authorizer(policy.bound_policy, ctx, auth_ctx)
                if isinstance(out, tuple) and len(out) == 2:
                    ok = bool(out[0])
                    code = _strip_unsafe_text(out[1], max_len=64).upper() or "AUTHZ_DENY"
                    if code not in _ALLOWED_REASON_CODES:
                        code = "AUTHZ_DENY"
                    return _AuthEvaluation(
                        allowed=ok,
                        required_action="allow" if ok else "block",
                        reason_code=("DEFAULT_ALLOW" if ok else code),
                        reason_text=("authorized" if ok else "authorization denied"),
                    )
                if isinstance(out, Mapping):
                    ok = bool(out.get("allowed", False))
                    raw_code = _strip_unsafe_text(out.get("reason_code", ""), max_len=64).upper()
                    code = raw_code if raw_code in _ALLOWED_REASON_CODES else "AUTHZ_DENY"
                    return _AuthEvaluation(
                        allowed=ok,
                        required_action="allow" if ok else "block",
                        reason_code=("DEFAULT_ALLOW" if ok else code),
                        reason_text=_strip_unsafe_text(out.get("reason", "authorization denied"), max_len=128),
                    )
                ok2 = bool(out)
                return _AuthEvaluation(
                    allowed=ok2,
                    required_action="allow" if ok2 else "block",
                    reason_code=("DEFAULT_ALLOW" if ok2 else "AUTHZ_DENY"),
                    reason_text=("authorized" if ok2 else "authorization denied"),
                )
            except Exception:
                return _AuthEvaluation(
                    allowed=False,
                    required_action="block",
                    reason_code="AUTHZ_DENY",
                    reason_text="authorizer error",
                )

        if route_profile not in bundle.config.sensitive_route_profiles and kind not in {"admin", "control"}:
            return _AuthEvaluation(
                allowed=True,
                required_action="allow",
                reason_code="DEFAULT_ALLOW",
                reason_text="non-sensitive route",
            )

        if auth_ctx.principal_id is None:
            return _AuthEvaluation(
                allowed=False,
                required_action="block",
                reason_code="AUTH_CONTEXT_MISSING",
                reason_text="sensitive route requires auth context",
            )

        if bundle.config.require_trusted_auth_context_for_sensitive and not auth_ctx.trusted:
            return _AuthEvaluation(
                allowed=False,
                required_action="block",
                reason_code="AUTH_CONTEXT_UNTRUSTED",
                reason_text="sensitive route requires trusted auth context",
            )

        role_set = set(auth_ctx.roles)
        scope_set = set(auth_ctx.scopes)

        if role_set.intersection(bundle.config.allowed_sensitive_roles):
            return _AuthEvaluation(True, "allow", "DEFAULT_ALLOW", "role-authorized")
        if scope_set.intersection(bundle.config.allowed_sensitive_scopes):
            return _AuthEvaluation(True, "allow", "DEFAULT_ALLOW", "scope-authorized")
        if (
            bundle.config.allow_internal_principal_for_sensitive
            and ctx.trust_zone in {"internal", "admin", "ops"}
            and auth_ctx.principal_id is not None
        ):
            return _AuthEvaluation(True, "allow", "DEFAULT_ALLOW", "internal principal allowed")

        return _AuthEvaluation(
            allowed=False,
            required_action="block",
            reason_code="AUTHZ_DENY",
            reason_text="sensitive route denied",
        )

    def _evaluate_rate_limits(
        self,
        ctx: SecurityContext,
        bundle: _CompiledSecurityBundle,
        policy: _PolicyEvaluation,
        decision_seq: int,
        decision_ts_unix_ns: int,
        decision_ts_mono_ns: int,
    ) -> _RateEvaluation:
        cost = self._compute_cost(policy.bound_policy, ctx)
        decisions: Dict[str, Any] = {}
        reason_codes: List[str] = []
        required_action: RequiredAction = "allow"
        error = False

        def _synth(zone: str, reason: str, action: RequiredAction) -> _SyntheticRateDecision:
            nonlocal required_action, error
            error = True
            required_action = _action_max(required_action, action)
            return _SyntheticRateDecision(
                zone=zone,
                allowed=(action == "allow"),
                reason=reason,
                retry_after_s=None,
                cfg_fp=bundle.cfg_fp,
                decision_seq=decision_seq,
                bundle_version=bundle.version,
                zone_resolution="error",
                requested_zone_hash=None,
            )

        if ctx.ip:
            zone = self._choose_zone_for_ip(policy.bound_policy, ctx)
            try:
                decisions["ip"] = self._consume_rate(zone=zone, key=self._rate_key_ip(ctx), cost=1.0)
            except Exception:
                decisions["ip"] = _synth(zone, "dependency_error", bundle.config.rate_error_action)
                reason_codes.append("RATE_DEPENDENCY_ERROR")

        tenant = ctx.binding_context().get("tenant") or ctx.tenant_id or "*"
        zone_tenant = self._choose_zone_for_tenant(policy.bound_policy, ctx)
        try:
            decisions["tenant"] = self._consume_rate(
                zone=zone_tenant,
                key=self._rate_key_tenant(tenant, ctx),
                cost=cost,
            )
        except Exception:
            decisions["tenant"] = _synth(zone_tenant, "dependency_error", bundle.config.rate_error_action)
            reason_codes.append("RATE_DEPENDENCY_ERROR")

        zone_um = self._choose_zone_for_user_model(policy.bound_policy, ctx)
        try:
            decisions["user_model"] = self._consume_rate(
                zone=zone_um,
                key=self._rate_key_user_model(ctx, tenant),
                cost=cost,
            )
        except Exception:
            decisions["user_model"] = _synth(zone_um, "dependency_error", bundle.config.rate_error_action)
            reason_codes.append("RATE_DEPENDENCY_ERROR")

        zone_pol = self._choose_zone_for_policy(policy.bound_policy, ctx)
        try:
            decisions["policy"] = self._consume_rate(
                zone=zone_pol,
                key=self._rate_key_policy(ctx, policy.policy_ref or "default"),
                cost=max(1.0, cost),
            )
        except Exception:
            decisions["policy"] = _synth(zone_pol, "dependency_error", bundle.config.rate_error_action)
            reason_codes.append("RATE_DEPENDENCY_ERROR")

        if self._denied(decisions.get("ip")):
            reason_codes.append("RATE_IP_DENY")
            required_action = _action_max(required_action, "block")
        if self._denied(decisions.get("tenant")):
            reason_codes.append("RATE_TENANT_DENY")
            required_action = _action_max(required_action, "block")
        if self._denied(decisions.get("user_model")):
            reason_codes.append("RATE_USER_MODEL_DENY")
            required_action = _action_max(required_action, "block")
        if self._denied(decisions.get("policy")):
            reason_codes.append("RATE_POLICY_DENY")
            required_action = _action_max(required_action, "block")

        return _RateEvaluation(
            decisions=decisions,
            error=error,
            required_action=required_action,
            reason_codes=_normalize_reason_codes(reason_codes, max_items=32),
        )

    def _consume_rate(self, *, zone: str, key: Any, cost: float) -> Any:
        return self._limiter.consume_decision(key=key, cost=cost, zone=zone)

    def _rate_key_ip(self, ctx: SecurityContext) -> Any:
        if ctx.ip is None:
            return None
        return ctx.ip

    def _rate_key_tenant(self, tenant: str, ctx: SecurityContext) -> Any:
        try:
            return RateKey(
                tenant_id=tenant,
                principal_id=ctx.principal_id or "*",
                subject_id=_subject_digest(ctx.subject_id(), self._bundle.identity_hasher),
                session_id=_safe_id(getattr(ctx.subject, "session", None), default=None, max_len=128),
                resource_id="tenant",
                route_id=ctx.route_profile,
            )
        except Exception:
            return (tenant,)

    def _rate_key_user_model(self, ctx: SecurityContext, tenant: str) -> Any:
        model_id = ctx.binding_context().get("model_id") or _safe_id(getattr(ctx.subject, "model_id", None), default=None, max_len=128) or "*"
        try:
            return RateKey(
                tenant_id=tenant,
                principal_id=ctx.principal_id or "*",
                subject_id=_subject_digest(ctx.subject_id(), self._bundle.identity_hasher),
                session_id=_safe_id(getattr(ctx.subject, "session", None), default=None, max_len=128),
                resource_id=model_id,
                route_id=ctx.route_profile,
            )
        except Exception:
            return (tenant, ctx.principal_id or "*", model_id)

    def _rate_key_policy(self, ctx: SecurityContext, policy_ref: str) -> Any:
        tenant = ctx.binding_context().get("tenant") or ctx.tenant_id or "*"
        try:
            return RateKey(
                tenant_id=tenant,
                principal_id=ctx.principal_id or "*",
                subject_id=_subject_digest(ctx.subject_id(), self._bundle.identity_hasher),
                session_id=_safe_id(getattr(ctx.subject, "session", None), default=None, max_len=128),
                resource_id=policy_ref,
                route_id=ctx.kind,
            )
        except Exception:
            return (tenant, policy_ref, ctx.kind)

    def _evaluate_detector(
        self,
        ctx: SecurityContext,
        bundle: _CompiledSecurityBundle,
        policy: _PolicyEvaluation,
        *,
        execute: bool,
    ) -> _DetectorResult:
        if self._detector is None:
            return _DetectorResult(risk_label=policy.risk_label, trigger=False, preview_only=not execute)

        if execute:
            method_names = ("evaluate", "execute", "update_security", "update", "step")
        else:
            method_names = ("preview", "evaluate_preview", "preview_security", "explain_preview")
            if bundle.config.strict_preview_requires_preview_method and bundle.config.profile in {"FINREG", "LOCKDOWN"}:
                pass

        fn = None
        for name in method_names:
            candidate = getattr(self._detector, name, None)
            if callable(candidate):
                fn = candidate
                break

        if fn is None:
            if execute:
                return _DetectorResult(
                    risk_label=policy.risk_label,
                    trigger=False,
                    error=True,
                    reason="detector_method_missing",
                    action=bundle.config.detector_error_action,
                    controller_mode="detector_unavailable",
                )
            return _DetectorResult(
                risk_label=policy.risk_label,
                trigger=False,
                preview_only=True,
                error=True,
                reason="preview_unavailable",
                controller_mode="preview_unavailable",
            )

        try:
            out = fn(ctx, policy.bound_policy)
        except TypeError as e:
            if execute:
                return _DetectorResult(
                    risk_label=policy.risk_label,
                    trigger=False,
                    error=True,
                    reason="detector_bad_signature",
                    action=bundle.config.detector_error_action,
                    controller_mode="detector_bad_signature",
                )
            return _DetectorResult(
                risk_label=policy.risk_label,
                trigger=False,
                preview_only=True,
                error=True,
                reason=f"preview_bad_signature:{_safe_name(type(e).__name__, default='TypeError')}",
                controller_mode="preview_unavailable",
            )
        except Exception:
            if execute:
                return _DetectorResult(
                    risk_label=policy.risk_label,
                    trigger=False,
                    error=True,
                    reason="detector_error",
                    action=bundle.config.detector_error_action,
                    controller_mode="detector_error",
                )
            return _DetectorResult(
                risk_label=policy.risk_label,
                trigger=False,
                preview_only=True,
                error=True,
                reason="preview_error",
                controller_mode="preview_error",
            )

        det = self._coerce_detector_output(out, policy.risk_label)
        if not execute:
            det = _DetectorResult(
                risk_score=det.risk_score,
                risk_label=det.risk_label,
                action=det.action,
                trigger=det.trigger,
                reason=det.reason,
                controller_mode=det.controller_mode,
                guarantee_scope=det.guarantee_scope,
                av_label=det.av_label,
                av_trigger=det.av_trigger,
                threat_tags=det.threat_tags,
                audit_ref=None,
                receipt_ref=None,
                e_state=det.e_state,
                security=det.security,
                error=det.error,
                preview_only=True,
            )
        return self._apply_detector_signal_policy(det, ctx.signal_envelope or SecuritySignalEnvelope(), bundle)

    def _coerce_detector_output(self, out: Any, fallback_risk_label: str) -> _DetectorResult:
        if out is None:
            return _DetectorResult(risk_label=fallback_risk_label, trigger=False)

        if isinstance(out, tuple):
            if len(out) == 2:
                score = _safe_score(out[0]) if out[0] is not None else None
                return _DetectorResult(risk_score=score, risk_label=fallback_risk_label, trigger=bool(out[1]))
            if len(out) >= 3:
                score = _safe_score(out[0]) if out[0] is not None else None
                mode = _safe_label(out[2], default="") if isinstance(out[2], str) else ""
                return _DetectorResult(
                    risk_score=score,
                    risk_label=fallback_risk_label,
                    trigger=bool(out[1]),
                    controller_mode=(mode or None),
                )

        if isinstance(out, (int, float)) and not isinstance(out, bool):
            return _DetectorResult(
                risk_score=_safe_score(out),
                risk_label=fallback_risk_label,
                trigger=False,
            )

        if isinstance(out, Mapping):
            e_state = out.get("e_state")
            security = out.get("security") if isinstance(out.get("security"), Mapping) else {}
            ctrl = e_state.get("controller") if isinstance(e_state, Mapping) and isinstance(e_state.get("controller"), Mapping) else {}
            validity = e_state.get("validity") if isinstance(e_state, Mapping) and isinstance(e_state.get("validity"), Mapping) else {}

            risk_score = _coerce_float(out.get("score"))
            if risk_score is None:
                risk_score = _coerce_float(out.get("risk_score"))
            risk_label = _safe_label(out.get("risk_label"), default="") if isinstance(out.get("risk_label"), str) else ""
            if not risk_label and isinstance(security, Mapping):
                risk_label = _safe_label(security.get("risk_label"), default="")

            guarantee_scope = None
            for candidate in (
                out.get("guarantee_scope"),
                out.get("statistical_guarantee_scope"),
                security.get("statistical_guarantee_scope") if isinstance(security, Mapping) else None,
                validity.get("statistical_guarantee_scope") if isinstance(validity, Mapping) else None,
            ):
                if isinstance(candidate, str):
                    guarantee_scope = _safe_label(candidate, default="") or None
                    if guarantee_scope:
                        break

            controller_mode = None
            for candidate in (
                out.get("controller_mode"),
                ctrl.get("controller_mode") if isinstance(ctrl, Mapping) else None,
            ):
                if isinstance(candidate, str):
                    controller_mode = _safe_label(candidate, default="") or None
                    if controller_mode:
                        break

            av_label = None
            for candidate in (
                out.get("av_label"),
                security.get("av_label") if isinstance(security, Mapping) else None,
                ctrl.get("label") if isinstance(ctrl, Mapping) else None,
            ):
                if isinstance(candidate, str):
                    av_label = _safe_label(candidate, default="") or None
                    if av_label:
                        break

            action = None
            if isinstance(out.get("action"), str):
                a = _safe_label(out.get("action"), default="")
                if a in {"allow", "block", "degrade", "advisory", "degraded_allow", "degraded_block", "deny"}:
                    action = a

            trigger = _coerce_bool(out.get("e_triggered"), default=False)
            if not trigger:
                trigger = _coerce_bool(out.get("trigger"), default=False)
            if not trigger and isinstance(security, Mapping):
                trigger = _coerce_bool(security.get("trigger"), default=False)

            threat_tags: Tuple[str, ...] = ()
            raw_tags = out.get("threat_tags")
            if isinstance(raw_tags, (list, tuple)):
                tags: List[str] = []
                for item in raw_tags[:8]:
                    s = _safe_label(item, default="")
                    if s:
                        tags.append(s)
                threat_tags = tuple(sorted(set(tags)))

            return _DetectorResult(
                risk_score=_safe_score(risk_score) if risk_score is not None else None,
                risk_label=risk_label or fallback_risk_label,
                action=action,
                trigger=bool(trigger),
                reason=_safe_label(out.get("reason"), default="") or None if isinstance(out.get("reason"), str) else None,
                controller_mode=controller_mode,
                guarantee_scope=guarantee_scope,
                av_label=av_label,
                av_trigger=_coerce_bool(out.get("av_trigger"), default=False) if out.get("av_trigger") is not None else None,
                threat_tags=threat_tags,
                audit_ref=_safe_id(out.get("audit_ref"), default=None, max_len=256),
                receipt_ref=_safe_id(out.get("receipt_ref"), default=None, max_len=256),
                e_state=dict(e_state) if isinstance(e_state, Mapping) else None,
                security=dict(security) if isinstance(security, Mapping) else {},
                error=False,
            )

        return _DetectorResult(risk_label=fallback_risk_label, trigger=False)

    def _apply_detector_signal_policy(
        self,
        det: _DetectorResult,
        env: SecuritySignalEnvelope,
        bundle: _CompiledSecurityBundle,
    ) -> _DetectorResult:
        envn = env.normalized()
        degraded_reason: Optional[str] = None

        if bundle.config.max_signal_freshness_ms is not None and envn.freshness_ms is not None:
            if envn.freshness_ms > bundle.config.max_signal_freshness_ms:
                if det.action in {"block", "deny"} or det.trigger:
                    degraded_reason = "DETECTOR_SIGNAL_STALE"

        if bundle.config.require_signed_signal_for_block and (det.action in {"block", "deny"} or det.trigger):
            if not envn.signed:
                degraded_reason = degraded_reason or "DETECTOR_SIGNAL_UNSIGNED"

        if bundle.config.require_trusted_signal_for_block and (det.action in {"block", "deny"} or det.trigger):
            if not envn.trusted:
                degraded_reason = degraded_reason or "DETECTOR_SIGNAL_UNTRUSTED"

        if degraded_reason is None:
            return det

        new_action: Optional[str]
        if det.action in {"block", "deny"}:
            new_action = "degrade"
        elif det.trigger:
            new_action = "degrade"
        else:
            new_action = det.action

        return _DetectorResult(
            risk_score=det.risk_score,
            risk_label=det.risk_label,
            action=new_action,
            trigger=False,
            reason=degraded_reason,
            controller_mode=det.controller_mode,
            guarantee_scope=det.guarantee_scope,
            av_label=det.av_label,
            av_trigger=det.av_trigger,
            threat_tags=det.threat_tags,
            audit_ref=det.audit_ref,
            receipt_ref=det.receipt_ref,
            e_state=det.e_state,
            security=det.security,
            error=det.error,
            preview_only=det.preview_only,
        )

    def _evaluate_route(
        self,
        *,
        ctx: SecurityContext,
        bundle: _CompiledSecurityBundle,
        policy: _PolicyEvaluation,
        detector: _DetectorResult,
        auth: _AuthEvaluation,
        rate: _RateEvaluation,
        event_id: str,
        decision_seq: int,
        decision_ts_unix_ns: int,
        decision_ts_mono_ns: int,
    ) -> _RouteEvaluation:
        prior_action = _action_max(
            policy.required_action,
            _action_max(auth.required_action, rate.required_action),
        )
        if detector.action in {"block", "deny"} or detector.trigger:
            prior_action = _action_max(prior_action, "block")
        elif detector.action in {"degrade", "advisory"}:
            prior_action = _action_max(prior_action, "degrade")

        raw_route: Optional[Any] = None
        degraded = False
        unavailable = False
        reason_codes: List[str] = []
        if self._strategy_router is not None:
            try:
                raw_route = self._invoke_strategy_router(
                    ctx=ctx,
                    bundle=bundle,
                    policy=policy,
                    detector=detector,
                    prior_action=prior_action,
                    decision_seq=decision_seq,
                    decision_ts_unix_ns=decision_ts_unix_ns,
                    decision_ts_mono_ns=decision_ts_mono_ns,
                    event_id=event_id,
                )
            except Exception:
                raw_route = None
                degraded = True
                unavailable = True
                reason_codes.append("ROUTE_UNAVAILABLE")

        if raw_route is None:
            if bundle.config.synthetic_route_on_error:
                raw_route = self._build_synthetic_route_contract(
                    ctx=ctx,
                    bundle=bundle,
                    policy=policy,
                    detector=detector,
                    required_action=(bundle.config.route_error_action if unavailable else prior_action),
                    decision_seq=decision_seq,
                    decision_ts_unix_ns=decision_ts_unix_ns,
                    decision_ts_mono_ns=decision_ts_mono_ns,
                    event_id=event_id,
                    degraded_reason_codes=tuple(reason_codes),
                )
                degraded = True or degraded
            else:
                unavailable = True
                degraded = True
                reason_codes.append("ROUTE_UNAVAILABLE")
                return _RouteEvaluation(
                    route=None,
                    degraded=True,
                    unavailable=True,
                    required_action=bundle.config.route_error_action,
                    enforcement_mode="must_enforce" if bundle.config.route_error_action != "allow" else "advisory",
                    reason_codes=_normalize_reason_codes(reason_codes, max_items=16),
                )

        route = self._coerce_route_contract(
            raw_route=raw_route,
            ctx=ctx,
            bundle=bundle,
            policy=policy,
            detector=detector,
            decision_seq=decision_seq,
            decision_ts_unix_ns=decision_ts_unix_ns,
            decision_ts_mono_ns=decision_ts_mono_ns,
            event_id=event_id,
            degraded_reason_codes=tuple(reason_codes),
        )

        required_action = route.required_action
        enforcement_mode = route.enforcement_mode

        if bundle.config.require_route_contract and route is None:
            required_action = bundle.config.route_error_action
            enforcement_mode = "fail_closed" if required_action == "block" else "must_enforce"
            degraded = True
            unavailable = True
            reason_codes.append("ROUTE_REQUIRED_MISSING")

        reason_codes.extend(route.reason_codes if route is not None else ())
        return _RouteEvaluation(
            route=route,
            degraded=degraded,
            unavailable=unavailable,
            required_action=required_action,
            enforcement_mode=enforcement_mode,
            reason_codes=_normalize_reason_codes(reason_codes, max_items=16),
        )

    def _invoke_strategy_router(
        self,
        *,
        ctx: SecurityContext,
        bundle: _CompiledSecurityBundle,
        policy: _PolicyEvaluation,
        detector: _DetectorResult,
        prior_action: RequiredAction,
        decision_seq: int,
        decision_ts_unix_ns: int,
        decision_ts_mono_ns: int,
        event_id: str,
    ) -> Any:
        trust_zone = ctx.trust_zone
        route_profile = policy.route_profile
        risk_label = detector.risk_label or policy.risk_label
        threat_kind = detector.threat_tags[0] if detector.threat_tags else None
        threat_kinds = list(detector.threat_tags) if detector.threat_tags else None

        t_low = _coerce_float(getattr(policy.bound_policy, "t_low", None))
        t_high = _coerce_float(getattr(policy.bound_policy, "t_high", None))
        p_low = _coerce_float(getattr(policy.bound_policy, "top_p_low", None))
        p_high = _coerce_float(getattr(policy.bound_policy, "top_p_high", None))

        if risk_label in {"high", "critical"} or prior_action == "block" or detector.trigger:
            base_temp = t_low if t_low is not None else ctx.base_temp
            base_top_p = p_low if p_low is not None else ctx.base_top_p
        else:
            base_temp = t_high if t_high is not None else (t_low if t_low is not None else ctx.base_temp)
            base_top_p = p_high if p_high is not None else (p_low if p_low is not None else ctx.base_top_p)

        env = ctx.signal_envelope or SecuritySignalEnvelope()

        # Try newest routing signature first.
        try:
            return self._strategy_router.decide(
                decision_fail=(prior_action == "block"),
                score=float(detector.risk_score if detector.risk_score is not None else 0.0),
                base_temp=float(base_temp),
                base_top_p=float(base_top_p),
                risk_label=risk_label,
                route_profile=route_profile,
                e_triggered=bool(detector.trigger),
                trust_zone=trust_zone,
                threat_kind=threat_kind,
                threat_kinds=threat_kinds,
                pq_unhealthy=bool(ctx.pq_unhealthy),
                av_label=detector.av_label,
                av_trigger=detector.av_trigger,
                route_context=StrategyRouteContext(
                    request_id=ctx.request_id,
                    trace_id=ctx.trace_id,
                    tenant_id=ctx.tenant_id,
                    principal_id=ctx.principal_id,
                    trust_zone=trust_zone,
                    route_profile=route_profile,
                ),
                signal_envelope=StrategySignalEnvelope(
                    source=env.source,
                    trusted=env.trusted,
                    signed=env.signed,
                    signer_kid=env.signer_kid,
                    source_cfg_fp=env.source_cfg_fp,
                    source_policy_ref=env.source_policy_ref,
                    freshness_ms=env.freshness_ms,
                    replay_checked=env.replay_checked,
                ),
                controller_mode=detector.controller_mode,
                guarantee_scope=detector.guarantee_scope,
                max_tokens=ctx.base_max_tokens,
            )
        except TypeError:
            # Compatibility with older routing versions; routing is deterministic and side-effect free.
            return self._strategy_router.decide(
                decision_fail=(prior_action == "block"),
                score=float(detector.risk_score if detector.risk_score is not None else 0.0),
                base_temp=float(base_temp),
                base_top_p=float(base_top_p),
                risk_label=risk_label,
                route_profile=route_profile,
                e_triggered=bool(detector.trigger),
                trust_zone=trust_zone,
                threat_kind=threat_kind,
                threat_kinds=threat_kinds,
                pq_unhealthy=bool(ctx.pq_unhealthy),
                av_label=detector.av_label,
                av_trigger=detector.av_trigger,
            )

    # ------------------------------------------------------------------
    # Composition / artifacts / integrity
    # ------------------------------------------------------------------

    def _compose_decision(
        self,
        snap: _EvaluationSnapshot,
        *,
        router_mode: RouterMode,
        degraded_reason_codes: Tuple[str, ...],
    ) -> SecurityDecision:
        ctx = snap.ctx
        bundle = snap.bundle
        policy = snap.policy
        auth = snap.auth
        rate = snap.rate
        detector = snap.detector
        route_eval = snap.route_eval

        source_actions: List[Tuple[str, RequiredAction, str]] = [
            ("policy", policy.required_action, "POLICY_BLOCK" if policy.required_action == "block" else ("POLICY_DEGRADE" if policy.required_action == "degrade" else "DEFAULT_ALLOW")),
            ("auth", auth.required_action, auth.reason_code),
            ("rate", rate.required_action, (rate.reason_codes[0] if rate.reason_codes else "DEFAULT_ALLOW")),
            ("detector", self._detector_required_action(bundle, detector), self._detector_primary_reason(detector)),
            ("route", route_eval.required_action, (route_eval.reason_codes[0] if route_eval.reason_codes else "DEFAULT_ALLOW")),
        ]

        required_action: RequiredAction = "allow"
        primary_reason_code = "DEFAULT_ALLOW"
        primary_rank = -1
        reason_accum: List[str] = []
        degraded_accum: List[str] = list(degraded_reason_codes)
        compat_warnings: List[str] = list(ctx.normalization_warnings)

        for _source, act, code in source_actions:
            required_action = _action_max(required_action, act)
            if code in _ALLOWED_REASON_CODES and code not in reason_accum:
                if code != "DEFAULT_ALLOW":
                    reason_accum.append(code)
                rank = _action_rank(_required_action_from_reason(code))
                if rank > primary_rank:
                    primary_rank = rank
                    primary_reason_code = code

        for code in rate.reason_codes:
            if code not in reason_accum and code != "DEFAULT_ALLOW":
                reason_accum.append(code)
        for code in route_eval.reason_codes:
            if code not in reason_accum and code != "DEFAULT_ALLOW":
                reason_accum.append(code)

        if detector.error:
            compat_warnings.append("detector_error")
        if detector.preview_only:
            compat_warnings.append("detector_preview_only")
        if route_eval.unavailable:
            compat_warnings.append("route_unavailable")

        if required_action == "allow":
            action_taken: RequiredAction = "allow"
            allowed = True
        elif required_action == "degrade":
            action_taken = "degrade"
            allowed = True
        else:
            action_taken = "block"
            allowed = False

        enforcement_mode: EnforcementMode
        if required_action == "block":
            enforcement_mode = "must_enforce"
        elif required_action == "degrade":
            enforcement_mode = "must_enforce"
        else:
            enforcement_mode = "advisory"

        enforcement_mode = _enforcement_max(enforcement_mode, route_eval.enforcement_mode)
        if router_mode == "fail_closed" and required_action == "block":
            enforcement_mode = "fail_closed"

        if not reason_accum:
            reason_accum = ["DEFAULT_ALLOW"]

        if primary_reason_code == "DEFAULT_ALLOW":
            primary_reason_code = reason_accum[0] if reason_accum else "DEFAULT_ALLOW"

        route = route_eval.route
        evidence_identity = self._build_evidence_identity(
            snap=snap,
            route=route,
            policy_digest=policy.policy_digest,
            audit_ref=detector.audit_ref,
            receipt_ref=detector.receipt_ref,
        )
        security_block = self._build_security_block(
            snap=snap,
            route=route,
            receipt_required=bool(route.receipt_required) if route is not None else policy.receipt_required,
            attestation_required=bool(route.attestation_required) if route is not None else policy.attestation_required,
            audit_ref=detector.audit_ref,
            receipt_ref=detector.receipt_ref,
        )
        artifacts = {
            "receipt_required": bool(route.receipt_required) if route is not None else policy.receipt_required,
            "ledger_required": bool(route.ledger_required) if route is not None else policy.ledger_required,
            "attestation_required": bool(route.attestation_required) if route is not None else policy.attestation_required,
            "ledger_stage": "skipped",
            "ledger_prepare_ref": None,
            "ledger_commit_ref": None,
            "outbox_status": "none",
        }

        reason_codes = _normalize_reason_codes(reason_accum, max_items=32)
        degraded_codes = _normalize_reason_codes(degraded_accum, max_items=16)
        reason_text = ";".join(list(reason_codes) + list(degraded_codes)) or "DEFAULT_ALLOW"

        decision = SecurityDecision(
            schema=_SCHEMA,
            router=_ROUTER_NAME,
            version=_ROUTER_VERSION,
            instance_id=self._instance_id,
            activation_id=bundle.activation.activation_id,
            config_fingerprint=bundle.cfg_fp,
            bundle_version=bundle.version,
            bundle_updated_at_unix_ns=bundle.updated_at_unix_ns,
            event_id=snap.event_id,
            decision_seq=snap.decision_seq,
            decision_ts_unix_ns=snap.decision_ts_unix_ns,
            decision_ts_mono_ns=snap.decision_ts_mono_ns,
            batch_id=snap.batch_id,
            allowed=allowed,
            action=action_taken,
            action_taken=action_taken,
            required_action=required_action,
            enforcement_mode=enforcement_mode,
            primary_reason_code=primary_reason_code,
            reason_codes=reason_codes,
            degraded_reason_codes=degraded_codes,
            reason=reason_text,
            bound_policy=policy.bound_policy,
            policy_ref=policy.policy_ref,
            policyset_ref=policy.policyset_ref,
            policy_digest=policy.policy_digest,
            route=route,
            route_plan_id=(getattr(route, "route_plan_id", None) if route is not None else None),
            decision_id=(getattr(route, "decision_id", None) if route is not None else None),
            rate_decisions=rate.decisions,
            risk_score=detector.risk_score,
            risk_label=detector.risk_label or policy.risk_label,
            e_triggered=bool(detector.trigger),
            controller_mode=detector.controller_mode,
            guarantee_scope=detector.guarantee_scope,
            e_state=detector.e_state,
            security=security_block,
            evidence_identity=evidence_identity,
            artifacts=artifacts,
            audit_ref=detector.audit_ref,
            receipt_ref=detector.receipt_ref,
            receipt=None,
            integrity_ok=True,
            integrity_errors=tuple(),
            normalization_warnings=ctx.normalization_warnings,
            compat_warnings=tuple(sorted(set(compat_warnings))),
        )
        return decision

    def _finalize_with_artifacts(self, decision: SecurityDecision, snap: _EvaluationSnapshot) -> SecurityDecision:
        bundle = snap.bundle
        artifacts = dict(decision.artifacts)
        audit_ref = decision.audit_ref
        receipt_ref = decision.receipt_ref
        receipt = decision.receipt
        reason_codes = list(decision.reason_codes)
        primary_reason = decision.primary_reason_code
        required_action = decision.required_action
        action_taken = decision.action_taken
        allowed = decision.allowed
        enforcement_mode = decision.enforcement_mode

        # Receipt / attestation first, because it can change final decision.
        receipt_required = bool(artifacts.get("receipt_required"))
        attestation_required = bool(artifacts.get("attestation_required"))

        if receipt_required:
            if self._attestor is None:
                reason_codes.append("ATTESTOR_REQUIRED_UNAVAILABLE")
                if bundle.config.require_attestor_when_required or attestation_required:
                    required_action = _action_max(required_action, bundle.config.attestation_error_action)
                    action_taken = required_action
                    allowed = required_action != "block"
                    enforcement_mode = "fail_closed" if required_action == "block" else "must_enforce"
            else:
                try:
                    receipt = self._issue_security_receipt(
                        decision=decision,
                        snap=snap,
                        audit_ref=audit_ref,
                    )
                    if receipt:
                        receipt_ref = _safe_id(receipt.get("receipt"), default=None, max_len=256) or receipt_ref
                        reason_codes.append("RECEIPT_ISSUED")
                    else:
                        reason_codes.append("RECEIPT_SKIPPED")
                except Exception:
                    reason_codes.append("ATTESTATION_FAILED")
                    if attestation_required or bundle.config.require_attestor_when_required:
                        required_action = _action_max(required_action, bundle.config.attestation_error_action)
                        action_taken = required_action
                        allowed = required_action != "block"
                        enforcement_mode = "fail_closed" if required_action == "block" else "must_enforce"

        # Ledger after receipt so the final payload is final.
        if self._ledger_sink is not None and (bool(artifacts.get("ledger_required")) or bundle.config.audit_emit_all_decisions):
            payload = decision.to_audit_event()
            payload["artifacts"] = dict(artifacts)
            payload["receipt_ref"] = receipt_ref
            payload["receipt_present"] = bool(receipt)
            payload_digest = _safe_digest_hex(ctx="tcd:security:ledger_payload", payload=payload, out_hex=32)

            try:
                prepare_ref = self._ledger_sink.prepare(decision.event_id, payload)
                artifacts["ledger_prepare_ref"] = prepare_ref
                artifacts["ledger_stage"] = "prepared"
            except Exception:
                artifacts["ledger_stage"] = "failed"
                reason_codes.append("LEDGER_PREPARE_FAILED")
                if self._outbox_sink is not None and bundle.config.outbox_enabled and bundle.config.outbox_on_required_sink_failure:
                    try:
                        outbox_ref = self._outbox_sink.enqueue(
                            kind="security_router.ledger",
                            dedupe_key=decision.event_id,
                            payload=payload,
                            payload_digest=payload_digest,
                        )
                        artifacts["outbox_status"] = "queued"
                        artifacts["outbox_ref"] = outbox_ref
                        reason_codes.append("OUTBOX_QUEUED")
                    except Exception:
                        artifacts["outbox_status"] = "dropped"
                        reason_codes.append("OUTBOX_QUEUE_FAILED")
                        if bool(artifacts.get("ledger_required")) and bundle.config.require_ledger_when_required:
                            required_action = _action_max(required_action, "block")
                            action_taken = required_action
                            allowed = required_action != "block"
                            enforcement_mode = "fail_closed"
                elif bool(artifacts.get("ledger_required")) and bundle.config.require_ledger_when_required:
                    required_action = _action_max(required_action, "block")
                    action_taken = required_action
                    allowed = required_action != "block"
                    enforcement_mode = "fail_closed"
            else:
                try:
                    commit_ref = self._ledger_sink.commit(decision.event_id, payload)
                    artifacts["ledger_commit_ref"] = commit_ref
                    artifacts["ledger_stage"] = "committed"
                except Exception:
                    artifacts["ledger_stage"] = "failed"
                    reason_codes.append("LEDGER_COMMIT_FAILED")
                    if self._outbox_sink is not None and bundle.config.outbox_enabled and bundle.config.outbox_on_required_sink_failure:
                        try:
                            outbox_ref = self._outbox_sink.enqueue(
                                kind="security_router.ledger",
                                dedupe_key=decision.event_id,
                                payload=payload,
                                payload_digest=payload_digest,
                            )
                            artifacts["outbox_status"] = "queued"
                            artifacts["outbox_ref"] = outbox_ref
                            reason_codes.append("OUTBOX_QUEUED")
                        except Exception:
                            artifacts["outbox_status"] = "dropped"
                            reason_codes.append("OUTBOX_QUEUE_FAILED")
                            if bool(artifacts.get("ledger_required")) and bundle.config.require_ledger_when_required:
                                required_action = _action_max(required_action, "block")
                                action_taken = required_action
                                allowed = required_action != "block"
                                enforcement_mode = "fail_closed"
                    elif bool(artifacts.get("ledger_required")) and bundle.config.require_ledger_when_required:
                        required_action = _action_max(required_action, "block")
                        action_taken = required_action
                        allowed = required_action != "block"
                        enforcement_mode = "fail_closed"

        # Audit last, after final action and artifacts are settled.
        if self._audit_sink is not None and (bundle.config.audit_emit_all_decisions or action_taken != "allow"):
            try:
                audit_payload = decision.to_audit_event()
                audit_payload["artifacts"] = dict(artifacts)
                audit_payload["action"] = action_taken
                audit_payload["required_action"] = required_action
                audit_payload["allowed"] = allowed
                audit_payload["enforcement_mode"] = enforcement_mode
                audit_ref = self._audit_sink.emit("security_router.decision", audit_payload) or audit_ref
            except Exception:
                reason_codes.append("AUDIT_EMIT_FAIL")

        if primary_reason not in reason_codes and reason_codes:
            primary_reason = reason_codes[0]
        reason_codes_final = _normalize_reason_codes(reason_codes, max_items=32)
        if reason_codes_final:
            primary_reason = reason_codes_final[0]

        evidence_identity = dict(decision.evidence_identity)
        evidence_identity["receipt_ref"] = receipt_ref
        evidence_identity["audit_ref"] = audit_ref

        security_block = dict(decision.security)
        security_block["receipt_required"] = bool(artifacts.get("receipt_required"))
        security_block["ledger_required"] = bool(artifacts.get("ledger_required"))
        security_block["attestation_required"] = bool(artifacts.get("attestation_required"))
        security_block["audit_ref"] = audit_ref
        security_block["receipt_ref"] = receipt_ref

        reason_text = ";".join(list(reason_codes_final) + list(decision.degraded_reason_codes)) or "DEFAULT_ALLOW"

        return SecurityDecision(
            schema=decision.schema,
            router=decision.router,
            version=decision.version,
            instance_id=decision.instance_id,
            activation_id=decision.activation_id,
            config_fingerprint=decision.config_fingerprint,
            bundle_version=decision.bundle_version,
            bundle_updated_at_unix_ns=decision.bundle_updated_at_unix_ns,
            event_id=decision.event_id,
            decision_seq=decision.decision_seq,
            decision_ts_unix_ns=decision.decision_ts_unix_ns,
            decision_ts_mono_ns=decision.decision_ts_mono_ns,
            batch_id=decision.batch_id,
            allowed=allowed,
            action=action_taken,
            action_taken=action_taken,
            required_action=required_action,
            enforcement_mode=enforcement_mode,
            primary_reason_code=primary_reason,
            reason_codes=reason_codes_final,
            degraded_reason_codes=decision.degraded_reason_codes,
            reason=reason_text,
            bound_policy=decision.bound_policy,
            policy_ref=decision.policy_ref,
            policyset_ref=decision.policyset_ref,
            policy_digest=decision.policy_digest,
            route=decision.route,
            route_plan_id=decision.route_plan_id,
            decision_id=decision.decision_id,
            rate_decisions=decision.rate_decisions,
            risk_score=decision.risk_score,
            risk_label=decision.risk_label,
            e_triggered=decision.e_triggered,
            controller_mode=decision.controller_mode,
            guarantee_scope=decision.guarantee_scope,
            e_state=decision.e_state,
            security=security_block,
            evidence_identity=evidence_identity,
            artifacts=artifacts,
            audit_ref=audit_ref,
            receipt_ref=receipt_ref,
            receipt=receipt,
            integrity_ok=decision.integrity_ok,
            integrity_errors=decision.integrity_errors,
            normalization_warnings=decision.normalization_warnings,
            compat_warnings=decision.compat_warnings,
        )

    def _finalize_integrity(self, decision: SecurityDecision, snap: _EvaluationSnapshot) -> SecurityDecision:
        errors: List[str] = []

        if decision.required_action == "block" and decision.allowed:
            errors.append("required_action_block_but_allowed_true")
        if decision.required_action != "block" and not decision.allowed and decision.action != "block":
            errors.append("allowed_false_without_block")
        if decision.route is None and snap.bundle.config.require_route_contract:
            errors.append("route_contract_missing")
        if decision.route_plan_id is None:
            errors.append("route_plan_id_missing")
        if decision.decision_id is None:
            errors.append("decision_id_missing")
        if decision.artifacts.get("attestation_required") and not decision.receipt_ref:
            errors.append("attestation_required_but_receipt_missing")
        if decision.artifacts.get("ledger_required") and decision.artifacts.get("ledger_stage") == "failed":
            errors.append("ledger_required_but_commit_failed")

        e_ctrl = None
        if isinstance(decision.e_state, Mapping):
            ctrl = decision.e_state.get("controller")
            if isinstance(ctrl, Mapping):
                e_ctrl = ctrl

        if e_ctrl is not None:
            state_domain_id = _safe_id(e_ctrl.get("state_domain_id"), default=None, max_len=256)
            if state_domain_id and decision.evidence_identity.get("state_domain_id") not in {None, state_domain_id}:
                errors.append("state_domain_id_mismatch")
            det_cfg = _safe_id(e_ctrl.get("cfg_fp"), default=None, max_len=256)
            if det_cfg and decision.evidence_identity.get("detector_cfg_fp") not in {None, det_cfg}:
                errors.append("detector_cfg_fp_mismatch")

        integrity_ok = len(errors) == 0
        integrity_errors = tuple(errors)

        reason_codes = list(decision.reason_codes)
        if errors and "INTEGRITY_ERROR" not in reason_codes:
            reason_codes.append("INTEGRITY_ERROR")
        reason_codes_final = _normalize_reason_codes(reason_codes, max_items=32)
        primary_reason_code = decision.primary_reason_code
        if errors:
            primary_reason_code = "INTEGRITY_ERROR" if "INTEGRITY_ERROR" in reason_codes_final else primary_reason_code

        reason_text = ";".join(list(reason_codes_final) + list(decision.degraded_reason_codes)) or "DEFAULT_ALLOW"

        return SecurityDecision(
            schema=decision.schema,
            router=decision.router,
            version=decision.version,
            instance_id=decision.instance_id,
            activation_id=decision.activation_id,
            config_fingerprint=decision.config_fingerprint,
            bundle_version=decision.bundle_version,
            bundle_updated_at_unix_ns=decision.bundle_updated_at_unix_ns,
            event_id=decision.event_id,
            decision_seq=decision.decision_seq,
            decision_ts_unix_ns=decision.decision_ts_unix_ns,
            decision_ts_mono_ns=decision.decision_ts_mono_ns,
            batch_id=decision.batch_id,
            allowed=(False if errors and decision.required_action == "block" else decision.allowed),
            action=decision.action,
            action_taken=decision.action_taken,
            required_action=decision.required_action,
            enforcement_mode=decision.enforcement_mode,
            primary_reason_code=primary_reason_code,
            reason_codes=reason_codes_final,
            degraded_reason_codes=decision.degraded_reason_codes,
            reason=reason_text,
            bound_policy=decision.bound_policy,
            policy_ref=decision.policy_ref,
            policyset_ref=decision.policyset_ref,
            policy_digest=decision.policy_digest,
            route=decision.route,
            route_plan_id=decision.route_plan_id,
            decision_id=decision.decision_id,
            rate_decisions=decision.rate_decisions,
            risk_score=decision.risk_score,
            risk_label=decision.risk_label,
            e_triggered=decision.e_triggered,
            controller_mode=decision.controller_mode,
            guarantee_scope=decision.guarantee_scope,
            e_state=decision.e_state,
            security=decision.security,
            evidence_identity=decision.evidence_identity,
            artifacts=decision.artifacts,
            audit_ref=decision.audit_ref,
            receipt_ref=decision.receipt_ref,
            receipt=decision.receipt,
            integrity_ok=integrity_ok,
            integrity_errors=integrity_errors,
            normalization_warnings=decision.normalization_warnings,
            compat_warnings=decision.compat_warnings,
        )

    # ------------------------------------------------------------------
    # Detector action policy / auth / rate / route helpers
    # ------------------------------------------------------------------

    def _detector_required_action(self, bundle: _CompiledSecurityBundle, det: _DetectorResult) -> RequiredAction:
        if det.error:
            return bundle.config.detector_error_action
        act = _safe_label(det.action, default="")
        if act in {"block", "deny", "degraded_block"}:
            return "block"
        if act in {"degrade", "advisory"}:
            return "degrade"
        if det.trigger:
            return "block"
        return "allow"

    def _detector_primary_reason(self, det: _DetectorResult) -> str:
        if det.error:
            return "DETECTOR_ERROR"
        if _safe_label(det.action, default="") in {"block", "deny", "degraded_block"}:
            return "DETECTOR_ACTION_BLOCK"
        if _safe_label(det.action, default="") in {"degrade", "advisory"}:
            return "DETECTOR_ACTION_DEGRADE"
        if det.trigger:
            return "DETECTOR_TRIGGER"
        if det.risk_score is not None:
            if det.risk_score >= 0.99:
                return "DETECTOR_CRITICAL"
            if det.risk_score >= 0.95:
                return "DETECTOR_HIGH"
        return "DEFAULT_ALLOW"

    def _derive_event_id(
        self,
        ctx: SecurityContext,
        decision_ts_unix_ns: int,
        decision_seq: int,
        bundle: _CompiledSecurityBundle,
    ) -> str:
        if ctx.event_id:
            return ctx.event_id
        if ctx.idempotency_key:
            payload = {
                "idempotency_key": ctx.idempotency_key,
                "tenant_id": ctx.tenant_id,
                "principal_id": ctx.principal_id,
                "route_profile": ctx.route_profile,
            }
        elif ctx.request_id:
            payload = {
                "request_id": ctx.request_id,
                "trace_id": ctx.trace_id,
                "tenant_id": ctx.tenant_id,
                "principal_id": ctx.principal_id,
            }
        elif ctx.trace_id:
            payload = {
                "trace_id": ctx.trace_id,
                "tenant_id": ctx.tenant_id,
                "principal_id": ctx.principal_id,
                "subject_hash": _subject_digest(ctx.subject_id(), bundle.identity_hasher),
            }
        elif ctx.body_digest:
            bucket_ns = (decision_ts_unix_ns // (bundle.config.event_id_bucket_s * 1_000_000_000)) * (bundle.config.event_id_bucket_s * 1_000_000_000)
            payload = {
                "body_digest": ctx.body_digest,
                "tenant_id": ctx.tenant_id,
                "route_profile": ctx.route_profile,
                "bucket_ns": bucket_ns,
            }
        else:
            bucket_ns = (decision_ts_unix_ns // (bundle.config.event_id_bucket_s * 1_000_000_000)) * (bundle.config.event_id_bucket_s * 1_000_000_000)
            payload = {
                "subject_hash": _subject_digest(ctx.subject_id(), bundle.identity_hasher),
                "tenant_id": ctx.tenant_id,
                "kind": ctx.kind,
                "trust_zone": ctx.trust_zone,
                "route_profile": ctx.route_profile,
                "bucket_ns": bucket_ns,
                "decision_seq": decision_seq,
                "instance_id": self._instance_id,
            }
        return f"{_EVENT_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:security:event', payload=payload, out_hex=32)}"

    def _compute_cost(self, bp: Any, ctx: SecurityContext) -> float:
        total_tokens = max(1, int(ctx.tokens_in) + int(ctx.tokens_out))
        divisor = float(_coerce_float(getattr(bp, "token_cost_divisor", None)) or 50.0)
        divisor = max(1.0, divisor)
        return float(total_tokens) / divisor

    def _denied(self, d: Optional[Any]) -> bool:
        if d is None:
            return False
        return not bool(getattr(d, "allowed", True))

    def _choose_zone_for_ip(self, bp: Any, ctx: SecurityContext) -> str:
        if ctx.trust_zone in {"internal", "partner", "admin", "ops"}:
            return ctx.trust_zone
        return "internet"

    def _choose_zone_for_tenant(self, bp: Any, ctx: SecurityContext) -> str:
        risk_label = _safe_label(getattr(bp, "risk_label", None), default="")
        compliance_profile = _safe_label(getattr(bp, "compliance_profile", None), default="")
        if risk_label in {"high", "critical"} or compliance_profile in {"high", "strict"}:
            return "high_security"
        return "tenant"

    def _choose_zone_for_user_model(self, bp: Any, ctx: SecurityContext) -> str:
        route_profile = self._policy_route_profile(bp, ctx)
        if ctx.kind == "admin" or route_profile == "admin":
            return "admin"
        if route_profile == "control":
            return "control"
        return "user_model"

    def _choose_zone_for_policy(self, bp: Any, ctx: SecurityContext) -> str:
        route_profile = self._policy_route_profile(bp, ctx)
        if route_profile in {"admin", "control", "restricted"}:
            return "policy_restricted"
        if _safe_label(getattr(bp, "compliance_profile", None), default="") in {"strict", "high"}:
            return "policy_high"
        return "policy"

    def _build_synthetic_route_contract(
        self,
        *,
        ctx: SecurityContext,
        bundle: _CompiledSecurityBundle,
        policy: _PolicyEvaluation,
        detector: _DetectorResult,
        required_action: RequiredAction,
        decision_seq: int,
        decision_ts_unix_ns: int,
        decision_ts_mono_ns: int,
        event_id: str,
        degraded_reason_codes: Tuple[str, ...],
    ) -> SecurityRouteContract:
        env = ctx.signal_envelope or SecuritySignalEnvelope()
        safety_tier = "strict" if required_action == "block" else ("elevated" if required_action == "degrade" else "normal")

        if required_action == "block":
            temperature = 0.0
            top_p = 0.0
            decoder = "safe"
            max_tokens = 0
            latency_hint = "high_safety"
            tool_calls_allowed = False
            retrieval_allowed = False
            streaming_allowed = False
            external_calls_allowed = False
            response_policy = "restricted"
            enforcement_mode: EnforcementMode = "fail_closed"
        elif required_action == "degrade":
            temperature = min(0.5, ctx.base_temp)
            top_p = min(0.8, ctx.base_top_p)
            decoder = "cautious"
            max_tokens = ctx.base_max_tokens
            latency_hint = "high_safety"
            tool_calls_allowed = False
            retrieval_allowed = False
            streaming_allowed = False
            external_calls_allowed = False
            response_policy = "cautious"
            enforcement_mode = "must_enforce"
        else:
            temperature = ctx.base_temp
            top_p = ctx.base_top_p
            decoder = "default"
            max_tokens = ctx.base_max_tokens
            latency_hint = "normal"
            tool_calls_allowed = True
            retrieval_allowed = True
            streaming_allowed = True
            external_calls_allowed = True
            response_policy = "default"
            enforcement_mode = "advisory"

        context_digest = _context_digest(ctx, bundle.identity_hasher)
        signal_digest = _signal_digest(env, detector, ctx=ctx, hasher=bundle.identity_hasher)
        route_plan_payload = {
            "cfg_fp": bundle.cfg_fp,
            "bundle_version": bundle.version,
            "policy_ref": policy.policy_ref,
            "policyset_ref": policy.policyset_ref,
            "required_action": required_action,
            "enforcement_mode": enforcement_mode,
            "trust_zone": ctx.trust_zone,
            "route_profile": policy.route_profile,
            "risk_label": detector.risk_label or policy.risk_label,
            "score": float(detector.risk_score if detector.risk_score is not None else 0.0),
            "decision_fail": bool(required_action == "block"),
            "signal_digest": signal_digest,
            "context_digest": context_digest,
        }
        route_plan_id = f"{_ROUTE_PLAN_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:security:route_plan', payload=route_plan_payload, out_hex=32)}"
        decision_id = f"{_DECISION_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:security:route_decision', payload={'event_id': event_id, 'route_plan_id': route_plan_id, 'decision_seq': decision_seq}, out_hex=32)}"

        reason_codes = _normalize_reason_codes(
            ["ROUTE_BLOCK" if required_action == "block" else ("ROUTE_DEGRADE" if required_action == "degrade" else "DEFAULT_ALLOW")] + list(degraded_reason_codes),
            max_items=16,
        )
        primary_reason = reason_codes[0] if reason_codes else "DEFAULT_ALLOW"
        reason_text = ";".join(list(reason_codes) + list(degraded_reason_codes)) or "DEFAULT_ALLOW"

        return SecurityRouteContract(
            schema="tcd.route.v4",
            router=f"{_ROUTER_NAME}.synthetic_route",
            version=_ROUTER_VERSION,
            instance_id=self._instance_id,
            activation_id=bundle.activation.activation_id,
            config_fingerprint=bundle.cfg_fp,
            bundle_version=bundle.version,
            bundle_updated_at_unix_ns=bundle.updated_at_unix_ns,
            policy_ref=policy.policy_ref,
            policyset_ref=policy.policyset_ref,
            patch_id=bundle.config.patch_id,
            change_ticket_id=bundle.config.change_ticket_id,
            activated_by=bundle.config.activated_by,
            router_mode="degraded" if degraded_reason_codes else "normal",
            route_id_kind="plan",
            route_plan_id=route_plan_id,
            route_id=route_plan_id,
            decision_id=decision_id,
            decision_seq=decision_seq,
            decision_ts_unix_ns=decision_ts_unix_ns,
            decision_ts_mono_ns=decision_ts_mono_ns,
            safety_tier=safety_tier,
            required_action=required_action,
            action_hint=required_action,
            enforcement_mode=enforcement_mode,
            temperature=float(temperature),
            top_p=float(top_p),
            decoder=decoder,
            max_tokens=max_tokens,
            latency_hint=latency_hint,
            tool_calls_allowed=tool_calls_allowed,
            retrieval_allowed=retrieval_allowed,
            streaming_allowed=streaming_allowed,
            external_calls_allowed=external_calls_allowed,
            response_policy=response_policy,
            receipt_required=policy.receipt_required,
            ledger_required=policy.ledger_required,
            attestation_required=policy.attestation_required,
            trust_zone=ctx.trust_zone,
            route_profile=policy.route_profile,
            risk_label=detector.risk_label or policy.risk_label,
            score=float(detector.risk_score if detector.risk_score is not None else 0.0),
            decision_fail=bool(required_action == "block"),
            e_triggered=bool(detector.trigger),
            pq_unhealthy=bool(ctx.pq_unhealthy),
            av_label=detector.av_label,
            av_trigger=detector.av_trigger,
            threat_tags=detector.threat_tags,
            controller_mode=detector.controller_mode,
            guarantee_scope=detector.guarantee_scope,
            signal_source=env.source,
            signal_trust_mode=env.trust_mode(),
            signal_signed=env.signed,
            signal_signer_kid=env.signer_kid,
            signal_cfg_fp=env.source_cfg_fp,
            signal_policy_ref=env.source_policy_ref,
            signal_freshness_ms=env.freshness_ms,
            signal_replay_checked=env.replay_checked,
            signal_digest=signal_digest,
            context_digest=context_digest,
            primary_reason_code=primary_reason,
            reason_codes=reason_codes,
            degraded_reason_codes=degraded_reason_codes,
            reason=reason_text,
            tags=_normalize_tags((f"router:{_ROUTER_NAME}", f"kind:{ctx.kind}", f"tier:{safety_tier}"), max_items=16),
        )

    def _coerce_route_contract(
        self,
        *,
        raw_route: Any,
        ctx: SecurityContext,
        bundle: _CompiledSecurityBundle,
        policy: _PolicyEvaluation,
        detector: _DetectorResult,
        decision_seq: int,
        decision_ts_unix_ns: int,
        decision_ts_mono_ns: int,
        event_id: str,
        degraded_reason_codes: Tuple[str, ...],
    ) -> SecurityRouteContract:
        if isinstance(raw_route, SecurityRouteContract):
            return raw_route

        env = ctx.signal_envelope or SecuritySignalEnvelope()
        route_dict: Dict[str, Any] = {}
        if hasattr(raw_route, "to_dict"):
            try:
                route_dict = dict(raw_route.to_dict())
            except Exception:
                route_dict = {}
        if not route_dict and isinstance(raw_route, Mapping):
            route_dict = dict(raw_route)

        context_digest = _safe_id(route_dict.get("context_digest"), default=None, max_len=256) or _context_digest(ctx, bundle.identity_hasher)
        signal_digest = _safe_id(route_dict.get("signal_digest"), default=None, max_len=256) or _signal_digest(env, detector, ctx=ctx, hasher=bundle.identity_hasher)

        required_action = _safe_label(route_dict.get("required_action"), default="")
        if required_action not in _ALLOWED_REQUIRED_ACTIONS:
            hint = _safe_label(route_dict.get("action_hint"), default="")
            if hint in _ALLOWED_REQUIRED_ACTIONS:
                required_action = hint
            else:
                tier = _safe_label(route_dict.get("safety_tier"), default="normal")
                required_action = "block" if tier == "strict" else ("degrade" if tier == "elevated" else "allow")
        enforcement_mode = _safe_label(route_dict.get("enforcement_mode"), default="")
        if enforcement_mode not in _ALLOWED_ENFORCEMENT:
            enforcement_mode = "must_enforce" if required_action in {"degrade", "block"} else "advisory"

        route_plan_id = _safe_id(route_dict.get("route_plan_id"), default=None, max_len=256)
        route_id = _safe_id(route_dict.get("route_id"), default=None, max_len=256)
        decision_id = _safe_id(route_dict.get("decision_id"), default=None, max_len=256)

        if route_plan_id is None:
            payload = {
                "cfg_fp": _safe_id(route_dict.get("config_fingerprint"), default=bundle.cfg_fp, max_len=256),
                "bundle_version": _coerce_int(route_dict.get("bundle_version")) or bundle.version,
                "policy_ref": _safe_id(route_dict.get("policy_ref"), default=policy.policy_ref, max_len=128),
                "policyset_ref": _safe_id(route_dict.get("policyset_ref"), default=policy.policyset_ref, max_len=128),
                "required_action": required_action,
                "enforcement_mode": enforcement_mode,
                "trust_zone": _safe_label(route_dict.get("trust_zone"), default=ctx.trust_zone),
                "route_profile": _safe_label(route_dict.get("route_profile"), default=policy.route_profile),
                "risk_label": _safe_label(route_dict.get("risk_label"), default=detector.risk_label or policy.risk_label),
                "score": float(_coerce_float(route_dict.get("score")) or detector.risk_score or 0.0),
                "signal_digest": signal_digest,
                "context_digest": context_digest,
            }
            route_plan_id = f"{_ROUTE_PLAN_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:security:route_plan', payload=payload, out_hex=32)}"

        if route_id is None:
            route_id = route_plan_id

        if decision_id is None:
            decision_id = f"{_DECISION_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:security:route_decision', payload={'event_id': event_id, 'route_plan_id': route_plan_id, 'decision_seq': decision_seq}, out_hex=32)}"

        safety_tier = _safe_label(route_dict.get("safety_tier"), default="normal")
        if safety_tier not in {"normal", "elevated", "strict"}:
            safety_tier = "strict" if required_action == "block" else ("elevated" if required_action == "degrade" else "normal")

        primary_reason_code = _strip_unsafe_text(route_dict.get("primary_reason_code"), max_len=64).upper()
        reason_codes = tuple()
        if "reason_codes" in route_dict and isinstance(route_dict["reason_codes"], (list, tuple)):
            reason_codes = _normalize_reason_codes((str(x) for x in route_dict["reason_codes"]), max_items=16)
        if not reason_codes and primary_reason_code in _ALLOWED_REASON_CODES:
            reason_codes = (primary_reason_code,)
        if not reason_codes:
            reason_codes = _normalize_reason_codes(
                [("ROUTE_BLOCK" if required_action == "block" else ("ROUTE_DEGRADE" if required_action == "degrade" else "DEFAULT_ALLOW"))],
                max_items=16,
            )
        primary_reason_code = reason_codes[0] if reason_codes else "DEFAULT_ALLOW"

        degraded_codes = tuple()
        if "degraded_reason_codes" in route_dict and isinstance(route_dict["degraded_reason_codes"], (list, tuple)):
            degraded_codes = _normalize_reason_codes((str(x) for x in route_dict["degraded_reason_codes"]), max_items=16)
        if degraded_reason_codes:
            degraded_codes = _normalize_reason_codes(tuple(degraded_codes) + degraded_reason_codes, max_items=16)

        reason_text = _strip_unsafe_text(route_dict.get("reason"), max_len=1024)
        if not reason_text:
            reason_text = ";".join(list(reason_codes) + list(degraded_codes)) or "DEFAULT_ALLOW"

        threat_tags = tuple()
        if isinstance(route_dict.get("threat_tags"), (list, tuple)):
            threat_tags = _normalize_str_tuple((str(x) for x in route_dict["threat_tags"]), max_items=8)

        tags = tuple()
        if isinstance(route_dict.get("tags"), (list, tuple)):
            tags = _normalize_tags((str(x) for x in route_dict["tags"]), max_items=32)

        return SecurityRouteContract(
            schema=_strip_unsafe_text(route_dict.get("schema"), max_len=64) or "tcd.route.v4",
            router=_strip_unsafe_text(route_dict.get("router"), max_len=128) or _ROUTER_NAME,
            version=_strip_unsafe_text(route_dict.get("version"), max_len=64) or _ROUTER_VERSION,
            instance_id=_safe_id(route_dict.get("instance_id"), default=self._instance_id, max_len=128) or self._instance_id,
            activation_id=_safe_id(route_dict.get("activation_id"), default=bundle.activation.activation_id, max_len=128) or bundle.activation.activation_id,
            config_fingerprint=_safe_id(route_dict.get("config_fingerprint"), default=bundle.cfg_fp, max_len=256) or bundle.cfg_fp,
            bundle_version=_coerce_int(route_dict.get("bundle_version")) or bundle.version,
            bundle_updated_at_unix_ns=_coerce_int(route_dict.get("bundle_updated_at_unix_ns")) or bundle.updated_at_unix_ns,
            policy_ref=_safe_id(route_dict.get("policy_ref"), default=policy.policy_ref, max_len=128),
            policyset_ref=_safe_id(route_dict.get("policyset_ref"), default=policy.policyset_ref, max_len=128),
            patch_id=_safe_id(route_dict.get("patch_id"), default=bundle.config.patch_id, max_len=128),
            change_ticket_id=_safe_id(route_dict.get("change_ticket_id"), default=bundle.config.change_ticket_id, max_len=128),
            activated_by=_safe_id(route_dict.get("activated_by"), default=bundle.config.activated_by, max_len=128),
            router_mode=_safe_label(route_dict.get("router_mode"), default="normal") if _safe_label(route_dict.get("router_mode"), default="normal") in _ALLOWED_ROUTER_MODES else "normal",
            route_id_kind="plan",
            route_plan_id=route_plan_id,
            route_id=route_id,
            decision_id=decision_id,
            decision_seq=_coerce_int(route_dict.get("decision_seq")) or decision_seq,
            decision_ts_unix_ns=_coerce_int(route_dict.get("decision_ts_unix_ns")) or decision_ts_unix_ns,
            decision_ts_mono_ns=_coerce_int(route_dict.get("decision_ts_mono_ns")) or decision_ts_mono_ns,
            safety_tier=safety_tier,
            required_action=required_action,  # type: ignore[arg-type]
            action_hint=_safe_label(route_dict.get("action_hint"), default=required_action) if _safe_label(route_dict.get("action_hint"), default=required_action) in _ALLOWED_REQUIRED_ACTIONS else required_action,  # type: ignore[arg-type]
            enforcement_mode=enforcement_mode,  # type: ignore[arg-type]
            temperature=_clamp_float(route_dict.get("temperature"), default=ctx.base_temp, lo=0.0, hi=10.0),
            top_p=_clamp_float(route_dict.get("top_p"), default=ctx.base_top_p, lo=0.0, hi=1.0),
            decoder=_safe_name(route_dict.get("decoder"), default="default"),
            max_tokens=(
                _clamp_int(route_dict.get("max_tokens"), default=1, lo=0, hi=10_000_000)
                if route_dict.get("max_tokens") is not None
                else ctx.base_max_tokens
            ),
            latency_hint=_safe_label(route_dict.get("latency_hint"), default="normal"),
            tool_calls_allowed=_coerce_bool(route_dict.get("tool_calls_allowed"), default=(required_action == "allow")),
            retrieval_allowed=_coerce_bool(route_dict.get("retrieval_allowed"), default=(required_action == "allow")),
            streaming_allowed=_coerce_bool(route_dict.get("streaming_allowed"), default=(required_action == "allow")),
            external_calls_allowed=_coerce_bool(route_dict.get("external_calls_allowed"), default=(required_action == "allow")),
            response_policy=_safe_label(route_dict.get("response_policy"), default=("restricted" if required_action == "block" else ("cautious" if required_action == "degrade" else "default"))),
            receipt_required=_coerce_bool(route_dict.get("receipt_required"), default=policy.receipt_required),
            ledger_required=_coerce_bool(route_dict.get("ledger_required"), default=policy.ledger_required),
            attestation_required=_coerce_bool(route_dict.get("attestation_required"), default=policy.attestation_required),
            trust_zone=_safe_label(route_dict.get("trust_zone"), default=ctx.trust_zone),
            route_profile=_safe_label(route_dict.get("route_profile"), default=policy.route_profile),
            risk_label=_safe_label(route_dict.get("risk_label"), default=detector.risk_label or policy.risk_label),
            score=_safe_score(route_dict.get("score") if "score" in route_dict else (detector.risk_score or 0.0)),
            decision_fail=_coerce_bool(route_dict.get("decision_fail"), default=False),
            e_triggered=_coerce_bool(route_dict.get("e_triggered"), default=bool(detector.trigger)),
            pq_unhealthy=_coerce_bool(route_dict.get("pq_unhealthy"), default=bool(ctx.pq_unhealthy)),
            av_label=_safe_label(route_dict.get("av_label"), default="") or detector.av_label,
            av_trigger=(None if route_dict.get("av_trigger") is None else _coerce_bool(route_dict.get("av_trigger"), default=False)),
            threat_tags=threat_tags,
            controller_mode=_safe_label(route_dict.get("controller_mode"), default="") or detector.controller_mode,
            guarantee_scope=_safe_label(route_dict.get("guarantee_scope"), default="") or detector.guarantee_scope,
            signal_source=_safe_name(route_dict.get("signal_source"), default=env.source),
            signal_trust_mode=_safe_label(route_dict.get("signal_trust_mode"), default=env.trust_mode()) if _safe_label(route_dict.get("signal_trust_mode"), default=env.trust_mode()) in _ALLOWED_SIGNAL_TRUST else env.trust_mode(),  # type: ignore[arg-type]
            signal_signed=_coerce_bool(route_dict.get("signal_signed"), default=env.signed),
            signal_signer_kid=_safe_id(route_dict.get("signal_signer_kid"), default=env.signer_kid, max_len=64),
            signal_cfg_fp=_safe_id(route_dict.get("signal_cfg_fp"), default=env.source_cfg_fp, max_len=128),
            signal_policy_ref=_safe_id(route_dict.get("signal_policy_ref"), default=env.source_policy_ref, max_len=128),
            signal_freshness_ms=(
                _clamp_int(route_dict.get("signal_freshness_ms"), default=0, lo=0, hi=86_400_000)
                if route_dict.get("signal_freshness_ms") is not None
                else env.freshness_ms
            ),
            signal_replay_checked=(None if route_dict.get("signal_replay_checked") is None else _coerce_bool(route_dict.get("signal_replay_checked"), default=False)),
            signal_digest=signal_digest,
            context_digest=context_digest,
            primary_reason_code=primary_reason_code,
            reason_codes=reason_codes,
            degraded_reason_codes=degraded_codes,
            reason=reason_text,
            tags=tags,
        )

    def _build_evidence_identity(
        self,
        *,
        snap: _EvaluationSnapshot,
        route: Optional[Any],
        policy_digest: str,
        audit_ref: Optional[str],
        receipt_ref: Optional[str],
    ) -> Dict[str, Any]:
        detector_cfg_fp = None
        detector_bundle_version = None
        state_domain_id = None
        adapter_registry_fp = None
        if isinstance(snap.detector.e_state, Mapping):
            ctrl = snap.detector.e_state.get("controller")
            if isinstance(ctrl, Mapping):
                detector_cfg_fp = _safe_id(ctrl.get("cfg_fp"), default=None, max_len=256)
                detector_bundle_version = _coerce_int(ctrl.get("bundle_version"))
                state_domain_id = _safe_id(ctrl.get("state_domain_id"), default=None, max_len=256)
                adapter_registry_fp = _safe_id(ctrl.get("adapter_registry_fp"), default=None, max_len=256)

        return {
            "event_id": snap.event_id,
            "decision_seq": snap.decision_seq,
            "decision_id": getattr(route, "decision_id", None) if route is not None else None,
            "route_plan_id": getattr(route, "route_plan_id", None) if route is not None else None,
            "security_cfg_fp": snap.bundle.cfg_fp,
            "security_bundle_version": snap.bundle.version,
            "activation_id": snap.bundle.activation.activation_id,
            "security_policy_ref": snap.policy.policy_ref,
            "security_policyset_ref": snap.policy.policyset_ref,
            "security_policy_digest": policy_digest,
            "route_cfg_fp": getattr(route, "config_fingerprint", None) if route is not None else None,
            "route_bundle_version": getattr(route, "bundle_version", None) if route is not None else None,
            "route_policy_ref": getattr(route, "policy_ref", None) if route is not None else None,
            "route_policyset_ref": getattr(route, "policyset_ref", None) if route is not None else None,
            "state_domain_id": state_domain_id,
            "detector_cfg_fp": detector_cfg_fp,
            "detector_bundle_version": detector_bundle_version,
            "adapter_registry_fp": adapter_registry_fp,
            "audit_ref": audit_ref,
            "receipt_ref": receipt_ref,
            "subject_hash": _subject_digest(snap.ctx.subject_id(), snap.bundle.identity_hasher),
        }

    def _build_security_block(
        self,
        *,
        snap: _EvaluationSnapshot,
        route: Optional[Any],
        receipt_required: bool,
        attestation_required: bool,
        audit_ref: Optional[str],
        receipt_ref: Optional[str],
    ) -> Dict[str, Any]:
        pq_required = bool(snap.ctx.pq_required) or bool(getattr(route, "attestation_required", False))
        pq_ok = None
        if pq_required:
            pq_ok = None if not snap.ctx.pq_unhealthy else False
        return {
            "event_id": snap.event_id,
            "trust_zone": snap.ctx.trust_zone,
            "route_profile": snap.policy.route_profile,
            "risk_label": snap.detector.risk_label or snap.policy.risk_label,
            "controller_mode": snap.detector.controller_mode,
            "statistical_guarantee_scope": snap.detector.guarantee_scope,
            "state_domain_id": (
                snap.detector.e_state.get("controller", {}).get("state_domain_id")
                if isinstance(snap.detector.e_state, Mapping)
                else None
            ),
            "route_plan_id": getattr(route, "route_plan_id", None) if route is not None else None,
            "decision_id": getattr(route, "decision_id", None) if route is not None else None,
            "cfg_fp": getattr(route, "config_fingerprint", None) if route is not None else snap.bundle.cfg_fp,
            "bundle_version": getattr(route, "bundle_version", None) if route is not None else snap.bundle.version,
            "pq_required": pq_required,
            "pq_ok": pq_ok,
            "receipt_required": receipt_required,
            "ledger_required": bool(getattr(route, "ledger_required", False)) if route is not None else snap.policy.ledger_required,
            "attestation_required": attestation_required,
            "audit_ref": audit_ref,
            "receipt_ref": receipt_ref,
            "rate_limit": {
                name: {
                    "zone": getattr(d, "zone", None),
                    "allowed": getattr(d, "allowed", None),
                    "reason": getattr(d, "reason", None),
                    "retry_after_s": getattr(d, "retry_after_s", None),
                }
                for name, d in snap.rate.decisions.items()
            },
        }

    # ------------------------------------------------------------------
    # Artifact emission
    # ------------------------------------------------------------------

    def _issue_security_receipt(
        self,
        *,
        decision: SecurityDecision,
        snap: _EvaluationSnapshot,
        audit_ref: Optional[str],
    ) -> Dict[str, Any]:
        if self._attestor is None:
            raise RuntimeError("attestor unavailable")

        ctx = snap.ctx
        bp = snap.policy.bound_policy

        req_obj = {
            "ts_ns": decision.decision_ts_unix_ns,
            "event_id": decision.event_id,
            "request_id": ctx.request_id,
            "trace_id": ctx.trace_id,
            "subject": {
                "subject_hash": _subject_digest(ctx.subject_id(), snap.bundle.identity_hasher),
                "tenant_id": ctx.tenant_id,
                "principal_hash": (_subject_digest(ctx.principal_id, snap.bundle.identity_hasher) if ctx.principal_id else None),
                "kind": ctx.kind,
                "trust_zone": ctx.trust_zone,
                "route_profile": ctx.route_profile,
                "ip_hash": (_subject_digest(ctx.ip, snap.bundle.identity_hasher) if ctx.ip else None),
                "ctx": ({k: v for k, v in ctx.binding_context().items() if k in _CTX_KEYS} if bool(getattr(bp, "attach_match_context", False)) else None),
            },
        }

        comp_obj = {
            "kind": "security_router",
            "allowed": bool(decision.allowed),
            "action": decision.action,
            "required_action": decision.required_action,
            "enforcement_mode": decision.enforcement_mode,
            "policy_ref": decision.policy_ref,
            "policyset_ref": decision.policyset_ref,
            "policy_digest": decision.policy_digest,
            "reason_codes": list(decision.reason_codes),
            "route": decision.route.to_receipt_dict() if decision.route is not None and hasattr(decision.route, "to_receipt_dict") else None,
            "audit_ref": audit_ref,
            "decision_id": decision.decision_id,
            "route_plan_id": decision.route_plan_id,
        }

        if decision.e_state is not None:
            e_obj = dict(decision.e_state)
        else:
            e_obj = {
                "score": float(decision.risk_score if decision.risk_score is not None else 0.0),
                "decision": decision.action,
                "e_value": float(_coerce_float(getattr(self._base_av, "alpha_base", None)) or 1.0),
                "alpha_alloc": 0.0,
                "alpha_spent": 0.0,
                "budget_remaining": 0.0,
                "policy_digest": decision.policy_digest,
            }

        witness_segments: List[Dict[str, Any]] = [
            {
                "kind": "security_policy",
                "id": _ROUTER_NAME,
                "digest": decision.policy_digest,
                "meta": {
                    "policy_ref": decision.policy_ref,
                    "policyset_ref": decision.policyset_ref,
                },
            }
        ]
        if decision.route_plan_id:
            witness_segments.append(
                {
                    "kind": "route_plan",
                    "id": _ROUTER_NAME,
                    "digest": decision.route_plan_id,
                    "meta": {
                        "decision_id": decision.decision_id,
                        "route_policy_ref": getattr(decision.route, "policy_ref", None) if decision.route is not None else None,
                    },
                }
            )

        witness_tags = [
            "security_router",
            decision.action,
            _safe_label(ctx.kind, default="inference"),
        ]

        meta = {
            "event_type": "security_router.decision",
            "_tcd_event_id": decision.event_id,
            "_tcd_ts_ns": decision.decision_ts_unix_ns,
            "policy_ref": decision.policy_ref,
            "policyset_ref": decision.policyset_ref,
            "policy_digest": decision.policy_digest,
            "route_profile": snap.policy.route_profile,
            "trust_zone": ctx.trust_zone,
            "audit_ref": audit_ref,
            "subject_hash": _subject_digest(ctx.subject_id(), snap.bundle.identity_hasher),
            "instance_id": self._instance_id,
            "config_fingerprint": snap.bundle.cfg_fp,
            "activation_id": snap.bundle.activation.activation_id,
        }

        receipt = self._attestor.issue(
            req_obj=req_obj,
            comp_obj=comp_obj,
            e_obj=e_obj,
            witness_segments=witness_segments,
            witness_tags=witness_tags,
            meta=meta,
        )
        if not isinstance(receipt, Mapping):
            return {}
        out = dict(receipt)
        return {
            "receipt": out.get("receipt"),
            "receipt_body": out.get("receipt_body"),
            "receipt_sig": out.get("receipt_sig"),
            "verify_key": out.get("verify_key"),
            "receipt_integrity": out.get("receipt_integrity"),
            "receipt_secondary": out.get("receipt_secondary"),
            "receipt_sig_secondary": out.get("receipt_sig_secondary"),
        }


    # ------------------------------------------------------------------
    # Integrity / dependency status
    # ------------------------------------------------------------------

    def _dependency_status(self) -> Dict[str, Any]:
        return {
            "policy_store": self._policies is not None,
            "rate_limiter": self._limiter is not None,
            "attestor": self._attestor is not None,
            "detector": self._detector is not None,
            "strategy_router": self._strategy_router is not None,
            "audit_sink": self._audit_sink is not None,
            "telemetry_sink": self._telemetry_sink is not None,
            "ledger_sink": self._ledger_sink is not None,
            "outbox_sink": self._outbox_sink is not None,
        }