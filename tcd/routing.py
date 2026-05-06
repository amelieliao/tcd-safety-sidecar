from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Literal

try:  # pragma: no cover
    from .crypto import Blake3Hash  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover
    Blake3Hash = None  # type: ignore[assignment]


__all__ = [
    "Route",
    "StrategyConfig",
    "StrategyTierPreset",
    "StrategyPolicySpec",
    "StrategyBundleActivation",
    "StrategyPublicConfigView",
    "StrategyBundleDiagnostics",
    "StrategyRouteContext",
    "StrategySignals",
    "StrategySamplingBase",
    "StrategySignalEnvelope",
    "StrategyRouter",
]

# =============================================================================
# Types / constants
# =============================================================================

Profile = Literal["DEV", "PROD", "FINREG", "LOCKDOWN"]
OnConfigError = Literal["use_last_known_good", "fail_closed", "raise", "fallback"]
DeclaredHashAlgorithm = Literal["sha256", "blake3"]
SafeDigestAlgorithm = Literal["sha256"]
SafetyTier = Literal["normal", "elevated", "strict"]
RouterMode = Literal["normal", "last_known_good", "fail_closed", "disabled", "degraded"]
RequiredAction = Literal["allow", "degrade", "block"]
EnforcementMode = Literal["advisory", "must_enforce", "fail_closed"]
RouteIdKind = Literal["plan"]
SignalTrustMode = Literal["trusted", "advisory", "untrusted"]

TrustZone = Literal["internet", "partner", "internal", "admin", "ops", "unknown", "__config_error__"]
RouteProfile = Literal["inference", "batch", "admin", "control", "metrics", "health", "unknown"]
RiskLabel = Literal["low", "normal", "elevated", "high", "critical", "unknown"]

_SCHEMA = "tcd.route.v4"
_ROUTER_NAME = "tcd.routing"
_ROUTER_VERSION = "3.0.0"

_CFG_FP_VERSION = "cfg1"
_ROUTE_PLAN_ID_VERSION = "rp1"
_DECISION_ID_VERSION = "rd1"
_CONTEXT_DIGEST_VERSION = "cx1"
_SIGNAL_DIGEST_VERSION = "sg1"
_ACTIVATION_ID_VERSION = "ac1"
_SAFE_DIGEST_ALG: SafeDigestAlgorithm = "sha256"

_ALLOWED_PROFILES = frozenset({"DEV", "PROD", "FINREG", "LOCKDOWN"})
_ALLOWED_TIERS = frozenset({"normal", "elevated", "strict"})
_ALLOWED_REQUIRED_ACTIONS = frozenset({"allow", "degrade", "block"})
_ALLOWED_ENFORCEMENT = frozenset({"advisory", "must_enforce", "fail_closed"})
_ALLOWED_LATENCY_HINTS = frozenset({"normal", "low_latency", "high_safety"})
_ALLOWED_DECLARED_HASH_ALGS = frozenset({"sha256", "blake3"})

_ALLOWED_TRUST_ZONES_DEFAULT = frozenset({"internet", "partner", "internal", "admin", "ops"})
_ALLOWED_ROUTE_PROFILES_DEFAULT = frozenset({"inference", "batch", "admin", "control", "metrics", "health"})
_ALLOWED_RISK_LABELS_DEFAULT = frozenset({"low", "normal", "elevated", "high", "critical"})
_ALLOWED_THREAT_TAGS_DEFAULT = frozenset(
    {"apt", "insider", "supply_chain", "tool_abuse", "policy_bypass", "data_exfil"}
)
_ALLOWED_AV_LABELS_DEFAULT = frozenset(
    {"low", "normal", "elevated", "high", "strict", "critical", "restricted", "degraded"}
)

_DEFAULT_PROFILE_DEFAULTS = MappingProxyType(
    {
        "inference": "normal",
        "batch": "normal",
        "admin": "strict",
        "control": "strict",
        "metrics": "normal",
        "health": "normal",
    }
)

_DEFAULT_ZONE_DEFAULTS = MappingProxyType(
    {
        "internet": "elevated",
        "partner": "normal",
        "internal": "normal",
        "admin": "strict",
        "ops": "strict",
    }
)

_DEFAULT_RISK_LABEL_DEFAULTS = MappingProxyType(
    {
        "low": "normal",
        "normal": "normal",
        "elevated": "elevated",
        "high": "elevated",
        "critical": "strict",
    }
)

_DEFAULT_AV_STRICT_LABELS = ("strict", "critical", "restricted")
_AV_NON_RISK_LABEL_ALIASES = frozenset({"default", "prod", "dev", "finreg", "lockdown"})

_REASON_CODES = frozenset(
    {
        "ROUTER_DISABLED",
        "ROUTER_LAST_KNOWN_GOOD",
        "ROUTER_FAIL_CLOSED",
        "CFG_ERROR",
        "CFG_ERROR_LKG",
        "CFG_HASH_BACKEND_UNAVAILABLE",
        "STRICT_TEMP_CAP_TIGHTENED",
        "STRICT_TOP_P_CAP_TIGHTENED",
        "STRICT_MAX_TOKENS_TIGHTENED",
        "ELEVATED_MAX_TOKENS_TIGHTENED",
        "ELEVATED_ACTION_TIGHTENED",
        "STRICT_ACTION_TIGHTENED",
        "CRITICAL_ACTION_TIGHTENED",
        "INVALID_TRUST_ZONE",
        "UNKNOWN_TRUST_ZONE",
        "INVALID_ROUTE_PROFILE",
        "UNKNOWN_ROUTE_PROFILE",
        "INVALID_RISK_LABEL",
        "UNKNOWN_RISK_LABEL",
        "UNKNOWN_THREAT_DROPPED",
        "UNKNOWN_AV_LABEL_DROPPED",
        "UNTRUSTED_STRICT_SIGNAL_DOWNGRADED",
        "UNSIGNED_BLOCK_SIGNAL_DOWNGRADED",
        "STALE_SIGNAL_DOWNGRADED",
        "BASELINE_ZONE_ELEVATED",
        "BASELINE_ZONE_STRICT",
        "BASELINE_PROFILE_ELEVATED",
        "BASELINE_PROFILE_STRICT",
        "BASELINE_RISK_ELEVATED",
        "BASELINE_RISK_STRICT",
        "SIGNAL_DECISION_FAIL",
        "SIGNAL_E_TRIGGER",
        "SIGNAL_AV_TRIGGER",
        "SIGNAL_AV_LABEL_STRICT",
        "SIGNAL_RISK_SCORE_HIGH",
        "SIGNAL_RISK_SCORE_CRITICAL",
        "SIGNAL_RISK_LABEL_HIGH",
        "SIGNAL_RISK_LABEL_CRITICAL",
        "SIGNAL_THREAT_APT",
        "SIGNAL_THREAT_INSIDER",
        "SIGNAL_THREAT_SUPPLY_CHAIN",
        "SIGNAL_PQ_UNHEALTHY",
        "ROUTE_NORMAL",
        "ROUTE_ELEVATED",
        "ROUTE_STRICT",
        "CRITICAL_BASIS_BLOCK",
        "BALANCED_ROUTE",
    }
)

_ASCII_CTRL_RE = __import__("re").compile(r"[\x00-\x1F\x7F]")
_SAFE_LABEL_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = __import__("re").compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_ID_RE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#]{0,255}$")

# =============================================================================
# Hardening helpers
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
    s = v[:max_len]
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
        return x if x == x and abs(x) != float("inf") else None
    if type(v) is str:
        s = v.strip()
        if not s or len(s) > 64:
            return None
        try:
            x = float(s)
        except Exception:
            return None
        return x if x == x and abs(x) != float("inf") else None
    return None


def _coerce_int(v: Any) -> Optional[int]:
    if type(v) is int:
        return int(v)
    if type(v) is str:
        s = v.strip()
        if not s or len(s) > 64:
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



def _safe_score(v: Any, *, default: float = 0.0) -> float:
    return _clamp_float(v, default=default, lo=0.0, hi=1.0)


def _normalize_signal_tags(values: Any, *, max_items: int = 8) -> Tuple[str, ...]:
    if values is None:
        return tuple()
    if isinstance(values, str):
        seq: Sequence[Any] = [values]
    elif isinstance(values, (list, tuple, set, frozenset)):
        seq = list(values)
    else:
        return tuple()
    return _normalize_label_tuple(seq, max_items=max_items)

def _safe_oneof(v: Any, *, allowed: Sequence[str], default: str, lower: bool = True) -> str:
    s = _strip_unsafe_text(v, max_len=64)
    if lower:
        s = s.lower()
        allowed_set = {x.lower() for x in allowed}
    else:
        allowed_set = set(allowed)
    if s in allowed_set:
        return s
    return default


def _stable_float_for_id(x: float) -> str:
    if not isinstance(x, float):
        x = float(x)
    if not (x == x) or abs(x) == float("inf"):
        return "0"
    s = f"{x:.12f}"
    s = s.rstrip("0").rstrip(".")
    return s if s else "0"


def _stable_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int)):
        return obj
    if isinstance(obj, float):
        return _stable_float_for_id(float(obj))
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
    return _safe_name(type(obj).__name__, default="object")


def _canon_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        _stable_jsonable(obj),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def _safe_digest_hex(*, ctx: str, payload: Mapping[str, Any], out_hex: int) -> str:
    raw = ctx.encode("utf-8", errors="strict") + b"\x00" + _canon_json_bytes(payload)
    return hashlib.sha256(raw).hexdigest()[:out_hex]


def _normalize_label_tuple(
    values: Any,
    *,
    default_values: Sequence[str] = (),
    max_items: int = 32,
    allowed: Optional[Sequence[str]] = None,
) -> Tuple[str, ...]:
    out: List[str] = []
    seen = set()

    if isinstance(values, (tuple, list)):
        seq = list(values)
    elif type(values) is str:
        seq = [values]
    else:
        seq = list(default_values)

    allowed_set = {str(x).lower() for x in allowed} if allowed is not None else None

    for item in seq:
        if len(out) >= max_items:
            break
        s = _safe_label(item, default="")
        if not s:
            continue
        if allowed_set is not None and s not in allowed_set:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)

    if not out and default_values:
        for item in default_values:
            if len(out) >= max_items:
                break
            s = _safe_label(item, default="")
            if not s:
                continue
            if allowed_set is not None and s not in allowed_set:
                continue
            if s in seen:
                continue
            seen.add(s)
            out.append(s)

    return tuple(out)


def _normalize_tags(tags: Sequence[str], *, max_items: int) -> Tuple[str, ...]:
    out: List[str] = []
    seen = set()
    for t in tags:
        if len(out) >= max_items:
            break
        s = _strip_unsafe_text(t, max_len=128)
        if not s:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
    return tuple(out)


def _normalize_reason_codes(codes: Sequence[str], *, max_items: int) -> Tuple[str, ...]:
    out: List[str] = []
    seen = set()
    for c in codes:
        s = _strip_unsafe_text(c, max_len=64)
        if not s:
            continue
        if s not in _REASON_CODES:
            continue
        if s in seen:
            continue
        seen.add(s)
        out.append(s)
        if len(out) >= max_items:
            break
    return tuple(out)


def _tier_rank(tier: str) -> int:
    if tier == "strict":
        return 2
    if tier == "elevated":
        return 1
    return 0


def _tier_max(a: SafetyTier, b: SafetyTier) -> SafetyTier:
    return a if _tier_rank(a) >= _tier_rank(b) else b


def _safe_tier(v: Any, *, default: SafetyTier) -> SafetyTier:
    s = _safe_label(v, default=default)
    if s not in _ALLOWED_TIERS:
        return default
    return s  # type: ignore[return-value]


def _required_action_rank(action: str) -> int:
    if action == "block":
        return 2
    if action == "degrade":
        return 1
    return 0


def _action_max(a: RequiredAction, b: RequiredAction) -> RequiredAction:
    return a if _required_action_rank(a) >= _required_action_rank(b) else b


# =============================================================================
# Public structured inputs / outputs
# =============================================================================


@dataclass(frozen=True)
class StrategySignalEnvelope:
    source: str = "legacy_implicit"
    trusted: bool = True
    signed: bool = False
    signer_kid: Optional[str] = None
    source_cfg_fp: Optional[str] = None
    source_policy_ref: Optional[str] = None
    freshness_ms: Optional[int] = None
    replay_checked: Optional[bool] = None

    def normalized(self) -> "StrategySignalEnvelope":
        return StrategySignalEnvelope(
            source=_safe_name(self.source, default="legacy_implicit"),
            trusted=_coerce_bool(self.trusted, default=True),
            signed=_coerce_bool(self.signed, default=False),
            signer_kid=_safe_id(self.signer_kid, default=None, max_len=64),
            source_cfg_fp=_safe_id(self.source_cfg_fp, default=None, max_len=128),
            source_policy_ref=_safe_id(self.source_policy_ref, default=None, max_len=128),
            freshness_ms=(
                _clamp_int(self.freshness_ms, default=0, lo=0, hi=86_400_000)
                if self.freshness_ms is not None
                else None
            ),
            replay_checked=(
                None
                if self.replay_checked is None
                else _coerce_bool(self.replay_checked, default=False)
            ),
        )


@dataclass(frozen=True)
class StrategyRouteContext:
    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    tenant_id: Optional[str] = None
    principal_id: Optional[str] = None
    trust_zone: str = "internet"
    route_profile: str = "inference"

    def normalized(self) -> "StrategyRouteContext":
        return StrategyRouteContext(
            request_id=_safe_id(self.request_id, default=None, max_len=128),
            trace_id=_safe_id(self.trace_id, default=None, max_len=128),
            tenant_id=_safe_id(self.tenant_id, default=None, max_len=128),
            principal_id=_safe_id(self.principal_id, default=None, max_len=128),
            trust_zone=_safe_label(self.trust_zone, default="internet"),
            route_profile=_safe_label(self.route_profile, default="inference"),
        )


@dataclass(frozen=True)
class StrategySignals:
    score: float
    risk_label: str = "normal"
    decision_fail: bool = False
    e_triggered: bool = False
    pq_unhealthy: bool = False
    av_label: Optional[str] = None
    av_trigger: Optional[bool] = None
    threat_tags: Tuple[str, ...] = ()
    controller_mode: Optional[str] = None
    guarantee_scope: Optional[str] = None

    def normalized(self) -> "StrategySignals":
        return StrategySignals(
            score=_safe_score(self.score),
            risk_label=_safe_label(self.risk_label, default="normal"),
            decision_fail=_coerce_bool(self.decision_fail, default=False),
            e_triggered=_coerce_bool(self.e_triggered, default=False),
            pq_unhealthy=_coerce_bool(self.pq_unhealthy, default=False),
            av_label=_safe_label(self.av_label, default="") or None if isinstance(self.av_label, str) else None,
            av_trigger=None if self.av_trigger is None else _coerce_bool(self.av_trigger, default=False),
            threat_tags=_normalize_signal_tags(self.threat_tags, max_items=8),
            controller_mode=_safe_label(self.controller_mode, default="") or None if isinstance(self.controller_mode, str) else None,
            guarantee_scope=_safe_label(self.guarantee_scope, default="") or None if isinstance(self.guarantee_scope, str) else None,
        )


@dataclass(frozen=True)
class StrategySamplingBase:
    temperature: float = 1.0
    top_p: float = 1.0
    max_tokens: Optional[int] = None

    def normalized(self) -> "StrategySamplingBase":
        return StrategySamplingBase(
            temperature=_clamp_float(self.temperature, default=1.0, lo=0.0, hi=10.0),
            top_p=_clamp_float(self.top_p, default=1.0, lo=0.0, hi=1.0),
            max_tokens=(
                _clamp_int(self.max_tokens, default=1, lo=1, hi=10_000_000)
                if self.max_tokens is not None
                else None
            ),
        )


@dataclass(frozen=True)
class StrategyTierPreset:
    safety_tier: SafetyTier
    decoder: str
    latency_hint: str
    required_action: RequiredAction
    enforcement_mode: EnforcementMode
    temperature: Optional[float]
    top_p: Optional[float]
    max_tokens: Optional[int]
    tool_calls_allowed: bool
    retrieval_allowed: bool
    streaming_allowed: bool
    external_calls_allowed: bool
    response_policy: str
    receipt_required: bool
    ledger_required: bool
    attestation_required: bool


@dataclass(frozen=True)
class StrategyPolicySpec:
    schema_version: int
    profile: Profile
    enabled: bool
    on_config_error: OnConfigError

    policy_ref: Optional[str]
    policyset_ref: Optional[str]
    patch_id: Optional[str]
    change_ticket_id: Optional[str]
    activated_by: Optional[str]
    approved_by: Tuple[str, ...]

    declared_hash_algorithm: DeclaredHashAlgorithm
    runtime_safe_digest_algorithm: SafeDigestAlgorithm

    min_temperature: float
    max_temperature: float
    min_top_p: float
    max_top_p: float

    degrade_temp_factor: float
    degrade_top_p_factor: float
    soft_degrade_temp_factor: float
    soft_degrade_top_p_factor: float

    strict_temp_cap: float
    strict_top_p_cap: float
    elevated_temp_cap: Optional[float]
    elevated_top_p_cap: Optional[float]

    high_risk_threshold: float
    critical_risk_threshold: float

    profile_defaults: Mapping[str, SafetyTier]
    zone_defaults: Mapping[str, SafetyTier]
    risk_label_defaults: Mapping[str, SafetyTier]

    allowed_trust_zones: Tuple[str, ...]
    allowed_route_profiles: Tuple[str, ...]
    allowed_risk_labels: Tuple[str, ...]
    allowed_threat_tags: Tuple[str, ...]
    allowed_av_labels: Tuple[str, ...]

    force_strict_on_apt: bool
    force_strict_on_insider: bool
    force_strict_on_supply_chain: bool
    force_strict_on_pq_unhealthy: bool
    force_strict_on_decision_fail: bool
    force_strict_on_e_trigger: bool
    force_strict_on_av_trigger: bool
    av_strict_labels: Tuple[str, ...]

    require_trusted_signal_for_strict: bool
    require_signed_signal_for_block: bool
    max_signal_freshness_ms: Optional[int]
    critical_basis_force_block: bool

    normal_preset: StrategyTierPreset
    elevated_preset: StrategyTierPreset
    strict_preset: StrategyTierPreset

    max_tags: int
    max_reason_codes: int


@dataclass(frozen=True)
class StrategyBundleActivation:
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
class Route:
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

    safety_tier: SafetyTier
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

    @property
    def route_config_fingerprint(self) -> str:
        return self.config_fingerprint

    @property
    def cfg_fp(self) -> str:
        return self.config_fingerprint

    @property
    def config_fingerprint_kind(self) -> str:
        return "route"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema": self.schema,
            "router": self.router,
            "version": self.version,
            "instance_id": self.instance_id,
            "activation_id": self.activation_id,
            "config_fingerprint": self.config_fingerprint,
            "route_config_fingerprint": self.config_fingerprint,
            "cfg_fp": self.config_fingerprint,
            "config_fingerprint_kind": "route",
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
            "route_config_fingerprint": self.config_fingerprint,
            "cfg_fp": self.config_fingerprint,
            "config_fingerprint_kind": "route",
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
            "type": "tcd.route.decision",
            "decision_id": self.decision_id,
            "route_plan_id": self.route_plan_id,
            "decision_seq": self.decision_seq,
            "decision_ts_unix_ns": self.decision_ts_unix_ns,
            "router_mode": self.router_mode,
            "activation_id": self.activation_id,
            "config_fingerprint": self.config_fingerprint,
            "route_config_fingerprint": self.config_fingerprint,
            "cfg_fp": self.config_fingerprint,
            "config_fingerprint_kind": "route",
            "bundle_version": self.bundle_version,
            "policy_ref": self.policy_ref,
            "policyset_ref": self.policyset_ref,
            "patch_id": self.patch_id,
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
        }


@dataclass(frozen=True)
class StrategyPublicConfigView:
    cfg_fp: str
    bundle_version: int
    activation_id: str
    bundle_updated_at_unix_ns: int
    profile: Profile
    enabled: bool
    policy_ref: Optional[str]
    policyset_ref: Optional[str]
    patch_id: Optional[str]
    declared_hash_algorithm: DeclaredHashAlgorithm
    runtime_safe_digest_algorithm: SafeDigestAlgorithm
    has_errors: bool
    has_warnings: bool
    router_mode: RouterMode


@dataclass(frozen=True)
class StrategyBundleDiagnostics:
    active_cfg_fp: str
    active_bundle_version: int
    active_activation_id: str
    active_updated_at_unix_ns: int
    profile: Profile
    enabled: bool
    policy_ref: Optional[str]
    policyset_ref: Optional[str]
    patch_id: Optional[str]
    declared_hash_algorithm: DeclaredHashAlgorithm
    runtime_safe_digest_algorithm: SafeDigestAlgorithm
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    using_last_known_good: bool
    last_known_good_cfg_fp: Optional[str]
    last_rejected_cfg_fp: Optional[str]


# =============================================================================
# External mutable config
# =============================================================================


@dataclass
class StrategyConfig:
    """
    External mutable routing config.

    The router compiles this into an immutable bundle. Runtime never reads this
    object directly after compilation.

    Design goals:
      - safe defaults
      - strict vocabulary
      - strong route contract
      - last-known-good governance
      - stable config fingerprint independent of optional hash backends
    """

    schema_version: int = 4
    enabled: bool = True
    profile: Profile = "PROD"
    on_config_error: OnConfigError = "use_last_known_good"

    # Policy / rollout provenance
    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    patch_id: Optional[str] = None
    change_ticket_id: Optional[str] = None
    activated_by: Optional[str] = None
    approved_by: Tuple[str, ...] = ()

    # Declared hash preference (observational / governance only)
    hash_algorithm: DeclaredHashAlgorithm = "sha256"

    # Sampling bounds
    min_temperature: float = 0.1
    max_temperature: float = 2.0
    min_top_p: float = 0.1
    max_top_p: float = 1.0

    # Relative degrade factors
    degrade_temp_factor: float = 0.7
    degrade_top_p_factor: float = 0.85
    soft_degrade_temp_factor: float = 0.85
    soft_degrade_top_p_factor: float = 0.9

    # Absolute caps / optional presets
    strict_temp_cap: float = 0.7
    strict_top_p_cap: float = 0.9
    elevated_temp_cap: Optional[float] = None
    elevated_top_p_cap: Optional[float] = None

    normal_temperature: Optional[float] = None
    normal_top_p: Optional[float] = None
    elevated_temperature: Optional[float] = None
    elevated_top_p: Optional[float] = None
    strict_temperature: Optional[float] = None
    strict_top_p: Optional[float] = None

    # Risk thresholds
    high_risk_threshold: float = 0.95
    critical_risk_threshold: float = 0.99

    # Token caps
    normal_max_tokens: Optional[int] = None
    elevated_safety_max_tokens: Optional[int] = None
    strict_safety_max_tokens: Optional[int] = None

    # Allowed vocabularies
    allowed_trust_zones: Optional[Tuple[str, ...]] = None
    allowed_route_profiles: Optional[Tuple[str, ...]] = None
    allowed_risk_labels: Optional[Tuple[str, ...]] = None
    allowed_threat_tags: Optional[Tuple[str, ...]] = None
    allowed_av_labels: Optional[Tuple[str, ...]] = None

    # Baseline tier maps
    profile_defaults: Dict[str, str] = field(default_factory=lambda: dict(_DEFAULT_PROFILE_DEFAULTS))
    zone_defaults: Dict[str, str] = field(default_factory=lambda: dict(_DEFAULT_ZONE_DEFAULTS))
    risk_label_defaults: Dict[str, str] = field(default_factory=lambda: dict(_DEFAULT_RISK_LABEL_DEFAULTS))

    # Escalation flags
    force_strict_on_apt: bool = True
    force_strict_on_insider: bool = True
    force_strict_on_supply_chain: bool = True
    force_strict_on_pq_unhealthy: bool = True
    force_strict_on_decision_fail: bool = True
    force_strict_on_e_trigger: bool = True
    force_strict_on_av_trigger: bool = True
    av_strict_labels: Tuple[str, ...] = _DEFAULT_AV_STRICT_LABELS

    # Signal provenance governance
    require_trusted_signal_for_strict: bool = False
    require_signed_signal_for_block: bool = False
    max_signal_freshness_ms: Optional[int] = None
    critical_basis_force_block: bool = True

    # Decoder / route presets
    default_decoder: str = "default"
    elevated_decoder: str = "cautious"
    strict_decoder: str = "safe"

    normal_latency_hint: str = "normal"
    elevated_latency_hint: str = "normal"
    strict_latency_hint: str = "high_safety"

    normal_action: RequiredAction = "allow"
    elevated_action: RequiredAction = "degrade"
    strict_action: RequiredAction = "degrade"
    critical_action: RequiredAction = "block"

    normal_enforcement_mode: EnforcementMode = "advisory"
    elevated_enforcement_mode: EnforcementMode = "must_enforce"
    strict_enforcement_mode: EnforcementMode = "must_enforce"
    critical_enforcement_mode: EnforcementMode = "must_enforce"

    # Route contract
    normal_tool_calls_allowed: bool = True
    elevated_tool_calls_allowed: bool = True
    strict_tool_calls_allowed: bool = False

    normal_retrieval_allowed: bool = True
    elevated_retrieval_allowed: bool = True
    strict_retrieval_allowed: bool = False

    normal_streaming_allowed: bool = True
    elevated_streaming_allowed: bool = True
    strict_streaming_allowed: bool = False

    normal_external_calls_allowed: bool = True
    elevated_external_calls_allowed: bool = False
    strict_external_calls_allowed: bool = False

    normal_response_policy: str = "standard"
    elevated_response_policy: str = "cautious"
    strict_response_policy: str = "restricted"

    normal_receipt_required: bool = False
    elevated_receipt_required: bool = False
    strict_receipt_required: bool = True

    normal_ledger_required: bool = False
    elevated_ledger_required: bool = False
    strict_ledger_required: bool = True

    normal_attestation_required: bool = False
    elevated_attestation_required: bool = False
    strict_attestation_required: bool = True

    # Output shaping
    max_tags: int = 24
    max_reason_codes: int = 16

    def normalized_copy(self) -> "StrategyConfig":
        c = StrategyConfig()

        c.schema_version = _clamp_int(self.schema_version, default=4, lo=1, hi=1_000_000)

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
        c.approved_by = _normalize_label_tuple(self.approved_by, max_items=16)

        alg = _safe_label(self.hash_algorithm, default="sha256")
        if alg not in _ALLOWED_DECLARED_HASH_ALGS:
            alg = "sha256"
        c.hash_algorithm = alg  # type: ignore[assignment]

        c.min_temperature = _clamp_float(self.min_temperature, default=0.1, lo=0.0, hi=10.0)
        c.max_temperature = _clamp_float(self.max_temperature, default=2.0, lo=0.0, hi=10.0)
        if c.max_temperature < c.min_temperature:
            c.min_temperature, c.max_temperature = c.max_temperature, c.min_temperature

        c.min_top_p = _clamp_float(self.min_top_p, default=0.1, lo=0.0, hi=1.0)
        c.max_top_p = _clamp_float(self.max_top_p, default=1.0, lo=0.0, hi=1.0)
        if c.max_top_p < c.min_top_p:
            c.min_top_p, c.max_top_p = c.max_top_p, c.min_top_p

        c.degrade_temp_factor = _clamp_float(self.degrade_temp_factor, default=0.7, lo=0.0, hi=1.0)
        c.degrade_top_p_factor = _clamp_float(self.degrade_top_p_factor, default=0.85, lo=0.0, hi=1.0)
        c.soft_degrade_temp_factor = _clamp_float(self.soft_degrade_temp_factor, default=0.85, lo=0.0, hi=1.0)
        c.soft_degrade_top_p_factor = _clamp_float(self.soft_degrade_top_p_factor, default=0.9, lo=0.0, hi=1.0)

        c.strict_temp_cap = _clamp_float(
            self.strict_temp_cap,
            default=min(0.7, c.max_temperature),
            lo=c.min_temperature,
            hi=c.max_temperature,
        )
        c.strict_top_p_cap = _clamp_float(
            self.strict_top_p_cap,
            default=min(0.9, c.max_top_p),
            lo=c.min_top_p,
            hi=c.max_top_p,
        )
        c.elevated_temp_cap = (
            _clamp_float(self.elevated_temp_cap, default=c.max_temperature, lo=c.min_temperature, hi=c.max_temperature)
            if self.elevated_temp_cap is not None
            else None
        )
        c.elevated_top_p_cap = (
            _clamp_float(self.elevated_top_p_cap, default=c.max_top_p, lo=c.min_top_p, hi=c.max_top_p)
            if self.elevated_top_p_cap is not None
            else None
        )

        c.normal_temperature = (
            _clamp_float(self.normal_temperature, default=1.0, lo=c.min_temperature, hi=c.max_temperature)
            if self.normal_temperature is not None
            else None
        )
        c.normal_top_p = (
            _clamp_float(self.normal_top_p, default=1.0, lo=c.min_top_p, hi=c.max_top_p)
            if self.normal_top_p is not None
            else None
        )
        c.elevated_temperature = (
            _clamp_float(self.elevated_temperature, default=1.0, lo=c.min_temperature, hi=c.max_temperature)
            if self.elevated_temperature is not None
            else None
        )
        c.elevated_top_p = (
            _clamp_float(self.elevated_top_p, default=1.0, lo=c.min_top_p, hi=c.max_top_p)
            if self.elevated_top_p is not None
            else None
        )
        c.strict_temperature = (
            _clamp_float(self.strict_temperature, default=1.0, lo=c.min_temperature, hi=c.max_temperature)
            if self.strict_temperature is not None
            else None
        )
        c.strict_top_p = (
            _clamp_float(self.strict_top_p, default=1.0, lo=c.min_top_p, hi=c.max_top_p)
            if self.strict_top_p is not None
            else None
        )

        c.high_risk_threshold = _clamp_float(self.high_risk_threshold, default=0.95, lo=0.0, hi=1.0)
        c.critical_risk_threshold = _clamp_float(self.critical_risk_threshold, default=0.99, lo=0.0, hi=1.0)
        if c.critical_risk_threshold < c.high_risk_threshold:
            c.critical_risk_threshold = c.high_risk_threshold

        c.normal_max_tokens = (
            _clamp_int(self.normal_max_tokens, default=1, lo=1, hi=10_000_000)
            if self.normal_max_tokens is not None
            else None
        )
        c.elevated_safety_max_tokens = (
            _clamp_int(self.elevated_safety_max_tokens, default=1, lo=1, hi=10_000_000)
            if self.elevated_safety_max_tokens is not None
            else None
        )
        c.strict_safety_max_tokens = (
            _clamp_int(self.strict_safety_max_tokens, default=1, lo=1, hi=10_000_000)
            if self.strict_safety_max_tokens is not None
            else None
        )

        c.allowed_trust_zones = _normalize_label_tuple(
            self.allowed_trust_zones,
            default_values=tuple(sorted(_ALLOWED_TRUST_ZONES_DEFAULT)),
            max_items=32,
            allowed=tuple(sorted(_ALLOWED_TRUST_ZONES_DEFAULT)),
        )
        c.allowed_route_profiles = _normalize_label_tuple(
            self.allowed_route_profiles,
            default_values=tuple(sorted(_ALLOWED_ROUTE_PROFILES_DEFAULT)),
            max_items=32,
            allowed=tuple(sorted(_ALLOWED_ROUTE_PROFILES_DEFAULT)),
        )
        c.allowed_risk_labels = _normalize_label_tuple(
            self.allowed_risk_labels,
            default_values=tuple(sorted(_ALLOWED_RISK_LABELS_DEFAULT)),
            max_items=32,
            allowed=tuple(sorted(_ALLOWED_RISK_LABELS_DEFAULT)),
        )
        c.allowed_threat_tags = _normalize_label_tuple(
            self.allowed_threat_tags,
            default_values=tuple(sorted(_ALLOWED_THREAT_TAGS_DEFAULT)),
            max_items=32,
            allowed=tuple(sorted(_ALLOWED_THREAT_TAGS_DEFAULT)),
        )
        c.allowed_av_labels = _normalize_label_tuple(
            self.allowed_av_labels,
            default_values=tuple(sorted(_ALLOWED_AV_LABELS_DEFAULT)),
            max_items=32,
            allowed=tuple(sorted(_ALLOWED_AV_LABELS_DEFAULT)),
        )

        c.profile_defaults = {}
        for k, v in (self.profile_defaults or {}).items():
            kk = _safe_label(k, default="")
            if kk and kk in c.allowed_route_profiles:
                c.profile_defaults[kk] = _safe_tier(v, default="normal")
        for k, v in _DEFAULT_PROFILE_DEFAULTS.items():
            if k not in c.profile_defaults:
                c.profile_defaults[k] = _safe_tier(v, default="normal")

        c.zone_defaults = {}
        for k, v in (self.zone_defaults or {}).items():
            kk = _safe_label(k, default="")
            if kk and kk in c.allowed_trust_zones:
                c.zone_defaults[kk] = _safe_tier(v, default="normal")
        for k, v in _DEFAULT_ZONE_DEFAULTS.items():
            if k not in c.zone_defaults:
                c.zone_defaults[k] = _safe_tier(v, default="normal")

        c.risk_label_defaults = {}
        for k, v in (self.risk_label_defaults or {}).items():
            kk = _safe_label(k, default="")
            if kk and kk in c.allowed_risk_labels:
                c.risk_label_defaults[kk] = _safe_tier(v, default="normal")
        for k, v in _DEFAULT_RISK_LABEL_DEFAULTS.items():
            if k not in c.risk_label_defaults:
                c.risk_label_defaults[k] = _safe_tier(v, default="normal")

        c.force_strict_on_apt = bool(self.force_strict_on_apt)
        c.force_strict_on_insider = bool(self.force_strict_on_insider)
        c.force_strict_on_supply_chain = bool(self.force_strict_on_supply_chain)
        c.force_strict_on_pq_unhealthy = bool(self.force_strict_on_pq_unhealthy)
        c.force_strict_on_decision_fail = bool(self.force_strict_on_decision_fail)
        c.force_strict_on_e_trigger = bool(self.force_strict_on_e_trigger)
        c.force_strict_on_av_trigger = bool(self.force_strict_on_av_trigger)
        c.av_strict_labels = _normalize_label_tuple(
            self.av_strict_labels,
            default_values=_DEFAULT_AV_STRICT_LABELS,
            max_items=16,
            allowed=c.allowed_av_labels,
        )

        c.require_trusted_signal_for_strict = bool(self.require_trusted_signal_for_strict)
        c.require_signed_signal_for_block = bool(self.require_signed_signal_for_block)
        c.max_signal_freshness_ms = (
            _clamp_int(self.max_signal_freshness_ms, default=0, lo=0, hi=86_400_000)
            if self.max_signal_freshness_ms is not None
            else None
        )
        c.critical_basis_force_block = bool(self.critical_basis_force_block)

        c.default_decoder = _safe_name(self.default_decoder, default="default")
        c.elevated_decoder = _safe_name(self.elevated_decoder, default="cautious")
        c.strict_decoder = _safe_name(self.strict_decoder, default="safe")

        c.normal_latency_hint = _safe_oneof(self.normal_latency_hint, allowed=tuple(_ALLOWED_LATENCY_HINTS), default="normal")
        c.elevated_latency_hint = _safe_oneof(self.elevated_latency_hint, allowed=tuple(_ALLOWED_LATENCY_HINTS), default="normal")
        c.strict_latency_hint = _safe_oneof(self.strict_latency_hint, allowed=tuple(_ALLOWED_LATENCY_HINTS), default="high_safety")

        c.normal_action = _safe_oneof(self.normal_action, allowed=tuple(_ALLOWED_REQUIRED_ACTIONS), default="allow")  # type: ignore[assignment]
        c.elevated_action = _safe_oneof(self.elevated_action, allowed=tuple(_ALLOWED_REQUIRED_ACTIONS), default="degrade")  # type: ignore[assignment]
        c.strict_action = _safe_oneof(self.strict_action, allowed=tuple(_ALLOWED_REQUIRED_ACTIONS), default="degrade")  # type: ignore[assignment]
        c.critical_action = _safe_oneof(self.critical_action, allowed=tuple(_ALLOWED_REQUIRED_ACTIONS), default="block")  # type: ignore[assignment]

        c.normal_enforcement_mode = _safe_oneof(
            self.normal_enforcement_mode,
            allowed=tuple(_ALLOWED_ENFORCEMENT),
            default="advisory",
        )  # type: ignore[assignment]
        c.elevated_enforcement_mode = _safe_oneof(
            self.elevated_enforcement_mode,
            allowed=tuple(_ALLOWED_ENFORCEMENT),
            default="must_enforce",
        )  # type: ignore[assignment]
        c.strict_enforcement_mode = _safe_oneof(
            self.strict_enforcement_mode,
            allowed=tuple(_ALLOWED_ENFORCEMENT),
            default="must_enforce",
        )  # type: ignore[assignment]
        c.critical_enforcement_mode = _safe_oneof(
            self.critical_enforcement_mode,
            allowed=tuple(_ALLOWED_ENFORCEMENT),
            default="must_enforce",
        )  # type: ignore[assignment]

        c.normal_tool_calls_allowed = bool(self.normal_tool_calls_allowed)
        c.elevated_tool_calls_allowed = bool(self.elevated_tool_calls_allowed)
        c.strict_tool_calls_allowed = bool(self.strict_tool_calls_allowed)

        c.normal_retrieval_allowed = bool(self.normal_retrieval_allowed)
        c.elevated_retrieval_allowed = bool(self.elevated_retrieval_allowed)
        c.strict_retrieval_allowed = bool(self.strict_retrieval_allowed)

        c.normal_streaming_allowed = bool(self.normal_streaming_allowed)
        c.elevated_streaming_allowed = bool(self.elevated_streaming_allowed)
        c.strict_streaming_allowed = bool(self.strict_streaming_allowed)

        c.normal_external_calls_allowed = bool(self.normal_external_calls_allowed)
        c.elevated_external_calls_allowed = bool(self.elevated_external_calls_allowed)
        c.strict_external_calls_allowed = bool(self.strict_external_calls_allowed)

        c.normal_response_policy = _safe_label(self.normal_response_policy, default="standard")
        c.elevated_response_policy = _safe_label(self.elevated_response_policy, default="cautious")
        c.strict_response_policy = _safe_label(self.strict_response_policy, default="restricted")

        c.normal_receipt_required = bool(self.normal_receipt_required)
        c.elevated_receipt_required = bool(self.elevated_receipt_required)
        c.strict_receipt_required = bool(self.strict_receipt_required)

        c.normal_ledger_required = bool(self.normal_ledger_required)
        c.elevated_ledger_required = bool(self.elevated_ledger_required)
        c.strict_ledger_required = bool(self.strict_ledger_required)

        c.normal_attestation_required = bool(self.normal_attestation_required)
        c.elevated_attestation_required = bool(self.elevated_attestation_required)
        c.strict_attestation_required = bool(self.strict_attestation_required)

        c.max_tags = _clamp_int(self.max_tags, default=24, lo=1, hi=256)
        c.max_reason_codes = _clamp_int(self.max_reason_codes, default=16, lo=1, hi=64)

        # Profile-aware tightening
        if c.profile in {"FINREG", "LOCKDOWN"}:
            c.require_trusted_signal_for_strict = True
            c.require_signed_signal_for_block = True
            if c.elevated_action == "allow":
                c.elevated_action = "degrade"  # type: ignore[assignment]
            if c.strict_action == "allow":
                c.strict_action = "degrade"  # type: ignore[assignment]
            c.critical_action = "block"  # type: ignore[assignment]
            c.strict_receipt_required = True
            c.strict_ledger_required = True
            c.strict_attestation_required = True
            c.strict_tool_calls_allowed = False
            c.strict_retrieval_allowed = False
            c.strict_streaming_allowed = False
            c.strict_external_calls_allowed = False

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
            "hash_algorithm": c.hash_algorithm,
            "min_temperature": c.min_temperature,
            "max_temperature": c.max_temperature,
            "min_top_p": c.min_top_p,
            "max_top_p": c.max_top_p,
            "degrade_temp_factor": c.degrade_temp_factor,
            "degrade_top_p_factor": c.degrade_top_p_factor,
            "soft_degrade_temp_factor": c.soft_degrade_temp_factor,
            "soft_degrade_top_p_factor": c.soft_degrade_top_p_factor,
            "strict_temp_cap": c.strict_temp_cap,
            "strict_top_p_cap": c.strict_top_p_cap,
            "elevated_temp_cap": c.elevated_temp_cap,
            "elevated_top_p_cap": c.elevated_top_p_cap,
            "normal_temperature": c.normal_temperature,
            "normal_top_p": c.normal_top_p,
            "elevated_temperature": c.elevated_temperature,
            "elevated_top_p": c.elevated_top_p,
            "strict_temperature": c.strict_temperature,
            "strict_top_p": c.strict_top_p,
            "high_risk_threshold": c.high_risk_threshold,
            "critical_risk_threshold": c.critical_risk_threshold,
            "normal_max_tokens": c.normal_max_tokens,
            "elevated_safety_max_tokens": c.elevated_safety_max_tokens,
            "strict_safety_max_tokens": c.strict_safety_max_tokens,
            "allowed_trust_zones": list(c.allowed_trust_zones),
            "allowed_route_profiles": list(c.allowed_route_profiles),
            "allowed_risk_labels": list(c.allowed_risk_labels),
            "allowed_threat_tags": list(c.allowed_threat_tags),
            "allowed_av_labels": list(c.allowed_av_labels),
            "profile_defaults": dict(sorted(c.profile_defaults.items())),
            "zone_defaults": dict(sorted(c.zone_defaults.items())),
            "risk_label_defaults": dict(sorted(c.risk_label_defaults.items())),
            "force_strict_on_apt": c.force_strict_on_apt,
            "force_strict_on_insider": c.force_strict_on_insider,
            "force_strict_on_supply_chain": c.force_strict_on_supply_chain,
            "force_strict_on_pq_unhealthy": c.force_strict_on_pq_unhealthy,
            "force_strict_on_decision_fail": c.force_strict_on_decision_fail,
            "force_strict_on_e_trigger": c.force_strict_on_e_trigger,
            "force_strict_on_av_trigger": c.force_strict_on_av_trigger,
            "av_strict_labels": list(c.av_strict_labels),
            "require_trusted_signal_for_strict": c.require_trusted_signal_for_strict,
            "require_signed_signal_for_block": c.require_signed_signal_for_block,
            "max_signal_freshness_ms": c.max_signal_freshness_ms,
            "critical_basis_force_block": c.critical_basis_force_block,
            "default_decoder": c.default_decoder,
            "elevated_decoder": c.elevated_decoder,
            "strict_decoder": c.strict_decoder,
            "normal_latency_hint": c.normal_latency_hint,
            "elevated_latency_hint": c.elevated_latency_hint,
            "strict_latency_hint": c.strict_latency_hint,
            "normal_action": c.normal_action,
            "elevated_action": c.elevated_action,
            "strict_action": c.strict_action,
            "critical_action": c.critical_action,
            "normal_enforcement_mode": c.normal_enforcement_mode,
            "elevated_enforcement_mode": c.elevated_enforcement_mode,
            "strict_enforcement_mode": c.strict_enforcement_mode,
            "critical_enforcement_mode": c.critical_enforcement_mode,
            "normal_tool_calls_allowed": c.normal_tool_calls_allowed,
            "elevated_tool_calls_allowed": c.elevated_tool_calls_allowed,
            "strict_tool_calls_allowed": c.strict_tool_calls_allowed,
            "normal_retrieval_allowed": c.normal_retrieval_allowed,
            "elevated_retrieval_allowed": c.elevated_retrieval_allowed,
            "strict_retrieval_allowed": c.strict_retrieval_allowed,
            "normal_streaming_allowed": c.normal_streaming_allowed,
            "elevated_streaming_allowed": c.elevated_streaming_allowed,
            "strict_streaming_allowed": c.strict_streaming_allowed,
            "normal_external_calls_allowed": c.normal_external_calls_allowed,
            "elevated_external_calls_allowed": c.elevated_external_calls_allowed,
            "strict_external_calls_allowed": c.strict_external_calls_allowed,
            "normal_response_policy": c.normal_response_policy,
            "elevated_response_policy": c.elevated_response_policy,
            "strict_response_policy": c.strict_response_policy,
            "normal_receipt_required": c.normal_receipt_required,
            "elevated_receipt_required": c.elevated_receipt_required,
            "strict_receipt_required": c.strict_receipt_required,
            "normal_ledger_required": c.normal_ledger_required,
            "elevated_ledger_required": c.elevated_ledger_required,
            "strict_ledger_required": c.strict_ledger_required,
            "normal_attestation_required": c.normal_attestation_required,
            "elevated_attestation_required": c.elevated_attestation_required,
            "strict_attestation_required": c.strict_attestation_required,
            "max_tags": c.max_tags,
            "max_reason_codes": c.max_reason_codes,
        }

    def fingerprint(self) -> str:
        payload = self.to_public_dict()
        digest = _safe_digest_hex(ctx="tcd:route:cfg", payload=payload, out_hex=64)
        return f"{_CFG_FP_VERSION}:{_SAFE_DIGEST_ALG}:{digest}"


# =============================================================================
# Internal immutable bundle
# =============================================================================


@dataclass(frozen=True)
class _CompiledBundle:
    version: int
    updated_at_unix_ns: int
    cfg_fp: str
    activation: StrategyBundleActivation
    spec: StrategyPolicySpec
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]


# =============================================================================
# Strategy router
# =============================================================================


class StrategyRouter:
    """
    Risk-aware deterministic routing control plane.

    L6/L7 upgrades:
      - immutable compiled bundle + atomic swap
      - safe, always-available digests on every path
      - last-known-good + fail-closed governance
      - strong low-cardinality vocabularies
      - route contract, not just sampler hints
      - route_plan_id vs decision_id separation
      - explain API for operator-facing reasoning
    """

    def __init__(self, config: Optional[StrategyConfig] = None) -> None:
        self._instance_id = os.urandom(8).hex()
        self._bundle_lock = threading.RLock()
        self._seq_lock = threading.Lock()
        self._decision_seq = 0

        cfg = (config or StrategyConfig()).normalized_copy()
        bundle = self._compile_bundle(cfg, previous=None, previous_cfg_fp=None)

        if bundle.errors and cfg.on_config_error == "raise":
            raise ValueError("invalid StrategyConfig: " + "; ".join(bundle.errors[:3]))

        self._bundle = bundle
        self._last_known_good: Optional[_CompiledBundle] = None if bundle.errors else bundle
        self._rejected_bundle: Optional[_CompiledBundle] = None
        self._using_last_known_good = False

    # ------------------------------------------------------------------
    # Public config / diagnostics API
    # ------------------------------------------------------------------

    @property
    def config(self) -> StrategyConfig:
        with self._bundle_lock:
            spec = self._bundle.spec
            cfg = StrategyConfig(
                schema_version=spec.schema_version,
                enabled=spec.enabled,
                profile=spec.profile,
                on_config_error=spec.on_config_error,
                policy_ref=spec.policy_ref,
                policyset_ref=spec.policyset_ref,
                patch_id=spec.patch_id,
                change_ticket_id=spec.change_ticket_id,
                activated_by=spec.activated_by,
                approved_by=spec.approved_by,
                hash_algorithm=spec.declared_hash_algorithm,
                min_temperature=spec.min_temperature,
                max_temperature=spec.max_temperature,
                min_top_p=spec.min_top_p,
                max_top_p=spec.max_top_p,
                degrade_temp_factor=spec.degrade_temp_factor,
                degrade_top_p_factor=spec.degrade_top_p_factor,
                soft_degrade_temp_factor=spec.soft_degrade_temp_factor,
                soft_degrade_top_p_factor=spec.soft_degrade_top_p_factor,
                strict_temp_cap=spec.strict_temp_cap,
                strict_top_p_cap=spec.strict_top_p_cap,
                elevated_temp_cap=spec.elevated_temp_cap,
                elevated_top_p_cap=spec.elevated_top_p_cap,
                high_risk_threshold=spec.high_risk_threshold,
                critical_risk_threshold=spec.critical_risk_threshold,
                normal_temperature=spec.normal_preset.temperature,
                normal_top_p=spec.normal_preset.top_p,
                elevated_temperature=spec.elevated_preset.temperature,
                elevated_top_p=spec.elevated_preset.top_p,
                strict_temperature=spec.strict_preset.temperature,
                strict_top_p=spec.strict_preset.top_p,
                normal_max_tokens=spec.normal_preset.max_tokens,
                elevated_safety_max_tokens=spec.elevated_preset.max_tokens,
                strict_safety_max_tokens=spec.strict_preset.max_tokens,
                profile_defaults=dict(spec.profile_defaults),
                zone_defaults=dict(spec.zone_defaults),
                risk_label_defaults=dict(spec.risk_label_defaults),
                allowed_trust_zones=spec.allowed_trust_zones,
                allowed_route_profiles=spec.allowed_route_profiles,
                allowed_risk_labels=spec.allowed_risk_labels,
                allowed_threat_tags=spec.allowed_threat_tags,
                allowed_av_labels=spec.allowed_av_labels,
                force_strict_on_apt=spec.force_strict_on_apt,
                force_strict_on_insider=spec.force_strict_on_insider,
                force_strict_on_supply_chain=spec.force_strict_on_supply_chain,
                force_strict_on_pq_unhealthy=spec.force_strict_on_pq_unhealthy,
                force_strict_on_decision_fail=spec.force_strict_on_decision_fail,
                force_strict_on_e_trigger=spec.force_strict_on_e_trigger,
                force_strict_on_av_trigger=spec.force_strict_on_av_trigger,
                av_strict_labels=spec.av_strict_labels,
                require_trusted_signal_for_strict=spec.require_trusted_signal_for_strict,
                require_signed_signal_for_block=spec.require_signed_signal_for_block,
                max_signal_freshness_ms=spec.max_signal_freshness_ms,
                critical_basis_force_block=spec.critical_basis_force_block,
                default_decoder=spec.normal_preset.decoder,
                elevated_decoder=spec.elevated_preset.decoder,
                strict_decoder=spec.strict_preset.decoder,
                normal_latency_hint=spec.normal_preset.latency_hint,
                elevated_latency_hint=spec.elevated_preset.latency_hint,
                strict_latency_hint=spec.strict_preset.latency_hint,
                normal_action=spec.normal_preset.required_action,
                elevated_action=spec.elevated_preset.required_action,
                strict_action=spec.strict_preset.required_action,
                critical_action=spec.strict_preset.required_action,
                normal_enforcement_mode=spec.normal_preset.enforcement_mode,
                elevated_enforcement_mode=spec.elevated_preset.enforcement_mode,
                strict_enforcement_mode=spec.strict_preset.enforcement_mode,
                critical_enforcement_mode=spec.strict_preset.enforcement_mode,
                normal_tool_calls_allowed=spec.normal_preset.tool_calls_allowed,
                elevated_tool_calls_allowed=spec.elevated_preset.tool_calls_allowed,
                strict_tool_calls_allowed=spec.strict_preset.tool_calls_allowed,
                normal_retrieval_allowed=spec.normal_preset.retrieval_allowed,
                elevated_retrieval_allowed=spec.elevated_preset.retrieval_allowed,
                strict_retrieval_allowed=spec.strict_preset.retrieval_allowed,
                normal_streaming_allowed=spec.normal_preset.streaming_allowed,
                elevated_streaming_allowed=spec.elevated_preset.streaming_allowed,
                strict_streaming_allowed=spec.strict_preset.streaming_allowed,
                normal_external_calls_allowed=spec.normal_preset.external_calls_allowed,
                elevated_external_calls_allowed=spec.elevated_preset.external_calls_allowed,
                strict_external_calls_allowed=spec.strict_preset.external_calls_allowed,
                normal_response_policy=spec.normal_preset.response_policy,
                elevated_response_policy=spec.elevated_preset.response_policy,
                strict_response_policy=spec.strict_preset.response_policy,
                normal_receipt_required=spec.normal_preset.receipt_required,
                elevated_receipt_required=spec.elevated_preset.receipt_required,
                strict_receipt_required=spec.strict_preset.receipt_required,
                normal_ledger_required=spec.normal_preset.ledger_required,
                elevated_ledger_required=spec.elevated_preset.ledger_required,
                strict_ledger_required=spec.strict_preset.ledger_required,
                normal_attestation_required=spec.normal_preset.attestation_required,
                elevated_attestation_required=spec.elevated_preset.attestation_required,
                strict_attestation_required=spec.strict_preset.attestation_required,
                max_tags=spec.max_tags,
                max_reason_codes=spec.max_reason_codes,
            )
            return cfg.normalized_copy()

    @property
    def cfg_fp(self) -> str:
        with self._bundle_lock:
            return self._bundle.cfg_fp

    @property
    def bundle_version(self) -> int:
        with self._bundle_lock:
            return self._bundle.version

    def public_config_snapshot(self) -> StrategyPublicConfigView:
        bundle, router_mode, _ = self._bundle_snapshot()
        return StrategyPublicConfigView(
            cfg_fp=bundle.cfg_fp,
            bundle_version=bundle.version,
            activation_id=bundle.activation.activation_id,
            bundle_updated_at_unix_ns=bundle.updated_at_unix_ns,
            profile=bundle.spec.profile,
            enabled=bundle.spec.enabled,
            policy_ref=bundle.spec.policy_ref,
            policyset_ref=bundle.spec.policyset_ref,
            patch_id=bundle.spec.patch_id,
            declared_hash_algorithm=bundle.spec.declared_hash_algorithm,
            runtime_safe_digest_algorithm=bundle.spec.runtime_safe_digest_algorithm,
            has_errors=bool(bundle.errors),
            has_warnings=bool(bundle.warnings),
            router_mode=router_mode,
        )

    def bundle_diagnostics(self) -> StrategyBundleDiagnostics:
        with self._bundle_lock:
            active = self._bundle
            lkg = self._last_known_good
            rejected = self._rejected_bundle
            return StrategyBundleDiagnostics(
                active_cfg_fp=active.cfg_fp,
                active_bundle_version=active.version,
                active_activation_id=active.activation.activation_id,
                active_updated_at_unix_ns=active.updated_at_unix_ns,
                profile=active.spec.profile,
                enabled=active.spec.enabled,
                policy_ref=active.spec.policy_ref,
                policyset_ref=active.spec.policyset_ref,
                patch_id=active.spec.patch_id,
                declared_hash_algorithm=active.spec.declared_hash_algorithm,
                runtime_safe_digest_algorithm=active.spec.runtime_safe_digest_algorithm,
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
            "activation_id": d.active_activation_id,
            "bundle_updated_at_unix_ns": d.active_updated_at_unix_ns,
            "profile": d.profile,
            "enabled": d.enabled,
            "policy_ref": d.policy_ref,
            "policyset_ref": d.policyset_ref,
            "patch_id": d.patch_id,
            "declared_hash_algorithm": d.declared_hash_algorithm,
            "runtime_safe_digest_algorithm": d.runtime_safe_digest_algorithm,
            "using_last_known_good": d.using_last_known_good,
            "last_known_good_cfg_fp": d.last_known_good_cfg_fp,
            "last_rejected_cfg_fp": d.last_rejected_cfg_fp,
            "error_count": len(d.errors),
            "warning_count": len(d.warnings),
            "errors": list(d.errors[:50]),
            "warnings": list(d.warnings[:50]),
        }

    def set_config(self, config: StrategyConfig) -> None:
        cfg = config.normalized_copy()
        with self._bundle_lock:
            previous = self._bundle
            new_bundle = self._compile_bundle(cfg, previous=previous, previous_cfg_fp=previous.cfg_fp)

            if new_bundle.errors and cfg.on_config_error == "raise":
                raise ValueError("invalid StrategyConfig: " + "; ".join(new_bundle.errors[:3]))

            if new_bundle.errors and cfg.on_config_error == "use_last_known_good" and self._last_known_good is not None:
                self._rejected_bundle = new_bundle
                self._using_last_known_good = True
                return

            self._bundle = new_bundle
            self._rejected_bundle = new_bundle if new_bundle.errors else None
            self._using_last_known_good = False

            if not new_bundle.errors:
                self._last_known_good = new_bundle

    # ------------------------------------------------------------------
    # Public routing API
    # ------------------------------------------------------------------

    def decide_many(self, items: Sequence[Mapping[str, Any]]) -> List[Route]:
        bundle, router_mode, degraded_codes = self._bundle_snapshot()
        out: List[Route] = []
        for item in items:
            if not isinstance(item, Mapping):
                out.append(
                    self._decide_with_bundle(
                        bundle=bundle,
                        router_mode=router_mode,
                        degraded_codes=degraded_codes,
                        route_context=StrategyRouteContext(),
                        signals=StrategySignals(score=0.0),
                        base=StrategySamplingBase(),
                        envelope=StrategySignalEnvelope(),
                    )
                )
                continue

            security_raw = item.get("security")
            security = security_raw if isinstance(security_raw, Mapping) else {}

            e_state_raw = item.get("e_state")
            e_state = e_state_raw if isinstance(e_state_raw, Mapping) else {}
            validity_raw = e_state.get("validity") if isinstance(e_state, Mapping) else None
            validity = validity_raw if isinstance(validity_raw, Mapping) else {}
            process_raw = e_state.get("process") if isinstance(e_state, Mapping) else None
            process = process_raw if isinstance(process_raw, Mapping) else {}
            controller_raw = e_state.get("controller") if isinstance(e_state, Mapping) else None
            controller = controller_raw if isinstance(controller_raw, Mapping) else {}

            av_label_raw = item.get("av_label") if item.get("av_label") is not None else security.get("av_label")
            av_label_norm = _safe_label(av_label_raw, default="") if isinstance(av_label_raw, str) else ""
            if av_label_norm and av_label_norm not in bundle.spec.allowed_av_labels:
                if av_label_norm in _AV_NON_RISK_LABEL_ALIASES:
                    av_label_raw = None

            ctx = StrategyRouteContext(
                request_id=item.get("request_id"),
                trace_id=item.get("trace_id"),
                tenant_id=item.get("tenant_id"),
                principal_id=item.get("principal_id"),
                trust_zone=item.get("trust_zone", "internet"),
                route_profile=item.get("route_profile", "inference"),
            )
            signals = StrategySignals(
                score=item.get("score", 0.0),
                risk_label=(
                    item.get("risk_label")
                    if item.get("risk_label") is not None
                    else security.get("risk_label", "normal")
                ),
                decision_fail=item.get("decision_fail", False),
                e_triggered=item.get("e_triggered", False),
                pq_unhealthy=item.get("pq_unhealthy", False),
                av_label=av_label_raw,
                av_trigger=(
                    item.get("av_trigger")
                    if item.get("av_trigger") is not None
                    else security.get("av_trigger", security.get("trigger"))
                ),
                threat_tags=_normalize_signal_tags(item.get("threat_kinds") if item.get("threat_kinds") is not None else item.get("threat_tags"), max_items=8),
                controller_mode=(
                    item.get("controller_mode")
                    if item.get("controller_mode") is not None
                    else security.get("controller_mode")
                ),
                guarantee_scope=(
                    item.get("guarantee_scope")
                    if item.get("guarantee_scope") is not None
                    else security.get(
                        "guarantee_scope",
                        security.get(
                            "statistical_guarantee_scope",
                            validity.get("statistical_guarantee_scope", process.get("guarantee_scope")),
                        ),
                    )
                ),
            )
            base = StrategySamplingBase(
                temperature=item.get("base_temp", item.get("temperature", 1.0)),
                top_p=item.get("base_top_p", item.get("top_p", 1.0)),
                max_tokens=item.get("max_tokens"),
            )
            env_raw = item.get("signal_envelope")
            if isinstance(env_raw, StrategySignalEnvelope):
                env = env_raw
            elif isinstance(env_raw, Mapping):
                env = StrategySignalEnvelope(
                    source=env_raw.get("source", "legacy_implicit"),
                    trusted=_coerce_bool(env_raw.get("trusted", True), default=True),
                    signed=_coerce_bool(env_raw.get("signed", False), default=False),
                    signer_kid=env_raw.get("signer_kid"),
                    source_cfg_fp=env_raw.get("source_cfg_fp"),
                    source_policy_ref=env_raw.get("source_policy_ref"),
                    freshness_ms=env_raw.get("freshness_ms"),
                    replay_checked=env_raw.get("replay_checked"),
                )
            else:
                env = StrategySignalEnvelope()
            out.append(
                self._decide_with_bundle(
                    bundle=bundle,
                    router_mode=router_mode,
                    degraded_codes=degraded_codes,
                    route_context=ctx.normalized(),
                    signals=signals.normalized(),
                    base=base.normalized(),
                    envelope=env.normalized(),
                )
            )
        return out

    def decide(
        self,
        *,
        decision_fail: bool,
        score: float,
        base_temp: float,
        base_top_p: float,
        risk_label: str = "normal",
        route_profile: str = "inference",
        e_triggered: bool = False,
        trust_zone: str = "internet",
        threat_kind: Optional[str] = None,
        threat_kinds: Optional[Sequence[str]] = None,
        pq_unhealthy: bool = False,
        av_label: Optional[str] = None,
        av_trigger: Optional[bool] = None,
        meta: Optional[Dict[str, Any]] = None,
        # structured overrides / provenance
        route_context: Optional[StrategyRouteContext] = None,
        signal_envelope: Optional[StrategySignalEnvelope] = None,
        request_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        tenant_id: Optional[str] = None,
        principal_id: Optional[str] = None,
        controller_mode: Optional[str] = None,
        guarantee_scope: Optional[str] = None,
        max_tokens: Optional[int] = None,
    ) -> Route:
        """
        Backward-compatible routing entrypoint.

        `meta` is intentionally ignored for routing semantics. It is accepted
        only for compatibility so callers do not accidentally build content-
        dependent routing behaviour.
        """
        del meta

        bundle, router_mode, degraded_codes = self._bundle_snapshot()

        ctx = (route_context or StrategyRouteContext(
            request_id=request_id,
            trace_id=trace_id,
            tenant_id=tenant_id,
            principal_id=principal_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
        )).normalized()

        signals = StrategySignals(
            score=score,
            risk_label=risk_label,
            decision_fail=decision_fail,
            e_triggered=e_triggered,
            pq_unhealthy=pq_unhealthy,
            av_label=av_label,
            av_trigger=av_trigger,
            threat_tags=_normalize_signal_tags(threat_kinds if threat_kinds is not None else ([threat_kind] if threat_kind else ()), max_items=8),
            controller_mode=controller_mode,
            guarantee_scope=guarantee_scope,
        ).normalized()

        base = StrategySamplingBase(
            temperature=base_temp,
            top_p=base_top_p,
            max_tokens=max_tokens,
        ).normalized()

        env = (signal_envelope or StrategySignalEnvelope()).normalized()

        return self._decide_with_bundle(
            bundle=bundle,
            router_mode=router_mode,
            degraded_codes=degraded_codes,
            route_context=ctx,
            signals=signals,
            base=base,
            envelope=env,
        )

    def decide_explain(
        self,
        *,
        route_context: StrategyRouteContext,
        signals: StrategySignals,
        sampling: StrategySamplingBase,
        signal_envelope: Optional[StrategySignalEnvelope] = None,
    ) -> Dict[str, Any]:
        bundle, router_mode, degraded_codes = self._bundle_snapshot()
        ctx = route_context.normalized()
        sig = signals.normalized()
        base = sampling.normalized()
        env = (signal_envelope or StrategySignalEnvelope()).normalized()

        eval_out = self._evaluate(bundle, ctx, sig, base, env, router_mode, degraded_codes)
        return {
            "schema": _SCHEMA,
            "router": _ROUTER_NAME,
            "version": _ROUTER_VERSION,
            "instance_id": self._instance_id,
            "config_fingerprint": bundle.cfg_fp,
            "route_config_fingerprint": bundle.cfg_fp,
            "cfg_fp": bundle.cfg_fp,
            "config_fingerprint_kind": "route",
            "bundle_version": bundle.version,
            "activation_id": bundle.activation.activation_id,
            "router_mode": eval_out["router_mode"],
            "baseline": eval_out["baseline"],
            "resolved_context": eval_out["resolved_context"],
            "signal_provenance": eval_out["signal_provenance"],
            "signals_summary": eval_out["signals_summary"],
            "route_contract": eval_out["route_contract"],
            "reason_codes": list(eval_out["reason_codes"]),
            "degraded_reason_codes": list(eval_out["degraded_reason_codes"]),
            "tags": list(eval_out["tags"]),
        }

    # ------------------------------------------------------------------
    # Internal evaluation logic
    # ------------------------------------------------------------------

    def _next_decision_seq(self) -> int:
        with self._seq_lock:
            self._decision_seq += 1
            return self._decision_seq

    def _bundle_snapshot(self) -> Tuple[_CompiledBundle, RouterMode, Tuple[str, ...]]:
        with self._bundle_lock:
            if not self._bundle.spec.enabled:
                return self._bundle, "disabled", tuple()
            if self._using_last_known_good:
                reasons = self._rejected_bundle.errors[:8] if self._rejected_bundle is not None else tuple()
                return self._bundle, "last_known_good", reasons
            if self._bundle.errors:
                return self._bundle, "fail_closed", self._bundle.errors[:8]
            return self._bundle, "normal", tuple()

    def _decide_with_bundle(
        self,
        *,
        bundle: _CompiledBundle,
        router_mode: RouterMode,
        degraded_codes: Tuple[str, ...],
        route_context: StrategyRouteContext,
        signals: StrategySignals,
        base: StrategySamplingBase,
        envelope: StrategySignalEnvelope,
    ) -> Route:
        if router_mode == "disabled":
            return self._build_disabled_route(bundle, route_context, envelope)

        if router_mode == "fail_closed":
            return self._build_fail_closed_route(bundle, route_context, envelope, degraded_codes)

        eval_out = self._evaluate(bundle, route_context, signals, base, envelope, router_mode, degraded_codes)

        # fail-closed from resolution policy
        if eval_out["fail_closed"]:
            return self._build_fail_closed_route(
                bundle,
                route_context,
                envelope,
                tuple(eval_out["degraded_reason_codes"]) + tuple(eval_out["reason_codes"]),
            )

        decision_seq = self._next_decision_seq()
        decision_ts_unix_ns = time.time_ns()
        decision_ts_mono_ns = time.monotonic_ns()

        route_plan_payload = {
            "cfg_fp": bundle.cfg_fp,
            "bundle_version": bundle.version,
            "activation_id": bundle.activation.activation_id,
            "policy_ref": bundle.spec.policy_ref,
            "policyset_ref": bundle.spec.policyset_ref,
            "resolved_context": eval_out["resolved_context"],
            "signals_summary": eval_out["signals_summary"],
            "route_contract": eval_out["route_contract"],
            "reason_codes": list(eval_out["reason_codes"]),
            "degraded_reason_codes": list(eval_out["degraded_reason_codes"]),
        }
        route_plan_id = f"{_ROUTE_PLAN_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:plan', payload=route_plan_payload, out_hex=32)}"

        if route_context.request_id or route_context.trace_id:
            decision_payload = {
                "route_plan_id": route_plan_id,
                "request_id": route_context.request_id,
                "trace_id": route_context.trace_id,
                "context_digest": eval_out["context_digest"],
                "signal_digest": eval_out["signal_digest"],
                "cfg_fp": bundle.cfg_fp,
                "bundle_version": bundle.version,
            }
        else:
            decision_payload = {
                "instance_id": self._instance_id,
                "route_plan_id": route_plan_id,
                "decision_seq": decision_seq,
                "decision_ts_unix_ns": decision_ts_unix_ns,
            }
        decision_id = f"{_DECISION_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:decision', payload=decision_payload, out_hex=32)}"

        return Route(
            schema=_SCHEMA,
            router=_ROUTER_NAME,
            version=_ROUTER_VERSION,
            instance_id=self._instance_id,
            activation_id=bundle.activation.activation_id,
            config_fingerprint=bundle.cfg_fp,
            bundle_version=bundle.version,
            bundle_updated_at_unix_ns=bundle.updated_at_unix_ns,
            policy_ref=bundle.spec.policy_ref,
            policyset_ref=bundle.spec.policyset_ref,
            patch_id=bundle.spec.patch_id,
            change_ticket_id=bundle.spec.change_ticket_id,
            activated_by=bundle.spec.activated_by,
            router_mode=eval_out["router_mode"],
            route_id_kind="plan",
            route_plan_id=route_plan_id,
            route_id=route_plan_id,
            decision_id=decision_id,
            decision_seq=decision_seq,
            decision_ts_unix_ns=decision_ts_unix_ns,
            decision_ts_mono_ns=decision_ts_mono_ns,
            safety_tier=eval_out["route_contract"]["safety_tier"],
            required_action=eval_out["route_contract"]["required_action"],
            action_hint=eval_out["route_contract"]["required_action"],
            enforcement_mode=eval_out["route_contract"]["enforcement_mode"],
            temperature=eval_out["route_contract"]["temperature"],
            top_p=eval_out["route_contract"]["top_p"],
            decoder=eval_out["route_contract"]["decoder"],
            max_tokens=eval_out["route_contract"]["max_tokens"],
            latency_hint=eval_out["route_contract"]["latency_hint"],
            tool_calls_allowed=eval_out["route_contract"]["tool_calls_allowed"],
            retrieval_allowed=eval_out["route_contract"]["retrieval_allowed"],
            streaming_allowed=eval_out["route_contract"]["streaming_allowed"],
            external_calls_allowed=eval_out["route_contract"]["external_calls_allowed"],
            response_policy=eval_out["route_contract"]["response_policy"],
            receipt_required=eval_out["route_contract"]["receipt_required"],
            ledger_required=eval_out["route_contract"]["ledger_required"],
            attestation_required=eval_out["route_contract"]["attestation_required"],
            trust_zone=eval_out["resolved_context"]["trust_zone"],
            route_profile=eval_out["resolved_context"]["route_profile"],
            risk_label=eval_out["resolved_context"]["risk_label"],
            score=signals.score,
            decision_fail=signals.decision_fail,
            e_triggered=signals.e_triggered,
            pq_unhealthy=signals.pq_unhealthy,
            av_label=signals.av_label,
            av_trigger=signals.av_trigger,
            threat_tags=tuple(eval_out["resolved_context"]["threat_tags"]),
            controller_mode=signals.controller_mode,
            guarantee_scope=signals.guarantee_scope,
            signal_source=envelope.source,
            signal_trust_mode=eval_out["signal_provenance"]["signal_trust_mode"],
            signal_signed=eval_out["signal_provenance"]["signal_signed"],
            signal_signer_kid=eval_out["signal_provenance"]["signal_signer_kid"],
            signal_cfg_fp=eval_out["signal_provenance"]["signal_cfg_fp"],
            signal_policy_ref=eval_out["signal_provenance"]["signal_policy_ref"],
            signal_freshness_ms=eval_out["signal_provenance"]["signal_freshness_ms"],
            signal_replay_checked=eval_out["signal_provenance"]["signal_replay_checked"],
            signal_digest=eval_out["signal_digest"],
            context_digest=eval_out["context_digest"],
            primary_reason_code=eval_out["reason_codes"][0] if eval_out["reason_codes"] else "BALANCED_ROUTE",
            reason_codes=tuple(eval_out["reason_codes"]),
            degraded_reason_codes=tuple(eval_out["degraded_reason_codes"]),
            reason=";".join(eval_out["reason_codes"] + eval_out["degraded_reason_codes"]) or "BALANCED_ROUTE",
            tags=tuple(eval_out["tags"]),
        )

    def _evaluate(
        self,
        bundle: _CompiledBundle,
        route_context: StrategyRouteContext,
        signals: StrategySignals,
        base: StrategySamplingBase,
        envelope: StrategySignalEnvelope,
        router_mode: RouterMode,
        degraded_codes: Tuple[str, ...],
    ) -> Dict[str, Any]:
        reason_codes: List[str] = []
        degraded_reason_codes: List[str] = list(_normalize_reason_codes(degraded_codes, max_items=bundle.spec.max_reason_codes))
        tags: List[str] = []

        resolved_zone, zone_fail_closed, zone_min_tier, zone_codes = self._resolve_trust_zone(bundle, route_context.trust_zone)
        resolved_profile, profile_fail_closed, profile_min_tier, profile_codes = self._resolve_route_profile(bundle, route_context.route_profile)
        resolved_risk, risk_fail_closed, risk_min_tier, risk_codes = self._resolve_risk_label(bundle, signals.risk_label)

        reason_codes.extend(zone_codes)
        reason_codes.extend(profile_codes)
        reason_codes.extend(risk_codes)

        threat_tags: List[str] = []
        for t in signals.threat_tags:
            st = _safe_label(t, default="")
            if not st:
                continue
            if st not in bundle.spec.allowed_threat_tags:
                degraded_reason_codes.append("UNKNOWN_THREAT_DROPPED")
                continue
            threat_tags.append(st)

        av_label = signals.av_label
        if av_label is not None and av_label not in bundle.spec.allowed_av_labels:
            if av_label in _AV_NON_RISK_LABEL_ALIASES:
                av_label = None
            else:
                av_label = None
                degraded_reason_codes.append("UNKNOWN_AV_LABEL_DROPPED")

        baseline_profile_tier = bundle.spec.profile_defaults.get(resolved_profile, "normal")
        baseline_zone_tier = bundle.spec.zone_defaults.get(resolved_zone, "normal")
        baseline_risk_tier = bundle.spec.risk_label_defaults.get(resolved_risk, "normal")

        safety_tier: SafetyTier = _tier_max(
            _tier_max(baseline_profile_tier, baseline_zone_tier),
            baseline_risk_tier,
        )

        safety_tier = _tier_max(safety_tier, zone_min_tier)
        safety_tier = _tier_max(safety_tier, profile_min_tier)
        safety_tier = _tier_max(safety_tier, risk_min_tier)

        if baseline_zone_tier == "elevated":
            reason_codes.append("BASELINE_ZONE_ELEVATED")
        elif baseline_zone_tier == "strict":
            reason_codes.append("BASELINE_ZONE_STRICT")

        if baseline_profile_tier == "elevated":
            reason_codes.append("BASELINE_PROFILE_ELEVATED")
        elif baseline_profile_tier == "strict":
            reason_codes.append("BASELINE_PROFILE_STRICT")

        if baseline_risk_tier == "elevated":
            reason_codes.append("BASELINE_RISK_ELEVATED")
        elif baseline_risk_tier == "strict":
            reason_codes.append("BASELINE_RISK_STRICT")

        signal_trust_mode: SignalTrustMode = "trusted" if envelope.trusted else "advisory"
        if not envelope.trusted:
            signal_trust_mode = "untrusted"
        if envelope.trusted and not envelope.signed and bundle.spec.require_signed_signal_for_block:
            signal_trust_mode = "advisory"

        strict_signal_allowed = True
        if bundle.spec.require_trusted_signal_for_strict and not envelope.trusted:
            strict_signal_allowed = False

        if bundle.spec.max_signal_freshness_ms is not None and envelope.freshness_ms is not None:
            if envelope.freshness_ms > bundle.spec.max_signal_freshness_ms:
                strict_signal_allowed = False
                degraded_reason_codes.append("STALE_SIGNAL_DOWNGRADED")

        strict_mode = safety_tier == "strict"
        soft_degrade = safety_tier == "elevated"
        critical_basis = False

        if signals.decision_fail and bundle.spec.force_strict_on_decision_fail:
            reason_codes.append("SIGNAL_DECISION_FAIL")
            tags.append("signal:decision_fail")
            if strict_signal_allowed:
                strict_mode = True
                critical_basis = True
            else:
                soft_degrade = True
                degraded_reason_codes.append("UNTRUSTED_STRICT_SIGNAL_DOWNGRADED")

        if signals.e_triggered and bundle.spec.force_strict_on_e_trigger:
            reason_codes.append("SIGNAL_E_TRIGGER")
            tags.append("signal:e_triggered")
            if strict_signal_allowed:
                strict_mode = True
                critical_basis = True
            else:
                soft_degrade = True
                degraded_reason_codes.append("UNTRUSTED_STRICT_SIGNAL_DOWNGRADED")

        if signals.av_trigger and bundle.spec.force_strict_on_av_trigger:
            reason_codes.append("SIGNAL_AV_TRIGGER")
            tags.append("signal:av_trigger")
            if strict_signal_allowed:
                strict_mode = True
                critical_basis = True
            else:
                soft_degrade = True
                degraded_reason_codes.append("UNTRUSTED_STRICT_SIGNAL_DOWNGRADED")

        if av_label and av_label in bundle.spec.av_strict_labels:
            reason_codes.append("SIGNAL_AV_LABEL_STRICT")
            tags.append(f"av:{av_label}")
            if strict_signal_allowed:
                strict_mode = True
                critical_basis = True
            else:
                soft_degrade = True
                degraded_reason_codes.append("UNTRUSTED_STRICT_SIGNAL_DOWNGRADED")

        if resolved_risk in {"high", "elevated"}:
            reason_codes.append("SIGNAL_RISK_LABEL_HIGH")
            soft_degrade = True
        elif resolved_risk == "critical":
            reason_codes.append("SIGNAL_RISK_LABEL_CRITICAL")
            if strict_signal_allowed:
                strict_mode = True
                critical_basis = True
            else:
                soft_degrade = True
                degraded_reason_codes.append("UNTRUSTED_STRICT_SIGNAL_DOWNGRADED")

        if signals.score >= bundle.spec.critical_risk_threshold:
            reason_codes.append("SIGNAL_RISK_SCORE_CRITICAL")
            tags.append("signal:risk_score_critical")
            if strict_signal_allowed:
                strict_mode = True
                critical_basis = True
            else:
                soft_degrade = True
                degraded_reason_codes.append("UNTRUSTED_STRICT_SIGNAL_DOWNGRADED")
        elif signals.score >= bundle.spec.high_risk_threshold:
            reason_codes.append("SIGNAL_RISK_SCORE_HIGH")
            tags.append("signal:risk_score_high")
            soft_degrade = True

        for tk in threat_tags:
            tags.append(f"threat:{tk}")
            if tk == "apt" and bundle.spec.force_strict_on_apt:
                reason_codes.append("SIGNAL_THREAT_APT")
                if strict_signal_allowed:
                    strict_mode = True
                    critical_basis = True
                else:
                    soft_degrade = True
                    degraded_reason_codes.append("UNTRUSTED_STRICT_SIGNAL_DOWNGRADED")
            elif tk == "insider" and bundle.spec.force_strict_on_insider:
                reason_codes.append("SIGNAL_THREAT_INSIDER")
                if strict_signal_allowed:
                    strict_mode = True
                    critical_basis = True
                else:
                    soft_degrade = True
                    degraded_reason_codes.append("UNTRUSTED_STRICT_SIGNAL_DOWNGRADED")
            elif tk == "supply_chain" and bundle.spec.force_strict_on_supply_chain:
                reason_codes.append("SIGNAL_THREAT_SUPPLY_CHAIN")
                if strict_signal_allowed:
                    strict_mode = True
                    critical_basis = True
                else:
                    soft_degrade = True
                    degraded_reason_codes.append("UNTRUSTED_STRICT_SIGNAL_DOWNGRADED")

        if signals.pq_unhealthy and bundle.spec.force_strict_on_pq_unhealthy:
            reason_codes.append("SIGNAL_PQ_UNHEALTHY")
            tags.append("signal:pq_unhealthy")
            if strict_signal_allowed:
                strict_mode = True
                critical_basis = True
            else:
                soft_degrade = True
                degraded_reason_codes.append("UNTRUSTED_STRICT_SIGNAL_DOWNGRADED")

        if strict_mode:
            safety_tier = "strict"
            reason_codes.append("ROUTE_STRICT")
        elif soft_degrade:
            safety_tier = "elevated"
            reason_codes.append("ROUTE_ELEVATED")
        else:
            safety_tier = "normal"
            reason_codes.append("ROUTE_NORMAL")
            reason_codes.append("BALANCED_ROUTE")

        route_contract = self._build_route_contract(bundle, safety_tier, base, critical_basis, envelope, degraded_reason_codes)

        if critical_basis and bundle.spec.critical_basis_force_block:
            if bundle.spec.require_signed_signal_for_block and not envelope.signed:
                degraded_reason_codes.append("UNSIGNED_BLOCK_SIGNAL_DOWNGRADED")
            else:
                route_contract["required_action"] = _action_max(route_contract["required_action"], "block")
                route_contract["action_hint"] = route_contract["required_action"]
                route_contract["enforcement_mode"] = (
                    "fail_closed" if bundle.spec.profile in {"FINREG", "LOCKDOWN"} else route_contract["enforcement_mode"]
                )
                reason_codes.append("CRITICAL_BASIS_BLOCK")

        if router_mode == "last_known_good":
            degraded_reason_codes.append("ROUTER_LAST_KNOWN_GOOD")
            tags.append("router:last_known_good")
        elif router_mode == "degraded":
            tags.append("router:degraded")

        tags.append(f"zone:{resolved_zone}")
        tags.append(f"profile:{resolved_profile}")
        tags.append(f"risk:{resolved_risk}")
        tags.append(f"tier:{safety_tier}")

        if bundle.spec.policy_ref:
            # kept as a dedicated field in output; do not inject policy_ref directly as tag
            pass

        # profile-based fail-closed semantics
        fail_closed = zone_fail_closed or profile_fail_closed or risk_fail_closed

        resolved_context = {
            "trust_zone": resolved_zone,
            "route_profile": resolved_profile,
            "risk_label": resolved_risk,
            "threat_tags": tuple(threat_tags),
        }

        signal_provenance = {
            "signal_source": envelope.source,
            "signal_trust_mode": signal_trust_mode,
            "signal_signed": bool(envelope.signed),
            "signal_signer_kid": envelope.signer_kid,
            "signal_cfg_fp": envelope.source_cfg_fp,
            "signal_policy_ref": envelope.source_policy_ref,
            "signal_freshness_ms": envelope.freshness_ms,
            "signal_replay_checked": envelope.replay_checked,
        }

        signals_summary = {
            "score": signals.score,
            "decision_fail": bool(signals.decision_fail),
            "e_triggered": bool(signals.e_triggered),
            "pq_unhealthy": bool(signals.pq_unhealthy),
            "av_label": av_label,
            "av_trigger": signals.av_trigger,
            "threat_tags": tuple(threat_tags),
            "controller_mode": signals.controller_mode,
            "guarantee_scope": signals.guarantee_scope,
        }

        context_digest_payload = {
            "request_id": route_context.request_id,
            "trace_id": route_context.trace_id,
            "tenant_id": route_context.tenant_id,
            "principal_id": route_context.principal_id,
            "trust_zone": resolved_zone,
            "route_profile": resolved_profile,
        }
        context_digest = f"{_CONTEXT_DIGEST_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:context', payload=context_digest_payload, out_hex=24)}"

        signal_digest_payload = {
            "source": envelope.source,
            "trusted": envelope.trusted,
            "signed": envelope.signed,
            "signer_kid": envelope.signer_kid,
            "source_cfg_fp": envelope.source_cfg_fp,
            "source_policy_ref": envelope.source_policy_ref,
            "freshness_ms": envelope.freshness_ms,
            "replay_checked": envelope.replay_checked,
            "signals": signals_summary,
        }
        signal_digest = f"{_SIGNAL_DIGEST_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:signals', payload=signal_digest_payload, out_hex=24)}"

        return {
            "router_mode": router_mode,
            "fail_closed": fail_closed,
            "baseline": {
                "profile_tier": baseline_profile_tier,
                "zone_tier": baseline_zone_tier,
                "risk_tier": baseline_risk_tier,
                "safety_tier": safety_tier,
                "critical_basis": critical_basis,
            },
            "resolved_context": resolved_context,
            "signal_provenance": signal_provenance,
            "signals_summary": signals_summary,
            "route_contract": route_contract,
            "reason_codes": _normalize_reason_codes(reason_codes, max_items=bundle.spec.max_reason_codes),
            "degraded_reason_codes": _normalize_reason_codes(degraded_reason_codes, max_items=bundle.spec.max_reason_codes),
            "tags": _normalize_tags(tags, max_items=bundle.spec.max_tags),
            "context_digest": context_digest,
            "signal_digest": signal_digest,
        }

    def _resolve_trust_zone(
        self,
        bundle: _CompiledBundle,
        raw: str,
    ) -> Tuple[str, bool, SafetyTier, Tuple[str, ...]]:
        s = _safe_label(raw, default="")
        if not s:
            if bundle.spec.profile in {"FINREG", "LOCKDOWN"}:
                return "unknown", True, "strict", ("INVALID_TRUST_ZONE",)
            if bundle.spec.profile == "PROD":
                return "unknown", False, "strict", ("INVALID_TRUST_ZONE",)
            return "unknown", False, "elevated", ("INVALID_TRUST_ZONE",)
        if s not in bundle.spec.allowed_trust_zones:
            if bundle.spec.profile in {"FINREG", "LOCKDOWN"}:
                return "unknown", True, "strict", ("UNKNOWN_TRUST_ZONE",)
            if bundle.spec.profile == "PROD":
                return "unknown", False, "strict", ("UNKNOWN_TRUST_ZONE",)
            return "unknown", False, "elevated", ("UNKNOWN_TRUST_ZONE",)
        return s, False, "normal", tuple()

    def _resolve_route_profile(
        self,
        bundle: _CompiledBundle,
        raw: str,
    ) -> Tuple[str, bool, SafetyTier, Tuple[str, ...]]:
        s = _safe_label(raw, default="")
        if not s:
            if bundle.spec.profile in {"FINREG", "LOCKDOWN"}:
                return "unknown", False, "strict", ("INVALID_ROUTE_PROFILE",)
            if bundle.spec.profile == "PROD":
                return "unknown", False, "elevated", ("INVALID_ROUTE_PROFILE",)
            return "unknown", False, "normal", ("INVALID_ROUTE_PROFILE",)
        if s not in bundle.spec.allowed_route_profiles:
            if bundle.spec.profile in {"FINREG", "LOCKDOWN"}:
                return "unknown", False, "strict", ("UNKNOWN_ROUTE_PROFILE",)
            if bundle.spec.profile == "PROD":
                return "unknown", False, "elevated", ("UNKNOWN_ROUTE_PROFILE",)
            return "unknown", False, "normal", ("UNKNOWN_ROUTE_PROFILE",)
        return s, False, "normal", tuple()

    def _resolve_risk_label(
        self,
        bundle: _CompiledBundle,
        raw: str,
    ) -> Tuple[str, bool, SafetyTier, Tuple[str, ...]]:
        s = _safe_label(raw, default="")
        if not s:
            if bundle.spec.profile in {"FINREG", "LOCKDOWN"}:
                return "unknown", True, "strict", ("INVALID_RISK_LABEL",)
            if bundle.spec.profile == "PROD":
                return "unknown", False, "strict", ("INVALID_RISK_LABEL",)
            return "unknown", False, "elevated", ("INVALID_RISK_LABEL",)
        if s not in bundle.spec.allowed_risk_labels:
            if bundle.spec.profile in {"FINREG", "LOCKDOWN"}:
                return "unknown", True, "strict", ("UNKNOWN_RISK_LABEL",)
            if bundle.spec.profile == "PROD":
                return "unknown", False, "strict", ("UNKNOWN_RISK_LABEL",)
            return "unknown", False, "elevated", ("UNKNOWN_RISK_LABEL",)
        return s, False, "normal", tuple()

    def _build_route_contract(
        self,
        bundle: _CompiledBundle,
        safety_tier: SafetyTier,
        base: StrategySamplingBase,
        critical_basis: bool,
        envelope: StrategySignalEnvelope,
        degraded_reason_codes: List[str],
    ) -> Dict[str, Any]:
        if safety_tier == "strict":
            preset = bundle.spec.strict_preset
            temperature = self._select_temperature(bundle, preset, base, hard=True)
            top_p = self._select_top_p(bundle, preset, base, hard=True)
        elif safety_tier == "elevated":
            preset = bundle.spec.elevated_preset
            temperature = self._select_temperature(bundle, preset, base, hard=False)
            top_p = self._select_top_p(bundle, preset, base, hard=False)
        else:
            preset = bundle.spec.normal_preset
            temperature = self._select_temperature(bundle, preset, base, hard=False)
            top_p = self._select_top_p(bundle, preset, base, hard=False)

        max_tokens = preset.max_tokens if preset.max_tokens is not None else base.max_tokens

        required_action = preset.required_action
        enforcement_mode = preset.enforcement_mode

        return {
            "safety_tier": safety_tier,
            "required_action": required_action,
            "action_hint": required_action,
            "enforcement_mode": enforcement_mode,
            "temperature": temperature,
            "top_p": top_p,
            "decoder": preset.decoder,
            "max_tokens": max_tokens,
            "latency_hint": preset.latency_hint,
            "tool_calls_allowed": preset.tool_calls_allowed,
            "retrieval_allowed": preset.retrieval_allowed,
            "streaming_allowed": preset.streaming_allowed,
            "external_calls_allowed": preset.external_calls_allowed,
            "response_policy": preset.response_policy,
            "receipt_required": preset.receipt_required,
            "ledger_required": preset.ledger_required,
            "attestation_required": preset.attestation_required,
        }

    def _select_temperature(
        self,
        bundle: _CompiledBundle,
        preset: StrategyTierPreset,
        base: StrategySamplingBase,
        *,
        hard: bool,
    ) -> float:
        if preset.temperature is not None:
            return self._clamp_temp(bundle, preset.temperature)

        t = base.temperature
        if preset.safety_tier == "strict":
            t *= bundle.spec.degrade_temp_factor
            t = min(t, bundle.spec.strict_temp_cap)
        elif preset.safety_tier == "elevated":
            t *= bundle.spec.soft_degrade_temp_factor
            if bundle.spec.elevated_temp_cap is not None:
                t = min(t, bundle.spec.elevated_temp_cap)
        return self._clamp_temp(bundle, t)

    def _select_top_p(
        self,
        bundle: _CompiledBundle,
        preset: StrategyTierPreset,
        base: StrategySamplingBase,
        *,
        hard: bool,
    ) -> float:
        if preset.top_p is not None:
            return self._clamp_top_p(bundle, preset.top_p)

        p = base.top_p
        if preset.safety_tier == "strict":
            p *= bundle.spec.degrade_top_p_factor
            p = min(p, bundle.spec.strict_top_p_cap)
        elif preset.safety_tier == "elevated":
            p *= bundle.spec.soft_degrade_top_p_factor
            if bundle.spec.elevated_top_p_cap is not None:
                p = min(p, bundle.spec.elevated_top_p_cap)
        return self._clamp_top_p(bundle, p)

    def _build_disabled_route(
        self,
        bundle: _CompiledBundle,
        route_context: StrategyRouteContext,
        envelope: StrategySignalEnvelope,
    ) -> Route:
        decision_seq = self._next_decision_seq()
        decision_ts_unix_ns = time.time_ns()
        decision_ts_mono_ns = time.monotonic_ns()

        ctx = route_context.normalized()
        route_plan_id = f"{_ROUTE_PLAN_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:disabled_plan', payload={'cfg_fp': bundle.cfg_fp}, out_hex=32)}"
        decision_id = f"{_DECISION_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:disabled_decision', payload={'route_plan_id': route_plan_id, 'seq': decision_seq, 'ts': decision_ts_unix_ns, 'request_id': ctx.request_id}, out_hex=32)}"

        context_digest = f"{_CONTEXT_DIGEST_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:context', payload={'request_id': ctx.request_id, 'trace_id': ctx.trace_id, 'tenant_id': ctx.tenant_id, 'principal_id': ctx.principal_id, 'trust_zone': 'internet', 'route_profile': 'inference'}, out_hex=24)}"
        signal_digest = f"{_SIGNAL_DIGEST_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:signals', payload={'source': envelope.source, 'trusted': envelope.trusted, 'signed': envelope.signed}, out_hex=24)}"

        return Route(
            schema=_SCHEMA,
            router=_ROUTER_NAME,
            version=_ROUTER_VERSION,
            instance_id=self._instance_id,
            activation_id=bundle.activation.activation_id,
            config_fingerprint=bundle.cfg_fp,
            bundle_version=bundle.version,
            bundle_updated_at_unix_ns=bundle.updated_at_unix_ns,
            policy_ref=bundle.spec.policy_ref,
            policyset_ref=bundle.spec.policyset_ref,
            patch_id=bundle.spec.patch_id,
            change_ticket_id=bundle.spec.change_ticket_id,
            activated_by=bundle.spec.activated_by,
            router_mode="disabled",
            route_id_kind="plan",
            route_plan_id=route_plan_id,
            route_id=route_plan_id,
            decision_id=decision_id,
            decision_seq=decision_seq,
            decision_ts_unix_ns=decision_ts_unix_ns,
            decision_ts_mono_ns=decision_ts_mono_ns,
            safety_tier="normal",
            required_action="allow",
            action_hint="allow",
            enforcement_mode="advisory",
            temperature=self._clamp_temp(bundle, 1.0),
            top_p=self._clamp_top_p(bundle, 1.0),
            decoder=bundle.spec.normal_preset.decoder,
            max_tokens=bundle.spec.normal_preset.max_tokens,
            latency_hint=bundle.spec.normal_preset.latency_hint,
            tool_calls_allowed=bundle.spec.normal_preset.tool_calls_allowed,
            retrieval_allowed=bundle.spec.normal_preset.retrieval_allowed,
            streaming_allowed=bundle.spec.normal_preset.streaming_allowed,
            external_calls_allowed=bundle.spec.normal_preset.external_calls_allowed,
            response_policy=bundle.spec.normal_preset.response_policy,
            receipt_required=bundle.spec.normal_preset.receipt_required,
            ledger_required=bundle.spec.normal_preset.ledger_required,
            attestation_required=bundle.spec.normal_preset.attestation_required,
            trust_zone="internet",
            route_profile="inference",
            risk_label="normal",
            score=0.0,
            decision_fail=False,
            e_triggered=False,
            pq_unhealthy=False,
            av_label=None,
            av_trigger=None,
            threat_tags=tuple(),
            controller_mode=None,
            guarantee_scope=None,
            signal_source=envelope.source,
            signal_trust_mode="trusted" if envelope.trusted else "untrusted",
            signal_signed=bool(envelope.signed),
            signal_signer_kid=envelope.signer_kid,
            signal_cfg_fp=envelope.source_cfg_fp,
            signal_policy_ref=envelope.source_policy_ref,
            signal_freshness_ms=envelope.freshness_ms,
            signal_replay_checked=envelope.replay_checked,
            signal_digest=signal_digest,
            context_digest=context_digest,
            primary_reason_code="ROUTER_DISABLED",
            reason_codes=("ROUTER_DISABLED",),
            degraded_reason_codes=tuple(),
            reason="ROUTER_DISABLED",
            tags=("router:disabled",),
        )

    def _build_fail_closed_route(
        self,
        bundle: _CompiledBundle,
        route_context: StrategyRouteContext,
        envelope: StrategySignalEnvelope,
        degraded_codes: Sequence[str],
    ) -> Route:
        decision_seq = self._next_decision_seq()
        decision_ts_unix_ns = time.time_ns()
        decision_ts_mono_ns = time.monotonic_ns()

        ctx = route_context.normalized()
        preset = bundle.spec.strict_preset
        temperature = self._select_temperature(bundle, preset, StrategySamplingBase(), hard=True)
        top_p = self._select_top_p(bundle, preset, StrategySamplingBase(), hard=True)

        reason_codes = _normalize_reason_codes(("CFG_ERROR", "ROUTER_FAIL_CLOSED", "ROUTE_STRICT"), max_items=bundle.spec.max_reason_codes)
        degraded_reason_codes = _normalize_reason_codes(degraded_codes, max_items=bundle.spec.max_reason_codes)

        route_plan_id = f"{_ROUTE_PLAN_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:fail_closed_plan', payload={'cfg_fp': bundle.cfg_fp, 'reason_codes': list(reason_codes), 'degraded_reason_codes': list(degraded_reason_codes)}, out_hex=32)}"
        decision_id = f"{_DECISION_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:fail_closed_decision', payload={'route_plan_id': route_plan_id, 'seq': decision_seq, 'ts': decision_ts_unix_ns, 'request_id': ctx.request_id}, out_hex=32)}"

        context_digest = f"{_CONTEXT_DIGEST_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:context', payload={'request_id': ctx.request_id, 'trace_id': ctx.trace_id, 'tenant_id': ctx.tenant_id, 'principal_id': ctx.principal_id, 'trust_zone': '__config_error__', 'route_profile': 'control'}, out_hex=24)}"
        signal_digest = f"{_SIGNAL_DIGEST_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:signals', payload={'source': envelope.source, 'trusted': envelope.trusted, 'signed': envelope.signed}, out_hex=24)}"

        return Route(
            schema=_SCHEMA,
            router=_ROUTER_NAME,
            version=_ROUTER_VERSION,
            instance_id=self._instance_id,
            activation_id=bundle.activation.activation_id,
            config_fingerprint=bundle.cfg_fp,
            bundle_version=bundle.version,
            bundle_updated_at_unix_ns=bundle.updated_at_unix_ns,
            policy_ref=bundle.spec.policy_ref,
            policyset_ref=bundle.spec.policyset_ref,
            patch_id=bundle.spec.patch_id,
            change_ticket_id=bundle.spec.change_ticket_id,
            activated_by=bundle.spec.activated_by,
            router_mode="fail_closed",
            route_id_kind="plan",
            route_plan_id=route_plan_id,
            route_id=route_plan_id,
            decision_id=decision_id,
            decision_seq=decision_seq,
            decision_ts_unix_ns=decision_ts_unix_ns,
            decision_ts_mono_ns=decision_ts_mono_ns,
            safety_tier="strict",
            required_action="block",
            action_hint="block",
            enforcement_mode="fail_closed",
            temperature=temperature,
            top_p=top_p,
            decoder=preset.decoder,
            max_tokens=preset.max_tokens,
            latency_hint=preset.latency_hint,
            tool_calls_allowed=False,
            retrieval_allowed=False,
            streaming_allowed=False,
            external_calls_allowed=False,
            response_policy="restricted",
            receipt_required=True,
            ledger_required=True,
            attestation_required=True,
            trust_zone="__config_error__",
            route_profile="control",
            risk_label="critical",
            score=1.0,
            decision_fail=True,
            e_triggered=True,
            pq_unhealthy=False,
            av_label=None,
            av_trigger=None,
            threat_tags=("config_error",),
            controller_mode=None,
            guarantee_scope=None,
            signal_source=envelope.source,
            signal_trust_mode="trusted" if envelope.trusted else "untrusted",
            signal_signed=bool(envelope.signed),
            signal_signer_kid=envelope.signer_kid,
            signal_cfg_fp=envelope.source_cfg_fp,
            signal_policy_ref=envelope.source_policy_ref,
            signal_freshness_ms=envelope.freshness_ms,
            signal_replay_checked=envelope.replay_checked,
            signal_digest=signal_digest,
            context_digest=context_digest,
            primary_reason_code=reason_codes[0],
            reason_codes=reason_codes,
            degraded_reason_codes=degraded_reason_codes,
            reason=";".join(reason_codes + degraded_reason_codes),
            tags=("router:fail_closed", "route:degrade_strict", "signal:config_error"),
        )

    def _clamp_temp(self, bundle: _CompiledBundle, value: Any) -> float:
        return _clamp_float(value, default=1.0, lo=bundle.spec.min_temperature, hi=bundle.spec.max_temperature)

    def _clamp_top_p(self, bundle: _CompiledBundle, value: Any) -> float:
        return _clamp_float(value, default=1.0, lo=bundle.spec.min_top_p, hi=bundle.spec.max_top_p)

    # ------------------------------------------------------------------
    # Bundle compilation
    # ------------------------------------------------------------------

    def _compile_bundle(
        self,
        config: StrategyConfig,
        *,
        previous: Optional[_CompiledBundle],
        previous_cfg_fp: Optional[str],
    ) -> _CompiledBundle:
        cfg = config.normalized_copy()
        errors: List[str] = []
        warnings: List[str] = []

        if cfg.hash_algorithm == "blake3" and Blake3Hash is None:
            errors.append("CFG_HASH_BACKEND_UNAVAILABLE")

        # Monotonicity tightening
        if cfg.elevated_temp_cap is not None and cfg.strict_temp_cap > cfg.elevated_temp_cap:
            warnings.append("STRICT_TEMP_CAP_TIGHTENED")
            cfg.strict_temp_cap = cfg.elevated_temp_cap
        if cfg.elevated_top_p_cap is not None and cfg.strict_top_p_cap > cfg.elevated_top_p_cap:
            warnings.append("STRICT_TOP_P_CAP_TIGHTENED")
            cfg.strict_top_p_cap = cfg.elevated_top_p_cap

        if cfg.elevated_safety_max_tokens is not None and cfg.strict_safety_max_tokens is not None:
            if cfg.strict_safety_max_tokens > cfg.elevated_safety_max_tokens:
                warnings.append("STRICT_MAX_TOKENS_TIGHTENED")
                cfg.strict_safety_max_tokens = cfg.elevated_safety_max_tokens
        if cfg.normal_max_tokens is not None and cfg.elevated_safety_max_tokens is not None:
            if cfg.elevated_safety_max_tokens > cfg.normal_max_tokens:
                warnings.append("ELEVATED_MAX_TOKENS_TIGHTENED")
                cfg.elevated_safety_max_tokens = cfg.normal_max_tokens
                if cfg.strict_safety_max_tokens is not None and cfg.strict_safety_max_tokens > cfg.elevated_safety_max_tokens:
                    cfg.strict_safety_max_tokens = cfg.elevated_safety_max_tokens

        if _required_action_rank(cfg.elevated_action) < _required_action_rank(cfg.normal_action):
            warnings.append("ELEVATED_ACTION_TIGHTENED")
            cfg.elevated_action = cfg.normal_action  # type: ignore[assignment]
        if _required_action_rank(cfg.strict_action) < _required_action_rank(cfg.elevated_action):
            warnings.append("STRICT_ACTION_TIGHTENED")
            cfg.strict_action = cfg.elevated_action  # type: ignore[assignment]
        if _required_action_rank(cfg.critical_action) < _required_action_rank(cfg.strict_action):
            warnings.append("CRITICAL_ACTION_TIGHTENED")
            cfg.critical_action = "block"  # type: ignore[assignment]

        profile_defaults = MappingProxyType(dict(sorted(cfg.profile_defaults.items())))
        zone_defaults = MappingProxyType(dict(sorted(cfg.zone_defaults.items())))
        risk_label_defaults = MappingProxyType(dict(sorted(cfg.risk_label_defaults.items())))

        normal_preset = StrategyTierPreset(
            safety_tier="normal",
            decoder=cfg.default_decoder,
            latency_hint=cfg.normal_latency_hint,
            required_action=cfg.normal_action,
            enforcement_mode=cfg.normal_enforcement_mode,
            temperature=cfg.normal_temperature,
            top_p=cfg.normal_top_p,
            max_tokens=cfg.normal_max_tokens,
            tool_calls_allowed=cfg.normal_tool_calls_allowed,
            retrieval_allowed=cfg.normal_retrieval_allowed,
            streaming_allowed=cfg.normal_streaming_allowed,
            external_calls_allowed=cfg.normal_external_calls_allowed,
            response_policy=cfg.normal_response_policy,
            receipt_required=cfg.normal_receipt_required,
            ledger_required=cfg.normal_ledger_required,
            attestation_required=cfg.normal_attestation_required,
        )
        elevated_preset = StrategyTierPreset(
            safety_tier="elevated",
            decoder=cfg.elevated_decoder,
            latency_hint=cfg.elevated_latency_hint,
            required_action=cfg.elevated_action,
            enforcement_mode=cfg.elevated_enforcement_mode,
            temperature=cfg.elevated_temperature,
            top_p=cfg.elevated_top_p,
            max_tokens=cfg.elevated_safety_max_tokens,
            tool_calls_allowed=cfg.elevated_tool_calls_allowed,
            retrieval_allowed=cfg.elevated_retrieval_allowed,
            streaming_allowed=cfg.elevated_streaming_allowed,
            external_calls_allowed=cfg.elevated_external_calls_allowed,
            response_policy=cfg.elevated_response_policy,
            receipt_required=cfg.elevated_receipt_required,
            ledger_required=cfg.elevated_ledger_required,
            attestation_required=cfg.elevated_attestation_required,
        )
        strict_preset = StrategyTierPreset(
            safety_tier="strict",
            decoder=cfg.strict_decoder,
            latency_hint=cfg.strict_latency_hint,
            required_action=cfg.strict_action,
            enforcement_mode=cfg.strict_enforcement_mode,
            temperature=cfg.strict_temperature,
            top_p=cfg.strict_top_p,
            max_tokens=cfg.strict_safety_max_tokens,
            tool_calls_allowed=cfg.strict_tool_calls_allowed,
            retrieval_allowed=cfg.strict_retrieval_allowed,
            streaming_allowed=cfg.strict_streaming_allowed,
            external_calls_allowed=cfg.strict_external_calls_allowed,
            response_policy=cfg.strict_response_policy,
            receipt_required=cfg.strict_receipt_required,
            ledger_required=cfg.strict_ledger_required,
            attestation_required=cfg.strict_attestation_required,
        )

        spec = StrategyPolicySpec(
            schema_version=cfg.schema_version,
            profile=cfg.profile,
            enabled=cfg.enabled,
            on_config_error=cfg.on_config_error,
            policy_ref=cfg.policy_ref,
            policyset_ref=cfg.policyset_ref,
            patch_id=cfg.patch_id,
            change_ticket_id=cfg.change_ticket_id,
            activated_by=cfg.activated_by,
            approved_by=cfg.approved_by,
            declared_hash_algorithm=cfg.hash_algorithm,
            runtime_safe_digest_algorithm=_SAFE_DIGEST_ALG,
            min_temperature=cfg.min_temperature,
            max_temperature=cfg.max_temperature,
            min_top_p=cfg.min_top_p,
            max_top_p=cfg.max_top_p,
            degrade_temp_factor=cfg.degrade_temp_factor,
            degrade_top_p_factor=cfg.degrade_top_p_factor,
            soft_degrade_temp_factor=cfg.soft_degrade_temp_factor,
            soft_degrade_top_p_factor=cfg.soft_degrade_top_p_factor,
            strict_temp_cap=cfg.strict_temp_cap,
            strict_top_p_cap=cfg.strict_top_p_cap,
            elevated_temp_cap=cfg.elevated_temp_cap,
            elevated_top_p_cap=cfg.elevated_top_p_cap,
            high_risk_threshold=cfg.high_risk_threshold,
            critical_risk_threshold=cfg.critical_risk_threshold,
            profile_defaults=profile_defaults,
            zone_defaults=zone_defaults,
            risk_label_defaults=risk_label_defaults,
            allowed_trust_zones=cfg.allowed_trust_zones,
            allowed_route_profiles=cfg.allowed_route_profiles,
            allowed_risk_labels=cfg.allowed_risk_labels,
            allowed_threat_tags=cfg.allowed_threat_tags,
            allowed_av_labels=cfg.allowed_av_labels,
            force_strict_on_apt=cfg.force_strict_on_apt,
            force_strict_on_insider=cfg.force_strict_on_insider,
            force_strict_on_supply_chain=cfg.force_strict_on_supply_chain,
            force_strict_on_pq_unhealthy=cfg.force_strict_on_pq_unhealthy,
            force_strict_on_decision_fail=cfg.force_strict_on_decision_fail,
            force_strict_on_e_trigger=cfg.force_strict_on_e_trigger,
            force_strict_on_av_trigger=cfg.force_strict_on_av_trigger,
            av_strict_labels=cfg.av_strict_labels,
            require_trusted_signal_for_strict=cfg.require_trusted_signal_for_strict,
            require_signed_signal_for_block=cfg.require_signed_signal_for_block,
            max_signal_freshness_ms=cfg.max_signal_freshness_ms,
            critical_basis_force_block=cfg.critical_basis_force_block,
            normal_preset=normal_preset,
            elevated_preset=elevated_preset,
            strict_preset=strict_preset,
            max_tags=cfg.max_tags,
            max_reason_codes=cfg.max_reason_codes,
        )

        cfg_fp_payload = cfg.to_public_dict()
        cfg_fp = f"{_CFG_FP_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:cfg', payload=cfg_fp_payload, out_hex=64)}"

        updated_at_unix_ns = time.time_ns()
        version = 1 if previous is None else previous.version + 1
        activation_mode = "normal"
        activation_payload = {
            "cfg_fp": cfg_fp,
            "bundle_version": version,
            "updated_at_unix_ns": updated_at_unix_ns,
            "policy_ref": spec.policy_ref,
            "policyset_ref": spec.policyset_ref,
            "patch_id": spec.patch_id,
            "change_ticket_id": spec.change_ticket_id,
            "activated_by": spec.activated_by,
            "approved_by": list(spec.approved_by),
            "previous_cfg_fp": previous_cfg_fp,
            "activation_mode": activation_mode,
        }
        activation_id = f"{_ACTIVATION_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_safe_digest_hex(ctx='tcd:route:activation', payload=activation_payload, out_hex=32)}"

        activation = StrategyBundleActivation(
            activation_id=activation_id,
            cfg_fp=cfg_fp,
            bundle_version=version,
            policy_ref=spec.policy_ref,
            policyset_ref=spec.policyset_ref,
            patch_id=spec.patch_id,
            change_ticket_id=spec.change_ticket_id,
            activated_by=spec.activated_by,
            approved_by=spec.approved_by,
            activated_at_unix_ns=updated_at_unix_ns,
            previous_cfg_fp=previous_cfg_fp,
            activation_mode=activation_mode,
        )

        return _CompiledBundle(
            version=version,
            updated_at_unix_ns=updated_at_unix_ns,
            cfg_fp=cfg_fp,
            activation=activation,
            spec=spec,
            errors=tuple(_normalize_reason_codes(errors, max_items=64)),
            warnings=tuple(_normalize_reason_codes(warnings, max_items=64)),
        )