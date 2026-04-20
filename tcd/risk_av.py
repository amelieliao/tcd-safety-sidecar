下面是按你贴出来的版本，直接把 _make_initial_state(...) 插进 AlwaysValidRiskController 里、位置放在 _selected_track(...) 后面、_update_state(...) 前面 的完整代码框。

from __future__ import annotations
import base64
import hashlib
import hmac
import json
import math
import os
import threading
import time
import unicodedata
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, MutableMapping, Optional, Protocol, Sequence, Tuple, Literal
try:  # optional, explicit use only when selected by config
    from .crypto import Blake3Hash
except ImportError:  # pragma: no cover
    Blake3Hash = None  # type: ignore[assignment]
__all__ = [
    "StreamIdentityPolicy",
    "StreamIdentityResult",
    "EvidencePacket",
    "AlwaysValidPolicySpec",
    "AlwaysValidSecretConfig",
    "AlwaysValidRuntimeConfig",
    "AlwaysValidPublicConfigView",
    "AlwaysValidBundleDiagnostics",
    "AlwaysValidConfig",
    "EProcessState",
    "StateRecord",
    "ScoreToPAdapter",
    "HeuristicScoreAdapter",
    "PredictableScoreAdapter",
    "AlwaysValidAuditSink",
    "AlwaysValidTelemetrySink",
    "AlwaysValidReceiptSink",
    "EProcessStateBackend",
    "InMemoryEProcessStateBackend",
    "AlwaysValidRiskController",
]
# ---------------------------------------------------------------------------
# Constants / schemas / enums
# ---------------------------------------------------------------------------
Profile = Literal["DEV", "PROD", "FINREG", "LOCKDOWN"]
# backward-compatible: "fallback" will be normalized to "use_last_known_good"
OnConfigError = Literal["use_last_known_good", "fail_closed", "raise", "fallback"]
DecisionMode = Literal[
    "strict_only",
    "controller_only",
    "prefer_current_strict",
    "dual_track",
]
LegacyDecisionSource = Literal[
    "controller",
    "strict",
    "strict_if_available_else_controller",
]
ScoreToPMode = Literal["one_minus_score", "sigmoid_tail", "exp_tail"]
NewStreamPolicy = Literal["deny_new_when_full", "evict_lru"]
OnStateExhaustion = Literal["allow", "deny"]
StreamHashAlgorithm = Literal["hmac_sha256", "blake2b", "blake3"]
IdentityMode = Literal[
    "require_explicit",
    "derive_from_ctx",
    "use_default",
    "dev_fallback_default",
]
IdentityErrorMode = Literal["fail_closed", "allow_degraded", "use_default"]
GuaranteeScope = Literal[
    "strict_direct_p",
    "predictable_calibrated_p",
    "heuristic_only",
    "none",
]
ControllerMode = Literal[
    "normal",
    "last_known_good",
    "fail_closed",
    "degraded_identity",
    "degraded_state_backend",
    "degraded_calibration",
]
Action = Literal["allow", "advisory", "block", "degraded_allow", "degraded_block"]
NeutralUpdateMode = Literal["noop", "decay", "reward"]
_CONTROLLER_NAME = "tcd.risk_av"
_CONTROLLER_VERSION = "2.0.0"
_SCHEMA = "tcd.eprocess.v3"
_ASCII_CTRL_RE = __import__("re").compile(r"[\x00-\x1F\x7F]")
_SAFE_LABEL_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = __import__("re").compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_ID_RE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#]{0,255}$")
_HEX_RE = __import__("re").compile(r"^[0-9a-fA-F]{16,4096}$")
# Conservative secret detection for caller-provided metadata/context
_JWT_RE = __import__("re").compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = __import__("re").compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----",
    __import__("re").IGNORECASE,
)
_BEARER_RE = __import__("re").compile(
    r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b",
    __import__("re").IGNORECASE,
)
_BASIC_RE = __import__("re").compile(
    r"\bBasic\s+[A-Za-z0-9+/=]{16,}\b",
    __import__("re").IGNORECASE,
)
_KV_SECRET_RE = __import__("re").compile(
    r"(?i)\b(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]{8,})"
)
_FORBIDDEN_META_KEY_TOKENS = {
    "prompt",
    "completion",
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
    "token",
    "secret",
    "password",
    "apikey",
    "api_key",
    "private",
    "privatekey",
}
_DEFAULT_SEVERITY_WEIGHTS = MappingProxyType(
    {
        "low": 1.0,
        "medium": 2.0,
        "high": 3.0,
        "critical": 4.0,
    }
)
_DEFAULT_P_TO_E_KAPPAS = (0.2, 0.5, 0.8)
# ---------------------------------------------------------------------------
# Low-level hardening helpers
# ---------------------------------------------------------------------------
def _has_unsafe_unicode(s: str) -> bool:
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False
def _strip_unsafe_text(s: Any, *, max_len: int) -> str:
    if not isinstance(s, str):
        return ""
    if len(s) > max_len:
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
    out: list[str] = []
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
    if not s:
        return default
    if not _SAFE_ID_RE.fullmatch(s):
        return default
    return s
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
    if _KV_SECRET_RE.search(s):
        return True
    return False
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
        if not s or len(s) > 64:
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
def _safe_exp(x: float) -> float:
    try:
        if x > 700.0:
            return float("inf")
        if x < -700.0:
            return 0.0
        return math.exp(x)
    except Exception:
        return float("nan")
def _canon_json(obj: Any) -> str:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
def _parse_key_material(v: Any) -> Optional[bytes]:
    """
    Supports:
      - bytes
      - "hex:<...>"
      - "b64:<...>"
      - plain hex
      - plain base64url
    """
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
        if not _HEX_RE.fullmatch(hx) or len(hx) % 2 != 0:
            return None
        try:
            return bytes.fromhex(hx)
        except Exception:
            return None
    if s.lower().startswith("b64:"):
        raw = s[4:].strip()
        try:
            pad = "=" * ((4 - (len(raw) % 4)) % 4)
            out = base64.urlsafe_b64decode((raw + pad).encode("utf-8", errors="strict"))
            return out if out else None
        except Exception:
            return None
    if _HEX_RE.fullmatch(s) and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s)
        except Exception:
            return None
    try:
        pad = "=" * ((4 - (len(s) % 4)) % 4)
        out = base64.urlsafe_b64decode((s + pad).encode("utf-8", errors="strict"))
        return out if out else None
    except Exception:
        return None
def _logsumexp(values: Sequence[float]) -> float:
    if not values:
        return float("-inf")
    m = max(values)
    if not math.isfinite(m):
        return m
    acc = 0.0
    for v in values:
        acc += math.exp(v - m)
    if acc <= 0.0 or not math.isfinite(acc):
        return m
    return m + math.log(acc)
def _key_tokenize(k: str) -> Tuple[str, ...]:
    s = _strip_unsafe_text(k, max_len=128)
    if not s:
        return tuple()
    out: list[str] = []
    cur: list[str] = []
    prev_is_alnum = False
    for ch in s:
        if ch.isalnum():
            if prev_is_alnum:
                cur.append(ch.lower())
            else:
                if cur:
                    out.append("".join(cur))
                cur = [ch.lower()]
                prev_is_alnum = True
        else:
            if cur:
                out.append("".join(cur))
                cur = []
            prev_is_alnum = False
    if cur:
        out.append("".join(cur))
    fused = "".join(out)
    if fused and fused not in out:
        out.append(fused)
    return tuple(x for x in out if x)
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
def _json_sanitize(
    obj: Any,
    *,
    budget: _JsonBudget,
    depth: int,
    redact_secrets: bool,
) -> Any:
    """
    JSON-safe sanitizer that does not call str()/repr() on unknown objects.
    Only exact builtins are traversed.
    """
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
        s = _strip_unsafe_text(obj, max_len=512)
        if redact_secrets and _looks_like_secret(s):
            s = "[redacted]"
        if len(s) > 512:
            s = s[:512] + "...[truncated]"
        if not budget.take_str(len(s)):
            return "[truncated]"
        return s
    if t in (bytes, bytearray):
        return f"[bytes:{len(obj)}]"
    if depth >= budget.max_depth:
        return "[truncated-depth]"
    if t is dict:
        out: Dict[str, Any] = {}
        n = 0
        for k, v in obj.items():
            if n >= budget.max_items:
                out["_tcd_truncated"] = True
                break
            if type(k) is not str:
                continue
            kk = _safe_id(k, default=None, max_len=128)
            if kk is None:
                continue
            toks = _key_tokenize(kk)
            if any(tok in _FORBIDDEN_META_KEY_TOKENS for tok in toks):
                continue
            out[kk] = _json_sanitize(
                v,
                budget=budget,
                depth=depth + 1,
                redact_secrets=redact_secrets,
            )
            n += 1
        return out
    if t in (list, tuple):
        out_list = []
        for i, item in enumerate(obj):
            if i >= budget.max_items:
                out_list.append("[truncated]")
                break
            out_list.append(
                _json_sanitize(
                    item,
                    budget=budget,
                    depth=depth + 1,
                    redact_secrets=redact_secrets,
                )
            )
        return out_list
    return f"[type:{t.__name__}]"
def _clone_deque_floats(d: deque[float], maxlen: Optional[int]) -> deque[float]:
    return deque(list(d), maxlen=maxlen)
# ---------------------------------------------------------------------------
# Public models / split config
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class StreamIdentityPolicy:
    mode: IdentityMode = "dev_fallback_default"
    schema_ref: str = "stream.v1"
    include_fields: Tuple[str, ...] = ("tenant", "user", "model_id")
    strict_profiles_forbid_default: bool = True
    expose_raw_stream_id: bool = False
    hash_only_in_strict: bool = True
    on_identity_error: IdentityErrorMode = "fail_closed"
    def normalized_copy(self) -> "StreamIdentityPolicy":
        mode = self.mode if self.mode in {"require_explicit", "derive_from_ctx", "use_default", "dev_fallback_default"} else "dev_fallback_default"
        schema_ref = _safe_id(self.schema_ref, default="stream.v1", max_len=64) or "stream.v1"
        include_fields: List[str] = []
        for x in self.include_fields:
            sx = _safe_label(x, default="")
            if sx:
                include_fields.append(sx)
        if not include_fields:
            include_fields = ["tenant", "user", "model_id"]
        on_err = self.on_identity_error if self.on_identity_error in {"fail_closed", "allow_degraded", "use_default"} else "fail_closed"
        return StreamIdentityPolicy(
            mode=mode,
            schema_ref=schema_ref,
            include_fields=tuple(include_fields[:16]),
            strict_profiles_forbid_default=bool(self.strict_profiles_forbid_default),
            expose_raw_stream_id=bool(self.expose_raw_stream_id),
            hash_only_in_strict=bool(self.hash_only_in_strict),
            on_identity_error=on_err,
        )
@dataclass(frozen=True)
class StreamIdentityResult:
    raw_stream_id: Optional[str]
    canonical_stream_id: Optional[str]
    stream_hash: str
    identity_status: Literal["ok", "missing", "invalid", "derived", "degraded_default"]
    schema_ref: str
    raw_exposed: bool
@dataclass(frozen=True)
class EvidencePacket:
    current_step_has_direct_p: bool
    strict_p_value: Optional[float]
    current_step_has_controller_p: bool
    controller_p_value: Optional[float]
    controller_p_kind: Literal["direct", "calibrated", "heuristic", "neutral"]
    current_step_has_calibrated_p: bool
    calibrated_p_value: Optional[float]
    calibration_ref: Optional[str]
    calibration_cfg_digest: Optional[str]
    calibration_state_digest: Optional[str]
    current_step_has_score: bool
    raw_score: Optional[float]
    score_source: Optional[str]
    guarantee_scope: GuaranteeScope
@dataclass(frozen=True)
class AlwaysValidPolicySpec:
    schema_version: int
    profile: Profile
    label: str
    policyset_ref: Optional[str]
    on_config_error: OnConfigError
    decision_mode: DecisionMode
    block_on_trigger: bool
    threshold_log_e: float
    threshold_clear_log_e: float
    max_log_e: float
    min_log_e: float
    max_step_abs_log_e: float
    alpha_base: float
    alpha_wealth_init: float
    alpha_wealth_cap: float
    alpha_spend_per_decision: float
    alpha_reward_per_safe_decision: float
    freeze_on_exhaust: bool
    max_weight: float
    severity_weights: Mapping[str, float]
    min_p_value: float
    max_p_value: float
    p_to_e_kappas: Tuple[float, ...]
    p_to_e_weights: Tuple[float, ...]
    score_to_p_mode: ScoreToPMode
    score_reference: float
    score_scale: float
    heuristic_p_weight: float
    strict_requires_direct_p: bool
    heuristic_allowed_for_blocking: bool
    calibrated_score_allowed_for_blocking: bool
    neutral_update_mode: NeutralUpdateMode
    neutral_decay_rate: float
    stream_identity: StreamIdentityPolicy
    score_adapter_default: Optional[str]
@dataclass(frozen=True)
class AlwaysValidSecretConfig:
    stream_hash_algorithm: StreamHashAlgorithm
    stream_hash_key: Optional[bytes]
    stream_hash_key_id: Optional[str]
    stream_hash_mode: str
    min_stream_hash_key_bytes: int
@dataclass(frozen=True)
class AlwaysValidRuntimeConfig:
    enabled: bool
    max_streams: int
    idle_ttl_s: float
    stream_cleanup_budget: int
    new_stream_policy: NewStreamPolicy
    on_state_exhaustion: OnStateExhaustion
    evict_only_inactive_streams: bool
    max_retired_state_domains: int
    history_window: int
    retain_history: bool
    include_history_in_snapshot: bool
    ewma_alpha: float
    meta_max_nodes: int
    meta_max_items: int
    meta_max_depth: int
    meta_max_str_total: int
    audit_emit_all_steps: bool
    audit_emit_triggers: bool
    telemetry_emit_all_steps: bool
    telemetry_emit_triggers: bool
    receipt_issue_on_block: bool
    receipt_issue_on_trigger: bool
@dataclass(frozen=True)
class AlwaysValidPublicConfigView:
    cfg_fp: str
    bundle_version: int
    policyset_ref: Optional[str]
    profile: Profile
    label: str
    decision_mode: DecisionMode
    on_config_error: OnConfigError
    stream_hash_algorithm: StreamHashAlgorithm
    stream_hash_key_id: Optional[str]
    stream_hash_mode: str
    state_domain_id: str
    adapter_registry_fp: str
    enabled: bool
    has_errors: bool
    has_warnings: bool
@dataclass(frozen=True)
class AlwaysValidBundleDiagnostics:
    active_cfg_fp: str
    active_bundle_version: int
    active_updated_at_unix_ns: int
    policyset_ref: Optional[str]
    profile: Profile
    label: str
    enabled: bool
    state_domain_id: str
    adapter_registry_fp: str
    stream_hash_algorithm: StreamHashAlgorithm
    stream_hash_key_id: Optional[str]
    stream_hash_mode: str
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    using_last_known_good: bool
    last_known_good_cfg_fp: Optional[str]
    last_rejected_cfg_fp: Optional[str]
@dataclass
class AlwaysValidConfig:
    """
    Aggregate configuration.
    This remains the public configuration object for backward compatibility,
    but internally the controller compiles it into:
      - AlwaysValidPolicySpec
      - AlwaysValidSecretConfig
      - AlwaysValidRuntimeConfig
      - immutable compiled bundle
    """
    schema_version: int = 3
    enabled: bool = True
    profile: Profile = "PROD"
    label: str = "default"
    policyset_ref: Optional[str] = None
    on_config_error: OnConfigError = "use_last_known_good"
    # Decision semantics (new + backward-compatible legacy alias)
    decision_mode: Optional[DecisionMode] = None
    decision_source: Optional[LegacyDecisionSource] = "controller"
    block_on_trigger: bool = False
    # Trigger thresholds / hysteresis
    threshold_log_e: float = 4.0
    threshold_clear_log_e: float = 3.0
    max_log_e: float = 32.0
    min_log_e: float = -32.0
    max_step_abs_log_e: float = 16.0
    # Alpha-wealth / controller budgeting
    alpha_base: float = 0.05
    alpha_wealth_init: float = 1.0
    alpha_wealth_cap: float = 1.0
    alpha_spend_per_decision: float = 0.0
    alpha_reward_per_safe_decision: float = 0.0
    freeze_on_exhaust: bool = False
    # Weighting
    max_weight: float = 10.0
    severity_weights: Dict[str, float] = field(default_factory=lambda: dict(_DEFAULT_SEVERITY_WEIGHTS))
    # P-value handling
    min_p_value: float = 1e-12
    max_p_value: float = 1.0
    # Direct p -> e calibrator
    p_to_e_kappas: Tuple[float, ...] = _DEFAULT_P_TO_E_KAPPAS
    p_to_e_weights: Optional[Tuple[float, ...]] = None
    # Score -> pseudo-p mapping
    score_to_p_mode: ScoreToPMode = "one_minus_score"
    score_reference: float = 0.5
    score_scale: float = 10.0
    heuristic_p_weight: float = 0.5
    score_adapter_default: Optional[str] = None
    # Track semantics
    strict_requires_direct_p: bool = True
    heuristic_allowed_for_blocking: bool = False
    calibrated_score_allowed_for_blocking: bool = True
    neutral_update_mode: NeutralUpdateMode = "noop"
    neutral_decay_rate: float = 0.0
    # Stream identity governance
    stream_identity: StreamIdentityPolicy = field(default_factory=StreamIdentityPolicy)
    # Stream store governance
    max_streams: int = 100_000
    idle_ttl_s: float = 24.0 * 3600.0
    stream_cleanup_budget: int = 8
    new_stream_policy: NewStreamPolicy = "deny_new_when_full"
    on_state_exhaustion: OnStateExhaustion = "deny"
    evict_only_inactive_streams: bool = True
    max_retired_state_domains: int = 2
    # Stream hashing / pseudonymization
    stream_hash_algorithm: StreamHashAlgorithm = "hmac_sha256"
    stream_hash_key: Optional[Any] = None
    stream_hash_key_id: Optional[str] = None
    auto_ephemeral_hash_key_if_missing: bool = True
    min_stream_hash_key_bytes: int = 16
    # Time
    monotonic_fn: Optional[Callable[[], Any]] = None
    wall_time_fn: Optional[Callable[[], Any]] = None
    # Diagnostics / history / output budgets
    history_window: int = 64
    retain_history: bool = True
    include_history_in_snapshot: bool = False
    ewma_alpha: float = 0.1
    meta_max_nodes: int = 256
    meta_max_items: int = 64
    meta_max_depth: int = 4
    meta_max_str_total: int = 8192
    # Sink emission policy
    audit_emit_all_steps: bool = False
    audit_emit_triggers: bool = True
    telemetry_emit_all_steps: bool = False
    telemetry_emit_triggers: bool = True
    receipt_issue_on_block: bool = True
    receipt_issue_on_trigger: bool = False
    def normalized_copy(self) -> "AlwaysValidConfig":
        c = AlwaysValidConfig()
        c.schema_version = _clamp_int(self.schema_version, default=3, lo=1, hi=1_000_000)
        prof = _safe_label(self.profile, default="prod").upper()
        if prof not in {"DEV", "PROD", "FINREG", "LOCKDOWN"}:
            prof = "PROD"
        c.profile = prof  # type: ignore[assignment]
        c.enabled = bool(self.enabled)
        c.label = _safe_label(self.label, default="default")
        c.policyset_ref = _safe_id(self.policyset_ref, default=None, max_len=128)
        on_err = self.on_config_error
        if on_err not in {"use_last_known_good", "fail_closed", "raise", "fallback"}:
            on_err = "fail_closed"
        if on_err == "fallback":
            on_err = "use_last_known_good"
        c.on_config_error = on_err  # type: ignore[assignment]
        if self.decision_mode in {"strict_only", "controller_only", "prefer_current_strict", "dual_track"}:
            c.decision_mode = self.decision_mode
        else:
            legacy = self.decision_source if self.decision_source in {"controller", "strict", "strict_if_available_else_controller"} else "controller"
            if legacy == "strict":
                c.decision_mode = "strict_only"
            elif legacy == "strict_if_available_else_controller":
                c.decision_mode = "prefer_current_strict"
            else:
                c.decision_mode = "controller_only"
        c.decision_source = None
        c.block_on_trigger = bool(self.block_on_trigger)
        c.threshold_log_e = _clamp_float(self.threshold_log_e, default=4.0, lo=0.0, hi=1_000_000.0)
        c.threshold_clear_log_e = _clamp_float(self.threshold_clear_log_e, default=3.0, lo=-1_000_000.0, hi=c.threshold_log_e)
        if c.threshold_clear_log_e > c.threshold_log_e:
            c.threshold_clear_log_e = c.threshold_log_e
        c.max_log_e = _clamp_float(self.max_log_e, default=32.0, lo=0.0, hi=1_000_000.0)
        c.min_log_e = _clamp_float(self.min_log_e, default=-32.0, lo=-1_000_000.0, hi=0.0)
        if c.min_log_e > c.max_log_e:
            c.min_log_e, c.max_log_e = c.max_log_e, c.min_log_e
        c.max_step_abs_log_e = _clamp_float(self.max_step_abs_log_e, default=16.0, lo=0.0, hi=1_000_000.0)
        c.alpha_base = _clamp_float(self.alpha_base, default=0.05, lo=1e-12, hi=1.0)
        c.alpha_wealth_init = _clamp_float(self.alpha_wealth_init, default=1.0, lo=0.0, hi=1_000_000.0)
        c.alpha_wealth_cap = _clamp_float(self.alpha_wealth_cap, default=max(1.0, c.alpha_wealth_init), lo=0.0, hi=1_000_000.0)
        if c.alpha_wealth_cap < c.alpha_wealth_init:
            c.alpha_wealth_cap = c.alpha_wealth_init
        c.alpha_spend_per_decision = _clamp_float(self.alpha_spend_per_decision, default=0.0, lo=0.0, hi=1_000_000.0)
        c.alpha_reward_per_safe_decision = _clamp_float(self.alpha_reward_per_safe_decision, default=0.0, lo=0.0, hi=1_000_000.0)
        c.freeze_on_exhaust = bool(self.freeze_on_exhaust)
        c.max_weight = _clamp_float(self.max_weight, default=10.0, lo=0.0, hi=1_000_000.0)
        sev: Dict[str, float] = {}
        if isinstance(self.severity_weights, Mapping):
            for k, v in self.severity_weights.items():
                kk = _safe_label(k, default="")
                if not kk:
                    continue
                vv = _clamp_float(v, default=1.0, lo=0.0, hi=max(1.0, c.max_weight))
                sev[kk] = vv
        if not sev:
            sev = dict(_DEFAULT_SEVERITY_WEIGHTS)
        c.severity_weights = sev
        c.min_p_value = _clamp_float(self.min_p_value, default=1e-12, lo=1e-300, hi=1.0)
        c.max_p_value = _clamp_float(self.max_p_value, default=1.0, lo=c.min_p_value, hi=1.0)
        if c.max_p_value < c.min_p_value:
            c.max_p_value = c.min_p_value
        kappas: list[float] = []
        seq: Sequence[Any]
        if isinstance(self.p_to_e_kappas, tuple):
            seq = self.p_to_e_kappas
        elif isinstance(self.p_to_e_kappas, list):
            seq = tuple(self.p_to_e_kappas)
        else:
            seq = _DEFAULT_P_TO_E_KAPPAS
        for x in seq:
            xv = _coerce_float(x)
            if xv is None:
                continue
            if 0.0 < xv < 1.0:
                kappas.append(float(xv))
        if not kappas:
            kappas = list(_DEFAULT_P_TO_E_KAPPAS)
        c.p_to_e_kappas = tuple(kappas)
        if isinstance(self.p_to_e_weights, tuple):
            wseq = self.p_to_e_weights
        elif isinstance(self.p_to_e_weights, list):
            wseq = tuple(self.p_to_e_weights)
        else:
            wseq = None
        if wseq is not None and len(wseq) == len(c.p_to_e_kappas):
            ws: list[float] = []
            for x in wseq:
                xv = _coerce_float(x)
                if xv is None or xv < 0.0:
                    ws.append(0.0)
                else:
                    ws.append(float(xv))
            tot = sum(ws)
            if tot > 0.0 and math.isfinite(tot):
                c.p_to_e_weights = tuple(x / tot for x in ws)
            else:
                c.p_to_e_weights = None
        else:
            c.p_to_e_weights = None
        c.score_to_p_mode = self.score_to_p_mode if self.score_to_p_mode in {"one_minus_score", "sigmoid_tail", "exp_tail"} else "one_minus_score"
        c.score_reference = _clamp_float(self.score_reference, default=0.5, lo=-1_000_000.0, hi=1_000_000.0)
        c.score_scale = _clamp_float(self.score_scale, default=10.0, lo=1e-6, hi=1_000_000.0)
        c.heuristic_p_weight = _clamp_float(self.heuristic_p_weight, default=0.5, lo=0.0, hi=1.0)
        c.score_adapter_default = _safe_id(self.score_adapter_default, default=None, max_len=64)
        c.strict_requires_direct_p = bool(self.strict_requires_direct_p)
        c.heuristic_allowed_for_blocking = bool(self.heuristic_allowed_for_blocking)
        c.calibrated_score_allowed_for_blocking = bool(self.calibrated_score_allowed_for_blocking)
        c.neutral_update_mode = self.neutral_update_mode if self.neutral_update_mode in {"noop", "decay", "reward"} else "noop"
        c.neutral_decay_rate = _clamp_float(self.neutral_decay_rate, default=0.0, lo=0.0, hi=1.0)
        c.stream_identity = self.stream_identity.normalized_copy()
        c.max_streams = _clamp_int(self.max_streams, default=100_000, lo=1, hi=10_000_000)
        c.idle_ttl_s = _clamp_float(self.idle_ttl_s, default=24.0 * 3600.0, lo=0.0, hi=1_000_000_000.0)
        c.stream_cleanup_budget = _clamp_int(self.stream_cleanup_budget, default=8, lo=0, hi=10_000)
        c.new_stream_policy = self.new_stream_policy if self.new_stream_policy in {"deny_new_when_full", "evict_lru"} else "deny_new_when_full"
        c.on_state_exhaustion = self.on_state_exhaustion if self.on_state_exhaustion in {"allow", "deny"} else "deny"
        c.evict_only_inactive_streams = bool(self.evict_only_inactive_streams)
        c.max_retired_state_domains = _clamp_int(self.max_retired_state_domains, default=2, lo=0, hi=64)
        c.stream_hash_algorithm = (
            self.stream_hash_algorithm
            if self.stream_hash_algorithm in {"hmac_sha256", "blake2b", "blake3"}
            else "hmac_sha256"
        )
        c.stream_hash_key = self.stream_hash_key
        c.stream_hash_key_id = _safe_id(self.stream_hash_key_id, default=None, max_len=64)
        c.auto_ephemeral_hash_key_if_missing = bool(self.auto_ephemeral_hash_key_if_missing)
        c.min_stream_hash_key_bytes = _clamp_int(self.min_stream_hash_key_bytes, default=16, lo=1, hi=4096)
        c.monotonic_fn = self.monotonic_fn if callable(self.monotonic_fn) else None
        c.wall_time_fn = self.wall_time_fn if callable(self.wall_time_fn) else None
        c.history_window = _clamp_int(self.history_window, default=64, lo=0, hi=4096)
        c.retain_history = bool(self.retain_history)
        c.include_history_in_snapshot = bool(self.include_history_in_snapshot)
        c.ewma_alpha = _clamp_float(self.ewma_alpha, default=0.1, lo=0.0, hi=1.0)
        c.meta_max_nodes = _clamp_int(self.meta_max_nodes, default=256, lo=16, hi=1_000_000)
        c.meta_max_items = _clamp_int(self.meta_max_items, default=64, lo=1, hi=4096)
        c.meta_max_depth = _clamp_int(self.meta_max_depth, default=4, lo=1, hi=32)
        c.meta_max_str_total = _clamp_int(self.meta_max_str_total, default=8192, lo=256, hi=10_000_000)
        c.audit_emit_all_steps = bool(self.audit_emit_all_steps)
        c.audit_emit_triggers = bool(self.audit_emit_triggers)
        c.telemetry_emit_all_steps = bool(self.telemetry_emit_all_steps)
        c.telemetry_emit_triggers = bool(self.telemetry_emit_triggers)
        c.receipt_issue_on_block = bool(self.receipt_issue_on_block)
        c.receipt_issue_on_trigger = bool(self.receipt_issue_on_trigger)
        # profile-aware tightening
        if c.profile in {"FINREG", "LOCKDOWN"}:
            if c.on_config_error == "use_last_known_good":
                pass
            c.include_history_in_snapshot = False
            c.meta_max_items = min(c.meta_max_items, 32)
            c.meta_max_nodes = min(c.meta_max_nodes, 256)
            c.max_streams = min(c.max_streams, 1_000_000)
            c.heuristic_allowed_for_blocking = False
            c.stream_identity = StreamIdentityPolicy(
                mode=c.stream_identity.mode,
                schema_ref=c.stream_identity.schema_ref,
                include_fields=c.stream_identity.include_fields,
                strict_profiles_forbid_default=True,
                expose_raw_stream_id=False,
                hash_only_in_strict=True,
                on_identity_error="fail_closed" if c.stream_identity.on_identity_error == "use_default" else c.stream_identity.on_identity_error,
            ).normalized_copy()
        return c
    def to_policy_spec(self) -> AlwaysValidPolicySpec:
        c = self.normalized_copy()
        sev = MappingProxyType(dict(sorted(c.severity_weights.items())))
        weights = tuple(c.p_to_e_weights) if c.p_to_e_weights is not None else tuple(1.0 / len(c.p_to_e_kappas) for _ in c.p_to_e_kappas)
        return AlwaysValidPolicySpec(
            schema_version=c.schema_version,
            profile=c.profile,
            label=c.label,
            policyset_ref=c.policyset_ref,
            on_config_error=c.on_config_error,
            decision_mode=c.decision_mode or "controller_only",
            block_on_trigger=c.block_on_trigger,
            threshold_log_e=c.threshold_log_e,
            threshold_clear_log_e=c.threshold_clear_log_e,
            max_log_e=c.max_log_e,
            min_log_e=c.min_log_e,
            max_step_abs_log_e=c.max_step_abs_log_e,
            alpha_base=c.alpha_base,
            alpha_wealth_init=c.alpha_wealth_init,
            alpha_wealth_cap=c.alpha_wealth_cap,
            alpha_spend_per_decision=c.alpha_spend_per_decision,
            alpha_reward_per_safe_decision=c.alpha_reward_per_safe_decision,
            freeze_on_exhaust=c.freeze_on_exhaust,
            max_weight=c.max_weight,
            severity_weights=sev,
            min_p_value=c.min_p_value,
            max_p_value=c.max_p_value,
            p_to_e_kappas=tuple(c.p_to_e_kappas),
            p_to_e_weights=weights,
            score_to_p_mode=c.score_to_p_mode,
            score_reference=c.score_reference,
            score_scale=c.score_scale,
            heuristic_p_weight=c.heuristic_p_weight,
            strict_requires_direct_p=c.strict_requires_direct_p,
            heuristic_allowed_for_blocking=c.heuristic_allowed_for_blocking,
            calibrated_score_allowed_for_blocking=c.calibrated_score_allowed_for_blocking,
            neutral_update_mode=c.neutral_update_mode,
            neutral_decay_rate=c.neutral_decay_rate,
            stream_identity=c.stream_identity,
            score_adapter_default=c.score_adapter_default,
        )
    def to_secret_config(self) -> AlwaysValidSecretConfig:
        c = self.normalized_copy()
        key_bytes = _parse_key_material(c.stream_hash_key)
        mode = "configured" if key_bytes is not None else "none"
        return AlwaysValidSecretConfig(
            stream_hash_algorithm=c.stream_hash_algorithm,
            stream_hash_key=key_bytes,
            stream_hash_key_id=c.stream_hash_key_id,
            stream_hash_mode=mode,
            min_stream_hash_key_bytes=c.min_stream_hash_key_bytes,
        )
    def to_runtime_config(self) -> AlwaysValidRuntimeConfig:
        c = self.normalized_copy()
        return AlwaysValidRuntimeConfig(
            enabled=c.enabled,
            max_streams=c.max_streams,
            idle_ttl_s=c.idle_ttl_s,
            stream_cleanup_budget=c.stream_cleanup_budget,
            new_stream_policy=c.new_stream_policy,
            on_state_exhaustion=c.on_state_exhaustion,
            evict_only_inactive_streams=c.evict_only_inactive_streams,
            max_retired_state_domains=c.max_retired_state_domains,
            history_window=c.history_window,
            retain_history=c.retain_history,
            include_history_in_snapshot=c.include_history_in_snapshot,
            ewma_alpha=c.ewma_alpha,
            meta_max_nodes=c.meta_max_nodes,
            meta_max_items=c.meta_max_items,
            meta_max_depth=c.meta_max_depth,
            meta_max_str_total=c.meta_max_str_total,
            audit_emit_all_steps=c.audit_emit_all_steps,
            audit_emit_triggers=c.audit_emit_triggers,
            telemetry_emit_all_steps=c.telemetry_emit_all_steps,
            telemetry_emit_triggers=c.telemetry_emit_triggers,
            receipt_issue_on_block=c.receipt_issue_on_block,
            receipt_issue_on_trigger=c.receipt_issue_on_trigger,
        )
    def secret_stripped_copy(self) -> "AlwaysValidConfig":
        c = self.normalized_copy()
        c.stream_hash_key = None
        return c
    def fingerprint(self) -> str:
        spec = self.to_policy_spec()
        secret = self.to_secret_config()
        runtime = self.to_runtime_config()
        payload = {
            "schema_version": spec.schema_version,
            "profile": spec.profile,
            "label": spec.label,
            "policyset_ref": spec.policyset_ref,
            "on_config_error": spec.on_config_error,
            "decision_mode": spec.decision_mode,
            "block_on_trigger": spec.block_on_trigger,
            "threshold_log_e": spec.threshold_log_e,
            "threshold_clear_log_e": spec.threshold_clear_log_e,
            "max_log_e": spec.max_log_e,
            "min_log_e": spec.min_log_e,
            "max_step_abs_log_e": spec.max_step_abs_log_e,
            "alpha_base": spec.alpha_base,
            "alpha_wealth_init": spec.alpha_wealth_init,
            "alpha_wealth_cap": spec.alpha_wealth_cap,
            "alpha_spend_per_decision": spec.alpha_spend_per_decision,
            "alpha_reward_per_safe_decision": spec.alpha_reward_per_safe_decision,
            "freeze_on_exhaust": spec.freeze_on_exhaust,
            "max_weight": spec.max_weight,
            "severity_weights": dict(spec.severity_weights),
            "min_p_value": spec.min_p_value,
            "max_p_value": spec.max_p_value,
            "p_to_e_kappas": list(spec.p_to_e_kappas),
            "p_to_e_weights": list(spec.p_to_e_weights),
            "score_to_p_mode": spec.score_to_p_mode,
            "score_reference": spec.score_reference,
            "score_scale": spec.score_scale,
            "heuristic_p_weight": spec.heuristic_p_weight,
            "strict_requires_direct_p": spec.strict_requires_direct_p,
            "heuristic_allowed_for_blocking": spec.heuristic_allowed_for_blocking,
            "calibrated_score_allowed_for_blocking": spec.calibrated_score_allowed_for_blocking,
            "neutral_update_mode": spec.neutral_update_mode,
            "neutral_decay_rate": spec.neutral_decay_rate,
            "stream_identity": {
                "mode": spec.stream_identity.mode,
                "schema_ref": spec.stream_identity.schema_ref,
                "include_fields": list(spec.stream_identity.include_fields),
                "strict_profiles_forbid_default": spec.stream_identity.strict_profiles_forbid_default,
                "expose_raw_stream_id": spec.stream_identity.expose_raw_stream_id,
                "hash_only_in_strict": spec.stream_identity.hash_only_in_strict,
                "on_identity_error": spec.stream_identity.on_identity_error,
            },
            "score_adapter_default": spec.score_adapter_default,
            "stream_hash_algorithm": secret.stream_hash_algorithm,
            "stream_hash_key_id": secret.stream_hash_key_id,
            "stream_hash_mode": secret.stream_hash_mode,
            "min_stream_hash_key_bytes": secret.min_stream_hash_key_bytes,
            "enabled": runtime.enabled,
            "max_streams": runtime.max_streams,
            "idle_ttl_s": runtime.idle_ttl_s,
            "stream_cleanup_budget": runtime.stream_cleanup_budget,
            "new_stream_policy": runtime.new_stream_policy,
            "on_state_exhaustion": runtime.on_state_exhaustion,
            "evict_only_inactive_streams": runtime.evict_only_inactive_streams,
            "max_retired_state_domains": runtime.max_retired_state_domains,
            "history_window": runtime.history_window,
            "retain_history": runtime.retain_history,
            "include_history_in_snapshot": runtime.include_history_in_snapshot,
            "ewma_alpha": runtime.ewma_alpha,
            "meta_max_nodes": runtime.meta_max_nodes,
            "meta_max_items": runtime.meta_max_items,
            "meta_max_depth": runtime.meta_max_depth,
            "meta_max_str_total": runtime.meta_max_str_total,
            "audit_emit_all_steps": runtime.audit_emit_all_steps,
            "audit_emit_triggers": runtime.audit_emit_triggers,
            "telemetry_emit_all_steps": runtime.telemetry_emit_all_steps,
            "telemetry_emit_triggers": runtime.telemetry_emit_triggers,
            "receipt_issue_on_block": runtime.receipt_issue_on_block,
            "receipt_issue_on_trigger": runtime.receipt_issue_on_trigger,
        }
        raw = _canon_json(payload).encode("utf-8", errors="strict")
        d = hashlib.sha256(raw).hexdigest()
        return f"cfg1:{d}"
# ---------------------------------------------------------------------------
# State models / backend
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class EProcessState:
    strict_log_e: float = 0.0
    controller_log_e: float = 0.0
    alpha_wealth: float = 1.0
    decisions: int = 0
    triggers: int = 0
    active: bool = False
    frozen: bool = False
    last_trigger_step: Optional[int] = None
    exhausted_step: Optional[int] = None
    last_update_mono_ns: int = 0
    last_update_unix_ns: int = 0
    last_p_value: float = 1.0
    last_p_source: str = "neutral"
    last_score: Optional[float] = None
    last_calibration_ref: Optional[str] = None
    last_calibration_cfg_digest: Optional[str] = None
    last_calibration_state_digest: Optional[str] = None
    last_guarantee_scope: GuaranteeScope = "none"
    ewma_score: Optional[float] = None
    ewma_neglogp: float = 0.0
    min_p_value: float = 1.0
    min_p_value_step: Optional[int] = None
    max_score: Optional[float] = None
    max_score_step: Optional[int] = None
    direct_p_steps: int = 0
    calibrated_p_steps: int = 0
    heuristic_p_steps: int = 0
    neutral_steps: int = 0
    small_p_count_05: int = 0
    small_p_count_01: int = 0
    small_p_count_001: int = 0
    fisher_stat: float = 0.0
    fisher_df: int = 0
    history_p: deque[float] = field(default_factory=deque)
    history_score: deque[float] = field(default_factory=deque)
    history_log_e: deque[float] = field(default_factory=deque)
def _clone_state(st: EProcessState, *, history_window: int) -> EProcessState:
    maxlen = history_window if history_window > 0 else None
    return EProcessState(
        strict_log_e=st.strict_log_e,
        controller_log_e=st.controller_log_e,
        alpha_wealth=st.alpha_wealth,
        decisions=st.decisions,
        triggers=st.triggers,
        active=st.active,
        frozen=st.frozen,
        last_trigger_step=st.last_trigger_step,
        exhausted_step=st.exhausted_step,
        last_update_mono_ns=st.last_update_mono_ns,
        last_update_unix_ns=st.last_update_unix_ns,
        last_p_value=st.last_p_value,
        last_p_source=st.last_p_source,
        last_score=st.last_score,
        last_calibration_ref=st.last_calibration_ref,
        last_calibration_cfg_digest=st.last_calibration_cfg_digest,
        last_calibration_state_digest=st.last_calibration_state_digest,
        last_guarantee_scope=st.last_guarantee_scope,
        ewma_score=st.ewma_score,
        ewma_neglogp=st.ewma_neglogp,
        min_p_value=st.min_p_value,
        min_p_value_step=st.min_p_value_step,
        max_score=st.max_score,
        max_score_step=st.max_score_step,
        direct_p_steps=st.direct_p_steps,
        calibrated_p_steps=st.calibrated_p_steps,
        heuristic_p_steps=st.heuristic_p_steps,
        neutral_steps=st.neutral_steps,
        small_p_count_05=st.small_p_count_05,
        small_p_count_01=st.small_p_count_01,
        small_p_count_001=st.small_p_count_001,
        fisher_stat=st.fisher_stat,
        fisher_df=st.fisher_df,
        history_p=deque(list(st.history_p), maxlen=maxlen),
        history_score=deque(list(st.history_score), maxlen=maxlen),
        history_log_e=deque(list(st.history_log_e), maxlen=maxlen),
    )
@dataclass(frozen=True)
class StateRecord:
    state_domain_id: str
    stream_hash: str
    revision: int
    state: EProcessState
class EProcessStateBackend(Protocol):
    def load(self, *, state_domain_id: str, stream_hash: str, history_window: int) -> Optional[StateRecord]:
        ...
    def upsert(
        self,
        *,
        state_domain_id: str,
        stream_hash: str,
        expected_revision: Optional[int],
        new_state: EProcessState,
        max_streams: int,
        new_stream_policy: NewStreamPolicy,
        evict_only_inactive_streams: bool,
        idle_ttl_ns: int,
        now_mono_ns: int,
        history_window: int,
    ) -> Tuple[bool, Optional[StateRecord], str]:
        ...
    def delete_stream(self, *, state_domain_id: str, stream_hash: str) -> bool:
        ...
    def clear_domain(self, *, state_domain_id: str) -> int:
        ...
    def compact(self, *, state_domain_id: str, idle_ttl_ns: int, now_mono_ns: int, budget: int) -> Dict[str, int]:
        ...
    def list_streams(self, *, state_domain_id: str, limit: int, history_window: int) -> List[StateRecord]:
        ...
    def count_streams(self, *, state_domain_id: str) -> int:
        ...
    def health(self) -> Dict[str, Any]:
        ...
@dataclass
class _DomainStore:
    records: Dict[str, StateRecord] = field(default_factory=dict)
    lru: "OrderedDict[str, None]" = field(default_factory=OrderedDict)
class InMemoryEProcessStateBackend:
    """
    Local best-effort backend with:
      - per-domain record map
      - LRU eviction
      - idle compaction
      - compare-and-swap style revision updates
    """
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._domains: Dict[str, _DomainStore] = {}
        self._cas_conflicts = 0
        self._compactions = 0
        self._evictions = 0
    def load(self, *, state_domain_id: str, stream_hash: str, history_window: int) -> Optional[StateRecord]:
        with self._lock:
            ds = self._domains.get(state_domain_id)
            if ds is None:
                return None
            rec = ds.records.get(stream_hash)
            if rec is None:
                return None
            ds.lru.pop(stream_hash, None)
            ds.lru[stream_hash] = None
            return StateRecord(
                state_domain_id=rec.state_domain_id,
                stream_hash=rec.stream_hash,
                revision=rec.revision,
                state=_clone_state(rec.state, history_window=history_window),
            )
    def upsert(
        self,
        *,
        state_domain_id: str,
        stream_hash: str,
        expected_revision: Optional[int],
        new_state: EProcessState,
        max_streams: int,
        new_stream_policy: NewStreamPolicy,
        evict_only_inactive_streams: bool,
        idle_ttl_ns: int,
        now_mono_ns: int,
        history_window: int,
    ) -> Tuple[bool, Optional[StateRecord], str]:
        with self._lock:
            ds = self._domains.setdefault(state_domain_id, _DomainStore())
            self._compact_domain_locked(ds, idle_ttl_ns=idle_ttl_ns, now_mono_ns=now_mono_ns, budget=max(1, 8))
            existing = ds.records.get(stream_hash)
            if existing is None:
                if len(ds.records) >= max_streams:
                    if new_stream_policy != "evict_lru":
                        return False, None, "state_capacity_exhausted"
                    victim: Optional[str] = None
                    for k in ds.lru.keys():
                        rec = ds.records.get(k)
                        if rec is None:
                            victim = k
                            break
                        if evict_only_inactive_streams and rec.state.active:
                            continue
                        victim = k
                        break
                    if victim is None:
                        return False, None, "state_capacity_exhausted"
                    ds.records.pop(victim, None)
                    ds.lru.pop(victim, None)
                    self._evictions += 1
                revision = 1
            else:
                if expected_revision is not None and existing.revision != expected_revision:
                    self._cas_conflicts += 1
                    return False, None, "revision_conflict"
                revision = existing.revision + 1
            rec = StateRecord(
                state_domain_id=state_domain_id,
                stream_hash=stream_hash,
                revision=revision,
                state=_clone_state(new_state, history_window=history_window),
            )
            ds.records[stream_hash] = rec
            ds.lru.pop(stream_hash, None)
            ds.lru[stream_hash] = None
            out = StateRecord(
                state_domain_id=rec.state_domain_id,
                stream_hash=rec.stream_hash,
                revision=rec.revision,
                state=_clone_state(rec.state, history_window=history_window),
            )
            return True, out, "ok"
    def delete_stream(self, *, state_domain_id: str, stream_hash: str) -> bool:
        with self._lock:
            ds = self._domains.get(state_domain_id)
            if ds is None:
                return False
            existed = stream_hash in ds.records
            ds.records.pop(stream_hash, None)
            ds.lru.pop(stream_hash, None)
            if not ds.records:
                self._domains.pop(state_domain_id, None)
            return existed
    def clear_domain(self, *, state_domain_id: str) -> int:
        with self._lock:
            ds = self._domains.pop(state_domain_id, None)
            if ds is None:
                return 0
            return len(ds.records)
    def compact(self, *, state_domain_id: str, idle_ttl_ns: int, now_mono_ns: int, budget: int) -> Dict[str, int]:
        with self._lock:
            ds = self._domains.get(state_domain_id)
            if ds is None:
                return {"removed": 0}
            removed = self._compact_domain_locked(ds, idle_ttl_ns=idle_ttl_ns, now_mono_ns=now_mono_ns, budget=budget)
            if not ds.records:
                self._domains.pop(state_domain_id, None)
            return {"removed": removed}
    def list_streams(self, *, state_domain_id: str, limit: int, history_window: int) -> List[StateRecord]:
        lim = _clamp_int(limit, default=100, lo=1, hi=100_000)
        with self._lock:
            ds = self._domains.get(state_domain_id)
            if ds is None:
                return []
            out: List[StateRecord] = []
            for sh in reversed(ds.lru.keys()):
                rec = ds.records.get(sh)
                if rec is None:
                    continue
                out.append(
                    StateRecord(
                        state_domain_id=rec.state_domain_id,
                        stream_hash=rec.stream_hash,
                        revision=rec.revision,
                        state=_clone_state(rec.state, history_window=history_window),
                    )
                )
                if len(out) >= lim:
                    break
            return out
    def count_streams(self, *, state_domain_id: str) -> int:
        with self._lock:
            ds = self._domains.get(state_domain_id)
            return len(ds.records) if ds is not None else 0
    def health(self) -> Dict[str, Any]:
        with self._lock:
            total = 0
            per_domain: Dict[str, int] = {}
            for did, ds in self._domains.items():
                n = len(ds.records)
                total += n
                per_domain[did] = n
            return {
                "backend": "memory",
                "domain_count": len(self._domains),
                "total_streams": total,
                "per_domain": per_domain,
                "cas_conflicts": int(self._cas_conflicts),
                "compactions": int(self._compactions),
                "evictions": int(self._evictions),
            }
    def _compact_domain_locked(self, ds: _DomainStore, *, idle_ttl_ns: int, now_mono_ns: int, budget: int) -> int:
        if idle_ttl_ns <= 0 or budget <= 0:
            return 0
        removed = 0
        while budget > 0 and ds.lru:
            stream_hash = next(iter(ds.lru.keys()))
            rec = ds.records.get(stream_hash)
            if rec is None:
                ds.lru.pop(stream_hash, None)
                budget -= 1
                continue
            if (now_mono_ns - rec.state.last_update_mono_ns) <= idle_ttl_ns:
                break
            ds.records.pop(stream_hash, None)
            ds.lru.pop(stream_hash, None)
            removed += 1
            budget -= 1
        if removed > 0:
            self._compactions += 1
        return removed
# ---------------------------------------------------------------------------
# Split config -> compiled bundle
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class _CompiledBundle:
    version: int
    updated_at_unix_ns: int
    cfg_fp: str
    state_domain_id: str
    adapter_registry_fp: str
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    enabled: bool
    policy_spec: AlwaysValidPolicySpec
    secret_cfg: AlwaysValidSecretConfig
    runtime_cfg: AlwaysValidRuntimeConfig
    monotonic_fn: Callable[[], Any]
    wall_time_fn: Callable[[], Any]
# ---------------------------------------------------------------------------
# Adapter implementations
# ---------------------------------------------------------------------------
class HeuristicScoreAdapter:
    """
    Deterministic heuristic adapter.
    Advisory-grade by default; not strict-valid.
    """
    def __init__(
        self,
        *,
        mode: ScoreToPMode = "one_minus_score",
        score_reference: float = 0.5,
        score_scale: float = 10.0,
        adapter_ref: str = "heuristic.default",
    ) -> None:
        self._mode = mode if mode in {"one_minus_score", "sigmoid_tail", "exp_tail"} else "one_minus_score"
        self._score_reference = float(score_reference)
        self._score_scale = float(score_scale) if math.isfinite(float(score_scale)) and float(score_scale) > 0.0 else 10.0
        self._ref = _safe_id(adapter_ref, default="heuristic.default", max_len=64) or "heuristic.default"
    def p_value(self, *, score: float, meta: Mapping[str, Any], ctx: Mapping[str, Any]) -> float:
        s = float(score)
        if self._mode == "one_minus_score":
            x = 1.0 - s
        elif self._mode == "sigmoid_tail":
            z = self._score_scale * (s - self._score_reference)
            if z >= 0:
                ez = math.exp(-z)
                x = ez / (1.0 + ez)
            else:
                ez = math.exp(z)
                x = 1.0 / (1.0 + ez)
        else:
            z = max(0.0, s - self._score_reference)
            x = math.exp(-self._score_scale * z)
        if not math.isfinite(x):
            return 1.0
        return float(x)
    def provenance(self) -> Dict[str, Any]:
        payload = {
            "adapter_ref": self._ref,
            "mode": self._mode,
            "score_reference": self._score_reference,
            "score_scale": self._score_scale,
        }
        cfg_digest = hashlib.sha256(_canon_json(payload).encode("utf-8", errors="strict")).hexdigest()
        return {
            "adapter_ref": self._ref,
            "guarantee_scope": "heuristic_only",
            "cfg_digest": cfg_digest,
            "state_digest": None,
            "engine": "heuristic",
        }
class PredictableScoreAdapter:
    """
    Adapter around an external calibrator-like object.
    Supported methods (first matching callable is used):
      - p_value(score=..., meta=..., ctx=...)
      - predict_p_value(score=..., meta=..., ctx=...)
      - predict(score)
      - __call__(score)
    """
    def __init__(self, calibrator: Any, *, adapter_ref: str = "predictable.default") -> None:
        self._calibrator = calibrator
        self._ref = _safe_id(adapter_ref, default="predictable.default", max_len=64) or "predictable.default"
    def p_value(self, *, score: float, meta: Mapping[str, Any], ctx: Mapping[str, Any]) -> float:
        cal = self._calibrator
        for method_name in ("p_value", "predict_p_value"):
            fn = getattr(cal, method_name, None)
            if callable(fn):
                try:
                    out = fn(score=score, meta=meta, ctx=ctx)
                except TypeError:
                    out = fn(score)
                p = _coerce_float(out)
                if p is not None:
                    return float(p)
        fn_pred = getattr(cal, "predict", None)
        if callable(fn_pred):
            try:
                out = fn_pred(score)
            except Exception:
                out = None
            p = _coerce_float(out)
            if p is not None:
                return float(p)
        if callable(cal):
            try:
                out = cal(score)
            except Exception:
                out = None
            p = _coerce_float(out)
            if p is not None:
                return float(p)
        raise ValueError("predictable calibrator did not return a valid finite p-value")
    def provenance(self) -> Dict[str, Any]:
        cal = self._calibrator
        cfg_digest = None
        state_digest = None
        engine = "predictable"
        x = getattr(cal, "cfg_digest_hex", None)
        if type(x) is str:
            cfg_digest = _safe_id(x, default=None, max_len=128)
        x = getattr(cal, "cfg_fp", None)
        if cfg_digest is None and type(x) is str:
            cfg_digest = _safe_id(x, default=None, max_len=128)
        fn = getattr(cal, "state_digest", None)
        if callable(fn):
            try:
                sd = fn()
            except Exception:
                sd = None
            if type(sd) is str:
                state_digest = _safe_id(sd, default=None, max_len=128)
        x = getattr(cal, "engine_version", None)
        if type(x) is str:
            engine = _safe_id(x, default="predictable", max_len=64) or "predictable"
        if cfg_digest is None:
            payload = {
                "adapter_ref": self._ref,
                "engine": engine,
                "type": type(cal).__name__,
            }
            cfg_digest = hashlib.sha256(_canon_json(payload).encode("utf-8", errors="strict")).hexdigest()
        return {
            "adapter_ref": self._ref,
            "guarantee_scope": "predictable_calibrated_p",
            "cfg_digest": cfg_digest,
            "state_digest": state_digest,
            "engine": engine,
        }
# ---------------------------------------------------------------------------
# Main controller
# ---------------------------------------------------------------------------
class AlwaysValidRiskController:
    """
    Research-grade anytime-valid / e-process statistical platform.
    Properties:
      - immutable compiled config bundle + atomic swap
      - strict direct-p track and richer controller track
      - bounded, privacy-aware state store
      - dual clocks for auditability / replay
      - optional audit / receipt / telemetry integration
      - content-agnostic: never inspects request payloads
    """
    def __init__(
        self,
        config: Optional[AlwaysValidConfig] = None,
        *,
        state_backend: Optional[EProcessStateBackend] = None,
        score_adapters: Optional[Mapping[str, ScoreToPAdapter]] = None,
        audit_sink: Optional[AlwaysValidAuditSink] = None,
        telemetry_sink: Optional[AlwaysValidTelemetrySink] = None,
        receipt_sink: Optional[AlwaysValidReceiptSink] = None,
        **overrides: Any,
    ) -> None:
        base = config or AlwaysValidConfig()
        for key, value in overrides.items():
            if hasattr(base, key):
                try:
                    setattr(base, key, value)
                except Exception:
                    pass
        self._bundle_lock = threading.RLock()
        self._seq_lock = threading.Lock()
        self._instance_id = os.urandom(8).hex()
        self._audit_sink = audit_sink
        self._telemetry_sink = telemetry_sink
        self._receipt_sink = receipt_sink
        self._backend: EProcessStateBackend = state_backend or InMemoryEProcessStateBackend()
        self._score_adapters = self._normalize_score_adapters(score_adapters or {})
        self._adapter_registry_fp = self._fingerprint_score_adapters(self._score_adapters)
        self._source_config = base.normalized_copy()
        initial_bundle = self._compile_bundle(self._source_config, previous=None, adapter_registry_fp=self._adapter_registry_fp)
        if initial_bundle.errors and initial_bundle.policy_spec.on_config_error == "raise":
            raise ValueError("invalid AlwaysValidConfig: " + "; ".join(initial_bundle.errors[:3]))
        self._bundle = initial_bundle
        self._last_known_good: Optional[_CompiledBundle] = None if initial_bundle.errors else initial_bundle
        self._rejected_bundle: Optional[_CompiledBundle] = None
        self._using_last_known_good = False
        self._retired_domain_ids: deque[str] = deque(maxlen=max(1, initial_bundle.runtime_cfg.max_retired_state_domains))
        # health counters
        self._decision_seq = 0
        self._state_capacity_denies = 0
        self._config_error_denies = 0
        self._backend_conflict_denies = 0
        self._identity_denies = 0
        self._allowed_steps = 0
        self._blocked_steps = 0
        self._audit_emit_failures = 0
        self._telemetry_emit_failures = 0
        self._receipt_emit_failures = 0
    # ------------------------------------------------------------------
    # Public config / diagnostics API
    # ------------------------------------------------------------------
    @property
    def config(self) -> AlwaysValidConfig:
        """
        Secret-stripped normalized config snapshot.
        """
        with self._bundle_lock:
            return self._source_config.secret_stripped_copy()
    @property
    def cfg_fp(self) -> str:
        with self._bundle_lock:
            return self._bundle.cfg_fp
    @property
    def bundle_version(self) -> int:
        with self._bundle_lock:
            return self._bundle.version
    def public_config_snapshot(self) -> AlwaysValidPublicConfigView:
        with self._bundle_lock:
            b = self._bundle
            return AlwaysValidPublicConfigView(
                cfg_fp=b.cfg_fp,
                bundle_version=b.version,
                policyset_ref=b.policy_spec.policyset_ref,
                profile=b.policy_spec.profile,
                label=b.policy_spec.label,
                decision_mode=b.policy_spec.decision_mode,
                on_config_error=b.policy_spec.on_config_error,
                stream_hash_algorithm=b.secret_cfg.stream_hash_algorithm,
                stream_hash_key_id=b.secret_cfg.stream_hash_key_id,
                stream_hash_mode=b.secret_cfg.stream_hash_mode,
                state_domain_id=b.state_domain_id,
                adapter_registry_fp=b.adapter_registry_fp,
                enabled=b.enabled,
                has_errors=bool(b.errors),
                has_warnings=bool(b.warnings),
            )
    def bundle_diagnostics(self) -> AlwaysValidBundleDiagnostics:
        with self._bundle_lock:
            active = self._bundle
            lkg = self._last_known_good
            rejected = self._rejected_bundle
            return AlwaysValidBundleDiagnostics(
                active_cfg_fp=active.cfg_fp,
                active_bundle_version=active.version,
                active_updated_at_unix_ns=active.updated_at_unix_ns,
                policyset_ref=active.policy_spec.policyset_ref,
                profile=active.policy_spec.profile,
                label=active.policy_spec.label,
                enabled=active.enabled,
                state_domain_id=active.state_domain_id,
                adapter_registry_fp=active.adapter_registry_fp,
                stream_hash_algorithm=active.secret_cfg.stream_hash_algorithm,
                stream_hash_key_id=active.secret_cfg.stream_hash_key_id,
                stream_hash_mode=active.secret_cfg.stream_hash_mode,
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
            "controller": _CONTROLLER_NAME,
            "version": _CONTROLLER_VERSION,
            "instance_id": self._instance_id,
            "cfg_fp": d.active_cfg_fp,
            "bundle_version": d.active_bundle_version,
            "updated_at_unix_ns": d.active_updated_at_unix_ns,
            "profile": d.profile,
            "label": d.label,
            "policyset_ref": d.policyset_ref,
            "enabled": d.enabled,
            "state_domain_id": d.state_domain_id,
            "adapter_registry_fp": d.adapter_registry_fp,
            "stream_hash_algorithm": d.stream_hash_algorithm,
            "stream_hash_key_id": d.stream_hash_key_id,
            "stream_hash_mode": d.stream_hash_mode,
            "error_count": len(d.errors),
            "warning_count": len(d.warnings),
            "errors": list(d.errors[:50]),
            "warnings": list(d.warnings[:50]),
            "using_last_known_good": d.using_last_known_good,
            "last_known_good_cfg_fp": d.last_known_good_cfg_fp,
            "last_rejected_cfg_fp": d.last_rejected_cfg_fp,
            "state_scope": "local_best_effort",
        }
    def set_config(self, config: AlwaysValidConfig) -> None:
        new_cfg = config.normalized_copy()
        with self._bundle_lock:
            previous = self._bundle
            new_bundle = self._compile_bundle(new_cfg, previous=previous, adapter_registry_fp=self._adapter_registry_fp)
            if new_bundle.errors and new_bundle.policy_spec.on_config_error == "raise":
                raise ValueError("invalid AlwaysValidConfig: " + "; ".join(new_bundle.errors[:3]))
            if new_bundle.errors and new_bundle.policy_spec.on_config_error == "use_last_known_good" and self._last_known_good is not None:
                self._rejected_bundle = new_bundle
                self._using_last_known_good = True
                return
            old_domain = previous.state_domain_id
            self._source_config = new_cfg
            self._bundle = new_bundle
            self._rejected_bundle = new_bundle if new_bundle.errors else None
            self._using_last_known_good = False
            if not new_bundle.errors:
                self._last_known_good = new_bundle
            new_domain = new_bundle.state_domain_id
            if old_domain != new_domain:
                self._retired_domain_ids.append(old_domain)
                max_keep = max(0, new_bundle.runtime_cfg.max_retired_state_domains)
                while len(self._retired_domain_ids) > max_keep:
                    stale = self._retired_domain_ids.popleft()
                    try:
                        self._backend.clear_domain(state_domain_id=stale)
                    except Exception:
                        pass
    def set_score_adapters(self, adapters: Mapping[str, ScoreToPAdapter]) -> None:
        normalized = self._normalize_score_adapters(adapters)
        adapter_fp = self._fingerprint_score_adapters(normalized)
        with self._bundle_lock:
            self._score_adapters = normalized
            self._adapter_registry_fp = adapter_fp
            # Recompile against current source config
            previous = self._bundle
            new_bundle = self._compile_bundle(self._source_config, previous=previous, adapter_registry_fp=adapter_fp)
            if new_bundle.errors and new_bundle.policy_spec.on_config_error == "raise":
                raise ValueError("invalid config after adapter swap: " + "; ".join(new_bundle.errors[:3]))
            if new_bundle.errors and new_bundle.policy_spec.on_config_error == "use_last_known_good" and self._last_known_good is not None:
                self._rejected_bundle = new_bundle
                self._using_last_known_good = True
                return
            old_domain = previous.state_domain_id
            self._bundle = new_bundle
            self._rejected_bundle = new_bundle if new_bundle.errors else None
            self._using_last_known_good = False
            if not new_bundle.errors:
                self._last_known_good = new_bundle
            if old_domain != new_bundle.state_domain_id:
                self._retired_domain_ids.append(old_domain)
                max_keep = max(0, new_bundle.runtime_cfg.max_retired_state_domains)
                while len(self._retired_domain_ids) > max_keep:
                    stale = self._retired_domain_ids.popleft()
                    try:
                        self._backend.clear_domain(state_domain_id=stale)
                    except Exception:
                        pass
    # ------------------------------------------------------------------
    # Public runtime API
    # ------------------------------------------------------------------
    def step(
        self,
        request: Any = None,
        *,
        stream_id: Optional[str] = None,
        p_value: Optional[float] = None,
        score: Optional[float] = None,
        score_adapter: Optional[str] = None,
        weight: float = 1.0,
        severity: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        **ctx: Any,
    ) -> Dict[str, Any]:
        bundle, base_mode = self._bundle_snapshot()
        now_mono_ns = self._mono_ns(bundle)
        now_unix_ns = self._wall_ns(bundle)
        meta_s = self._sanitize_meta_dict(bundle, meta or {})
        ctx_s = self._sanitize_meta_dict(bundle, ctx or {})
        identity = self._build_identity_result(
            bundle=bundle,
            stream_id=stream_id,
            request=request,
            meta=meta_s,
            ctx=ctx_s,
        )
        # Disabled
        if not bundle.enabled:
            seq = self._next_decision_seq()
            result = self._build_step_result(
                bundle=bundle,
                sid=identity.canonical_stream_id or "default",
                stream_hash=identity.stream_hash,
                state=None,
                state_revision=None,
                allowed=True,
                action="allow",
                reason="disabled",
                controller_mode=base_mode,
                degraded_reasons=(),
                evidence=EvidencePacket(
                    current_step_has_direct_p=False,
                    strict_p_value=None,
                    current_step_has_controller_p=False,
                    controller_p_value=None,
                    controller_p_kind="neutral",
                    current_step_has_calibrated_p=False,
                    calibrated_p_value=None,
                    calibration_ref=None,
                    calibration_cfg_digest=None,
                    calibration_state_digest=None,
                    current_step_has_score=False,
                    raw_score=self._normalize_score(score),
                    score_source=None,
                    guarantee_scope="none",
                ),
                effective_weight=0.0,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
                meta_s=meta_s,
                ctx_s=ctx_s,
                has_request=request is not None,
                decision_seq=seq,
                identity=identity,
                audit_ref=None,
                receipt_ref=None,
            )
            self._emit_artifacts(bundle=bundle, result=result)
            return result
        # Config errors on active bundle
        if bundle.errors:
            if bundle.policy_spec.on_config_error == "raise":
                raise RuntimeError("AlwaysValidRiskController active bundle has compile errors")
            seq = self._next_decision_seq()
            self._config_error_denies += 1
            self._blocked_steps += 1
            result = self._build_step_result(
                bundle=bundle,
                sid=identity.canonical_stream_id or "default",
                stream_hash=identity.stream_hash,
                state=None,
                state_revision=None,
                allowed=False,
                action="degraded_block",
                reason="config_error",
                controller_mode="fail_closed",
                degraded_reasons=tuple(bundle.errors[:8]),
                evidence=EvidencePacket(
                    current_step_has_direct_p=False,
                    strict_p_value=None,
                    current_step_has_controller_p=False,
                    controller_p_value=None,
                    controller_p_kind="neutral",
                    current_step_has_calibrated_p=False,
                    calibrated_p_value=None,
                    calibration_ref=None,
                    calibration_cfg_digest=None,
                    calibration_state_digest=None,
                    current_step_has_score=score is not None,
                    raw_score=self._normalize_score(score),
                    score_source=None,
                    guarantee_scope="none",
                ),
                effective_weight=0.0,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
                meta_s=meta_s,
                ctx_s=ctx_s,
                has_request=request is not None,
                decision_seq=seq,
                identity=identity,
                audit_ref=None,
                receipt_ref=None,
            )
            self._emit_artifacts(bundle=bundle, result=result)
            return result
        # Identity gating
        if identity.identity_status in {"missing", "invalid"}:
            if bundle.policy_spec.stream_identity.on_identity_error == "allow_degraded":
                seq = self._next_decision_seq()
                self._allowed_steps += 1
                result = self._build_step_result(
                    bundle=bundle,
                    sid=identity.canonical_stream_id or "default",
                    stream_hash=identity.stream_hash,
                    state=None,
                    state_revision=None,
                    allowed=True,
                    action="degraded_allow",
                    reason="identity_error",
                    controller_mode="degraded_identity",
                    degraded_reasons=(identity.identity_status,),
                    evidence=EvidencePacket(
                        current_step_has_direct_p=False,
                        strict_p_value=None,
                        current_step_has_controller_p=False,
                        controller_p_value=None,
                        controller_p_kind="neutral",
                        current_step_has_calibrated_p=False,
                        calibrated_p_value=None,
                        calibration_ref=None,
                        calibration_cfg_digest=None,
                        calibration_state_digest=None,
                        current_step_has_score=score is not None,
                        raw_score=self._normalize_score(score),
                        score_source=None,
                        guarantee_scope="none",
                    ),
                    effective_weight=0.0,
                    now_mono_ns=now_mono_ns,
                    now_unix_ns=now_unix_ns,
                    meta_s=meta_s,
                    ctx_s=ctx_s,
                    has_request=request is not None,
                    decision_seq=seq,
                    identity=identity,
                    audit_ref=None,
                    receipt_ref=None,
                )
                self._emit_artifacts(bundle=bundle, result=result)
                return result
            seq = self._next_decision_seq()
            self._identity_denies += 1
            self._blocked_steps += 1
            result = self._build_step_result(
                bundle=bundle,
                sid=identity.canonical_stream_id or "default",
                stream_hash=identity.stream_hash,
                state=None,
                state_revision=None,
                allowed=False,
                action="degraded_block",
                reason="identity_error",
                controller_mode="degraded_identity",
                degraded_reasons=(identity.identity_status,),
                evidence=EvidencePacket(
                    current_step_has_direct_p=False,
                    strict_p_value=None,
                    current_step_has_controller_p=False,
                    controller_p_value=None,
                    controller_p_kind="neutral",
                    current_step_has_calibrated_p=False,
                    calibrated_p_value=None,
                    calibration_ref=None,
                    calibration_cfg_digest=None,
                    calibration_state_digest=None,
                    current_step_has_score=score is not None,
                    raw_score=self._normalize_score(score),
                    score_source=None,
                    guarantee_scope="none",
                ),
                effective_weight=0.0,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
                meta_s=meta_s,
                ctx_s=ctx_s,
                has_request=request is not None,
                decision_seq=seq,
                identity=identity,
                audit_ref=None,
                receipt_ref=None,
            )
            self._emit_artifacts(bundle=bundle, result=result)
            return result
        evidence, calibration_degraded = self._build_evidence_packet(
            bundle=bundle,
            p_value=p_value,
            score=score,
            score_adapter=score_adapter,
            meta=meta_s,
            ctx=ctx_s,
        )
        eff_weight = self._effective_weight(bundle, weight, severity)
        stream_hash = identity.stream_hash
        state_revision: Optional[int] = None
        final_state: Optional[EProcessState] = None
        degraded_reasons: List[str] = []
        if calibration_degraded:
            degraded_reasons.append(calibration_degraded)
        for _attempt in range(3):
            try:
                rec = self._backend.load(
                    state_domain_id=bundle.state_domain_id,
                    stream_hash=stream_hash,
                    history_window=bundle.runtime_cfg.history_window,
                )
            except Exception:
                rec = None
            if rec is None:
                st = self._make_initial_state(bundle, now_mono_ns, now_unix_ns)
                expected_revision = None
            else:
                st = _clone_state(rec.state, history_window=bundle.runtime_cfg.history_window)
                expected_revision = rec.revision
            self._update_state(
                bundle=bundle,
                state=st,
                evidence=evidence,
                effective_weight=eff_weight,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
            )
            selected_log_e, selected_source, guarantee_scope = self._selected_track(bundle, st, evidence)
            prev_active = st.active
            if not prev_active:
                active = bool(selected_log_e >= bundle.policy_spec.threshold_log_e)
                newly_triggered = active
            else:
                active = bool(selected_log_e >= bundle.policy_spec.threshold_clear_log_e)
                newly_triggered = False
            st.active = active
            if newly_triggered:
                st.triggers += 1
                st.last_trigger_step = st.decisions
            if (not active) and (not st.frozen) and bundle.policy_spec.alpha_reward_per_safe_decision > 0.0:
                st.alpha_wealth = min(
                    bundle.policy_spec.alpha_wealth_cap,
                    st.alpha_wealth + bundle.policy_spec.alpha_reward_per_safe_decision,
                )
            block_basis_allowed = True
            if guarantee_scope == "heuristic_only" and not bundle.policy_spec.heuristic_allowed_for_blocking:
                block_basis_allowed = False
            if guarantee_scope == "predictable_calibrated_p" and not bundle.policy_spec.calibrated_score_allowed_for_blocking:
                block_basis_allowed = False
            if active and bundle.policy_spec.block_on_trigger and block_basis_allowed:
                allowed = False
                action: Action = "block"
                reason = "e-process-trigger"
            elif active:
                allowed = True
                action = "advisory"
                reason = "e-process-trigger-advisory"
            else:
                allowed = True
                action = "allow"
                reason = "always-valid"
            try:
                ok, new_rec, status = self._backend.upsert(
                    state_domain_id=bundle.state_domain_id,
                    stream_hash=stream_hash,
                    expected_revision=expected_revision,
                    new_state=st,
                    max_streams=bundle.runtime_cfg.max_streams,
                    new_stream_policy=bundle.runtime_cfg.new_stream_policy,
                    evict_only_inactive_streams=bundle.runtime_cfg.evict_only_inactive_streams,
                    idle_ttl_ns=bundle.runtime_cfg.idle_ttl_s * 1_000_000_000.0 if False else int(bundle.runtime_cfg.idle_ttl_s * 1_000_000_000.0),
                    now_mono_ns=now_mono_ns,
                    history_window=bundle.runtime_cfg.history_window,
                )
            except Exception:
                ok = False
                new_rec = None
                status = "backend_error"
            if ok and new_rec is not None:
                final_state = _clone_state(new_rec.state, history_window=bundle.runtime_cfg.history_window)
                state_revision = new_rec.revision
                break
            if status == "revision_conflict":
                degraded_reasons.append("revision_conflict")
                continue
            if status == "state_capacity_exhausted":
                seq = self._next_decision_seq()
                if bundle.runtime_cfg.on_state_exhaustion == "allow":
                    self._allowed_steps += 1
                    result = self._build_step_result(
                        bundle=bundle,
                        sid=identity.canonical_stream_id or "default",
                        stream_hash=stream_hash,
                        state=None,
                        state_revision=None,
                        allowed=True,
                        action="degraded_allow",
                        reason="state_capacity_exhausted",
                        controller_mode="degraded_state_backend",
                        degraded_reasons=tuple(degraded_reasons + ["state_capacity_exhausted"]),
                        evidence=evidence,
                        effective_weight=eff_weight,
                        now_mono_ns=now_mono_ns,
                        now_unix_ns=now_unix_ns,
                        meta_s=meta_s,
                        ctx_s=ctx_s,
                        has_request=request is not None,
                        decision_seq=seq,
                        identity=identity,
                        audit_ref=None,
                        receipt_ref=None,
                    )
                else:
                    self._state_capacity_denies += 1
                    self._blocked_steps += 1
                    result = self._build_step_result(
                        bundle=bundle,
                        sid=identity.canonical_stream_id or "default",
                        stream_hash=stream_hash,
                        state=None,
                        state_revision=None,
                        allowed=False,
                        action="degraded_block",
                        reason="state_capacity_exhausted",
                        controller_mode="degraded_state_backend",
                        degraded_reasons=tuple(degraded_reasons + ["state_capacity_exhausted"]),
                        evidence=evidence,
                        effective_weight=eff_weight,
                        now_mono_ns=now_mono_ns,
                        now_unix_ns=now_unix_ns,
                        meta_s=meta_s,
                        ctx_s=ctx_s,
                        has_request=request is not None,
                        decision_seq=seq,
                        identity=identity,
                        audit_ref=None,
                        receipt_ref=None,
                    )
                self._emit_artifacts(bundle=bundle, result=result)
                return result
            # backend error / unknown failure
            seq = self._next_decision_seq()
            degraded_reasons.append(status)
            if bundle.runtime_cfg.on_state_exhaustion == "allow" and bundle.policy_spec.profile not in {"FINREG", "LOCKDOWN"}:
                self._allowed_steps += 1
                result = self._build_step_result(
                    bundle=bundle,
                    sid=identity.canonical_stream_id or "default",
                    stream_hash=stream_hash,
                    state=None,
                    state_revision=None,
                    allowed=True,
                    action="degraded_allow",
                    reason="backend_error",
                    controller_mode="degraded_state_backend",
                    degraded_reasons=tuple(degraded_reasons),
                    evidence=evidence,
                    effective_weight=eff_weight,
                    now_mono_ns=now_mono_ns,
                    now_unix_ns=now_unix_ns,
                    meta_s=meta_s,
                    ctx_s=ctx_s,
                    has_request=request is not None,
                    decision_seq=seq,
                    identity=identity,
                    audit_ref=None,
                    receipt_ref=None,
                )
            else:
                self._backend_conflict_denies += 1
                self._blocked_steps += 1
                result = self._build_step_result(
                    bundle=bundle,
                    sid=identity.canonical_stream_id or "default",
                    stream_hash=stream_hash,
                    state=None,
                    state_revision=None,
                    allowed=False,
                    action="degraded_block",
                    reason="backend_error",
                    controller_mode="degraded_state_backend",
                    degraded_reasons=tuple(degraded_reasons),
                    evidence=evidence,
                    effective_weight=eff_weight,
                    now_mono_ns=now_mono_ns,
                    now_unix_ns=now_unix_ns,
                    meta_s=meta_s,
                    ctx_s=ctx_s,
                    has_request=request is not None,
                    decision_seq=seq,
                    identity=identity,
                    audit_ref=None,
                    receipt_ref=None,
                )
            self._emit_artifacts(bundle=bundle, result=result)
            return result
        else:
            seq = self._next_decision_seq()
            self._backend_conflict_denies += 1
            self._blocked_steps += 1
            result = self._build_step_result(
                bundle=bundle,
                sid=identity.canonical_stream_id or "default",
                stream_hash=stream_hash,
                state=None,
                state_revision=None,
                allowed=False,
                action="degraded_block",
                reason="backend_conflict",
                controller_mode="degraded_state_backend",
                degraded_reasons=tuple(degraded_reasons + ["backend_conflict"]),
                evidence=evidence,
                effective_weight=eff_weight,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
                meta_s=meta_s,
                ctx_s=ctx_s,
                has_request=request is not None,
                decision_seq=seq,
                identity=identity,
                audit_ref=None,
                receipt_ref=None,
            )
            self._emit_artifacts(bundle=bundle, result=result)
            return result
        if final_state is None:
            # extremely defensive fallback
            seq = self._next_decision_seq()
            self._backend_conflict_denies += 1
            self._blocked_steps += 1
            result = self._build_step_result(
                bundle=bundle,
                sid=identity.canonical_stream_id or "default",
                stream_hash=stream_hash,
                state=None,
                state_revision=None,
                allowed=False,
                action="degraded_block",
                reason="backend_error",
                controller_mode="degraded_state_backend",
                degraded_reasons=tuple(degraded_reasons + ["backend_error"]),
                evidence=evidence,
                effective_weight=eff_weight,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
                meta_s=meta_s,
                ctx_s=ctx_s,
                has_request=request is not None,
                decision_seq=seq,
                identity=identity,
                audit_ref=None,
                receipt_ref=None,
            )
            self._emit_artifacts(bundle=bundle, result=result)
            return result
        seq = self._next_decision_seq()
        if action in {"block", "degraded_block"}:
            self._blocked_steps += 1
        else:
            self._allowed_steps += 1
        controller_mode: ControllerMode = base_mode
        if calibration_degraded:
            controller_mode = "degraded_calibration"
        result = self._build_step_result(
            bundle=bundle,
            sid=identity.canonical_stream_id or "default",
            stream_hash=stream_hash,
            state=final_state,
            state_revision=state_revision,
            allowed=allowed,
            action=action,
            reason=reason,
            controller_mode=controller_mode,
            degraded_reasons=tuple(degraded_reasons),
            evidence=evidence,
            effective_weight=eff_weight,
            now_mono_ns=now_mono_ns,
            now_unix_ns=now_unix_ns,
            meta_s=meta_s,
            ctx_s=ctx_s,
            has_request=request is not None,
            decision_seq=seq,
            identity=identity,
            audit_ref=None,
            receipt_ref=None,
        )
        self._emit_artifacts(bundle=bundle, result=result)
        return result
    def step_direct_p(
        self,
        *,
        stream_id: Optional[str],
        p_value: float,
        weight: float = 1.0,
        severity: Optional[str] = None,
        meta: Optional[Mapping[str, Any]] = None,
        ctx: Optional[Mapping[str, Any]] = None,
        request: Any = None,
    ) -> Dict[str, Any]:
        return self.step(
            request=request,
            stream_id=stream_id,
            p_value=p_value,
            score=None,
            weight=weight,
            severity=severity,
            meta=dict(meta or {}),
            **dict(ctx or {}),
        )
    def step_score(
        self,
        *,
        stream_id: Optional[str],
        score: float,
        score_adapter: Optional[str] = None,
        weight: float = 1.0,
        severity: Optional[str] = None,
        meta: Optional[Mapping[str, Any]] = None,
        ctx: Optional[Mapping[str, Any]] = None,
        request: Any = None,
    ) -> Dict[str, Any]:
        return self.step(
            request=request,
            stream_id=stream_id,
            p_value=None,
            score=score,
            score_adapter=score_adapter,
            weight=weight,
            severity=severity,
            meta=dict(meta or {}),
            **dict(ctx or {}),
        )
    def step_many(self, items: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, Mapping):
                out.append(self.step())
                continue
            request = item.get("request")
            kwargs: Dict[str, Any] = {}
            for k, v in item.items():
                if k == "request":
                    continue
                kwargs[k] = v
            out.append(self.step(request=request, **kwargs))
        return out
    def snapshot(self, stream_id: Optional[str] = None) -> Dict[str, Any]:
        bundle, base_mode = self._bundle_snapshot()
        now_mono_ns = self._mono_ns(bundle)
        now_unix_ns = self._wall_ns(bundle)
        identity = self._build_identity_result(
            bundle=bundle,
            stream_id=stream_id,
            request=None,
            meta={},
            ctx={},
        )
        rec = self._backend.load(
            state_domain_id=bundle.state_domain_id,
            stream_hash=identity.stream_hash,
            history_window=bundle.runtime_cfg.history_window,
        )
        return self._build_snapshot_result(
            bundle=bundle,
            sid=identity.canonical_stream_id or "default",
            stream_hash=identity.stream_hash,
            state=rec.state if rec is not None else None,
            state_revision=rec.revision if rec is not None else None,
            now_mono_ns=now_mono_ns,
            now_unix_ns=now_unix_ns,
            controller_mode=base_mode,
            identity=identity,
        )
    def reset_stream(self, stream_id: str) -> bool:
        bundle, _ = self._bundle_snapshot()
        identity = self._build_identity_result(
            bundle=bundle,
            stream_id=stream_id,
            request=None,
            meta={},
            ctx={},
        )
        existed = self._backend.delete_stream(
            state_domain_id=bundle.state_domain_id,
            stream_hash=identity.stream_hash,
        )
        if existed:
            self._emit_mutation_event(
                bundle=bundle,
                event_type="always_valid.stream_reset",
                payload={
                    "schema": _SCHEMA,
                    "controller": _CONTROLLER_NAME,
                    "version": _CONTROLLER_VERSION,
                    "instance_id": self._instance_id,
                    "cfg_fp": bundle.cfg_fp,
                    "bundle_version": bundle.version,
                    "state_domain_id": bundle.state_domain_id,
                    "stream_hash": identity.stream_hash,
                    "ts_unix_ns": self._wall_ns(bundle),
                },
            )
        return existed
    def clear(self) -> None:
        bundle, _ = self._bundle_snapshot()
        removed = self._backend.clear_domain(state_domain_id=bundle.state_domain_id)
        self._emit_mutation_event(
            bundle=bundle,
            event_type="always_valid.domain_cleared",
            payload={
                "schema": _SCHEMA,
                "controller": _CONTROLLER_NAME,
                "version": _CONTROLLER_VERSION,
                "instance_id": self._instance_id,
                "cfg_fp": bundle.cfg_fp,
                "bundle_version": bundle.version,
                "state_domain_id": bundle.state_domain_id,
                "removed_streams": removed,
                "ts_unix_ns": self._wall_ns(bundle),
            },
        )
    def compact(self, *, budget: Optional[int] = None) -> Dict[str, Any]:
        bundle, _ = self._bundle_snapshot()
        b = _clamp_int(budget, default=bundle.runtime_cfg.stream_cleanup_budget, lo=0, hi=1_000_000)
        stats = self._backend.compact(
            state_domain_id=bundle.state_domain_id,
            idle_ttl_ns=int(bundle.runtime_cfg.idle_ttl_s * 1_000_000_000.0),
            now_mono_ns=self._mono_ns(bundle),
            budget=b,
        )
        self._emit_mutation_event(
            bundle=bundle,
            event_type="always_valid.compacted",
            payload={
                "schema": _SCHEMA,
                "controller": _CONTROLLER_NAME,
                "version": _CONTROLLER_VERSION,
                "instance_id": self._instance_id,
                "cfg_fp": bundle.cfg_fp,
                "bundle_version": bundle.version,
                "state_domain_id": bundle.state_domain_id,
                "stats": stats,
                "ts_unix_ns": self._wall_ns(bundle),
            },
        )
        return stats
    def all_stream_ids(self) -> Dict[str, int]:
        bundle, _ = self._bundle_snapshot()
        recs = self._backend.list_streams(
            state_domain_id=bundle.state_domain_id,
            limit=1_000_000,
            history_window=0,
        )
        return {r.stream_hash: int(r.state.decisions) for r in recs}
    def streams_overview(
        self,
        *,
        limit: int = 100,
        sort_by: str = "controller_log_e",
    ) -> Dict[str, Any]:
        bundle, base_mode = self._bundle_snapshot()
        now_mono_ns = self._mono_ns(bundle)
        now_unix_ns = self._wall_ns(bundle)
        lim = _clamp_int(limit, default=100, lo=1, hi=10_000)
        recs = self._backend.list_streams(
            state_domain_id=bundle.state_domain_id,
            limit=max(lim, 1_000),
            history_window=bundle.runtime_cfg.history_window,
        )
        rows = []
        for rec in recs:
            st = rec.state
            selected_log_e, selected_source, guarantee_scope = self._selected_track(
                bundle,
                st,
                EvidencePacket(
                    current_step_has_direct_p=False,
                    strict_p_value=None,
                    current_step_has_controller_p=False,
                    controller_p_value=None,
                    controller_p_kind="neutral",
                    current_step_has_calibrated_p=False,
                    calibrated_p_value=None,
                    calibration_ref=None,
                    calibration_cfg_digest=None,
                    calibration_state_digest=None,
                    current_step_has_score=False,
                    raw_score=None,
                    score_source=None,
                    guarantee_scope="none",
                ),
            )
            rows.append(
                {
                    "stream_hash": rec.stream_hash,
                    "state_revision": rec.revision,
                    "selected_source": selected_source,
                    "guarantee_scope": guarantee_scope,
                    "selected_log_e": float(selected_log_e),
                    "selected_e_value": _safe_exp(selected_log_e),
                    "strict_log_e": float(st.strict_log_e),
                    "controller_log_e": float(st.controller_log_e),
                    "active": bool(st.active),
                    "frozen": bool(st.frozen),
                    "alpha_wealth": float(st.alpha_wealth),
                    "decisions": int(st.decisions),
                    "triggers": int(st.triggers),
                    "last_trigger_step": st.last_trigger_step,
                    "direct_p_steps": int(st.direct_p_steps),
                    "calibrated_p_steps": int(st.calibrated_p_steps),
                    "heuristic_p_steps": int(st.heuristic_p_steps),
                    "last_update_mono_ns": int(st.last_update_mono_ns),
                    "last_update_unix_ns": int(st.last_update_unix_ns),
                }
            )
        key_name = sort_by if sort_by in {
            "selected_log_e",
            "strict_log_e",
            "controller_log_e",
            "decisions",
            "triggers",
        } else "controller_log_e"
        rows.sort(key=lambda r: (r.get(key_name, 0.0), r["decisions"]), reverse=True)
        rows = rows[:lim]
        return {
            "schema": _SCHEMA,
            "controller": {
                "name": _CONTROLLER_NAME,
                "version": _CONTROLLER_VERSION,
                "instance_id": self._instance_id,
                "cfg_fp": bundle.cfg_fp,
                "bundle_version": bundle.version,
                "state_domain_id": bundle.state_domain_id,
                "profile": bundle.policy_spec.profile,
                "label": bundle.policy_spec.label,
                "policyset_ref": bundle.policy_spec.policyset_ref,
                "adapter_registry_fp": bundle.adapter_registry_fp,
                "ts_monotonic_ns": now_mono_ns,
                "ts_unix_ns": now_unix_ns,
                "enabled": bundle.enabled,
                "controller_mode": base_mode,
            },
            "streams": rows,
        }
    def controller_health(self) -> Dict[str, Any]:
        bundle, base_mode = self._bundle_snapshot()
        now_mono_ns = self._mono_ns(bundle)
        now_unix_ns = self._wall_ns(bundle)
        recs = self._backend.list_streams(
            state_domain_id=bundle.state_domain_id,
            limit=1_000_000,
            history_window=0,
        )
        active_count = 0
        frozen_count = 0
        for rec in recs:
            st = rec.state
            if st.active:
                active_count += 1
            if st.frozen:
                frozen_count += 1
        return {
            "schema": _SCHEMA,
            "controller": {
                "name": _CONTROLLER_NAME,
                "version": _CONTROLLER_VERSION,
                "instance_id": self._instance_id,
                "cfg_fp": bundle.cfg_fp,
                "bundle_version": bundle.version,
                "state_domain_id": bundle.state_domain_id,
                "ts_monotonic_ns": now_mono_ns,
                "ts_unix_ns": now_unix_ns,
                "profile": bundle.policy_spec.profile,
                "label": bundle.policy_spec.label,
                "policyset_ref": bundle.policy_spec.policyset_ref,
                "enabled": bundle.enabled,
                "controller_mode": base_mode,
                "state_scope": "local_best_effort",
            },
            "health": {
                "stream_count": len(recs),
                "active_stream_count": active_count,
                "frozen_stream_count": frozen_count,
                "config_error_count": len(bundle.errors),
                "config_warning_count": len(bundle.warnings),
                "state_capacity_denies": int(self._state_capacity_denies),
                "config_error_denies": int(self._config_error_denies),
                "backend_conflict_denies": int(self._backend_conflict_denies),
                "identity_denies": int(self._identity_denies),
                "allowed_steps": int(self._allowed_steps),
                "blocked_steps": int(self._blocked_steps),
                "audit_emit_failures": int(self._audit_emit_failures),
                "telemetry_emit_failures": int(self._telemetry_emit_failures),
                "receipt_emit_failures": int(self._receipt_emit_failures),
                "decision_seq": int(self._decision_seq),
            },
            "backend": self._backend.health(),
            "errors": list(bundle.errors[:50]),
            "warnings": list(bundle.warnings[:50]),
        }
    # ------------------------------------------------------------------
    # Internal helpers: bundle / config compilation
    # ------------------------------------------------------------------
    def _normalize_score_adapters(self, adapters: Mapping[str, ScoreToPAdapter]) -> Dict[str, ScoreToPAdapter]:
        out: Dict[str, ScoreToPAdapter] = {}
        for k, v in adapters.items():
            kk = _safe_id(k, default=None, max_len=64)
            if kk is None:
                continue
            if hasattr(v, "p_value") and hasattr(v, "provenance"):
                out[kk] = v
        return out
    def _fingerprint_score_adapters(self, adapters: Mapping[str, ScoreToPAdapter]) -> str:
        rows = []
        for name in sorted(adapters.keys()):
            adapter = adapters[name]
            try:
                prov = adapter.provenance()
            except Exception:
                prov = {"adapter_ref": name, "engine": "error"}
            rows.append({"name": name, "prov": prov})
        raw = _canon_json(rows).encode("utf-8", errors="strict")
        return "adp1:" + hashlib.sha256(raw).hexdigest()
    def _compile_bundle(
        self,
        cfg: AlwaysValidConfig,
        *,
        previous: Optional[_CompiledBundle],
        adapter_registry_fp: str,
    ) -> _CompiledBundle:
        c = cfg.normalized_copy()
        policy = c.to_policy_spec()
        runtime = c.to_runtime_config()
        secret = c.to_secret_config()
        errors: List[str] = []
        warnings: List[str] = []
        if secret.stream_hash_key is not None and len(secret.stream_hash_key) < secret.min_stream_hash_key_bytes:
            errors.append("stream_hash_key shorter than min_stream_hash_key_bytes")
        key_bytes = secret.stream_hash_key
        key_mode = secret.stream_hash_mode
        if secret.stream_hash_algorithm == "hmac_sha256":
            if key_bytes is None and c.auto_ephemeral_hash_key_if_missing:
                if previous is not None and previous.secret_cfg.stream_hash_mode == "ephemeral" and previous.secret_cfg.stream_hash_key is not None:
                    key_bytes = previous.secret_cfg.stream_hash_key
                else:
                    key_bytes = os.urandom(max(16, secret.min_stream_hash_key_bytes))
                key_mode = "ephemeral"
            elif key_bytes is None:
                errors.append("stream_hash_algorithm='hmac_sha256' requires configured or ephemeral key")
        elif secret.stream_hash_algorithm == "blake3":
            if Blake3Hash is None:
                errors.append("stream_hash_algorithm='blake3' requested but Blake3Hash unavailable")
        # Compile p->e mixture
        kappas = tuple(x for x in policy.p_to_e_kappas if 0.0 < x < 1.0)
        if not kappas:
            errors.append("no valid p_to_e_kappas after normalization")
            kappas = _DEFAULT_P_TO_E_KAPPAS
        weights = policy.p_to_e_weights
        if len(weights) != len(kappas):
            warnings.append("p_to_e_weights missing/invalid length; using equal weights")
            weights = tuple(1.0 / len(kappas) for _ in kappas)
        else:
            tot = sum(weights)
            if tot <= 0.0 or not math.isfinite(tot):
                warnings.append("p_to_e_weights invalid sum; using equal weights")
                weights = tuple(1.0 / len(kappas) for _ in kappas)
            else:
                weights = tuple(float(w) / tot for w in weights)
        stream_key_id = secret.stream_hash_key_id or ("ephemeral" if key_mode == "ephemeral" else "none")
        state_domain_payload = {
            "cfg_fp": c.fingerprint(),
            "stream_identity_schema_ref": policy.stream_identity.schema_ref,
            "stream_hash_algorithm": secret.stream_hash_algorithm,
            "stream_hash_key_id": stream_key_id,
            "decision_mode": policy.decision_mode,
            "adapter_registry_fp": adapter_registry_fp,
        }
        state_domain_id = "dom1:" + hashlib.sha256(_canon_json(state_domain_payload).encode("utf-8", errors="strict")).hexdigest()[:32]
        updated_at_unix_ns = self._call_time_ns(c.wall_time_fn or time.time_ns, fallback=time.time_ns)
        version = 1 if previous is None else previous.version + 1
        cfg_fp = c.fingerprint()
        compiled_secret = AlwaysValidSecretConfig(
            stream_hash_algorithm=secret.stream_hash_algorithm,
            stream_hash_key=key_bytes,
            stream_hash_key_id=secret.stream_hash_key_id,
            stream_hash_mode=key_mode,
            min_stream_hash_key_bytes=secret.min_stream_hash_key_bytes,
        )
        return _CompiledBundle(
            version=version,
            updated_at_unix_ns=updated_at_unix_ns,
            cfg_fp=cfg_fp,
            state_domain_id=state_domain_id,
            adapter_registry_fp=adapter_registry_fp,
            errors=tuple(errors),
            warnings=tuple(warnings),
            enabled=runtime.enabled,
            policy_spec=policy,
            secret_cfg=compiled_secret,
            runtime_cfg=runtime,
            monotonic_fn=c.monotonic_fn or time.monotonic_ns,
            wall_time_fn=c.wall_time_fn or time.time_ns,
        )
    # ------------------------------------------------------------------
    # Internal helpers: time / identity / evidence
    # ------------------------------------------------------------------
    def _bundle_snapshot(self) -> Tuple[_CompiledBundle, ControllerMode]:
        with self._bundle_lock:
            if self._using_last_known_good:
                return self._bundle, "last_known_good"
            if self._bundle.errors and self._bundle.policy_spec.on_config_error == "fail_closed":
                return self._bundle, "fail_closed"
            return self._bundle, "normal"
    def _call_time_ns(self, fn: Callable[[], Any], *, fallback: Callable[[], int]) -> int:
        try:
            v = fn()
        except Exception:
            return int(fallback())
        if type(v) is int:
            return int(v)
        if isinstance(v, (float, int)) and math.isfinite(float(v)):
            return int(float(v) * 1_000_000_000.0)
        return int(fallback())
    def _mono_ns(self, bundle: _CompiledBundle) -> int:
        return self._call_time_ns(bundle.monotonic_fn, fallback=time.monotonic_ns)
    def _wall_ns(self, bundle: _CompiledBundle) -> int:
        return self._call_time_ns(bundle.wall_time_fn, fallback=time.time_ns)
    def _next_decision_seq(self) -> int:
        with self._seq_lock:
            self._decision_seq += 1
            return self._decision_seq
    def _sanitize_stream_id(self, stream_id: Optional[str]) -> Optional[str]:
        return _safe_id(stream_id, default=None, max_len=256)
    def _hash_stream_id(self, bundle: _CompiledBundle, canonical_stream_id: str) -> str:
        sid = _strip_unsafe_text(canonical_stream_id, max_len=4096)
        data = sid.encode("utf-8", errors="surrogatepass")
        key_id = bundle.secret_cfg.stream_hash_key_id or ("ephemeral" if bundle.secret_cfg.stream_hash_mode == "ephemeral" else "none")
        if bundle.secret_cfg.stream_hash_algorithm == "hmac_sha256":
            key = bundle.secret_cfg.stream_hash_key or b""
            dig = hmac.new(
                key,
                b"tcd:eprocess:stream:v2\x00" + data,
                digestmod=hashlib.sha256,
            ).hexdigest()[:48]
            return f"{key_id}:{dig}"
        if bundle.secret_cfg.stream_hash_algorithm == "blake3" and Blake3Hash is not None:
            dig = Blake3Hash().hex(
                b"tcd:eprocess:stream:v2\x00" + data,
                ctx="tcd:eprocess:stream",
            )[:48]
            return f"{key_id}:{dig}"
        dig = hashlib.blake2b(
            b"tcd:eprocess:stream:v2\x00" + data,
            digest_size=24,
            key=bundle.secret_cfg.stream_hash_key or b"",
        ).hexdigest()[:48]
        return f"{key_id}:{dig}"
    def _build_identity_result(
        self,
        *,
        bundle: _CompiledBundle,
        stream_id: Optional[str],
        request: Any,
        meta: Mapping[str, Any],
        ctx: Mapping[str, Any],
    ) -> StreamIdentityResult:
        pol = bundle.policy_spec.stream_identity
        raw = self._sanitize_stream_id(stream_id)
        canonical: Optional[str] = None
        status: Literal["ok", "missing", "invalid", "derived", "degraded_default"]
        if raw is not None:
            canonical = raw
            status = "ok"
        else:
            if pol.mode == "derive_from_ctx":
                parts: List[str] = []
                for k in pol.include_fields:
                    v = ctx.get(k)
                    if v is None:
                        v = meta.get(k)
                    sid = _safe_id(v, default=None, max_len=64)
                    if sid:
                        parts.append(f"{k}={sid}")
                if parts:
                    canonical = "|".join(parts)
                    status = "derived"
                else:
                    status = "missing"
            elif pol.mode == "use_default":
                canonical = "default"
                status = "degraded_default"
            elif pol.mode == "dev_fallback_default":
                if bundle.policy_spec.profile == "DEV":
                    canonical = "default"
                    status = "degraded_default"
                else:
                    status = "missing"
            else:
                status = "missing"
        if status == "degraded_default" and pol.strict_profiles_forbid_default and bundle.policy_spec.profile in {"FINREG", "LOCKDOWN"}:
            canonical = None
            status = "missing"
        if canonical is None and pol.on_identity_error == "use_default":
            if not (pol.strict_profiles_forbid_default and bundle.policy_spec.profile in {"FINREG", "LOCKDOWN"}):
                canonical = "default"
                status = "degraded_default"
        if canonical is None:
            canonical = "__missing__"
        stream_hash = self._hash_stream_id(bundle, canonical)
        raw_exposed = bool(pol.expose_raw_stream_id)
        if bundle.policy_spec.profile in {"FINREG", "LOCKDOWN"} and pol.hash_only_in_strict:
            raw_exposed = False
        return StreamIdentityResult(
            raw_stream_id=raw if raw_exposed else None,
            canonical_stream_id=(canonical if canonical != "__missing__" else None),
            stream_hash=stream_hash,
            identity_status=status,
            schema_ref=pol.schema_ref,
            raw_exposed=raw_exposed,
        )
    def _normalize_score(self, score: Optional[float]) -> Optional[float]:
        s = _coerce_float(score)
        return float(s) if s is not None else None
    def _heuristic_p(self, bundle: _CompiledBundle, score: float) -> float:
        if bundle.policy_spec.score_to_p_mode == "one_minus_score":
            x = 1.0 - score
        elif bundle.policy_spec.score_to_p_mode == "sigmoid_tail":
            z = bundle.policy_spec.score_scale * (score - bundle.policy_spec.score_reference)
            if z >= 0:
                ez = math.exp(-z)
                x = ez / (1.0 + ez)
            else:
                ez = math.exp(z)
                x = 1.0 / (1.0 + ez)
        else:
            z = max(0.0, score - bundle.policy_spec.score_reference)
            x = math.exp(-bundle.policy_spec.score_scale * z)
        if not math.isfinite(x):
            x = 1.0
        return min(bundle.policy_spec.max_p_value, max(bundle.policy_spec.min_p_value, float(x)))
    def _build_evidence_packet(
        self,
        *,
        bundle: _CompiledBundle,
        p_value: Optional[float],
        score: Optional[float],
        score_adapter: Optional[str],
        meta: Mapping[str, Any],
        ctx: Mapping[str, Any],
    ) -> Tuple[EvidencePacket, Optional[str]]:
        p = _coerce_float(p_value)
        if p is not None:
            p = min(bundle.policy_spec.max_p_value, max(bundle.policy_spec.min_p_value, p))
            return (
                EvidencePacket(
                    current_step_has_direct_p=True,
                    strict_p_value=float(p),
                    current_step_has_controller_p=True,
                    controller_p_value=float(p),
                    controller_p_kind="direct",
                    current_step_has_calibrated_p=False,
                    calibrated_p_value=None,
                    calibration_ref=None,
                    calibration_cfg_digest=None,
                    calibration_state_digest=None,
                    current_step_has_score=score is not None,
                    raw_score=self._normalize_score(score),
                    score_source=None,
                    guarantee_scope="strict_direct_p",
                ),
                None,
            )
        s = self._normalize_score(score)
        if s is None:
            return (
                EvidencePacket(
                    current_step_has_direct_p=False,
                    strict_p_value=None,
                    current_step_has_controller_p=False,
                    controller_p_value=None,
                    controller_p_kind="neutral",
                    current_step_has_calibrated_p=False,
                    calibrated_p_value=None,
                    calibration_ref=None,
                    calibration_cfg_digest=None,
                    calibration_state_digest=None,
                    current_step_has_score=False,
                    raw_score=None,
                    score_source=None,
                    guarantee_scope="none",
                ),
                None,
            )
        adapter_name = _safe_id(score_adapter, default=None, max_len=64) or bundle.policy_spec.score_adapter_default
        if adapter_name is not None:
            adapter = self._score_adapters.get(adapter_name)
            if adapter is not None:
                try:
                    p_cal = adapter.p_value(score=float(s), meta=meta, ctx=ctx)
                    p_val = _coerce_float(p_cal)
                except Exception:
                    p_val = None
                if p_val is not None:
                    p_val = min(bundle.policy_spec.max_p_value, max(bundle.policy_spec.min_p_value, p_val))
                    try:
                        prov = adapter.provenance()
                    except Exception:
                        prov = {}
                    calibration_ref = _safe_id(prov.get("adapter_ref"), default=adapter_name, max_len=64) or adapter_name
                    cfg_digest = _safe_id(prov.get("cfg_digest"), default=None, max_len=128)
                    state_digest = _safe_id(prov.get("state_digest"), default=None, max_len=128)
                    g = prov.get("guarantee_scope")
                    if g not in {"predictable_calibrated_p", "heuristic_only", "strict_direct_p", "none"}:
                        g = "predictable_calibrated_p"
                    return (
                        EvidencePacket(
                            current_step_has_direct_p=False,
                            strict_p_value=None,
                            current_step_has_controller_p=True,
                            controller_p_value=float(p_val),
                            controller_p_kind="calibrated",
                            current_step_has_calibrated_p=True,
                            calibrated_p_value=float(p_val),
                            calibration_ref=calibration_ref,
                            calibration_cfg_digest=cfg_digest,
                            calibration_state_digest=state_digest,
                            current_step_has_score=True,
                            raw_score=float(s),
                            score_source=adapter_name,
                            guarantee_scope=g,  # type: ignore[arg-type]
                        ),
                        None,
                    )
                return (
                    EvidencePacket(
                        current_step_has_direct_p=False,
                        strict_p_value=None,
                        current_step_has_controller_p=True,
                        controller_p_value=self._heuristic_p(bundle, float(s)),
                        controller_p_kind="heuristic",
                        current_step_has_calibrated_p=False,
                        calibrated_p_value=None,
                        calibration_ref=None,
                        calibration_cfg_digest=None,
                        calibration_state_digest=None,
                        current_step_has_score=True,
                        raw_score=float(s),
                        score_source=adapter_name,
                        guarantee_scope="heuristic_only",
                    ),
                    "adapter_failed_fell_back_to_heuristic",
                )
            return (
                EvidencePacket(
                    current_step_has_direct_p=False,
                    strict_p_value=None,
                    current_step_has_controller_p=True,
                    controller_p_value=self._heuristic_p(bundle, float(s)),
                    controller_p_kind="heuristic",
                    current_step_has_calibrated_p=False,
                    calibrated_p_value=None,
                    calibration_ref=None,
                    calibration_cfg_digest=None,
                    calibration_state_digest=None,
                    current_step_has_score=True,
                    raw_score=float(s),
                    score_source=adapter_name,
                    guarantee_scope="heuristic_only",
                ),
                "adapter_missing_fell_back_to_heuristic",
            )
        return (
            EvidencePacket(
                current_step_has_direct_p=False,
                strict_p_value=None,
                current_step_has_controller_p=True,
                controller_p_value=self._heuristic_p(bundle, float(s)),
                controller_p_kind="heuristic",
                current_step_has_calibrated_p=False,
                calibrated_p_value=None,
                calibration_ref=None,
                calibration_cfg_digest=None,
                calibration_state_digest=None,
                current_step_has_score=True,
                raw_score=float(s),
                score_source=None,
                guarantee_scope="heuristic_only",
            ),
            None,
        )
    # ------------------------------------------------------------------
    # Internal helpers: update math
    # ------------------------------------------------------------------
    def _effective_weight(
        self,
        bundle: _CompiledBundle,
        base_weight: float,
        severity: Optional[str],
    ) -> float:
        w = _coerce_float(base_weight)
        if w is None:
            w = 1.0
        sev_mult = 1.0
        if type(severity) is str:
            sev = _safe_label(severity, default="")
            sev_mult = float(bundle.policy_spec.severity_weights.get(sev, 1.0))
        eff = w * sev_mult
        if not math.isfinite(eff):
            eff = 1.0
        if eff < 0.0:
            eff = 0.0
        if eff > bundle.policy_spec.max_weight:
            eff = bundle.policy_spec.max_weight
        return float(eff)
    def _e_log_increment(self, bundle: _CompiledBundle, p_like: float) -> float:
        p = min(bundle.policy_spec.max_p_value, max(bundle.policy_spec.min_p_value, p_like))
        lp = math.log(p)
        terms: List[float] = []
        for kappa, w in zip(bundle.policy_spec.p_to_e_kappas, bundle.policy_spec.p_to_e_weights):
            term = math.log(w) + math.log(kappa) + (kappa - 1.0) * lp
            terms.append(term)
        inc = _logsumexp(terms)
        if not math.isfinite(inc):
            return 0.0
        if inc > bundle.policy_spec.max_step_abs_log_e:
            return bundle.policy_spec.max_step_abs_log_e
        if inc < -bundle.policy_spec.max_step_abs_log_e:
            return -bundle.policy_spec.max_step_abs_log_e
        return float(inc)
    def _selected_track(
        self,
        bundle: _CompiledBundle,
        st: EProcessState,
        evidence: EvidencePacket,
    ) -> Tuple[float, str, GuaranteeScope]:
        mode = bundle.policy_spec.decision_mode
        if mode == "controller_only":
            return float(st.controller_log_e), "controller", st.last_guarantee_scope
        if mode == "strict_only":
            if bundle.policy_spec.strict_requires_direct_p and st.direct_p_steps <= 0:
                return 0.0, "strict", "none"
            return float(st.strict_log_e), "strict", "strict_direct_p"
        if mode == "prefer_current_strict":
            if evidence.current_step_has_direct_p:
                return float(st.strict_log_e), "strict", "strict_direct_p"
            return float(st.controller_log_e), "controller", st.last_guarantee_scope
        # dual_track
        if st.strict_log_e >= st.controller_log_e:
            if bundle.policy_spec.strict_requires_direct_p and st.direct_p_steps <= 0:
                return float(st.controller_log_e), "dual_controller", st.last_guarantee_scope
            return float(st.strict_log_e), "dual_strict", "strict_direct_p"
        return float(st.controller_log_e), "dual_controller", st.last_guarantee_scope
    def _make_initial_state(
        self,
        bundle: _CompiledBundle,
        now_mono_ns: int,
        now_unix_ns: int,
    ) -> EProcessState:
        """
        Initialize per-stream e-process state.
        This restores the missing initialization path used when a stream_hash
        is first seen by the controller. It preserves the current v3 semantics:
          - fresh strict/controller log-e start at 0
          - alpha wealth starts from policy_spec.alpha_wealth_init
          - timestamps are initialized immediately
          - bounded history deques honor runtime_cfg.retain_history/history_window
          - if freeze_on_exhaust is enabled and initial wealth is already zero,
            the state starts frozen and marks exhausted_step=0
        """
        history_window = int(bundle.runtime_cfg.history_window)
        retain_history = bool(bundle.runtime_cfg.retain_history)
        maxlen = history_window if (retain_history and history_window > 0) else None
        alpha_wealth = float(bundle.policy_spec.alpha_wealth_init)
        if not math.isfinite(alpha_wealth):
            alpha_wealth = 0.0
        alpha_wealth = max(0.0, min(alpha_wealth, float(bundle.policy_spec.alpha_wealth_cap)))
        exhausted_at_boot = bool(bundle.policy_spec.freeze_on_exhaust and alpha_wealth <= 0.0)
        return EProcessState(
            strict_log_e=0.0,
            controller_log_e=0.0,
            alpha_wealth=alpha_wealth,
            decisions=0,
            triggers=0,
            active=False,
            frozen=exhausted_at_boot,
            last_trigger_step=None,
            exhausted_step=0 if exhausted_at_boot else None,
            last_update_mono_ns=int(now_mono_ns),
            last_update_unix_ns=int(now_unix_ns),
            last_p_value=1.0,
            last_p_source="neutral",
            last_score=None,
            last_calibration_ref=None,
            last_calibration_cfg_digest=None,
            last_calibration_state_digest=None,
            last_guarantee_scope="none",
            ewma_score=None,
            ewma_neglogp=0.0,
            min_p_value=1.0,
            min_p_value_step=None,
            max_score=None,
            max_score_step=None,
            direct_p_steps=0,
            calibrated_p_steps=0,
            heuristic_p_steps=0,
            neutral_steps=0,
            small_p_count_05=0,
            small_p_count_01=0,
            small_p_count_001=0,
            fisher_stat=0.0,
            fisher_df=0,
            history_p=deque(maxlen=maxlen),
            history_score=deque(maxlen=maxlen),
            history_log_e=deque(maxlen=maxlen),
        )
    def _update_state(
        self,
        *,
        bundle: _CompiledBundle,
        state: EProcessState,
        evidence: EvidencePacket,
        effective_weight: float,
        now_mono_ns: int,
        now_unix_ns: int,
    ) -> None:
        state.decisions += 1
        state.last_update_mono_ns = now_mono_ns
        state.last_update_unix_ns = now_unix_ns
        state.last_score = evidence.raw_score
        state.last_calibration_ref = evidence.calibration_ref
        state.last_calibration_cfg_digest = evidence.calibration_cfg_digest
        state.last_calibration_state_digest = evidence.calibration_state_digest
        state.last_guarantee_scope = evidence.guarantee_scope if evidence.controller_p_kind in {"calibrated", "heuristic"} else "none"
        # Step evidence source counters / last p
        if evidence.current_step_has_direct_p and evidence.strict_p_value is not None:
            p = float(evidence.strict_p_value)
            state.last_p_value = p
            state.last_p_source = "direct"
            state.direct_p_steps += 1
        elif evidence.current_step_has_calibrated_p and evidence.calibrated_p_value is not None:
            p = float(evidence.calibrated_p_value)
            state.last_p_value = p
            state.last_p_source = "calibrated"
            state.calibrated_p_steps += 1
        elif evidence.current_step_has_controller_p and evidence.controller_p_value is not None and evidence.controller_p_kind == "heuristic":
            p = float(evidence.controller_p_value)
            state.last_p_value = p
            state.last_p_source = "heuristic"
            state.heuristic_p_steps += 1
        else:
            p = 1.0
            state.last_p_value = 1.0
            state.last_p_source = "neutral"
            state.neutral_steps += 1
        # descriptive stats
        if evidence.current_step_has_controller_p and evidence.controller_p_value is not None:
            nl = -math.log(max(bundle.policy_spec.min_p_value, evidence.controller_p_value))
            a = bundle.runtime_cfg.ewma_alpha
            state.ewma_neglogp = nl if state.decisions == 1 else ((a * nl) + ((1.0 - a) * state.ewma_neglogp))
        if evidence.raw_score is not None:
            a = bundle.runtime_cfg.ewma_alpha
            state.ewma_score = evidence.raw_score if state.ewma_score is None else ((a * evidence.raw_score) + ((1.0 - a) * state.ewma_score))
            if state.max_score is None or evidence.raw_score > state.max_score:
                state.max_score = evidence.raw_score
                state.max_score_step = state.decisions
        if evidence.current_step_has_controller_p and evidence.controller_p_value is not None:
            pv = evidence.controller_p_value
            if pv < state.min_p_value:
                state.min_p_value = pv
                state.min_p_value_step = state.decisions
            if pv <= 0.05:
                state.small_p_count_05 += 1
            if pv <= 0.01:
                state.small_p_count_01 += 1
            if pv <= 0.001:
                state.small_p_count_001 += 1
        # Fisher diagnostic: direct p-values only
        if evidence.current_step_has_direct_p and evidence.strict_p_value is not None:
            try:
                state.fisher_stat += -2.0 * math.log(max(bundle.policy_spec.min_p_value, evidence.strict_p_value))
                state.fisher_df += 2
            except Exception:
                pass
        # History
        if bundle.runtime_cfg.retain_history and bundle.runtime_cfg.history_window > 0:
            if evidence.current_step_has_controller_p and evidence.controller_p_value is not None:
                state.history_p.append(float(evidence.controller_p_value))
            if evidence.raw_score is not None:
                state.history_score.append(float(evidence.raw_score))
        # Strict process: only direct p-values update
        if evidence.current_step_has_direct_p and evidence.strict_p_value is not None:
            strict_inc = self._e_log_increment(bundle, evidence.strict_p_value)
            state.strict_log_e = min(
                bundle.policy_spec.max_log_e,
                max(bundle.policy_spec.min_log_e, state.strict_log_e + strict_inc),
            )
        # Controller track
        if bundle.policy_spec.freeze_on_exhaust and state.frozen:
            pass
        else:
            if bundle.policy_spec.alpha_spend_per_decision > 0.0:
                spend = bundle.policy_spec.alpha_spend_per_decision * max(1.0, effective_weight)
                state.alpha_wealth = max(0.0, state.alpha_wealth - spend)
            if evidence.current_step_has_controller_p and evidence.controller_p_value is not None:
                controller_inc = self._e_log_increment(bundle, evidence.controller_p_value)
                if evidence.controller_p_kind == "heuristic":
                    controller_inc *= bundle.policy_spec.heuristic_p_weight
                controller_inc *= effective_weight
                if not math.isfinite(controller_inc):
                    controller_inc = 0.0
                state.controller_log_e = min(
                    bundle.policy_spec.max_log_e,
                    max(bundle.policy_spec.min_log_e, state.controller_log_e + controller_inc),
                )
            else:
                # neutral update policy
                if bundle.policy_spec.neutral_update_mode == "decay":
                    factor = max(0.0, 1.0 - bundle.policy_spec.neutral_decay_rate)
                    state.controller_log_e *= factor
                elif bundle.policy_spec.neutral_update_mode == "reward":
                    # reward handled after trigger evaluation on safe decision
                    pass
            if bundle.policy_spec.freeze_on_exhaust and state.alpha_wealth <= 0.0:
                state.alpha_wealth = 0.0
                state.frozen = True
                if state.exhausted_step is None:
                    state.exhausted_step = state.decisions
        if bundle.runtime_cfg.retain_history and bundle.runtime_cfg.history_window > 0:
            state.history_log_e.append(float(state.controller_log_e))
    # ------------------------------------------------------------------
    # Internal helpers: result building / sinks
    # ------------------------------------------------------------------
    def _sanitize_meta_dict(self, bundle: _CompiledBundle, obj: Mapping[str, Any]) -> Dict[str, Any]:
        budget = _JsonBudget(
            max_nodes=bundle.runtime_cfg.meta_max_nodes,
            max_items=bundle.runtime_cfg.meta_max_items,
            max_depth=bundle.runtime_cfg.meta_max_depth,
            max_str_total=bundle.runtime_cfg.meta_max_str_total,
        )
        safe = _json_sanitize(obj, budget=budget, depth=0, redact_secrets=True)
        return safe if isinstance(safe, dict) else {}
    def _build_process_block(
        self,
        bundle: _CompiledBundle,
        st: Optional[EProcessState],
        *,
        selected_source: str,
        guarantee_scope: GuaranteeScope,
    ) -> Dict[str, Any]:
        if st is None:
            selected_log_e = 0.0
            return {
                "strict_e_value": 1.0,
                "controller_e_value": 1.0,
                "selected_source": selected_source,
                "selected_log_e": 0.0,
                "selected_e_value": 1.0,
                "guarantee_scope": guarantee_scope,
                "alpha_base": bundle.policy_spec.alpha_base,
                "alpha_wealth": bundle.policy_spec.alpha_wealth_init,
                "alpha_wealth_init": bundle.policy_spec.alpha_wealth_init,
                "alpha_wealth_cap": bundle.policy_spec.alpha_wealth_cap,
                "alpha_spend_per_decision": bundle.policy_spec.alpha_spend_per_decision,
                "alpha_reward_per_safe_decision": bundle.policy_spec.alpha_reward_per_safe_decision,
                "threshold_log_e": bundle.policy_spec.threshold_log_e,
                "threshold_clear_log_e": bundle.policy_spec.threshold_clear_log_e,
                "threshold_e_value": _safe_exp(bundle.policy_spec.threshold_log_e),
                "trigger": False,
                "decisions": 0,
                "triggers": 0,
                "last_trigger_step": None,
                "strict_log_e": 0.0,
                "controller_log_e": 0.0,
                "frozen": False,
                "active": False,
                "exhausted_step": None,
            }
        selected_log_e = st.strict_log_e if selected_source in {"strict", "dual_strict"} else st.controller_log_e
        return {
            "strict_e_value": _safe_exp(st.strict_log_e),
            "controller_e_value": _safe_exp(st.controller_log_e),
            "selected_source": selected_source,
            "selected_log_e": float(selected_log_e),
            "selected_e_value": _safe_exp(selected_log_e),
            "guarantee_scope": guarantee_scope,
            "alpha_base": bundle.policy_spec.alpha_base,
            "alpha_wealth": float(st.alpha_wealth),
            "alpha_wealth_init": bundle.policy_spec.alpha_wealth_init,
            "alpha_wealth_cap": bundle.policy_spec.alpha_wealth_cap,
            "alpha_spend_per_decision": bundle.policy_spec.alpha_spend_per_decision,
            "alpha_reward_per_safe_decision": bundle.policy_spec.alpha_reward_per_safe_decision,
            "threshold_log_e": bundle.policy_spec.threshold_log_e,
            "threshold_clear_log_e": bundle.policy_spec.threshold_clear_log_e,
            "threshold_e_value": _safe_exp(bundle.policy_spec.threshold_log_e),
            "trigger": bool(st.active),
            "decisions": int(st.decisions),
            "triggers": int(st.triggers),
            "last_trigger_step": st.last_trigger_step,
            "strict_log_e": float(st.strict_log_e),
            "controller_log_e": float(st.controller_log_e),
            "frozen": bool(st.frozen),
            "active": bool(st.active),
            "exhausted_step": st.exhausted_step,
        }
    def _build_stats_block(self, bundle: _CompiledBundle, st: Optional[EProcessState]) -> Dict[str, Any]:
        if st is None:
            return {
                "direct_p_steps": 0,
                "calibrated_p_steps": 0,
                "heuristic_p_steps": 0,
                "neutral_steps": 0,
                "min_p_value": 1.0,
                "min_p_value_step": None,
                "max_score": None,
                "max_score_step": None,
                "ewma_score": None,
                "ewma_neglogp": 0.0,
                "fisher_stat": 0.0,
                "fisher_df": 0,
                "small_p_count_05": 0,
                "small_p_count_01": 0,
                "small_p_count_001": 0,
            }
        out = {
            "direct_p_steps": int(st.direct_p_steps),
            "calibrated_p_steps": int(st.calibrated_p_steps),
            "heuristic_p_steps": int(st.heuristic_p_steps),
            "neutral_steps": int(st.neutral_steps),
            "min_p_value": float(st.min_p_value),
            "min_p_value_step": st.min_p_value_step,
            "max_score": float(st.max_score) if st.max_score is not None else None,
            "max_score_step": st.max_score_step,
            "ewma_score": float(st.ewma_score) if st.ewma_score is not None else None,
            "ewma_neglogp": float(st.ewma_neglogp),
            "fisher_stat": float(st.fisher_stat),
            "fisher_df": int(st.fisher_df),
            "small_p_count_05": int(st.small_p_count_05),
            "small_p_count_01": int(st.small_p_count_01),
            "small_p_count_001": int(st.small_p_count_001),
            "last_p_value": float(st.last_p_value),
            "last_p_source": st.last_p_source,
            "last_score": float(st.last_score) if st.last_score is not None else None,
            "last_calibration_ref": st.last_calibration_ref,
            "last_calibration_cfg_digest": st.last_calibration_cfg_digest,
            "last_calibration_state_digest": st.last_calibration_state_digest,
            "last_update_mono_ns": int(st.last_update_mono_ns),
            "last_update_unix_ns": int(st.last_update_unix_ns),
        }
        if bundle.runtime_cfg.include_history_in_snapshot and bundle.runtime_cfg.retain_history and bundle.runtime_cfg.history_window > 0:
            out["history"] = {
                "p_values": list(st.history_p),
                "scores": list(st.history_score),
                "controller_log_e": list(st.history_log_e),
            }
        return out
    def _build_validity_block(
        self,
        bundle: _CompiledBundle,
        *,
        evidence: EvidencePacket,
        selected_source: str,
        state: Optional[EProcessState],
    ) -> Dict[str, Any]:
        return {
            "strict_process_valid_if_direct_p_values_are_valid": True,
            "controller_process_is_statistical_controller_not_pure_e_process": True,
            "decision_mode": bundle.policy_spec.decision_mode,
            "selected_source": selected_source,
            "p_source_this_step": evidence.controller_p_kind,
            "current_step_has_direct_p": evidence.current_step_has_direct_p,
            "current_step_has_calibrated_p": evidence.current_step_has_calibrated_p,
            "current_step_has_score": evidence.current_step_has_score,
            "has_direct_p_history": bool(state.direct_p_steps > 0) if state is not None else False,
            "has_calibrated_history": bool(state.calibrated_p_steps > 0) if state is not None else False,
            "has_heuristic_history": bool(state.heuristic_p_steps > 0) if state is not None else False,
        }
    def _build_step_result(
        self,
        *,
        bundle: _CompiledBundle,
        sid: str,
        stream_hash: str,
        state: Optional[EProcessState],
        state_revision: Optional[int],
        allowed: bool,
        action: Action,
        reason: str,
        controller_mode: ControllerMode,
        degraded_reasons: Sequence[str],
        evidence: EvidencePacket,
        effective_weight: float,
        now_mono_ns: int,
        now_unix_ns: int,
        meta_s: Dict[str, Any],
        ctx_s: Dict[str, Any],
        has_request: bool,
        decision_seq: int,
        identity: StreamIdentityResult,
        audit_ref: Optional[str],
        receipt_ref: Optional[str],
    ) -> Dict[str, Any]:
        st = state if state is not None else None
        selected_log_e, selected_source, guarantee_scope = (
            self._selected_track(bundle, st, evidence)
            if st is not None
            else (
                0.0,
                "strict" if bundle.policy_spec.decision_mode == "strict_only" else "controller",
                "none",
            )
        )
        process = self._build_process_block(
            bundle,
            st,
            selected_source=selected_source,
            guarantee_scope=guarantee_scope,
        )
        stats = self._build_stats_block(bundle, st)
        validity = self._build_validity_block(bundle, evidence=evidence, selected_source=selected_source, state=st)
        security = {
            "av_label": bundle.policy_spec.label,
            "policyset_ref": bundle.policy_spec.policyset_ref,
            "cfg_fp": bundle.cfg_fp,
            "bundle_version": bundle.version,
            "trigger": bool(process["trigger"]),
            "trigger_reason": reason,
            "block_on_trigger": bool(bundle.policy_spec.block_on_trigger),
            "stream_hash": stream_hash,
            "selected_source": selected_source,
            "statistical_guarantee_scope": guarantee_scope,
            "state_scope": "local_best_effort",
            "state_domain_id": bundle.state_domain_id,
        }
        return {
            "allowed": bool(allowed),
            "action": action,
            "controller_mode": controller_mode,
            "degraded_reasons": list(degraded_reasons),
            "reason": reason,
            "stream_id": sid if identity.raw_exposed else None,
            "stream_hash": stream_hash,
            "identity_status": identity.identity_status,
            "decision_seq": int(decision_seq),
            "bundle_version": int(bundle.version),
            "config_fingerprint": bundle.cfg_fp,
            "state_domain_id": bundle.state_domain_id,
            "state_revision": state_revision,
            "p_value": float(evidence.controller_p_value if evidence.controller_p_value is not None else (evidence.strict_p_value if evidence.strict_p_value is not None else 1.0)),
            "p_source": evidence.controller_p_kind,
            "score": float(evidence.raw_score) if evidence.raw_score is not None else None,
            "effective_weight": float(effective_weight),
            "meta": meta_s,
            "ctx": ctx_s,
            "has_request": bool(has_request),
            "audit_ref": audit_ref,
            "receipt_ref": receipt_ref,
            "e_state": {
                "schema": _SCHEMA,
                "controller": {
                    "name": _CONTROLLER_NAME,
                    "version": _CONTROLLER_VERSION,
                    "instance_id": self._instance_id,
                    "profile": bundle.policy_spec.profile,
                    "label": bundle.policy_spec.label,
                    "policyset_ref": bundle.policy_spec.policyset_ref,
                    "cfg_fp": bundle.cfg_fp,
                    "bundle_version": int(bundle.version),
                    "state_domain_id": bundle.state_domain_id,
                    "adapter_registry_fp": bundle.adapter_registry_fp,
                    "ts_monotonic_ns": int(now_mono_ns),
                    "ts_unix_ns": int(now_unix_ns),
                    "enabled": bool(bundle.enabled),
                    "state_scope": "local_best_effort",
                },
                "stream": {
                    "id": sid if identity.raw_exposed else None,
                    "hash": stream_hash,
                    "identity_status": identity.identity_status,
                    "schema_ref": identity.schema_ref,
                },
                "process": process,
                "stats": stats,
                "validity": validity,
            },
            "security": security,
        }
    def _build_snapshot_result(
        self,
        *,
        bundle: _CompiledBundle,
        sid: str,
        stream_hash: str,
        state: Optional[EProcessState],
        state_revision: Optional[int],
        now_mono_ns: int,
        now_unix_ns: int,
        controller_mode: ControllerMode,
        identity: StreamIdentityResult,
    ) -> Dict[str, Any]:
        neutral_evidence = EvidencePacket(
            current_step_has_direct_p=False,
            strict_p_value=None,
            current_step_has_controller_p=False,
            controller_p_value=None,
            controller_p_kind="neutral",
            current_step_has_calibrated_p=False,
            calibrated_p_value=None,
            calibration_ref=None,
            calibration_cfg_digest=None,
            calibration_state_digest=None,
            current_step_has_score=False,
            raw_score=None,
            score_source=None,
            guarantee_scope="none",
        )
        if state is not None:
            _, selected_source, guarantee_scope = self._selected_track(bundle, state, neutral_evidence)
        else:
            selected_source = "strict" if bundle.policy_spec.decision_mode == "strict_only" else "controller"
            guarantee_scope = "none"
        process = self._build_process_block(bundle, state, selected_source=selected_source, guarantee_scope=guarantee_scope)
        stats = self._build_stats_block(bundle, state)
        validity = self._build_validity_block(bundle, evidence=neutral_evidence, selected_source=selected_source, state=state)
        return {
            "schema": _SCHEMA,
            "controller": {
                "name": _CONTROLLER_NAME,
                "version": _CONTROLLER_VERSION,
                "instance_id": self._instance_id,
                "profile": bundle.policy_spec.profile,
                "label": bundle.policy_spec.label,
                "policyset_ref": bundle.policy_spec.policyset_ref,
                "cfg_fp": bundle.cfg_fp,
                "bundle_version": int(bundle.version),
                "state_domain_id": bundle.state_domain_id,
                "adapter_registry_fp": bundle.adapter_registry_fp,
                "ts_monotonic_ns": int(now_mono_ns),
                "ts_unix_ns": int(now_unix_ns),
                "enabled": bool(bundle.enabled),
                "controller_mode": controller_mode,
                "state_scope": "local_best_effort",
            },
            "stream": {
                "id": sid if identity.raw_exposed else None,
                "hash": stream_hash,
                "identity_status": identity.identity_status,
                "schema_ref": identity.schema_ref,
            },
            "state_revision": state_revision,
            "process": process,
            "stats": stats,
            "validity": validity,
        }
    def _emit_artifacts(self, *, bundle: _CompiledBundle, result: Dict[str, Any]) -> None:
        audit_ref: Optional[str] = None
        receipt_ref: Optional[str] = None
        should_audit = bool(bundle.runtime_cfg.audit_emit_all_steps)
        if result["reason"] in {"e-process-trigger", "e-process-trigger-advisory", "config_error", "identity_error", "state_capacity_exhausted", "backend_error", "backend_conflict"}:
            should_audit = should_audit or bundle.runtime_cfg.audit_emit_triggers
        if should_audit and self._audit_sink is not None:
            try:
                payload = self._sanitize_meta_dict(bundle, result)
                audit_ref = self._audit_sink.emit("always_valid.step", payload)
            except Exception:
                self._audit_emit_failures += 1
        should_receipt = False
        if result["action"] == "block" and bundle.runtime_cfg.receipt_issue_on_block:
            should_receipt = True
        if result["reason"] == "e-process-trigger-advisory" and bundle.runtime_cfg.receipt_issue_on_trigger:
            should_receipt = True
        if should_receipt and self._receipt_sink is not None:
            try:
                payload = {
                    "schema": _SCHEMA,
                    "event_type": "always_valid.step",
                    "cfg_fp": bundle.cfg_fp,
                    "bundle_version": bundle.version,
                    "policyset_ref": bundle.policy_spec.policyset_ref,
                    "state_domain_id": bundle.state_domain_id,
                    "decision_seq": result["decision_seq"],
                    "stream_hash": result["stream_hash"],
                    "reason": result["reason"],
                    "action": result["action"],
                    "selected_source": result["security"]["selected_source"],
                    "statistical_guarantee_scope": result["security"]["statistical_guarantee_scope"],
                    "trigger": result["security"]["trigger"],
                    "audit_ref": audit_ref,
                    "ts_unix_ns": result["e_state"]["controller"]["ts_unix_ns"],
                }
                payload = self._sanitize_meta_dict(bundle, payload)
                receipt_ref = self._receipt_sink.issue(payload)
            except Exception:
                self._receipt_emit_failures += 1
        if self._telemetry_sink is not None:
            should_metric = bool(bundle.runtime_cfg.telemetry_emit_all_steps)
            if result["reason"] in {"e-process-trigger", "e-process-trigger-advisory", "config_error", "identity_error", "state_capacity_exhausted", "backend_error", "backend_conflict"}:
                should_metric = should_metric or bundle.runtime_cfg.telemetry_emit_triggers
            if should_metric:
                labels = {
                    "profile": bundle.policy_spec.profile,
                    "label": bundle.policy_spec.label,
                    "controller_mode": result["controller_mode"],
                    "action": result["action"],
                    "reason": result["reason"],
                    "selected_source": result["security"]["selected_source"],
                    "guarantee_scope": result["security"]["statistical_guarantee_scope"],
                }
                try:
                    self._telemetry_sink.record_metric("tcd.av.step.count", 1.0, labels)
                    self._telemetry_sink.record_event("tcd.av.step", labels)
                except Exception:
                    self._telemetry_emit_failures += 1
        result["audit_ref"] = audit_ref
        result["receipt_ref"] = receipt_ref
    def _emit_mutation_event(self, *, bundle: _CompiledBundle, event_type: str, payload: Mapping[str, Any]) -> None:
        if self._audit_sink is not None:
            try:
                self._audit_sink.emit(event_type, self._sanitize_meta_dict(bundle, payload))
            except Exception:
                self._audit_emit_failures += 1
        if self._telemetry_sink is not None:
            try:
                self._telemetry_sink.record_event(event_type, {"cfg_fp": bundle.cfg_fp, "bundle_version": bundle.version})
            except Exception:
                self._telemetry_emit_failures += 1