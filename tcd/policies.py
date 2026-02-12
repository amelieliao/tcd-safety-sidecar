

_fields, replace
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union, Literal

from pydantic import BaseModel, Field, ValidationError, ConfigDict, field_validator

from .crypto import Blake3Hash
from .detector import TCDConfig
from .risk_av import AlwaysValidConfig

__all__ = [
    "MatchSpec",
    "DetectorOverrides",
    "AVOverrides",
    "RoutingOverrides",
    "ReceiptOptions",
    "SREOptions",
    "AuditOptions",
    "PolicyRule",
    "BoundPolicy",
    "PolicyStore",
]

# ---------------------------------------------------------------------------
# Matching helpers + canonicalization
# ---------------------------------------------------------------------------

_HASH_CTX_RULE = "tcd:policy"
_HASH_CTX_SET = "tcd:policyset"

# Optional: safer regex engine with timeouts (if installed).
try:  # pragma: no cover
    import regex as _regex  # type: ignore
except Exception:  # pragma: no cover
    _regex = None  # type: ignore


# ---- hardening primitives (local; do NOT depend on other modules) ----

_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")

# Safe identifiers for labels used in refs/metrics (do NOT use for routes).
_SAFE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_VER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,63}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#]{0,255}$")

# Keys allowed in ctx (MatchSpec fields)
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


def _strip_unsafe_text(s: str, *, max_len: int) -> str:
    if not isinstance(s, str):
        return ""
    if len(s) > max_len:
        s = s[:max_len]
    if _ASCII_CTRL_RE.search(s):
        s = _ASCII_CTRL_RE.sub("", s)
    return s.strip()


def _safe_label(s: Any, *, default: Optional[str] = None) -> Optional[str]:
    if not isinstance(s, str):
        return default
    x = _strip_unsafe_text(s.lower(), max_len=64)
    if not x:
        return default
    if not _SAFE_LABEL_RE.fullmatch(x):
        return default
    return x


def _safe_id(s: Any, *, default: Optional[str] = None, max_len: int = 256) -> Optional[str]:
    if not isinstance(s, str):
        return default
    x = _strip_unsafe_text(s, max_len=max_len)
    if not x:
        return default
    if not _SAFE_ID_RE.fullmatch(x):
        return default
    return x


def _canon_json(obj: Any) -> str:
    # L7: JSON closure + deterministic encoding (no NaN/Inf)
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _dc_copy(dc: Any) -> Any:
    """
    Defensive copy for dataclasses. Always returns a distinct instance for
    dataclass inputs; otherwise returns the original object.
    """
    try:
        return replace(dc)
    except Exception:
        return dc


def _dc_update(dc: Any, override: Dict[str, Any]) -> Any:
    """
    Shallow, field-safe dataclass update (ignores unknown keys).
    L7: never returns the same instance when dc is a dataclass; it returns a new copy.
    """
    try:
        valid = {f.name for f in dc_fields(dc)}
    except Exception:
        return dc

    if not override:
        # still copy to avoid shared-mutable leakage into BoundPolicy
        return _dc_copy(dc)

    kwargs = {k: v for k, v in (override or {}).items() if k in valid}
    if not kwargs:
        return _dc_copy(dc)
    try:
        return replace(dc, **kwargs)
    except Exception:
        # fail-closed to base copy
        return _dc_copy(dc)


# ---------------------------------------------------------------------------
# Pattern grammar / compilation (L7 hardened)
# ---------------------------------------------------------------------------

PatEngine = Literal["re", "regex"]


def _is_regex(p: Optional[str]) -> bool:
    # Syntax: "/.../" only. No flags here (flags can be added later via schema).
    return isinstance(p, str) and len(p) >= 2 and p.startswith("/") and p.endswith("/")


def _regex_inner(p: str) -> str:
    return p[1:-1]


_BAD_RE = object()  # sentinel: never matches
_Pat = Union[str, re.Pattern, object, Any]  # Any: regex.Pattern if using `regex` module


@dataclass(frozen=True)
class RegexPolicy:
    """
    L7 regex safety policy.

    - max_pattern_len bounds compilation & matching complexity surface.
    - engine selects stdlib `re` or optional `regex`.
    - timeout_ms is only effective when engine == "regex" and library is available.
    - allow_regex controls whether /.../ patterns are permitted at all.
    - reject_empty_regex blocks '//' which would otherwise match everything and outrank '*'.
    """
    allow_regex: bool = True
    engine: PatEngine = "re"
    timeout_ms: int = 0
    max_pattern_len: int = 512
    reject_empty_regex: bool = True


def _compile_pat(p: Optional[str], rp: RegexPolicy) -> Optional[_Pat]:
    """
    Compile a match token into:
      - None  => wildcard
      - literal string
      - compiled regex pattern
      - _BAD_RE => invalid/disabled/unsafe (never matches)
    """
    if p is None:
        return None
    if not isinstance(p, str):
        # Defensive: non-str in policy should never match
        return _BAD_RE

    p = _strip_unsafe_text(p, max_len=2048)
    if not p or p == "*":
        return None

    if _is_regex(p):
        if not rp.allow_regex:
            return _BAD_RE
        inner = _regex_inner(p)
        if rp.reject_empty_regex and inner == "":
            return _BAD_RE
        if len(inner) > rp.max_pattern_len:
            return _BAD_RE

        # Prefer regex module with timeout if configured & available
        if rp.engine == "regex" and _regex is not None:
            try:
                return _regex.compile(inner)
            except Exception:
                return _BAD_RE

        # stdlib re
        try:
            return re.compile(inner)
        except Exception:
            return _BAD_RE

    # Literal token: keep exact match (case-sensitive). Bound length.
    if len(p) > 512:
        return _BAD_RE
    return p


def _match_token_compiled(value: Any, pat: Optional[_Pat], rp: RegexPolicy) -> bool:
    """
    L7: ctx values may be non-str; never throw. Coerce safely.
    """
    if pat is None:
        return True
    if pat is _BAD_RE:
        return False

    v = value if isinstance(value, str) else ""
    # Clamp to prevent huge user-controlled strings causing regex blowups
    v = _strip_unsafe_text(v, max_len=512)

    if isinstance(pat, str):
        return v == pat

    # regex-like
    try:
        # `regex` module supports timeout per-call.
        if rp.engine == "regex" and _regex is not None and rp.timeout_ms > 0:
            try:
                return bool(pat.fullmatch(v, timeout=rp.timeout_ms / 1000.0))
            except TypeError:
                # pattern may be stdlib `re`
                return bool(pat.fullmatch(v))
            except Exception:
                # includes regex.TimeoutError
                return False
        return bool(pat.fullmatch(v))
    except Exception:
        return False


def _specificity_from_match(match: "MatchSpec", rp: RegexPolicy) -> int:
    """
    L7: empty regex is treated as invalid (0 specificity and will not match anyway).
    """
    score = 0
    pats = [
        match.tenant,
        match.user,
        match.session,
        match.model_id,
        match.gpu_id,
        match.task,
        match.lang,
        match.env,
        match.trust_zone,
        match.route,
        match.data_class,
        match.workload,
        match.jurisdiction,
        match.regulation,
        match.client_app,
        match.access_channel,
    ]
    for p in pats:
        if p is None or p == "*":
            continue
        if _is_regex(p):
            inner = _regex_inner(p)
            if rp.reject_empty_regex and inner == "":
                continue
            score += 1
        else:
            score += 2
    return score


# ---------------------------------------------------------------------------
# Schemas (Pydantic v2; extra=forbid to catch typos in policy files)
# ---------------------------------------------------------------------------


class _StrictStrModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_default=True,
    )


def _sanitize_pat_str(v: Any) -> str:
    # allow "*" or "/.../" or literal; just sanitize control chars & length here.
    if v is None:
        return "*"
    if not isinstance(v, str):
        v = str(v)
    v = _strip_unsafe_text(v, max_len=512)
    return v if v else "*"


class MatchSpec(_StrictStrModel):
    """
    Matching template for routing a request into a policy rule.
    """
    # Logical identity / workload
    tenant: str = "*"
    user: str = "*"
    session: str = "*"
    model_id: str = "*"
    gpu_id: str = "*"
    task: str = "*"
    lang: str = "*"

    # Environment / topology hints
    env: str = "*"
    trust_zone: str = "*"
    route: str = "*"

    # Data / workload classification
    data_class: str = "*"
    workload: str = "*"

    # Regulatory / jurisdictional labels
    jurisdiction: str = "*"
    regulation: str = "*"

    # Client / access channel
    client_app: str = "*"
    access_channel: str = "*"

    @field_validator(
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
        mode="before",
    )
    @classmethod
    def _v_pat(cls, v: Any) -> str:
        return _sanitize_pat_str(v)


class DetectorOverrides(_StrictStrModel):
    """
    Fine-grained overrides for detector configuration.
    """
    window_size: Optional[int] = None
    ewma_alpha: Optional[float] = None
    entropy_floor: Optional[float] = None
    spread_threshold: Optional[float] = None
    rel_drop_threshold: Optional[float] = None
    z_threshold: Optional[float] = None
    min_calibration_steps: Optional[int] = None
    hard_fail_on_floor: Optional[bool] = None

    combine_mode: Optional[str] = None
    on_threshold: Optional[float] = None
    off_threshold: Optional[float] = None
    cooldown_steps: Optional[int] = None

    multi_var_enabled: Optional[bool] = None
    multi_var_window: Optional[int] = None
    multi_var_dim_limit: Optional[int] = None
    apt_profile: Optional[str] = None

    @field_validator("combine_mode", "apt_profile", mode="before")
    @classmethod
    def _v_lbl(cls, v: Any) -> Any:
        if v is None:
            return None
        s = _safe_label(str(v), default=None)
        return s


class AVOverrides(_StrictStrModel):
    """
    Overrides for anytime-valid / e-process configuration.
    """
    alpha_base: Optional[float] = None
    alpha_budget_fraction: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    e_stream: Optional[str] = None

    @field_validator("e_stream", mode="before")
    @classmethod
    def _v_stream(cls, v: Any) -> Any:
        if v is None:
            return None
        return _safe_label(str(v), default=None)


class RoutingOverrides(_StrictStrModel):
    """
    Routing and generation knobs.
    """
    # Clamp to reasonable ranges
    t_low: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    t_high: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    top_p_low: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    top_p_high: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    fallback_decoder: Optional[str] = None
    action_hint: Optional[str] = None
    route_profile: Optional[str] = None

    @field_validator("fallback_decoder", "action_hint", "route_profile", mode="before")
    @classmethod
    def _v_lbl(cls, v: Any) -> Any:
        if v is None:
            return None
        return _safe_label(str(v), default=None)


class ReceiptOptions(_StrictStrModel):
    """
    Control receipts & verification metrics.
    """
    enable_issue: bool = False
    enable_verify_metrics: bool = False

    attach_policy_refs: bool = True
    attach_match_context: bool = False

    profile: Optional[str] = None
    crypto_profile: Optional[str] = None
    match_context_level: Optional[str] = None

    @field_validator("profile", "crypto_profile", "match_context_level", mode="before")
    @classmethod
    def _v_lbl(cls, v: Any) -> Any:
        if v is None:
            return None
        # allow slightly wider id charset here
        return _safe_id(str(v), default=None, max_len=128)


class SREOptions(_StrictStrModel):
    """
    Service reliability knobs.
    """
    slo_latency_ms: Optional[float] = Field(default=None, ge=0.0, le=10_000_000.0)
    token_cost_divisor: Optional[float] = Field(default=None, ge=1.0, le=1_000_000.0)
    error_budget_fraction: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    probe_sample_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class AuditOptions(_StrictStrModel):
    """
    Per-policy audit and telemetry shaping options.
    """
    audit_label: Optional[str] = None
    sample_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    log_level: Optional[str] = None
    incident_class: Optional[str] = None
    force_audit_on_violation: Optional[bool] = None
    require_full_trace: Optional[bool] = None

    @field_validator("audit_label", "log_level", "incident_class", mode="before")
    @classmethod
    def _v_lbl(cls, v: Any) -> Any:
        if v is None:
            return None
        return _safe_label(str(v), default=None)


class PolicyRule(_StrictStrModel):
    """
    A single policy rule.
    """
    name: str = Field(..., min_length=1, max_length=128)
    version: str = Field(default="1", max_length=64)
    priority: int = 0

    match: MatchSpec = Field(default_factory=MatchSpec)

    detector: Optional[DetectorOverrides] = None
    av: Optional[AVOverrides] = None
    routing: Optional[RoutingOverrides] = None
    receipt: Optional[ReceiptOptions] = None
    sre: Optional[SREOptions] = None
    audit: Optional[AuditOptions] = None

    compliance_profile: Optional[str] = None
    risk_label: Optional[str] = None

    origin: Optional[str] = None
    policy_patch_id: Optional[str] = None
    commit_hash: Optional[str] = None
    change_ticket_id: Optional[str] = None

    @field_validator("name", mode="before")
    @classmethod
    def _v_name(cls, v: Any) -> str:
        s = _strip_unsafe_text(str(v), max_len=128)
        if not _SAFE_NAME_RE.fullmatch(s):
            # L7: refuse unsafe names instead of letting them leak into refs/metrics
            raise ValueError("policy name must be a safe identifier")
        return s

    @field_validator("version", mode="before")
    @classmethod
    def _v_ver(cls, v: Any) -> str:
        s = _strip_unsafe_text(str(v), max_len=64) if v is not None else "1"
        if not s:
            s = "1"
        if not _SAFE_VER_RE.fullmatch(s):
            raise ValueError("policy version must be a safe identifier")
        return s

    @field_validator("compliance_profile", "risk_label", mode="before")
    @classmethod
    def _v_lbl(cls, v: Any) -> Any:
        if v is None:
            return None
        return _safe_label(str(v), default=None)

    @field_validator("origin", "policy_patch_id", "commit_hash", "change_ticket_id", mode="before")
    @classmethod
    def _v_ids(cls, v: Any) -> Any:
        if v is None:
            return None
        return _safe_id(str(v), default=None, max_len=256)

    def policy_ref(self) -> str:
        """
        Stable reference token for this policy rule.
        """
        payload = {
            "name": self.name,
            "version": self.version,
            "priority": int(self.priority),
            "match": self.match.model_dump(),
            "detector": self.detector.model_dump() if self.detector else {},
            "av": self.av.model_dump() if self.av else {},
            "routing": self.routing.model_dump() if self.routing else {},
            "receipt": self.receipt.model_dump() if self.receipt else {},
            "sre": self.sre.model_dump() if self.sre else {},
            "audit": self.audit.model_dump() if self.audit else {},
            "compliance_profile": self.compliance_profile,
            "risk_label": self.risk_label,
            "origin": self.origin,
            "policy_patch_id": self.policy_patch_id,
            "commit_hash": self.commit_hash,
            "change_ticket_id": self.change_ticket_id,
        }
        h = Blake3Hash().hex(_canon_json(payload).encode("utf-8"), ctx=_HASH_CTX_RULE)
        return f"{self.name}@{self.version}#{h[:12]}"


# ---------------------------------------------------------------------------
# Bound output (immutable-ish)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BoundPolicy:
    """
    Immutable, fully-resolved policy view for a single request context.

    L7 hardening notes:
      - match is returned as a read-only mappingproxy (cannot be mutated by callers)
      - detector_cfg / av_cfg are fresh dataclass instances per bind() call
        to prevent shared-mutable leakage across requests.
    """

    name: str
    version: str
    policy_ref: str
    priority: int

    # Effective configs
    detector_cfg: TCDConfig
    av_cfg: AlwaysValidConfig

    # Routing knobs
    t_low: Optional[float]
    t_high: Optional[float]
    top_p_low: Optional[float]
    top_p_high: Optional[float]
    fallback_decoder: Optional[str]
    action_hint: Optional[str]
    route_profile: Optional[str]

    # Receipt / metrics
    enable_receipts: bool
    enable_verify_metrics: bool
    attach_policy_refs: bool
    attach_match_context: bool
    receipt_profile: Optional[str]
    receipt_crypto_profile: Optional[str]
    receipt_match_context_level: Optional[str]

    # SRE knobs
    slo_latency_ms: Optional[float]
    token_cost_divisor: float
    error_budget_fraction: Optional[float]
    probe_sample_rate: Optional[float]

    # AV / e-process derived hints
    alpha_budget_fraction: Optional[float]
    e_stream: Optional[str]

    # Audit / compliance tags
    compliance_profile: Optional[str]
    risk_label: Optional[str]
    audit_label: Optional[str]
    audit_sample_rate: Optional[float]
    audit_log_level: Optional[str]
    audit_incident_class: Optional[str]
    audit_force_on_violation: Optional[bool]
    audit_require_full_trace: Optional[bool]

    # Original match template (for introspection and receipts; no content).
    match: Mapping[str, str]

    # L7: provenance pointers + policyset ref (optional but very useful for receipts/audit).
    policyset_ref: Optional[str] = None
    origin: Optional[str] = None
    policy_patch_id: Optional[str] = None
    commit_hash: Optional[str] = None
    change_ticket_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Internal: compiled rules for fast, deterministic matching
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class _CompiledRule:
    # precompiled patterns
    tenant: Optional[_Pat]
    user: Optional[_Pat]
    session: Optional[_Pat]
    model_id: Optional[_Pat]
    gpu_id: Optional[_Pat]
    task: Optional[_Pat]
    lang: Optional[_Pat]
    env: Optional[_Pat]
    trust_zone: Optional[_Pat]
    route: Optional[_Pat]
    data_class: Optional[_Pat]
    workload: Optional[_Pat]
    jurisdiction: Optional[_Pat]
    regulation: Optional[_Pat]
    client_app: Optional[_Pat]
    access_channel: Optional[_Pat]

    specificity: int
    priority: int
    order: int  # original order for stable tie-break

    # cached refs and precomputed bound template
    policy_ref: str
    bound_template: BoundPolicy

    # store effective configs separately for quick per-bind cloning
    detector_cfg_eff: TCDConfig
    av_cfg_eff: AlwaysValidConfig


def _matches_compiled(ctx: Mapping[str, str], cr: _CompiledRule, rp: RegexPolicy) -> bool:
    """
    Evaluate a compiled rule against a normalized context mapping.
    """
    return (
        _match_token_compiled(ctx.get("tenant", ""), cr.tenant, rp)
        and _match_token_compiled(ctx.get("user", ""), cr.user, rp)
        and _match_token_compiled(ctx.get("session", ""), cr.session, rp)
        and _match_token_compiled(ctx.get("model_id", ""), cr.model_id, rp)
        and _match_token_compiled(ctx.get("gpu_id", ""), cr.gpu_id, rp)
        and _match_token_compiled(ctx.get("task", ""), cr.task, rp)
        and _match_token_compiled(ctx.get("lang", ""), cr.lang, rp)
        and _match_token_compiled(ctx.get("env", ""), cr.env, rp)
        and _match_token_compiled(ctx.get("trust_zone", ""), cr.trust_zone, rp)
        and _match_token_compiled(ctx.get("route", ""), cr.route, rp)
        and _match_token_compiled(ctx.get("data_class", ""), cr.data_class, rp)
        and _match_token_compiled(ctx.get("workload", ""), cr.workload, rp)
        and _match_token_compiled(ctx.get("jurisdiction", ""), cr.jurisdiction, rp)
        and _match_token_compiled(ctx.get("regulation", ""), cr.regulation, rp)
        and _match_token_compiled(ctx.get("client_app", ""), cr.client_app, rp)
        and _match_token_compiled(ctx.get("access_channel", ""), cr.access_channel, rp)
    )


# ---------------------------------------------------------------------------
# Policy store (L7 bundle: lockless reads + atomic swap)
# ---------------------------------------------------------------------------

OnLoadErrorMode = Literal["fail_open", "fail_closed", "raise"]


@dataclass(frozen=True)
class _PolicyBundle:
    rules: Tuple[PolicyRule, ...]
    compiled: Tuple[_CompiledRule, ...]
    set_ref: str
    updated_ts: float
    errors: Tuple[str, ...]
    on_error: OnLoadErrorMode
    default_policy: BoundPolicy
    error_policy: BoundPolicy
    regex_policy: RegexPolicy


class PolicyStore:
    """
    L7 policy store:

      - Deterministic selection: specificity(desc), priority(desc), order(asc)
      - Regex compilation cached; optional regex timeout support via `regex` module
      - Copy-on-write bundle: bind() is lockless (fast path), replace_rules() swaps atomically
      - No shared-mutable leakage: BoundPolicy always contains fresh dataclass config instances
      - Diagnostics retained: load/compile errors recorded (no silent drops)
      - Fail-open / fail-closed / raise policy on load errors configurable
    """

    def __init__(
        self,
        rules: List[PolicyRule],
        *,
        base_detector: Optional[TCDConfig] = None,
        base_av: Optional[AlwaysValidConfig] = None,
        default_token_cost_divisor: float = 50.0,
        # L7 controls
        on_load_error: OnLoadErrorMode = "fail_closed",
        strict_validation: bool = False,
        max_rules: int = 10_000,
        max_env_json_bytes: int = 2_000_000,
        regex_policy: Optional[RegexPolicy] = None,
    ):
        self._lock = threading.RLock()

        self._base_detector = _dc_copy(base_detector or TCDConfig())
        self._base_av = _dc_copy(base_av or AlwaysValidConfig())
        self._default_token_cost_divisor = float(default_token_cost_divisor)

        self._hasher = Blake3Hash()

        self._strict_validation = bool(strict_validation)
        self._max_rules = int(max(0, max_rules))
        self._max_env_json_bytes = int(max(0, max_env_json_bytes))

        rp = regex_policy or RegexPolicy(
            allow_regex=True,
            engine="regex" if (_regex is not None) else "re",
            timeout_ms=25 if (_regex is not None) else 0,  # safe default if available
            max_pattern_len=512,
            reject_empty_regex=True,
        )

        self._bundle: _PolicyBundle = self._build_bundle(
            rules=rules or [],
            rp=rp,
            on_error=on_load_error,
        )

    # ---------- construction / loading ----------

    @staticmethod
    def _parse_rules(obj: Any) -> Tuple[List[PolicyRule], List[str]]:
        """
        Parse JSON-compatible object into PolicyRule list.
        Accepted layouts:
          - {"rules": [ ... ]} or [ ... ]
        """
        errors: List[str] = []
        if isinstance(obj, dict) and "rules" in obj and isinstance(obj["rules"], list):
            arr = obj["rules"]
        elif isinstance(obj, list):
            arr = obj
        else:
            return [], ["policy blob is neither a list nor {'rules': [...]}"]

        out: List[PolicyRule] = []
        for i, item in enumerate(arr):
            try:
                out.append(PolicyRule.model_validate(item))
            except ValidationError as e:
                errors.append(f"rule[{i}] validation error: {e.__class__.__name__}")
        return out, errors

    @classmethod
    def from_env(cls, env_key: str = "TCD_POLICIES_JSON", **kwargs) -> "PolicyStore":
        txt = os.environ.get(env_key, "")
        # L7: size limit to prevent env-based DoS
        if isinstance(txt, str) and kwargs.get("max_env_json_bytes") is not None:
            lim = int(kwargs.get("max_env_json_bytes") or 0)
            if lim > 0 and len(txt.encode("utf-8", errors="ignore")) > lim:
                # Treat as load error -> store will fail-closed by default
                return cls(rules=[], **kwargs)

        txt = (txt or "").strip()
        if not txt:
            return cls(rules=[], **kwargs)
        try:
            obj = json.loads(txt)
        except Exception:
            return cls(rules=[], **kwargs)
        rules, _ = cls._parse_rules(obj)
        return cls(rules=rules, **kwargs)

    @classmethod
    def from_file(cls, path: str, **kwargs) -> "PolicyStore":
        try:
            # L7: file size guard (best-effort)
            if os.path.exists(path):
                lim = int(kwargs.get("max_env_json_bytes") or 0)
                if lim > 0 and os.path.getsize(path) > lim:
                    return cls(rules=[], **kwargs)
            with open(path, "r", encoding="utf-8") as fr:
                obj = json.load(fr)
        except Exception:
            return cls(rules=[], **kwargs)
        rules, _ = cls._parse_rules(obj)
        return cls(rules=rules, **kwargs)

    @classmethod
    def from_signed_blob(
        cls,
        blob: bytes,
        *,
        verifier: Optional[Callable[[bytes], None]] = None,
        **kwargs,
    ) -> "PolicyStore":
        if verifier is not None:
            verifier(blob)
        # L7: size guard
        lim = int(kwargs.get("max_env_json_bytes") or 0)
        if lim > 0 and isinstance(blob, (bytes, bytearray)) and len(blob) > lim:
            return cls(rules=[], **kwargs)
        try:
            obj = json.loads(blob.decode("utf-8", errors="strict"))
        except Exception:
            return cls(rules=[], **kwargs)
        rules, _ = cls._parse_rules(obj)
        return cls(rules=rules, **kwargs)

    # ---------- mutation / read ----------

    def replace_rules(self, rules: List[PolicyRule]) -> None:
        """
        Replace rule set atomically (copy-on-write).
        """
        with self._lock:
            self._bundle = self._build_bundle(
                rules=rules or [],
                rp=self._bundle.regex_policy,
                on_error=self._bundle.on_error,
            )

    def rules(self) -> List[PolicyRule]:
        """
        Return deep copies of current rules (callers cannot mutate store state).
        """
        b = self._bundle
        return [r.model_copy(deep=True) for r in b.rules]

    def policyset_ref(self) -> str:
        return self._bundle.set_ref

    def rules_refs(self) -> List[str]:
        return [cr.policy_ref for cr in self._bundle.compiled]

    def diagnostics(self) -> Dict[str, Any]:
        """
        L7: expose load/compile diagnostics (safe, non-sensitive).
        """
        b = self._bundle
        return {
            "policyset_ref": b.set_ref,
            "updated_ts": b.updated_ts,
            "rule_count": len(b.rules),
            "compiled_rule_count": len(b.compiled),
            "error_count": len(b.errors),
            "errors": list(b.errors[:50]),
            "on_load_error": b.on_error,
            "regex_engine": b.regex_policy.engine,
            "regex_timeout_ms": b.regex_policy.timeout_ms,
            "regex_max_pattern_len": b.regex_policy.max_pattern_len,
        }

    # ---------- binding ----------

    def bind(self, ctx: Dict[str, Any]) -> BoundPolicy:
        """
        Determine effective policy for a request context.

        L7: bind is lockless; it uses the current immutable bundle snapshot.
        """
        b = self._bundle
        ctx_n = self._normalize_ctx(ctx)

        # If store had fatal errors and is configured to raise, do it here.
        if b.errors and b.on_error == "raise":
            raise RuntimeError("PolicyStore has load/compile errors; refusing to bind")

        for cr in b.compiled:
            if _matches_compiled(ctx_n, cr, b.regex_policy):
                # Return fresh cfg instances to prevent shared mutation.
                det = _dc_copy(cr.detector_cfg_eff)
                av = _dc_copy(cr.av_cfg_eff)
                return replace(cr.bound_template, detector_cfg=det, av_cfg=av)

        # No rule matched.
        if b.errors and b.on_error == "fail_closed":
            det = _dc_copy(b.error_policy.detector_cfg)
            av = _dc_copy(b.error_policy.av_cfg)
            return replace(b.error_policy, detector_cfg=det, av_cfg=av)

        det = _dc_copy(b.default_policy.detector_cfg)
        av = _dc_copy(b.default_policy.av_cfg)
        return replace(b.default_policy, detector_cfg=det, av_cfg=av)

    def bind_explain(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """
        Debug-friendly bind with match trace (no content).
        """
        b = self._bundle
        ctx_n = self._normalize_ctx(ctx)
        out = {
            "policyset_ref": b.set_ref,
            "updated_ts": b.updated_ts,
            "matched": False,
            "matched_policy_ref": None,
            "candidate_count": len(b.compiled),
            "errors": list(b.errors[:20]),
        }
        for cr in b.compiled:
            if _matches_compiled(ctx_n, cr, b.regex_policy):
                out["matched"] = True
                out["matched_policy_ref"] = cr.policy_ref
                out["matched_policy_name"] = cr.bound_template.name
                out["matched_policy_version"] = cr.bound_template.version
                out["priority"] = cr.priority
                out["specificity"] = cr.specificity
                break
        return out

    def bind_many(self, ctxs: Sequence[Dict[str, Any]]) -> List[BoundPolicy]:
        """
        Batch bind for throughput. Uses one bundle snapshot.
        """
        b = self._bundle
        out: List[BoundPolicy] = []
        for ctx in ctxs:
            ctx_n = self._normalize_ctx(ctx)
            chosen: Optional[_CompiledRule] = None
            for cr in b.compiled:
                if _matches_compiled(ctx_n, cr, b.regex_policy):
                    chosen = cr
                    break
            if chosen is None:
                bp = b.error_policy if (b.errors and b.on_error == "fail_closed") else b.default_policy
                out.append(replace(bp, detector_cfg=_dc_copy(bp.detector_cfg), av_cfg=_dc_copy(bp.av_cfg)))
            else:
                out.append(replace(chosen.bound_template, detector_cfg=_dc_copy(chosen.detector_cfg_eff), av_cfg=_dc_copy(chosen.av_cfg_eff)))
        return out

    # ---------- internals ----------

    def _normalize_ctx(self, ctx: Mapping[str, Any]) -> Dict[str, str]:
        """
        L7: normalize ctx into safe bounded strings for matching.
        - Drops unknown keys
        - Coerces non-str to ""
        - Strips control chars
        - Bounds length
        """
        out: Dict[str, str] = {}
        if not isinstance(ctx, Mapping):
            return {k: "" for k in _CTX_KEYS}
        for k in _CTX_KEYS:
            v = ctx.get(k, "")
            if isinstance(v, str):
                out[k] = _strip_unsafe_text(v, max_len=512)
            else:
                out[k] = ""
        return out

    def _build_bundle(self, *, rules: List[PolicyRule], rp: RegexPolicy, on_error: OnLoadErrorMode) -> _PolicyBundle:
        errors: List[str] = []
        # Rule deep-copy to avoid external mutation (critical).
        safe_rules: List[PolicyRule] = []
        for i, r in enumerate(rules or []):
            try:
                if isinstance(r, PolicyRule):
                    safe_rules.append(r.model_copy(deep=True))
                elif isinstance(r, dict):
                    safe_rules.append(PolicyRule.model_validate(r))
                else:
                    errors.append(f"rule[{i}] unsupported type: {type(r).__name__}")
            except ValidationError:
                errors.append(f"rule[{i}] validation error")

        if self._max_rules > 0 and len(safe_rules) > self._max_rules:
            errors.append(f"too many rules: {len(safe_rules)} > max_rules={self._max_rules}; truncating")
            safe_rules = safe_rules[: self._max_rules]

        # Precompute compiled rules with effective configs and BoundPolicy templates.
        compiled: List[_CompiledRule] = []
        for idx, rule in enumerate(safe_rules):
            cr, err = self._compile_rule(rule, idx, rp)
            if err:
                errors.append(err)
                if self._strict_validation:
                    # strict: keep no partial bundle if any rule invalid
                    compiled = []
                    break
                continue
            if cr is not None:
                compiled.append(cr)

        # Sort deterministically:
        # highest specificity, highest priority, lowest order (earliest wins)
        compiled.sort(key=lambda x: (-int(x.specificity), -int(x.priority), int(x.order)))

        # Compute effective set ref based on EFFECTIVE rule set (validated rules only)
        canon = {"rules": [r.model_dump() for r in safe_rules], "version": "1"}
        digest = self._hasher.hex(_canon_json(canon).encode("utf-8"), ctx=_HASH_CTX_SET)
        set_ref = f"set@1#{digest[:12]}"

        # Build default and error policies (bounded, safe)
        default_policy = self._default_bound_policy(set_ref=set_ref)
        error_policy = self._error_bound_policy(set_ref=set_ref)

        return _PolicyBundle(
            rules=tuple(safe_rules),
            compiled=tuple(compiled),
            set_ref=set_ref,
            updated_ts=time.time(),
            errors=tuple(errors),
            on_error=on_error,
            default_policy=default_policy,
            error_policy=error_policy,
            regex_policy=rp,
        )

    def _compile_rule(self, rule: PolicyRule, idx: int, rp: RegexPolicy) -> Tuple[Optional[_CompiledRule], Optional[str]]:
        """
        Compile a PolicyRule into a matching plan + bound template.
        Returns (compiled_rule, error_string).
        """
        m = rule.match

        pats = {
            "tenant": _compile_pat(m.tenant, rp),
            "user": _compile_pat(m.user, rp),
            "session": _compile_pat(m.session, rp),
            "model_id": _compile_pat(m.model_id, rp),
            "gpu_id": _compile_pat(m.gpu_id, rp),
            "task": _compile_pat(m.task, rp),
            "lang": _compile_pat(m.lang, rp),
            "env": _compile_pat(m.env, rp),
            "trust_zone": _compile_pat(m.trust_zone, rp),
            "route": _compile_pat(m.route, rp),
            "data_class": _compile_pat(m.data_class, rp),
            "workload": _compile_pat(m.workload, rp),
            "jurisdiction": _compile_pat(m.jurisdiction, rp),
            "regulation": _compile_pat(m.regulation, rp),
            "client_app": _compile_pat(m.client_app, rp),
            "access_channel": _compile_pat(m.access_channel, rp),
        }

        # If any pattern is _BAD_RE, rule is invalid and should be rejected (L7).
        bad_fields = [k for k, v in pats.items() if v is _BAD_RE]
        if bad_fields:
            return None, f"rule[{idx}] {rule.name}@{rule.version}: invalid/unsafe patterns in {bad_fields}"

        # Specificity score (deterministic)
        spec = _specificity_from_match(m, rp)
        prio = int(rule.priority)

        # Effective configs precomputed ONCE per ruleset update.
        det_override = rule.detector.model_dump(exclude_none=True) if rule.detector else {}
        av_override = rule.av.model_dump(exclude_none=True) if rule.av else {}

        det_eff = _dc_update(self._base_detector, det_override)
        av_eff = _dc_update(self._base_av, av_override)

        # Routing knobs (already validated/clamped by schema)
        r = rule.routing.model_dump(exclude_none=True) if rule.routing else {}
        t_low = r.get("t_low")
        t_high = r.get("t_high")
        top_p_low = r.get("top_p_low")
        top_p_high = r.get("top_p_high")
        fallback_decoder = r.get("fallback_decoder")
        action_hint = r.get("action_hint")
        route_profile = r.get("route_profile")

        # Receipts / metrics
        enable_receipts = bool(rule.receipt.enable_issue) if rule.receipt else False
        enable_verify_metrics = bool(rule.receipt.enable_verify_metrics) if rule.receipt else False
        attach_policy_refs = bool(rule.receipt.attach_policy_refs) if rule.receipt else True
        attach_match_context = bool(rule.receipt.attach_match_context) if rule.receipt else False
        receipt_profile = rule.receipt.profile if rule.receipt else None
        receipt_crypto_profile = rule.receipt.crypto_profile if rule.receipt else None
        receipt_match_context_level = rule.receipt.match_context_level if rule.receipt else None

        # SRE
        slo_latency_ms = rule.sre.slo_latency_ms if rule.sre else None
        token_cost_divisor = float(
            (rule.sre.token_cost_divisor if (rule.sre and rule.sre.token_cost_divisor is not None) else None)
            or self._default_token_cost_divisor
        )
        error_budget_fraction = rule.sre.error_budget_fraction if rule.sre else None
        probe_sample_rate = rule.sre.probe_sample_rate if rule.sre else None

        # AV hints
        alpha_budget_fraction = rule.av.alpha_budget_fraction if rule.av else None
        e_stream = rule.av.e_stream if rule.av else None

        # Audit tags
        compliance_profile = rule.compliance_profile
        risk_label = rule.risk_label
        audit_label = rule.audit.audit_label if rule.audit else None
        audit_sample_rate = rule.audit.sample_rate if rule.audit else None
        audit_log_level = rule.audit.log_level if rule.audit else None
        audit_incident_class = rule.audit.incident_class if rule.audit else None
        audit_force_on_violation = rule.audit.force_audit_on_violation if rule.audit else None
        audit_require_full_trace = rule.audit.require_full_trace if rule.audit else None

        # Safety-oriented defaults for high risk/compliance
        high_risk = bool(risk_label and risk_label.lower() in {"high", "critical"})
        high_compliance = bool(compliance_profile and compliance_profile.lower() in {"high", "strict"})
        if high_risk or high_compliance:
            enable_receipts = True if not enable_receipts else enable_receipts
            if audit_sample_rate is None:
                audit_sample_rate = 1.0
            if audit_force_on_violation is None:
                audit_force_on_violation = True

        # Bound match template: read-only mappingproxy to avoid mutation.
        match_dict = rule.match.model_dump()
        match_ro = MappingProxyType({k: str(match_dict.get(k, "*")) for k in _CTX_KEYS})

        pref = rule.policy_ref()

        # Build template BoundPolicy (configs will be replaced with fresh copies per bind)
        template = BoundPolicy(
            name=rule.name,
            version=rule.version,
            policy_ref=pref,
            priority=prio,
            detector_cfg=det_eff,
            av_cfg=av_eff,
            t_low=t_low,
            t_high=t_high,
            top_p_low=top_p_low,
            top_p_high=top_p_high,
            fallback_decoder=fallback_decoder,
            action_hint=action_hint,
            route_profile=route_profile,
            enable_receipts=enable_receipts,
            enable_verify_metrics=enable_verify_metrics,
            attach_policy_refs=attach_policy_refs,
            attach_match_context=attach_match_context,
            receipt_profile=receipt_profile,
            receipt_crypto_profile=receipt_crypto_profile,
            receipt_match_context_level=receipt_match_context_level,
            slo_latency_ms=slo_latency_ms,
            token_cost_divisor=token_cost_divisor,
            error_budget_fraction=error_budget_fraction,
            probe_sample_rate=probe_sample_rate,
            alpha_budget_fraction=alpha_budget_fraction,
            e_stream=e_stream,
            compliance_profile=compliance_profile,
            risk_label=risk_label,
            audit_label=audit_label,
            audit_sample_rate=audit_sample_rate,
            audit_log_level=audit_log_level,
            audit_incident_class=audit_incident_class,
            audit_force_on_violation=audit_force_on_violation,
            audit_require_full_trace=audit_require_full_trace,
            match=match_ro,
            policyset_ref=None,  # filled at bundle build by replace() if needed
            origin=rule.origin,
            policy_patch_id=rule.policy_patch_id,
            commit_hash=rule.commit_hash,
            change_ticket_id=rule.change_ticket_id,
        )

        return (
            _CompiledRule(
                tenant=pats["tenant"],
                user=pats["user"],
                session=pats["session"],
                model_id=pats["model_id"],
                gpu_id=pats["gpu_id"],
                task=pats["task"],
                lang=pats["lang"],
                env=pats["env"],
                trust_zone=pats["trust_zone"],
                route=pats["route"],
                data_class=pats["data_class"],
                workload=pats["workload"],
                jurisdiction=pats["jurisdiction"],
                regulation=pats["regulation"],
                client_app=pats["client_app"],
                access_channel=pats["access_channel"],
                specificity=spec,
                priority=prio,
                order=idx,
                policy_ref=pref,
                bound_template=template,
                detector_cfg_eff=det_eff,
                av_cfg_eff=av_eff,
            ),
            None,
        )

    def _default_bound_policy(self, *, set_ref: str) -> BoundPolicy:
        # Default: fail-open baseline (behavior depends on outer layer).
        det = _dc_copy(self._base_detector)
        av = _dc_copy(self._base_av)
        match_ro = MappingProxyType({k: "*" for k in _CTX_KEYS})
        return BoundPolicy(
            name="default",
            version="0",
            policy_ref="default@0#000000000000",
            priority=0,
            detector_cfg=det,
            av_cfg=av,
            t_low=None,
            t_high=None,
            top_p_low=None,
            top_p_high=None,
            fallback_decoder=None,
            action_hint=None,
            route_profile=None,
            enable_receipts=False,
            enable_verify_metrics=False,
            attach_policy_refs=True,
            attach_match_context=False,
            receipt_profile=None,
            receipt_crypto_profile=None,
            receipt_match_context_level=None,
            slo_latency_ms=None,
            token_cost_divisor=float(self._default_token_cost_divisor),
            error_budget_fraction=None,
            probe_sample_rate=None,
            alpha_budget_fraction=None,
            e_stream=None,
            compliance_profile=None,
            risk_label=None,
            audit_label=None,
            audit_sample_rate=None,
            audit_log_level=None,
            audit_incident_class=None,
            audit_force_on_violation=None,
            audit_require_full_trace=None,
            match=match_ro,
            policyset_ref=set_ref,
        )

    def _error_bound_policy(self, *, set_ref: str) -> BoundPolicy:
        # Fail-closed hint policy for misload/miscompile. Outer layer should treat as "deny".
        det = _dc_copy(self._base_detector)
        av = _dc_copy(self._base_av)
        match_ro = MappingProxyType({k: "*" for k in _CTX_KEYS})
        return BoundPolicy(
            name="policy_error",
            version="1",
            policy_ref="policy_error@1#ffffffffffff",
            priority=10**9,
            detector_cfg=det,
            av_cfg=av,
            t_low=None,
            t_high=None,
            top_p_low=None,
            top_p_high=None,
            fallback_decoder=None,
            action_hint="block",
            route_profile="restricted",
            enable_receipts=True,
            enable_verify_metrics=True,
            attach_policy_refs=True,
            attach_match_context=False,
            receipt_profile="reg_strict",
            receipt_crypto_profile=None,
            receipt_match_context_level="coarse",
            slo_latency_ms=None,
            token_cost_divisor=float(self._default_token_cost_divisor),
            error_budget_fraction=0.0,
            probe_sample_rate=1.0,
            alpha_budget_fraction=None,
            e_stream=None,
            compliance_profile="strict",
            risk_label="critical",
            audit_label="restricted",
            audit_sample_rate=1.0,
            audit_log_level="error",
            audit_incident_class="compliance",
            audit_force_on_violation=True,
            audit_require_full_trace=True,
            match=match_ro,
            policyset_ref=set_ref,
        )


# NOTE: If you need a deterministic policyset_ref inside every rule template,
# call replace() at bundle build time. Here we keep it in BoundPolicy itself
# via default/error policies, and external layers can use PolicyStore.policyset_ref().