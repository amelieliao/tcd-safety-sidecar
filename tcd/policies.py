# FILE: tcd/policies.py
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, fields, replace
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from pydantic import BaseModel, Field, ValidationError, ConfigDict

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


def _is_regex(p: Optional[str]) -> bool:
    return isinstance(p, str) and len(p) >= 2 and p.startswith("/") and p.endswith("/")


def _canon_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _dc_update(dc, override: Dict[str, Any]):
    """Shallow, field-safe dataclass update (ignores unknown keys)."""
    if not override:
        return dc
    valid = {f.name for f in fields(dc)}
    kwargs = {k: v for k, v in (override or {}).items() if k in valid}
    return replace(dc, **kwargs) if kwargs else dc


# ---------------------------------------------------------------------------
# Schemas (Pydantic v2; extra=forbid to catch typos in policy files)
# ---------------------------------------------------------------------------


class MatchSpec(BaseModel):
    """
    Matching template for routing a request into a policy rule.

    All fields default to "*" which means "match anything". Literal strings
    are matched exactly; regex-like patterns are written as `/.../` and are
    compiled and used with fullmatch.
    """
    model_config = ConfigDict(extra="forbid")

    # Logical identity / workload
    tenant: str = "*"
    user: str = "*"
    session: str = "*"
    model_id: str = "*"
    gpu_id: str = "*"
    task: str = "*"
    lang: str = "*"

    # Environment / topology hints (populated by request context layer)
    env: str = "*"          # e.g. "dev", "staging", "prod"
    trust_zone: str = "*"   # e.g. "internal", "partner", "internet"
    route: str = "*"        # e.g. "/v1/chat", "admin:keys"

    # Data / workload classification
    data_class: str = "*"       # e.g. "public", "internal", "confidential"
    workload: str = "*"         # e.g. "inference", "training", "admin"

    # Regulatory / jurisdictional labels
    jurisdiction: str = "*"     # e.g. "region1", "region2"
    regulation: str = "*"       # e.g. "GDPR", "PCI", "sector_rule"

    # Client / access channel
    client_app: str = "*"       # e.g. "web", "mobile", "cli"
    access_channel: str = "*"   # e.g. "vpn", "internet", "on_prem"


class DetectorOverrides(BaseModel):
    """
    Fine-grained overrides for the multivariate / anomaly detector
    configuration. All fields are optional; only non-null values
    are applied on top of the base TCDConfig.
    """
    model_config = ConfigDict(extra="forbid")

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

    # Multivariate / APT-style extensions.
    multi_var_enabled: Optional[bool] = None
    multi_var_window: Optional[int] = None
    multi_var_dim_limit: Optional[int] = None
    apt_profile: Optional[str] = None  # e.g. "normal", "high_sensitivity", "observe_only"


class AVOverrides(BaseModel):
    """
    Overrides for the anytime-valid / e-process configuration per policy.
    """
    model_config = ConfigDict(extra="forbid")

    alpha_base: Optional[float] = None
    # Fraction of a global error / discovery budget this policy may consume.
    alpha_budget_fraction: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    # Logical stream identifier for the e-process linked to this policy.
    e_stream: Optional[str] = None


class RoutingOverrides(BaseModel):
    """
    Routing and generation knobs that a policy can set.

    These do not perform the routing themselves; they are surfaced
    through BoundPolicy for the serving layer to interpret.
    """
    model_config = ConfigDict(extra="forbid")

    t_low: Optional[float] = None
    t_high: Optional[float] = None
    top_p_low: Optional[float] = None
    top_p_high: Optional[float] = None
    fallback_decoder: Optional[str] = None

    # Optional high-level action hints: these are labels only.
    # The actual enforcement (slowdown, block, degrade) belongs
    # in the runtime / middleware layer.
    action_hint: Optional[str] = None  # e.g. "allow", "slow", "degrade", "block"
    route_profile: Optional[str] = None  # e.g. "interactive", "batch", "sensitive"


class ReceiptOptions(BaseModel):
    """
    Control how receipts and verification metrics should be handled
    for a given policy rule.
    """
    model_config = ConfigDict(extra="forbid")

    # Whether to issue receipts for requests matched to this policy.
    enable_issue: bool = False
    # Whether to emit extra verification metrics when receipts are present.
    enable_verify_metrics: bool = False

    # Whether to attach policy references (policy_ref, policyset_ref) into
    # receipt metadata for downstream auditing.
    attach_policy_refs: bool = True
    # Whether to attach a coarse match-context summary (no content).
    attach_match_context: bool = False

    # Receipt profile and crypto profile identifiers. These are labels
    # interpreted by the attestation layer.
    profile: Optional[str] = None          # e.g. "minimal", "full", "reg_strict"
    crypto_profile: Optional[str] = None   # e.g. "pq_profile_v1", "hybrid_profile"

    # How much of match-context is allowed into receipts, e.g.
    # "none", "coarse", "full_ids".
    match_context_level: Optional[str] = None


class SREOptions(BaseModel):
    """
    Service reliability knobs that can be driven by policies.
    """
    model_config = ConfigDict(extra="forbid")

    slo_latency_ms: Optional[float] = None
    token_cost_divisor: Optional[float] = Field(default=None, ge=1.0)
    # Optional fraction of an error budget this policy is allowed to
    # consume before stronger actions are considered by SRE logic.
    error_budget_fraction: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    # Optional sampling rate for active probes / synthetic checks
    # targeting traffic covered by this policy.
    probe_sample_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)


class AuditOptions(BaseModel):
    """
    Per-policy audit and telemetry shaping options.

    These fields guide how strongly this policy should be surfaced
    to metrics, logs and external observability backends. They do not
    directly control logging sinks; instead they are carried in
    BoundPolicy and interpreted by the outer stack.
    """
    model_config = ConfigDict(extra="forbid")

    # Coarse label used by telemetry and receipts, e.g. "default",
    # "sensitive", "restricted".
    audit_label: Optional[str] = None

    # Suggested telemetry sampling rate for this policy, in [0, 1].
    sample_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)

    # Optional log level hint for events related to this policy,
    # e.g. "info", "warn", "error".
    log_level: Optional[str] = None

    # Incident classification for violations routed under this policy.
    incident_class: Optional[str] = None  # e.g. "none", "security", "compliance"

    # Whether violations under this policy should always emit an
    # audit event, regardless of global sampling.
    force_audit_on_violation: Optional[bool] = None

    # Whether this policy requires full tracing (non-sampled) when
    # possible, for deeper auditability.
    require_full_trace: Optional[bool] = None


class PolicyRule(BaseModel):
    """
    A single policy rule.

    Regex patterns in the match section are denoted as '/.../' and
    are compiled and full-matched at bind time.
    """
    model_config = ConfigDict(extra="forbid")

    # Human-readable policy name.
    name: str
    # Semantic version string for this rule.
    version: str = "1"
    # Priority used for tie-breaking between rules with identical specificity.
    priority: int = 0

    # Matching template.
    match: MatchSpec = Field(default_factory=MatchSpec)

    # Behavioural overrides.
    detector: Optional[DetectorOverrides] = None
    av: Optional[AVOverrides] = None
    routing: Optional[RoutingOverrides] = None
    receipt: Optional[ReceiptOptions] = None
    sre: Optional[SREOptions] = None
    audit: Optional[AuditOptions] = None

    # Optional high-level classification labels to drive compliance
    # and risk-aware orchestration. These are purely tags; the runtime
    # decides how to interpret them.
    compliance_profile: Optional[str] = None
    risk_label: Optional[str] = None

    # Origin / change-control pointers. These fields only contain
    # identifiers or hashes, not business content.
    origin: Optional[str] = None                 # e.g. "patch_runtime", "manual", "ci"
    policy_patch_id: Optional[str] = None        # patch_runtime patch_id
    commit_hash: Optional[str] = None            # git commit or similar
    change_ticket_id: Optional[str] = None       # external change ticket id

    def policy_ref(self) -> str:
        """
        Compute a stable reference token for this policy rule.

        The reference is a function of the name, version, priority,
        matching template and all effective options, using a
        domain-separated Blake3 hash.
        """
        payload = {
            "name": self.name,
            "version": self.version,
            "priority": self.priority,
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
# Bound output (immutable)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BoundPolicy:
    """
    Immutable, fully-resolved policy view for a single request context.

    This is what the runtime / middleware layer consumes at decision
    time. All heavy work (regex compilation, dataclass merging, hashing)
    is done when the PolicyStore is updated.
    """

    name: str
    version: str
    policy_ref: str
    priority: int

    # Effective configs
    detector_cfg: TCDConfig
    av_cfg: AlwaysValidConfig

    # Routing knobs (None -> service default)
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
    match: Dict[str, str]


# ---------------------------------------------------------------------------
# Internal: compiled rules for fast, deterministic matching
# ---------------------------------------------------------------------------

_BAD_RE = object()  # sentinel: never matches

_Pat = Union[str, re.Pattern, object]


def _compile_pat(p: Optional[str]) -> Optional[_Pat]:
    if p is None or p == "*":
        return None
    if _is_regex(p):
        try:
            # Compile inner pattern; we will use fullmatch at evaluation time.
            return re.compile(p[1:-1])
        except Exception:
            return _BAD_RE
    return p  # literal string


def _match_token_compiled(value: str, pat: Optional[_Pat]) -> bool:
    if pat is None:
        return True
    if pat is _BAD_RE:
        return False
    if isinstance(pat, re.Pattern):
        return bool(pat.fullmatch(value or ""))
    return (value or "") == pat


def _specificity_from_match(match: MatchSpec) -> int:
    """
    Compute a simple specificity score for a match template.

    More specific patterns (literals) receive a higher score than regexes,
    which in turn are higher than wildcards. This is used to prefer
    more precise rules when multiple rules can match a context.
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
        score += 1 if _is_regex(p) else 2
    return score


@dataclass(frozen=True)
class _CompiledRule:
    rule: PolicyRule
    # compiled patterns
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
    policy_ref: str
    order: int  # original order for stable tie-breaking


def _compile_rule(rule: PolicyRule, idx: int) -> _CompiledRule:
    m = rule.match
    return _CompiledRule(
        rule=rule,
        tenant=_compile_pat(m.tenant),
        user=_compile_pat(m.user),
        session=_compile_pat(m.session),
        model_id=_compile_pat(m.model_id),
        gpu_id=_compile_pat(m.gpu_id),
        task=_compile_pat(m.task),
        lang=_compile_pat(m.lang),
        env=_compile_pat(m.env),
        trust_zone=_compile_pat(m.trust_zone),
        route=_compile_pat(m.route),
        data_class=_compile_pat(m.data_class),
        workload=_compile_pat(m.workload),
        jurisdiction=_compile_pat(m.jurisdiction),
        regulation=_compile_pat(m.regulation),
        client_app=_compile_pat(m.client_app),
        access_channel=_compile_pat(m.access_channel),
        specificity=_specificity_from_match(m),
        policy_ref=rule.policy_ref(),
        order=idx,
    )


def _matches_compiled(ctx: Dict[str, str], cr: _CompiledRule) -> bool:
    """
    Evaluate a compiled rule against a simple context dictionary.

    All context fields are treated as simple strings; missing entries
    are equivalent to empty string.
    """
    return (
        _match_token_compiled(ctx.get("tenant", ""), cr.tenant)
        and _match_token_compiled(ctx.get("user", ""), cr.user)
        and _match_token_compiled(ctx.get("session", ""), cr.session)
        and _match_token_compiled(ctx.get("model_id", ""), cr.model_id)
        and _match_token_compiled(ctx.get("gpu_id", ""), cr.gpu_id)
        and _match_token_compiled(ctx.get("task", ""), cr.task)
        and _match_token_compiled(ctx.get("lang", ""), cr.lang)
        and _match_token_compiled(ctx.get("env", ""), cr.env)
        and _match_token_compiled(ctx.get("trust_zone", ""), cr.trust_zone)
        and _match_token_compiled(ctx.get("route", ""), cr.route)
        and _match_token_compiled(ctx.get("data_class", ""), cr.data_class)
        and _match_token_compiled(ctx.get("workload", ""), cr.workload)
        and _match_token_compiled(ctx.get("jurisdiction", ""), cr.jurisdiction)
        and _match_token_compiled(ctx.get("regulation", ""), cr.regulation)
        and _match_token_compiled(ctx.get("client_app", ""), cr.client_app)
        and _match_token_compiled(ctx.get("access_channel", ""), cr.access_channel)
    )


# ---------------------------------------------------------------------------
# Policy store
# ---------------------------------------------------------------------------

class PolicyStore:
    """
    Thread-safe policy store with:

      - deterministic selection (specificity, priority, then original order);
      - precompiled regex patterns for fast evaluation;
      - domain-separated set digest for audits and receipts.

    PolicyStore is intended to be the single source of truth for
    routing a request context into a BoundPolicy.
    """

    def __init__(
        self,
        rules: List[PolicyRule],
        *,
        base_detector: Optional[TCDConfig] = None,
        base_av: Optional[AlwaysValidConfig] = None,
        default_token_cost_divisor: float = 50.0,
    ):
        self._lock = threading.RLock()
        self._base_detector = base_detector or TCDConfig()
        self._base_av = base_av or AlwaysValidConfig()
        self._default_token_cost_divisor = float(default_token_cost_divisor)

        self._hasher = Blake3Hash()
        self._rules: List[PolicyRule] = []
        self._compiled: List[_CompiledRule] = []
        self._set_ref: str = "set@1#000000000000"
        self.replace_rules(rules or [])

    # ---------- construction ----------

    @staticmethod
    def _parse_rules(obj: Any) -> List[PolicyRule]:
        """
        Parse a JSON-compatible object into a list of PolicyRule instances.

        The accepted layout is either:
          - {"rules": [ ... ]}  or
          - [ ... ]
        """
        if isinstance(obj, dict) and "rules" in obj and isinstance(obj["rules"], list):
            arr = obj["rules"]
        elif isinstance(obj, list):
            arr = obj
        else:
            return []
        out: List[PolicyRule] = []
        for item in arr:
            try:
                out.append(PolicyRule.model_validate(item))
            except ValidationError:
                # Skip invalid entries to avoid failing the entire set on a single bad rule.
                continue
        return out

    @classmethod
    def from_env(cls, env_key: str = "TCD_POLICIES_JSON", **kwargs) -> "PolicyStore":
        """
        Build a PolicyStore from a JSON string stored in an environment variable.
        """
        txt = os.environ.get(env_key, "").strip()
        if not txt:
            return cls(rules=[], **kwargs)
        try:
            obj = json.loads(txt)
        except Exception:
            return cls(rules=[], **kwargs)
        return cls(rules=cls._parse_rules(obj), **kwargs)

    @classmethod
    def from_file(cls, path: str, **kwargs) -> "PolicyStore":
        """
        Build a PolicyStore from a JSON file at the given path.
        """
        try:
            with open(path, "r", encoding="utf-8") as fr:
                obj = json.load(fr)
        except Exception:
            return cls(rules=[], **kwargs)
        return cls(rules=cls._parse_rules(obj), **kwargs)

    @classmethod
    def from_signed_blob(
        cls,
        blob: bytes,
        *,
        verifier: Optional[Callable[[bytes], None]] = None,
        **kwargs,
    ) -> "PolicyStore":
        """
        Build a PolicyStore from a signed JSON blob.

        If a verifier is provided, it is called with the raw blob before any
        parsing. The verifier should raise on failure. Signature algorithms
        and key handling are implemented by the caller.
        """
        if verifier is not None:
            verifier(blob)
        try:
            obj = json.loads(blob.decode("utf-8"))
        except Exception:
            return cls(rules=[], **kwargs)
        return cls(rules=cls._parse_rules(obj), **kwargs)

    # ---------- mutation / read ----------

    def replace_rules(self, rules: List[PolicyRule]) -> None:
        """
        Replace the rule set and rebuild compiled cache + set digest atomically.
        """
        with self._lock:
            self._rules = list(rules or [])
            self._compiled = [_compile_rule(r, idx) for idx, r in enumerate(self._rules)]
            # Pre-sort by deterministic keys to accelerate bind():
            # primary: specificity (desc),
            # secondary: priority (desc),
            # tertiary: original order (asc, via reversed order key).
            self._compiled.sort(
                key=lambda cr: (cr.specificity, int(cr.rule.priority), -cr.order),
                reverse=True,
            )
            # Compute a stable set reference for audits.
            canon = {"rules": [r.model_dump() for r in self._rules], "version": "1"}
            digest = self._hasher.hex(
                _canon_json(canon).encode("utf-8"),
                ctx=_HASH_CTX_SET,
            )
            self._set_ref = f"set@1#{digest[:12]}"

    def rules(self) -> List[PolicyRule]:
        """
        Return a shallow copy of the current rules.
        """
        with self._lock:
            return list(self._rules)

    def policyset_ref(self) -> str:
        """
        Return the canonical reference of the current rule set (stable digest).
        """
        with self._lock:
            return self._set_ref

    def rules_refs(self) -> List[str]:
        """
        Return the list of per-rule refs (cached).
        """
        with self._lock:
            return [cr.policy_ref for cr in self._compiled]

    # ---------- binding ----------

    def bind(self, ctx: Dict[str, str]) -> BoundPolicy:
        """
        Determine the effective policy for a request context.

        Selection is deterministic and stable across processes given the
        same rule order, and uses only the declared MatchSpec keys from
        the provided context dictionary.
        """
        with self._lock:
            # Fast path: iterate pre-sorted compiled rules until first match.
            chosen: Optional[_CompiledRule] = None
            for cr in self._compiled:
                if _matches_compiled(ctx, cr):
                    chosen = cr
                    break

            if chosen is None:
                # Default fallback: base configs + synthetic default rule.
                det = self._base_detector
                av = self._base_av
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
                    token_cost_divisor=self._default_token_cost_divisor,
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
                    match={
                        "tenant": "*",
                        "user": "*",
                        "session": "*",
                        "model_id": "*",
                        "gpu_id": "*",
                        "task": "*",
                        "lang": "*",
                        "env": "*",
                        "trust_zone": "*",
                        "route": "*",
                        "data_class": "*",
                        "workload": "*",
                        "jurisdiction": "*",
                        "regulation": "*",
                        "client_app": "*",
                        "access_channel": "*",
                    },
                )

            rule = chosen.rule

            # Effective detector cfg
            det = self._base_detector
            if rule.detector:
                det = _dc_update(det, rule.detector.model_dump(exclude_none=True))

            # Effective AV cfg
            av = self._base_av
            if rule.av:
                av = _dc_update(av, rule.av.model_dump(exclude_none=True))

            # Routing
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
            enable_verify_metrics = (
                bool(rule.receipt.enable_verify_metrics) if rule.receipt else False
            )
            attach_policy_refs = (
                bool(rule.receipt.attach_policy_refs) if rule.receipt else True
            )
            attach_match_context = (
                bool(rule.receipt.attach_match_context) if rule.receipt else False
            )
            receipt_profile = rule.receipt.profile if rule.receipt else None
            receipt_crypto_profile = (
                rule.receipt.crypto_profile if rule.receipt else None
            )
            receipt_match_context_level = (
                rule.receipt.match_context_level if rule.receipt else None
            )

            # SRE
            slo_latency_ms = rule.sre.slo_latency_ms if rule.sre else None
            tcd = (
                rule.sre.token_cost_divisor
                if (rule.sre and rule.sre.token_cost_divisor)
                else None
            )
            token_cost_divisor = float(tcd or self._default_token_cost_divisor)
            error_budget_fraction = (
                rule.sre.error_budget_fraction if rule.sre else None
            )
            probe_sample_rate = rule.sre.probe_sample_rate if rule.sre else None

            # AV / e-process hints
            alpha_budget_fraction = (
                rule.av.alpha_budget_fraction if rule.av else None
            )
            e_stream = rule.av.e_stream if rule.av else None

            # Audit / compliance tags
            compliance_profile = rule.compliance_profile
            risk_label = rule.risk_label
            audit_label = rule.audit.audit_label if rule.audit else None
            audit_sample_rate = rule.audit.sample_rate if rule.audit else None
            audit_log_level = rule.audit.log_level if rule.audit else None
            audit_incident_class = (
                rule.audit.incident_class if rule.audit else None
            )
            audit_force_on_violation = (
                rule.audit.force_audit_on_violation if rule.audit else None
            )
            audit_require_full_trace = (
                rule.audit.require_full_trace if rule.audit else None
            )

            # Safety-oriented defaults: if a policy is explicitly marked high
            # risk or high compliance, make sure receipts and audit sampling
            # are not silently weakened.
            high_risk = bool(
                risk_label and risk_label.lower() in {"high", "critical"}
            )
            high_compliance = bool(
                compliance_profile
                and compliance_profile.lower() in {"high", "strict"}
            )
            if high_risk or high_compliance:
                if not enable_receipts:
                    enable_receipts = True
                if audit_sample_rate is None:
                    audit_sample_rate = 1.0

            return BoundPolicy(
                name=rule.name,
                version=rule.version,
                policy_ref=chosen.policy_ref,  # cached
                priority=int(rule.priority),
                detector_cfg=det,
                av_cfg=av,
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
                match=rule.match.model_dump(),
            )