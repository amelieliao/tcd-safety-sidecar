# FILE: tcd/policies.py
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass, fields, replace
from typing import Any, Dict, List, Optional, Tuple, Union

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
    model_config = ConfigDict(extra="forbid")
    tenant: str = "*"
    user: str = "*"
    session: str = "*"
    model_id: str = "*"
    gpu_id: str = "*"
    task: str = "*"
    lang: str = "*"


class DetectorOverrides(BaseModel):
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


class AVOverrides(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alpha_base: Optional[float] = None


class RoutingOverrides(BaseModel):
    model_config = ConfigDict(extra="forbid")
    t_low: Optional[float] = None
    t_high: Optional[float] = None
    top_p_low: Optional[float] = None
    top_p_high: Optional[float] = None
    fallback_decoder: Optional[str] = None


class ReceiptOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enable_issue: bool = False
    enable_verify_metrics: bool = False


class SREOptions(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slo_latency_ms: Optional[float] = None
    token_cost_divisor: Optional[float] = Field(default=None, ge=1.0)


class PolicyRule(BaseModel):
    """
    A single policy rule. Regex patterns are denoted as '/.../'.
    """
    model_config = ConfigDict(extra="forbid")

    name: str
    version: str = "1"
    priority: int = 0
    match: MatchSpec = Field(default_factory=MatchSpec)
    detector: Optional[DetectorOverrides] = None
    av: Optional[AVOverrides] = None
    routing: Optional[RoutingOverrides] = None
    receipt: Optional[ReceiptOptions] = None
    sre: Optional[SREOptions] = None

    def policy_ref(self) -> str:
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
        }
        h = Blake3Hash().hex(_canon_json(payload).encode("utf-8"), ctx=_HASH_CTX_RULE)
        return f"{self.name}@{self.version}#{h[:12]}"


# ---------------------------------------------------------------------------
# Bound output (immutable)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BoundPolicy:
    name: str
    version: str
    policy_ref: str
    priority: int

    # effective configs
    detector_cfg: TCDConfig
    av_cfg: AlwaysValidConfig

    # routing knobs (None -> service default)
    t_low: Optional[float]
    t_high: Optional[float]
    top_p_low: Optional[float]
    top_p_high: Optional[float]
    fallback_decoder: Optional[str]

    # receipt/metrics
    enable_receipts: bool
    enable_verify_metrics: bool

    # SRE knobs
    slo_latency_ms: Optional[float]
    token_cost_divisor: float

    # original match
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
    score = 0
    for pat in [match.tenant, match.user, match.session, match.model_id, match.gpu_id, match.task, match.lang]:
        if pat is None or pat == "*":
            continue
        score += 1 if _is_regex(pat) else 2
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
        specificity=_specificity_from_match(m),
        policy_ref=rule.policy_ref(),
        order=idx,
    )


def _matches_compiled(ctx: Dict[str, str], cr: _CompiledRule) -> bool:
    return (
        _match_token_compiled(ctx.get("tenant", ""), cr.tenant)
        and _match_token_compiled(ctx.get("user", ""), cr.user)
        and _match_token_compiled(ctx.get("session", ""), cr.session)
        and _match_token_compiled(ctx.get("model_id", ""), cr.model_id)
        and _match_token_compiled(ctx.get("gpu_id", ""), cr.gpu_id)
        and _match_token_compiled(ctx.get("task", ""), cr.task)
        and _match_token_compiled(ctx.get("lang", ""), cr.lang)
    )


# ---------------------------------------------------------------------------
# Policy store
# ---------------------------------------------------------------------------

class PolicyStore:
    """
    Thread-safe policy store with:
      - deterministic selection (specificity, priority, then original order)
      - precompiled regex patterns
      - domain-separated set digest for audits
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
        try:
            with open(path, "r", encoding="utf-8") as fr:
                obj = json.load(fr)
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
            # primary: specificity (desc), secondary: priority (desc), tertiary: original order (asc)
            self._compiled.sort(key=lambda cr: (cr.specificity, int(cr.rule.priority), -cr.order), reverse=True)
            # Compute a stable set reference for audits
            canon = {"rules": [r.model_dump() for r in self._rules], "version": "1"}
            digest = self._hasher.hex(_canon_json(canon).encode("utf-8"), ctx=_HASH_CTX_SET)
            self._set_ref = f"set@1#{digest[:12]}"

    def rules(self) -> List[PolicyRule]:
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
        Selection is deterministic and stable across processes given the same rule order.
        """
        with self._lock:
            # Fast path: iterate pre-sorted compiled rules until first match
            chosen: Optional[_CompiledRule] = None
            for cr in self._compiled:
                if _matches_compiled(ctx, cr):
                    chosen = cr
                    break

            if chosen is None:
                # default fallback
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
                    enable_receipts=False,
                    enable_verify_metrics=False,
                    slo_latency_ms=None,
                    token_cost_divisor=self._default_token_cost_divisor,
                    match={
                        "tenant": "*",
                        "user": "*",
                        "session": "*",
                        "model_id": "*",
                        "gpu_id": "*",
                        "task": "*",
                        "lang": "*",
                    },
                )

            rule = chosen.rule

            # effective detector cfg
            det = self._base_detector
            if rule.detector:
                det = _dc_update(det, rule.detector.model_dump(exclude_none=True))

            # effective AV cfg
            av = self._base_av
            if rule.av:
                av = _dc_update(av, rule.av.model_dump(exclude_none=True))

            # routing
            r = rule.routing.model_dump(exclude_none=True) if rule.routing else {}
            t_low = r.get("t_low")
            t_high = r.get("t_high")
            top_p_low = r.get("top_p_low")
            top_p_high = r.get("top_p_high")
            fallback_decoder = r.get("fallback_decoder")

            # receipts / metrics
            enable_receipts = bool(rule.receipt.enable_issue) if rule.receipt else False
            enable_verify_metrics = bool(rule.receipt.enable_verify_metrics) if rule.receipt else False

            # SRE
            slo_latency_ms = rule.sre.slo_latency_ms if rule.sre else None
            tcd = rule.sre.token_cost_divisor if (rule.sre and rule.sre.token_cost_divisor) else None
            token_cost_divisor = float(tcd or self._default_token_cost_divisor)

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
                enable_receipts=enable_receipts,
                enable_verify_metrics=enable_verify_metrics,
                slo_latency_ms=slo_latency_ms,
                token_cost_divisor=token_cost_divisor,
                match=rule.match.model_dump(),
            )