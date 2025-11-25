# FILE: tcd/routing.py
from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# Optional Blake3 helper; routing stays deterministic even without it.
try:
    from .crypto import Blake3Hash  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    Blake3Hash = None  # type: ignore[assignment]


# =============================================================================
# Route data model
# =============================================================================


@dataclass
class Route:
    """
    Auditable routing decision for a single generation.

    This object is deliberately compact and content-agnostic. It carries both
    decoding parameters and a small security metadata surface so that higher
    layers (receipts, PQ signatures, audit systems) can record and verify how
    the system reacted to upstream risk signals.

    Conventions for tags
    --------------------
    - Threat tags MUST use prefix "threat:":
        e.g. "threat:apt", "threat:insider", "threat:supply_chain".
    - Zone tags SHOULD use prefix "zone:":
        e.g. "zone:internet", "zone:internal", "zone:partner".
    - Policy tags SHOULD use prefix "policy:":
        e.g. "policy:strict_safety", "policy:degrade_soft".
    """

    # Core sampling knobs
    temperature: float
    top_p: float
    decoder: str

    # Generic explanation / tuning
    tags: List[str] = field(default_factory=list)
    reason: str = ""
    max_tokens: Optional[int] = None
    latency_hint: str = "normal"  # "normal", "low_latency", "high_safety"
    safety_tier: str = "normal"   # "normal", "elevated", "strict"

    # Security / audit surface
    route_id: str = ""                    # Deterministic ID for this routing decision
    policy_ref: Optional[str] = None      # Policy / config version that drove this decision
    trust_zone: str = "internet"          # "internet" | "internal" | "partner" | "admin" | ...

    # Threat and e-process hooks
    threat_tags: List[str] = field(default_factory=list)  # ["apt", "insider", ...]
    av_label: Optional[str] = None        # Label from upstream AV controller
    av_trigger: Optional[bool] = None     # e-process trigger flag from upstream AV

    # NOTE: Route does not include any raw prompt or completion content.
    # It is safe to embed in receipts and to be covered by PQ signatures.


@dataclass
class StrategyConfig:
    """
    Configuration surface for StrategyRouter.

    The router maps high-level risk and threat signals into sampling strategies.
    It must remain deterministic and content-agnostic so that its output can be
    embedded in receipts and covered by signatures in high-assurance deployments.
    """

    # Global bounds for sampling parameters
    min_temperature: float = 0.1
    max_temperature: float = 2.0
    min_top_p: float = 0.1
    max_top_p: float = 1.0

    # Hard degrade factors (for strict safety)
    degrade_temp_factor: float = 0.7
    degrade_top_p_factor: float = 0.85

    # Soft degrade factors (for elevated safety)
    soft_degrade_temp_factor: float = 0.85
    soft_degrade_top_p_factor: float = 0.9

    # Numeric risk score thresholds
    high_risk_threshold: float = 0.95
    critical_risk_threshold: float = 0.99

    # Optional token cap in strict safety tier
    strict_safety_max_tokens: Optional[int] = None

    # Baseline safety tier by profile (before risk adjustments)
    # Keys are low-cardinality profile labels, e.g. "inference", "admin", "control".
    profile_defaults: Dict[str, str] = field(
        default_factory=lambda: {
            "admin": "strict",
            "control": "strict",
            "inference": "normal",
        }
    )

    # Baseline safety tier by trust zone
    # Keys are coarse zones, aligned with rate limiting / policy layers.
    zone_defaults: Dict[str, str] = field(
        default_factory=lambda: {
            "internet": "elevated",
            "partner": "normal",
            "internal": "normal",
            "admin": "strict",
        }
    )

    # Threat sensitivity knobs
    force_strict_on_apt: bool = True
    force_strict_on_insider: bool = True
    force_strict_on_supply_chain: bool = True
    force_strict_on_pq_unhealthy: bool = True

    # Additional caps in strict mode (after degrade factors)
    strict_temp_cap: float = 0.7
    strict_top_p_cap: float = 0.9

    # Optional policy identifier for audit / receipts
    policy_ref: Optional[str] = None


# =============================================================================
# Strategy router
# =============================================================================


class StrategyRouter:
    """
    Risk-aware, deterministic sampling strategy router.

    This component sits between a higher-level security router (which produces
    allow/deny/degrade decisions and threat labels) and the model invocation
    layer. It consumes only coarse risk metadata and outputs a Route that:

      - is deterministic given (config, inputs),
      - can be serialized and embedded in receipts,
      - is safe to cover with classical or PQ signatures.

    Responsibilities
    ----------------
    - Map decision_fail / risk scores / labels / threat flags / e-process
      triggers into sampling parameters and safety tiers.
    - Expose a small, stable metadata surface (policy_ref, trust_zone,
      threat_tags, av_label/av_trigger) for audit and verification.
    - Stay content-agnostic and side-effect free.

    Non-responsibilities
    --------------------
    - It does not inspect prompts or completions.
    - It does not enforce access control or rate limiting.
    - It does not run anomaly detection; it only reacts to upstream signals.
    """

    def __init__(self, config: Optional[StrategyConfig] = None) -> None:
        self.config = config or StrategyConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

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
        threat_kind: Optional[str] = None,   # "apt", "insider", "supply_chain", ...
        pq_unhealthy: bool = False,
        av_label: Optional[str] = None,      # from upstream AV controller (if any)
        av_trigger: Optional[bool] = None,   # AV-specific trigger (can be distinct from e_triggered)
        meta: Optional[Dict[str, Any]] = None,
    ) -> Route:
        """
        Decide a sampling route based on upstream risk metadata.

        Parameters
        ----------
        decision_fail:
            True when an upstream safety or policy decision has failed and the
            caller intends to degrade or deny. Here it is interpreted as a
            strong signal to enter strict safety routing.

        score:
            Coarse risk score in [0, 1]. Higher implies higher risk. Typically
            produced by a detector or e-process controller.

        base_temp / base_top_p:
            Baseline sampling parameters chosen by the caller or policy. These
            will be clamped and adjusted according to the safety tier.

        risk_label:
            Coarse textual label such as "low", "normal", "high", "critical".

        route_profile:
            Coarse route type, e.g. "inference", "admin", "control". Used to
            determine baseline safety tier via config.profile_defaults.

        e_triggered:
            True if an upstream controller considers the stream to have crossed
            an e-process threshold. Treated similarly to a strong risk signal.

        trust_zone:
            Coarse trust zone for this request, aligned with rate limiting /
            policy layers, e.g. "internet", "partner", "internal", "admin".

        threat_kind:
            Optional high-level threat label, e.g. "apt", "insider",
            "supply_chain". Used only to choose safety tier; no content is
            inspected here.

        pq_unhealthy:
            True when PQ / signing infrastructure is in a degraded state for
            this request (e.g. key unavailability or verification issues).
            Configurable via force_strict_on_pq_unhealthy.

        av_label / av_trigger:
            Optional label and trigger flag from an upstream AV controller. The
            router only records these for audit and may treat av_trigger as a
            strong risk signal when present.

        meta:
            Optional extra metadata, reserved for future use. It is not read
            by this version of the router.

        Returns
        -------
        Route
            A structured, deterministic routing decision that can be logged,
            embedded into receipts, and signed.
        """
        del meta  # currently unused; kept for forward compatibility

        # Normalize core inputs.
        temp = self._clamp_temp(base_temp)
        top_p = self._clamp_top_p(base_top_p)
        score_f = self._safe_score(score)
        risk_label_norm = str(risk_label).strip().lower()
        profile = str(route_profile).strip().lower()
        tz = str(trust_zone).strip().lower()
        tk = (threat_kind or "").strip().lower()

        tags: List[str] = []
        reason_parts: List[str] = []
        threat_tags: List[str] = []

        # ------------------------------------------------------------------
        # 1) Baseline safety tier from profile + trust zone
        # ------------------------------------------------------------------
        tier_order: Dict[str, int] = {"normal": 0, "elevated": 1, "strict": 2}

        safety_tier = self.config.profile_defaults.get(profile, "normal")
        zone_tier = self.config.zone_defaults.get(tz, "normal")

        if tier_order.get(zone_tier, 0) > tier_order.get(safety_tier, 0):
            safety_tier = zone_tier

        # Map baseline tier to soft degradation flag later if needed.
        strict_mode = safety_tier == "strict"
        soft_degrade = safety_tier == "elevated"

        # ------------------------------------------------------------------
        # 2) Hard signals: explicit failures and e-process triggers
        # ------------------------------------------------------------------

        if decision_fail:
            strict_mode = True
            tags.append("decision_fail")
            reason_parts.append("decision_fail")

        if e_triggered:
            strict_mode = True
            tags.append("e_triggered")
            reason_parts.append("e_process_trigger")

        if av_trigger is True:
            strict_mode = True
            tags.append("av_trigger")
            reason_parts.append("av_process_trigger")

        # ------------------------------------------------------------------
        # 3) Textual and numeric risk signals
        # ------------------------------------------------------------------

        if risk_label_norm in ("high", "elevated"):
            soft_degrade = True
            tags.append("risk_label_high")

        elif risk_label_norm in ("critical",):
            strict_mode = True
            tags.append("risk_label_critical")
            reason_parts.append("risk_label_critical")

        if score_f >= self.config.critical_risk_threshold:
            strict_mode = True
            tags.append("risk_score_critical")
            reason_parts.append("score_critical")
        elif score_f >= self.config.high_risk_threshold:
            soft_degrade = True
            tags.append("risk_score_high")
            reason_parts.append("score_high")

        # ------------------------------------------------------------------
        # 4) Threat and PQ signals
        # ------------------------------------------------------------------

        if tz:
            tags.append(f"zone:{tz}")

        if profile and profile != "inference":
            tags.append(f"profile:{profile}")

        if tk:
            tags.append(f"threat:{tk}")
            threat_tags.append(tk)
            if tk == "apt" and self.config.force_strict_on_apt:
                strict_mode = True
                reason_parts.append("threat_apt")
            elif tk == "insider" and self.config.force_strict_on_insider:
                strict_mode = True
                reason_parts.append("threat_insider")
            elif tk == "supply_chain" and self.config.force_strict_on_supply_chain:
                strict_mode = True
                reason_parts.append("threat_supply_chain")

        if pq_unhealthy and self.config.force_strict_on_pq_unhealthy:
            strict_mode = True
            tags.append("pq_unhealthy")
            reason_parts.append("pq_unhealthy")

        # ------------------------------------------------------------------
        # 5) Resolve safety tier and adjust sampling parameters
        # ------------------------------------------------------------------

        # Strict overrides everything; soft_degrade covers elevated tier and
        # non-critical high risk.
        if strict_mode:
            # First, apply hard degrade factors.
            temp, top_p = self._apply_hard_degrade(temp, top_p)
            # Then apply strict caps to guard against extreme base values.
            temp = min(temp, self.config.strict_temp_cap)
            top_p = min(top_p, self.config.strict_top_p_cap)
            safety_tier = "strict"
            tags.append("degrade_strict")
        elif soft_degrade:
            temp, top_p = self._apply_soft_degrade(temp, top_p)
            safety_tier = "elevated"
            tags.append("degrade_soft")
        else:
            safety_tier = "normal"

        # Decoder profile and latency hint.
        if safety_tier == "strict":
            decoder = "safe"
            latency_hint = "high_safety"
        elif safety_tier == "elevated":
            decoder = "cautious"
            latency_hint = "normal"
        else:
            decoder = "default"
            latency_hint = "normal"

        # Optional token cap in strict mode.
        max_tokens: Optional[int] = None
        if safety_tier == "strict" and self.config.strict_safety_max_tokens is not None:
            max_tokens = int(self.config.strict_safety_max_tokens)
            tags.append("max_tokens_capped")

        if not reason_parts:
            reason_parts.append("balanced_route")

        reason = ";".join(reason_parts)

        # ------------------------------------------------------------------
        # 6) Construct deterministic route_id for audit / signatures
        # ------------------------------------------------------------------

        route_id = self._make_route_id(
            safety_tier=safety_tier,
            trust_zone=tz,
            risk_label=risk_label_norm,
            score=score_f,
            decision_fail=decision_fail,
            e_triggered=e_triggered or (av_trigger is True),
            threat_kind=tk,
            pq_unhealthy=pq_unhealthy,
            route_profile=profile,
        )

        return Route(
            temperature=temp,
            top_p=top_p,
            decoder=decoder,
            tags=tags,
            reason=reason,
            max_tokens=max_tokens,
            latency_hint=latency_hint,
            safety_tier=safety_tier,
            route_id=route_id,
            policy_ref=self.config.policy_ref,
            trust_zone=tz,
            threat_tags=threat_tags,
            av_label=av_label,
            av_trigger=av_trigger,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _clamp_temp(self, value: float) -> float:
        try:
            t = float(value)
        except Exception:
            t = 1.0
        if not (t == t):  # NaN check
            t = 1.0
        return max(self.config.min_temperature, min(self.config.max_temperature, t))

    def _clamp_top_p(self, value: float) -> float:
        try:
            p = float(value)
        except Exception:
            p = 1.0
        if not (p == p):  # NaN
            p = 1.0
        return max(self.config.min_top_p, min(self.config.max_top_p, p))

    @staticmethod
    def _safe_score(score: float) -> float:
        try:
            s = float(score)
        except Exception:
            return 0.0
        if not (s == s):  # NaN
            return 0.0
        if s < 0.0:
            return 0.0
        if s > 1.0:
            return 1.0
        return s

    def _apply_hard_degrade(self, temp: float, top_p: float) -> Tuple[float, float]:
        """
        Apply stronger degradation to sampling parameters.
        """
        t = temp * self.config.degrade_temp_factor
        p = top_p * self.config.degrade_top_p_factor
        return self._clamp_temp(t), self._clamp_top_p(p)

    def _apply_soft_degrade(self, temp: float, top_p: float) -> Tuple[float, float]:
        """
        Apply softer degradation to sampling parameters.
        """
        t = temp * self.config.soft_degrade_temp_factor
        p = top_p * self.config.soft_degrade_top_p_factor
        return self._clamp_temp(t), self._clamp_top_p(p)

    def _make_route_id(
        self,
        *,
        safety_tier: str,
        trust_zone: str,
        risk_label: str,
        score: float,
        decision_fail: bool,
        e_triggered: bool,
        threat_kind: str,
        pq_unhealthy: bool,
        route_profile: str,
    ) -> str:
        """
        Deterministic identifier for this routing decision.

        The ID is derived from:
          - the effective StrategyConfig.policy_ref,
          - the core risk and threat inputs,
          - the chosen safety_tier and trust_zone.

        It does NOT include prompts, completions, or other content-bearing
        values. Its purpose is to allow receipts and PQ signatures to bind
        to a stable view of the routing logic.
        """
        payload = {
            "policy_ref": self.config.policy_ref,
            "safety_tier": safety_tier,
            "trust_zone": trust_zone,
            "risk_label": risk_label,
            "score": float(score),
            "decision_fail": bool(decision_fail),
            "e_triggered": bool(e_triggered),
            "threat_kind": threat_kind,
            "pq_unhealthy": bool(pq_unhealthy),
            "route_profile": route_profile,
        }
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # Prefer Blake3 if available to align with the rest of the system,
        # fall back to a standard hash otherwise.
        if Blake3Hash is not None:
            try:
                hasher = Blake3Hash()
                return hasher.hex(data, ctx="tcd:route")[:32]
            except Exception:
                pass

        return hashlib.blake2s(data, digest_size=16).hexdigest()

__all__ = ["Route", "StrategyConfig", "StrategyRouter"]