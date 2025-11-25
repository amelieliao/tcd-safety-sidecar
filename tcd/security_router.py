# FILE: tcd/security_router.py
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

try:
    from .trust_graph import SubjectKey
except Exception:  # pragma: no cover
    @dataclass
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
except Exception:  # pragma: no cover
    PolicyStore = Any  # type: ignore[misc]
    BoundPolicy = Any  # type: ignore[misc]

try:
    from .ratelimit import RateLimiter, RateDecision
except Exception:  # pragma: no cover
    RateLimiter = Any  # type: ignore[misc]
    RateDecision = Any  # type: ignore[misc]

try:
    from .attest import Attestor
except Exception:  # pragma: no cover
    Attestor = None  # type: ignore[misc]

try:
    # Detector runtime should encapsulate multivariate / APT detection
    # and e-process / anytime-valid accounting.
    from .detector import TCDDetectorRuntime  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    TCDDetectorRuntime = Any  # type: ignore[misc]

try:
    from .risk_av import AlwaysValidConfig
except Exception:  # pragma: no cover
    @dataclass
    class AlwaysValidConfig:  # type: ignore[misc]
        alpha_base: float = 1.0


__all__ = [
    "SecurityContext",
    "SecurityDecision",
    "SecurityRouter",
]


# ---------------------------------------------------------------------------
# Context / decision models
# ---------------------------------------------------------------------------


@dataclass
class SecurityContext:
    """
    Aggregated, content-free context for a single request / operation.

    This object is provided by the serving / middleware layer and MUST NOT
    contain raw prompts or completions. Only identifiers and coarse metadata
    should be present.

    subject:
        Logical subject identifier (tenant / user / session / model).

    ctx:
        Flat context map used by PolicyStore for binding:
          - tenant, user, session, model_id, trust_zone, env, route, task, lang, ...
        The exact keys should match MatchSpec / PolicyRule fields.

    tokens_in / tokens_out:
        Approximate token counts for prompt and planned output. Used to
        estimate resource cost for rate limiting / SRE budgeting.

    ip:
        Optional coarse client network identifier (IP string or network tag).

    kind:
        High-level operation kind, e.g. "inference", "admin", "control".
    """

    subject: SubjectKey
    ctx: Dict[str, str]
    tokens_in: int
    tokens_out: int
    ip: Optional[str] = None
    kind: str = "inference"


@dataclass
class SecurityDecision:
    """
    Final decision for a request, produced by SecurityRouter.

    The router does NOT perform HTTP or model invocations; it only decides:
      - whether the request is allowed;
      - what action is recommended (allow / deny / degrade / queue / require_approval);
      - which reasons and signals support that decision;
      - what receipts (if any) were issued for auditing.
    """

    allowed: bool
    action: str  # "allow", "deny", "degrade", "queue", "require_approval"
    reasons: Tuple[str, ...]
    bound_policy: BoundPolicy
    rate_decisions: Dict[str, RateDecision]  # logical name -> decision
    risk_score: Optional[float] = None
    e_triggered: bool = False
    receipt: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Lightly serialize the decision for logs / debugging.
        """
        return {
            "allowed": self.allowed,
            "action": self.action,
            "reasons": list(self.reasons),
            "policy_ref": getattr(self.bound_policy, "policy_ref", None),
            "risk_score": self.risk_score,
            "e_triggered": self.e_triggered,
            "rate_decisions": {
                k: {
                    "zone": getattr(v, "zone", None),
                    "allowed": getattr(v, "allowed", None),
                    "reason": getattr(v, "reason", None),
                }
                for k, v in self.rate_decisions.items()
            },
            "receipt": {
                "has_receipt": bool(self.receipt),
            },
        }


# ---------------------------------------------------------------------------
# Security router
# ---------------------------------------------------------------------------


class SecurityRouter:
    """
    High-level security & compliance router.

    Responsibilities:
      - Bind request context to a BoundPolicy via PolicyStore;
      - Run anomaly detection / e-process updates for long-horizon threats;
      - Apply layered rate limiting (IP / tenant / user+model / policy);
      - Enforce trust / role based access control for sensitive operations;
      - Optionally issue Attestor receipts with full provenance:
          * policyset_ref, policy_ref,
          * subject identifiers,
          * rate-limit and detector signals,
          * e-process snapshot (if available).

    The router is deliberately content-agnostic: raw prompts and completions
    MUST NOT flow through this layer.
    """

    def __init__(
        self,
        policy_store: PolicyStore,
        rate_limiter: RateLimiter,
        attestor: Optional[Attestor] = None,
        detector_runtime: Optional[TCDDetectorRuntime] = None,
        *,
        base_av: Optional[AlwaysValidConfig] = None,
    ) -> None:
        self._policies = policy_store
        self._limiter = rate_limiter
        self._attestor = attestor
        self._detector = detector_runtime
        self._base_av = base_av or AlwaysValidConfig()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def route(self, sctx: SecurityContext) -> SecurityDecision:
        """
        Main entry point: decide how this request should be handled.

        This method is intended for hot-path usage and should avoid blocking
        operations. It only uses in-memory state and deterministic logic.
        """
        # 1) Bind policy
        bound_policy = self._policies.bind(sctx.ctx)
        reasons: list[str] = []

        # 2) Approximate cost from tokens using SRE knobs
        total_tokens = max(1, int(sctx.tokens_in) + int(sctx.tokens_out))
        divisor = float(getattr(bound_policy, "token_cost_divisor", 50.0) or 50.0)
        cost = float(total_tokens) / max(1.0, divisor)

        # 3) Layered rate limiting: IP -> tenant -> user+model
        rate_decisions: Dict[str, RateDecision] = {}

        # 3a) IP / network-level limiting
        if sctx.ip:
            d_ip = self._limiter.consume_decision(
                key=sctx.ip,
                cost=1.0,
                zone=self._choose_zone_for_ip(bound_policy, sctx),
            )
            rate_decisions["ip"] = d_ip
            if not getattr(d_ip, "allowed", True):
                reasons.append(f"ip:{getattr(d_ip, 'reason', 'unknown')}")

        # 3b) tenant-level limiting
        tenant = sctx.ctx.get("tenant", "*")
        d_tenant = self._limiter.consume_decision(
            key=(tenant,),
            cost=cost,
            zone=self._choose_zone_for_tenant(bound_policy, sctx),
        )
        rate_decisions["tenant"] = d_tenant
        if not getattr(d_tenant, "allowed", True):
            reasons.append(f"tenant:{getattr(d_tenant, 'reason', 'unknown')}")

        # 3c) user+model-level limiting
        user = sctx.ctx.get("user", "*")
        model_id = sctx.ctx.get("model_id", "*")
        d_user = self._limiter.consume_decision(
            key=(tenant, user, model_id),
            cost=cost,
            zone=self._choose_zone_for_user_model(bound_policy, sctx),
        )
        rate_decisions["user_model"] = d_user
        if not getattr(d_user, "allowed", True):
            reasons.append(f"user_model:{getattr(d_user, 'reason', 'unknown')}")

        # 4) Anomaly detection / long-horizon evidence (optional)
        risk_score: Optional[float] = None
        e_triggered = False
        if self._detector is not None:
            try:
                risk_score, e_triggered = self._update_detector(bound_policy, sctx)
                if risk_score is not None:
                    if risk_score > 0.99:
                        reasons.append("anomaly:critical")
                    elif risk_score > 0.95:
                        reasons.append("anomaly:high")
            except Exception:
                # Detector failures must not break routing.
                pass

        # 5) Trust / role-based access control for sensitive operations
        if not self._is_authorized(bound_policy, sctx):
            reasons.append("unauthorized_subject")

        # 6) Combine signals into a final action
        allowed = True
        action = "allow"

        if "unauthorized_subject" in reasons:
            allowed = False
            action = "deny"
        elif any(not getattr(d, "allowed", True) for d in rate_decisions.values()):
            allowed = False
            action = "deny"
        elif e_triggered:
            allowed = False
            action = "deny"

        # 7) Optionally issue a receipt for this security decision
        receipt_summary: Optional[Dict[str, Any]] = None
        if self._should_issue_receipt(bound_policy, sctx, allowed, tuple(reasons)):
            receipt_summary = self._issue_security_receipt(
                bound_policy=bound_policy,
                sctx=sctx,
                allowed=allowed,
                reasons=tuple(reasons),
                rate_decisions=rate_decisions,
                risk_score=risk_score,
                e_triggered=e_triggered,
            )

        return SecurityDecision(
            allowed=allowed,
            action=action,
            reasons=tuple(reasons),
            bound_policy=bound_policy,
            rate_decisions=rate_decisions,
            risk_score=risk_score,
            e_triggered=e_triggered,
            receipt=receipt_summary,
        )

    # ------------------------------------------------------------------
    # Zone selection helpers
    # ------------------------------------------------------------------

    def _choose_zone_for_ip(self, bp: BoundPolicy, sctx: SecurityContext) -> str:
        """
        Map client network context to a rate-limit zone.

        Default mapping (can be overridden by callers at a higher layer):
          - trust_zone="internal"  -> "internal"
          - trust_zone="partner"   -> "partner"
          - otherwise              -> "internet"
        """
        tz = sctx.ctx.get("trust_zone", "internet")
        if tz == "internal":
            return "internal"
        if tz == "partner":
            return "partner"
        return "internet"

    def _choose_zone_for_tenant(self, bp: BoundPolicy, sctx: SecurityContext) -> str:
        """
        Map tenant / policy context to a rate-limit zone.

        High-risk or high-security policies can be routed to a stricter zone.
        """
        risk_label = getattr(bp, "risk_label", None)
        compliance_profile = getattr(bp, "compliance_profile", None)
        if risk_label in ("high", "critical") or compliance_profile == "HIGH_SECURITY":
            return "high_security"
        return "tenant"

    def _choose_zone_for_user_model(self, bp: BoundPolicy, sctx: SecurityContext) -> str:
        """
        Map user + model context to a rate-limit zone.

        Admin routes or admin route profiles can be sent to a separate zone.
        """
        route_profile = getattr(bp, "route_profile", None)
        if sctx.kind == "admin" or route_profile == "admin":
            return "admin"
        return "user_model"

    # ------------------------------------------------------------------
    # Detector / e-process integration
    # ------------------------------------------------------------------

    def _update_detector(
        self,
        bp: BoundPolicy,
        sctx: SecurityContext,
    ) -> Tuple[Optional[float], bool]:
        """
        Update anomaly / APT detector and return (risk_score, e_triggered).

        The detector runtime is expected to encapsulate:
          - feature extraction from SecurityContext / BoundPolicy;
          - any e-process / anytime-valid accounting;
          - thresholding / trigger logic.

        This method is intentionally schematic; the concrete implementation
        belongs in the detector runtime.
        """
        if self._detector is None:
            return None, False

        try:
            # A plausible detector API could look like:
            #   risk_score, e_triggered = self._detector.update(sctx, bp)
            # Here we simply call `update` if present and interpret its return.
            upd = getattr(self._detector, "update", None)
            if callable(upd):
                out = upd(sctx, bp)
                # Allow either (score, trigger) or just score.
                if isinstance(out, tuple) and len(out) == 2:
                    score, trig = out
                    return float(score) if score is not None else None, bool(trig)
                else:
                    score = out
                    return float(score) if score is not None else None, False
        except Exception:
            return None, False

        return None, False

    # ------------------------------------------------------------------
    # Authorization / trust-graph hook
    # ------------------------------------------------------------------

    def _is_authorized(self, bp: BoundPolicy, sctx: SecurityContext) -> bool:
        """
        Coarse-grained authorization check for admin / sensitive operations.

        This is the main hook for trust-graph / role / attribute-based
        access control integration. By default it allows everything and
        should be overridden or wrapped by higher layers in real deployments.
        """
        # Example of a very simple default:
        #   - if route_profile == "admin", only allow tenants/users that
        #     match some internal allowlist.
        route_profile = getattr(bp, "route_profile", None)
        if route_profile != "admin" and sctx.kind != "admin":
            return True

        # Default implementation: always allow (placeholder).
        # Real deployments should integrate with trust_graph here.
        return True

    # ------------------------------------------------------------------
    # Receipt / attestation integration
    # ------------------------------------------------------------------

    def _should_issue_receipt(
        self,
        bp: BoundPolicy,
        sctx: SecurityContext,
        allowed: bool,
        reasons: Tuple[str, ...],
    ) -> bool:
        """
        Decide whether to ask Attestor to issue a receipt for this decision.

        A typical policy:
          - always issue for denied requests;
          - always issue for admin / high-risk policies;
          - optionally issue for specific regulation / jurisdiction domains.
        """
        if self._attestor is None:
            return False

        risk_label = getattr(bp, "risk_label", None)
        compliance_profile = getattr(bp, "compliance_profile", None)
        route_profile = getattr(bp, "route_profile", None)

        if not allowed:
            return True
        if risk_label in ("high", "critical"):
            return True
        if compliance_profile == "HIGH_SECURITY":
            return True
        if sctx.kind == "admin" or route_profile == "admin":
            return True

        return False

    def _issue_security_receipt(
        self,
        *,
        bound_policy: BoundPolicy,
        sctx: SecurityContext,
        allowed: bool,
        reasons: Tuple[str, ...],
        rate_decisions: Dict[str, RateDecision],
        risk_score: Optional[float],
        e_triggered: bool,
    ) -> Dict[str, Any]:
        """
        Ask Attestor to issue a receipt covering this router decision.

        The receipt binds:
          - policy_ref + policyset_ref;
          - subject + context labels (no content);
          - rate-limit decisions and anomaly signals;
          - a simple e-process snapshot (if provided by the detector).
        """
        if self._attestor is None:
            return {}

        # Request object: who / where.
        req_obj = {
            "ts": time.time(),
            "subject_id": sctx.subject.as_id(),
            "ctx": dict(sctx.ctx),
        }

        # Computation object: what decision was made and why.
        comp_obj = {
            "kind": "security_router",
            "policy_ref": getattr(bound_policy, "policy_ref", None),
            "policyset_ref": self._policies.policyset_ref(),
            "allowed": bool(allowed),
            "reasons": list(reasons),
            "rate_decisions": {
                name: {
                    "zone": getattr(d, "zone", None),
                    "allowed": getattr(d, "allowed", None),
                    "reason": getattr(d, "reason", None),
                }
                for name, d in rate_decisions.items()
            },
            "risk_score": risk_score,
            "e_triggered": bool(e_triggered),
        }

        # e-process snapshot: placeholder wiring.
        base_alpha = float(getattr(self._base_av, "alpha_base", 1.0) or 1.0)
        e_obj = {
            "e_value": base_alpha,
            "alpha_alloc": 0.0,
            "alpha_wealth": 0.0,
            "threshold": 0.0,
            "trigger": bool(e_triggered),
        }

        # Meta: where this decision lives in the stack.
        meta = {
            "type": "security_router",
            "policy_ref": getattr(bound_policy, "policy_ref", None),
            "policyset_ref": self._policies.policyset_ref(),
            # In a full system, callers are expected to enrich meta with:
            #   - build_digest / binary / container digests,
            #   - patch_state_ref from PatchRuntime,
            #   - crypto_profile / sig_alg for PQ / hybrid signatures.
        }

        try:
            receipt = self._attestor.issue(
                req_obj=req_obj,
                comp_obj=comp_obj,
                e_obj=e_obj,
                witness_segments=None,
                witness_tags=None,
                meta=meta,
            )
        except Exception:
            return {}

        return {
            "receipt": receipt.get("receipt"),
            "receipt_body": receipt.get("receipt_body"),
            "receipt_sig": receipt.get("receipt_sig"),
            "verify_key": receipt.get("verify_key"),
        }