# tcd/decision_engine.py
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Dict, Mapping, Optional


class DecisionAction(str, Enum):
    """
    Canonical action set for the TCD decision engine.

    NOTE: These are intentionally small and composable. The agent/runtime layer
    is responsible for mapping actions to concrete effects (rate limit, policy
    swap, circuit break, etc.).
    """

    ALLOW = "allow"
    BLOCK = "block"
    DEGRADE = "degrade"              # serve lower-risk / cheaper variant
    THROTTLE = "throttle"            # rate-limit or backoff
    ASK_FOR_REVIEW = "ask_for_review"
    ESCALATE_TO_HUMAN = "escalate_to_human"


@dataclass
class DecisionThresholds:
    """
    Threshold configuration for mapping risk + environment into actions.

    All thresholds live here to make the decision surface auditable and easy
    to serialize into receipts.
    """

    # risk in [0, 1]
    hard_block_risk: float = 0.98          # above this → BLOCK
    soft_block_risk: float = 0.92          # above this → ESCALATE / BLOCK
    throttle_risk: float = 0.80            # above this → THROTTLE
    degrade_risk: float = 0.65             # above this → DEGRADE

    # latency / error based gates (milliseconds / ratios)
    p95_latency_ms_soft: int = 800         # above this + moderate risk → THROTTLE
    p95_latency_ms_hard: int = 1500        # above this → DEGRADE / BLOCK
    error_rate_soft: float = 0.05          # recent error rate
    error_rate_hard: float = 0.15

    # load / concurrency
    in_flight_soft: int = 512
    in_flight_hard: int = 2048

    # heuristic for "this smells abnormal and needs a human"
    anomaly_risk_bump: float = 0.10


@dataclass
class EnvironmentSnapshot:
    """
    Minimal environment snapshot captured at decision time.

    This is what the rest of TCD should pass into DecisionEngine.decide().
    It is intentionally generic so the module can be reused across HTTP, gRPC,
    batch pipelines, etc.
    """

    risk_score: float
    tenant_id: str
    route: str
    method: str

    # Operational signals (all optional; missing means "unknown")
    p95_latency_ms: Optional[int] = None
    error_rate: Optional[float] = None
    in_flight_requests: Optional[int] = None

    # Is this request already flagged as anomalous by an upstream detector?
    is_anomalous: bool = False

    # Additional opaque features (country, model_id, user_tier, etc.)
    extra: Dict[str, Any] = None

    # Wall-clock timestamp in seconds since epoch (for receipts/logs)
    ts: float = None

    def __post_init__(self) -> None:
        if self.extra is None:
            self.extra = {}
        if self.ts is None:
            self.ts = time.time()


@dataclass
class DecisionResult:
    """
    Immutable result of a single decision.

    This is what should be threaded into audit / receipts / trust graph.
    """

    action: DecisionAction
    reason: str
    policy_version: str
    snapshot: EnvironmentSnapshot
    thresholds: DecisionThresholds
    created_at: float

    def to_dict(self) -> Dict[str, Any]:
        """
        Lossless, JSON-serializable representation suitable for receipts,
        logs, or trust_graph ingestion.
        """
        return {
            "action": self.action.value,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "created_at": self.created_at,
            "snapshot": asdict(self.snapshot),
            "thresholds": asdict(self.thresholds),
        }


class DecisionEngine:
    """
    Core policy engine for TCD.

    Responsibilities:
    - Map (risk_score, environment) → DecisionAction
    - Provide a deterministic, auditable decision surface
    - Emit enough metadata for receipts / trust graph without doing any I/O

    This class is intentionally pure: no network, no file writes. The caller
    decides how to persist DecisionResult and how to enact the returned action.
    """

    def __init__(
        self,
        thresholds: Optional[DecisionThresholds] = None,
        policy_version: str = "v1",
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._thresholds = thresholds or DecisionThresholds()
        self._policy_version = policy_version
        self._log = logger or logging.getLogger(__name__)

    @property
    def thresholds(self) -> DecisionThresholds:
        return self._thresholds

    @property
    def policy_version(self) -> str:
        return self._policy_version

    # ---- Public API ----------------------------------------------------- #

    def decide(self, snapshot: EnvironmentSnapshot) -> DecisionResult:
        """
        Compute the next action for the given snapshot.

        This method is deterministic given (thresholds, snapshot). All random
        or probabilistic behavior should be handled upstream and represented
        as features inside `snapshot.extra`.
        """
        risk = max(0.0, min(1.0, snapshot.risk_score))
        t = self._thresholds

        # Optional "risk bump" if another detector marked this as anomalous
        effective_risk = risk + (t.anomaly_risk_bump if snapshot.is_anomalous else 0.0)
        effective_risk = min(effective_risk, 1.0)

        reason_parts = [f"risk={risk:.3f}", f"effective_risk={effective_risk:.3f}"]

        # 1) Hard risk cutoffs: ESCALATE / BLOCK
        if effective_risk >= t.hard_block_risk:
            reason_parts.append(f"≥ hard_block_risk({t.hard_block_risk:.2f})")
            action = DecisionAction.BLOCK

        elif effective_risk >= t.soft_block_risk:
            reason_parts.append(f"≥ soft_block_risk({t.soft_block_risk:.2f})")
            action = DecisionAction.ESCALATE_TO_HUMAN

        # 2) Operational SLO guards can override to DEGRADE / THROTTLE
        else:
            action = self._decide_under_slo(snapshot, effective_risk, reason_parts)

        reason = "; ".join(reason_parts)
        now = time.time()

        self._log.debug(
            "TCD decision",
            extra={
                "action": action.value,
                "reason": reason,
                "risk": risk,
                "effective_risk": effective_risk,
                "tenant_id": snapshot.tenant_id,
                "route": snapshot.route,
                "method": snapshot.method,
                "policy_version": self._policy_version,
            },
        )

        return DecisionResult(
            action=action,
            reason=reason,
            policy_version=self._policy_version,
            snapshot=snapshot,
            thresholds=t,
            created_at=now,
        )

    # ---- Internal helpers ---------------------------------------------- #

    def _decide_under_slo(
        self,
        snapshot: EnvironmentSnapshot,
        effective_risk: float,
        reason_parts: list[str],
    ) -> DecisionAction:
        """
        Decide between ALLOW / THROTTLE / DEGRADE / ASK_FOR_REVIEW
        in the regime where risk is below the hard/soft block thresholds.
        """
        t = self._thresholds
        latency = snapshot.p95_latency_ms
        err = snapshot.error_rate
        inflight = snapshot.in_flight_requests

        # Throttle / degrade on combined moderate risk + SLO pressure
        if effective_risk >= t.throttle_risk:
            reason_parts.append(f"≥ throttle_risk({t.throttle_risk:.2f})")

            # High latency or heavy load → THROTTLE
            if (latency is not None and latency >= t.p95_latency_ms_soft) or (
                inflight is not None and inflight >= t.in_flight_soft
            ):
                reason_parts.append(
                    f"SLO_pressure(latency={latency}, in_flight={inflight})"
                )
                return DecisionAction.THROTTLE

            # Moderate risk but no obvious load → ASK_FOR_REVIEW
            return DecisionAction.ASK_FOR_REVIEW

        # Lower risk but SLO extremely unhappy → DEGRADE
        if latency is not None and latency >= t.p95_latency_ms_hard:
            reason_parts.append(
                f"p95_latency_ms={latency} ≥ hard({t.p95_latency_ms_hard})"
            )
            return DecisionAction.DEGRADE

        if err is not None and err >= t.error_rate_hard:
            reason_parts.append(f"error_rate={err:.3f} ≥ hard({t.error_rate_hard})")
            return DecisionAction.DEGRADE

        # Mild SLO pressure → THROTTLE, even at lower risk
        if latency is not None and latency >= t.p95_latency_ms_soft:
            reason_parts.append(
                f"p95_latency_ms={latency} ≥ soft({t.p95_latency_ms_soft})"
            )
            return DecisionAction.THROTTLE

        if err is not None and err >= t.error_rate_soft:
            reason_parts.append(f"error_rate={err:.3f} ≥ soft({t.error_rate_soft})")
            return DecisionAction.THROTTLE

        if inflight is not None and inflight >= t.in_flight_hard:
            reason_parts.append(
                f"in_flight_requests={inflight} ≥ hard({t.in_flight_hard})"
            )
            return DecisionAction.DEGRADE

        if inflight is not None and inflight >= t.in_flight_soft:
            reason_parts.append(
                f"in_flight_requests={inflight} ≥ soft({t.in_flight_soft})"
            )
            return DecisionAction.THROTTLE

        # Risk not too high, SLO okay → ALLOW
        if effective_risk >= t.degrade_risk:
            # slightly cautious path: allow, but mark as reviewable
            reason_parts.append(f"≥ degrade_risk({t.degrade_risk:.2f}), allow")
            return DecisionAction.ALLOW

        reason_parts.append("within_normal_bounds")
        return DecisionAction.ALLOW


# Convenience factory for wiring from a generic config dict
def build_decision_engine_from_config(
    cfg: Mapping[str, Any],
    logger: Optional[logging.Logger] = None,
) -> DecisionEngine:
    """
    Helper to build a DecisionEngine from a flat config mapping, e.g.:

    cfg = {
        "policy_version": "v2",
        "hard_block_risk": 0.99,
        "p95_latency_ms_soft": 600,
        ...
    }
    """
    thresholds_kwargs: Dict[str, Any] = {}
    policy_version = cfg.get("policy_version", "v1")

    for field in DecisionThresholds.__dataclass_fields__.keys():
        if field in cfg:
            thresholds_kwargs[field] = cfg[field]

    thresholds = DecisionThresholds(**thresholds_kwargs)
    return DecisionEngine(
        thresholds=thresholds,
        policy_version=policy_version,
        logger=logger,
    )