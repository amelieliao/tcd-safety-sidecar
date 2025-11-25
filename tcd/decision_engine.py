# FILE: tcd/decision_engine.py
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Dict, Mapping, Optional, List, Set

from .kv import canonical_kv_hash  # type: ignore


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
    throttle_risk: float = 0.80            # above this → THROTTLE / REVIEW
    degrade_risk: float = 0.65             # above this → ALLOW but marked for review

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

    # Additional opaque features (country, model_id, user_tier, override flags, PQ info, etc.)
    extra: Dict[str, Any] = None

    # Wall-clock timestamp in seconds since epoch (for receipts/logs)
    ts: float = None

    def __post_init__(self) -> None:
        if self.extra is None:
            self.extra = {}
        if self.ts is None:
            self.ts = time.time()
        # Normalize basic string fields defensively.
        self.tenant_id = str(self.tenant_id)[:128]
        self.route = str(self.route)[:128]
        self.method = str(self.method).upper()[:32]
        # Ensure risk_score is numeric; clamping happens at decision time.
        try:
            self.risk_score = float(self.risk_score)
        except Exception:
            self.risk_score = 0.0


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
    # Configuration hash of the DecisionEngine that produced this decision.
    config_hash: str

    def to_dict(self) -> Dict[str, Any]:
        """
        Lossless, JSON-serializable representation suitable for receipts,
        logs, or trust_graph ingestion.

        Snapshot and thresholds are passed through light sanitizers to:
          - Clamp risk and error ratios to [0,1].
          - Remove obviously forbidden keys from `extra` (prompt/completion/etc.).
          - Bound the size of `extra` and truncate long strings.
        """
        snap_dict = _snapshot_to_dict(self.snapshot)
        thresholds_dict = _thresholds_to_dict(self.thresholds)

        base: Dict[str, Any] = {
            "action": self.action.value,
            "reason": self.reason,
            "policy_version": self.policy_version,
            "created_at": self.created_at,
            "snapshot": snap_dict,
            "thresholds": thresholds_dict,
            "config_hash": self.config_hash,
        }

        # Stable, content-agnostic decision identifier for replay and audit.
        decision_id = canonical_kv_hash(
            {
                "action": base["action"],
                "policy_version": base["policy_version"],
                "tenant_id": snap_dict["tenant_id"],
                "route": snap_dict["route"],
                "method": snap_dict["method"],
                "ts": base["created_at"],
                "config_hash": base["config_hash"],
            },
            ctx="tcd:decision",
            label="decision_id",
        )
        base["decision_id"] = decision_id
        return base


# ---------------------------------------------------------------------------
# Internal sanitization / normalization helpers
# ---------------------------------------------------------------------------

_FORBIDDEN_EXTRA_KEYS: Set[str] = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "messages",
    "content",
    "body",
    "raw",
    "request_body",
    "response_body",
    "headers",
    "cookies",
}

_MAX_EXTRA_KEYS: int = 32
_MAX_EXTRA_STRING: int = 256

_ALLOWED_METHODS: Set[str] = {
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS",
    "RPC",
    "BATCH",
}

# Minimum spacing between risk thresholds to preserve a non-degenerate ladder.
_MIN_RISK_BAND: float = 0.05


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _normalize_thresholds(t: DecisionThresholds, logger: Optional[logging.Logger] = None) -> DecisionThresholds:
    """
    Clamp and normalize thresholds to a sane, auditable configuration.

    Rules:
      - Risk thresholds are clamped to [0,1].
      - They are ordered as: degrade ≤ throttle ≤ soft_block ≤ hard_block.
      - Adjacent risk thresholds are separated by at least _MIN_RISK_BAND.
      - Error-rate thresholds are clamped to [0,1].
      - Latency and concurrency thresholds are non-negative integers.
      - Anomaly bump is clamped to [0,1].
    """
    log = logger or logging.getLogger(__name__)
    clone = DecisionThresholds(**asdict(t))

    # Clamp risk thresholds
    clone.hard_block_risk = _clamp01(float(clone.hard_block_risk))
    clone.soft_block_risk = _clamp01(float(clone.soft_block_risk))
    clone.throttle_risk = _clamp01(float(clone.throttle_risk))
    clone.degrade_risk = _clamp01(float(clone.degrade_risk))

    chain = [
        ("degrade_risk", clone.degrade_risk),
        ("throttle_risk", clone.throttle_risk),
        ("soft_block_risk", clone.soft_block_risk),
        ("hard_block_risk", clone.hard_block_risk),
    ]
    values = [v for _, v in chain]
    if not (values[0] <= values[1] <= values[2] <= values[3]):
        log.warning(
            "Decision risk thresholds out of order; normalizing to ascending chain "
            "(degrade ≤ throttle ≤ soft_block ≤ hard_block), previous=%s",
            values,
        )
        values = sorted(values)

    # Enforce minimum spacing between successive risk thresholds.
    adj: List[float] = list(values)
    for i in range(3):
        if adj[i + 1] - adj[i] < _MIN_RISK_BAND:
            adj[i + 1] = min(1.0, adj[i] + _MIN_RISK_BAND)
    clone.degrade_risk, clone.throttle_risk, clone.soft_block_risk, clone.hard_block_risk = adj

    # Clamp error-rate thresholds to [0,1].
    clone.error_rate_soft = _clamp01(float(clone.error_rate_soft))
    clone.error_rate_hard = _clamp01(float(clone.error_rate_hard))

    # Ensure latency and concurrency thresholds are non-negative integers.
    clone.p95_latency_ms_soft = max(0, int(clone.p95_latency_ms_soft))
    clone.p95_latency_ms_hard = max(0, int(clone.p95_latency_ms_hard))
    clone.in_flight_soft = max(0, int(clone.in_flight_soft))
    clone.in_flight_hard = max(0, int(clone.in_flight_hard))

    # Clamp anomaly bump to [0,1].
    clone.anomaly_risk_bump = _clamp01(float(clone.anomaly_risk_bump))

    return clone


def _sanitize_extra(extra: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Sanitize the `extra` dict attached to an EnvironmentSnapshot:

      - Remove forbidden keys (prompt/completion/etc.).
      - Cap the total number of keys.
      - Truncate long string values.
      - Coerce complex types via repr() and truncate.
      - Normalize keys to strings for downstream JSON serialization.
    """
    if not extra:
        return {}

    items = sorted(extra.items(), key=lambda kv: str(kv[0]))
    out: Dict[str, Any] = {}
    count = 0
    for k, v in items:
        if count >= _MAX_EXTRA_KEYS:
            break
        ks = str(k)
        if ks.lower() in _FORBIDDEN_EXTRA_KEYS:
            continue

        if isinstance(v, str):
            if len(v) > _MAX_EXTRA_STRING:
                v = v[:_MAX_EXTRA_STRING]
        elif isinstance(v, (int, float, bool)) or v is None:
            # keep as-is
            pass
        else:
            # Collapse complex structures to a short, bounded representation.
            v_repr = repr(v)
            if len(v_repr) > _MAX_EXTRA_STRING:
                v_repr = v_repr[:_MAX_EXTRA_STRING]
            v = v_repr

        out[ks] = v
        count += 1
    return out


def _snapshot_to_dict(snap: EnvironmentSnapshot) -> Dict[str, Any]:
    """
    Convert an EnvironmentSnapshot into a receipt-ready dict while enforcing:

      - risk_score ∈ [0,1]
      - error_rate ∈ [0,1]
      - non-negative latencies and in-flight counts
      - sanitized `extra` payload
      - bounded method/route shapes
    """
    try:
        risk = _clamp01(float(snap.risk_score))
    except Exception:
        risk = 0.0

    err: Optional[float]
    if snap.error_rate is not None:
        try:
            err = _clamp01(float(snap.error_rate))
        except Exception:
            err = None
    else:
        err = None

    latency: Optional[int]
    if snap.p95_latency_ms is not None:
        try:
            latency = max(0, int(snap.p95_latency_ms))
        except Exception:
            latency = None
    else:
        latency = None

    inflight: Optional[int]
    if snap.in_flight_requests is not None:
        try:
            inflight = max(0, int(snap.in_flight_requests))
        except Exception:
            inflight = None
    else:
        inflight = None

    route = str(snap.route)[:128]
    method_norm = str(snap.method).upper()[:32]
    if method_norm in _ALLOWED_METHODS:
        method = method_norm
    else:
        method = method_norm

    tenant_id = str(snap.tenant_id)[:128]
    extra = _sanitize_extra(snap.extra or {})

    return {
        "risk_score": risk,
        "tenant_id": tenant_id,
        "route": route,
        "method": method,
        "p95_latency_ms": latency,
        "error_rate": err,
        "in_flight_requests": inflight,
        "is_anomalous": bool(snap.is_anomalous),
        "extra": extra,
        "ts": float(snap.ts),
    }


def _thresholds_to_dict(t: DecisionThresholds) -> Dict[str, Any]:
    """
    Convert thresholds into a dict suitable for inclusion in receipts.

    Risk and error thresholds are normalized at engine initialization, but they
    are passed through a clamp again here for robustness.
    """
    return {
        "hard_block_risk": _clamp01(float(t.hard_block_risk)),
        "soft_block_risk": _clamp01(float(t.soft_block_risk)),
        "throttle_risk": _clamp01(float(t.throttle_risk)),
        "degrade_risk": _clamp01(float(t.degrade_risk)),
        "p95_latency_ms_soft": max(0, int(t.p95_latency_ms_soft)),
        "p95_latency_ms_hard": max(0, int(t.p95_latency_ms_hard)),
        "error_rate_soft": _clamp01(float(t.error_rate_soft)),
        "error_rate_hard": _clamp01(float(t.error_rate_hard)),
        "in_flight_soft": max(0, int(t.in_flight_soft)),
        "in_flight_hard": max(0, int(t.in_flight_hard)),
        "anomaly_risk_bump": _clamp01(float(t.anomaly_risk_bump)),
    }


def _bounded_int(field: str, value: Any, default: int, min_v: int, max_v: int) -> int:
    """
    Clamp an integer configuration value into a bounded range.

    This is used for latency and concurrency thresholds so that misconfigured
    or adversarial configs cannot explode the decision surface.
    """
    try:
        v = int(value)
    except Exception:
        return default
    if v < min_v:
        return min_v
    if v > max_v:
        return max_v
    return v


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
        self._log = logger or logging.getLogger(__name__)
        raw_thresholds = thresholds or DecisionThresholds()
        self._thresholds = _normalize_thresholds(raw_thresholds, logger=self._log)
        self._policy_version = policy_version

        cfg_payload: Dict[str, Any] = {
            "policy_version": self._policy_version,
            "hard_block_risk": self._thresholds.hard_block_risk,
            "soft_block_risk": self._thresholds.soft_block_risk,
            "throttle_risk": self._thresholds.throttle_risk,
            "degrade_risk": self._thresholds.degrade_risk,
            "p95_latency_ms_soft": self._thresholds.p95_latency_ms_soft,
            "p95_latency_ms_hard": self._thresholds.p95_latency_ms_hard,
            "error_rate_soft": self._thresholds.error_rate_soft,
            "error_rate_hard": self._thresholds.error_rate_hard,
            "in_flight_soft": self._thresholds.in_flight_soft,
            "in_flight_hard": self._thresholds.in_flight_hard,
            "anomaly_risk_bump": self._thresholds.anomaly_risk_bump,
        }
        cfg_hash = canonical_kv_hash(
            cfg_payload,
            ctx="tcd:decision",
            label="decision_cfg",
        )
        self._config_hash = cfg_hash

        self._log.info(
            "DecisionEngine initialized: policy_version=%s, cfg_hash=%s",
            self._policy_version,
            self._config_hash,
        )

    @property
    def thresholds(self) -> DecisionThresholds:
        return self._thresholds

    @property
    def policy_version(self) -> str:
        return self._policy_version

    @property
    def config_hash(self) -> str:
        """
        Stable configuration hash for this decision engine instance.

        This can be embedded in receipts or logs to tie a decision back to
        the exact threshold configuration used.
        """
        return self._config_hash

    # ---- Public API ----------------------------------------------------- #

    def decide(self, snapshot: EnvironmentSnapshot) -> DecisionResult:
        """
        Compute the next action for the given snapshot.

        This method is deterministic given (thresholds, snapshot). All random
        or probabilistic behavior should be handled upstream and represented
        as features inside `snapshot.extra`.
        """
        # Risk normalization
        try:
            risk = _clamp01(float(snapshot.risk_score))
        except Exception:
            risk = 0.0
        t = self._thresholds

        # Optional "risk bump" if another detector marked this as anomalous
        effective_risk = risk + (t.anomaly_risk_bump if snapshot.is_anomalous else 0.0)
        effective_risk = _clamp01(effective_risk)

        reason_parts: List[str] = [f"risk={risk:.3f}", f"effective_risk={effective_risk:.3f}"]

        # 1) Hard risk cutoffs: ESCALATE / BLOCK
        if effective_risk >= t.hard_block_risk:
            reason_parts.append(f"≥ hard_block_risk({t.hard_block_risk:.2f})")
            action = DecisionAction.BLOCK

        elif effective_risk >= t.soft_block_risk:
            reason_parts.append(f"≥ soft_block_risk({t.soft_block_risk:.2f})")
            action = DecisionAction.ESCALATE_TO_HUMAN

        # 2) Operational SLO guards can override to DEGRADE / THROTTLE / REVIEW
        else:
            action = self._decide_under_slo(snapshot, effective_risk, reason_parts)

        reason = "; ".join(reason_parts)
        now = time.time()

        # Use the sanitized snapshot view for logging so logs never carry raw
        # extra payloads or unbounded values.
        snap_view = _snapshot_to_dict(snapshot)

        self._log.debug(
            "TCD decision",
            extra={
                "action": action.value,
                "reason": reason,
                "risk": snap_view["risk_score"],
                "tenant_id": snap_view["tenant_id"],
                "route": snap_view["route"],
                "method": snap_view["method"],
                "policy_version": self._policy_version,
                "config_hash": self._config_hash,
            },
        )

        return DecisionResult(
            action=action,
            reason=reason,
            policy_version=self._policy_version,
            snapshot=snapshot,
            thresholds=t,
            created_at=now,
            config_hash=self._config_hash,
        )

    # ---- Internal helpers ---------------------------------------------- #

    def _decide_under_slo(
        self,
        snapshot: EnvironmentSnapshot,
        effective_risk: float,
        reason_parts: List[str],
    ) -> DecisionAction:
        """
        Decide between ALLOW / THROTTLE / DEGRADE / ASK_FOR_REVIEW
        in the regime where risk is below the hard/soft block thresholds.
        """
        t = self._thresholds
        latency = snapshot.p95_latency_ms
        err = snapshot.error_rate
        inflight = snapshot.in_flight_requests

        # Throttle / review on combined moderate risk + SLO pressure.
        if effective_risk >= t.throttle_risk:
            reason_parts.append(f"≥ throttle_risk({t.throttle_risk:.2f})")

            slo_pressure = False
            if latency is not None and latency >= t.p95_latency_ms_soft:
                slo_pressure = True
            if inflight is not None and inflight >= t.in_flight_soft:
                slo_pressure = True
            if err is not None and err >= t.error_rate_soft:
                slo_pressure = True

            if slo_pressure:
                reason_parts.append(
                    f"SLO_pressure(latency={latency}, in_flight={inflight}, error_rate={err})"
                )
                return DecisionAction.THROTTLE

            # Moderate risk but no obvious SLO pressure: route to review lane.
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

        if inflight is not None and inflight >= t.in_flight_hard:
            reason_parts.append(
                f"in_flight_requests={inflight} ≥ hard({t.in_flight_hard})"
            )
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

        if inflight is not None and inflight >= t.in_flight_soft:
            reason_parts.append(
                f"in_flight_requests={inflight} ≥ soft({t.in_flight_soft})"
            )
            return DecisionAction.THROTTLE

        # Risk not too high, SLO okay → ALLOW
        if effective_risk >= t.degrade_risk:
            # Slightly cautious path: allow, but mark as reviewable.
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

    The config is normalized to ensure:
      - Risk thresholds are clamped to [0,1] and ordered with minimum spacing.
      - Error-rate thresholds are clamped to [0,1].
      - Latency and concurrency thresholds are non-negative integers within
        bounded ranges.
    """
    thresholds_kwargs: Dict[str, Any] = {}
    policy_version = cfg.get("policy_version", "v1")
    defaults = DecisionThresholds()

    for field_name in DecisionThresholds.__dataclass_fields__.keys():
        if field_name not in cfg:
            continue
        v = cfg[field_name]

        # Apply hard limits for latency and concurrency to defend against
        # misconfiguration or hostile config injections.
        if field_name in ("p95_latency_ms_soft", "p95_latency_ms_hard"):
            default_v = getattr(defaults, field_name)
            v = _bounded_int(field_name, v, default_v, min_v=50, max_v=60_000)
        elif field_name in ("in_flight_soft", "in_flight_hard"):
            default_v = getattr(defaults, field_name)
            v = _bounded_int(field_name, v, default_v, min_v=1, max_v=1_000_000)

        thresholds_kwargs[field_name] = v

    raw_thresholds = DecisionThresholds(**thresholds_kwargs)
    engine = DecisionEngine(
        thresholds=raw_thresholds,
        policy_version=policy_version,
        logger=logger,
    )
    return engine