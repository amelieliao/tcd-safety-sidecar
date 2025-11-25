# FILE: tcd/risk_av.py
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, MutableMapping, Optional
import math
import threading
import time

try:  # optional; used for hashing stream identifiers
    from .crypto import Blake3Hash
except Exception:  # pragma: no cover
    Blake3Hash = None  # type: ignore[assignment]


@dataclass
class AlwaysValidConfig:
    """
    Configuration for a lightweight e-process style risk controller.

    This module maintains per-stream evidence processes and returns structured
    state blocks that can be embedded into receipts or higher-level security
    decisions. It deliberately stays content-agnostic and does not enforce
    access control on its own.

    Fields
    ------
    enabled:
        Global on/off switch. When False, the controller returns a static
        non-triggered state and does not update any internal counters.

    alpha_base:
        Nominal level α used when a p-value is provided. Typical values are
        in (0, 0.5], such as 0.05 or 0.01.

    threshold_log_e:
        Threshold in log-space. When log_e >= threshold_log_e, the process
        is considered to have triggered.

    max_log_e / min_log_e:
        Bounds for clamping log_e to avoid numerical blow-up or underflow.

    alpha_wealth_init:
        Initial “budget” for alpha-wealth style accounting.

    alpha_spend_per_decision:
        Deterministic spending rate per decision. If > 0, alpha_wealth will
        decrease line by line, down to zero.

    block_on_trigger:
        If True, step() will set allowed=False whenever the process is
        triggered for a stream. If False, the trigger flag is advisory only.

    monotonic_fn:
        Optional monotonic time source, used for timestamps in snapshots.
        Defaults to time.monotonic if not provided.

    label:
        A coarse label for this controller instance (e.g. "inference",
        "admin", "supply_chain"). Propagated into e_state for receipts.

    policyset_ref:
        Optional reference to the policy set this controller is associated
        with. Useful for attestation and supply-chain style provenance.

    max_weight:
        Upper bound on the effective weight applied per step.

    min_p_value / max_p_value:
        Bounds for clamping p-values. Applied after parsing input and before
        computing e-process updates.

    freeze_on_exhaust:
        If True, once alpha_wealth reaches zero, the corresponding stream
        becomes frozen: subsequent calls still increment the decisions
        counter but do not change log_e or alpha_wealth.

    severity_weights:
        Mapping from severity labels to multiplicative weights. Used in
        step() when a severity is supplied.
    """

    enabled: bool = True
    alpha_base: float = 0.05
    threshold_log_e: float = 4.0
    max_log_e: float = 12.0
    min_log_e: float = -12.0
    alpha_wealth_init: float = 1.0
    alpha_spend_per_decision: float = 0.0
    block_on_trigger: bool = False

    monotonic_fn: Optional[Callable[[], float]] = None
    label: str = "default"
    policyset_ref: Optional[str] = None

    max_weight: float = 10.0
    min_p_value: float = 1e-12
    max_p_value: float = 1.0
    freeze_on_exhaust: bool = False

    severity_weights: Dict[str, float] = field(
        default_factory=lambda: {"low": 1.0, "medium": 2.0, "high": 3.0}
    )


@dataclass
class EProcessState:
    """
    Internal state of a single evidence process stream.

    Higher-level systems should treat this as an opaque state container and
    avoid depending on internal fields beyond those exposed through
    snapshot()/streams_overview().
    """

    log_e: float = 0.0
    alpha_wealth: float = 1.0
    decisions: int = 0
    triggers: int = 0
    last_trigger_step: Optional[int] = None
    frozen: bool = False


class AlwaysValidRiskController:
    """
    Anytime-valid (e-process style) risk signal controller.

    Responsibilities
    ----------------
    - Maintain per-stream evidence processes based on provided p-values or
      scores.
    - Provide a structured, fixed-schema e_state block suitable for:
        * embedding into receipts,
        * attaching to higher-level security router decisions,
        * use in external attestation / audit systems.
    - Stay content-agnostic and algorithm-neutral at the system level.

    Non-responsibilities
    --------------------
    - It does not inspect prompts, outputs, or secrets.
    - It does not perform anomaly detection by itself.
    - It does not directly enforce access control; it only emits signals
      and state to be interpreted elsewhere.
    """

    _CONTROLLER_NAME = "tcd.risk_av"
    _CONTROLLER_VERSION = "0.2.0"

    def __init__(
        self,
        config: Optional[AlwaysValidConfig] = None,
        **overrides: Any,
    ) -> None:
        cfg = config or AlwaysValidConfig()

        # Allow simple overrides via kwargs (e.g. alpha_base=0.01, label="admin").
        for key, value in overrides.items():
            if not hasattr(cfg, key):
                continue
            # Special-case severity_weights to accept dicts directly.
            if key == "severity_weights" and isinstance(value, dict):
                cfg.severity_weights = dict(value)
                continue
            try:
                current = getattr(cfg, key)
                setattr(cfg, key, type(current)(value))  # type: ignore[arg-type]
            except Exception:
                # Never fail construction on type coercion.
                continue

        self.config: AlwaysValidConfig = cfg
        self._mono: Callable[[], float] = self.config.monotonic_fn or time.monotonic

        self._lock = threading.RLock()
        # Internal mapping from hashed stream key -> EProcessState.
        self._streams: MutableMapping[str, EProcessState] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def step(
        self,
        request: Any = None,
        *,
        stream_id: Optional[str] = None,
        p_value: Optional[float] = None,
        score: Optional[float] = None,
        weight: float = 1.0,
        severity: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        **ctx: Any,
    ) -> Dict[str, Any]:
        """
        Advance the evidence process for a given stream and return a state block.

        Parameters
        ----------
        request:
            Optional opaque request object. Not inspected here; used only to
            set a boolean flag in the result.
        stream_id:
            Logical identifier for the evidence stream (e.g. "tenant:user:model").
            Used only for external correlation; internal storage uses a hashed key.
        p_value:
            Optional p-value in (0, 1]. If provided, it is clamped and used
            directly in the e-process update.
        score:
            Optional score where higher implies more suspicious behaviour. If
            p_value is None and score is provided, a simple heuristic mapping
            is used to obtain a pseudo p-value.
        weight:
            Base weight for this update. Combined with severity to form the
            effective weight.
        severity:
            Optional severity label, such as "low", "medium", "high". Mapped
            via config.severity_weights and combined with weight.
        meta:
            Free-form metadata for the caller (route, policy_ref, etc.). The
            controller does not interpret it.
        ctx:
            Additional keyword-only context. Forwarded into the result.

        Returns
        -------
        A dictionary with keys:

            allowed: bool
            reason: str
            stream_id: str
            e_state: dict (controller/stream/process blocks)
            p_value: float
            score: Optional[float]
            meta: dict
            ctx: dict
            has_request: bool
            security: dict (small summary for routing/attestation)
        """
        if meta is None:
            meta = {}

        sid = stream_id or "default"
        now = self._mono()
        key = self._canonical_stream_key(sid)

        # Disabled mode: no internal state updates; return a trivial snapshot.
        if not self.config.enabled:
            e_state = {
                "controller": {
                    "name": self._CONTROLLER_NAME,
                    "version": self._CONTROLLER_VERSION,
                    "label": self.config.label,
                    "policyset_ref": self.config.policyset_ref,
                    "ts_monotonic": now,
                },
                "stream": {
                    "id": sid,
                    "hash": key,
                },
                "process": {
                    "e_value": 1.0,
                    "alpha_base": float(self.config.alpha_base),
                    "alpha_wealth": float(self.config.alpha_wealth_init),
                    "alpha_wealth_init": float(self.config.alpha_wealth_init),
                    "alpha_spend_per_decision": float(
                        self.config.alpha_spend_per_decision
                    ),
                    "threshold": self._safe_exp(self.config.threshold_log_e),
                    "trigger": False,
                    "decisions": 0,
                    "triggers": 0,
                    "last_trigger_step": None,
                    "log_e": 0.0,
                    "frozen": False,
                },
            }
            return {
                "allowed": True,
                "reason": "disabled",
                "stream_id": sid,
                "e_state": e_state,
                "p_value": self._normalize_p_value(p_value, score),
                "score": score,
                "meta": meta,
                "ctx": ctx,
                "has_request": request is not None,
                "security": {
                    "av_label": self.config.label,
                    "policyset_ref": self.config.policyset_ref,
                    "trigger": False,
                    "trigger_reason": "disabled",
                    "stream_hash": key,
                },
            }

        with self._lock:
            state = self._streams.get(key)
            if state is None:
                state = EProcessState(
                    log_e=0.0,
                    alpha_wealth=self.config.alpha_wealth_init,
                )
                self._streams[key] = state

            # Compute effective weight from severity and base weight.
            eff_weight = self._effective_weight(weight, severity)

            # Derive p-like value.
            p = self._normalize_p_value(p_value, score)

            # Update state.
            self._update_state(state, p, eff_weight)

            # Evaluate trigger flag.
            trigger = (not state.frozen) and (
                state.log_e >= self.config.threshold_log_e
            )
            if trigger:
                state.triggers += 1
                state.last_trigger_step = state.decisions

            allowed = True
            if trigger and self.config.block_on_trigger:
                allowed = False
                reason = "e-process-trigger"
            elif trigger:
                reason = "e-process-trigger-advisory"
            else:
                reason = "always-valid"

            e_val = self._safe_exp(state.log_e)
            threshold_val = self._safe_exp(self.config.threshold_log_e)

            e_state = {
                "controller": {
                    "name": self._CONTROLLER_NAME,
                    "version": self._CONTROLLER_VERSION,
                    "label": self.config.label,
                    "policyset_ref": self.config.policyset_ref,
                    "ts_monotonic": now,
                },
                "stream": {
                    "id": sid,
                    "hash": key,
                },
                "process": {
                    "e_value": e_val,
                    "alpha_base": float(self.config.alpha_base),
                    "alpha_wealth": float(state.alpha_wealth),
                    "alpha_wealth_init": float(self.config.alpha_wealth_init),
                    "alpha_spend_per_decision": float(
                        self.config.alpha_spend_per_decision
                    ),
                    "threshold": threshold_val,
                    "trigger": bool(trigger),
                    "decisions": int(state.decisions),
                    "triggers": int(state.triggers),
                    "last_trigger_step": state.last_trigger_step,
                    "log_e": float(state.log_e),
                    "frozen": bool(state.frozen),
                },
            }

        return {
            "allowed": allowed,
            "reason": reason,
            "stream_id": sid,
            "e_state": e_state,
            "p_value": p,
            "score": score,
            "meta": meta,
            "ctx": ctx,
            "has_request": request is not None,
            "security": {
                "av_label": self.config.label,
                "policyset_ref": self.config.policyset_ref,
                "trigger": bool(trigger),
                "trigger_reason": reason,
                "stream_hash": key,
            },
        }

    # ------------------------------------------------------------------
    # Introspection helpers (for SRE / audits)
    # ------------------------------------------------------------------

    def snapshot(self, stream_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Return a snapshot of the state for a given stream.

        If the stream has never been seen, returns a non-triggered default
        snapshot with e_value=1.0 and alpha_wealth=alpha_wealth_init.
        """
        sid = stream_id or "default"
        key = self._canonical_stream_key(sid)
        now = self._mono()
        with self._lock:
            state = self._streams.get(key)

            if state is None:
                e_val = 1.0
                alpha_wealth = self.config.alpha_wealth_init
                decisions = 0
                triggers = 0
                last_trigger_step = None
                log_e = 0.0
                frozen = False
            else:
                e_val = self._safe_exp(state.log_e)
                alpha_wealth = state.alpha_wealth
                decisions = state.decisions
                triggers = state.triggers
                last_trigger_step = state.last_trigger_step
                log_e = state.log_e
                frozen = state.frozen

            trigger = (log_e >= self.config.threshold_log_e) and (not frozen)

            return {
                "controller": {
                    "name": self._CONTROLLER_NAME,
                    "version": self._CONTROLLER_VERSION,
                    "label": self.config.label,
                    "policyset_ref": self.config.policyset_ref,
                    "ts_monotonic": now,
                },
                "stream": {
                    "id": sid,
                    "hash": key,
                },
                "process": {
                    "e_value": e_val,
                    "alpha_base": float(self.config.alpha_base),
                    "alpha_wealth": float(alpha_wealth),
                    "alpha_wealth_init": float(self.config.alpha_wealth_init),
                    "alpha_spend_per_decision": float(
                        self.config.alpha_spend_per_decision
                    ),
                    "threshold": self._safe_exp(self.config.threshold_log_e),
                    "trigger": bool(trigger),
                    "decisions": int(decisions),
                    "triggers": int(triggers),
                    "last_trigger_step": last_trigger_step,
                    "log_e": float(log_e),
                    "frozen": bool(frozen),
                },
            }

    def all_stream_ids(self) -> Dict[str, int]:
        """
        Return a mapping from internal stream hash -> decisions count.

        The keys are hashed identifiers produced by _canonical_stream_key.
        Callers that need to correlate these hashes with logical stream ids
        should recompute the same hash function externally.
        """
        with self._lock:
            return {stream_hash: st.decisions for stream_hash, st in self._streams.items()}

    def streams_overview(self) -> Dict[str, Any]:
        """
        Return a coarse overview of all known streams for monitoring purposes.

        The overview contains per-stream statistics and a small copy of the
        current controller configuration parameters relevant for interpretation.
        """
        now = self._mono()
        with self._lock:
            streams = []
            for stream_hash, st in self._streams.items():
                streams.append(
                    {
                        "stream_hash": stream_hash,
                        "decisions": int(st.decisions),
                        "triggers": int(st.triggers),
                        "last_trigger_step": st.last_trigger_step,
                        "log_e": float(st.log_e),
                        "frozen": bool(st.frozen),
                    }
                )
            return {
                "controller": {
                    "name": self._CONTROLLER_NAME,
                    "version": self._CONTROLLER_VERSION,
                    "label": self.config.label,
                    "policyset_ref": self.config.policyset_ref,
                    "ts_monotonic": now,
                    "alpha_base": float(self.config.alpha_base),
                    "threshold_log_e": float(self.config.threshold_log_e),
                    "alpha_wealth_init": float(self.config.alpha_wealth_init),
                },
                "streams": streams,
            }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _canonical_stream_key(self, stream_id: str) -> str:
        """
        Map a logical stream identifier to an internal key.

        If a hash primitive is available, a fixed-length hash is used;
        otherwise, the raw identifier is returned.
        """
        if Blake3Hash is None:
            return stream_id
        try:
            hasher = Blake3Hash()
            raw = stream_id.encode("utf-8", errors="ignore")
            return hasher.hex(raw, ctx="tcd:eprocess:stream")[:32]
        except Exception:
            return stream_id

    def _effective_weight(self, base_weight: float, severity: Optional[str]) -> float:
        """
        Combine base weight and severity label into an effective weight,
        clamped into [0, max_weight].
        """
        try:
            w = float(base_weight)
        except Exception:
            w = 1.0

        if severity:
            sev = str(severity).lower().strip()
            w *= float(self.config.severity_weights.get(sev, 1.0))

        if not math.isfinite(w):
            w = 1.0

        w = max(0.0, min(self.config.max_weight, w))
        return w

    @staticmethod
    def _safe_exp(x: float) -> float:
        """
        Exponential with basic overflow protection.
        """
        try:
            if x > 700.0:
                return float("inf")
            if x < -700.0:
                return 0.0
            return math.exp(x)
        except Exception:
            return float("nan")

    def _normalize_p_value(
        self,
        p_value: Optional[float],
        score: Optional[float],
    ) -> float:
        """
        Map supplied p_value / score into a p-like value in (0, 1].

        If p_value is provided, it is clamped into [min_p_value, max_p_value].
        If p_value is None and score is provided with higher=more suspicious,
        a simple heuristic p ≈ 1 - score is used and then clamped.

        If neither is provided, a neutral value of 1.0 is returned.
        """
        min_p = float(self.config.min_p_value)
        max_p = float(self.config.max_p_value)

        if min_p <= 0.0 or max_p <= 0.0:
            min_p = 1e-12
            max_p = 1.0

        if max_p < min_p:
            max_p = min_p

        if p_value is not None:
            try:
                p = float(p_value)
            except Exception:
                p = 1.0
            if not math.isfinite(p):
                p = 1.0
            return min(max_p, max(min_p, p))

        if score is None:
            # No signal: treat as completely benign.
            return 1.0

        try:
            s = float(score)
        except Exception:
            return 1.0

        if not math.isfinite(s):
            return 1.0

        # Higher score → smaller p.
        p = 1.0 - s
        return min(max_p, max(min_p, p))

    def _update_state(
        self,
        state: EProcessState,
        p: float,
        weight: float,
    ) -> None:
        """
        Update the evidence process and alpha-wealth for a single step.

        A simple α/p update template is used:
            log_e_{t+1} = log_e_t + w * log(α / p)  when p <= α
            log_e_{t+1} = log_e_t                   otherwise

        The value is then clamped into [min_log_e, max_log_e]. If
        freeze_on_exhaust is enabled and alpha_wealth reaches zero, the
        stream is marked as frozen and no further updates are applied.
        """
        state.decisions += 1

        # If the stream is frozen, only count decisions; do not alter e or wealth.
        if self.config.freeze_on_exhaust and state.frozen:
            return

        # Spend alpha-wealth deterministically if configured.
        spend = float(self.config.alpha_spend_per_decision)
        if spend > 0.0:
            state.alpha_wealth = max(0.0, state.alpha_wealth - spend)

        # If alpha_wealth is exhausted and freeze_on_exhaust is set, freeze stream.
        if self.config.freeze_on_exhaust and state.alpha_wealth <= 0.0:
            state.alpha_wealth = 0.0
            state.frozen = True
            return

        alpha = float(self.config.alpha_base)
        if alpha <= 0.0:
            # Degenerate configuration: do not update e-process.
            return

        p_clamped = min(self.config.max_p_value, max(self.config.min_p_value, float(p)))
        if not math.isfinite(p_clamped):
            p_clamped = 1.0

        log_e = state.log_e

        # Only update when the observation is at or below α.
        if p_clamped <= alpha:
            try:
                increment = float(weight) * math.log(alpha / p_clamped)
            except Exception:
                increment = 0.0
            log_e += increment

        # Clamp to safety bounds.
        log_e = min(self.config.max_log_e, max(self.config.min_log_e, log_e))
        state.log_e = log_e


__all__ = ["AlwaysValidConfig", "EProcessState", "AlwaysValidRiskController"]