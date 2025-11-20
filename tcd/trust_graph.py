# tcd/trust_graph.py
from __future__ import annotations

import hashlib
import json
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

try:
    from .agent import ActionResult, ExecutionMode  # optional, for richer linking
except Exception:  # pragma: no cover
    ActionResult = Any  # type: ignore
    ExecutionMode = Any  # type: ignore


class EvidenceType(str, Enum):
    """
    Types of evidence that can contribute to the trust graph.
    """

    RECEIPT = "receipt"
    DECISION = "decision"
    ACTION = "action"
    VERIFICATION = "verification"
    ANOMALY = "anomaly"


@dataclass
class SubjectKey:
    """
    Canonical key for a subject entity in the trust graph.

    A subject can represent a tenant, user, session, or any combination
    that you consider a "principal" whose trustworthiness you want to track.
    """

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

    def to_labels(self) -> Dict[str, str]:
        return {
            "tenant": self.tenant or "",
            "user": self.user or "",
            "session": self.session or "",
            "model_id": self.model_id or "",
        }


@dataclass
class Evidence:
    """
    A single piece of evidence attached to a subject.

    Each evidence item carries a normalized contribution 'weight', where
    positive values push trust upward and negative values push it downward.
    The exact mapping from raw scores to weight is left to the caller.
    """

    evidence_id: str
    subject_id: str
    type: EvidenceType
    timestamp: float
    weight: float
    payload: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "subject_id": self.subject_id,
            "type": self.type.value,
            "timestamp": self.timestamp,
            "weight": self.weight,
            "payload": self.payload,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


@dataclass
class TrustState:
    """
    Aggregated trust state for a subject.

    trust_score is always clamped to [0, 1], where 0.5 represents neutral.
    Above 0.5 indicates increasing evidence of good behavior; below 0.5
    indicates increasing evidence of risk or unreliability.
    """

    subject_id: str
    trust_score: float = 0.5
    observations: int = 0
    last_update_ts: float = field(default_factory=lambda: time.time())
    last_evidence_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "trust_score": self.trust_score,
            "observations": self.observations,
            "last_update_ts": self.last_update_ts,
            "last_evidence_id": self.last_evidence_id,
        }


@dataclass
class TrustGraphConfig:
    """
    Configuration for the TrustGraph update dynamics.
    """

    decay_half_life_sec: float = 3600.0
    trust_update_step: float = 0.08
    max_evidence_per_subject: int = 1024
    max_total_evidence: int = 100_000

    positive_cap: float = 2.0
    negative_cap: float = 2.0

    neutral_trust: float = 0.5


class TrustGraph:
    """
    TrustGraph maintains a compact evidence graph for TCD decisions.

    It does not store raw content; instead, it only keeps normalized,
    hashed references and structured metadata. The main goal is to
    derive a stable trust signal for each subject from a stream of
    receipts, decisions, and actions.
    """

    def __init__(self, config: Optional[TrustGraphConfig] = None) -> None:
        self.config = config or TrustGraphConfig()
        self._states: Dict[str, TrustState] = {}
        self._evidence_by_subject: Dict[str, List[Evidence]] = {}
        self._evidence_total: List[Evidence] = []

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def get_state(self, subject: SubjectKey) -> TrustState:
        sid = subject.as_id()
        if sid not in self._states:
            self._states[sid] = TrustState(subject_id=sid, trust_score=self.config.neutral_trust)
        return self._states[sid]

    def get_state_by_id(self, subject_id: str) -> TrustState:
        if subject_id not in self._states:
            self._states[subject_id] = TrustState(subject_id=subject_id, trust_score=self.config.neutral_trust)
        return self._states[subject_id]

    def list_subjects(self) -> List[str]:
        return list(self._states.keys())

    def get_recent_evidence(
        self,
        subject: SubjectKey,
        limit: int = 32,
    ) -> List[Evidence]:
        sid = subject.as_id()
        ev_list = self._evidence_by_subject.get(sid, [])
        if not ev_list:
            return []
        return ev_list[-limit:]

    # ------------------------------------------------------------------
    # Evidence ingestion
    # ------------------------------------------------------------------

    def add_receipt_evidence(
        self,
        subject: SubjectKey,
        *,
        score: float,
        verdict: bool,
        e_value: Optional[float] = None,
        receipt_head_hex: Optional[str] = None,
        trust_hint: Optional[float] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> TrustState:
        """
        Add evidence from a single TCD risk decision + receipt.

        score: risk score in [0, 1].
        verdict: True if failure / unsafe, False if safe.
        trust_hint: optional external trust signal; values in [0, 1].
        """
        payload = {
            "score": float(score),
            "verdict": bool(verdict),
            "e_value": float(e_value) if e_value is not None else None,
            "receipt_head": receipt_head_hex,
        }
        if extra:
            payload.update(extra)

        weight = self._weight_from_risk(score=score, verdict=verdict, trust_hint=trust_hint)
        ev = self._make_evidence(
            subject=subject,
            type_=EvidenceType.RECEIPT,
            weight=weight,
            payload=payload,
        )
        return self._apply_evidence(ev)

    def add_decision_evidence(
        self,
        subject: SubjectKey,
        *,
        decision: str,
        score: float,
        trust_hint: Optional[float] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> TrustState:
        """
        Add evidence from a routing / decision engine outcome.

        decision: e.g. "allow", "block", "degrade", "throttle".
        score: risk score in [0, 1].
        """
        payload: Dict[str, Any] = {"decision": decision, "score": float(score)}
        if extra:
            payload.update(extra)

        negative = decision in ("block", "throttle", "escalate_to_human")
        weight = self._weight_from_risk(score=score, verdict=negative, trust_hint=trust_hint)

        ev = self._make_evidence(
            subject=subject,
            type_=EvidenceType.DECISION,
            weight=weight,
            payload=payload,
        )
        return self._apply_evidence(ev)

    def add_action_evidence(
        self,
        subject: SubjectKey,
        *,
        action_result: ActionResult,
    ) -> TrustState:
        """
        Add evidence from an agent action.

        The mapping is intentionally conservative:
        - Successful degrade/rollback/reload tends to increase trust.
        - Frequent restarts or failures may reduce trust.
        """
        payload = {
            "action": action_result.action,
            "mode": getattr(action_result.mode, "value", str(action_result.mode)),
            "ok": bool(action_result.ok),
            "duration_ms": float(action_result.duration_ms()),
            "error": action_result.error,
        }

        weight = self._weight_from_action(action_result)
        ev = self._make_evidence(
            subject=subject,
            type_=EvidenceType.ACTION,
            weight=weight,
            payload=payload,
        )
        return self._apply_evidence(ev)

    def add_verification_evidence(
        self,
        subject: SubjectKey,
        *,
        ok: bool,
        head_hex: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> TrustState:
        """
        Add evidence from a receipt / chain verification result.
        """
        payload: Dict[str, Any] = {"ok": bool(ok), "head": head_hex}
        if extra:
            payload.update(extra)

        weight = self._weight_from_verification(ok=ok)
        ev = self._make_evidence(
            subject=subject,
            type_=EvidenceType.VERIFICATION,
            weight=weight,
            payload=payload,
        )
        return self._apply_evidence(ev)

    def add_anomaly_evidence(
        self,
        subject: SubjectKey,
        *,
        severity: float,
        label: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> TrustState:
        """
        Add evidence for an anomaly detected by external systems.

        severity is in [0, 1]; higher means stronger negative signal.
        """
        severity = max(0.0, min(1.0, float(severity)))
        payload: Dict[str, Any] = {"severity": severity, "label": label}
        if extra:
            payload.update(extra)

        weight = -severity * self.config.negative_cap
        ev = self._make_evidence(
            subject=subject,
            type_=EvidenceType.ANOMALY,
            weight=weight,
            payload=payload,
        )
        return self._apply_evidence(ev)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_evidence(
        self,
        subject: SubjectKey,
        type_: EvidenceType,
        weight: float,
        payload: Dict[str, Any],
    ) -> Evidence:
        sid = subject.as_id()
        ts = time.time()
        ev_id = self._hash_evidence_id(sid, type_, ts, payload)
        return Evidence(
            evidence_id=ev_id,
            subject_id=sid,
            type=type_,
            timestamp=ts,
            weight=float(weight),
            payload=payload,
        )

    @staticmethod
    def _hash_evidence_id(
        subject_id: str,
        type_: EvidenceType,
        ts: float,
        payload: Dict[str, Any],
    ) -> str:
        h = hashlib.blake2s(digest_size=16)
        h.update(subject_id.encode("utf-8", errors="ignore"))
        h.update(type_.value.encode("utf-8", errors="ignore"))
        h.update(f"{ts:.6f}".encode("ascii", errors="ignore"))
        try:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        except Exception:
            encoded = b"{}"
        h.update(encoded)
        return h.hexdigest()

    def _apply_evidence(self, evidence: Evidence) -> TrustState:
        state = self.get_state_by_id(evidence.subject_id)
        state = self._decay_state(state, evidence.timestamp)

        bounded_weight = max(
            -self.config.negative_cap,
            min(self.config.positive_cap, evidence.weight),
        )
        step = self.config.trust_update_step
        state.trust_score = self._clamp01(
            state.trust_score + step * bounded_weight
        )
        state.observations += 1
        state.last_update_ts = evidence.timestamp
        state.last_evidence_id = evidence.evidence_id

        self._append_evidence(evidence)
        return state

    def _append_evidence(self, evidence: Evidence) -> None:
        sid = evidence.subject_id
        per_subject = self._evidence_by_subject.setdefault(sid, [])
        per_subject.append(evidence)
        if len(per_subject) > self.config.max_evidence_per_subject:
            excess = len(per_subject) - self.config.max_evidence_per_subject
            if excess > 0:
                del per_subject[0:excess]

        self._evidence_total.append(evidence)
        if len(self._evidence_total) > self.config.max_total_evidence:
            excess = len(self._evidence_total) - self.config.max_total_evidence
            if excess > 0:
                del self._evidence_total[0:excess]

    def _decay_state(self, state: TrustState, now: float) -> TrustState:
        hl = max(1.0, float(self.config.decay_half_life_sec))
        dt = max(0.0, now - state.last_update_ts)
        if dt <= 0.0:
            return state

        neutral = float(self.config.neutral_trust)
        if neutral < 0.0 or neutral > 1.0:
            neutral = 0.5

        decay_factor = 0.5 ** (dt / hl)
        state.trust_score = neutral + (state.trust_score - neutral) * decay_factor
        state.last_update_ts = now
        return state

    # ------------------------------------------------------------------
    # Weight mapping
    # ------------------------------------------------------------------

    def _weight_from_risk(
        self,
        *,
        score: float,
        verdict: bool,
        trust_hint: Optional[float],
    ) -> float:
        s = max(0.0, min(1.0, float(score)))
        base = (0.5 - s)
        if verdict:
            base = -abs(base)
        else:
            base = abs(base)

        scale = 1.0 + (1.0 - s)
        weight = base * scale

        if trust_hint is not None:
            hint = max(0.0, min(1.0, float(trust_hint)))
            centered = (hint - 0.5) * 2.0
            weight += 0.25 * centered

        return weight

    def _weight_from_action(self, action_result: ActionResult) -> float:
        try:
            ok = bool(action_result.ok)
            duration_ms = float(action_result.duration_ms())
            action_name = str(action_result.action)
            mode = getattr(action_result.mode, "value", str(action_result.mode))
        except Exception:
            return 0.0

        if not ok:
            return -1.0

        base = 0.3
        if action_name in ("rollback", "rotate_keys", "update_policies", "reload_config"):
            base = 0.5

        if mode == "canary":
            base *= 0.7
        elif mode == "production":
            base *= 1.0
        else:
            base *= 0.4

        if duration_ms > 5_000.0:
            base *= 0.5

        return base

    def _weight_from_verification(self, *, ok: bool) -> float:
        return 0.6 if ok else -1.2

    @staticmethod
    def _clamp01(x: float) -> float:
        return max(0.0, min(1.0, float(x)))