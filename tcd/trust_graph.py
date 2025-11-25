# FILE: tcd/trust_graph.py
from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

try:
    from .agent import ActionResult, ExecutionMode  # optional, for richer linking
except Exception:  # pragma: no cover
    ActionResult = Any  # type: ignore
    ExecutionMode = Any  # type: ignore

logger = logging.getLogger(__name__)

# ----------------------------------------------------------------------
# Content-agnostic guardrails
# ----------------------------------------------------------------------

_MAX_PAYLOAD_BYTES = 4096
_MAX_STR_LEN = 512
_FORBIDDEN_PAYLOAD_KEYS = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "messages",
    "content",
}


def _assert_payload_content_agnostic(payload: Dict[str, Any]) -> None:
    """
    Guard to keep Evidence payloads content-agnostic and small.

    Rules:
      - Recursively scan keys (up to depth 3) for clearly unsafe names
        such as "prompt" or "completion".
      - Restrict value types to: numbers, short strings, bool, None,
        small dicts, small lists/tuples.
      - Limit nesting depth to 4 and list length to 64.
      - Limit total JSON-encoded size to _MAX_PAYLOAD_BYTES.
    """

    def _check_keys(d: Dict[str, Any], depth: int = 0) -> None:
        if depth > 3:
            return
        try:
            keys = {str(k).lower() for k in d.keys()}
        except Exception:
            return
        if _FORBIDDEN_PAYLOAD_KEYS & keys:
            raise ValueError(
                "Evidence payload contains forbidden keys; it MUST NOT include "
                "raw prompts, completions or message content."
            )
        for v in d.values():
            if isinstance(v, dict):
                _check_keys(v, depth + 1)

    def _check_value(v: Any, depth: int = 0) -> None:
        if depth > 4:
            raise ValueError("Evidence payload is too deeply nested.")
        if v is None:
            return
        if isinstance(v, (int, float, bool)):
            try:
                if not math.isfinite(float(v)):
                    raise ValueError("Evidence payload has non-finite numeric value.")
            except Exception as exc:
                raise ValueError("Evidence payload has invalid numeric value.") from exc
            return
        if isinstance(v, str):
            if len(v) > _MAX_STR_LEN:
                raise ValueError("Evidence payload string too long.")
            return
        if isinstance(v, dict):
            for vv in v.values():
                _check_value(vv, depth + 1)
            return
        if isinstance(v, (list, tuple)):
            if len(v) > 64:
                raise ValueError("Evidence payload sequence too long.")
            for vv in v:
                _check_value(vv, depth + 1)
            return
        # Anything else (custom objects, bytes, etc.) is not allowed
        raise ValueError("Evidence payload contains unsupported value type.")

    # Key scan for obviously unsafe fields
    _check_keys(payload, 0)

    # Value type / length checks
    for v in payload.values():
        _check_value(v)

    # Global size limit
    try:
        encoded = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if len(encoded) > _MAX_PAYLOAD_BYTES:
            raise ValueError(
                "Evidence payload too large; keep it small and structural."
            )
    except ValueError:
        raise
    except Exception:
        # If serialization fails for some reason, we do not attempt to guess;
        # let the caller handle any persistence/serialization issues.
        return


# ----------------------------------------------------------------------
# Subject key
# ----------------------------------------------------------------------

class EvidenceType(str, Enum):
    """
    Types of evidence that can contribute to the trust graph.

    These are intentionally coarse-grained and content-agnostic.
    """

    RECEIPT = "receipt"
    DECISION = "decision"
    ACTION = "action"
    VERIFICATION = "verification"
    ANOMALY = "anomaly"
    HEALTH = "health"            # e.g. GPU / host health signals
    SUPPLY_CHAIN = "supply_chain"  # build / image / attestation signals
    OVERRIDE = "override"        # manual overrides / break-glass events


@dataclass
class SubjectKey:
    """
    Canonical key for a subject entity in the trust graph.

    A subject can represent a tenant, user, session, model, service, or any
    combination that you consider a "principal" whose trustworthiness you
    want to track.

    IMPORTANT:
      - tenant/user/session/model_id MUST be opaque IDs or hashes, not
        human-readable names or email addresses.
      - principal_type is a logical category, not an identity; it can be
        values like "user", "tenant", "session", "model", "admin", "service".
    """

    tenant: str = ""
    user: str = ""
    session: str = ""
    model_id: str = ""
    principal_type: str = ""  # "user","tenant","session","model","admin","service",...

    def as_id(self) -> str:
        parts = [
            f"tenant={self.tenant or '*'}",
            f"user={self.user or '*'}",
            f"session={self.session or '*'}",
            f"model={self.model_id or '*'}",
            f"ptype={self.principal_type or '*'}",
        ]
        return "|".join(parts)

    def to_labels(self) -> Dict[str, str]:
        return {
            "tenant": self.tenant or "",
            "user": self.user or "",
            "session": self.session or "",
            "model_id": self.model_id or "",
            "principal_type": self.principal_type or "",
        }


def _sanitize_subject(subject: SubjectKey) -> SubjectKey:
    """
    Best-effort sanity check for SubjectKey.

    - tenant/user/session/model_id MUST be opaque IDs or hashes, not
      emails or names.
    - If a component looks like it might contain PII (e.g. '@' or spaces),
      it is replaced with a hashed placeholder.
    - principal_type is passed through unchanged (it is a category string).
    """

    def _clean(value: str, placeholder_prefix: str) -> str:
        v = value or ""
        if not v:
            return placeholder_prefix
        if "@" in v or " " in v:
            try:
                digest = hashlib.blake2s(
                    v.encode("utf-8", errors="ignore"),
                    digest_size=8,
                ).hexdigest()
            except Exception:
                digest = "anon"
            logger.debug(
                "SubjectKey component looked like PII; using hashed placeholder."
            )
            return f"{placeholder_prefix}-{digest}"
        return v

    return SubjectKey(
        tenant=_clean(subject.tenant, "tenant"),
        user=_clean(subject.user, "user"),
        session=_clean(subject.session, "session"),
        model_id=_clean(subject.model_id, "model"),
        principal_type=subject.principal_type or "",
    )


# ----------------------------------------------------------------------
# Evidence & state
# ----------------------------------------------------------------------

@dataclass
class Evidence:
    """
    A single piece of evidence attached to a subject.

    Each evidence item carries a normalized contribution 'weight', where
    positive values push trust upward and negative values push it downward.
    The mapping from raw scores to weight is handled in the TrustGraph
    methods that create Evidence instances.

    The payload is required to be content-agnostic: no prompts, completions
    or other raw input/output material. Only small structured fields such as
    scores, decision labels, heads of receipts, or anonymized identifiers
    should be stored here.

    Additional fields capture security and supply-chain context in a
    content-agnostic way so that the trust graph can serve as a unified
    ledger across routing, e-process, PQ and attestation components.
    """

    evidence_id: str
    subject_id: str
    type: EvidenceType
    timestamp: float
    weight: float
    payload: Dict[str, Any] = field(default_factory=dict)

    # Source / channel metadata
    channel: str = "unknown"        # e.g. "tcd_router", "receipt_verifier", "gpu_probe"
    source_id: str = ""             # e.g. component id / service name

    # Security posture at the time of this evidence
    trust_zone: str = ""            # "internet","internal","partner","admin",...
    route_profile: str = ""         # e.g. "inference","admin","control"
    policy_ref: str = ""            # policy / playbook id used to derive this evidence
    threat_label: str = ""          # coarse threat tag, e.g. "apt","insider","supply_chain","none"

    # Override / break-glass
    override_applied: bool = False
    override_actor: str = ""        # opaque admin / role id

    # Supply-chain linkage
    supply_chain_ref: str = ""      # build / image / attestation ref

    # PQ posture at this evidence point
    pq_required: Optional[bool] = None
    pq_ok: Optional[bool] = None
    pq_chain_id: str = ""

    # Threat classification and e-process linking
    threat_vector: str = ""         # e.g. "apt","insider","supply_chain","pq","health","none"
    eprocess_ref: str = ""          # e-process instance / stream id
    risk_score_raw: Optional[float] = None

    # Idempotency token
    idem_token: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "subject_id": self.subject_id,
            "type": self.type.value,
            "timestamp": self.timestamp,
            "weight": self.weight,
            "payload": self.payload,
            "channel": self.channel,
            "source_id": self.source_id,
            "trust_zone": self.trust_zone,
            "route_profile": self.route_profile,
            "policy_ref": self.policy_ref,
            "threat_label": self.threat_label,
            "override_applied": self.override_applied,
            "override_actor": self.override_actor,
            "supply_chain_ref": self.supply_chain_ref,
            "pq_required": self.pq_required,
            "pq_ok": self.pq_ok,
            "pq_chain_id": self.pq_chain_id,
            "threat_vector": self.threat_vector,
            "eprocess_ref": self.eprocess_ref,
            "risk_score_raw": self.risk_score_raw,
            "idem_token": self.idem_token,
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

    Additional fields capture risk bands, freeze flags and PQ / supply-chain
    snapshots to make it easier to integrate with external policy engines
    and routing logic.
    """

    subject_id: str
    trust_score: float = 0.5
    observations: int = 0
    last_update_ts: float = field(default_factory=lambda: time.time())
    last_evidence_id: Optional[str] = None

    # Derived view of trust_score for routing / policy
    risk_band: str = "neutral"  # "high_risk","elevated_risk","neutral","reliable","high_trust"

    # Light-weight flags (small, fixed vocabulary)
    flags: List[str] = field(default_factory=list)

    # Last evidence type applied
    last_evidence_type: Optional[EvidenceType] = None

    # Freeze / compromise handling
    compromised: bool = False
    freeze_until_ts: Optional[float] = None

    # PQ / supply-chain snapshot
    last_pq_required: Optional[bool] = None
    last_pq_ok: Optional[bool] = None
    last_pq_chain_id: str = ""
    last_supply_chain_ref: str = ""

    # Lockdown level for router:
    #   "none"     -> normal routing
    #   "monitor"  -> raise logging / metrics
    #   "restrict" -> degrade / stricter policies
    #   "lockdown" -> block or human review
    lockdown_level: str = "none"

    # Threat vector counters (content-agnostic risk profiling)
    threat_counters: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "trust_score": self.trust_score,
            "observations": self.observations,
            "last_update_ts": self.last_update_ts,
            "last_evidence_id": self.last_evidence_id,
            "risk_band": self.risk_band,
            "flags": list(self.flags),
            "last_evidence_type": self.last_evidence_type.value if self.last_evidence_type else None,
            "compromised": self.compromised,
            "freeze_until_ts": self.freeze_until_ts,
            "last_pq_required": self.last_pq_required,
            "last_pq_ok": self.last_pq_ok,
            "last_pq_chain_id": self.last_pq_chain_id,
            "last_supply_chain_ref": self.last_supply_chain_ref,
            "lockdown_level": self.lockdown_level,
            "threat_counters": dict(self.threat_counters),
        }


@dataclass
class TrustGraphConfig:
    """
    Configuration for the TrustGraph update dynamics.

    All parameters are content-agnostic and only shape how evidence streams
    are aggregated into a trust_score in [0, 1].
    """

    # Time-decay behaviour
    decay_half_life_sec: float = 3600.0

    # Step size for each evidence contribution
    trust_update_step: float = 0.08

    # Evidence retention limits
    max_evidence_per_subject: int = 1024
    max_total_evidence: int = 100_000

    # Caps on individual evidence weight
    positive_cap: float = 2.0
    negative_cap: float = 2.0

    # Neutral trust anchor
    neutral_trust: float = 0.5

    # Optional: freeze window after severe negative evidence (seconds).
    # When > 0, strongly negative evidence (clipped at negative_cap) may
    # mark a subject as compromised and freeze further trust_score changes
    # for this duration, while still recording evidence for audit.
    freeze_on_compromise_sec: float = 0.0


# ----------------------------------------------------------------------
# Trust graph
# ----------------------------------------------------------------------

class TrustGraph:
    """
    TrustGraph maintains a compact, content-agnostic evidence graph.

    It does not store raw prompts, completions or other content. Instead,
    it only keeps:
      - normalized weights derived from risk scores / actions;
      - hashed identifiers for subjects and receipts;
      - structured, content-agnostic metadata (policy refs, threat labels,
        PQ posture, supply-chain references, override flags, health status).

    The main goal is to derive a stable trust signal for each subject from
    a stream of receipts, decisions, actions, health and anomaly signals,
    in a way that is:
      - replay-safe: idempotent tokens prevent double-counting;
      - auditable: every trust update is backed by a concrete Evidence;
      - independent of raw model inputs / outputs.
    """

    def __init__(self, config: Optional[TrustGraphConfig] = None) -> None:
        self.config = config or TrustGraphConfig()
        self._states: Dict[str, TrustState] = {}
        self._evidence_by_subject: Dict[str, List[Evidence]] = {}
        self._evidence_total: List[Evidence] = []
        # Idempotency tracking: idem_token -> first-seen timestamp
        self._seen_idem: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Public read API
    # ------------------------------------------------------------------

    def get_state(self, subject: SubjectKey) -> TrustState:
        subj = _sanitize_subject(subject)
        sid = subj.as_id()
        if sid not in self._states:
            self._states[sid] = TrustState(
                subject_id=sid,
                trust_score=self.config.neutral_trust,
            )
        return self._states[sid]

    def get_state_by_id(self, subject_id: str) -> TrustState:
        if subject_id not in self._states:
            self._states[subject_id] = TrustState(
                subject_id=subject_id,
                trust_score=self.config.neutral_trust,
            )
        return self._states[subject_id]

    def list_subjects(self) -> List[str]:
        return list(self._states.keys())

    def get_recent_evidence(
        self,
        subject: SubjectKey,
        limit: int = 32,
    ) -> List[Evidence]:
        subj = _sanitize_subject(subject)
        sid = subj.as_id()
        ev_list = self._evidence_by_subject.get(sid, [])
        if not ev_list:
            return []
        return ev_list[-limit:]

    # ------------------------------------------------------------------
    # Evidence ingestion (public API)
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
        # posture / metadata
        channel: str = "receipt",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        threat_label: str = "",
        threat_vector: str = "",
        override_applied: bool = False,
        override_actor: str = "",
        supply_chain_ref: str = "",
        pq_required: Optional[bool] = None,
        pq_ok: Optional[bool] = None,
        pq_chain_id: str = "",
        eprocess_ref: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        """
        Add evidence from a single risk decision plus its receipt.

        Args:
          score:
            Risk score in [0, 1].
          verdict:
            True if the decision indicates failure / unsafe; False if safe.
          e_value:
            Optional e-value from an anytime-valid e-process.
          receipt_head_hex:
            Receipt head identifier (hash), not the body.
          trust_hint:
            Optional external trust signal in [0, 1].
          channel, source_id, trust_zone, route_profile, policy_ref, threat_label,
          threat_vector, override_applied, override_actor, supply_chain_ref,
          pq_required, pq_ok, pq_chain_id, eprocess_ref, idem_token:
            Optional, content-agnostic metadata that bind this evidence into
            a broader security / supply-chain / PQ posture.
        """
        payload: Dict[str, Any] = {
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
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label=threat_label,
            threat_vector=threat_vector or threat_label or "",
            override_applied=override_applied,
            override_actor=override_actor,
            supply_chain_ref=supply_chain_ref,
            pq_required=pq_required,
            pq_ok=pq_ok,
            pq_chain_id=pq_chain_id,
            eprocess_ref=eprocess_ref,
            risk_score_raw=float(score),
            idem_token=idem_token,
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
        channel: str = "decision",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        threat_label: str = "",
        threat_vector: str = "",
        override_applied: bool = False,
        override_actor: str = "",
        eprocess_ref: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        """
        Add evidence from a routing / decision engine outcome.

        Args:
          decision:
            e.g. "allow", "block", "degrade", "throttle".
          score:
            Risk score in [0, 1].
          trust_hint:
            Optional external trust signal in [0, 1].
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
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label=threat_label,
            threat_vector=threat_vector or threat_label or "",
            override_applied=override_applied,
            override_actor=override_actor,
            eprocess_ref=eprocess_ref,
            risk_score_raw=float(score),
            idem_token=idem_token,
        )
        return self._apply_evidence(ev)

    def add_action_evidence(
        self,
        subject: SubjectKey,
        *,
        action_result: ActionResult,
        channel: str = "action",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        threat_label: str = "",
        threat_vector: str = "",
        eprocess_ref: str = "",
        idem_token: Optional[str] = None,
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
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label=threat_label,
            threat_vector=threat_vector or threat_label or "",
            eprocess_ref=eprocess_ref,
            idem_token=idem_token,
        )
        return self._apply_evidence(ev)

    def add_verification_evidence(
        self,
        subject: SubjectKey,
        *,
        ok: bool,
        head_hex: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
        channel: str = "verification",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        supply_chain_ref: str = "",
        pq_required: Optional[bool] = None,
        pq_ok: Optional[bool] = None,
        pq_chain_id: str = "",
        threat_label: str = "",
        threat_vector: str = "",
        eprocess_ref: str = "",
        idem_token: Optional[str] = None,
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
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            supply_chain_ref=supply_chain_ref,
            pq_required=pq_required,
            pq_ok=pq_ok,
            pq_chain_id=pq_chain_id,
            threat_label=threat_label,
            threat_vector=threat_vector or threat_label or "",
            eprocess_ref=eprocess_ref,
            idem_token=idem_token,
        )
        return self._apply_evidence(ev)

    def add_anomaly_evidence(
        self,
        subject: SubjectKey,
        *,
        severity: float,
        label: str,
        extra: Optional[Dict[str, Any]] = None,
        channel: str = "anomaly",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        threat_label: str = "anomaly",
        threat_vector: str = "",
        eprocess_ref: str = "",
        idem_token: Optional[str] = None,
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
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label=threat_label,
            threat_vector=threat_vector or threat_label or "",
            eprocess_ref=eprocess_ref,
            idem_token=idem_token,
        )
        return self._apply_evidence(ev)

    def add_health_evidence(
        self,
        subject: SubjectKey,
        *,
        health_ok: bool,
        details: Dict[str, Any],
        severity: float = 0.0,
        channel: str = "health",
        source_id: str = "gpu_probe",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        supply_chain_ref: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        """
        Add evidence from hardware / runtime health signals (e.g. GPU / host).

        health_ok=True:
          Small positive signal (device stable).
        health_ok=False:
          Negative signal proportional to severity in [0, 1].
        """
        severity = max(0.0, min(1.0, float(severity)))
        payload: Dict[str, Any] = {
            "health_ok": bool(health_ok),
            "severity": severity,
            "probe": details,
        }

        if health_ok:
            weight = 0.2 * (1.0 - severity)  # mild positive
            threat_label = ""
        else:
            weight = -self.config.negative_cap * max(0.3, severity)
            threat_label = "health"

        ev = self._make_evidence(
            subject=subject,
            type_=EvidenceType.HEALTH,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label=threat_label,
            threat_vector="health" if threat_label else "",
            supply_chain_ref=supply_chain_ref or str(details.get("supply_chain_ref", "")),
            idem_token=idem_token,
        )
        return self._apply_evidence(ev)

    def add_supply_chain_evidence(
        self,
        subject: SubjectKey,
        *,
        attested_ok: bool,
        build_id: str,
        image_digest: str,
        runtime_env: str,
        channel: str = "supply_chain",
        source_id: str = "supply_chain_attestor",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        pq_chain_id: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        """
        Add supply-chain / build / image attestation evidence.
        """
        payload: Dict[str, Any] = {
            "attested_ok": bool(attested_ok),
            "build_id": build_id,
            "image_digest": image_digest,
            "runtime_env": runtime_env,
        }

        weight = 0.7 if attested_ok else -1.5
        threat_label = "" if attested_ok else "supply_chain"

        ev = self._make_evidence(
            subject=subject,
            type_=EvidenceType.SUPPLY_CHAIN,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label=threat_label,
            threat_vector="supply_chain" if threat_label else "",
            supply_chain_ref=image_digest or build_id,
            pq_chain_id=pq_chain_id,
            idem_token=idem_token,
        )
        return self._apply_evidence(ev)

    def add_override_evidence(
        self,
        subject: SubjectKey,
        *,
        reason: str,
        actor: str,
        channel: str = "override",
        source_id: str = "admin_console",
        trust_zone: str = "admin",
        route_profile: str = "control",
        policy_ref: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        """
        Add evidence for a manual override / break-glass event.

        This is treated as a strong negative signal and can trigger
        compromise freeze windows depending on configuration.
        """
        payload: Dict[str, Any] = {
            "reason": reason,
            "actor": actor,
        }
        weight = -self.config.negative_cap  # full negative impact

        ev = self._make_evidence(
            subject=subject,
            type_=EvidenceType.OVERRIDE,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label="insider",
            threat_vector="insider",
            override_applied=True,
            override_actor=actor,
            idem_token=idem_token,
        )
        return self._apply_evidence(ev)

    def add_pq_attestation_evidence(
        self,
        subject: SubjectKey,
        *,
        pq_required: bool,
        pq_ok: bool,
        detail: Optional[Dict[str, Any]] = None,
        channel: str = "pq_attest",
        source_id: str = "pq_attestor",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        pq_chain_id: str = "",
        idem_token: Optional[str] = None,
    ) -> TrustState:
        """
        Add PQ attestation evidence.

        - pq_required=True & pq_ok=False: strong negative, can trigger lock.
        - pq_required=True & pq_ok=True: strong positive.
        - pq_required=False: mild signal.
        """
        payload: Dict[str, Any] = {
            "pq_required": bool(pq_required),
            "pq_ok": bool(pq_ok),
        }
        if detail:
            payload.update(detail)

        if pq_required and not pq_ok:
            weight = -1.5
            threat_label = "pq"
            threat_vector = "pq"
        elif pq_required and pq_ok:
            weight = 0.8
            threat_label = ""
            threat_vector = ""
        else:
            weight = 0.2 if pq_ok else 0.0
            threat_label = ""
            threat_vector = ""

        ev = self._make_evidence(
            subject=subject,
            type_=EvidenceType.VERIFICATION,
            weight=weight,
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label=threat_label,
            threat_vector=threat_vector,
            pq_required=pq_required,
            pq_ok=pq_ok,
            pq_chain_id=pq_chain_id,
            idem_token=idem_token,
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
        *,
        channel: str = "unknown",
        source_id: str = "",
        trust_zone: str = "",
        route_profile: str = "",
        policy_ref: str = "",
        threat_label: str = "",
        threat_vector: str = "",
        override_applied: bool = False,
        override_actor: str = "",
        supply_chain_ref: str = "",
        pq_required: Optional[bool] = None,
        pq_ok: Optional[bool] = None,
        pq_chain_id: str = "",
        eprocess_ref: str = "",
        risk_score_raw: Optional[float] = None,
        idem_token: Optional[str] = None,
    ) -> Evidence:
        subj = _sanitize_subject(subject)
        sid = subj.as_id()
        ts = time.time()

        # Enforce payload guardrails before hashing / storing
        _assert_payload_content_agnostic(payload)

        # For ID computation, include both payload and selected metadata so that
        # replay with different posture becomes a distinct evidence item.
        id_payload: Dict[str, Any] = dict(payload)
        id_payload.update(
            {
                "channel": channel,
                "source_id": source_id,
                "trust_zone": trust_zone,
                "route_profile": route_profile,
                "policy_ref": policy_ref,
                "threat_label": threat_label,
                "threat_vector": threat_vector,
                "override_applied": override_applied,
                "supply_chain_ref": supply_chain_ref,
                "pq_required": pq_required,
                "pq_ok": pq_ok,
                "pq_chain_id": pq_chain_id,
                "eprocess_ref": eprocess_ref,
                "risk_score_raw": risk_score_raw,
                "idem_token": idem_token,
            }
        )
        ev_id = self._hash_evidence_id(sid, type_, ts, id_payload)

        return Evidence(
            evidence_id=ev_id,
            subject_id=sid,
            type=type_,
            timestamp=ts,
            weight=float(weight),
            payload=payload,
            channel=channel,
            source_id=source_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
            policy_ref=policy_ref,
            threat_label=threat_label,
            override_applied=override_applied,
            override_actor=override_actor,
            supply_chain_ref=supply_chain_ref,
            pq_required=pq_required,
            pq_ok=pq_ok,
            pq_chain_id=pq_chain_id,
            threat_vector=threat_vector,
            eprocess_ref=eprocess_ref,
            risk_score_raw=risk_score_raw,
            idem_token=idem_token,
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
        # Use coarse timestamp granularity (seconds) for ordering without
        # making identical payloads indistinguishable.
        coarse_ts = int(ts)
        h.update(str(coarse_ts).encode("ascii", errors="ignore"))
        try:
            encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        except Exception:
            encoded = b"{}"
        h.update(encoded)
        return h.hexdigest()

    def _apply_evidence(self, evidence: Evidence) -> TrustState:
        # Idempotency: if idem_token is present and already seen, only record
        # the evidence without changing trust_score again.
        if evidence.idem_token:
            ts0 = self._seen_idem.get(evidence.idem_token)
            if ts0 is not None:
                self._append_evidence(evidence)
                state = self.get_state_by_id(evidence.subject_id)
                state.last_update_ts = evidence.timestamp
                state.last_evidence_id = evidence.evidence_id
                state.last_evidence_type = evidence.type
                # Posture updates still apply (PQ/supply/lockdown).
                self._update_posture(state, evidence)
                return state
            self._seen_idem[evidence.idem_token] = evidence.timestamp
            # Basic cleanup to avoid unbounded growth
            if len(self._seen_idem) > self.config.max_total_evidence * 2:
                cutoff = evidence.timestamp - 24 * 3600.0
                self._seen_idem = {
                    k: v for k, v in self._seen_idem.items() if v >= cutoff
                }

        state = self.get_state_by_id(evidence.subject_id)
        state = self._decay_state(state, evidence.timestamp)

        # If a freeze window is active, record the evidence but do not adjust trust_score.
        if state.freeze_until_ts is not None and evidence.timestamp < state.freeze_until_ts:
            self._append_evidence(evidence)
            state.last_update_ts = evidence.timestamp
            state.last_evidence_id = evidence.evidence_id
            state.last_evidence_type = evidence.type
            self._update_posture(state, evidence)
            return state

        bounded_weight = max(
            -self.config.negative_cap,
            min(self.config.positive_cap, evidence.weight),
        )
        step = self.config.trust_update_step
        state.trust_score = self._clamp01(state.trust_score + step * bounded_weight)
        state.observations += 1
        state.last_update_ts = evidence.timestamp
        state.last_evidence_id = evidence.evidence_id
        state.last_evidence_type = evidence.type

        # Update risk_band based on new trust_score
        state.risk_band = self._risk_band_for_score(state.trust_score)

        # Maintain small, fixed-volume flags
        if bounded_weight < 0:
            if "recent_negative" not in state.flags:
                state.flags.append("recent_negative")
            if "recent_positive" in state.flags:
                state.flags.remove("recent_positive")
        elif bounded_weight > 0:
            if "recent_positive" not in state.flags:
                state.flags.append("recent_positive")
            if "recent_negative" in state.flags:
                state.flags.remove("recent_negative")

        # Handle severe negative evidence (optional freeze / compromise marking)
        if (
            bounded_weight <= -self.config.negative_cap
            and self.config.freeze_on_compromise_sec > 0.0
        ):
            state.compromised = True
            state.freeze_until_ts = evidence.timestamp + float(
                self.config.freeze_on_compromise_sec
            )
            if "compromised" not in state.flags:
                state.flags.append("compromised")

        # Update PQ / supply-chain / threat posture and lockdown level
        self._update_posture(state, evidence)

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
        if not (0.0 <= neutral <= 1.0):
            neutral = 0.5

        # Exponential decay towards neutral; older evidence has less effect.
        decay_factor = 0.5 ** (dt / hl)
        state.trust_score = neutral + (state.trust_score - neutral) * decay_factor
        state.last_update_ts = now
        state.risk_band = self._risk_band_for_score(state.trust_score)
        state.lockdown_level = self._lockdown_for_state(state)
        return state

    def _update_posture(self, state: TrustState, evidence: Evidence) -> None:
        """
        Update PQ / supply-chain snapshots, threat counters and lockdown
        level based on a newly applied (or replayed) evidence item.
        """
        # PQ snapshot
        if evidence.pq_required is not None:
            state.last_pq_required = evidence.pq_required
        if evidence.pq_ok is not None:
            state.last_pq_ok = evidence.pq_ok
        if evidence.pq_chain_id:
            state.last_pq_chain_id = evidence.pq_chain_id

        # Supply-chain snapshot
        if evidence.supply_chain_ref:
            state.last_supply_chain_ref = evidence.supply_chain_ref

        # Threat counters
        tv = evidence.threat_vector or evidence.threat_label or ""
        if tv:
            state.threat_counters[tv] = state.threat_counters.get(tv, 0) + 1

        # Lockdown level
        state.lockdown_level = self._lockdown_for_state(state)

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
        """
        Map a risk score and verdict into an evidence weight.

        score:
          Risk score in [0, 1] where higher usually means riskier.
        verdict:
          True for negative outcome (unsafe / blocked), False for positive.
        trust_hint:
          Optional external trust signal in [0, 1] that can slightly nudge
          the weight up or down.
        """
        s = max(0.0, min(1.0, float(score)))

        # Base contribution: distance from 0.5, sign determined by verdict.
        base = (0.5 - s)
        if verdict:
            base = -abs(base)
        else:
            base = abs(base)

        # Down-weight extremely small scores; up-weight decisive values.
        scale = 1.0 + (1.0 - s)
        weight = base * scale

        # Incorporate external hint as a gentle bias.
        if trust_hint is not None:
            hint = max(0.0, min(1.0, float(trust_hint)))
            centered = (hint - 0.5) * 2.0  # [-1, 1]
            weight += 0.25 * centered

        return weight

    def _weight_from_action(self, action_result: ActionResult) -> float:
        """
        Map an agent action outcome into an evidence weight.

        The mapping is intentionally simple and conservative to make it easy
        to reason about in audit trails.
        """
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
        """
        Map a verification result into an evidence weight.

        Successful verification is a moderately strong positive signal;
        failure is a stronger negative signal.
        """
        return 0.6 if ok else -1.2

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _clamp01(x: float) -> float:
        return max(0.0, min(1.0, float(x)))

    @staticmethod
    def _risk_band_for_score(score: float) -> str:
        """
        Derive a coarse-grained risk band from a trust score in [0, 1].

        This is intended for routing / policy decisions, not fine-grained
        scoring. Thresholds are configurable by changing this function if
        needed.
        """
        s = max(0.0, min(1.0, float(score)))
        if s <= 0.2:
            return "high_risk"
        if s <= 0.4:
            return "elevated_risk"
        if s < 0.6:
            return "neutral"
        if s < 0.8:
            return "reliable"
        return "high_trust"

    def _lockdown_for_state(self, state: TrustState) -> str:
        """
        Compute a coarse-grained lockdown level for a given state based on
        trust_score, compromise flag, and threat counters.
        """
        s = max(0.0, min(1.0, float(state.trust_score)))
        if state.compromised:
            return "lockdown"
        if s <= 0.2:
            return "lockdown"
        if s <= 0.4:
            return "restrict"

        apt_count = state.threat_counters.get("apt", 0)
        insider_count = state.threat_counters.get("insider", 0)
        total_sensitive = apt_count + insider_count

        if total_sensitive > 10 and s < 0.6:
            return "restrict"
        if total_sensitive > 3:
            return "monitor"
        return "none"