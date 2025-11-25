# FILE: tcd/schemas.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# =============================================================================
# Shared / nested models
# =============================================================================


class ReceiptView(BaseModel):
    """
    Minimal, content-agnostic view of a receipt suitable for API responses.

    This model is designed to be safe to expose over APIs and to embed into
    audit logs. It does not contain raw prompts or outputs; it only carries
    identifiers and cryptographic material that can be covered by signatures.

    The recommended producer is the receipt / attestor layer, which can
    populate:
      - signature / PQ information (sig_scheme, pq_required, pq_ok, ...),
      - supply-chain anchors (build_id, image_digest, env_fingerprint, ...),
      - policy and stream bindings (policy_ref, stream_hash, ...).
    """

    # Core receipt identifiers
    head: str = Field(
        ...,
        description="Canonical receipt head identifier (typically a hash of body_json)",
    )
    body: Optional[str] = Field(
        None,
        description="Canonical body JSON (content-agnostic; may be omitted)",
    )

    # Raw crypto material (opaque at this layer)
    sig: Optional[str] = Field(
        None,
        description="Opaque signature material (hex string or similar)",
    )
    verify_key: Optional[str] = Field(
        None,
        description="Opaque verification key material or identifier",
    )

    # Signature / PQ metadata
    sig_scheme: Optional[str] = Field(
        None,
        description=(
            "Signature scheme identifier, e.g. 'ed25519', 'dilithium3', "
            "'ed25519+pq_fallback'"
        ),
    )
    sig_chain_id: Optional[str] = Field(
        None,
        description="Logical identifier for the signing key-chain or HSM slot used",
    )
    pq_required: Optional[bool] = Field(
        None,
        description="Whether this receipt is required to be PQ-safe under policy",
    )
    pq_ok: Optional[bool] = Field(
        None,
        description="Whether a PQ-capable signature or key was actually used",
    )

    # Storage / environment metadata
    store_backend: Optional[str] = Field(
        None,
        description="Backend used to persist this receipt entry (if any)",
    )
    store_id: Optional[int] = Field(
        None,
        description="Row identifier in the underlying receipt store (if any)",
    )
    ts: Optional[float] = Field(
        None,
        description="Storage timestamp for this receipt (seconds since epoch)",
    )
    build_id: Optional[str] = Field(
        None,
        description="Build or release identifier of the serving stack",
    )
    image_digest: Optional[str] = Field(
        None,
        description="Container or binary image digest used at decision time",
    )
    attestation_id: Optional[str] = Field(
        None,
        description="Opaque handle to a runtime or hardware attestation record",
    )
    env_fingerprint: Optional[str] = Field(
        None,
        description="Stable hash of runtime environment (config + binary) for audits",
    )

    # Policy / stream binding
    policy_ref: Optional[str] = Field(
        None,
        description="Policy identifier bound to this receipt",
    )
    stream_hash: Optional[str] = Field(
        None,
        description="Opaque hash for the logical stream (tenant:subject:model, etc.)",
    )

    # Free-form audit metadata
    meta: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional audit metadata (schemes, key ids, policyset_ref, "
            "supply-chain flags, etc.)"
        ),
    )

    class Config:
        extra = "ignore"
        frozen = False


class EProcessStateView(BaseModel):
    """
    Snapshot of an anytime-valid e-process used for risk control.

    This mirrors the structure returned by the internal risk controller, while
    remaining content-agnostic and stable enough to embed in receipts.

    Recommended key layout
    ----------------------
    controller:
        {
          "name": "tcd.always_valid",
          "version": "0.1.0",
          "label": "inference|admin|control|...",
          "policy_ref": "<policy:id>",
          "policyset_ref": "<policyset:id>",
        }

    stream:
        {
          "id": "<logical_stream_id>",        # optional opaque identifier
          "hash": "<blake3_hex>",            # preferred for receipts
          "trust_zone": "internet|internal|partner|admin|...",
          "route_profile": "inference|admin|control|...",
          "subject_hash": "<opaque_subject_hash>",
          "threat_tags": ["apt", "insider", ...],
        }

    process:
        {
          "log_e": float,
          "e_value": float,
          "alpha_base": float,
          "alpha_wealth": float,
          "threshold": float,
          "trigger": bool,
          "decisions": int,
          "triggers": int,
          "last_trigger_step": Optional[int],
          "fdr_target": Optional[float],
        }
    """

    controller: Dict[str, Any] = Field(
        default_factory=dict,
        description="Controller metadata (name, version, label, policy_ref, ...)",
    )
    stream: Dict[str, Any] = Field(
        default_factory=dict,
        description="Stream metadata (id, hash, trust_zone, route_profile, ...)",
    )
    process: Dict[str, Any] = Field(
        default_factory=dict,
        description="Numeric state of the e-process (log_e, alpha, counters, ...)",
    )

    class Config:
        extra = "ignore"
        frozen = False


class RouteView(BaseModel):
    """
    Public view of a routing decision, aligned with tcd.routing.Route.

    Only includes parameters and metadata that are safe to expose externally.
    It is designed to be directly embeddable into receipts and audit logs.
    """

    # Core decoding parameters
    temperature: float = Field(
        ...,
        description="Effective sampling temperature",
    )
    top_p: float = Field(
        ...,
        description="Effective top-p value",
    )
    decoder: str = Field(
        ...,
        description="Decoder profile label (default/cautious/safe/...)",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Routing tags (e.g. 'threat:apt', 'zone:internal', 'policy:strict')",
    )

    # Human-facing explanation
    reason: str = Field(
        "",
        description="Short explanation of why this route was chosen",
    )

    # Resource hints
    max_tokens: Optional[int] = Field(
        None,
        description="Optional max-tokens cap applied by the router",
    )
    latency_hint: str = Field(
        "normal",
        description="Latency preference: 'normal', 'low_latency', or 'high_safety'",
    )

    # Safety tiering
    safety_tier: str = Field(
        "normal",
        description="Safety tier: 'normal', 'elevated', or 'strict'",
    )

    # Deterministic route identifier
    route_id: str = Field(
        "",
        description="Deterministic identifier for the routing decision",
    )

    # Policy and trust zone
    policy_ref: Optional[str] = Field(
        None,
        description="Policy reference used by the router (if available)",
    )
    trust_zone: str = Field(
        "internet",
        description="Trust zone label associated with this request",
    )

    # Threat, AV and PQ metadata
    threat_tags: List[str] = Field(
        default_factory=list,
        description="High-level threat labels for this decision: ['apt','insider',...]",
    )
    av_label: Optional[str] = Field(
        None,
        description="Label from upstream AV controller (if any)",
    )
    av_trigger: Optional[bool] = Field(
        None,
        description="Trigger flag from upstream AV controller (if any)",
    )
    pq_required: Optional[bool] = Field(
        None,
        description="Whether this route requires PQ-safe signing or attestation",
    )
    pq_ok: Optional[bool] = Field(
        None,
        description="PQ health for this route ('True' if PQ signer/keys were healthy)",
    )

    # Override / governance flags
    override_flags: List[str] = Field(
        default_factory=list,
        description=(
            "Override markers such as 'manual_override', 'break_glass', "
            "'policy_bypass', for governance and insider audits"
        ),
    )

    class Config:
        extra = "ignore"
        frozen = False


# =============================================================================
# API input / output schemas
# =============================================================================


class DiagnoseIn(BaseModel):
    """
    Input schema for a diagnostic / safety evaluation request.

    This model is intentionally simple but includes a small metadata surface to
    let callers pass coarse routing, trust, threat and supply-chain hints
    without exposing raw identities.

    Notes
    -----
    - `subject` SHOULD be an opaque token or pseudonym in privacy-sensitive
      deployments.
    - `subject_hash` MAY be precomputed by the caller if hashing on the client
      side is preferred.
    """

    input: str = Field(
        ...,
        description="Text or payload to check (already preprocessed at caller side)",
    )

    input_kind: str = Field(
        "prompt",
        description="Coarse kind of input: 'prompt', 'completion', 'log', 'meta', ...",
    )

    subject: Optional[str] = Field(
        None,
        description="Opaque subject token (pseudonym or tenant-scoped id)",
    )

    subject_hash: Optional[str] = Field(
        None,
        description="Pre-hashed subject identifier (preferred if available)",
    )

    tenant_id: Optional[str] = Field(
        None,
        description="Optional tenant or account identifier (opaque string)",
    )

    trust_zone: Optional[str] = Field(
        None,
        description="Trust zone hint: 'internet', 'internal', 'partner', 'admin', ...",
    )

    route_profile: Optional[str] = Field(
        None,
        description="Routing profile hint: 'inference', 'admin', 'control', ...",
    )

    tags: List[str] = Field(
        default_factory=list,
        description="Free-form tags for coarse classification or routing hints",
    )

    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional non-sensitive context for detectors / policies",
    )

    # Threat and PQ hints from upstream systems (SIEM, control plane, etc.)
    threat_hint: Optional[str] = Field(
        None,
        description="Upstream threat classification hint: 'apt','insider','supply_chain',...",
    )
    threat_confidence: Optional[float] = Field(
        None,
        description="Optional confidence in [0,1] for threat_hint",
    )
    pq_required: Optional[bool] = Field(
        None,
        description="Caller-declared requirement for PQ-safe receipts or signatures",
    )

    # Supply-chain / compliance context (optional)
    build_id: Optional[str] = Field(
        None,
        description="Build or release identifier of the calling stack",
    )
    image_digest: Optional[str] = Field(
        None,
        description="Container or binary image digest known to the caller",
    )
    compliance_tags: List[str] = Field(
        default_factory=list,
        description="Regulatory or compliance tags: ['gdpr','hipaa','pci',...]",  # labels only
    )

    class Config:
        extra = "ignore"
        frozen = False


class DiagnoseOut(BaseModel):
    """
    Output schema for a diagnostic / safety evaluation.

    This model is a compact, stable contract between the core safety engine and
    external callers. It exposes verdicts, scores, e-process summaries, routing
    decisions and receipt pointers, all in a form suitable for audit and
    signatures.

    High-level semantics
    --------------------
    - verdict:
        Boolean decision from the diagnostic engine (True = allowed).
    - decision:
        Coarse decision label such as 'allow', 'degrade', 'block', 'log_only'.
    - action:
        Recommended enforcement action for the caller.
    - score / threshold:
        Risk score and the calibrated threshold used to derive the verdict.
    - e_state:
        Snapshot of the e-process controlling error budgets for this stream.
    - route:
        The chosen routing strategy for this decision.
    - receipt:
        View of the receipt associated with this decision.

    Security field conventions
    --------------------------
    - trust_zone / route_profile:
        Resolved trust and routing profile for this decision.
    - threat_kind / threat_confidence:
        Final threat classification and its confidence.
    - pq_required / pq_ok:
        PQ safety requirement and whether it was satisfied.
    - policy_ref / policyset_ref:
        Policy identifiers used to derive the decision.
    - security dict:
        Expected keys may include:
          * "stream_hash"
          * "route_id"
          * "policy_ref"
          * "policyset_ref"
          * "av_label"
          * "av_trigger"
          * "sig_scheme"
          * "sig_chain_id"
          * "pq_required"
          * "pq_ok"
          * "supply_chain_ok"
          * "supply_chain_reason"
    """

    # Core decision surface
    verdict: bool = Field(
        ...,
        description="Final boolean verdict (True = allowed, False = blocked)",
    )
    decision: str = Field(
        "allow",
        description="Coarse decision label: 'allow', 'degrade', 'block', 'log_only', 'none', ...",
    )
    cause: str = Field(
        "",
        description="Short human-readable explanation for the decision",
    )
    action: str = Field(
        "none",
        description="Recommended enforcement action for the caller",
    )

    # Scores and thresholds
    score: float = Field(
        0.0,
        description="Primary risk score (typically in [0, 1])",
    )
    threshold: float = Field(
        0.0,
        description="Threshold used to convert score into a verdict",
    )

    # Budget / e-process scalars
    budget_remaining: float = Field(
        0.0,
        description="Remaining budget indicator (alpha or similar quantity)",
    )
    step: int = Field(
        0,
        description="Monotone step counter for this stream or controller",
    )
    e_value: float = Field(
        1.0,
        description="Anytime-valid e-process value for this decision",
    )
    alpha_alloc: float = Field(
        0.0,
        description="Allocated alpha (or budget) for this decision",
    )
    alpha_spent: float = Field(
        0.0,
        description="Spent alpha (or budget) up to this decision",
    )

    # Component-level diagnostics (detector outputs, calibration info, etc.)
    components: Dict[str, Any] = Field(
        default_factory=dict,
        description="Structured per-component diagnostics and scores",
    )

    # E-process and routing snapshots
    e_state: Optional[EProcessStateView] = Field(
        None,
        description="Optional detailed e-process snapshot for this decision",
    )
    route: Optional[RouteView] = Field(
        None,
        description="Optional routing decision used for this request",
    )

    # Resolved security context
    trust_zone: Optional[str] = Field(
        None,
        description="Resolved trust zone for this decision",
    )
    route_profile: Optional[str] = Field(
        None,
        description="Resolved route profile for this decision",
    )
    threat_kind: Optional[str] = Field(
        None,
        description="Final threat classification: 'apt','insider','supply_chain',...",
    )
    threat_confidence: Optional[float] = Field(
        None,
        description="Threat confidence score in [0,1] for threat_kind",
    )
    pq_required: bool = Field(
        False,
        description="Whether PQ-safe receipts/signatures were required under policy",
    )
    pq_ok: Optional[bool] = Field(
        None,
        description="Whether PQ requirements were satisfied (True/False) or not applicable (None)",
    )
    policy_ref: Optional[str] = Field(
        None,
        description="Primary policy identifier used to derive this decision",
    )
    policyset_ref: Optional[str] = Field(
        None,
        description="Policy-set identifier (e.g., active bundle or config set)",
    )

    # Security metadata (structured but flexible)
    security: Dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional security metadata (stream_hash, route_id, sig_scheme, "
            "pq flags, supply-chain flags, etc.)"
        ),
    )

    # Receipt view (preferred structured form)
    receipt: Optional[ReceiptView] = Field(
        None,
        description="Structured view of the associated receipt, if any",
    )

    # Backward-compatible raw receipt fields (optional)
    receipt_body: Optional[str] = Field(
        None,
        description="(Deprecated) Raw canonical body JSON string, if exposed",
    )
    receipt_sig: Optional[str] = Field(
        None,
        description="(Deprecated) Opaque signature material if provided",
    )
    verify_key: Optional[str] = Field(
        None,
        description="(Deprecated) Opaque verification key / identifier",
    )

    class Config:
        extra = "ignore"
        frozen = False


__all__ = [
    "DiagnoseIn",
    "DiagnoseOut",
    "ReceiptView",
    "EProcessStateView",
    "RouteView",
]