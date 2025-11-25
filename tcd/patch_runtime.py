# FILE: tcd/patch_runtime.py
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Callable, Union

# ----------------------------------------------------------------------
# External, optional dependencies (agent, attestor, hashing, telemetry)
# ----------------------------------------------------------------------

try:
    from .agent import ControlAgent, ActionResult, ExecutionMode
except Exception:  # pragma: no cover
    ControlAgent = Any  # type: ignore
    ActionResult = Any  # type: ignore
    ExecutionMode = Any  # type: ignore

try:
    from .attest import Attestor
    from .kv import RollingHasher
except Exception:  # pragma: no cover
    Attestor = None  # type: ignore
    RollingHasher = None  # type: ignore

try:
    from .trust_graph import SubjectKey
except Exception:  # pragma: no cover
    @dataclass
    class SubjectKey:  # type: ignore
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
    from .otel_exporter import TCDOtelExporter
except Exception:  # pragma: no cover
    TCDOtelExporter = Any  # type: ignore


# ----------------------------------------------------------------------
# Patch enums and identities
# ----------------------------------------------------------------------


class PatchStatus(str, Enum):
    """
    Lifecycle status for a patch instance.
    """

    PENDING = "pending"
    APPLIED = "applied"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class PatchRiskLevel(str, Enum):
    """
    Coarse-grained risk label for a patch.

    This does not replace a full risk assessment pipeline; it is used
    to choose default execution modes and to drive audit policy.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PatchKind(str, Enum):
    """
    High-level category of the patch target.
    """

    POLICY = "policy"
    MODEL = "model"
    RUNTIME_CONFIG = "runtime_config"
    BINARY = "binary"
    INFRA = "infra"
    OTHER = "other"


@dataclass
class OperatorId:
    """
    Identity of the operator initiating patch actions.

    operator_id SHOULD already be a stable pseudonymous identifier
    (for example, hashed outside this module). This type is only used
    for routing and audit; it never attempts to resolve real identities.
    """

    operator_id: str
    roles: List[str] = field(default_factory=list)

    @property
    def hash_id(self) -> str:
        # Treat operator_id as already-sanitized / hashed.
        return self.operator_id


# ----------------------------------------------------------------------
# Core descriptors and state
# ----------------------------------------------------------------------


@dataclass
class PatchDescriptor:
    """
    Static metadata for a single patch.

    This describes *what* is being changed and how the patch is
    identified; it does not contain runtime status or receipts.
    """

    patch_id: str
    # Subject identity as a stable string; usually SubjectKey.as_id().
    subject_id: str
    # Category of the patch target.
    patch_kind: PatchKind = PatchKind.RUNTIME_CONFIG
    # Human-readable description (safe to display in dashboards).
    description: str = ""
    # Logical origin (change management ticket, CI pipeline, etc.).
    origin: str = ""
    # Creation timestamp (seconds since epoch, float).
    created_ts: float = field(default_factory=lambda: time.time())
    # Checksum of (subject, patch_blob); algorithm controlled via config.
    checksum: str = ""
    # Coarse risk classification.
    risk_level: PatchRiskLevel = PatchRiskLevel.LOW

    # Supply-chain / artifact metadata -------------------------------

    # Digest of the artifact being deployed (image, archive, etc.).
    artifact_digest: Optional[str] = None
    # Logical source of the artifact, e.g. "ci_pipeline", "manual", "partner".
    artifact_source: Optional[str] = None
    # Identifier or hash of SBOM that describes this artifact.
    artifact_sbom_id: Optional[str] = None
    # Optional CI / build pipeline run identifier.
    build_pipeline_id: Optional[str] = None
    # Optional VCS commit hash associated with this patch.
    commit_hash: Optional[str] = None

    # Execution constraints ------------------------------------------

    # Environments where this patch is allowed to run (e.g. "staging", "prod").
    allowed_envs: Optional[List[str]] = None
    # Trust zones where this patch is allowed (e.g. "internal", "partner").
    allowed_trust_zones: Optional[List[str]] = None
    # Optional limits on rollout scope, e.g. {"max_models": 3, "max_nodes": 10}.
    max_scope: Optional[Dict[str, int]] = None

    # Change-management metadata -------------------------------------

    # External change ticket identifier (e.g. from Issue / CM system).
    change_ticket_id: Optional[str] = None
    # Number of approvals required before apply is allowed.
    required_approvals: int = 0

    # Extra structured metadata (for extensions).
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "subject_id": self.subject_id,
            "patch_kind": self.patch_kind.value,
            "description": self.description,
            "origin": self.origin,
            "created_ts": self.created_ts,
            "checksum": self.checksum,
            "risk_level": self.risk_level.value,
            "artifact_digest": self.artifact_digest,
            "artifact_source": self.artifact_source,
            "artifact_sbom_id": self.artifact_sbom_id,
            "build_pipeline_id": self.build_pipeline_id,
            "commit_hash": self.commit_hash,
            "allowed_envs": list(self.allowed_envs) if self.allowed_envs is not None else None,
            "allowed_trust_zones": list(self.allowed_trust_zones) if self.allowed_trust_zones is not None else None,
            "max_scope": dict(self.max_scope) if self.max_scope is not None else None,
            "change_ticket_id": self.change_ticket_id,
            "required_approvals": self.required_approvals,
            "metadata": self.metadata,
        }


@dataclass
class PatchReceiptRef:
    """
    Reference to an attested receipt for a patch operation.

    The exact fields depend on the Attestor implementation; this struct
    only mirrors the subset that PatchRuntime cares about.
    """

    receipt_head: Optional[str] = None
    receipt_body: Optional[str] = None
    receipt_sig: Optional[str] = None
    verify_key: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_head": self.receipt_head,
            "receipt_body": self.receipt_body,
            "receipt_sig": self.receipt_sig,
            "verify_key": self.verify_key,
        }


@dataclass
class PatchState:
    """
    Mutable state of a patch across register / approve / apply / rollback.

    This is the primary object used for inspection and audit.
    """

    descriptor: PatchDescriptor
    status: PatchStatus = PatchStatus.PENDING

    last_update_ts: float = field(default_factory=lambda: time.time())
    last_error: Optional[str] = None

    # Apply / rollback timestamps.
    applied_ts: Optional[float] = None
    rolled_back_ts: Optional[float] = None

    # Receipts for the most recent apply / rollback operation.
    apply_receipt: Optional[PatchReceiptRef] = None
    rollback_receipt: Optional[PatchReceiptRef] = None

    # Governance / approval -------------------------------------------

    # Creator identity (pseudonymous / hashed).
    created_by: Optional[str] = None
    # Approval records: [{"operator_id_hash": "...", "role": "...", "ts": ...}, ...]
    approvals: List[Dict[str, Any]] = field(default_factory=list)
    # Hash of the operator who most recently acted on this patch.
    last_operator_id_hash: Optional[str] = None

    # Counters for attempts.
    apply_attempts: int = 0
    rollback_attempts: int = 0

    # Execution footprint ---------------------------------------------

    # Optional summary of where this patch was applied (nodes, models, etc.).
    apply_targets: Optional[Dict[str, Any]] = None
    # Whether a canary phase completed successfully before promotion.
    canary_success: Optional[bool] = None
    # Timestamp when the patch was promoted from canary to full rollout.
    promotion_ts: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "descriptor": self.descriptor.to_dict(),
            "status": self.status.value,
            "last_update_ts": self.last_update_ts,
            "last_error": self.last_error,
            "applied_ts": self.applied_ts,
            "rolled_back_ts": self.rolled_back_ts,
            "apply_receipt": self.apply_receipt.to_dict() if self.apply_receipt else None,
            "rollback_receipt": self.rollback_receipt.to_dict() if self.rollback_receipt else None,
            "created_by": self.created_by,
            "approvals": list(self.approvals),
            "last_operator_id_hash": self.last_operator_id_hash,
            "apply_attempts": self.apply_attempts,
            "rollback_attempts": self.rollback_attempts,
            "apply_targets": dict(self.apply_targets) if self.apply_targets is not None else None,
            "canary_success": self.canary_success,
            "promotion_ts": self.promotion_ts,
        }


# ----------------------------------------------------------------------
# Configuration and policy
# ----------------------------------------------------------------------


AuthorizeFn = Callable[
    [str, Union[PatchDescriptor, PatchState], Optional[OperatorId], Optional[str]],
    None,
]

EAllocatorFn = Callable[[PatchState, ActionResult], Dict[str, float]]


@dataclass
class PatchRuntimeConfig:
    """
    Configuration and policy switches for PatchRuntime.

    PatchRuntime is designed as the only legitimate entry point for
    changes to models, runtime, policies, and guards. Any modification
    that bypasses this runtime should be treated as an illegal path in
    the threat model.

    The runtime is deliberately conservative: it prefers to report
    failures and require explicit approvals instead of silently
    accepting questionable patches.
    """

    # Core behaviour ----------------------------------------------------

    # Automatically attempt rollback when apply fails (for non-dry runs).
    auto_rollback_on_failure: bool = True

    # Maximum number of patches to retain in memory. Oldest entries are
    # evicted when this limit is exceeded.
    max_patches: int = 1_000

    # Hash algorithm used for patch checksum; see _compute_checksum().
    # Supported values:
    #   - "blake3" (preferred when RollingHasher is available)
    #   - "sha256"
    #   - "sha1" (discouraged; controlled by allow_legacy_sha1)
    #   - anything else → blake2s with fixed digest size.
    hash_alg: str = "blake3"

    # Allow use of legacy algorithms such as SHA-1. When False and
    # hash_alg == "sha1", PatchRuntime will raise during initialization.
    allow_legacy_sha1: bool = False

    # Whether to request receipts from Attestor for apply/rollback.
    receipts_enable: bool = True

    # Prefix used for patch identifiers, before the checksum fragment.
    patch_id_prefix: str = "patch"

    # Logical kinds used for receipts / telemetry.
    apply_kind: str = "apply_patch"
    rollback_kind: str = "rollback"

    # Risk-aware execution defaults -------------------------------------

    # When no explicit ExecutionMode is provided, choose a default based
    # on risk_level and this config. The solver is:
    #   - risk_level == HIGH  → prefer canary_mode_default
    #   - otherwise           → prefer production_mode_default
    # If these are None, fall back to ExecutionMode.CANARY /
    # ExecutionMode.PRODUCTION when present on ExecutionMode.
    canary_mode_default: Optional[Any] = None
    production_mode_default: Optional[Any] = None

    # Enforce that HIGH risk patches cannot be executed with a direct
    # production mode; they must go through a staged path first.
    require_canary_for_high_risk: bool = True

    # Simple guardrail: limit number of pending patches per subject_id.
    max_pending_per_subject: int = 32

    # Allow registration of multiple patches with the same checksum for
    # a given subject. When False, a repeated checksum will re-use the
    # existing patch_id and state.
    allow_duplicate_checksums: bool = False

    # e-process / evidence defaults -------------------------------------

    # Default initial wealth and allocation used in e_obj for receipts.
    e_default_value: float = 1.0
    e_default_alpha_alloc: float = 0.0
    e_default_alpha_wealth: float = 0.0
    e_default_threshold: float = 0.0

    # Optional allocator that maps a (state, result) pair to e-process
    # fields; if provided, its output overrides the defaults above.
    e_allocator: Optional[EAllocatorFn] = None

    # Optional identifier to tie patch receipts to a global e-process.
    e_process_id: Optional[str] = None

    # Telemetry / audit integration -------------------------------------

    # Optional exporter; when provided, PatchRuntime will emit structured
    # events and metrics for register / approve / apply / rollback.
    telemetry: Optional[TCDOtelExporter] = None

    telemetry_emit_register_events: bool = True
    telemetry_emit_approve_events: bool = True
    telemetry_emit_apply_events: bool = True
    telemetry_emit_rollback_events: bool = True

    # Optional out-of-band audit hook: (event_name, payload) -> None.
    # This can be used to drive bespoke logging, SIEM sinks, etc.
    audit_hook: Optional[Callable[[str, Dict[str, Any]], None]] = None

    # When True, PatchRuntime will avoid including full metadata in the
    # receipt payload; only identifiers and coarse labels are used.
    minimize_receipt_metadata: bool = False

    # Authorization / environment ---------------------------------------

    # Optional authorization function. If present, it is invoked before
    # register / approve / apply / rollback. It must either return or
    # raise an exception to deny the operation.
    authorize_fn: Optional[AuthorizeFn] = None

    # Logical environment label for this runtime (e.g. "dev", "staging", "prod").
    environment: str = "prod"

    # Default trust zone label for this runtime instance (e.g. "internal").
    trust_zone: str = "default"

    # Supply-chain / attestation controls -------------------------------

    # Whether to verify artifact attestation during register_patch.
    verify_artifact_on_register: bool = False
    # When True, a failed artifact verification at register time causes
    # the registration to be rejected.
    require_verified_artifact_on_register: bool = False

    # Whether to re-verify artifact attestation at apply time.
    verify_artifact_on_apply: bool = True
    # When True, a failed artifact verification at apply time prevents
    # the patch from being applied.
    require_verified_artifact_on_apply: bool = True


# ----------------------------------------------------------------------
# Runtime
# ----------------------------------------------------------------------


class PatchRuntime:
    """
    PatchRuntime coordinates safe patch registration, approval, apply
    and rollback.

    It does not perform file edits directly. Instead, it delegates the
    actual operations to a ControlAgent and focuses on:

      - maintaining explicit patch descriptors and state;
      - enforcing approval and authorization hooks;
      - orchestrating apply → rollback flows with clear status;
      - computing content-bound checksums for patch blobs;
      - verifying artifacts via an Attestor (when configured);
      - issuing receipts via Attestor (when configured);
      - emitting structured telemetry and audit events.

    By design, this module is intended to be the only legitimate entry
    point for changes to models, runtime, policies, and guard rails in
    the hosting process.
    """

    def __init__(
        self,
        agent: Optional[ControlAgent] = None,
        attestor: Optional[Attestor] = None,
        *,
        config: Optional[PatchRuntimeConfig] = None,
    ) -> None:
        self.config = config or PatchRuntimeConfig()
        self._agent = agent
        self._attestor = attestor if self.config.receipts_enable else None

        # Validate hash configuration early.
        if self.config.hash_alg.lower() == "sha1" and not self.config.allow_legacy_sha1:
            raise ValueError(
                "hash_alg='sha1' is not allowed unless allow_legacy_sha1=True."
            )

        # In-memory patch registry; keyed by patch_id.
        self._patches: Dict[str, PatchState] = {}
        # Ordered list of patch_ids to allow simple eviction by age.
        self._order: List[str] = []

    # ------------------------------------------------------------------
    # Registration / lookup / approval
    # ------------------------------------------------------------------

    def register_patch(
        self,
        subject: SubjectKey,
        *,
        patch_blob: bytes,
        description: str,
        origin: str,
        risk_level: PatchRiskLevel = PatchRiskLevel.LOW,
        metadata: Optional[Dict[str, Any]] = None,
        patch_kind: PatchKind = PatchKind.RUNTIME_CONFIG,
        operator: Optional[OperatorId] = None,
        environment: Optional[str] = None,
    ) -> PatchState:
        """
        Register a new patch for a given logical subject.

        This computes a checksum bound to (subject, patch_blob) and
        constructs a PatchDescriptor and PatchState. The actual patch
        application must be triggered separately via apply_patch().
        """
        subject_id = subject.as_id()
        checksum = self._compute_checksum(subject, patch_blob)
        env = environment or self.config.environment

        # Optionally deduplicate on checksum per subject.
        if not self.config.allow_duplicate_checksums:
            existing = self._find_by_subject_and_checksum(subject_id, checksum)
            if existing is not None:
                return existing

        md = dict(metadata or {})

        descriptor = PatchDescriptor(
            patch_id=self._make_patch_id(checksum),
            subject_id=subject_id,
            patch_kind=patch_kind,
            description=description,
            origin=origin,
            created_ts=time.time(),
            checksum=checksum,
            risk_level=risk_level,
            artifact_digest=md.get("artifact_digest"),
            artifact_source=md.get("artifact_source"),
            artifact_sbom_id=md.get("artifact_sbom_id"),
            build_pipeline_id=md.get("build_pipeline_id"),
            commit_hash=md.get("commit_hash"),
            allowed_envs=md.get("allowed_envs"),
            allowed_trust_zones=md.get("allowed_trust_zones"),
            max_scope=md.get("max_scope"),
            change_ticket_id=md.get("change_ticket_id"),
            required_approvals=int(md.get("required_approvals", 0)),
            metadata=md,
        )

        # Authorization hook.
        self._authorize("register", descriptor, operator, env)

        # Optional artifact attestation at registration time.
        self._verify_artifact_on_register(descriptor)

        state = PatchState(
            descriptor=descriptor,
            status=PatchStatus.PENDING,
            created_by=operator.hash_id if operator is not None else None,
            last_operator_id_hash=operator.hash_id if operator is not None else None,
        )
        self._register_state(state)

        self._emit_telemetry_register(state, operator=operator, environment=env)
        self._emit_audit_event(
            "tcd.patch.register",
            {
                "patch_id": state.descriptor.patch_id,
                "subject_id": state.descriptor.subject_id,
                "patch_kind": state.descriptor.patch_kind.value,
                "risk_level": state.descriptor.risk_level.value,
                "environment": env,
                "trust_zone": self.config.trust_zone,
                "operator_id_hash": state.created_by,
                "change_ticket_id": state.descriptor.change_ticket_id,
            },
        )

        return state

    def approve_patch(
        self,
        patch_id: str,
        *,
        operator: OperatorId,
        role: str,
        reason: str = "",
        environment: Optional[str] = None,
    ) -> PatchState:
        """
        Record an approval for a patch.

        Approvals are purely metadata; enforcement (e.g. required count)
        happens when apply_patch() is called.
        """
        state = self._require_patch(patch_id)
        env = environment or self.config.environment

        self._authorize("approve", state, operator, env)

        now = time.time()
        state.last_update_ts = now
        state.last_operator_id_hash = operator.hash_id
        state.approvals.append(
            {
                "operator_id_hash": operator.hash_id,
                "role": role,
                "reason": reason,
                "ts": now,
            }
        )

        self._emit_telemetry_approve(state, operator=operator, environment=env)
        self._emit_audit_event(
            "tcd.patch.approve",
            {
                "patch_id": patch_id,
                "subject_id": state.descriptor.subject_id,
                "risk_level": state.descriptor.risk_level.value,
                "environment": env,
                "trust_zone": self.config.trust_zone,
                "operator_id_hash": operator.hash_id,
                "role": role,
                "reason": reason,
                "approval_count": len(state.approvals),
            },
        )

        return state

    def get_patch(self, patch_id: str) -> Optional[PatchState]:
        """
        Retrieve a PatchState by id.
        """
        return self._patches.get(patch_id)

    def list_patches(self) -> List[PatchState]:
        """
        List all known patches in registration order, oldest first.
        """
        return [self._patches[pid] for pid in self._order if pid in self._patches]

    # ------------------------------------------------------------------
    # Apply / rollback orchestration
    # ------------------------------------------------------------------

    def apply_patch(
        self,
        patch_id: str,
        *,
        dry_run: bool = False,
        mode: Optional[ExecutionMode] = None,
        reason: str = "",
        operator: Optional[OperatorId] = None,
        environment: Optional[str] = None,
    ) -> Tuple[PatchState, Optional[PatchReceiptRef], Optional[ActionResult]]:
        """
        Apply (or simulate applying) a patch by id.

        Returns (PatchState, PatchReceiptRef | None, ActionResult | None).
        The PatchState is always updated in memory; receipt and result
        may be None when no agent/attestor is configured.
        """
        state = self._require_patch(patch_id)
        env = environment or self.config.environment
        now = time.time()
        state.last_update_ts = now
        state.apply_attempts += 1
        if operator is not None:
            state.last_operator_id_hash = operator.hash_id

        # Authorization and approval checks.
        self._authorize("apply", state, operator, env)
        self._enforce_approvals_before_apply(state)

        if not self._agent:
            state.last_error = "ControlAgent not configured"
            state.status = PatchStatus.FAILED
            self._emit_audit_event(
                "tcd.patch.apply.error",
                {
                    "patch_id": patch_id,
                    "subject_id": state.descriptor.subject_id,
                    "error": state.last_error,
                    "environment": env,
                    "trust_zone": self.config.trust_zone,
                    "operator_id_hash": state.last_operator_id_hash,
                },
            )
            self._emit_telemetry_apply(
                state=state,
                ok=False,
                dry_run=dry_run,
                mode=None,
                environment=env,
            )
            return state, None, None

        # Optional artifact re-validation at apply time.
        if not self._verify_artifact_on_apply(state):
            # Artifact not acceptable; do not proceed.
            self._emit_telemetry_apply(
                state=state,
                ok=False,
                dry_run=dry_run,
                mode=None,
                environment=env,
            )
            self._emit_audit_event(
                "tcd.patch.apply.artifact_blocked",
                {
                    "patch_id": patch_id,
                    "subject_id": state.descriptor.subject_id,
                    "risk_level": state.descriptor.risk_level.value,
                    "environment": env,
                    "trust_zone": self.config.trust_zone,
                    "operator_id_hash": state.last_operator_id_hash,
                    "error": state.last_error,
                },
            )
            return state, None, None

        chosen_mode = self._choose_mode_for_apply(
            state=state,
            dry_run=dry_run,
            explicit_mode=mode,
        )

        metadata = self._make_agent_metadata(
            state=state,
            reason=reason,
            action_kind="apply",
        )

        result = self._agent.apply_patch(
            patch_id=patch_id,
            dry_run=dry_run,
            mode=chosen_mode,
            metadata=metadata,
        )

        # Update state based on result.
        if getattr(result, "ok", False):
            state.status = PatchStatus.APPLIED
            state.applied_ts = getattr(result, "finished_at", now)
            state.last_error = None
            # Optional footprint hints from ControlAgent.
            state.apply_targets = getattr(result, "targets", None)
            state.canary_success = getattr(result, "canary_success", None)
            state.promotion_ts = getattr(result, "promotion_ts", None)
            state.apply_receipt = self._issue_patch_receipt(
                kind=self.config.apply_kind,
                state=state,
                result=result,
            )
        else:
            state.status = PatchStatus.FAILED
            state.last_error = getattr(result, "error", None) or "apply failed"
            state.apply_receipt = self._issue_patch_receipt(
                kind=self.config.apply_kind,
                state=state,
                result=result,
            )

            # Auto-rollback path (for non-dry runs).
            if self.config.auto_rollback_on_failure and not dry_run:
                rollback_state, rollback_receipt, _ = self.rollback_patch(
                    patch_id=patch_id,
                    reason="auto rollback after failed apply",
                    operator=operator,
                    environment=env,
                )
                state.rollback_receipt = rollback_receipt
                state.status = rollback_state.status
                state.rolled_back_ts = rollback_state.rolled_back_ts

        self._emit_telemetry_apply(
            state=state,
            ok=getattr(result, "ok", False),
            dry_run=dry_run,
            mode=chosen_mode,
            environment=env,
        )
        self._emit_audit_event(
            "tcd.patch.apply",
            {
                "patch_id": patch_id,
                "subject_id": state.descriptor.subject_id,
                "status": state.status.value,
                "dry_run": dry_run,
                "mode": getattr(chosen_mode, "value", str(chosen_mode)),
                "risk_level": state.descriptor.risk_level.value,
                "environment": env,
                "trust_zone": self.config.trust_zone,
                "operator_id_hash": state.last_operator_id_hash,
                "reason": reason,
                "error": state.last_error,
            },
        )

        return state, state.apply_receipt, result

    def rollback_patch(
        self,
        patch_id: str,
        *,
        reason: str = "",
        mode: Optional[ExecutionMode] = None,
        operator: Optional[OperatorId] = None,
        environment: Optional[str] = None,
    ) -> Tuple[PatchState, Optional[PatchReceiptRef], Optional[ActionResult]]:
        """
        Roll back a previously applied patch by id.

        Returns (PatchState, PatchReceiptRef | None, ActionResult | None).
        """
        state = self._require_patch(patch_id)
        env = environment or self.config.environment
        now = time.time()
        state.last_update_ts = now
        state.rollback_attempts += 1
        if operator is not None:
            state.last_operator_id_hash = operator.hash_id

        self._authorize("rollback", state, operator, env)

        if not self._agent:
            state.last_error = "ControlAgent not configured"
            state.status = PatchStatus.FAILED
            self._emit_audit_event(
                "tcd.patch.rollback.error",
                {
                    "patch_id": patch_id,
                    "subject_id": state.descriptor.subject_id,
                    "error": state.last_error,
                    "environment": env,
                    "trust_zone": self.config.trust_zone,
                    "operator_id_hash": state.last_operator_id_hash,
                },
            )
            self._emit_telemetry_rollback(
                state=state,
                ok=False,
                mode=None,
                environment=env,
            )
            return state, None, None

        chosen_mode = self._choose_mode_for_rollback(
            state=state,
            explicit_mode=mode,
        )

        metadata = self._make_agent_metadata(
            state=state,
            reason=reason,
            action_kind="rollback",
        )

        result = self._agent.rollback(
            patch_id=patch_id,
            mode=chosen_mode,
            metadata=metadata,
        )

        if getattr(result, "ok", False):
            state.status = PatchStatus.ROLLED_BACK
            state.rolled_back_ts = getattr(result, "finished_at", now)
            state.last_error = None
        else:
            state.status = PatchStatus.FAILED
            state.last_error = getattr(result, "error", None) or "rollback failed"

        receipt = self._issue_patch_receipt(
            kind=self.config.rollback_kind,
            state=state,
            result=result,
        )
        state.rollback_receipt = receipt

        self._emit_telemetry_rollback(
            state=state,
            ok=getattr(result, "ok", False),
            mode=chosen_mode,
            environment=env,
        )
        self._emit_audit_event(
            "tcd.patch.rollback",
            {
                "patch_id": patch_id,
                "subject_id": state.descriptor.subject_id,
                "status": state.status.value,
                "mode": getattr(chosen_mode, "value", str(chosen_mode)),
                "risk_level": state.descriptor.risk_level.value,
                "environment": env,
                "trust_zone": self.config.trust_zone,
                "operator_id_hash": state.last_operator_id_hash,
                "reason": reason,
                "error": state.last_error,
            },
        )

        return state, receipt, result

    # ------------------------------------------------------------------
    # Internal helpers: registration / lookup
    # ------------------------------------------------------------------

    def _register_state(self, state: PatchState) -> None:
        """
        Insert a PatchState into the internal registry, enforcing limits
        on global patch count and per-subject pending count.
        """
        patch_id = state.descriptor.patch_id
        subject_id = state.descriptor.subject_id

        # Enforce per-subject pending limit.
        pending_for_subject = [
            s
            for s in self._patches.values()
            if s.descriptor.subject_id == subject_id
            and s.status == PatchStatus.PENDING
        ]
        if (
            self.config.max_pending_per_subject > 0
            and len(pending_for_subject) >= self.config.max_pending_per_subject
        ):
            raise ValueError(
                f"too many pending patches for subject_id={subject_id!r}; "
                f"limit={self.config.max_pending_per_subject}"
            )

        # Insert/replace and track order.
        if patch_id not in self._patches:
            self._order.append(patch_id)
        self._patches[patch_id] = state

        # Enforce global max_patches.
        if len(self._order) > self.config.max_patches:
            excess = len(self._order) - self.config.max_patches
            for old_id in self._order[:excess]:
                self._patches.pop(old_id, None)
            self._order = self._order[excess:]

    def _find_by_subject_and_checksum(
        self,
        subject_id: str,
        checksum: str,
    ) -> Optional[PatchState]:
        """
        Look for an existing patch with the same subject_id and checksum.
        """
        for state in self._patches.values():
            if (
                state.descriptor.subject_id == subject_id
                and state.descriptor.checksum == checksum
            ):
                return state
        return None

    def _require_patch(self, patch_id: str) -> PatchState:
        """
        Retrieve a patch or raise a KeyError if it does not exist.
        """
        state = self._patches.get(patch_id)
        if state is None:
            raise KeyError(f"unknown patch_id={patch_id}")
        return state

    # ------------------------------------------------------------------
    # Internal helpers: checksum and identifiers
    # ------------------------------------------------------------------

    def _compute_checksum(self, subject: SubjectKey, patch_blob: bytes) -> str:
        """
        Compute a checksum over (subject, patch_blob).

        When RollingHasher is available and hash_alg == "blake3",
        this uses the shared hashing infrastructure with a fixed
        context string. Otherwise, it falls back to a standard hash
        algorithm as configured.
        """
        alg = (self.config.hash_alg or "blake3").lower()
        subject_id = subject.as_id().encode("utf-8", errors="ignore")

        if RollingHasher is not None and alg == "blake3":
            h = RollingHasher(alg="blake3", ctx="tcd:patch")
            h.update_bytes(subject_id)
            h.update_bytes(patch_blob)
            return h.hex()

        if alg == "sha1":
            if not self.config.allow_legacy_sha1:
                raise ValueError(
                    "hash_alg='sha1' is disabled by default; "
                    "set allow_legacy_sha1=True if this is intentional."
                )
            h2 = hashlib.sha1()
        elif alg == "sha256":
            h2 = hashlib.sha256()
        else:
            # Default to blake2s with a small digest to keep identifiers compact.
            h2 = hashlib.blake2s(digest_size=16)

        h2.update(subject_id)
        h2.update(patch_blob)
        return h2.hexdigest()

    def _make_patch_id(self, checksum: str) -> str:
        """
        Construct a patch identifier from the checksum.
        """
        short = checksum[:12] if checksum else "unknown"
        return f"{self.config.patch_id_prefix}-{short}"

    # ------------------------------------------------------------------
    # Internal helpers: ExecutionMode and metadata
    # ------------------------------------------------------------------

    def _choose_mode_for_apply(
        self,
        *,
        state: PatchState,
        dry_run: bool,
        explicit_mode: Optional[ExecutionMode],
    ) -> Any:
        """
        Decide which ExecutionMode to use for apply_patch(), given
        risk_level, dry_run flag and explicit override.
        """
        if explicit_mode is not None:
            return explicit_mode

        # Dry-run normally uses a "canary" / safe mode when available.
        if dry_run:
            if self.config.canary_mode_default is not None:
                return self.config.canary_mode_default
            # Best-effort guess from ExecutionMode.
            if hasattr(ExecutionMode, "CANARY"):
                return ExecutionMode.CANARY  # type: ignore
            return getattr(ExecutionMode, "SAFE", ExecutionMode)  # type: ignore

        # Non-dry-run: choose based on risk.
        lvl = state.descriptor.risk_level
        if lvl == PatchRiskLevel.HIGH and self.config.require_canary_for_high_risk:
            # For high-risk patches, prefer canary-like mode even if not dry_run.
            if self.config.canary_mode_default is not None:
                return self.config.canary_mode_default
            if hasattr(ExecutionMode, "CANARY"):
                return ExecutionMode.CANARY  # type: ignore

        if self.config.production_mode_default is not None:
            return self.config.production_mode_default
        if hasattr(ExecutionMode, "PRODUCTION"):
            return ExecutionMode.PRODUCTION  # type: ignore

        # Fallback when ExecutionMode is a simple type alias.
        return ExecutionMode  # type: ignore

    def _choose_mode_for_rollback(
        self,
        *,
        state: PatchState,
        explicit_mode: Optional[ExecutionMode],
    ) -> Any:
        """
        Decide which ExecutionMode to use for rollback().
        """
        if explicit_mode is not None:
            return explicit_mode

        # Rollback is usually a production-path operation.
        if self.config.production_mode_default is not None:
            return self.config.production_mode_default
        if hasattr(ExecutionMode, "PRODUCTION"):
            return ExecutionMode.PRODUCTION  # type: ignore
        return ExecutionMode  # type: ignore

    def _make_agent_metadata(
        self,
        *,
        state: PatchState,
        reason: str,
        action_kind: str,
    ) -> Dict[str, Any]:
        """
        Construct metadata passed to ControlAgent.apply_patch / rollback.

        This metadata is distinct from receipt payloads; it is intended
        for the agent's internal logs and decision logic and must not
        contain secrets.
        """
        return {
            "patch_id": state.descriptor.patch_id,
            "subject_id": state.descriptor.subject_id,
            "reason": reason,
            "risk_level": state.descriptor.risk_level.value,
            "action_kind": action_kind,
            "origin": state.descriptor.origin,
            "patch_kind": state.descriptor.patch_kind.value,
            "artifact_digest": state.descriptor.artifact_digest,
            "allowed_envs": state.descriptor.allowed_envs,
            "allowed_trust_zones": state.descriptor.allowed_trust_zones,
            "change_ticket_id": state.descriptor.change_ticket_id,
        }

    # ------------------------------------------------------------------
    # Internal helpers: authorization / approvals / artifacts
    # ------------------------------------------------------------------

    def _authorize(
        self,
        action: str,
        obj: Union[PatchDescriptor, PatchState],
        operator: Optional[OperatorId],
        environment: Optional[str],
    ) -> None:
        """
        Invoke the configured authorization hook, if any.
        """
        fn = self.config.authorize_fn
        if not fn:
            return
        try:
            fn(action, obj, operator, environment)
        except Exception:
            # Re-raise to let callers see the denial.
            raise

    def _enforce_approvals_before_apply(self, state: PatchState) -> None:
        """
        Ensure required approvals are present before applying a patch.
        """
        required = max(0, state.descriptor.required_approvals)
        if required == 0:
            return
        if len(state.approvals) < required:
            raise PermissionError(
                f"patch_id={state.descriptor.patch_id} requires "
                f"{required} approvals, but only {len(state.approvals)} recorded"
            )

    def _verify_artifact_on_register(self, descriptor: PatchDescriptor) -> None:
        """
        Optionally verify artifact attestation during register_patch.
        """
        if not self._attestor or not self.config.verify_artifact_on_register:
            return

        digest = descriptor.artifact_digest or descriptor.metadata.get("artifact_digest")
        if not digest:
            return

        verifier = getattr(self._attestor, "verify_artifact", None)
        if not callable(verifier):
            return

        try:
            result = verifier(digest, descriptor.metadata)
        except Exception:
            status = "error"
            attestation_id = None
        else:
            status = result.get("status", "unknown") if isinstance(result, dict) else "unknown"
            attestation_id = result.get("attestation_id") if isinstance(result, dict) else None

        descriptor.metadata["attestation_status"] = status
        if attestation_id is not None:
            descriptor.metadata["attestation_id"] = attestation_id

        if self.config.require_verified_artifact_on_register and status != "verified":
            raise ValueError(
                f"artifact verification failed at register time for digest={digest!r}, status={status!r}"
            )

        # If verification is not strictly required but status is not "verified",
        # bump risk level to HIGH as an extra safety margin.
        if status != "verified" and descriptor.risk_level != PatchRiskLevel.HIGH:
            descriptor.risk_level = PatchRiskLevel.HIGH

    def _verify_artifact_on_apply(self, state: PatchState) -> bool:
        """
        Optionally re-verify artifact attestation at apply time.

        Returns True when it is acceptable to proceed with apply; False
        when the artifact should block the operation.
        """
        if not self._attestor or not self.config.verify_artifact_on_apply:
            return True

        digest = (
            state.descriptor.artifact_digest
            or state.descriptor.metadata.get("artifact_digest")
        )
        if not digest:
            return True

        verifier = getattr(self._attestor, "verify_artifact", None)
        if not callable(verifier):
            return True

        try:
            result = verifier(digest, state.descriptor.metadata)
        except Exception:
            status = "error"
            attestation_id = None
        else:
            status = result.get("status", "unknown") if isinstance(result, dict) else "unknown"
            attestation_id = result.get("attestation_id") if isinstance(result, dict) else None

        state.descriptor.metadata["attestation_status"] = status
        if attestation_id is not None:
            state.descriptor.metadata["attestation_id"] = attestation_id

        if self.config.require_verified_artifact_on_apply and status != "verified":
            state.status = PatchStatus.FAILED
            state.last_error = (
                f"artifact verification failed at apply time for digest={digest!r}, status={status!r}"
            )
            return False

        # If verification is not strictly required but status is not "verified",
        # keep going but raise effective risk.
        if status != "verified" and state.descriptor.risk_level != PatchRiskLevel.HIGH:
            state.descriptor.risk_level = PatchRiskLevel.HIGH

        return True

    # ------------------------------------------------------------------
    # Internal helpers: receipts and telemetry
    # ------------------------------------------------------------------

    def _issue_patch_receipt(
        self,
        *,
        kind: str,
        state: PatchState,
        result: ActionResult,
    ) -> Optional[PatchReceiptRef]:
        """
        Ask Attestor to issue a receipt covering this patch operation.

        The receipt binds:
          - patch descriptor (subject, checksum, risk, origin, artifact);
          - operation payload (kind, status, result summary);
          - a simple e-process snapshot with fixed defaults or allocator.

        When no Attestor is configured, returns None.
        """
        if self._attestor is None:
            return None

        try:
            # Compacted result payload for the receipt.
            payload = {
                "kind": kind,
                "patch_id": state.descriptor.patch_id,
                "subject_id": state.descriptor.subject_id,
                "patch_kind": state.descriptor.patch_kind.value,
                "status": state.status.value,
                "risk_level": state.descriptor.risk_level.value,
                "origin": state.descriptor.origin,
                "ok": bool(getattr(result, "ok", False)),
                "action": str(getattr(result, "action", "")),
                "mode": getattr(getattr(result, "mode", ""), "value", str(getattr(result, "mode", ""))),
                "duration_ms": float(getattr(result, "duration_ms", lambda: 0.0)()),
                "error": getattr(result, "error", None),
            }

            if self.config.minimize_receipt_metadata:
                patch_meta = {
                    "patch_id": state.descriptor.patch_id,
                    "subject_id": state.descriptor.subject_id,
                    "checksum": state.descriptor.checksum,
                    "risk_level": state.descriptor.risk_level.value,
                    "patch_kind": state.descriptor.patch_kind.value,
                }
            else:
                patch_meta = state.descriptor.to_dict()

            req_obj = {
                "ts": time.time(),
                "patch": patch_meta,
            }
            comp_obj = payload

            # Decide e-process values.
            e_fields: Dict[str, float]
            if self.config.e_allocator is not None:
                try:
                    e_fields = self.config.e_allocator(state, result)
                except Exception:
                    e_fields = {}
            else:
                e_fields = {}

            e_obj = {
                "e_value": float(e_fields.get("e_value", self.config.e_default_value)),
                "alpha_alloc": float(
                    e_fields.get("alpha_alloc", self.config.e_default_alpha_alloc)
                ),
                "alpha_wealth": float(
                    e_fields.get("alpha_wealth", self.config.e_default_alpha_wealth)
                ),
                "threshold": float(
                    e_fields.get("threshold", self.config.e_default_threshold)
                ),
                "trigger": bool(e_fields.get("trigger", False)),
            }

            meta = {
                "type": "patch_runtime",
                "kind": kind,
                "patch_id": state.descriptor.patch_id,
                "subject_id": state.descriptor.subject_id,
                "risk_level": state.descriptor.risk_level.value,
                "environment": self.config.environment,
                "trust_zone": self.config.trust_zone,
            }
            if self.config.e_process_id is not None:
                meta["e_process_id"] = self.config.e_process_id

            # Optionally surface crypto-related metadata if Attestor exposes it.
            crypto_profile = getattr(self._attestor, "crypto_profile", None)
            sig_scheme = getattr(self._attestor, "signature_scheme", None)
            if crypto_profile is not None:
                meta["crypto_profile"] = crypto_profile
            if sig_scheme is not None:
                meta["signature_scheme"] = sig_scheme

            receipt = self._attestor.issue(
                req_obj=req_obj,
                comp_obj=comp_obj,
                e_obj=e_obj,
                witness_segments=None,
                witness_tags=None,
                meta=meta,
            )

            return PatchReceiptRef(
                receipt_head=receipt.get("receipt"),
                receipt_body=receipt.get("receipt_body"),
                receipt_sig=receipt.get("receipt_sig"),
                verify_key=receipt.get("verify_key"),
            )
        except Exception:
            # Failing to issue a receipt must not break the main control flow.
            return None

    # Telemetry helpers -------------------------------------------------

    def _emit_telemetry_register(
        self,
        state: PatchState,
        operator: Optional[OperatorId],
        environment: str,
    ) -> None:
        exporter = self.config.telemetry
        if not exporter or not self.config.telemetry_emit_register_events:
            return

        attrs = {
            "patch_id": state.descriptor.patch_id,
            "subject_id": state.descriptor.subject_id,
            "patch_kind": state.descriptor.patch_kind.value,
            "risk_level": state.descriptor.risk_level.value,
            "environment": environment,
            "trust_zone": self.config.trust_zone,
            "operator_id_hash": operator.hash_id if operator is not None else None,
        }

        exporter.record_metric(
            name="tcd.patch.register.count",
            value=1.0,
            labels=attrs,
        )
        exporter.push_event(
            name="tcd.patch.register",
            attrs=attrs,
        )

    def _emit_telemetry_approve(
        self,
        state: PatchState,
        operator: OperatorId,
        environment: str,
    ) -> None:
        exporter = self.config.telemetry
        if not exporter or not self.config.telemetry_emit_approve_events:
            return

        attrs = {
            "patch_id": state.descriptor.patch_id,
            "subject_id": state.descriptor.subject_id,
            "patch_kind": state.descriptor.patch_kind.value,
            "risk_level": state.descriptor.risk_level.value,
            "environment": environment,
            "trust_zone": self.config.trust_zone,
            "operator_id_hash": operator.hash_id,
            "approval_count": len(state.approvals),
        }

        exporter.record_metric(
            name="tcd.patch.approve.count",
            value=1.0,
            labels=attrs,
        )
        exporter.push_event(
            name="tcd.patch.approve",
            attrs=attrs,
        )

    def _emit_telemetry_apply(
        self,
        *,
        state: PatchState,
        ok: bool,
        dry_run: bool,
        mode: Any,
        environment: str,
    ) -> None:
        """
        Emit telemetry for apply_patch().
        """
        exporter = self.config.telemetry
        if not exporter or not self.config.telemetry_emit_apply_events:
            return

        attrs = {
            "patch_id": state.descriptor.patch_id,
            "subject_id": state.descriptor.subject_id,
            "patch_kind": state.descriptor.patch_kind.value,
            "risk_level": state.descriptor.risk_level.value,
            "status": state.status.value,
            "dry_run": dry_run,
            "mode": getattr(mode, "value", str(mode)) if mode is not None else None,
            "environment": environment,
            "trust_zone": self.config.trust_zone,
            "operator_id_hash": state.last_operator_id_hash,
            "ok": bool(ok),
        }

        # Metric: count of apply operations.
        exporter.record_metric(
            name="tcd.patch.apply.count",
            value=1.0,
            labels=attrs,
        )

        # Event: detailed apply operation summary.
        exporter.push_event(
            name="tcd.patch.apply",
            attrs=dict(attrs, error=state.last_error),
        )

    def _emit_telemetry_rollback(
        self,
        *,
        state: PatchState,
        ok: bool,
        mode: Any,
        environment: str,
    ) -> None:
        """
        Emit telemetry for rollback_patch().
        """
        exporter = self.config.telemetry
        if not exporter or not self.config.telemetry_emit_rollback_events:
            return

        attrs = {
            "patch_id": state.descriptor.patch_id,
            "subject_id": state.descriptor.subject_id,
            "patch_kind": state.descriptor.patch_kind.value,
            "risk_level": state.descriptor.risk_level.value,
            "status": state.status.value,
            "mode": getattr(mode, "value", str(mode)) if mode is not None else None,
            "environment": environment,
            "trust_zone": self.config.trust_zone,
            "operator_id_hash": state.last_operator_id_hash,
            "ok": bool(ok),
        }

        exporter.record_metric(
            name="tcd.patch.rollback.count",
            value=1.0,
            labels=attrs,
        )

        exporter.push_event(
            name="tcd.patch.rollback",
            attrs=dict(attrs, error=state.last_error),
        )

    def _emit_audit_event(self, event_name: str, payload: Dict[str, Any]) -> None:
        """
        Send a coarse-grained audit event to the configured audit_hook, if any.
        """
        hook = self.config.audit_hook
        if not hook:
            return
        try:
            hook(event_name, payload)
        except Exception:
            # Audit hooks must not break primary flows.
            pass


__all__ = [
    "PatchStatus",
    "PatchRiskLevel",
    "PatchKind",
    "OperatorId",
    "PatchDescriptor",
    "PatchReceiptRef",
    "PatchState",
    "PatchRuntimeConfig",
    "PatchRuntime",
]