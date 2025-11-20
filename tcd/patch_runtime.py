# tcd/patch_runtime.py
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

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


class PatchStatus(str, Enum):
    PENDING = "pending"
    APPLIED = "applied"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class PatchRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class PatchDescriptor:
    patch_id: str
    subject_id: str
    description: str
    origin: str
    created_ts: float
    checksum: str
    risk_level: PatchRiskLevel = PatchRiskLevel.LOW
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "patch_id": self.patch_id,
            "subject_id": self.subject_id,
            "description": self.description,
            "origin": self.origin,
            "created_ts": self.created_ts,
            "checksum": self.checksum,
            "risk_level": self.risk_level.value,
            "metadata": self.metadata,
        }


@dataclass
class PatchReceiptRef:
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
    descriptor: PatchDescriptor
    status: PatchStatus = PatchStatus.PENDING

    last_update_ts: float = field(default_factory=lambda: time.time())
    last_error: Optional[str] = None

    applied_ts: Optional[float] = None
    rolled_back_ts: Optional[float] = None

    apply_receipt: Optional[PatchReceiptRef] = None
    rollback_receipt: Optional[PatchReceiptRef] = None

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
        }


@dataclass
class PatchRuntimeConfig:
    auto_rollback_on_failure: bool = True
    max_patches: int = 1_000
    hash_alg: str = "blake3"
    receipts_enable: bool = True
    patch_id_prefix: str = "patch"

    apply_kind: str = "apply_patch"
    rollback_kind: str = "rollback"


class PatchRuntime:
    """
    PatchRuntime coordinates safe patch application and rollback.

    It does not perform file edits directly. Instead, it delegates the
    actual operations to a ControlAgent and focuses on:
      - tracking patch states;
      - orchestrating apply → rollback flows;
      - issuing receipts for auditing.
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

        self._patches: Dict[str, PatchState] = {}
        self._order: List[str] = []

    # ------------------------------------------------------------------
    # Registration / lookup
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
    ) -> PatchState:
        checksum = self._compute_checksum(subject, patch_blob)
        patch_id = self._make_patch_id(checksum)

        descriptor = PatchDescriptor(
            patch_id=patch_id,
            subject_id=subject.as_id(),
            description=description,
            origin=origin,
            created_ts=time.time(),
            checksum=checksum,
            risk_level=risk_level,
            metadata=metadata or {},
        )

        state = PatchState(descriptor=descriptor, status=PatchStatus.PENDING)
        self._patches[patch_id] = state
        self._order.append(patch_id)

        if len(self._order) > self.config.max_patches:
            excess = len(self._order) - self.config.max_patches
            for old_id in self._order[:excess]:
                self._patches.pop(old_id, None)
            self._order = self._order[excess:]

        return state

    def get_patch(self, patch_id: str) -> Optional[PatchState]:
        return self._patches.get(patch_id)

    def list_patches(self) -> List[PatchState]:
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
    ) -> Tuple[PatchState, Optional[PatchReceiptRef], Optional[ActionResult]]:
        state = self._require_patch(patch_id)
        now = time.time()
        state.last_update_ts = now

        if not self._agent:
            state.last_error = "ControlAgent not configured"
            state.status = PatchStatus.FAILED
            return state, None, None

        metadata = {
            "patch_id": patch_id,
            "subject_id": state.descriptor.subject_id,
            "reason": reason,
            "risk_level": state.descriptor.risk_level.value,
        }

        if mode is None:
            mode = ExecutionMode.CANARY if dry_run else ExecutionMode.PRODUCTION

        result = self._agent.apply_patch(
            patch_id=patch_id,
            dry_run=dry_run,
            mode=mode,
            metadata=metadata,
        )

        if result.ok:
            state.status = PatchStatus.APPLIED
            state.applied_ts = result.finished_at
            state.last_error = None
            state.apply_receipt = self._issue_patch_receipt(
                kind=self.config.apply_kind,
                state=state,
                result=result,
            )
        else:
            state.status = PatchStatus.FAILED
            state.last_error = result.error or "apply failed"
            state.apply_receipt = self._issue_patch_receipt(
                kind=self.config.apply_kind,
                state=state,
                result=result,
            )
            if self.config.auto_rollback_on_failure and not dry_run:
                rollback_state, rollback_receipt, _ = self.rollback_patch(
                    patch_id=patch_id,
                    reason="auto rollback after failed apply",
                )
                state.rollback_receipt = rollback_receipt
                state.status = rollback_state.status
                state.rolled_back_ts = rollback_state.rolled_back_ts

        return state, state.apply_receipt, result

    def rollback_patch(
        self,
        patch_id: str,
        *,
        reason: str = "",
        mode: Optional[ExecutionMode] = None,
    ) -> Tuple[PatchState, Optional[PatchReceiptRef], Optional[ActionResult]]:
        state = self._require_patch(patch_id)
        now = time.time()
        state.last_update_ts = now

        if not self._agent:
            state.last_error = "ControlAgent not configured"
            state.status = PatchStatus.FAILED
            return state, None, None

        metadata = {
            "patch_id": patch_id,
            "subject_id": state.descriptor.subject_id,
            "reason": reason,
            "risk_level": state.descriptor.risk_level.value,
        }

        if mode is None:
            mode = ExecutionMode.PRODUCTION

        result = self._agent.rollback(
            patch_id=patch_id,
            mode=mode,
            metadata=metadata,
        )

        if result.ok:
            state.status = PatchStatus.ROLLED_BACK
            state.rolled_back_ts = result.finished_at
            state.last_error = None
        else:
            state.status = PatchStatus.FAILED
            state.last_error = result.error or "rollback failed"

        receipt = self._issue_patch_receipt(
            kind=self.config.rollback_kind,
            state=state,
            result=result,
        )
        state.rollback_receipt = receipt
        return state, receipt, result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _require_patch(self, patch_id: str) -> PatchState:
        state = self._patches.get(patch_id)
        if state is None:
            raise KeyError(f"unknown patch_id={patch_id}")
        return state

    def _compute_checksum(self, subject: SubjectKey, patch_blob: bytes) -> str:
        alg = (self.config.hash_alg or "blake3").lower()
        subject_id = subject.as_id().encode("utf-8", errors="ignore")

        if RollingHasher is not None and alg == "blake3":
            h = RollingHasher(alg="blake3", ctx="tcd:patch")
            h.update_bytes(subject_id)
            h.update_bytes(patch_blob)
            return h.hex()

        if alg == "sha256":
            h2 = hashlib.sha256()
        elif alg == "sha1":
            h2 = hashlib.sha1()
        else:
            h2 = hashlib.blake2s(digest_size=16)

        h2.update(subject_id)
        h2.update(patch_blob)
        return h2.hexdigest()

    def _make_patch_id(self, checksum: str) -> str:
        short = checksum[:12] if checksum else "unknown"
        return f"{self.config.patch_id_prefix}-{short}"

    def _issue_patch_receipt(
        self,
        *,
        kind: str,
        state: PatchState,
        result: ActionResult,
    ) -> Optional[PatchReceiptRef]:
        if self._attestor is None:
            return None

        try:
            payload = {
                "kind": kind,
                "patch_id": state.descriptor.patch_id,
                "subject_id": state.descriptor.subject_id,
                "status": state.status.value,
                "risk_level": state.descriptor.risk_level.value,
                "origin": state.descriptor.origin,
                "ok": bool(result.ok),
                "action": str(result.action),
                "mode": getattr(result.mode, "value", str(result.mode)),
                "duration_ms": float(result.duration_ms()),
                "error": result.error,
            }

            req_obj = {
                "ts": time.time(),
                "patch": state.descriptor.to_dict(),
            }
            comp_obj = payload
            e_obj = {
                "e_value": 1.0,
                "alpha_alloc": 0.0,
                "alpha_wealth": 0.0,
                "threshold": 0.0,
                "trigger": False,
            }

            meta = {
                "type": "patch_runtime",
                "kind": kind,
                "patch_id": state.descriptor.patch_id,
                "subject_id": state.descriptor.subject_id,
                "risk_level": state.descriptor.risk_level.value,
            }

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
            return None