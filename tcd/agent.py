# FILE: tcd/agent.py
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from prometheus_client import Counter, Histogram

from .rewrite_engine import PatchProposal

logger = logging.getLogger("tcd.agent")

# Optional attestation and ledger backends. These are wired by the control
# plane and are not required for basic in-process usage.
try:
    from .attest import Attestor, AttestorConfig, canonical_kv_hash  # type: ignore
except Exception:  # pragma: no cover
    Attestor = None  # type: ignore[assignment]
    AttestorConfig = None  # type: ignore[assignment]
    canonical_kv_hash = None  # type: ignore[assignment]

try:
    from .audit import AuditLedger  # type: ignore
except Exception:  # pragma: no cover
    AuditLedger = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


_AGENT_LATENCY = Histogram(
    "tcd_agent_action_latency_ms",
    "Latency of TrustAgent actions (ms)",
    buckets=(1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000),
    labelnames=("action", "mode", "ok"),
)

_AGENT_TOTAL = Counter(
    "tcd_agent_action_total",
    "Total TrustAgent actions",
    labelnames=("action", "mode", "ok"),
)

_AGENT_ERROR = Counter(
    "tcd_agent_action_error_total",
    "Errors from TrustAgent actions",
    labelnames=("action", "kind"),
)

_AGENT_ATTEST_ERROR = Counter(
    "tcd_agent_attestation_error_total",
    "Attestation failures in TrustAgent",
    labelnames=("action",),
)

_AGENT_LEDGER_ERROR = Counter(
    "tcd_agent_ledger_error_total",
    "Ledger append failures in TrustAgent",
    labelnames=("action",),
)


# ---------------------------------------------------------------------------
# Core types
# ---------------------------------------------------------------------------


class ExecutionMode(str, Enum):
    """
    Execution mode for change actions.
    """

    DRY_RUN = "dry_run"
    CANARY = "canary"
    PRODUCTION = "production"


@dataclass
class ActionContext:
    """
    Lightweight envelope describing the origin of a change request.
    """

    request_id: str = ""
    session_id: str = ""
    tenant: str = ""
    user: str = ""
    component: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "tenant": self.tenant,
            "user": self.user,
            "component": self.component,
            "metadata": self.metadata,
        }


@dataclass
class ActionResult:
    """
    Normalized outcome for a single TrustAgent action.
    """

    action_id: str
    action: str
    mode: ExecutionMode
    ok: bool
    started_at: float
    finished_at: float
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    context: Optional[ActionContext] = None

    # Attestation fields (optional, filled when attestation is enabled).
    receipt: Optional[str] = None
    receipt_body: Optional[str] = None
    receipt_sig: Optional[str] = None
    verify_key: Optional[str] = None

    def duration_ms(self) -> float:
        return max(0.0, (self.finished_at - self.started_at) * 1000.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action": self.action,
            "mode": self.mode.value,
            "ok": self.ok,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms(),
            "details": self.details,
            "context": self.context.to_dict() if self.context else None,
            "receipt": self.receipt,
            "receipt_body": self.receipt_body,
            "receipt_sig": self.receipt_sig,
            "verify_key": self.verify_key,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


@dataclass
class AgentConfig:
    """
    Policy surface for TrustAgent.

    All fields are intended to be low-cardinality and suitable for hashing
    into a stable policy digest.
    """

    # Behavioral knobs
    default_mode: ExecutionMode = ExecutionMode.DRY_RUN
    allow_auto_patch: bool = False
    allow_restart: bool = False
    allow_reload_config: bool = False
    allow_rollback: bool = False
    allow_key_rotation: bool = False
    allow_model_calibration: bool = False
    allow_policy_update: bool = False

    max_patch_hunks: int = 16
    max_patch_size_bytes: int = 128_000

    # Global safety profile
    strict_mode: bool = False
    attestation_enabled: bool = False
    require_attestor: bool = True
    require_ledger: bool = True
    allowed_modes: Optional[List[ExecutionMode]] = None
    max_action_duration_s: float = 30.0
    max_audit_log_entries: int = 1024

    # Change-governance and abuse-resistance
    require_change_ticket: bool = False
    require_human_approver: bool = False
    require_mfa_tag: bool = False
    forbidden_actions: Optional[List[str]] = None
    approval_system_allowlist: Optional[List[str]] = None
    per_action_guards: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # PQ / supply-chain binding
    require_pq_attestor: bool = False
    allowed_sig_algs: Optional[List[str]] = None
    supply_chain_label: str = ""
    node_id: str = ""
    proc_id: str = ""
    image_digest: str = ""
    build_id: str = ""

    def digest_material(self) -> Dict[str, Any]:
        """
        Stable material for a policy digest.
        """
        return {
            "default_mode": self.default_mode.value,
            "allow_auto_patch": bool(self.allow_auto_patch),
            "allow_restart": bool(self.allow_restart),
            "allow_reload_config": bool(self.allow_reload_config),
            "allow_rollback": bool(self.allow_rollback),
            "allow_key_rotation": bool(self.allow_key_rotation),
            "allow_model_calibration": bool(self.allow_model_calibration),
            "allow_policy_update": bool(self.allow_policy_update),
            "max_patch_hunks": int(self.max_patch_hunks),
            "max_patch_size_bytes": int(self.max_patch_size_bytes),
            "strict_mode": bool(self.strict_mode),
            "attestation_enabled": bool(self.attestation_enabled),
            "require_attestor": bool(self.require_attestor),
            "require_ledger": bool(self.require_ledger),
            "allowed_modes": [m.value for m in self.allowed_modes] if self.allowed_modes else [],
            "max_action_duration_s": float(self.max_action_duration_s),
            "max_audit_log_entries": int(self.max_audit_log_entries),
            "require_change_ticket": bool(self.require_change_ticket),
            "require_human_approver": bool(self.require_human_approver),
            "require_mfa_tag": bool(self.require_mfa_tag),
            "forbidden_actions": list(self.forbidden_actions or []),
            "approval_system_allowlist": list(self.approval_system_allowlist or []),
            "require_pq_attestor": bool(self.require_pq_attestor),
            "allowed_sig_algs": list(self.allowed_sig_algs or []),
            "supply_chain_label": self.supply_chain_label,
            "node_id": self.node_id,
            "proc_id": self.proc_id,
            "image_digest": self.image_digest,
            "build_id": self.build_id,
        }


# ---------------------------------------------------------------------------
# TrustAgent
# ---------------------------------------------------------------------------


class TrustAgent:
    """
    Hardened execution shell for control-plane actions.

    It does not perform any environment-specific mutations by itself; all
    side effects are delegated to injected callbacks. Every action produces
    a structured ActionResult and, when enabled, an attestation and ledger
    event that bind the action to a policy digest and supply-chain view.
    """

    def __init__(
        self,
        config: AgentConfig,
        *,
        apply_patch_cb: Optional[Callable[[PatchProposal, ExecutionMode, ActionContext | None], Any]] = None,
        restart_cb: Optional[Callable[[ActionContext | None], Any]] = None,
        reload_config_cb: Optional[Callable[[ActionContext | None], Any]] = None,
        rollback_cb: Optional[Callable[[ActionContext | None], Any]] = None,
        rotate_keys_cb: Optional[Callable[[ActionContext | None], Any]] = None,
        calibrate_model_cb: Optional[Callable[[ActionContext | None], Any]] = None,
        update_policies_cb: Optional[Callable[[ActionContext | None], Any]] = None,
        attestor: Optional[Any] = None,
        attestor_cfg: Optional[Any] = None,
        ledger: Optional[Any] = None,
        risk_oracle: Optional[Any] = None,
    ) -> None:
        self.config = config

        self._apply_patch_cb = apply_patch_cb
        self._restart_cb = restart_cb
        self._reload_config_cb = reload_config_cb
        self._rollback_cb = rollback_cb
        self._rotate_keys_cb = rotate_keys_cb
        self._calibrate_model_cb = calibrate_model_cb
        self._update_policies_cb = update_policies_cb

        self._attestor = attestor
        self._attestor_cfg = attestor_cfg
        self._ledger = ledger
        self._risk_oracle = risk_oracle

        self._audit_log: List[ActionResult] = []

        material = self.config.digest_material()
        if canonical_kv_hash is not None:
            try:
                self._policy_digest: str = canonical_kv_hash(
                    material,
                    ctx="tcd:agent_cfg",
                    label="tcd_agent_cfg",
                )
            except Exception:  # pragma: no cover
                logger.error("failed to compute TrustAgent policy digest; falling back to repr()")
                self._policy_digest = "agent_cfg:" + repr(material)
        else:
            self._policy_digest = "agent_cfg:" + repr(material)

        # Strict profile: enforce attestor / ledger / PQ requirements.
        if self.config.strict_mode:
            if self.config.attestation_enabled and self.config.require_attestor and self._attestor is None:
                raise RuntimeError("TrustAgent strict_mode requires an Attestor when attestation_enabled=True")
            if self.config.require_ledger and self._ledger is None:
                raise RuntimeError("TrustAgent strict_mode requires an AuditLedger")
            if self.config.attestation_enabled and self.config.require_pq_attestor:
                if self._attestor_cfg is None:
                    raise RuntimeError(
                        "TrustAgent strict_mode requires AttestorConfig when require_pq_attestor=True"
                    )
                sig_alg = getattr(self._attestor_cfg, "sig_alg", None)
                if not sig_alg:
                    raise RuntimeError("TrustAgent strict_mode requires sig_alg on AttestorConfig")
                if self.config.allowed_sig_algs and sig_alg not in self.config.allowed_sig_algs:
                    raise RuntimeError(f"Attestor sig_alg {sig_alg!r} not in allowed_sig_algs")

    # ------------------------------------------------------------------
    # Public inspection API
    # ------------------------------------------------------------------

    @property
    def policy_digest(self) -> str:
        return self._policy_digest

    @property
    def audit_log(self) -> List[ActionResult]:
        return list(self._audit_log)

    def last_result(self) -> Optional[ActionResult]:
        return self._audit_log[-1] if self._audit_log else None

    # ------------------------------------------------------------------
    # Core actions
    # ------------------------------------------------------------------

    def apply_patch(
        self,
        patch: PatchProposal,
        *,
        mode: Optional[ExecutionMode] = None,
        context: Optional[ActionContext] = None,
    ) -> ActionResult:
        """
        Apply a patch proposal according to policy and execution mode.
        """
        action = "apply_patch"
        mode = mode or self.config.default_mode
        started = time.time()

        if context is None:
            context = ActionContext(request_id=self._default_request_id())

        result = ActionResult(
            action_id=self._new_action_id(),
            action=action,
            mode=mode,
            ok=False,
            started_at=started,
            finished_at=started,
            error=None,
            details={
                "patch_id": patch.patch_id,
                "patch_risk": getattr(patch.risk, "value", str(patch.risk)),
                "hunk_count": len(patch.hunks),
                "effect_scope": mode.value,
            },
            context=context,
        )

        if self._blocked_by_mode_or_action(result):
            return self._wrap_up(result)

        if self._blocked_by_context_guards(result):
            return self._wrap_up(result)

        try:
            if len(patch.hunks) > self.config.max_patch_hunks:
                result.error = "patch too large: too many hunks"
                result.details["reason"] = "patch_hunk_limit"
                return self._wrap_up(result)

            encoded = patch.to_json().encode("utf-8")
            if len(encoded) > self.config.max_patch_size_bytes:
                result.error = "patch too large: exceeds byte limit"
                result.details["reason"] = "patch_size_limit"
                return self._wrap_up(result)

            if mode is ExecutionMode.DRY_RUN or not self.config.allow_auto_patch:
                result.ok = True
                result.details["applied"] = False
                result.details["reason"] = "dry_run_or_not_allowed"
                return self._wrap_up(result)

            if not self._apply_patch_cb:
                result.error = "no apply_patch callback configured"
                result.details["reason"] = "no_callback"
                return self._wrap_up(result)

            self._apply_patch_cb(patch, mode, context)
            result.ok = True
            result.details["applied"] = True
            return self._wrap_up(result)

        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.details["reason"] = "exception"
            _AGENT_ERROR.labels(action, "exception").inc()
            return self._wrap_up(result)

    def restart(
        self,
        *,
        mode: Optional[ExecutionMode] = None,
        context: Optional[ActionContext] = None,
    ) -> ActionResult:
        """
        Request a service restart.
        """
        return self._simple_action(
            action="restart",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_restart,
            callback=self._restart_cb,
        )

    def reload_config(
        self,
        *,
        mode: Optional[ExecutionMode] = None,
        context: Optional[ActionContext] = None,
    ) -> ActionResult:
        """
        Request a configuration reload.
        """
        return self._simple_action(
            action="reload_config",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_reload_config,
            callback=self._reload_config_cb,
        )

    def rollback(
        self,
        *,
        mode: Optional[ExecutionMode] = None,
        context: Optional[ActionContext] = None,
    ) -> ActionResult:
        """
        Request rollback to a previously known-good state.
        """
        return self._simple_action(
            action="rollback",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_rollback,
            callback=self._rollback_cb,
        )

    def rotate_keys(
        self,
        *,
        mode: Optional[ExecutionMode] = None,
        context: Optional[ActionContext] = None,
    ) -> ActionResult:
        """
        Trigger rotation of sensitive keys or credentials.
        """
        return self._simple_action(
            action="rotate_keys",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_key_rotation,
            callback=self._rotate_keys_cb,
        )

    def calibrate_model(
        self,
        *,
        mode: Optional[ExecutionMode] = None,
        context: Optional[ActionContext] = None,
    ) -> ActionResult:
        """
        Trigger recalibration of safety / risk models.
        """
        return self._simple_action(
            action="calibrate_model",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_model_calibration,
            callback=self._calibrate_model_cb,
        )

    def update_policies(
        self,
        *,
        mode: Optional[ExecutionMode] = None,
        context: Optional[ActionContext] = None,
    ) -> ActionResult:
        """
        Trigger reload or recompilation of safety policies.
        """
        return self._simple_action(
            action="update_policies",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_policy_update,
            callback=self._update_policies_cb,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _simple_action(
        self,
        *,
        action: str,
        mode: Optional[ExecutionMode],
        context: Optional[ActionContext],
        allow_flag: bool,
        callback: Optional[Callable[[ActionContext | None], Any]],
    ) -> ActionResult:
        mode = mode or self.config.default_mode
        started = time.time()

        if context is None:
            context = ActionContext(request_id=self._default_request_id())

        result = ActionResult(
            action_id=self._new_action_id(),
            action=action,
            mode=mode,
            ok=False,
            started_at=started,
            finished_at=started,
            error=None,
            details={},
            context=context,
        )

        if self._blocked_by_mode_or_action(result):
            return self._wrap_up(result)

        if self._blocked_by_context_guards(result):
            return self._wrap_up(result)

        try:
            if mode is ExecutionMode.DRY_RUN or not allow_flag:
                result.ok = True
                result.details["executed"] = False
                result.details["reason"] = "dry_run_or_not_allowed"
                return self._wrap_up(result)

            if not callback:
                result.error = "no_callback_configured"
                result.details["reason"] = "no_callback"
                return self._wrap_up(result)

            callback(context)
            result.ok = True
            result.details["executed"] = True
            return self._wrap_up(result)

        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.details["reason"] = "exception"
            _AGENT_ERROR.labels(action, "exception").inc()
            return self._wrap_up(result)

    def _blocked_by_mode_or_action(self, result: ActionResult) -> bool:
        """
        Enforce mode allow-list and explicit action bans.
        """
        if not self.config.strict_mode:
            return False

        if self.config.forbidden_actions and result.action in self.config.forbidden_actions:
            result.error = "action_forbidden_by_policy"
            result.details["reason"] = "action_forbidden"
            return True

        if self.config.allowed_modes and result.mode not in self.config.allowed_modes:
            result.error = "execution_mode_not_allowed"
            result.details["reason"] = "mode_forbidden"
            return True

        return False

    def _effective_guards_for_action(self, action: str) -> Dict[str, bool]:
        """
        Merge global guard flags with per-action overrides.
        """
        base = {
            "require_change_ticket": self.config.require_change_ticket,
            "require_human_approver": self.config.require_human_approver,
            "require_mfa_tag": self.config.require_mfa_tag,
        }
        overrides = self.config.per_action_guards.get(action) or {}
        merged = dict(base)
        for key in ("require_change_ticket", "require_human_approver", "require_mfa_tag"):
            if key in overrides:
                merged[key] = bool(overrides[key])
        return merged

    def _blocked_by_context_guards(self, result: ActionResult) -> bool:
        """
        Enforce change-governance rules based on ActionContext metadata.
        """
        if not self.config.strict_mode:
            return False

        ctx = result.context
        meta: Dict[str, Any] = ctx.metadata if (ctx and ctx.metadata) else {}

        guards = self._effective_guards_for_action(result.action)

        if result.mode is ExecutionMode.PRODUCTION:
            if guards.get("require_change_ticket"):
                if not meta.get("change_ticket_id"):
                    result.error = "missing_change_ticket"
                    result.details["reason"] = "missing_change_ticket"
                    return True

            if guards.get("require_human_approver"):
                approver = meta.get("approved_by")
                if not approver:
                    result.error = "missing_human_approver"
                    result.details["reason"] = "missing_human_approver"
                    return True
                actor = ctx.user if ctx else None
                if actor and actor == approver:
                    result.error = "approver_must_differ_from_actor"
                    result.details["reason"] = "approver_must_differ_from_actor"
                    return True

            if self.config.approval_system_allowlist:
                system_tag = meta.get("approval_system")
                if system_tag not in self.config.approval_system_allowlist:
                    result.error = "invalid_approval_system"
                    result.details["reason"] = "invalid_approval_system"
                    return True

        if guards.get("require_mfa_tag"):
            if not meta.get("mfa_verified"):
                result.error = "mfa_required"
                result.details["reason"] = "mfa_required"
                return True

        return False

    def _wrap_up(self, result: ActionResult) -> ActionResult:
        """
        Finalize an ActionResult: timing, oracle, attestation, ledger, metrics.
        """
        result.finished_at = time.time()
        duration_ms = result.duration_ms()
        duration_s = duration_ms / 1000.0

        result.details.setdefault("policy_digest", self._policy_digest)

        # SLA guard for long-running actions
        if self.config.strict_mode and duration_s > self.config.max_action_duration_s:
            result.details["latency_sla_violation"] = True
            _AGENT_ERROR.labels(result.action, "latency_sla").inc()
            logger.warning(
                "TrustAgent action %s exceeded max_action_duration_s: duration=%.3fs limit=%.3fs",
                result.action,
                duration_s,
                self.config.max_action_duration_s,
            )

        # Optional risk oracle: last-mile gating for anomalous behavior.
        if self._risk_oracle is not None:
            try:
                fn = getattr(self._risk_oracle, "evaluate", None) or getattr(self._risk_oracle, "eval", None)
                if fn is not None:
                    verdict = fn(result)
                    if isinstance(verdict, dict):
                        score = verdict.get("score")
                        if score is not None:
                            result.details["oracle_score"] = float(score)
                        if verdict.get("block"):
                            reason = verdict.get("reason") or "oracle_block"
                            result.ok = False
                            result.details.setdefault("reason", str(reason))
                            result.error = (result.error or "") + " [oracle_block]"
            except Exception:  # pragma: no cover
                _AGENT_ERROR.labels(result.action, "oracle").inc()
                logger.warning("TrustAgent risk oracle failed", exc_info=True)

        # Attestation: must not silently disappear in strict profiles.
        if self.config.attestation_enabled:
            if self._attestor is None and self.config.strict_mode and self.config.require_attestor:
                _AGENT_ATTEST_ERROR.labels(result.action).inc()
                if result.ok:
                    result.ok = False
                    result.details.setdefault("reason", "attestor_missing")
                    result.error = (result.error or "") + " [attestor_missing]"
            elif self._attestor is not None:
                try:
                    self._attach_attestation(result)
                except Exception:  # pragma: no cover
                    _AGENT_ATTEST_ERROR.labels(result.action).inc()
                    logger.error(
                        "TrustAgent attestation failed for action %s",
                        result.action,
                        exc_info=True,
                    )
                    if self.config.strict_mode and self.config.require_attestor and result.ok:
                        result.ok = False
                        result.details.setdefault("reason", "attestation_failure")
                        result.error = (result.error or "") + " [attestation_failure]"

        # Ledger: best-effort in general, hardened in strict profiles.
        if self._ledger is not None:
            try:
                self._append_ledger_event(result)
            except Exception:  # pragma: no cover
                _AGENT_LEDGER_ERROR.labels(result.action).inc()
                logger.warning("TrustAgent failed to append audit event to ledger", exc_info=True)
                if self.config.strict_mode and self.config.require_ledger and result.ok:
                    result.ok = False
                    result.details.setdefault("reason", "ledger_append_failure")
                    result.error = (result.error or "") + " [ledger_append_failure]"

        # In-memory audit log (bounded).
        self._audit_log.append(result)
        if len(self._audit_log) > self.config.max_audit_log_entries:
            self._audit_log.pop(0)

        # Metrics and structured log.
        ok_label = "yes" if result.ok else "no"
        _AGENT_LATENCY.labels(result.action, result.mode.value, ok_label).observe(duration_ms)
        _AGENT_TOTAL.labels(result.action, result.mode.value, ok_label).inc()
        if not result.ok:
            _AGENT_ERROR.labels(result.action, "action_error").inc()

        try:
            logger.info(
                "tcd.agent.action",
                extra={
                    "tcd_action": result.action,
                    "tcd_action_id": result.action_id,
                    "tcd_mode": result.mode.value,
                    "tcd_ok": result.ok,
                    "tcd_error": result.error,
                    "tcd_duration_ms": duration_ms,
                    "tcd_context": result.context.to_dict() if result.context else None,
                    "tcd_policy_digest": self._policy_digest,
                    "tcd_node_id": self.config.node_id,
                    "tcd_proc_id": self.config.proc_id,
                    "tcd_supply_chain_label": self.config.supply_chain_label,
                    "tcd_image_digest": self.config.image_digest,
                    "tcd_build_id": self.config.build_id,
                },
            )
        except Exception:  # pragma: no cover
            # Logging must never break the agent.
            pass

        return result

    def _attach_attestation(self, result: ActionResult) -> None:
        """
        Attach a signed attestation for this action using the configured Attestor.
        """
        if self._attestor is None:
            return

        ctx_dict = result.context.to_dict() if result.context else {}

        req_obj: Dict[str, Any] = {
            "action": result.action,
            "action_id": result.action_id,
            "mode": result.mode.value,
            "context": {
                "request_id": ctx_dict.get("request_id"),
                "session_id": ctx_dict.get("session_id"),
                "tenant": ctx_dict.get("tenant"),
                "user": ctx_dict.get("user"),
                "component": ctx_dict.get("component"),
            },
        }

        comp_obj: Dict[str, Any] = {
            "agent": "TrustAgent",
            "node_id": self.config.node_id,
            "proc_id": self.config.proc_id,
            "policy_digest": self._policy_digest,
            "supply_chain_label": self.config.supply_chain_label,
            "image_digest": self.config.image_digest,
            "build_id": self.config.build_id,
        }

        e_obj: Dict[str, Any] = {
            "decision": "success" if result.ok else "failure",
            "duration_ms": result.duration_ms(),
            "error": result.error,
            "action": result.action,
            "mode": result.mode.value,
            "risk": result.details.get("patch_risk") or result.details.get("risk_level"),
            "effect_scope": result.details.get("effect_scope"),
        }

        # Optional e-process budget view, if provided by the caller.
        for key in ("e_value", "alpha_spent", "alpha_alloc", "budget_remaining"):
            if key in result.details:
                e_obj[key] = result.details[key]

        segments: List[Dict[str, Any]] = [
            {
                "kind": "agent_cfg",
                "id": self.config.node_id or "tcd_agent",
                "digest": self._policy_digest,
                "meta": {},
            }
        ]

        if self._ledger is not None:
            try:
                segments.append(
                    {
                        "kind": "audit_ledger_head",
                        "id": self.config.node_id or "tcd_agent",
                        "digest": self._ledger.head(),
                        "meta": {},
                    }
                )
            except Exception:  # pragma: no cover
                logger.warning("TrustAgent could not read ledger head for attestation", exc_info=True)

        if self._attestor_cfg is not None:
            cfg_digest = getattr(self._attestor_cfg, "default_cfg_digest", None)
            if cfg_digest:
                segments.append(
                    {
                        "kind": "system_cfg",
                        "id": "tcd_system",
                        "digest": cfg_digest,
                        "meta": {},
                    }
                )

        tags = ["tcd_agent", result.action, result.mode.value]

        meta: Dict[str, Any] = {
            "ok": result.ok,
            "node_id": self.config.node_id,
            "proc_id": self.config.proc_id,
            "policy_digest": self._policy_digest,
            "supply_chain_label": self.config.supply_chain_label,
            "image_digest": self.config.image_digest,
            "build_id": self.config.build_id,
        }

        if self._attestor_cfg is not None:
            try:
                meta["attestor_policy_digest"] = self._attestor_cfg.policy_digest()
            except Exception:  # pragma: no cover
                pass

        att = self._attestor.issue(  # type: ignore[call-arg]
            req_obj=req_obj,
            comp_obj=comp_obj,
            e_obj=e_obj,
            witness_segments=segments,
            witness_tags=tags,
            meta=meta,
        )

        result.receipt = att.get("receipt")
        result.receipt_body = att.get("receipt_body")
        result.receipt_sig = att.get("receipt_sig")
        result.verify_key = att.get("verify_key")

    def _append_ledger_event(self, result: ActionResult) -> None:
        """
        Append a compact audit event to the configured ledger.
        """
        if self._ledger is None:
            return

        ctx_dict = result.context.to_dict() if result.context else {}

        evt: Dict[str, Any] = {
            "kind": "agent_action",
            "ts_ns": time.time_ns(),
            "agent": "TrustAgent",
            "action": result.action,
            "action_id": result.action_id,
            "mode": result.mode.value,
            "ok": result.ok,
            "error": result.error,
            "duration_ms": result.duration_ms(),
            "policy_digest": self._policy_digest,
            "node_id": self.config.node_id,
            "proc_id": self.config.proc_id,
            "supply_chain_label": self.config.supply_chain_label,
            "image_digest": self.config.image_digest,
            "build_id": self.config.build_id,
            "context": ctx_dict or None,
            "details": result.details,
            "receipt": result.receipt,
            "verify_key": result.verify_key,
        }

        if self._attestor_cfg is not None:
            try:
                evt["attestor_policy_digest"] = self._attestor_cfg.policy_digest()
            except Exception:  # pragma: no cover
                pass

        for key in ("e_value", "alpha_spent", "alpha_alloc", "budget_remaining"):
            if key in result.details:
                evt[key] = result.details[key]

        self._ledger.append(evt)

    @staticmethod
    def _default_request_id() -> str:
        return uuid.uuid4().hex[:16]

    @staticmethod
    def _new_action_id() -> str:
        return uuid.uuid4().hex