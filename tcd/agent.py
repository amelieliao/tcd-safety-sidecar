# tcd/agent.py
from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from .rewrite_engine import PatchProposal


logger = logging.getLogger("tcd.agent")


class ExecutionMode(str, Enum):
    """
    Execution mode for agent actions.

    DRY_RUN   – no side effects; only record intent.
    CANARY    – apply changes to a limited/canary environment.
    PRODUCTION – apply changes to primary production paths.
    """

    DRY_RUN = "dry_run"
    CANARY = "canary"
    PRODUCTION = "production"


@dataclass
class ActionContext:
    """
    Optional contextual envelope for an action.

    It can be propagated into receipts, logs, or external audit systems.
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
    Normalized result for any agent action.
    """

    action: str
    mode: ExecutionMode
    ok: bool
    started_at: float
    finished_at: float
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    context: Optional[ActionContext] = None

    def duration_ms(self) -> float:
        return max(0.0, (self.finished_at - self.started_at) * 1000.0)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action": self.action,
            "mode": self.mode.value,
            "ok": self.ok,
            "error": self.error,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms(),
            "details": self.details,
            "context": self.context.to_dict() if self.context else None,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


@dataclass
class AgentConfig:
    """
    Configuration knobs for the agent.

    All fields are intentionally conservative; they can be tuned per deployment.
    """

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


class TrustAgent:
    """
    TrustAgent is a thin, auditable execution layer for TCD.

    It does not hard-code any environment-specific side effects. Instead,
    it delegates actual work to injected callbacks, and always produces
    structured ActionResult objects that can be recorded or turned into receipts.
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
    ) -> None:
        self.config = config

        self._apply_patch_cb = apply_patch_cb
        self._restart_cb = restart_cb
        self._reload_config_cb = reload_config_cb
        self._rollback_cb = rollback_cb
        self._rotate_keys_cb = rotate_keys_cb
        self._calibrate_model_cb = calibrate_model_cb
        self._update_policies_cb = update_policies_cb

        self._audit_log: List[ActionResult] = []

    # ------------------------------------------------------------------
    # Public inspection API
    # ------------------------------------------------------------------

    @property
    def audit_log(self) -> List[ActionResult]:
        """
        In-memory audit log of recent actions. For production, you would
        normally forward results to an external sink instead of relying on
        this list.
        """
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
        Apply a patch proposal in the selected mode.

        Default is config.default_mode. In DRY_RUN, no callback is invoked,
        and the patch is only recorded.
        """
        action_name = "apply_patch"
        mode = mode or self.config.default_mode
        started = time.time()

        result = ActionResult(
            action=action_name,
            mode=mode,
            ok=False,
            started_at=started,
            finished_at=started,
            error=None,
            details={
                "patch_id": patch.patch_id,
                "patch_risk": patch.risk.value,
                "hunk_count": len(patch.hunks),
            },
            context=context,
        )

        try:
            if len(patch.hunks) > self.config.max_patch_hunks:
                result.error = "patch too large: too many hunks"
                return self._finalize(result)

            encoded = patch.to_json().encode("utf-8")
            if len(encoded) > self.config.max_patch_size_bytes:
                result.error = "patch too large: exceeds byte limit"
                return self._finalize(result)

            if mode is ExecutionMode.DRY_RUN or not self.config.allow_auto_patch:
                result.ok = True
                result.details["applied"] = False
                result.details["reason"] = "dry_run_or_not_allowed"
                return self._finalize(result)

            if not self._apply_patch_cb:
                result.error = "no apply_patch callback configured"
                return self._finalize(result)

            self._apply_patch_cb(patch, mode, context)
            result.ok = True
            result.details["applied"] = True
            return self._finalize(result)
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            return self._finalize(result)

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
        Request rollback to a previously known good version.
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
        Trigger key rotation for sensitive credentials.
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
        Trigger calibration of safety / risk models.
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
            action=action,
            mode=mode,
            ok=False,
            started_at=started,
            finished_at=started,
            error=None,
            details={},
            context=context,
        )

        try:
            if mode is ExecutionMode.DRY_RUN or not allow_flag:
                result.ok = True
                result.details["executed"] = False
                result.details["reason"] = "dry_run_or_not_allowed"
                return self._finalize(result)

            if not callback:
                result.error = "no callback configured"
                return self._finalize(result)

            callback(context)
            result.ok = True
            result.details["executed"] = True
            return self._finalize(result)
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            return self._finalize(result)

    def _finalize(self, result: ActionResult) -> ActionResult:
        result.finished_at = time.time()
        self._audit_log.append(result)

        try:
            logger.info(
                "tcd.agent.action",
                extra={
                    "tcd_action": result.action,
                    "tcd_mode": result.mode.value,
                    "tcd_ok": result.ok,
                    "tcd_error": result.error,
                    "tcd_duration_ms": result.duration_ms(),
                    "tcd_context": result.context.to_dict() if result.context else None,
                },
            )
        except Exception:
            # logging must never break the agent
            pass

        return result

    @staticmethod
    def _default_request_id() -> str:
        return uuid.uuid4().hex[:16]