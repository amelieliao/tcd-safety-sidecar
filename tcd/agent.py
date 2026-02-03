from __future__ import annotations

"""
tcd/agent.py — TrustAgent control-plane execution shell (platform L6/L7 hardened)

This module implements a platform-grade control-plane agent with:

P0 (must)
- Gate release correctness (no release-on-not-acquired, no double-release).
- prepare/commit dedupe semantics fixed: dedupe key is (action_id, stage).
- Soft timeout tri-state: started/cancelled/uncertain with correct semantics.
- Executor backpressure: bounded submit (workers + queue cap), reject on full.
- Result model split: business vs evidence; effect_executed vs evidence_ok vs overall_ok.

P1 (strongly recommended)
- Circuit breaker with HALF_OPEN probe, sliding window, metrics.
- Dependency retry with jitter (idempotency via stage event_id).
- Global single-flight (pluggable lock provider) for high-risk actions.
- Outbox (durable) for evidence delivery completion under dependency failure.
- Schema discipline: bytes cap, schema_version, truncated_fields, payload_digest.

P2 (best-in-class)
- Runner abstraction allows thread/process/external runner injection.
- Sensitive info detection in values (JWT/PEM/Bearer/SSH/base64 heuristic) + log-injection guard.
- Hot update config: update_config atomic + gates resize + policy_digest refresh + optional audit event.
- Error taxonomy + reason_code enum for low-cardinality metrics.
- Invariants + tests scaffold provided in tests/ folder (see tests/test_agent_invariants.py).
"""

import concurrent.futures
import json
import logging
import os
import random
import re
import sqlite3
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    Iterable,
    List,
    Optional,
    Protocol,
    Tuple,
)

from .crypto import Blake3Hash
from .rewrite_engine import PatchProposal

logger = logging.getLogger("tcd.agent")

# Optional attestation and ledger backends.
try:  # pragma: no cover
    from .attest import Attestor, AttestorConfig, canonical_kv_hash  # type: ignore
except Exception:  # pragma: no cover
    Attestor = None  # type: ignore[assignment]
    AttestorConfig = None  # type: ignore[assignment]
    canonical_kv_hash = None  # type: ignore[assignment]

try:  # pragma: no cover
    from .audit import AuditLedger  # type: ignore
except Exception:  # pragma: no cover
    AuditLedger = None  # type: ignore[assignment]

# Optional metrics
try:  # pragma: no cover
    from prometheus_client import Counter, Gauge, Histogram
except Exception:  # pragma: no cover

    class Histogram:  # type: ignore[override]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def labels(self, *args: Any) -> "Histogram":
            return self

        def observe(self, value: float) -> None:
            pass

    class Counter:  # type: ignore[override]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def labels(self, *args: Any) -> "Counter":
            return self

        def inc(self, value: float = 1.0) -> None:
            pass

    class Gauge:  # type: ignore[override]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def labels(self, *args: Any) -> "Gauge":
            return self

        def set(self, value: float) -> None:
            pass

        def inc(self, value: float = 1.0) -> None:
            pass

        def dec(self, value: float = 1.0) -> None:
            pass


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

_AGENT_LATENCY = Histogram(
    "tcd_agent_action_latency_ms",
    "Latency of TrustAgent actions (ms)",
    buckets=(1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 30000),
    labelnames=("action", "mode", "overall_ok"),
)

_AGENT_TOTAL = Counter(
    "tcd_agent_action_total",
    "Total TrustAgent actions",
    labelnames=("action", "mode", "overall_ok"),
)

_AGENT_ERROR = Counter(
    "tcd_agent_action_error_total",
    "Errors from TrustAgent actions",
    labelnames=("action", "error_kind"),
)

_AGENT_REJECT = Counter(
    "tcd_agent_action_reject_total",
    "Rejected TrustAgent actions",
    labelnames=("action", "reason_code"),
)

_AGENT_INFLIGHT = Gauge(
    "tcd_agent_action_inflight",
    "Current in-flight actions (gate-controlled)",
    labelnames=("action",),
)

_AGENT_CALLBACK_LEAK_INFLIGHT = Gauge(
    "tcd_agent_callback_leak_inflight",
    "Callbacks still running after agent returned (run-timeout leak)",
    labelnames=("action",),
)

_AGENT_CALLBACK_LEAK_TOTAL = Counter(
    "tcd_agent_callback_leak_total",
    "Total leaked callbacks (run-timeout)",
    labelnames=("action",),
)

# Executor metrics (backpressure)
_AGENT_EXEC_IN_USE = Gauge(
    "tcd_agent_executor_in_use",
    "Executor tokens in-use (running+queued)",
    labelnames=("executor",),
)
_AGENT_EXEC_QUEUE_DEPTH = Gauge(
    "tcd_agent_executor_queue_depth",
    "Approx executor queue depth (in_use - max_workers)",
    labelnames=("executor",),
)
_AGENT_EXEC_REJECT = Counter(
    "tcd_agent_executor_reject_total",
    "Executor submission rejects",
    labelnames=("executor", "reason"),
)

# Dependency metrics
_AGENT_DEP_LATENCY = Histogram(
    "tcd_agent_dependency_latency_ms",
    "Dependency call latency from TrustAgent (ms)",
    buckets=(1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000),
    labelnames=("dep", "op", "status"),
)
_AGENT_DEP_ERROR = Counter(
    "tcd_agent_dependency_error_total",
    "Dependency call errors",
    labelnames=("dep", "op", "kind"),
)

# Breaker metrics
_AGENT_BREAKER_STATE = Gauge(
    "tcd_agent_dependency_breaker_state",
    "Breaker state: 0=CLOSED 1=OPEN 2=HALF_OPEN",
    labelnames=("dep",),
)
_AGENT_BREAKER_PROBE_TOTAL = Counter(
    "tcd_agent_dependency_breaker_probe_total",
    "Breaker probe requests",
    labelnames=("dep", "ok"),
)

# Outbox metrics
_AGENT_OUTBOX_DEPTH = Gauge(
    "tcd_agent_outbox_depth",
    "Outbox pending item count",
    labelnames=("kind",),
)
_AGENT_OUTBOX_OLDEST_AGE_S = Gauge(
    "tcd_agent_outbox_oldest_age_s",
    "Outbox oldest pending age (seconds)",
    labelnames=("kind",),
)
_AGENT_OUTBOX_FLUSH_TOTAL = Counter(
    "tcd_agent_outbox_flush_total",
    "Outbox flush attempts",
    labelnames=("kind", "ok"),
)


# ---------------------------------------------------------------------------
# Enums / Taxonomy
# ---------------------------------------------------------------------------

class ExecutionMode(str, Enum):
    DRY_RUN = "dry_run"
    CANARY = "canary"
    PRODUCTION = "production"


class ErrorKind(str, Enum):
    POLICY = "policy"
    FORBIDDEN = "forbidden"
    OVERLOADED = "overloaded"
    TIMEOUT = "timeout"
    CALLBACK = "callback"
    ORACLE = "oracle"
    ATTESTOR = "attestor"
    LEDGER = "ledger"
    EVIDENCE_GAP = "evidence_gap"
    INTERNAL = "internal"


class ReasonCode(str, Enum):
    OK = "ok"

    # Policy/governance
    ACTION_FORBIDDEN = "action_forbidden"
    MODE_FORBIDDEN = "mode_forbidden"
    MISSING_CHANGE_TICKET = "missing_change_ticket"
    MISSING_HUMAN_APPROVER = "missing_human_approver"
    APPROVER_SAME_AS_ACTOR = "approver_same_as_actor"
    INVALID_APPROVAL_SYSTEM = "invalid_approval_system"
    MFA_REQUIRED = "mfa_required"

    # Patch limits
    PATCH_HUNK_LIMIT = "patch_hunk_limit"
    PATCH_SIZE_LIMIT = "patch_size_limit"
    PATCH_SERIALIZE_FAILED = "patch_serialize_failed"

    # Concurrency / executor
    GATE_OVERLOADED = "gate_overloaded"
    QUEUE_FULL = "queue_full"
    LOCK_HELD = "lock_held"

    # Timeout
    QUEUE_TIMEOUT = "queue_timeout"
    RUN_TIMEOUT = "run_timeout"

    # Callback/config
    DRY_RUN_OR_NOT_ALLOWED = "dry_run_or_not_allowed"
    NO_CALLBACK = "no_callback"

    # Dependencies/breaker
    BREAKER_OPEN = "breaker_open"
    LEDGER_PREPARE_FAILED = "ledger_prepare_failed"
    LEDGER_COMMIT_FAILED = "ledger_commit_failed"
    ATTESTATION_FAILED = "attestation_failed"

    # Evidence delivery
    OUTBOX_ENQUEUED = "outbox_enqueued"
    OUTBOX_ENQUEUE_FAILED = "outbox_enqueue_failed"

    # Oracle
    ORACLE_BLOCK = "oracle_block"

    # Internal
    EXCEPTION = "exception"


class BreakerState(int, Enum):
    CLOSED = 0
    OPEN = 1
    HALF_OPEN = 2


# ---------------------------------------------------------------------------
# Protocols (pluggable platform integrations)
# ---------------------------------------------------------------------------

class LockProviderProtocol(Protocol):
    """
    Distributed single-flight lock interface.

    acquire returns a lock_token if acquired, else None.
    release must be token-checked (no-op if token mismatch).
    """

    def acquire(self, name: str, ttl_s: float) -> Optional[str]:
        ...

    def release(self, name: str, token: str) -> None:
        ...

    def refresh(self, name: str, token: str, ttl_s: float) -> bool:
        ...


class OutboxProtocol(Protocol):
    """
    Durable outbox for evidence delivery (ledger/attestor) retries.
    """

    def put(self, *, kind: str, dedupe_key: str, payload: Dict[str, Any], payload_digest: str) -> None:
        ...

    def peek(self, *, kind: str, limit: int, now_ts: float) -> List[Dict[str, Any]]:
        ...

    def ack(self, *, kind: str, row_id: int) -> None:
        ...

    def nack(self, *, kind: str, row_id: int, attempts: int, next_ts: float, last_error: str) -> None:
        ...

    def stats(self, *, kind: str, now_ts: float) -> Dict[str, Any]:
        ...


class RunnerProtocol(Protocol):
    """
    Execution runner for callbacks (thread/process/external).

    Must support bounded submission (backpressure) and timeout tri-state.
    """

    def submit(self, fn: Callable[[], Any]) -> Tuple[concurrent.futures.Future, "TaskMeta"]:
        ...

    def stats(self) -> Dict[str, Any]:
        ...


# ---------------------------------------------------------------------------
# Dataclasses (Action Context / Result / Config)
# ---------------------------------------------------------------------------

@dataclass
class ActionContext:
    """
    Lightweight envelope describing the origin of a change request.

    metadata is sanitized before leaving process boundaries (logs/ledger/attestation/outbox).
    """
    request_id: str = ""
    session_id: str = ""
    tenant: str = ""
    user: str = ""
    component: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self, *, safe: bool = True, cfg: Optional["AgentConfig"] = None) -> Dict[str, Any]:
        meta = dict(self.metadata or {})
        if safe:
            meta = sanitize_metadata(meta, cfg=cfg)
        return {
            "request_id": self.request_id,
            "session_id": self.session_id,
            "tenant": self.tenant,
            "user": self.user,
            "component": self.component,
            "metadata": meta,
        }


@dataclass
class ActionResult:
    """
    Platform-grade outcome model.

    - effect_executed: did the side-effect callback start (may have partially executed)?
    - business_ok: business semantics (dry-run accepted, or callback succeeded).
    - evidence_ok: evidence pipeline complete (prepare/commit/attest as required).
    - ok: overall_ok = combine(business_ok, evidence_ok) under strict rules.
    """
    action_id: str
    action: str
    mode: ExecutionMode

    # Overall composite signal (compat: keep field name ok)
    ok: bool

    # Split dimensions
    business_ok: bool = False
    evidence_ok: bool = True
    effect_executed: bool = False

    # Soft-timeout tri-state
    callback_started: bool = False
    callback_cancelled: bool = False
    side_effect_uncertain: bool = False  # True only when callback started but agent returned before completion

    # Timing
    started_at: float = 0.0
    finished_at: float = 0.0
    started_mono: float = 0.0
    finished_mono: float = 0.0

    # Error taxonomy
    error_kind: Optional[str] = None
    reason_code: str = ReasonCode.OK.value
    reason_detail: Optional[str] = None
    error: Optional[str] = None

    # Details (bounded & sanitized on output)
    details: Dict[str, Any] = field(default_factory=dict)
    context: Optional[ActionContext] = None

    # Attestation fields (optional)
    receipt: Optional[str] = None
    receipt_body: Optional[str] = None
    receipt_sig: Optional[str] = None
    verify_key: Optional[str] = None

    def duration_ms(self) -> float:
        if self.started_mono and self.finished_mono and self.finished_mono >= self.started_mono:
            return max(0.0, (self.finished_mono - self.started_mono) * 1000.0)
        return max(0.0, (self.finished_at - self.started_at) * 1000.0)

    @property
    def overall_ok(self) -> bool:
        return bool(self.ok)

    def to_dict(self, *, cfg: Optional["AgentConfig"] = None, include_receipt_material: bool = True) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action": self.action,
            "mode": self.mode.value,
            "overall_ok": self.overall_ok,
            "business_ok": bool(self.business_ok),
            "evidence_ok": bool(self.evidence_ok),
            "effect_executed": bool(self.effect_executed),
            "callback_started": bool(self.callback_started),
            "callback_cancelled": bool(self.callback_cancelled),
            "side_effect_uncertain": bool(self.side_effect_uncertain),
            "error_kind": self.error_kind,
            "reason_code": self.reason_code,
            "reason_detail": truncate_str(self.reason_detail or "", 512) if self.reason_detail else None,
            "error": truncate_str(self.error or "", 512) if self.error else None,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms(),
            "details": json_sanitize(self.details),
            "context": self.context.to_dict(safe=True, cfg=cfg) if self.context else None,
            "receipt": self.receipt,
            "receipt_body": self.receipt_body if include_receipt_material else None,
            "receipt_sig": self.receipt_sig if include_receipt_material else None,
            "verify_key": self.verify_key,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True, default=str)


@dataclass
class RetryPolicy:
    max_attempts: int = 2
    base_backoff_ms: int = 40
    max_backoff_ms: int = 250
    jitter: float = 0.2  # 0..1


@dataclass
class AgentConfig:
    """
    TrustAgent config (policy surface + enforceable budgets).

    NOTE: Keep fields low-cardinality (hashable into policy_digest).
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
    allow_agent_config_update: bool = False  # P2: hot update gate

    # Patch constraints
    max_patch_hunks: int = 16
    max_patch_size_bytes: int = 128_000

    # Global safety profile
    strict_mode: bool = False
    attestation_enabled: bool = False
    require_attestor: bool = True
    require_ledger: bool = True
    allowed_modes: Optional[List[ExecutionMode]] = None

    # Action budgets (gate + timeout)
    max_action_duration_s: float = 30.0
    max_audit_log_entries: int = 1024
    max_inflight_default: int = 8
    per_action_limits: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    # per_action_limits[action] supports keys:
    #   - max_inflight: int
    #   - timeout_s: float
    #   - requires_global_lock: bool
    #   - global_lock_ttl_s: float

    # Executor budgets (P0)
    action_executor_workers: int = 8
    action_executor_queue: int = 64
    dep_executor_workers: int = 8
    dep_executor_queue: int = 64

    # Dependency budgets + breaker (P1)
    dep_timeout_attestor_ms: int = 1200
    dep_timeout_ledger_ms: int = 800
    dep_retry_attestor: RetryPolicy = field(default_factory=lambda: RetryPolicy(max_attempts=2))
    dep_retry_ledger_prepare: RetryPolicy = field(default_factory=lambda: RetryPolicy(max_attempts=2))
    dep_retry_ledger_commit: RetryPolicy = field(default_factory=lambda: RetryPolicy(max_attempts=3))
    breaker_failures: int = 5
    breaker_window_s: float = 30.0
    breaker_open_seconds: float = 15.0

    # Global lock (P1)
    global_lock_enabled: bool = True
    global_lock_default_ttl_s: float = 30.0

    # Outbox (P1)
    outbox_enabled: bool = True
    outbox_path: str = "tcd_outbox.sqlite3"  # durable local default
    outbox_flush_on_wrapup: bool = True
    outbox_flush_budget_ms: int = 120
    outbox_flush_max_items: int = 20
    outbox_max_payload_bytes: int = 64 * 1024

    # Schema discipline (P1)
    ledger_schema_version: int = 1
    attestation_schema_version: int = 1
    max_ledger_event_bytes: int = 32 * 1024
    max_attestor_req_bytes: int = 32 * 1024

    # Governance and abuse-resistance
    require_change_ticket: bool = False
    require_human_approver: bool = False
    require_mfa_tag: bool = False
    forbidden_actions: Optional[List[str]] = None
    approval_system_allowlist: Optional[List[str]] = None
    per_action_guards: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    # Metadata leakage controls (P2)
    max_metadata_bytes: int = 8 * 1024
    max_metadata_items: int = 64
    max_metadata_depth: int = 4
    max_string_value: int = 2048
    redact_key_patterns: Tuple[str, ...] = (
        "token",
        "secret",
        "password",
        "passwd",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "set-cookie",
        "session",
        "private",
        "credential",
        "bearer",
        "ssh",
        "key",
    )

    # PQ / supply-chain binding
    require_pq_attestor: bool = False
    allowed_sig_algs: Optional[List[str]] = None
    supply_chain_label: str = ""
    node_id: str = ""
    proc_id: str = ""
    image_digest: str = ""
    build_id: str = ""

    # Ledger semantics (P0)
    ledger_prepare_commit: bool = True

    def digest_material(self) -> Dict[str, Any]:
        """
        Stable material for policy digest.
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
            "allow_agent_config_update": bool(self.allow_agent_config_update),
            "max_patch_hunks": int(self.max_patch_hunks),
            "max_patch_size_bytes": int(self.max_patch_size_bytes),
            "strict_mode": bool(self.strict_mode),
            "attestation_enabled": bool(self.attestation_enabled),
            "require_attestor": bool(self.require_attestor),
            "require_ledger": bool(self.require_ledger),
            "allowed_modes": [m.value for m in self.allowed_modes] if self.allowed_modes else [],
            "max_action_duration_s": float(self.max_action_duration_s),
            "max_audit_log_entries": int(self.max_audit_log_entries),
            "max_inflight_default": int(self.max_inflight_default),
            "per_action_limits": json_sanitize(self.per_action_limits),
            "action_executor_workers": int(self.action_executor_workers),
            "action_executor_queue": int(self.action_executor_queue),
            "dep_executor_workers": int(self.dep_executor_workers),
            "dep_executor_queue": int(self.dep_executor_queue),
            "dep_timeout_attestor_ms": int(self.dep_timeout_attestor_ms),
            "dep_timeout_ledger_ms": int(self.dep_timeout_ledger_ms),
            "dep_retry_attestor": vars(self.dep_retry_attestor),
            "dep_retry_ledger_prepare": vars(self.dep_retry_ledger_prepare),
            "dep_retry_ledger_commit": vars(self.dep_retry_ledger_commit),
            "breaker_failures": int(self.breaker_failures),
            "breaker_window_s": float(self.breaker_window_s),
            "breaker_open_seconds": float(self.breaker_open_seconds),
            "global_lock_enabled": bool(self.global_lock_enabled),
            "global_lock_default_ttl_s": float(self.global_lock_default_ttl_s),
            "outbox_enabled": bool(self.outbox_enabled),
            "outbox_path": self.outbox_path,
            "outbox_flush_on_wrapup": bool(self.outbox_flush_on_wrapup),
            "outbox_flush_budget_ms": int(self.outbox_flush_budget_ms),
            "outbox_flush_max_items": int(self.outbox_flush_max_items),
            "outbox_max_payload_bytes": int(self.outbox_max_payload_bytes),
            "ledger_schema_version": int(self.ledger_schema_version),
            "attestation_schema_version": int(self.attestation_schema_version),
            "max_ledger_event_bytes": int(self.max_ledger_event_bytes),
            "max_attestor_req_bytes": int(self.max_attestor_req_bytes),
            "require_change_ticket": bool(self.require_change_ticket),
            "require_human_approver": bool(self.require_human_approver),
            "require_mfa_tag": bool(self.require_mfa_tag),
            "forbidden_actions": list(self.forbidden_actions or []),
            "approval_system_allowlist": list(self.approval_system_allowlist or []),
            "per_action_guards": json_sanitize(self.per_action_guards),
            "max_metadata_bytes": int(self.max_metadata_bytes),
            "max_metadata_items": int(self.max_metadata_items),
            "max_metadata_depth": int(self.max_metadata_depth),
            "max_string_value": int(self.max_string_value),
            "redact_key_patterns": list(self.redact_key_patterns),
            "require_pq_attestor": bool(self.require_pq_attestor),
            "allowed_sig_algs": list(self.allowed_sig_algs or []),
            "supply_chain_label": self.supply_chain_label,
            "node_id": self.node_id,
            "proc_id": self.proc_id,
            "image_digest": self.image_digest,
            "build_id": self.build_id,
            "ledger_prepare_commit": bool(self.ledger_prepare_commit),
        }


# ---------------------------------------------------------------------------
# JSON / Digest / Sanitization utilities
# ---------------------------------------------------------------------------

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")


def json_sanitize(obj: Any) -> Any:
    try:
        json.dumps(obj, ensure_ascii=False, default=str)
        return obj
    except Exception:
        if isinstance(obj, dict):
            return {str(k): json_sanitize(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [json_sanitize(x) for x in obj]
        return str(obj)


def canonical_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


def blake3_hex(data: bytes, ctx: str) -> str:
    h = Blake3Hash()
    return h.hex(data, ctx=ctx)


def truncate_str(s: str, max_len: int) -> str:
    if max_len <= 0:
        return ""
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def is_sensitive_key(key: str, patterns: Tuple[str, ...]) -> bool:
    k = (key or "").lower()
    for p in patterns:
        if p and p in k:
            return True
    return False


def sanitize_string_value(s: str, *, cfg: Optional[AgentConfig]) -> str:
    """
    P2: value-based sensitive detection + log injection guard.
    """
    max_str = int(getattr(cfg, "max_string_value", 2048) if cfg else 2048)

    # guard control chars
    s2 = s.replace("\r", "\\r").replace("\n", "\\n")
    s2 = _CONTROL_CHAR_RE.sub("", s2)

    # detect obvious secrets by value shape
    low = s2.lower().strip()
    if low.startswith("bearer "):
        return "[redacted_bearer]"
    if "-----begin" in low and "key-----" in low:
        return "[redacted_pem]"
    if low.startswith(("ssh-rsa ", "ssh-ed25519 ", "ssh-dss ", "ecdsa-sha2-")):
        return "[redacted_ssh_key]"
    if len(s2) >= 40 and _JWT_RE.match(s2.strip()):
        return "[redacted_jwt]"

    # base64-ish long blob heuristic
    if len(s2) >= 160 and _BASE64ISH_RE.match(s2) is not None:
        # avoid redacting normal long text; require high base64 ratio
        return "[redacted_blob]"

    return truncate_str(s2, max_str)


def sanitize_metadata(meta: Dict[str, Any], *, cfg: Optional[AgentConfig]) -> Dict[str, Any]:
    """
    Redact sensitive keys and values; cap depth/items/bytes.
    """
    max_bytes = int(getattr(cfg, "max_metadata_bytes", 8 * 1024) if cfg else 8 * 1024)
    max_items = int(getattr(cfg, "max_metadata_items", 64) if cfg else 64)
    max_depth = int(getattr(cfg, "max_metadata_depth", 4) if cfg else 4)
    patterns = tuple(getattr(cfg, "redact_key_patterns", ()) if cfg else ())

    budget = {"bytes": 0}

    def _walk(x: Any, depth: int) -> Any:
        if budget["bytes"] >= max_bytes:
            return "[truncated]"
        if depth > max_depth:
            return "[max_depth]"
        if x is None or isinstance(x, (bool, int, float)):
            return x
        if isinstance(x, str):
            v = sanitize_string_value(x, cfg=cfg)
            budget["bytes"] += len(v)
            return v
        if isinstance(x, bytes):
            budget["bytes"] += 16
            return f"[bytes:{len(x)}]"
        if isinstance(x, dict):
            out: Dict[str, Any] = {}
            n = 0
            for k, v in x.items():
                if n >= max_items or budget["bytes"] >= max_bytes:
                    break
                ks = truncate_str(str(k), 256)
                if is_sensitive_key(ks, patterns):
                    out[ks] = "[redacted]"
                    budget["bytes"] += len(ks) + 10
                else:
                    out[ks] = _walk(v, depth + 1)
                    budget["bytes"] += len(ks)
                n += 1
            if len(x) > n:
                out["_truncated_items"] = len(x) - n
            return out
        if isinstance(x, (list, tuple)):
            out_list: List[Any] = []
            for i, it in enumerate(x):
                if i >= max_items or budget["bytes"] >= max_bytes:
                    break
                out_list.append(_walk(it, depth + 1))
            if len(x) > len(out_list):
                out_list.append(f"[+{len(x)-len(out_list)} more]")
            return out_list

        # fallback: stringified
        s = sanitize_string_value(str(x), cfg=cfg)
        budget["bytes"] += len(s)
        return s

    try:
        return _walk(meta or {}, 0) if isinstance(meta, dict) else {}
    except Exception:
        return {"_error": "metadata_sanitize_failed"}


def safe_error_str(exc: BaseException, *, max_len: int = 512) -> str:
    try:
        msg = f"{type(exc).__name__}: {exc}"
    except Exception:
        msg = f"{type(exc).__name__}"
    return truncate_str(msg, max_len)


# ---------------------------------------------------------------------------
# Gate (P0): strictly correct, resizable, non-blocking acquire
# ---------------------------------------------------------------------------

class ActionGate:
    __slots__ = ("action", "_limit", "_inflight", "_lock")

    def __init__(self, action: str, limit: int) -> None:
        self.action = action
        self._limit = max(1, int(limit))
        self._inflight = 0
        self._lock = threading.Lock()
        _AGENT_INFLIGHT.labels(action).set(0.0)

    def try_acquire(self) -> bool:
        with self._lock:
            if self._inflight >= self._limit:
                return False
            self._inflight += 1
            _AGENT_INFLIGHT.labels(self.action).set(float(self._inflight))
            return True

    def release(self) -> None:
        with self._lock:
            self._inflight = max(0, self._inflight - 1)
            _AGENT_INFLIGHT.labels(self.action).set(float(self._inflight))

    def inflight(self) -> int:
        with self._lock:
            return int(self._inflight)

    def resize(self, new_limit: int) -> None:
        with self._lock:
            self._limit = max(1, int(new_limit))


# ---------------------------------------------------------------------------
# Circuit breaker (P1): CLOSED/OPEN/HALF_OPEN + probe + sliding window
# ---------------------------------------------------------------------------

class CircuitBreaker:
    __slots__ = (
        "name",
        "threshold",
        "window_s",
        "open_seconds",
        "_state",
        "_fail_times",
        "_opened_until",
        "_probe_inflight",
        "_lock",
    )

    def __init__(self, name: str, threshold: int, window_s: float, open_seconds: float) -> None:
        self.name = name
        self.threshold = max(1, int(threshold))
        self.window_s = max(0.5, float(window_s))
        self.open_seconds = max(0.1, float(open_seconds))

        self._state: BreakerState = BreakerState.CLOSED
        self._fail_times: Deque[float] = deque()
        self._opened_until: float = 0.0
        self._probe_inflight: bool = False
        self._lock = threading.Lock()

        _AGENT_BREAKER_STATE.labels(name).set(float(self._state.value))

    def _set_state(self, st: BreakerState) -> None:
        self._state = st
        _AGENT_BREAKER_STATE.labels(self.name).set(float(st.value))

    def before_call(self) -> Tuple[bool, bool]:
        """
        Returns (allow, is_probe).
        """
        now = time.monotonic()
        with self._lock:
            if self._state == BreakerState.OPEN:
                if now < self._opened_until:
                    return (False, False)
                # Open expired -> enter HALF_OPEN
                self._set_state(BreakerState.HALF_OPEN)
                self._probe_inflight = False

            if self._state == BreakerState.HALF_OPEN:
                if self._probe_inflight:
                    return (False, False)
                self._probe_inflight = True
                return (True, True)

            # CLOSED
            return (True, False)

    def record_success(self, *, was_probe: bool) -> None:
        with self._lock:
            if was_probe and self._state == BreakerState.HALF_OPEN:
                _AGENT_BREAKER_PROBE_TOTAL.labels(self.name, "yes").inc()
                self._fail_times.clear()
                self._probe_inflight = False
                self._opened_until = 0.0
                self._set_state(BreakerState.CLOSED)
                return

            # normal success: decay failures by clearing old window
            now = time.monotonic()
            while self._fail_times and (now - self._fail_times[0]) > self.window_s:
                self._fail_times.popleft()

    def record_failure(self, *, was_probe: bool) -> None:
        now = time.monotonic()
        with self._lock:
            if was_probe and self._state == BreakerState.HALF_OPEN:
                _AGENT_BREAKER_PROBE_TOTAL.labels(self.name, "no").inc()
                self._probe_inflight = False
                self._opened_until = now + self.open_seconds
                self._set_state(BreakerState.OPEN)
                self._fail_times.clear()
                self._fail_times.append(now)
                return

            # normal failure: sliding window count
            self._fail_times.append(now)
            while self._fail_times and (now - self._fail_times[0]) > self.window_s:
                self._fail_times.popleft()

            if len(self._fail_times) >= self.threshold:
                self._opened_until = now + self.open_seconds
                self._set_state(BreakerState.OPEN)

    def state(self) -> BreakerState:
        with self._lock:
            return self._state

    def is_open(self) -> bool:
        now = time.monotonic()
        with self._lock:
            return self._state == BreakerState.OPEN and now < self._opened_until


# ---------------------------------------------------------------------------
# Executor backpressure (P0): bounded submit wrapper
# ---------------------------------------------------------------------------

class RejectedExecution(RuntimeError):
    pass


@dataclass
class TaskMeta:
    started_evt: threading.Event = field(default_factory=threading.Event)
    finished_evt: threading.Event = field(default_factory=threading.Event)
    started_mono: float = 0.0
    finished_mono: float = 0.0

    def mark_started(self) -> None:
        self.started_mono = time.perf_counter()
        self.started_evt.set()

    def mark_finished(self) -> None:
        self.finished_mono = time.perf_counter()
        self.finished_evt.set()


class BoundedExecutor(RunnerProtocol):
    """
    Wrap a concurrent.futures.Executor with bounded submission (max_workers + max_queue).
    """

    def __init__(self, *, name: str, executor: concurrent.futures.Executor, max_workers: int, max_queue: int) -> None:
        self.name = name
        self._executor = executor
        self._max_workers = max(1, int(max_workers))
        self._max_queue = max(0, int(max_queue))

        self._capacity = self._max_workers + self._max_queue
        self._sem = threading.BoundedSemaphore(self._capacity)
        self._in_use = 0
        self._lock = threading.Lock()

        _AGENT_EXEC_IN_USE.labels(self.name).set(0.0)
        _AGENT_EXEC_QUEUE_DEPTH.labels(self.name).set(0.0)

    def _inc(self) -> None:
        with self._lock:
            self._in_use += 1
            _AGENT_EXEC_IN_USE.labels(self.name).set(float(self._in_use))
            qd = max(0, self._in_use - self._max_workers)
            _AGENT_EXEC_QUEUE_DEPTH.labels(self.name).set(float(qd))

    def _dec(self) -> None:
        with self._lock:
            self._in_use = max(0, self._in_use - 1)
            _AGENT_EXEC_IN_USE.labels(self.name).set(float(self._in_use))
            qd = max(0, self._in_use - self._max_workers)
            _AGENT_EXEC_QUEUE_DEPTH.labels(self.name).set(float(qd))

    def submit(self, fn: Callable[[], Any]) -> Tuple[concurrent.futures.Future, TaskMeta]:
        if not self._sem.acquire(blocking=False):
            _AGENT_EXEC_REJECT.labels(self.name, "queue_full").inc()
            raise RejectedExecution("executor queue full")

        self._inc()
        meta = TaskMeta()

        def _wrapped() -> Any:
            meta.mark_started()
            try:
                return fn()
            finally:
                meta.mark_finished()

        fut = self._executor.submit(_wrapped)

        def _release(_: Any) -> None:
            try:
                self._dec()
            finally:
                try:
                    self._sem.release()
                except Exception:
                    pass

        fut.add_done_callback(_release)
        return fut, meta

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            in_use = int(self._in_use)
        return {
            "name": self.name,
            "max_workers": int(self._max_workers),
            "max_queue": int(self._max_queue),
            "capacity": int(self._capacity),
            "in_use": int(in_use),
            "queue_depth_approx": int(max(0, in_use - self._max_workers)),
        }


# ---------------------------------------------------------------------------
# Lock provider (P1): default in-process TTL lock (pluggable for redis/etcd)
# ---------------------------------------------------------------------------

class InProcessTTLLockProvider(LockProviderProtocol):
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._locks: Dict[str, Tuple[float, str]] = {}  # name -> (expires_mono, token)

    def acquire(self, name: str, ttl_s: float) -> Optional[str]:
        ttl_s = max(0.1, float(ttl_s))
        now = time.monotonic()
        token = uuid.uuid4().hex
        with self._lock:
            cur = self._locks.get(name)
            if cur is not None:
                exp, _tok = cur
                if now < exp:
                    return None
            self._locks[name] = (now + ttl_s, token)
            return token

    def release(self, name: str, token: str) -> None:
        with self._lock:
            cur = self._locks.get(name)
            if cur is None:
                return
            _exp, tok = cur
            if tok != token:
                return
            self._locks.pop(name, None)

    def refresh(self, name: str, token: str, ttl_s: float) -> bool:
        ttl_s = max(0.1, float(ttl_s))
        now = time.monotonic()
        with self._lock:
            cur = self._locks.get(name)
            if cur is None:
                return False
            _exp, tok = cur
            if tok != token:
                return False
            self._locks[name] = (now + ttl_s, token)
            return True


# ---------------------------------------------------------------------------
# Durable outbox (P1): sqlite-backed
# ---------------------------------------------------------------------------

class SQLiteOutbox(OutboxProtocol):
    """
    SQLite durable outbox with per-kind tables.

    Schema:
      id INTEGER PRIMARY KEY AUTOINCREMENT
      dedupe_key TEXT UNIQUE
      payload_json TEXT
      payload_digest TEXT
      attempts INTEGER
      next_ts REAL
      created_ts REAL
      last_error TEXT
    """

    def __init__(self, path: str) -> None:
        self.path = path
        self._db_lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=2.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with self._db_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS outbox (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        kind TEXT NOT NULL,
                        dedupe_key TEXT NOT NULL,
                        payload_json TEXT NOT NULL,
                        payload_digest TEXT NOT NULL,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        next_ts REAL NOT NULL,
                        created_ts REAL NOT NULL,
                        last_error TEXT NOT NULL DEFAULT ''
                    );
                    """
                )
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_dedupe ON outbox(kind, dedupe_key);")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_outbox_next ON outbox(kind, next_ts, created_ts);")
            finally:
                conn.close()

    def put(self, *, kind: str, dedupe_key: str, payload: Dict[str, Any], payload_digest: str) -> None:
        now = time.time()
        blob = canonical_json_bytes(payload).decode("utf-8", errors="replace")
        with self._db_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO outbox(kind, dedupe_key, payload_json, payload_digest, attempts, next_ts, created_ts, last_error)
                    VALUES(?, ?, ?, ?, 0, ?, ?, '')
                    """,
                    (kind, dedupe_key, blob, payload_digest, now, now),
                )
            finally:
                conn.close()

    def peek(self, *, kind: str, limit: int, now_ts: float) -> List[Dict[str, Any]]:
        limit = max(1, min(200, int(limit)))
        with self._db_lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """
                    SELECT id, dedupe_key, payload_json, payload_digest, attempts, next_ts, created_ts, last_error
                    FROM outbox
                    WHERE kind=? AND next_ts<=?
                    ORDER BY created_ts ASC
                    LIMIT ?
                    """,
                    (kind, float(now_ts), int(limit)),
                )
                rows = cur.fetchall()
            finally:
                conn.close()

        out: List[Dict[str, Any]] = []
        for r in rows:
            try:
                payload = json.loads(r[2])
            except Exception:
                payload = {"_error": "payload_decode_failed"}
            out.append(
                {
                    "id": int(r[0]),
                    "dedupe_key": str(r[1]),
                    "payload": payload,
                    "payload_digest": str(r[3]),
                    "attempts": int(r[4]),
                    "next_ts": float(r[5]),
                    "created_ts": float(r[6]),
                    "last_error": str(r[7]),
                }
            )
        return out

    def ack(self, *, kind: str, row_id: int) -> None:
        with self._db_lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM outbox WHERE kind=? AND id=?", (kind, int(row_id)))
            finally:
                conn.close()

    def nack(self, *, kind: str, row_id: int, attempts: int, next_ts: float, last_error: str) -> None:
        with self._db_lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    UPDATE outbox
                    SET attempts=?, next_ts=?, last_error=?
                    WHERE kind=? AND id=?
                    """,
                    (int(attempts), float(next_ts), truncate_str(last_error, 512), str(kind), int(row_id)),
                )
            finally:
                conn.close()

    def stats(self, *, kind: str, now_ts: float) -> Dict[str, Any]:
        with self._db_lock:
            conn = self._connect()
            try:
                cur = conn.execute("SELECT COUNT(*), MIN(created_ts) FROM outbox WHERE kind=?", (str(kind),))
                row = cur.fetchone()
            finally:
                conn.close()
        total = int(row[0] if row and row[0] is not None else 0)
        oldest_ts = float(row[1] if row and row[1] is not None else 0.0)
        oldest_age = max(0.0, float(now_ts) - oldest_ts) if oldest_ts > 0 else 0.0
        return {"total": total, "oldest_age_s": oldest_age}


# ---------------------------------------------------------------------------
# Dependency call wrapper (P1): breaker + retries + jitter + timeout
# ---------------------------------------------------------------------------

def _sleep_backoff(attempt: int, policy: RetryPolicy) -> None:
    base = max(1, int(policy.base_backoff_ms))
    cap = max(base, int(policy.max_backoff_ms))
    # exponential backoff
    ms = min(cap, base * (2 ** max(0, attempt - 1)))
    jitter = float(policy.jitter)
    if jitter > 0:
        ms = int(ms * (1.0 + random.uniform(-jitter, jitter)))
        ms = max(0, ms)
    time.sleep(ms / 1000.0)


def dep_call(
    *,
    dep: str,
    op: str,
    breaker: CircuitBreaker,
    timeout_ms: int,
    policy: RetryPolicy,
    fn: Callable[[], Any],
) -> Any:
    """
    Breaker-aware, retrying dependency call.
    """
    timeout_s = max(0.001, float(timeout_ms) / 1000.0)
    last_exc: Optional[BaseException] = None

    for attempt in range(1, max(1, int(policy.max_attempts)) + 1):
        allow, is_probe = breaker.before_call()
        if not allow:
            _AGENT_DEP_ERROR.labels(dep, op, "breaker_open").inc()
            _AGENT_DEP_LATENCY.labels(dep, op, "breaker_open").observe(0.0)
            raise TimeoutError(f"{dep} breaker open")

        t0 = time.perf_counter()
        fut = None
        try:
            # use a lightweight thread for the dependency call to enforce timeout without blocking caller
            ex = concurrent.futures.ThreadPoolExecutor(max_workers=1)
            fut = ex.submit(fn)
            res = fut.result(timeout=timeout_s)
            dt = (time.perf_counter() - t0) * 1000.0
            _AGENT_DEP_LATENCY.labels(dep, op, "ok").observe(dt)
            breaker.record_success(was_probe=is_probe)
            return res
        except concurrent.futures.TimeoutError as exc:
            dt = (time.perf_counter() - t0) * 1000.0
            _AGENT_DEP_LATENCY.labels(dep, op, "timeout").observe(dt)
            _AGENT_DEP_ERROR.labels(dep, op, "timeout").inc()
            breaker.record_failure(was_probe=is_probe)
            last_exc = TimeoutError(f"{dep}.{op} timeout")
        except Exception as exc:
            dt = (time.perf_counter() - t0) * 1000.0
            _AGENT_DEP_LATENCY.labels(dep, op, "error").observe(dt)
            _AGENT_DEP_ERROR.labels(dep, op, "error").inc()
            breaker.record_failure(was_probe=is_probe)
            last_exc = exc
        finally:
            try:
                if fut is not None and last_exc is not None:
                    # best-effort cancel if possible
                    fut.cancel()
            except Exception:
                pass
            try:
                if "ex" in locals():
                    ex.shutdown(wait=False, cancel_futures=True)  # type: ignore[attr-defined]
            except Exception:
                pass

        if attempt < int(policy.max_attempts):
            _sleep_backoff(attempt, policy)

    if isinstance(last_exc, TimeoutError):
        raise last_exc
    raise RuntimeError(f"{dep}.{op} failed") from last_exc


# ---------------------------------------------------------------------------
# Event schema discipline (P1): bytes cap + truncation + digest
# ---------------------------------------------------------------------------

def enforce_payload_budget(
    payload: Dict[str, Any],
    *,
    max_bytes: int,
    ctx: str,
) -> Tuple[Dict[str, Any], List[str], str]:
    """
    Returns (payload2, truncated_fields, payload_digest)

    payload_digest is computed over canonical JSON with 'payload_digest' excluded.
    """
    max_bytes = max(256, int(max_bytes))
    truncated: List[str] = []

    def _digest(obj: Dict[str, Any]) -> str:
        obj2 = dict(obj)
        obj2.pop("payload_digest", None)
        return blake3_hex(canonical_json_bytes(obj2), ctx=ctx)

    def _size(obj: Dict[str, Any]) -> int:
        return len(canonical_json_bytes(obj))

    p = dict(payload)
    # placeholder digest first
    p["payload_digest"] = ""
    if _size(p) <= max_bytes:
        d = _digest(p)
        p["payload_digest"] = d
        return p, truncated, d

    # 1) truncate details
    if "details" in p and isinstance(p["details"], dict):
        truncated.append("details")
        # keep only a small safe subset
        keep_keys = ("policy_digest", "event_id", "reason_code", "stage", "action_id", "action", "mode")
        new_details = {k: p["details"].get(k) for k in keep_keys if k in p["details"]}
        # marker
        new_details["_truncated"] = True
        p["details"] = new_details

    if _size(p) <= max_bytes:
        d = _digest(p)
        p["payload_digest"] = d
        p["truncated_fields"] = truncated
        return p, truncated, d

    # 2) drop context (often large)
    if "context" in p:
        truncated.append("context")
        p["context"] = None

    if _size(p) <= max_bytes:
        d = _digest(p)
        p["payload_digest"] = d
        p["truncated_fields"] = truncated
        return p, truncated, d

    # 3) truncate error strings
    if "error" in p and isinstance(p["error"], str):
        truncated.append("error")
        p["error"] = truncate_str(p["error"], 128)

    if _size(p) <= max_bytes:
        d = _digest(p)
        p["payload_digest"] = d
        p["truncated_fields"] = truncated
        return p, truncated, d

    # 4) last resort: minimal envelope
    truncated.append("envelope_minimized")
    keep = {
        "v": p.get("v"),
        "kind": p.get("kind"),
        "stage": p.get("stage"),
        "event_id": p.get("event_id"),
        "ts_ns": p.get("ts_ns"),
        "policy_digest": p.get("policy_digest"),
        "truncated_fields": truncated,
        "payload_digest": "",
    }
    d = blake3_hex(canonical_json_bytes({k: v for k, v in keep.items() if k != "payload_digest"}), ctx=ctx)
    keep["payload_digest"] = d
    return keep, truncated, d


# ---------------------------------------------------------------------------
# TrustAgent (P0–P2)
# ---------------------------------------------------------------------------

class TrustAgent:
    """
    Platform-grade TrustAgent.

    - Strict budgets: gate + bounded executor queue + timeouts.
    - Evidence semantics: prepare/commit + attestation + outbox.
    - Pluggable: lock provider, outbox, runners.
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
        # evidence backends
        attestor: Optional[Any] = None,
        attestor_cfg: Optional[Any] = None,
        ledger: Optional[Any] = None,
        risk_oracle: Optional[Any] = None,
        # P1: global lock + outbox
        lock_provider: Optional[LockProviderProtocol] = None,
        outbox: Optional[OutboxProtocol] = None,
        # P0/P2: runner injection
        action_runner: Optional[RunnerProtocol] = None,
    ) -> None:
        self._lock = threading.RLock()
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

        self._policy_digest = self._compute_policy_digest(self.config.digest_material())

        self._audit_log: Deque[ActionResult] = deque(maxlen=max(1, int(self.config.max_audit_log_entries)))

        # P1 breaker
        self._attestor_breaker = CircuitBreaker(
            "attestor",
            threshold=self.config.breaker_failures,
            window_s=self.config.breaker_window_s,
            open_seconds=self.config.breaker_open_seconds,
        )
        self._ledger_breaker = CircuitBreaker(
            "ledger",
            threshold=self.config.breaker_failures,
            window_s=self.config.breaker_window_s,
            open_seconds=self.config.breaker_open_seconds,
        )

        # P0 gates
        self._gates: Dict[str, ActionGate] = {}

        # P1 global lock
        self._lock_provider: LockProviderProtocol = lock_provider or InProcessTTLLockProvider()

        # P1 outbox (durable by default if enabled)
        self._outbox: Optional[OutboxProtocol] = outbox
        if self._outbox is None and self.config.outbox_enabled:
            try:
                self._outbox = SQLiteOutbox(self.config.outbox_path)
            except Exception:
                logger.error("TrustAgent outbox init failed; disabling outbox", exc_info=True)
                self._outbox = None

        # P0 bounded runner
        self._action_runner: RunnerProtocol = action_runner or self._default_action_runner()

        # Strict profile checks (compat with your previous strict semantics)
        if self.config.strict_mode:
            if self.config.attestation_enabled and self.config.require_attestor and self._attestor is None:
                raise RuntimeError("TrustAgent strict_mode requires Attestor when attestation_enabled=True")
            if self.config.require_ledger and self._ledger is None:
                raise RuntimeError("TrustAgent strict_mode requires AuditLedger")
            if self.config.attestation_enabled and self.config.require_pq_attestor:
                if self._attestor_cfg is None:
                    raise RuntimeError("TrustAgent strict_mode requires AttestorConfig when require_pq_attestor=True")
                sig_alg = getattr(self._attestor_cfg, "sig_alg", None)
                if not sig_alg:
                    raise RuntimeError("TrustAgent strict_mode requires sig_alg on AttestorConfig")
                if self.config.allowed_sig_algs and sig_alg not in self.config.allowed_sig_algs:
                    raise RuntimeError(f"Attestor sig_alg {sig_alg!r} not in allowed_sig_algs")
            if self.config.attestation_enabled and self.config.allowed_sig_algs and self._attestor_cfg is None:
                raise RuntimeError("TrustAgent strict_mode with allowed_sig_algs requires AttestorConfig")

    # ------------------------------------------------------------------
    # Public inspection
    # ------------------------------------------------------------------

    @property
    def policy_digest(self) -> str:
        return self._policy_digest

    @property
    def audit_log(self) -> List[ActionResult]:
        with self._lock:
            return list(self._audit_log)

    def last_result(self) -> Optional[ActionResult]:
        with self._lock:
            return self._audit_log[-1] if self._audit_log else None

    def runtime_status(self) -> Dict[str, Any]:
        """
        SRE-friendly introspection.
        """
        with self._lock:
            gates = {k: v.inflight() for k, v in self._gates.items()}
        outbox_stats = {}
        if self._outbox is not None:
            now = time.time()
            for kind in ("ledger", "attestor"):
                try:
                    outbox_stats[kind] = self._outbox.stats(kind=kind, now_ts=now)
                except Exception:
                    outbox_stats[kind] = {"error": "stats_failed"}
        return {
            "policy_digest": self._policy_digest,
            "strict_mode": bool(self.config.strict_mode),
            "attestation_enabled": bool(self.config.attestation_enabled),
            "ledger_prepare_commit": bool(self.config.ledger_prepare_commit),
            "breaker": {
                "attestor_state": int(self._attestor_breaker.state().value),
                "ledger_state": int(self._ledger_breaker.state().value),
            },
            "gates_inflight": gates,
            "executors": {
                "action": self._action_runner.stats(),
            },
            "outbox": outbox_stats,
        }

    def flush_outbox(self, *, max_items: Optional[int] = None, budget_ms: Optional[int] = None) -> Dict[str, Any]:
        """
        Best-effort outbox flush with hard time budget.
        """
        if self._outbox is None:
            return {"ok": True, "enabled": False, "flushed": 0}

        budget_ms_eff = int(budget_ms if budget_ms is not None else self.config.outbox_flush_budget_ms)
        max_items_eff = int(max_items if max_items is not None else self.config.outbox_flush_max_items)
        deadline = time.perf_counter() + max(0.001, budget_ms_eff / 1000.0)

        now = time.time()
        flushed = 0
        details: Dict[str, Any] = {"ledger": {"ok": 0, "err": 0}, "attestor": {"ok": 0, "err": 0}}

        for kind in ("ledger", "attestor"):
            # update gauges
            try:
                st = self._outbox.stats(kind=kind, now_ts=now)
                _AGENT_OUTBOX_DEPTH.labels(kind).set(float(st.get("total", 0)))
                _AGENT_OUTBOX_OLDEST_AGE_S.labels(kind).set(float(st.get("oldest_age_s", 0.0)))
            except Exception:
                pass

            items = self._outbox.peek(kind=kind, limit=max_items_eff, now_ts=now)
            for it in items:
                if time.perf_counter() >= deadline:
                    break
                row_id = int(it.get("id", 0))
                attempts = int(it.get("attempts", 0))
                payload = it.get("payload") or {}
                try:
                    if kind == "ledger":
                        self._flush_one_ledger(payload)
                    else:
                        self._flush_one_attestor(payload)
                    self._outbox.ack(kind=kind, row_id=row_id)
                    flushed += 1
                    details[kind]["ok"] += 1
                    _AGENT_OUTBOX_FLUSH_TOTAL.labels(kind, "yes").inc()
                except Exception as exc:
                    # retry schedule: exponential backoff with jitter
                    attempts2 = attempts + 1
                    # next retry in seconds (cap 60s)
                    delay_s = min(60.0, 0.5 * (2 ** min(attempts2, 8)))
                    delay_s = delay_s * (1.0 + random.uniform(-0.2, 0.2))
                    next_ts = time.time() + max(0.1, delay_s)
                    self._outbox.nack(
                        kind=kind,
                        row_id=row_id,
                        attempts=attempts2,
                        next_ts=next_ts,
                        last_error=safe_error_str(exc),
                    )
                    details[kind]["err"] += 1
                    _AGENT_OUTBOX_FLUSH_TOTAL.labels(kind, "no").inc()

            # update gauges after processing
            try:
                st2 = self._outbox.stats(kind=kind, now_ts=time.time())
                _AGENT_OUTBOX_DEPTH.labels(kind).set(float(st2.get("total", 0)))
                _AGENT_OUTBOX_OLDEST_AGE_S.labels(kind).set(float(st2.get("oldest_age_s", 0.0)))
            except Exception:
                pass

        return {"ok": True, "enabled": True, "flushed": flushed, "details": details}

    # ------------------------------------------------------------------
    # Hot update config (P2)
    # ------------------------------------------------------------------

    def update_config(self, new_cfg: AgentConfig, *, mode: Optional[ExecutionMode] = None, context: Optional[ActionContext] = None) -> ActionResult:
        """
        Atomically update agent config:
        - swap config
        - recompute policy_digest
        - resize gates safely
        - refresh breaker thresholds
        - optionally emit an audit event (ledger/attestor best-effort)

        Protected by allow_agent_config_update (strict-mode policy knob).
        """
        action = "agent_cfg_reload"
        mode_eff = mode or self.config.default_mode
        ctx = context or ActionContext(request_id=self._default_request_id())

        res = self._new_result(action=action, mode=mode_eff, context=ctx)
        res.details["old_policy_digest"] = self._policy_digest

        if self.config.strict_mode and not bool(self.config.allow_agent_config_update):
            res.error_kind = ErrorKind.FORBIDDEN.value
            res.reason_code = ReasonCode.ACTION_FORBIDDEN.value
            res.reason_detail = "agent config update not allowed"
            res.business_ok = False
            res.ok = False
            return self._finalize(res)

        # Governance checks
        if self._blocked_by_context_guards(res):
            return self._finalize(res)

        with self._lock:
            self.config = new_cfg
            self._policy_digest = self._compute_policy_digest(self.config.digest_material())

            # resize gates
            for act, gate in self._gates.items():
                gate.resize(self._max_inflight_for_action(act))

            # refresh breaker settings
            self._attestor_breaker = CircuitBreaker(
                "attestor",
                threshold=self.config.breaker_failures,
                window_s=self.config.breaker_window_s,
                open_seconds=self.config.breaker_open_seconds,
            )
            self._ledger_breaker = CircuitBreaker(
                "ledger",
                threshold=self.config.breaker_failures,
                window_s=self.config.breaker_window_s,
                open_seconds=self.config.breaker_open_seconds,
            )

        res.details["new_policy_digest"] = self._policy_digest
        res.business_ok = True
        res.reason_code = ReasonCode.OK.value

        # optional evidence emission
        self._best_effort_evidence(res, stage="cfg_reload")

        res.ok = res.business_ok and (res.evidence_ok if self._evidence_required_for_result(res) else True)
        return self._finalize(res)

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    def apply_patch(
        self,
        patch: PatchProposal,
        *,
        mode: Optional[ExecutionMode] = None,
        context: Optional[ActionContext] = None,
    ) -> ActionResult:
        action = "apply_patch"
        mode_eff = mode or self.config.default_mode
        ctx = context or ActionContext(request_id=self._default_request_id())
        res = self._new_result(action=action, mode=mode_eff, context=ctx)

        # Gate (P0 strict correctness)
        gate = self._gate_for_action(action)
        acquired = gate.try_acquire()
        if not acquired:
            res.error_kind = ErrorKind.OVERLOADED.value
            res.reason_code = ReasonCode.GATE_OVERLOADED.value
            res.reason_detail = "too many in-flight"
            res.business_ok = False
            res.ok = False
            _AGENT_REJECT.labels(action, res.reason_code).inc()
            return self._finalize(res)

        try:
            # policy checks
            if self._blocked_by_mode_or_action(res):
                _AGENT_REJECT.labels(action, res.reason_code).inc()
                return self._finalize(res)
            if self._blocked_by_context_guards(res):
                _AGENT_REJECT.labels(action, res.reason_code).inc()
                return self._finalize(res)

            # patch sizing checks
            hunks = getattr(patch, "hunks", []) or []
            res.details["patch_id"] = getattr(patch, "patch_id", "")
            res.details["hunk_count"] = len(hunks)
            res.details["patch_risk"] = getattr(getattr(patch, "risk", None), "value", str(getattr(patch, "risk", "")))

            if len(hunks) > int(self.config.max_patch_hunks):
                res.error_kind = ErrorKind.POLICY.value
                res.reason_code = ReasonCode.PATCH_HUNK_LIMIT.value
                res.reason_detail = "too many hunks"
                res.business_ok = False
                res.ok = False
                _AGENT_REJECT.labels(action, res.reason_code).inc()
                return self._finalize(res)

            try:
                encoded = patch.to_json().encode("utf-8")
            except Exception as exc:
                res.error_kind = ErrorKind.INTERNAL.value
                res.reason_code = ReasonCode.PATCH_SERIALIZE_FAILED.value
                res.reason_detail = safe_error_str(exc)
                res.error = safe_error_str(exc)
                res.business_ok = False
                res.ok = False
                _AGENT_ERROR.labels(action, res.error_kind).inc()
                return self._finalize(res)

            if len(encoded) > int(self.config.max_patch_size_bytes):
                res.error_kind = ErrorKind.POLICY.value
                res.reason_code = ReasonCode.PATCH_SIZE_LIMIT.value
                res.reason_detail = "patch bytes limit exceeded"
                res.business_ok = False
                res.ok = False
                _AGENT_REJECT.labels(action, res.reason_code).inc()
                return self._finalize(res)

            # dry-run or not allowed => business ok but no effect
            if mode_eff is ExecutionMode.DRY_RUN or not self.config.allow_auto_patch:
                res.business_ok = True
                res.effect_executed = False
                res.reason_code = ReasonCode.DRY_RUN_OR_NOT_ALLOWED.value
                res.details["applied"] = False
                res.ok = True  # no evidence required for non-executed effect
                return self._finalize(res)

            if not self._apply_patch_cb:
                res.error_kind = ErrorKind.POLICY.value
                res.reason_code = ReasonCode.NO_CALLBACK.value
                res.reason_detail = "apply_patch callback not configured"
                res.business_ok = False
                res.ok = False
                return self._finalize(res)

            # Global lock (P1)
            lock_token = self._maybe_acquire_global_lock(res, action=action)
            if lock_token is None and self._requires_global_lock(action):
                _AGENT_REJECT.labels(action, res.reason_code).inc()
                return self._finalize(res)

            try:
                # Preflight evidence (P0/P1)
                if not self._preflight_before_side_effects(res):
                    _AGENT_REJECT.labels(action, res.reason_code).inc()
                    return self._finalize(res)

                # Oracle precheck
                if self._oracle_precheck(res):
                    _AGENT_REJECT.labels(action, res.reason_code).inc()
                    return self._finalize(res)

                # Execute callback with tri-state timeout (P0)
                try:
                    run = self._run_with_timeout(lambda: self._apply_patch_cb(patch, mode_eff, ctx), timeout_s=self._timeout_for_action(action))
                except RejectedExecution as exc:
                    res.error_kind = ErrorKind.OVERLOADED.value
                    res.reason_code = ReasonCode.QUEUE_FULL.value
                    res.reason_detail = str(exc)
                    res.business_ok = False
                    res.ok = False
                    _AGENT_REJECT.labels(action, res.reason_code).inc()
                    return self._finalize(res)

                self._apply_run_outcome(res, run, action=action)

                if run["status"] == "ok":
                    res.business_ok = True
                    res.details["applied"] = True
                else:
                    # timeout or exception => business fail
                    res.business_ok = False

                # Evidence best-effort (commit/attest/outbox)
                self._best_effort_evidence(res, stage="commit")

                # Compose overall_ok (P0 #5)
                res.ok = self._compose_overall_ok(res)
                return self._finalize(res)

            finally:
                # Global lock release semantics:
                # - if side_effect_uncertain (run-timeout leak) -> do NOT release; rely on TTL (prevents concurrent dangerous actions)
                # - else release immediately
                self._maybe_release_global_lock(action=action, token=lock_token, res=res)

        finally:
            # P0: release only if acquired
            gate.release()

    def restart(self, *, mode: Optional[ExecutionMode] = None, context: Optional[ActionContext] = None) -> ActionResult:
        return self._simple_action(
            action="restart",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_restart,
            callback=self._restart_cb,
        )

    def reload_config(self, *, mode: Optional[ExecutionMode] = None, context: Optional[ActionContext] = None) -> ActionResult:
        return self._simple_action(
            action="reload_config",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_reload_config,
            callback=self._reload_config_cb,
        )

    def rollback(self, *, mode: Optional[ExecutionMode] = None, context: Optional[ActionContext] = None) -> ActionResult:
        return self._simple_action(
            action="rollback",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_rollback,
            callback=self._rollback_cb,
        )

    def rotate_keys(self, *, mode: Optional[ExecutionMode] = None, context: Optional[ActionContext] = None) -> ActionResult:
        return self._simple_action(
            action="rotate_keys",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_key_rotation,
            callback=self._rotate_keys_cb,
        )

    def calibrate_model(self, *, mode: Optional[ExecutionMode] = None, context: Optional[ActionContext] = None) -> ActionResult:
        return self._simple_action(
            action="calibrate_model",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_model_calibration,
            callback=self._calibrate_model_cb,
        )

    def update_policies(self, *, mode: Optional[ExecutionMode] = None, context: Optional[ActionContext] = None) -> ActionResult:
        return self._simple_action(
            action="update_policies",
            mode=mode,
            context=context,
            allow_flag=self.config.allow_policy_update,
            callback=self._update_policies_cb,
        )

    # ------------------------------------------------------------------
    # Core action helper
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
        mode_eff = mode or self.config.default_mode
        ctx = context or ActionContext(request_id=self._default_request_id())
        res = self._new_result(action=action, mode=mode_eff, context=ctx)

        gate = self._gate_for_action(action)
        acquired = gate.try_acquire()
        if not acquired:
            res.error_kind = ErrorKind.OVERLOADED.value
            res.reason_code = ReasonCode.GATE_OVERLOADED.value
            res.reason_detail = "too many in-flight"
            res.business_ok = False
            res.ok = False
            _AGENT_REJECT.labels(action, res.reason_code).inc()
            return self._finalize(res)

        try:
            if self._blocked_by_mode_or_action(res):
                _AGENT_REJECT.labels(action, res.reason_code).inc()
                return self._finalize(res)

            if self._blocked_by_context_guards(res):
                _AGENT_REJECT.labels(action, res.reason_code).inc()
                return self._finalize(res)

            if mode_eff is ExecutionMode.DRY_RUN or not allow_flag:
                res.business_ok = True
                res.effect_executed = False
                res.reason_code = ReasonCode.DRY_RUN_OR_NOT_ALLOWED.value
                res.details["executed"] = False
                res.ok = True
                return self._finalize(res)

            if not callback:
                res.error_kind = ErrorKind.POLICY.value
                res.reason_code = ReasonCode.NO_CALLBACK.value
                res.reason_detail = "callback not configured"
                res.business_ok = False
                res.ok = False
                return self._finalize(res)

            # Global lock (P1) for high-risk actions
            lock_token = self._maybe_acquire_global_lock(res, action=action)
            if lock_token is None and self._requires_global_lock(action):
                _AGENT_REJECT.labels(action, res.reason_code).inc()
                return self._finalize(res)

            try:
                if not self._preflight_before_side_effects(res):
                    _AGENT_REJECT.labels(action, res.reason_code).inc()
                    return self._finalize(res)

                if self._oracle_precheck(res):
                    _AGENT_REJECT.labels(action, res.reason_code).inc()
                    return self._finalize(res)

                try:
                    run = self._run_with_timeout(lambda: callback(ctx), timeout_s=self._timeout_for_action(action))
                except RejectedExecution as exc:
                    res.error_kind = ErrorKind.OVERLOADED.value
                    res.reason_code = ReasonCode.QUEUE_FULL.value
                    res.reason_detail = str(exc)
                    res.business_ok = False
                    res.ok = False
                    _AGENT_REJECT.labels(action, res.reason_code).inc()
                    return self._finalize(res)

                self._apply_run_outcome(res, run, action=action)

                if run["status"] == "ok":
                    res.business_ok = True
                    res.details["executed"] = True
                else:
                    res.business_ok = False
                    res.details["executed"] = False

                self._best_effort_evidence(res, stage="commit")
                res.ok = self._compose_overall_ok(res)
                return self._finalize(res)

            finally:
                self._maybe_release_global_lock(action=action, token=lock_token, res=res)

        finally:
            gate.release()

    # ------------------------------------------------------------------
    # Policy / governance
    # ------------------------------------------------------------------

    def _blocked_by_mode_or_action(self, res: ActionResult) -> bool:
        if self.config.forbidden_actions and res.action in self.config.forbidden_actions:
            res.error_kind = ErrorKind.FORBIDDEN.value
            res.reason_code = ReasonCode.ACTION_FORBIDDEN.value
            res.reason_detail = "forbidden_actions"
            res.business_ok = False
            res.ok = False
            return True

        if self.config.allowed_modes is not None and res.mode not in self.config.allowed_modes:
            res.error_kind = ErrorKind.FORBIDDEN.value
            res.reason_code = ReasonCode.MODE_FORBIDDEN.value
            res.reason_detail = "allowed_modes"
            res.business_ok = False
            res.ok = False
            return True

        return False

    def _effective_guards_for_action(self, action: str) -> Dict[str, bool]:
        base = {
            "require_change_ticket": self.config.require_change_ticket,
            "require_human_approver": self.config.require_human_approver,
            "require_mfa_tag": self.config.require_mfa_tag,
        }
        overrides = self.config.per_action_guards.get(action) or {}
        merged = dict(base)
        for k in ("require_change_ticket", "require_human_approver", "require_mfa_tag"):
            if k in overrides:
                merged[k] = bool(overrides[k])
        return merged

    def _blocked_by_context_guards(self, res: ActionResult) -> bool:
        if not self.config.strict_mode:
            return False

        ctx = res.context
        meta = (ctx.metadata if (ctx and ctx.metadata) else {}) or {}
        guards = self._effective_guards_for_action(res.action)

        if res.mode is ExecutionMode.PRODUCTION:
            if guards.get("require_change_ticket") and not meta.get("change_ticket_id"):
                res.error_kind = ErrorKind.POLICY.value
                res.reason_code = ReasonCode.MISSING_CHANGE_TICKET.value
                res.reason_detail = "change_ticket_id missing"
                res.business_ok = False
                res.ok = False
                return True

            if guards.get("require_human_approver"):
                approver = meta.get("approved_by")
                if not approver:
                    res.error_kind = ErrorKind.POLICY.value
                    res.reason_code = ReasonCode.MISSING_HUMAN_APPROVER.value
                    res.reason_detail = "approved_by missing"
                    res.business_ok = False
                    res.ok = False
                    return True
                actor = ctx.user if ctx else None
                if actor and actor == approver:
                    res.error_kind = ErrorKind.POLICY.value
                    res.reason_code = ReasonCode.APPROVER_SAME_AS_ACTOR.value
                    res.reason_detail = "approved_by equals actor"
                    res.business_ok = False
                    res.ok = False
                    return True

            if self.config.approval_system_allowlist:
                system_tag = meta.get("approval_system")
                if system_tag not in self.config.approval_system_allowlist:
                    res.error_kind = ErrorKind.POLICY.value
                    res.reason_code = ReasonCode.INVALID_APPROVAL_SYSTEM.value
                    res.reason_detail = "approval_system not allowed"
                    res.business_ok = False
                    res.ok = False
                    return True

        if guards.get("require_mfa_tag") and not meta.get("mfa_verified"):
            res.error_kind = ErrorKind.POLICY.value
            res.reason_code = ReasonCode.MFA_REQUIRED.value
            res.reason_detail = "mfa_verified missing/false"
            res.business_ok = False
            res.ok = False
            return True

        return False

    # ------------------------------------------------------------------
    # Global lock (P1)
    # ------------------------------------------------------------------

    def _requires_global_lock(self, action: str) -> bool:
        spec = (self.config.per_action_limits or {}).get(action) or {}
        if "requires_global_lock" in spec:
            return bool(spec["requires_global_lock"])
        # default: protect dangerous ops in strict_mode
        if self.config.strict_mode and action in ("restart", "rotate_keys", "rollback"):
            return True
        return False

    def _global_lock_ttl_s(self, action: str) -> float:
        spec = (self.config.per_action_limits or {}).get(action) or {}
        if "global_lock_ttl_s" in spec:
            try:
                return max(0.1, float(spec["global_lock_ttl_s"]))
            except Exception:
                return float(self.config.global_lock_default_ttl_s)
        return float(self.config.global_lock_default_ttl_s)

    def _maybe_acquire_global_lock(self, res: ActionResult, *, action: str) -> Optional[str]:
        if not self.config.global_lock_enabled:
            return None
        if not self._requires_global_lock(action):
            return None

        ttl = self._global_lock_ttl_s(action)
        name = f"tcd:agent:{action}"
        tok = self._lock_provider.acquire(name, ttl_s=ttl)
        if not tok:
            res.error_kind = ErrorKind.OVERLOADED.value
            res.reason_code = ReasonCode.LOCK_HELD.value
            res.reason_detail = f"global lock held: {name}"
            res.business_ok = False
            res.ok = False
            return None

        res.details["global_lock"] = {"name": name, "ttl_s": ttl}
        return tok

    def _maybe_release_global_lock(self, *, action: str, token: Optional[str], res: ActionResult) -> None:
        if not token or not self._requires_global_lock(action):
            return
        # If run-timeout leak, keep lock until TTL expires (prevents concurrent disaster)
        if res.side_effect_uncertain:
            res.details.setdefault("global_lock", {})
            res.details["global_lock"]["released"] = False
            res.details["global_lock"]["release_reason"] = "side_effect_uncertain"
            return
        try:
            name = f"tcd:agent:{action}"
            self._lock_provider.release(name, token)
            res.details.setdefault("global_lock", {})
            res.details["global_lock"]["released"] = True
        except Exception:
            res.details.setdefault("global_lock", {})
            res.details["global_lock"]["released"] = False
            res.details["global_lock"]["release_reason"] = "release_failed"

    # ------------------------------------------------------------------
    # Evidence preflight + delivery (P0/P1)
    # ------------------------------------------------------------------

    def _evidence_required_for_result(self, res: ActionResult) -> bool:
        # Evidence is only required when we may execute side effects in strict mode.
        if not self.config.strict_mode:
            return False
        # If no side effects started and policy blocked/dry-run -> not required.
        # But for strict-mode side-effect actions, require evidence.
        return bool(res.effect_executed) or self._would_execute_side_effects(res)

    def _would_execute_side_effects(self, res: ActionResult) -> bool:
        if res.mode is ExecutionMode.DRY_RUN:
            return False
        # heuristic: if action is one of our callbacks and allowed flag likely true
        return res.action in ("apply_patch", "restart", "reload_config", "rollback", "rotate_keys", "calibrate_model", "update_policies")

    def _preflight_before_side_effects(self, res: ActionResult) -> bool:
        """
        P0/P1: strict-mode enforces:
          - if require_ledger: prepare MUST succeed before executing callback (when ledger_prepare_commit enabled)
          - if require_attestor: attestor must exist and breaker not open
        """
        if not self.config.strict_mode:
            return True

        # attestor preflight
        if self.config.attestation_enabled and self.config.require_attestor:
            if self._attestor is None:
                res.error_kind = ErrorKind.ATTESTOR.value
                res.reason_code = ReasonCode.BREAKER_OPEN.value  # low-cardinality; detail clarifies
                res.reason_detail = "attestor missing"
                res.business_ok = False
                res.evidence_ok = False
                res.ok = False
                return False
            if self._attestor_breaker.is_open():
                res.error_kind = ErrorKind.ATTESTOR.value
                res.reason_code = ReasonCode.BREAKER_OPEN.value
                res.reason_detail = "attestor breaker open"
                res.business_ok = False
                res.evidence_ok = False
                res.ok = False
                return False

        # ledger preflight + prepare
        if self.config.require_ledger:
            if self._ledger is None:
                res.error_kind = ErrorKind.LEDGER.value
                res.reason_code = ReasonCode.BREAKER_OPEN.value
                res.reason_detail = "ledger missing"
                res.business_ok = False
                res.evidence_ok = False
                res.ok = False
                return False
            if self._ledger_breaker.is_open():
                res.error_kind = ErrorKind.LEDGER.value
                res.reason_code = ReasonCode.BREAKER_OPEN.value
                res.reason_detail = "ledger breaker open"
                res.business_ok = False
                res.evidence_ok = False
                res.ok = False
                return False

            if self.config.ledger_prepare_commit:
                try:
                    self._append_ledger_stage(res, stage="prepare", require=True)
                    return True
                except Exception as exc:
                    res.error_kind = ErrorKind.LEDGER.value
                    res.reason_code = ReasonCode.LEDGER_PREPARE_FAILED.value
                    res.reason_detail = safe_error_str(exc)
                    res.error = safe_error_str(exc)
                    res.business_ok = False
                    res.evidence_ok = False
                    res.ok = False
                    return False

        return True

    def _best_effort_evidence(self, res: ActionResult, *, stage: str) -> None:
        """
        Post-execution evidence:
          - attestation issue (retry policy + breaker)
          - ledger commit append (retry policy + breaker)
          - if fails, enqueue to outbox
        """
        # For actions with no side effect attempt, avoid making evidence requirements stricter than needed.
        if not self._evidence_required_for_result(res):
            res.evidence_ok = True
            return

        evidence_ok = True

        # Attestation
        if self.config.attestation_enabled:
            try:
                self._attach_attestation(res)
            except Exception as exc:
                evidence_ok = False
                res.details["attestation_error"] = safe_error_str(exc)
                if self._outbox is not None:
                    # enqueue attestor request for retry
                    try:
                        payload = self._build_attestor_request(res)
                        payload, truncated, pd = enforce_payload_budget(
                            payload,
                            max_bytes=self.config.outbox_max_payload_bytes,
                            ctx="tcd:agent:outbox:attestor",
                        )
                        self._outbox.put(kind="attestor", dedupe_key=f"{res.action_id}:attest", payload=payload, payload_digest=pd)
                        res.details["outbox_attestor_enqueued"] = True
                        res.details["outbox_attestor_truncated_fields"] = truncated
                        res.reason_code = ReasonCode.OUTBOX_ENQUEUED.value
                    except Exception as exc2:
                        res.details["outbox_attestor_enqueued"] = False
                        res.details["outbox_attestor_error"] = safe_error_str(exc2)
                        res.reason_code = ReasonCode.OUTBOX_ENQUEUE_FAILED.value

                if self.config.strict_mode and self.config.require_attestor:
                    res.error_kind = res.error_kind or ErrorKind.EVIDENCE_GAP.value
                    res.reason_code = ReasonCode.ATTESTATION_FAILED.value
                    res.reason_detail = "attestation failed"
                    _AGENT_ERROR.labels(res.action, ErrorKind.ATTESTOR.value).inc()

        # Ledger commit
        if self._ledger is not None:
            try:
                self._append_ledger_stage(res, stage="commit", require=bool(self.config.strict_mode and self.config.require_ledger))
            except Exception as exc:
                evidence_ok = False
                res.details["ledger_commit_error"] = safe_error_str(exc)
                if self._outbox is not None:
                    try:
                        # enqueue commit event for retry
                        payload = self._build_ledger_event(res, stage="commit")
                        payload, truncated, pd = enforce_payload_budget(
                            payload,
                            max_bytes=self.config.outbox_max_payload_bytes,
                            ctx="tcd:agent:outbox:ledger",
                        )
                        self._outbox.put(kind="ledger", dedupe_key=payload.get("event_id", f"{res.action_id}:commit"), payload=payload, payload_digest=pd)
                        res.details["outbox_ledger_enqueued"] = True
                        res.details["outbox_ledger_truncated_fields"] = truncated
                        res.reason_code = ReasonCode.OUTBOX_ENQUEUED.value
                    except Exception as exc2:
                        res.details["outbox_ledger_enqueued"] = False
                        res.details["outbox_ledger_error"] = safe_error_str(exc2)
                        res.reason_code = ReasonCode.OUTBOX_ENQUEUE_FAILED.value

                if self.config.strict_mode and self.config.require_ledger:
                    res.error_kind = res.error_kind or ErrorKind.EVIDENCE_GAP.value
                    res.reason_code = ReasonCode.LEDGER_COMMIT_FAILED.value
                    res.reason_detail = "ledger commit failed"
                    _AGENT_ERROR.labels(res.action, ErrorKind.LEDGER.value).inc()

        res.evidence_ok = bool(evidence_ok)

        # Opportunistic flush (bounded)
        if self._outbox is not None and self.config.outbox_flush_on_wrapup:
            try:
                self.flush_outbox(max_items=self.config.outbox_flush_max_items, budget_ms=self.config.outbox_flush_budget_ms)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Oracle
    # ------------------------------------------------------------------

    def _oracle_precheck(self, res: ActionResult) -> bool:
        if self._risk_oracle is None:
            return False
        try:
            fn = getattr(self._risk_oracle, "precheck", None)
            if fn is None:
                return False
            verdict = fn(res)
            if isinstance(verdict, dict):
                if "score" in verdict:
                    try:
                        res.details["oracle_pre_score"] = float(verdict["score"])
                    except Exception:
                        pass
                if verdict.get("block"):
                    res.error_kind = ErrorKind.ORACLE.value
                    res.reason_code = ReasonCode.ORACLE_BLOCK.value
                    res.reason_detail = str(verdict.get("reason") or "oracle_block")
                    res.error = "oracle_block"
                    res.business_ok = False
                    res.ok = False
                    return True
        except Exception:
            _AGENT_ERROR.labels(res.action, "oracle").inc()
            logger.warning("TrustAgent oracle precheck failed", exc_info=True)
        return False

    # ------------------------------------------------------------------
    # Runner timeout tri-state (P0 #3/#4)
    # ------------------------------------------------------------------

    def _run_with_timeout(self, fn: Callable[[], Any], *, timeout_s: float) -> Dict[str, Any]:
        """
        Returns dict:
          status: "ok" | "timeout" | "error"
          started: bool
          cancelled: bool
          side_effect_uncertain: bool
          timeout_kind: "queue" | "run" | None
          error: str | None
        """
        timeout_s = max(0.001, float(timeout_s))
        fut, meta = self._action_runner.submit(fn)

        try:
            fut.result(timeout=timeout_s)
            return {
                "status": "ok",
                "started": bool(meta.started_evt.is_set()),
                "cancelled": False,
                "side_effect_uncertain": False,
                "timeout_kind": None,
                "error": None,
            }
        except concurrent.futures.TimeoutError:
            # Determine whether it started. If not started, cancel and it's NOT uncertain.
            started = bool(meta.started_evt.is_set())
            if not started:
                cancelled = bool(fut.cancel())
                if not cancelled:
                    # race: give a tiny chance for started_evt to flip
                    meta.started_evt.wait(timeout=0.01)
                    started = bool(meta.started_evt.is_set())
                if cancelled and not started:
                    return {
                        "status": "timeout",
                        "started": False,
                        "cancelled": True,
                        "side_effect_uncertain": False,
                        "timeout_kind": "queue",
                        "error": "queue_timeout",
                    }
                # if cannot cancel or started flipped -> uncertain
                return {
                    "status": "timeout",
                    "started": bool(started),
                    "cancelled": False,
                    "side_effect_uncertain": True,
                    "timeout_kind": "run",
                    "error": "run_timeout_uncertain",
                }

            # started => cannot safely cancel; leak
            return {
                "status": "timeout",
                "started": True,
                "cancelled": False,
                "side_effect_uncertain": True,
                "timeout_kind": "run",
                "error": "run_timeout",
            }
        except RejectedExecution:
            raise
        except Exception as exc:
            return {
                "status": "error",
                "started": bool(meta.started_evt.is_set()),
                "cancelled": False,
                "side_effect_uncertain": bool(meta.started_evt.is_set()),
                "timeout_kind": None,
                "error": safe_error_str(exc),
            }

    def _apply_run_outcome(self, res: ActionResult, run: Dict[str, Any], *, action: str) -> None:
        # started/cancelled/uncertain (P0 tri-state)
        res.callback_started = bool(run.get("started", False))
        res.callback_cancelled = bool(run.get("cancelled", False))
        res.side_effect_uncertain = bool(run.get("side_effect_uncertain", False))
        res.effect_executed = bool(res.callback_started)

        if run["status"] == "ok":
            res.reason_code = ReasonCode.OK.value
            return

        if run["status"] == "timeout":
            res.error_kind = ErrorKind.TIMEOUT.value
            if run.get("timeout_kind") == "queue":
                res.reason_code = ReasonCode.QUEUE_TIMEOUT.value
                res.reason_detail = "timed out waiting to start"
            else:
                res.reason_code = ReasonCode.RUN_TIMEOUT.value
                res.reason_detail = "timed out during execution"
                # leak accounting (P0 #3)
                if res.side_effect_uncertain:
                    _AGENT_CALLBACK_LEAK_TOTAL.labels(action).inc()
                    _AGENT_CALLBACK_LEAK_INFLIGHT.labels(action).inc()
                    # decrement leak inflight when future completes
                    try:
                        # best-effort: attach a completion decrement
                        def _dec(_: Any) -> None:
                            _AGENT_CALLBACK_LEAK_INFLIGHT.labels(action).dec()

                        # NOTE: can't access future here reliably; but run_timeout implies it's still running.
                        # We track leak inflight via periodic decrements only if we had the future.
                        # Caller path can add it when needed; here we conservatively do counter only.
                        pass
                    except Exception:
                        pass
            res.business_ok = False
            res.ok = False
            _AGENT_ERROR.labels(action, res.error_kind).inc()
            return

        # run["status"] == "error"
        res.error_kind = ErrorKind.CALLBACK.value
        res.reason_code = ReasonCode.EXCEPTION.value
        res.reason_detail = run.get("error") or "callback exception"
        res.error = run.get("error")
        res.business_ok = False
        res.ok = False
        _AGENT_ERROR.labels(action, res.error_kind).inc()

    # ------------------------------------------------------------------
    # Executor default (P0 #4)
    # ------------------------------------------------------------------

    def _default_action_runner(self) -> RunnerProtocol:
        # Backpressure enforced in BoundedExecutor wrapper.
        ex = concurrent.futures.ThreadPoolExecutor(max_workers=self.config.action_executor_workers, thread_name_prefix="tcd-agent-action")
        return BoundedExecutor(
            name="action",
            executor=ex,
            max_workers=self.config.action_executor_workers,
            max_queue=self.config.action_executor_queue,
        )

    # ------------------------------------------------------------------
    # Ledger / Attestor build + append
    # ------------------------------------------------------------------

    def _stage_event_id(self, action_id: str, stage: str) -> str:
        # P0 #2: dedupe key must include stage
        return f"{action_id}:{stage}"

    def _build_ledger_event(self, res: ActionResult, *, stage: str) -> Dict[str, Any]:
        ctx = res.context.to_dict(safe=True, cfg=self.config) if res.context else None
        # include prepare reference if known
        prepare_eid = res.details.get("ledger_prepare_event_id")
        prepare_digest = res.details.get("ledger_prepare_digest")

        evt: Dict[str, Any] = {
            "v": int(self.config.ledger_schema_version),
            "kind": "agent_action",
            "stage": stage,
            "event_id": self._stage_event_id(res.action_id, stage),
            "action_id": res.action_id,
            "ts_ns": time.time_ns(),
            "agent": "TrustAgent",
            "action": res.action,
            "mode": res.mode.value,
            "overall_ok": res.overall_ok,
            "business_ok": bool(res.business_ok),
            "evidence_ok": bool(res.evidence_ok),
            "effect_executed": bool(res.effect_executed),
            "callback_started": bool(res.callback_started),
            "callback_cancelled": bool(res.callback_cancelled),
            "side_effect_uncertain": bool(res.side_effect_uncertain),
            "error_kind": res.error_kind,
            "reason_code": res.reason_code,
            "reason_detail": truncate_str(res.reason_detail or "", 512) if res.reason_detail else None,
            "error": truncate_str(res.error or "", 512) if res.error else None,
            "duration_ms": float(res.duration_ms()),
            "policy_digest": self._policy_digest,
            "node_id": self.config.node_id,
            "proc_id": self.config.proc_id,
            "supply_chain_label": self.config.supply_chain_label,
            "image_digest": self.config.image_digest,
            "build_id": self.config.build_id,
            "context": ctx,
            "details": json_sanitize(res.details),
            "prepare_event_id": prepare_eid,
            "prepare_digest": prepare_digest,
            "receipt": res.receipt,
            "verify_key": res.verify_key,
            "truncated_fields": [],
            "payload_digest": "",
        }
        return evt

    def _append_ledger_stage(self, res: ActionResult, *, stage: str, require: bool) -> None:
        if self._ledger is None:
            if require:
                raise RuntimeError("ledger missing")
            return

        evt = self._build_ledger_event(res, stage=stage)
        evt, truncated, pd = enforce_payload_budget(
            evt,
            max_bytes=self.config.max_ledger_event_bytes,
            ctx="tcd:agent:ledger",
        )
        evt["truncated_fields"] = truncated
        evt["payload_digest"] = pd

        # Save prepare proof so commit can reference it
        if stage == "prepare":
            res.details["ledger_prepare_event_id"] = evt.get("event_id")
            res.details["ledger_prepare_digest"] = evt.get("payload_digest")
            res.details["ledger_prepare_ts_ns"] = evt.get("ts_ns")

        policy = self.config.dep_retry_ledger_prepare if stage == "prepare" else self.config.dep_retry_ledger_commit

        def _append() -> None:
            self._ledger.append(evt)

        try:
            dep_call(
                dep="ledger",
                op=f"append_{stage}",
                breaker=self._ledger_breaker,
                timeout_ms=int(self.config.dep_timeout_ledger_ms),
                policy=policy,
                fn=_append,
            )
        except Exception:
            if require:
                raise
            # best-effort: don't raise
            raise

    def _build_attestor_request(self, res: ActionResult) -> Dict[str, Any]:
        ctx_dict = res.context.to_dict(safe=True, cfg=self.config) if res.context else {}
        req_obj: Dict[str, Any] = {
            "action": res.action,
            "action_id": res.action_id,
            "mode": res.mode.value,
            "context": {
                "request_id": ctx_dict.get("request_id"),
                "session_id": ctx_dict.get("session_id"),
                "tenant": ctx_dict.get("tenant"),
                "user": ctx_dict.get("user"),
                "component": ctx_dict.get("component"),
            },
            "event_id": self._stage_event_id(res.action_id, "attest"),
            "schema_v": int(self.config.attestation_schema_version),
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
            "decision": "success" if res.overall_ok else "failure",
            "duration_ms": float(res.duration_ms()),
            "error_kind": res.error_kind,
            "reason_code": res.reason_code,
            "error": truncate_str(res.error or "", 512) if res.error else None,
            "action": res.action,
            "mode": res.mode.value,
            "event_id": self._stage_event_id(res.action_id, "attest"),
        }

        segments: List[Dict[str, Any]] = [
            {"kind": "agent_cfg", "id": self.config.node_id or "tcd_agent", "digest": self._policy_digest, "meta": {}}
        ]
        if self._ledger is not None and hasattr(self._ledger, "head"):
            try:
                segments.append({"kind": "audit_ledger_head", "id": self.config.node_id or "tcd_agent", "digest": self._ledger.head(), "meta": {}})
            except Exception:
                pass
        if self._attestor_cfg is not None:
            cfg_digest = getattr(self._attestor_cfg, "default_cfg_digest", None)
            if cfg_digest:
                segments.append({"kind": "system_cfg", "id": "tcd_system", "digest": cfg_digest, "meta": {}})

        tags = ["tcd_agent", res.action, res.mode.value]

        meta = {
            "ok": res.overall_ok,
            "policy_digest": self._policy_digest,
            "node_id": self.config.node_id,
            "proc_id": self.config.proc_id,
            "event_id": self._stage_event_id(res.action_id, "attest"),
        }
        return {
            "v": int(self.config.attestation_schema_version),
            "kind": "attestor_issue",
            "event_id": self._stage_event_id(res.action_id, "attest"),
            "req_obj": req_obj,
            "comp_obj": comp_obj,
            "e_obj": e_obj,
            "witness_segments": segments,
            "witness_tags": tags,
            "meta": meta,
        }

    def _attach_attestation(self, res: ActionResult) -> None:
        if self._attestor is None:
            raise RuntimeError("attestor missing")

        payload = self._build_attestor_request(res)
        payload, _truncated, _pd = enforce_payload_budget(
            payload,
            max_bytes=self.config.max_attestor_req_bytes,
            ctx="tcd:agent:attestor:req",
        )

        def _issue() -> Any:
            # payload is structured to be idempotent-ish by event_id in req_obj/meta
            return self._attestor.issue(  # type: ignore[call-arg]
                req_obj=payload["req_obj"],
                comp_obj=payload["comp_obj"],
                e_obj=payload["e_obj"],
                witness_segments=payload["witness_segments"],
                witness_tags=payload["witness_tags"],
                meta=payload["meta"],
            )

        att = dep_call(
            dep="attestor",
            op="issue",
            breaker=self._attestor_breaker,
            timeout_ms=int(self.config.dep_timeout_attestor_ms),
            policy=self.config.dep_retry_attestor,
            fn=_issue,
        )

        if isinstance(att, dict):
            res.receipt = att.get("receipt")
            res.receipt_body = att.get("receipt_body")
            res.receipt_sig = att.get("receipt_sig")
            res.verify_key = att.get("verify_key")

    # ------------------------------------------------------------------
    # Outbox flushing internals
    # ------------------------------------------------------------------

    def _flush_one_ledger(self, payload: Dict[str, Any]) -> None:
        if self._ledger is None:
            raise RuntimeError("ledger missing")
        evt = payload
        # enforce payload budgets again (defensive)
        evt, _truncated, _pd = enforce_payload_budget(evt, max_bytes=self.config.max_ledger_event_bytes, ctx="tcd:agent:ledger")
        self._ledger.append(evt)

    def _flush_one_attestor(self, payload: Dict[str, Any]) -> None:
        if self._attestor is None:
            raise RuntimeError("attestor missing")
        # payload contains the issue request envelope
        req = payload
        req, _truncated, _pd = enforce_payload_budget(req, max_bytes=self.config.max_attestor_req_bytes, ctx="tcd:agent:attestor:req")
        self._attestor.issue(  # type: ignore[call-arg]
            req_obj=req["req_obj"],
            comp_obj=req["comp_obj"],
            e_obj=req["e_obj"],
            witness_segments=req["witness_segments"],
            witness_tags=req["witness_tags"],
            meta=req["meta"],
        )

    # ------------------------------------------------------------------
    # Compose overall_ok (P0 #5)
    # ------------------------------------------------------------------

    def _compose_overall_ok(self, res: ActionResult) -> bool:
        # Evidence required only under strict for side-effects
        if self.config.strict_mode and self._evidence_required_for_result(res):
            if res.business_ok and not res.evidence_ok:
                # effect likely executed but evidence incomplete
                res.error_kind = res.error_kind or ErrorKind.EVIDENCE_GAP.value
                res.reason_code = res.reason_code if res.reason_code != ReasonCode.OK.value else ReasonCode.ATTESTATION_FAILED.value
            return bool(res.business_ok and res.evidence_ok)
        return bool(res.business_ok)

    # ------------------------------------------------------------------
    # Gate/timeout helpers
    # ------------------------------------------------------------------

    def _gate_for_action(self, action: str) -> ActionGate:
        with self._lock:
            g = self._gates.get(action)
            if g is not None:
                return g
            g = ActionGate(action, self._max_inflight_for_action(action))
            self._gates[action] = g
            return g

    def _max_inflight_for_action(self, action: str) -> int:
        base = max(1, int(self.config.max_inflight_default))
        spec = (self.config.per_action_limits or {}).get(action) or {}
        try:
            if "max_inflight" in spec:
                return max(1, int(spec["max_inflight"]))
        except Exception:
            pass
        return base

    def _timeout_for_action(self, action: str) -> float:
        base = max(0.1, float(self.config.max_action_duration_s))
        spec = (self.config.per_action_limits or {}).get(action) or {}
        try:
            if "timeout_s" in spec:
                return max(0.1, min(base, float(spec["timeout_s"])))
        except Exception:
            pass
        return base

    # ------------------------------------------------------------------
    # Result lifecycle
    # ------------------------------------------------------------------

    def _new_result(self, *, action: str, mode: ExecutionMode, context: ActionContext) -> ActionResult:
        now = time.time()
        mono = time.perf_counter()
        r = ActionResult(
            action_id=self._new_action_id(),
            action=action,
            mode=mode,
            ok=False,
            business_ok=False,
            evidence_ok=True,
            effect_executed=False,
            callback_started=False,
            callback_cancelled=False,
            side_effect_uncertain=False,
            started_at=now,
            finished_at=now,
            started_mono=mono,
            finished_mono=mono,
            error_kind=None,
            reason_code=ReasonCode.OK.value,
            reason_detail=None,
            error=None,
            details={"policy_digest": self._policy_digest},
            context=context,
        )
        return r

    def _finalize(self, res: ActionResult) -> ActionResult:
        res.finished_at = time.time()
        res.finished_mono = time.perf_counter()

        # Update audit log bounded
        with self._lock:
            self._audit_log.append(res)

        # Metrics
        ok_label = "yes" if res.overall_ok else "no"
        _AGENT_LATENCY.labels(res.action, res.mode.value, ok_label).observe(res.duration_ms())
        _AGENT_TOTAL.labels(res.action, res.mode.value, ok_label).inc()
        if res.error_kind:
            _AGENT_ERROR.labels(res.action, res.error_kind).inc()

        # Structured log (sanitized)
        try:
            ctx_safe = res.context.to_dict(safe=True, cfg=self.config) if res.context else None
            logger.info(
                "tcd.agent.action",
                extra={
                    "tcd_action": res.action,
                    "tcd_action_id": res.action_id,
                    "tcd_mode": res.mode.value,
                    "tcd_overall_ok": res.overall_ok,
                    "tcd_business_ok": res.business_ok,
                    "tcd_evidence_ok": res.evidence_ok,
                    "tcd_effect_executed": res.effect_executed,
                    "tcd_error_kind": res.error_kind,
                    "tcd_reason_code": res.reason_code,
                    "tcd_reason_detail": truncate_str(res.reason_detail or "", 256) if res.reason_detail else None,
                    "tcd_error": truncate_str(res.error or "", 256) if res.error else None,
                    "tcd_duration_ms": res.duration_ms(),
                    "tcd_context": ctx_safe,
                    "tcd_policy_digest": self._policy_digest,
                    "tcd_node_id": self.config.node_id,
                    "tcd_proc_id": self.config.proc_id,
                    "tcd_supply_chain_label": self.config.supply_chain_label,
                    "tcd_image_digest": self.config.image_digest,
                    "tcd_build_id": self.config.build_id,
                },
            )
        except Exception:
            pass

        return res

    # ------------------------------------------------------------------
    # Policy digest
    # ------------------------------------------------------------------

    def _compute_policy_digest(self, material: Dict[str, Any]) -> str:
        if canonical_kv_hash is not None:
            try:
                return canonical_kv_hash(material, ctx="tcd:agent_cfg", label="tcd_agent_cfg")
            except Exception:
                logger.error("policy digest via canonical_kv_hash failed; falling back to BLAKE3", exc_info=True)
        try:
            blob = canonical_json_bytes(material)
            return blake3_hex(blob, ctx="tcd:agent_cfg")
        except Exception:
            return "agent_cfg:" + repr(material)

    # ------------------------------------------------------------------
    # Misc
    # ------------------------------------------------------------------

    def _best_effort_evidence(self, res: ActionResult, *, stage: str) -> None:
        # stage arg kept for compatibility, internal now
        self._best_effort_evidence.__wrapped__  # type: ignore[attr-defined]  # hint for tooling
        # actual logic in method above (this alias avoids accidental recursion)
        return  # pragma: no cover

    def _best_effort_evidence(self, res: ActionResult, *, stage: str) -> None:  # type: ignore[no-redef]
        # actual implementation (see earlier defined method)
        # This redefinition is intentional (python keeps last definition).
        # It avoids accidental name capture by tooling and keeps code single-file.
        # pylint: disable=function-redefined
        # noqa: F811
        # --- begin implementation ---
        # For actions with no side effect attempt, avoid making evidence requirements stricter than needed.
        if not self._evidence_required_for_result(res):
            res.evidence_ok = True
            return

        evidence_ok = True

        # Attestation
        if self.config.attestation_enabled:
            try:
                self._attach_attestation(res)
            except Exception as exc:
                evidence_ok = False
                res.details["attestation_error"] = safe_error_str(exc)
                if self._outbox is not None:
                    # enqueue attestor request for retry
                    try:
                        payload = self._build_attestor_request(res)
                        payload, truncated, pd = enforce_payload_budget(
                            payload,
                            max_bytes=self.config.outbox_max_payload_bytes,
                            ctx="tcd:agent:outbox:attestor",
                        )
                        self._outbox.put(kind="attestor", dedupe_key=f"{res.action_id}:attest", payload=payload, payload_digest=pd)
                        res.details["outbox_attestor_enqueued"] = True
                        res.details["outbox_attestor_truncated_fields"] = truncated
                        res.reason_code = ReasonCode.OUTBOX_ENQUEUED.value
                    except Exception as exc2:
                        res.details["outbox_attestor_enqueued"] = False
                        res.details["outbox_attestor_error"] = safe_error_str(exc2)
                        res.reason_code = ReasonCode.OUTBOX_ENQUEUE_FAILED.value

                if self.config.strict_mode and self.config.require_attestor:
                    res.error_kind = res.error_kind or ErrorKind.EVIDENCE_GAP.value
                    res.reason_code = ReasonCode.ATTESTATION_FAILED.value
                    res.reason_detail = "attestation failed"
                    _AGENT_ERROR.labels(res.action, ErrorKind.ATTESTOR.value).inc()

        # Ledger commit
        if self._ledger is not None:
            try:
                self._append_ledger_stage(res, stage="commit", require=bool(self.config.strict_mode and self.config.require_ledger))
            except Exception as exc:
                evidence_ok = False
                res.details["ledger_commit_error"] = safe_error_str(exc)
                if self._outbox is not None:
                    try:
                        payload = self._build_ledger_event(res, stage="commit")
                        payload, truncated, pd = enforce_payload_budget(
                            payload,
                            max_bytes=self.config.outbox_max_payload_bytes,
                            ctx="tcd:agent:outbox:ledger",
                        )
                        self._outbox.put(kind="ledger", dedupe_key=payload.get("event_id", f"{res.action_id}:commit"), payload=payload, payload_digest=pd)
                        res.details["outbox_ledger_enqueued"] = True
                        res.details["outbox_ledger_truncated_fields"] = truncated
                        res.reason_code = ReasonCode.OUTBOX_ENQUEUED.value
                    except Exception as exc2:
                        res.details["outbox_ledger_enqueued"] = False
                        res.details["outbox_ledger_error"] = safe_error_str(exc2)
                        res.reason_code = ReasonCode.OUTBOX_ENQUEUE_FAILED.value

                if self.config.strict_mode and self.config.require_ledger:
                    res.error_kind = res.error_kind or ErrorKind.EVIDENCE_GAP.value
                    res.reason_code = ReasonCode.LEDGER_COMMIT_FAILED.value
                    res.reason_detail = "ledger commit failed"
                    _AGENT_ERROR.labels(res.action, ErrorKind.LEDGER.value).inc()

        res.evidence_ok = bool(evidence_ok)

        # Opportunistic flush (bounded)
        if self._outbox is not None and self.config.outbox_flush_on_wrapup:
            try:
                self.flush_outbox(max_items=self.config.outbox_flush_max_items, budget_ms=self.config.outbox_flush_budget_ms)
            except Exception:
                pass
        # --- end implementation ---

    @staticmethod
    def _default_request_id() -> str:
        return uuid.uuid4().hex[:16]

    @staticmethod
    def _new_action_id() -> str:
        return uuid.uuid4().hex