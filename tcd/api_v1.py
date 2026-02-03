# FILE: tcd/api_v1.py
from __future__ import annotations

"""
tcd/api_v1.py — /v1/diagnose hardened API surface (L6/L7 platform-grade)

This file implements *all* requirements from your checklist, in code (not just
a proposal). Key properties that are now *strictly enforced*:

Concurrency / locks / threads
- No fake/placeholder dependency calls (breaker never self-poisons).
- Controller lock acquire+release happens in the *same worker thread*.
- Controller lock waiting is budgeted (lock acquire timeout + metrics).
- Per-route in-flight gate supports optional wait (async, non-blocking).

E2E deadline propagation
- max_end_to_end_latency_s is an enforced deadline.
- Each dependency call timeout is capped by remaining E2E budget.
- queue_timeout vs run_timeout are distinguished (metrics + error.extra.phase).

Multi-instance correctness
- Stable event_id from Idempotency-Key; otherwise derived from body_digest + time bucket.
- event_id is used consistently across attestation + ledger + outbox.
- Instance identity (node_id/proc_id/build_id/image_digest) is attached everywhere.
- HALF_OPEN breaker probes use jitter + sampling to avoid probe storms.
- Outbox path defaults to per-process to avoid cross-worker SQLite contention.

Evidence chain hardening
- Ledger events are two-stage: prepare + commit (independently deduped).
- Outbox dedupe conflicts (same key, different digest) are not silently ignored:
  update + conflict counter.
- Outbox has bounded capacity + explicit drop policy + observability.
- Evidence fields have strict size/format caps (receipt/body/sig/verify_key).

DoS surface hardening
- Hard body cap regardless of Content-Length (stream-bounded read).
- JSON depth + JSON complexity budgets enforced *before* pydantic parse.
- Content-Type enforcement for JSON endpoints.
- Header count/bytes budgets enforced.
- Stream extend peak fixed (len(buf)+len(chunk) check).
- Response components are recursively sanitized + bounded.

Auth/identity + privacy
- auth_mode label is normalized (low cardinality).
- principal/key_id are hashed by default (PII-safe). Optional raw recording requires explicit flag.
- Optional mTLS header gate is only trusted behind configured proxy CIDRs.

Dependency governance
- Separate executors for auth/controller/evidence/sqlite (no starvation).
- Local queue_full/queue_timeout do NOT poison dependency breakers.
- Small retry policy for idempotent ops (budgeted, jittered).
- client disconnect => skip expensive non-critical steps (attest/ledger/flush).

Observability
- Structured per-request end log (safe, low-cardinality).
- Parsing cost metrics: body_bytes, header_bytes, json_depth_est, parse_latency approx.
- Executor saturation + reject metrics.
- Error extra is sanitized + size-capped.
- Optional debug_errors adds breaker snapshot (still sanitized).

Lifecycle + modularity
- Factory function create_v1_service/create_v1_router for dependency injection.
- Startup/shutdown hooks for executor shutdown + optional background outbox flusher.
- Config hot-reload hook with digest recomputation + cfg_reload audit event.
"""

import asyncio
import concurrent.futures
import contextlib
import dataclasses
import ipaddress
import json
import logging
import os
import random
import re
import sqlite3
import threading
import time
from collections import deque
from typing import Any, Awaitable, Callable, Deque, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Request
from fastapi.routing import APIRoute
from starlette.responses import JSONResponse, Response
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_413_REQUEST_ENTITY_TOO_LARGE,
    HTTP_429_TOO_MANY_REQUESTS,
    HTTP_500_INTERNAL_SERVER_ERROR,
    HTTP_503_SERVICE_UNAVAILABLE,
)

# Some status codes are not always exported by starlette.status in all versions.
HTTP_415_UNSUPPORTED_MEDIA_TYPE = 415
HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE = 431
HTTP_504_GATEWAY_TIMEOUT = 504

# Optional metrics (safe stubs if missing)
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


from .crypto import Blake3Hash
from .risk_av import AlwaysValidConfig, AlwaysValidRiskController
from .schemas import DiagnoseIn, DiagnoseOut

# Optional higher-layer integrations (soft import)
try:  # Authenticator / AuthContext
    from .auth import Authenticator, AuthResult, build_authenticator_from_env  # type: ignore
except Exception:  # pragma: no cover
    Authenticator = None  # type: ignore[assignment]
    AuthResult = None  # type: ignore[assignment]
    build_authenticator_from_env = None  # type: ignore[assignment]

try:  # Attestor / AttestorConfig / canonical_kv_hash
    from .attest import Attestor, AttestorConfig, canonical_kv_hash  # type: ignore
except Exception:  # pragma: no cover
    Attestor = None  # type: ignore[assignment]
    AttestorConfig = None  # type: ignore[assignment]
    canonical_kv_hash = None  # type: ignore[assignment]

try:  # Local audit ledger
    from .audit import AuditLedger  # type: ignore
except Exception:  # pragma: no cover
    AuditLedger = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Env helpers
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool) -> bool:
    raw = (os.getenv(name, "") or "").strip().lower()
    if not raw:
        return bool(default)
    return raw in ("1", "true", "yes", "y", "on", "ok")


def _env_int(name: str, default: int) -> int:
    raw = (os.getenv(name, "") or "").strip()
    if not raw:
        return int(default)
    try:
        return int(raw)
    except Exception:
        return int(default)


def _env_float(name: str, default: float) -> float:
    raw = (os.getenv(name, "") or "").strip()
    if not raw:
        return float(default)
    try:
        return float(raw)
    except Exception:
        return float(default)


def _split_env_list(name: str) -> Optional[List[str]]:
    raw = os.getenv(name, "")
    xs = [x.strip() for x in raw.split(",") if x.strip()]
    return xs or None


# ---------------------------------------------------------------------------
# Error taxonomy (stable kinds)
# ---------------------------------------------------------------------------

ERR_BAD_REQUEST = "BAD_REQUEST"
ERR_PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
ERR_OVERLOADED = "OVERLOADED"
ERR_AUTH = "AUTH"
ERR_FORBIDDEN = "FORBIDDEN"
ERR_TIMEOUT = "TIMEOUT"
ERR_DEPENDENCY = "DEPENDENCY"
ERR_INTERNAL = "INTERNAL"
ERR_EVIDENCE = "EVIDENCE"
ERR_VERIFY_KEY = "VERIFY_KEY"
ERR_UNSUPPORTED_MEDIA = "UNSUPPORTED_MEDIA"
ERR_HEADERS_TOO_LARGE = "HEADERS_TOO_LARGE"
ERR_JSON_TOO_DEEP = "JSON_TOO_DEEP"
ERR_JSON_TOO_COMPLEX = "JSON_TOO_COMPLEX"


# ---------------------------------------------------------------------------
# Security: safe strings, redaction, hashing
# ---------------------------------------------------------------------------

_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._-]{10,}")
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=_-]{80,}$")

_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_VERIFY_KEY_RE = re.compile(r"^[A-Za-z0-9+/=_:\-.,]{1,1024}$")


def _truncate(s: str, n: int) -> str:
    if n <= 0:
        return ""
    if len(s) <= n:
        return s
    return s[: max(0, n - 3)] + "..."


def _safe_text(s: Any, *, max_len: int = 256) -> str:
    try:
        out = str(s)
    except Exception:
        out = "<unprintable>"
    out = out.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    out = _CTRL_CHARS_RE.sub("", out)
    out = out.strip()
    return _truncate(out, max_len)


def _looks_sensitive_value(s: str) -> bool:
    if not s:
        return False
    if _JWT_RE.match(s):
        return True
    if _PEM_RE.search(s):
        return True
    if _BEARER_RE.search(s):
        return True
    if _BASE64ISH_RE.match(s) and len(s) > 120:
        return True
    return False


def _redact_if_needed(s: str) -> str:
    return "[redacted]" if _looks_sensitive_value(s) else s


def _blake3_hex(data: bytes, *, ctx: str) -> str:
    return Blake3Hash().hex(data, ctx=ctx)


def _hash_token(s: str, *, ctx: str, n: int = 16) -> str:
    h = _blake3_hex(s.encode("utf-8", errors="ignore"), ctx=ctx)
    return h[: max(8, min(64, int(n)))]


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _model_dump(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if hasattr(obj, "model_dump"):
        try:
            return dict(obj.model_dump())  # pydantic v2
        except Exception:
            return {}
    if hasattr(obj, "dict"):
        try:
            return dict(obj.dict())  # pydantic v1
        except Exception:
            return {}
    return {}


# ---------------------------------------------------------------------------
# Metrics (existing + expanded; low-cardinality labels only)
# ---------------------------------------------------------------------------

_REQ_LATENCY = Histogram(
    "tcd_api_v1_request_latency_seconds",
    "Latency of /v1/diagnose requests",
    buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20, 0.50, 1.0, 2.0, 5.0),
    labelnames=("route", "verdict", "auth_mode"),
)

_REQ_TOTAL = Counter(
    "tcd_api_v1_request_total",
    "Total /v1/diagnose requests by status",
    labelnames=("route", "status"),
)

_REQ_ERROR = Counter(
    "tcd_api_v1_error_total",
    "Internal errors in /v1/diagnose handler",
    labelnames=("route", "kind"),
)

_REQ_REJECTED = Counter(
    "tcd_api_v1_rejected_total",
    "Rejected /v1/diagnose requests (size/auth/etc.)",
    labelnames=("route", "reason"),
)

_LEDGER_ERROR = Counter(
    "tcd_api_v1_ledger_error_total",
    "Failures when appending to local AuditLedger in /v1/diagnose",
    labelnames=("route", "stage"),
)

# Parsing/DoS metrics
_REQ_BODY_BYTES = Histogram(
    "tcd_api_v1_body_bytes",
    "Request body bytes observed by route wrapper",
    buckets=(0, 64, 256, 1024, 4096, 16384, 65536, 131072, 262144, 524288),
    labelnames=("route",),
)
_REQ_HEADER_BYTES = Histogram(
    "tcd_api_v1_header_bytes",
    "Total header bytes observed by route wrapper",
    buckets=(0, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768),
    labelnames=("route",),
)
_REQ_HEADER_COUNT = Histogram(
    "tcd_api_v1_header_count",
    "Header fields count observed by route wrapper",
    buckets=(0, 8, 16, 32, 64, 96, 128, 192),
    labelnames=("route",),
)
_REQ_JSON_DEPTH_EST = Histogram(
    "tcd_api_v1_json_depth_est",
    "Estimated JSON nesting depth (pre-parse scan)",
    buckets=(0, 2, 4, 8, 16, 32, 64, 96, 128, 192),
    labelnames=("route",),
)
_REQ_PARSE_LAT_MS = Histogram(
    "tcd_api_v1_parse_latency_ms",
    "Approx latency from body-guard end to handler entry (pydantic+route overhead)",
    buckets=(0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200),
    labelnames=("route",),
)

# Concurrency gate
_REQ_INFLIGHT = Gauge(
    "tcd_api_v1_inflight",
    "In-flight /v1/diagnose requests (gate)",
    labelnames=("route",),
)
_GATE_LIMIT = Gauge(
    "tcd_api_v1_gate_limit",
    "Configured gate limit",
    labelnames=("route",),
)
_GATE_REJECT = Counter(
    "tcd_api_v1_gate_reject_total",
    "Gate rejections",
    labelnames=("route", "reason"),
)

# Dependency metrics
_DEP_LATENCY = Histogram(
    "tcd_api_v1_dependency_latency_ms",
    "Latency of dependency calls in /v1/diagnose (ms)",
    buckets=(1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000),
    labelnames=("dep", "op", "status"),
)
_DEP_ERROR = Counter(
    "tcd_api_v1_dependency_error_total",
    "Dependency errors in /v1/diagnose",
    labelnames=("dep", "op", "kind"),
)

# Breaker metrics
_BREAKER_STATE = Gauge(
    "tcd_api_v1_dependency_breaker_state",
    "Circuit breaker state: 0=CLOSED 1=OPEN 2=HALF_OPEN",
    labelnames=("dep",),
)
_BREAKER_PROBE_TOTAL = Counter(
    "tcd_api_v1_dependency_breaker_probe_total",
    "Circuit breaker probes",
    labelnames=("dep", "ok"),
)

# Executors
_EXEC_RESERVED = Gauge(
    "tcd_api_v1_executor_reserved",
    "Reserved slots in bounded executors",
    labelnames=("pool",),
)
_EXEC_REJECT = Counter(
    "tcd_api_v1_executor_reject_total",
    "Rejected submissions to bounded executors",
    labelnames=("pool",),
)

# Controller lock
_CTRL_LOCK_WAIT_MS = Histogram(
    "tcd_api_v1_controller_lock_wait_ms",
    "Time waiting to acquire controller lock (ms)",
    buckets=(0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100, 200),
    labelnames=("route", "status"),
)
_CTRL_LOCK_BUSY = Counter(
    "tcd_api_v1_controller_lock_busy_total",
    "Controller lock contention causing fast-fail",
    labelnames=("route",),
)

# Outbox
_OUTBOX_DEPTH = Gauge(
    "tcd_api_v1_outbox_depth",
    "Outbox pending depth (ledger evidence)",
    labelnames=("kind",),
)
_OUTBOX_OLDEST_AGE_S = Gauge(
    "tcd_api_v1_outbox_oldest_age_s",
    "Outbox oldest pending age (seconds)",
    labelnames=("kind",),
)
_OUTBOX_FLUSH_TOTAL = Counter(
    "tcd_api_v1_outbox_flush_total",
    "Outbox flush attempts",
    labelnames=("kind", "ok"),
)
_OUTBOX_CONFLICT_TOTAL = Counter(
    "tcd_api_v1_outbox_conflict_total",
    "Outbox dedupe conflicts (same key, different digest)",
    labelnames=("kind",),
)
_OUTBOX_DROP_TOTAL = Counter(
    "tcd_api_v1_outbox_drop_total",
    "Outbox drops due to capacity policy",
    labelnames=("kind", "policy"),
)

# Auth reject reason (low-cardinality)
_AUTH_REJECT_TOTAL = Counter(
    "tcd_api_v1_auth_reject_total",
    "Auth rejections by reason_code (if provided)",
    labelnames=("route", "reason_code"),
)

# ---------------------------------------------------------------------------
# Config (includes all knobs requested)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ApiV1Config:
    # Core behavior
    route_name: str = "v1.diagnose"
    strict_mode: bool = False

    # E2E
    max_end_to_end_latency_s: float = 1.0

    # Request guards
    max_payload_bytes: int = 256 * 1024
    require_json_content_type: bool = True
    max_header_bytes: int = 16 * 1024
    max_header_count: int = 96
    max_json_depth: int = 96
    max_json_tokens: int = 60_000
    max_json_string_len: int = 32 * 1024
    max_json_number_len: int = 256

    # Response / components bounds
    components_max_depth: int = 8
    components_max_items: int = 256
    components_max_str_len: int = 2048
    components_max_total_bytes: int = 32 * 1024

    # Evidence bounds
    max_receipt_len: int = 256
    max_receipt_body_bytes: int = 48 * 1024
    max_receipt_sig_bytes: int = 8 * 1024
    max_verify_key_len: int = 1024
    truncate_evidence_in_nonstrict: bool = True

    # Concurrency gate
    max_inflight: int = 64
    gate_wait_ms: int = 0  # 0 = try_acquire; >0 = wait up to this time

    # Executors (separated pools)
    exec_auth_workers: int = 8
    exec_auth_queue: int = 64
    exec_ctrl_workers: int = 8
    exec_ctrl_queue: int = 64
    exec_evidence_workers: int = 8
    exec_evidence_queue: int = 128
    exec_sql_workers: int = 4
    exec_sql_queue: int = 128

    # Dependency budgets (ms)
    auth_timeout_ms: int = 350
    controller_timeout_ms: int = 800
    controller_lock_timeout_ms: int = 50
    attestor_timeout_ms: int = 1200
    ledger_timeout_ms: int = 600
    sqlite_timeout_ms: int = 250

    # Circuit breaker
    breaker_failures: int = 5
    breaker_window_s: float = 30.0
    breaker_open_seconds: float = 15.0
    breaker_probe_jitter_s: float = 2.0
    breaker_probe_probability: float = 0.25

    # Retry (budgeted, idempotent ops only)
    dep_retry_max: int = 1
    dep_retry_base_ms: int = 40

    # Auth / attestation / ledger presence requirements
    require_auth: bool = True
    require_attestor: bool = True
    require_ledger: bool = True
    allowed_auth_modes: Optional[List[str]] = None  # compared against normalized mode

    # PQ signature policy
    require_pq_sig: bool = False
    allowed_sig_algs: Optional[List[str]] = None

    # Issue attestation
    issue_attestation: bool = True

    # Ledger semantics (two-stage)
    ledger_prepare_required: bool = False
    ledger_commit_required: bool = False

    # Outbox
    outbox_enabled: bool = True
    outbox_path: str = "tcd_api_v1_outbox.sqlite3"
    outbox_per_process: bool = True
    outbox_max_payload_bytes: int = 48 * 1024
    outbox_flush_budget_ms: int = 80
    outbox_flush_max_items: int = 30
    outbox_flush_sample_rate: float = 0.10
    outbox_flush_min_remaining_ms: int = 80
    outbox_background_flush_interval_s: float = 0.0  # 0 disables background task
    outbox_max_rows: int = 50_000
    outbox_max_db_bytes: int = 256 * 1024 * 1024
    outbox_drop_policy: str = "drop_oldest"  # drop_oldest|drop_newest|reject_request

    # verify_key policy
    verify_key_allowlist: Optional[List[str]] = None
    verify_key_denylist: Optional[List[str]] = None

    # mTLS header gate (trusted proxy model)
    require_mtls_header: bool = False
    mtls_verify_header: str = "X-SSL-Client-Verify"
    mtls_verify_value: str = "SUCCESS"
    mtls_trusted_proxy_cidrs: Optional[List[str]] = None

    # Privacy controls
    attach_auth_context: bool = True
    auth_record_principal: bool = False  # if False, record principal_hash only
    auth_record_key_id: bool = False     # if False, record key_id_hash only

    # Instance identity
    node_id: str = ""
    proc_id: str = ""
    build_id: str = ""
    image_digest: str = ""

    # Logging / debug
    log_requests: bool = True
    debug_errors: bool = False

    # Idempotency derivation
    idempotency_time_bucket_s: int = 60

    def digest_material(self) -> Dict[str, Any]:
        # Keep stable, low-cardinality config digest material
        return {
            "route_name": self.route_name,
            "strict_mode": bool(self.strict_mode),
            "max_end_to_end_latency_s": float(self.max_end_to_end_latency_s),
            "max_payload_bytes": int(self.max_payload_bytes),
            "require_json_content_type": bool(self.require_json_content_type),
            "max_header_bytes": int(self.max_header_bytes),
            "max_header_count": int(self.max_header_count),
            "max_json_depth": int(self.max_json_depth),
            "max_json_tokens": int(self.max_json_tokens),
            "max_json_string_len": int(self.max_json_string_len),
            "max_json_number_len": int(self.max_json_number_len),
            "components_max_depth": int(self.components_max_depth),
            "components_max_items": int(self.components_max_items),
            "components_max_str_len": int(self.components_max_str_len),
            "components_max_total_bytes": int(self.components_max_total_bytes),
            "max_receipt_len": int(self.max_receipt_len),
            "max_receipt_body_bytes": int(self.max_receipt_body_bytes),
            "max_receipt_sig_bytes": int(self.max_receipt_sig_bytes),
            "max_verify_key_len": int(self.max_verify_key_len),
            "truncate_evidence_in_nonstrict": bool(self.truncate_evidence_in_nonstrict),
            "max_inflight": int(self.max_inflight),
            "gate_wait_ms": int(self.gate_wait_ms),
            "exec_auth_workers": int(self.exec_auth_workers),
            "exec_auth_queue": int(self.exec_auth_queue),
            "exec_ctrl_workers": int(self.exec_ctrl_workers),
            "exec_ctrl_queue": int(self.exec_ctrl_queue),
            "exec_evidence_workers": int(self.exec_evidence_workers),
            "exec_evidence_queue": int(self.exec_evidence_queue),
            "exec_sql_workers": int(self.exec_sql_workers),
            "exec_sql_queue": int(self.exec_sql_queue),
            "auth_timeout_ms": int(self.auth_timeout_ms),
            "controller_timeout_ms": int(self.controller_timeout_ms),
            "controller_lock_timeout_ms": int(self.controller_lock_timeout_ms),
            "attestor_timeout_ms": int(self.attestor_timeout_ms),
            "ledger_timeout_ms": int(self.ledger_timeout_ms),
            "sqlite_timeout_ms": int(self.sqlite_timeout_ms),
            "breaker_failures": int(self.breaker_failures),
            "breaker_window_s": float(self.breaker_window_s),
            "breaker_open_seconds": float(self.breaker_open_seconds),
            "breaker_probe_jitter_s": float(self.breaker_probe_jitter_s),
            "breaker_probe_probability": float(self.breaker_probe_probability),
            "dep_retry_max": int(self.dep_retry_max),
            "dep_retry_base_ms": int(self.dep_retry_base_ms),
            "require_auth": bool(self.require_auth),
            "require_attestor": bool(self.require_attestor),
            "require_ledger": bool(self.require_ledger),
            "allowed_auth_modes": list(self.allowed_auth_modes or []),
            "require_pq_sig": bool(self.require_pq_sig),
            "allowed_sig_algs": list(self.allowed_sig_algs or []),
            "issue_attestation": bool(self.issue_attestation),
            "ledger_prepare_required": bool(self.ledger_prepare_required),
            "ledger_commit_required": bool(self.ledger_commit_required),
            "outbox_enabled": bool(self.outbox_enabled),
            "outbox_path": self.outbox_path,
            "outbox_per_process": bool(self.outbox_per_process),
            "outbox_max_payload_bytes": int(self.outbox_max_payload_bytes),
            "outbox_flush_budget_ms": int(self.outbox_flush_budget_ms),
            "outbox_flush_max_items": int(self.outbox_flush_max_items),
            "outbox_flush_sample_rate": float(self.outbox_flush_sample_rate),
            "outbox_flush_min_remaining_ms": int(self.outbox_flush_min_remaining_ms),
            "outbox_background_flush_interval_s": float(self.outbox_background_flush_interval_s),
            "outbox_max_rows": int(self.outbox_max_rows),
            "outbox_max_db_bytes": int(self.outbox_max_db_bytes),
            "outbox_drop_policy": self.outbox_drop_policy,
            "verify_key_allowlist": list(self.verify_key_allowlist or []),
            "verify_key_denylist": list(self.verify_key_denylist or []),
            "require_mtls_header": bool(self.require_mtls_header),
            "mtls_verify_header": self.mtls_verify_header,
            "mtls_verify_value": self.mtls_verify_value,
            "mtls_trusted_proxy_cidrs": list(self.mtls_trusted_proxy_cidrs or []),
            "attach_auth_context": bool(self.attach_auth_context),
            "auth_record_principal": bool(self.auth_record_principal),
            "auth_record_key_id": bool(self.auth_record_key_id),
            "node_id": self.node_id,
            "proc_id": self.proc_id,
            "build_id": self.build_id,
            "image_digest": self.image_digest,
            "log_requests": bool(self.log_requests),
            "debug_errors": bool(self.debug_errors),
            "idempotency_time_bucket_s": int(self.idempotency_time_bucket_s),
        }


def _build_cfg_from_env() -> ApiV1Config:
    cfg = ApiV1Config(
        route_name=os.getenv("TCD_API_V1_ROUTE_NAME", "v1.diagnose"),
        strict_mode=_env_bool("TCD_API_V1_STRICT_MODE", False),
        max_end_to_end_latency_s=_env_float("TCD_API_V1_MAX_E2E_LATENCY_S", 1.0),
        max_payload_bytes=_env_int("TCD_API_V1_MAX_PAYLOAD_BYTES", 256 * 1024),
        require_json_content_type=_env_bool("TCD_API_V1_REQUIRE_JSON_CT", True),
        max_header_bytes=_env_int("TCD_API_V1_MAX_HEADER_BYTES", 16 * 1024),
        max_header_count=_env_int("TCD_API_V1_MAX_HEADER_COUNT", 96),
        max_json_depth=_env_int("TCD_API_V1_MAX_JSON_DEPTH", 96),
        max_json_tokens=_env_int("TCD_API_V1_MAX_JSON_TOKENS", 60_000),
        max_json_string_len=_env_int("TCD_API_V1_MAX_JSON_STRLEN", 32 * 1024),
        max_json_number_len=_env_int("TCD_API_V1_MAX_JSON_NUMLEN", 256),
        components_max_depth=_env_int("TCD_API_V1_COMPONENTS_MAX_DEPTH", 8),
        components_max_items=_env_int("TCD_API_V1_COMPONENTS_MAX_ITEMS", 256),
        components_max_str_len=_env_int("TCD_API_V1_COMPONENTS_MAX_STRLEN", 2048),
        components_max_total_bytes=_env_int("TCD_API_V1_COMPONENTS_MAX_BYTES", 32 * 1024),
        max_receipt_len=_env_int("TCD_API_V1_MAX_RECEIPT_LEN", 256),
        max_receipt_body_bytes=_env_int("TCD_API_V1_MAX_RECEIPT_BODY_BYTES", 48 * 1024),
        max_receipt_sig_bytes=_env_int("TCD_API_V1_MAX_RECEIPT_SIG_BYTES", 8 * 1024),
        max_verify_key_len=_env_int("TCD_API_V1_MAX_VERIFY_KEY_LEN", 1024),
        truncate_evidence_in_nonstrict=_env_bool("TCD_API_V1_TRUNC_EVIDENCE_NONSTRICT", True),
        max_inflight=_env_int("TCD_API_V1_MAX_INFLIGHT", 64),
        gate_wait_ms=_env_int("TCD_API_V1_GATE_WAIT_MS", 0),
        exec_auth_workers=_env_int("TCD_API_V1_EXEC_AUTH_WORKERS", 8),
        exec_auth_queue=_env_int("TCD_API_V1_EXEC_AUTH_QUEUE", 64),
        exec_ctrl_workers=_env_int("TCD_API_V1_EXEC_CTRL_WORKERS", 8),
        exec_ctrl_queue=_env_int("TCD_API_V1_EXEC_CTRL_QUEUE", 64),
        exec_evidence_workers=_env_int("TCD_API_V1_EXEC_EVID_WORKERS", 8),
        exec_evidence_queue=_env_int("TCD_API_V1_EXEC_EVID_QUEUE", 128),
        exec_sql_workers=_env_int("TCD_API_V1_EXEC_SQL_WORKERS", 4),
        exec_sql_queue=_env_int("TCD_API_V1_EXEC_SQL_QUEUE", 128),
        auth_timeout_ms=_env_int("TCD_API_V1_AUTH_TIMEOUT_MS", 350),
        controller_timeout_ms=_env_int("TCD_API_V1_CTRL_TIMEOUT_MS", 800),
        controller_lock_timeout_ms=_env_int("TCD_API_V1_CTRL_LOCK_TIMEOUT_MS", 50),
        attestor_timeout_ms=_env_int("TCD_API_V1_ATTEST_TIMEOUT_MS", 1200),
        ledger_timeout_ms=_env_int("TCD_API_V1_LEDGER_TIMEOUT_MS", 600),
        sqlite_timeout_ms=_env_int("TCD_API_V1_SQLITE_TIMEOUT_MS", 250),
        breaker_failures=_env_int("TCD_API_V1_BREAKER_FAILURES", 5),
        breaker_window_s=_env_float("TCD_API_V1_BREAKER_WINDOW_S", 30.0),
        breaker_open_seconds=_env_float("TCD_API_V1_BREAKER_OPEN_S", 15.0),
        breaker_probe_jitter_s=_env_float("TCD_API_V1_BREAKER_PROBE_JITTER_S", 2.0),
        breaker_probe_probability=_env_float("TCD_API_V1_BREAKER_PROBE_PROB", 0.25),
        dep_retry_max=_env_int("TCD_API_V1_DEP_RETRY_MAX", 1),
        dep_retry_base_ms=_env_int("TCD_API_V1_DEP_RETRY_BASE_MS", 40),
        require_auth=_env_bool("TCD_API_V1_REQUIRE_AUTH", True),
        require_attestor=_env_bool("TCD_API_V1_REQUIRE_ATTESTOR", True),
        require_ledger=_env_bool("TCD_API_V1_REQUIRE_LEDGER", True),
        allowed_auth_modes=_split_env_list("TCD_API_V1_ALLOWED_AUTH_MODES"),
        require_pq_sig=_env_bool("TCD_API_V1_REQUIRE_PQ_SIG", False),
        allowed_sig_algs=_split_env_list("TCD_API_V1_ALLOWED_SIG_ALGS"),
        issue_attestation=_env_bool("TCD_API_V1_ISSUE_ATTESTATION", True),
        ledger_prepare_required=_env_bool("TCD_API_V1_LEDGER_PREPARE_REQUIRED", False),
        ledger_commit_required=_env_bool("TCD_API_V1_LEDGER_COMMIT_REQUIRED", False),
        outbox_enabled=_env_bool("TCD_API_V1_OUTBOX_ENABLED", True),
        outbox_path=os.getenv("TCD_API_V1_OUTBOX_PATH", "tcd_api_v1_outbox.sqlite3"),
        outbox_per_process=_env_bool("TCD_API_V1_OUTBOX_PER_PROCESS", True),
        outbox_max_payload_bytes=_env_int("TCD_API_V1_OUTBOX_MAX_PAYLOAD_BYTES", 48 * 1024),
        outbox_flush_budget_ms=_env_int("TCD_API_V1_OUTBOX_FLUSH_BUDGET_MS", 80),
        outbox_flush_max_items=_env_int("TCD_API_V1_OUTBOX_FLUSH_MAX_ITEMS", 30),
        outbox_flush_sample_rate=_env_float("TCD_API_V1_OUTBOX_FLUSH_SAMPLE_RATE", 0.10),
        outbox_flush_min_remaining_ms=_env_int("TCD_API_V1_OUTBOX_FLUSH_MIN_REMAINING_MS", 80),
        outbox_background_flush_interval_s=_env_float("TCD_API_V1_OUTBOX_BG_FLUSH_INTERVAL_S", 0.0),
        outbox_max_rows=_env_int("TCD_API_V1_OUTBOX_MAX_ROWS", 50_000),
        outbox_max_db_bytes=_env_int("TCD_API_V1_OUTBOX_MAX_DB_BYTES", 256 * 1024 * 1024),
        outbox_drop_policy=os.getenv("TCD_API_V1_OUTBOX_DROP_POLICY", "drop_oldest"),
        verify_key_allowlist=_split_env_list("TCD_API_V1_VERIFY_KEY_ALLOWLIST"),
        verify_key_denylist=_split_env_list("TCD_API_V1_VERIFY_KEY_DENYLIST"),
        require_mtls_header=_env_bool("TCD_API_V1_REQUIRE_MTLS_HEADER", False),
        mtls_verify_header=os.getenv("TCD_API_V1_MTLS_VERIFY_HEADER", "X-SSL-Client-Verify"),
        mtls_verify_value=os.getenv("TCD_API_V1_MTLS_VERIFY_VALUE", "SUCCESS"),
        mtls_trusted_proxy_cidrs=_split_env_list("TCD_API_V1_MTLS_TRUSTED_PROXY_CIDRS"),
        attach_auth_context=_env_bool("TCD_API_V1_ATTACH_AUTH_CONTEXT", True),
        auth_record_principal=_env_bool("TCD_API_V1_AUTH_RECORD_PRINCIPAL", False),
        auth_record_key_id=_env_bool("TCD_API_V1_AUTH_RECORD_KEY_ID", False),
        node_id=os.getenv("TCD_NODE_ID", os.getenv("HOSTNAME", ""))[:128],
        proc_id=os.getenv("TCD_PROC_ID", str(os.getpid()))[:64],
        build_id=os.getenv("TCD_BUILD_ID", "")[:128],
        image_digest=os.getenv("TCD_IMAGE_DIGEST", "")[:128],
        log_requests=_env_bool("TCD_API_V1_LOG_REQUESTS", True),
        debug_errors=_env_bool("TCD_API_V1_DEBUG_ERRORS", False),
        idempotency_time_bucket_s=_env_int("TCD_API_V1_IDEMPOTENCY_BUCKET_S", 60),
    )

    # Normalize outbox path for per-process safety
    if cfg.outbox_enabled and cfg.outbox_per_process:
        # Allow templating via {pid}/{proc_id}
        p = cfg.outbox_path
        if "{pid}" in p or "{proc_id}" in p:
            p = p.replace("{pid}", str(os.getpid())).replace("{proc_id}", cfg.proc_id or str(os.getpid()))
        else:
            # Default append suffix to avoid cross-process sqlite lock contention
            p = f"{p}.{os.getpid()}"
        cfg.outbox_path = p

    return cfg


# ---------------------------------------------------------------------------
# Config digest witness
# ---------------------------------------------------------------------------


def _compute_cfg_digest(cfg: ApiV1Config) -> str:
    if canonical_kv_hash is not None:
        try:
            return canonical_kv_hash(cfg.digest_material(), ctx="tcd:api_v1_cfg", label="api_v1_cfg")  # type: ignore[misc]
        except Exception:
            logger.error("failed to compute ApiV1Config digest via canonical_kv_hash; falling back to BLAKE3", exc_info=True)
    try:
        blob = json.dumps(cfg.digest_material(), sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return _blake3_hex(blob, ctx="tcd:api_v1_cfg")
    except Exception:
        return "api_v1_cfg:" + repr(cfg.digest_material())


# ---------------------------------------------------------------------------
# JSON depth + complexity guards (pre-parse scan)
# ---------------------------------------------------------------------------


def _json_depth_scan(body: bytes, *, max_depth: int) -> Tuple[int, bool]:
    """
    Returns (max_depth_seen, exceeds_max_depth).

    Conservative: ignores braces inside strings.
    """
    if max_depth <= 0:
        return (0, False)
    b = body.lstrip()
    if not b or b[:1] not in (b"{", b"["):
        return (0, False)

    depth = 0
    max_seen = 0
    in_str = False
    esc = False

    for ch in b:
        if in_str:
            if esc:
                esc = False
                continue
            if ch == 0x5C:
                esc = True
                continue
            if ch == 0x22:
                in_str = False
            continue

        if ch == 0x22:
            in_str = True
            continue

        if ch == 0x7B or ch == 0x5B:  # { or [
            depth += 1
            if depth > max_seen:
                max_seen = depth
            if depth > max_depth:
                return (max_seen, True)
        elif ch == 0x7D or ch == 0x5D:  # } or ]
            depth = max(0, depth - 1)

    return (max_seen, False)


def _json_complexity_scan(
    body: bytes,
    *,
    max_tokens: int,
    max_string_len: int,
    max_number_len: int,
) -> Tuple[Dict[str, int], bool]:
    """
    Returns (stats, exceeds).

    stats includes token_count, max_string_len, max_number_len.
    """
    b = body.lstrip()
    if not b or b[:1] not in (b"{", b"["):
        return ({"token_count": 0, "max_string_len": 0, "max_number_len": 0}, False)

    token_count = 0
    in_str = False
    esc = False
    cur_str_len = 0
    max_str = 0

    cur_num_len = 0
    max_num = 0
    in_num = False

    def _flush_num() -> None:
        nonlocal in_num, cur_num_len, max_num
        if in_num:
            if cur_num_len > max_num:
                max_num = cur_num_len
            in_num = False
            cur_num_len = 0

    for ch in b:
        if in_str:
            if esc:
                esc = False
                cur_str_len += 1
                continue
            if ch == 0x5C:  # backslash
                esc = True
                cur_str_len += 1
                continue
            if ch == 0x22:  # quote
                in_str = False
                if cur_str_len > max_str:
                    max_str = cur_str_len
                cur_str_len = 0
                continue
            cur_str_len += 1
            if max_string_len > 0 and cur_str_len > max_string_len:
                return ({"token_count": token_count, "max_string_len": max(cur_str_len, max_str), "max_number_len": max_num}, True)
            continue

        # not in string
        if ch == 0x22:
            _flush_num()
            in_str = True
            cur_str_len = 0
            continue

        # number detection outside strings: digits/./-/+ (very conservative)
        if (0x30 <= ch <= 0x39) or ch in (0x2D, 0x2B, 0x2E, 0x65, 0x45):  # 0-9 - + . e E
            in_num = True
            cur_num_len += 1
            if max_number_len > 0 and cur_num_len > max_number_len:
                return ({"token_count": token_count, "max_string_len": max_str, "max_number_len": max(cur_num_len, max_num)}, True)
            continue

        # delimiter => flush num
        if in_num:
            _flush_num()

        # token heuristics
        if ch in (0x7B, 0x7D, 0x5B, 0x5D, 0x2C, 0x3A):  # { } [ ] , :
            token_count += 1
            if max_tokens > 0 and token_count > max_tokens:
                return ({"token_count": token_count, "max_string_len": max_str, "max_number_len": max_num}, True)

    _flush_num()
    return ({"token_count": token_count, "max_string_len": max_str, "max_number_len": max_num}, False)


# ---------------------------------------------------------------------------
# Sanitization for components and error extra (bounded, non-throwing)
# ---------------------------------------------------------------------------


def _sanitize_error_extra(extra: Optional[Dict[str, Any]], *, max_depth: int = 3, max_keys: int = 24, max_bytes: int = 2048) -> Dict[str, Any]:
    """
    Sanitizes error extra to prevent PII/secret leakage and bounds size.
    """
    if not extra:
        return {}

    out: Dict[str, Any] = {}
    bytes_budget = max(256, int(max_bytes))

    def _put(k: str, v: Any) -> None:
        nonlocal bytes_budget
        if bytes_budget <= 0:
            return
        ks = _safe_text(k, max_len=64)
        try:
            vs = _safe_text(v, max_len=256)
            vs = _redact_if_needed(vs)
            item = vs
        except Exception:
            item = "<unprintable>"
        enc = (ks + ":" + str(item)).encode("utf-8", errors="ignore")
        if len(enc) > bytes_budget:
            return
        bytes_budget -= len(enc)
        out[ks] = item

    def _walk(obj: Any, depth: int) -> None:
        if depth <= 0 or not isinstance(obj, dict):
            return
        for i, (k, v) in enumerate(list(obj.items())[: max_keys]):
            if isinstance(v, dict):
                # keep shallow structural hint only
                _put(k, f"dict(keys={len(v)})")
                _walk(v, depth - 1)
            elif isinstance(v, (list, tuple)):
                _put(k, f"list(len={len(v)})")
            else:
                _put(k, v)

    _walk(extra, max_depth)
    return out


def _sanitize_json_value(
    v: Any,
    *,
    max_depth: int,
    max_items: int,
    max_str_len: int,
    total_budget: List[int],
) -> Any:
    """
    Recursive sanitizer for components-like JSON. Enforces:
    - depth cap
    - list/dict item caps
    - string truncation + sensitive redaction
    - total serialized bytes approximate cap via total_budget[0]
    """
    if total_budget[0] <= 0:
        return "[truncated]"
    if max_depth <= 0:
        return "[truncated]"

    if v is None or isinstance(v, (bool, int, float)):
        return v

    if isinstance(v, (bytes, bytearray, memoryview)):
        # never emit raw bytes
        return "[bytes]"

    if isinstance(v, str):
        s = _safe_text(v, max_len=max_str_len)
        s = _redact_if_needed(s)
        total_budget[0] -= len(s.encode("utf-8", errors="ignore"))
        return s

    if isinstance(v, dict):
        out: Dict[str, Any] = {}
        for i, (k, vv) in enumerate(list(v.items())[: max_items]):
            if total_budget[0] <= 0:
                break
            ks = _safe_text(k, max_len=64)
            ks = _redact_if_needed(ks)
            out[ks] = _sanitize_json_value(
                vv,
                max_depth=max_depth - 1,
                max_items=max_items,
                max_str_len=max_str_len,
                total_budget=total_budget,
            )
        if len(v) > max_items:
            out["_truncated"] = True
        return out

    if isinstance(v, (list, tuple)):
        out_list: List[Any] = []
        for vv in list(v)[: max_items]:
            if total_budget[0] <= 0:
                break
            out_list.append(
                _sanitize_json_value(
                    vv,
                    max_depth=max_depth - 1,
                    max_items=max_items,
                    max_str_len=max_str_len,
                    total_budget=total_budget,
                )
            )
        if len(v) > max_items:
            out_list.append("[truncated]")
        return out_list

    # fallback: stringify
    s2 = _safe_text(v, max_len=max_str_len)
    s2 = _redact_if_needed(s2)
    total_budget[0] -= len(s2.encode("utf-8", errors="ignore"))
    return s2


def _sanitize_components(components: Any, cfg: ApiV1Config) -> Dict[str, Any]:
    if not isinstance(components, dict):
        return {}
    budget = [max(256, int(cfg.components_max_total_bytes))]
    out = _sanitize_json_value(
        components,
        max_depth=int(cfg.components_max_depth),
        max_items=int(cfg.components_max_items),
        max_str_len=int(cfg.components_max_str_len),
        total_budget=budget,
    )
    return out if isinstance(out, dict) else {}


# ---------------------------------------------------------------------------
# Auth context projection (PII-safe by default)
# ---------------------------------------------------------------------------


def _normalize_auth_mode(mode: Any) -> str:
    """
    Low-cardinality auth_mode label for metrics.
    """
    m = _safe_text(mode, max_len=32).lower()
    if not m or m == "none":
        return "none"
    if m in ("api_key", "apikey", "key"):
        return "api_key"
    if m in ("jwt", "bearer", "oauth", "oidc"):
        return "jwt"
    if m in ("mtls", "mTLS", "mutual_tls"):
        return "mtls"
    if m in ("internal", "service", "svc"):
        return "service"
    return "other"


def _sanitize_auth_ctx(auth_ctx: Any, cfg: ApiV1Config) -> Dict[str, Any]:
    """
    Compact, low-leakage auth context view for components/auth/audit.
    principal/key_id are hashed by default.
    """
    if auth_ctx is None:
        return {}

    out: Dict[str, Any] = {}

    mode = getattr(auth_ctx, "mode", None)
    principal = getattr(auth_ctx, "principal", None)
    scopes = getattr(auth_ctx, "scopes", None)
    key_id = getattr(auth_ctx, "key_id", None)
    policy_digest_hex = getattr(auth_ctx, "policy_digest_hex", None)
    issued_at = getattr(auth_ctx, "issued_at", None)

    if mode is not None:
        out["mode"] = _normalize_auth_mode(mode)

    if principal is not None:
        p = _safe_text(principal, max_len=256)
        if _looks_sensitive_value(p):
            p = "[redacted]"
        if cfg.auth_record_principal:
            out["principal"] = p
        out["principal_hash"] = _hash_token(p, ctx="tcd:auth:principal", n=16)

    if scopes:
        try:
            xs = list(scopes)
        except Exception:
            xs = []
        out["scopes"] = [_safe_text(x, max_len=96) for x in xs[:32]]

    if key_id is not None:
        kid = _safe_text(key_id, max_len=256)
        if _looks_sensitive_value(kid):
            kid = "[redacted]"
        if cfg.auth_record_key_id:
            out["key_id"] = kid
        out["key_id_hash"] = _hash_token(kid, ctx="tcd:auth:key_id", n=16)

    if policy_digest_hex is not None:
        out["policy_digest"] = _safe_text(policy_digest_hex, max_len=96)

    if issued_at is not None:
        try:
            out["issued_at"] = float(issued_at)
        except Exception:
            pass

    return out


# ---------------------------------------------------------------------------
# Dependency wrappers: bounded executors + timeouts + breaker + retry + phases
# ---------------------------------------------------------------------------

class _RejectedExecution(RuntimeError):
    pass


@dataclasses.dataclass
class _TaskMeta:
    started_evt: threading.Event = dataclasses.field(default_factory=threading.Event)
    finished_evt: threading.Event = dataclasses.field(default_factory=threading.Event)

    def mark_started(self) -> None:
        self.started_evt.set()

    def mark_finished(self) -> None:
        self.finished_evt.set()


class _CallTimeout(RuntimeError):
    def __init__(self, msg: str, *, started: bool, cancelled: bool) -> None:
        super().__init__(msg)
        self.started = bool(started)
        self.cancelled = bool(cancelled)


class _BoundedExecutor:
    """
    ThreadPoolExecutor with bounded admission (workers + queue).
    Capacity = workers + queue.
    """

    def __init__(self, *, pool: str, max_workers: int, max_queue: int) -> None:
        self.pool = str(pool)
        self.max_workers = max(1, int(max_workers))
        self.max_queue = max(0, int(max_queue))
        self.capacity = self.max_workers + self.max_queue

        self._sem = threading.BoundedSemaphore(self.capacity)
        self._reserved = 0
        self._reserved_lock = threading.Lock()

        self._executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix=f"tcd-{self.pool}",
        )
        _EXEC_RESERVED.labels(self.pool).set(0.0)

    def _inc_reserved(self) -> None:
        with self._reserved_lock:
            self._reserved += 1
            _EXEC_RESERVED.labels(self.pool).set(float(self._reserved))

    def _dec_reserved(self) -> None:
        with self._reserved_lock:
            self._reserved = max(0, self._reserved - 1)
            _EXEC_RESERVED.labels(self.pool).set(float(self._reserved))

    def submit(self, fn: Callable[[], Any]) -> Tuple[concurrent.futures.Future, _TaskMeta]:
        if not self._sem.acquire(blocking=False):
            _EXEC_REJECT.labels(self.pool).inc()
            raise _RejectedExecution("executor queue full")

        self._inc_reserved()
        meta = _TaskMeta()

        def _wrapped() -> Any:
            meta.mark_started()
            try:
                return fn()
            finally:
                meta.mark_finished()

        fut = self._executor.submit(_wrapped)

        def _release(_: Any) -> None:
            try:
                self._sem.release()
            except Exception:
                pass
            self._dec_reserved()

        fut.add_done_callback(_release)
        return fut, meta

    async def run(self, fn: Callable[[], Any], *, timeout_s: float) -> Any:
        fut, meta = self.submit(fn)
        try:
            return await asyncio.wait_for(asyncio.wrap_future(fut), timeout=max(0.001, float(timeout_s)))
        except asyncio.TimeoutError as exc:
            started = meta.started_evt.is_set()
            cancelled = False
            if not started:
                # queue timeout: cancel if not started
                with contextlib.suppress(Exception):
                    cancelled = fut.cancel()
            raise _CallTimeout("call timed out", started=started, cancelled=cancelled) from exc

    def shutdown(self) -> None:
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)  # py>=3.9
        except TypeError:  # pragma: no cover
            self._executor.shutdown(wait=False)
        except Exception:  # pragma: no cover
            pass


class _BreakerState:
    CLOSED = 0
    OPEN = 1
    HALF_OPEN = 2


class _CircuitBreaker:
    """
    HALF_OPEN probes are jittered + sampled to avoid probe storms.
    """

    def __init__(
        self,
        *,
        dep: str,
        threshold: int,
        window_s: float,
        open_seconds: float,
        probe_jitter_s: float,
        probe_probability: float,
    ) -> None:
        self.dep = str(dep)
        self.threshold = max(1, int(threshold))
        self.window_s = max(0.5, float(window_s))
        self.open_seconds = max(0.1, float(open_seconds))
        self.probe_jitter_s = max(0.0, float(probe_jitter_s))
        self.probe_probability = float(probe_probability)
        if self.probe_probability <= 0.0:
            self.probe_probability = 0.01
        if self.probe_probability > 1.0:
            self.probe_probability = 1.0

        self._state = _BreakerState.CLOSED
        self._fail_times: Deque[float] = deque()
        self._opened_until = 0.0
        self._probe_inflight = False
        self._next_probe_at = 0.0
        self._lock = threading.Lock()
        _BREAKER_STATE.labels(self.dep).set(float(self._state))

    def _set_state(self, st: int) -> None:
        self._state = int(st)
        _BREAKER_STATE.labels(self.dep).set(float(self._state))

    def snapshot(self) -> Dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            st = self._state
            opened_rem = max(0.0, self._opened_until - now) if st == _BreakerState.OPEN else 0.0
            probe_rem = max(0.0, self._next_probe_at - now) if st == _BreakerState.HALF_OPEN else 0.0
        name = {0: "CLOSED", 1: "OPEN", 2: "HALF_OPEN"}.get(st, "UNKNOWN")
        return {"state": name, "open_remaining_s": round(opened_rem, 3), "probe_delay_s": round(probe_rem, 3)}

    def before_call(self) -> Tuple[bool, bool]:
        """
        Returns (allowed, is_probe).
        """
        now = time.monotonic()
        with self._lock:
            if self._state == _BreakerState.OPEN:
                if now < self._opened_until:
                    return (False, False)
                # transition to HALF_OPEN with jittered probe time
                self._set_state(_BreakerState.HALF_OPEN)
                self._probe_inflight = False
                self._next_probe_at = now + (random.random() * self.probe_jitter_s)

            if self._state == _BreakerState.HALF_OPEN:
                if now < self._next_probe_at:
                    return (False, False)
                if self._probe_inflight:
                    return (False, False)
                # probabilistic probe admission
                if random.random() > self.probe_probability:
                    return (False, False)
                self._probe_inflight = True
                return (True, True)

            return (True, False)

    def record_success(self, *, was_probe: bool) -> None:
        now = time.monotonic()
        with self._lock:
            if was_probe and self._state == _BreakerState.HALF_OPEN:
                _BREAKER_PROBE_TOTAL.labels(self.dep, "yes").inc()
                self._fail_times.clear()
                self._probe_inflight = False
                self._opened_until = 0.0
                self._next_probe_at = 0.0
                self._set_state(_BreakerState.CLOSED)
                return

            # decay window
            while self._fail_times and (now - self._fail_times[0]) > self.window_s:
                self._fail_times.popleft()

    def record_failure(self, *, was_probe: bool) -> None:
        now = time.monotonic()
        with self._lock:
            if was_probe and self._state == _BreakerState.HALF_OPEN:
                _BREAKER_PROBE_TOTAL.labels(self.dep, "no").inc()
                self._probe_inflight = False
                self._opened_until = now + self.open_seconds
                self._set_state(_BreakerState.OPEN)
                self._fail_times.clear()
                self._fail_times.append(now)
                return

            self._fail_times.append(now)
            while self._fail_times and (now - self._fail_times[0]) > self.window_s:
                self._fail_times.popleft()

            if len(self._fail_times) >= self.threshold:
                self._opened_until = now + self.open_seconds
                self._set_state(_BreakerState.OPEN)

    def is_open(self) -> bool:
        now = time.monotonic()
        with self._lock:
            return self._state == _BreakerState.OPEN and now < self._opened_until


class _DepException(Exception):
    def __init__(self, dep: str, op: str, *, kind: str, phase: str) -> None:
        super().__init__(f"{dep}.{op}: {kind} ({phase})")
        self.dep = dep
        self.op = op
        self.kind = kind
        self.phase = phase


async def _sleep_ms(ms: int) -> None:
    await asyncio.sleep(max(0.0, float(ms) / 1000.0))


# ---------------------------------------------------------------------------
# Async gate (non-blocking; supports optional wait)
# ---------------------------------------------------------------------------

class _AsyncGate:
    def __init__(self, limit: int) -> None:
        self.limit = max(1, int(limit))
        self._inflight = 0
        self._lock = asyncio.Lock()
        self._cond = asyncio.Condition(self._lock)

    async def acquire(self, *, timeout_s: float) -> bool:
        timeout_s = max(0.0, float(timeout_s))
        end = time.monotonic() + timeout_s
        async with self._cond:
            while self._inflight >= self.limit:
                if timeout_s <= 0.0:
                    return False
                rem = end - time.monotonic()
                if rem <= 0.0:
                    return False
                try:
                    await asyncio.wait_for(self._cond.wait(), timeout=rem)
                except asyncio.TimeoutError:
                    return False
            self._inflight += 1
            return True

    async def release(self) -> None:
        async with self._cond:
            self._inflight = max(0, self._inflight - 1)
            self._cond.notify(1)

    async def set_limit(self, limit: int) -> None:
        async with self._cond:
            self.limit = max(1, int(limit))
            self._cond.notify_all()

    async def inflight(self) -> int:
        async with self._lock:
            return int(self._inflight)


# ---------------------------------------------------------------------------
# SQLite outbox (sync core; all calls are executed in SQL executor)
# ---------------------------------------------------------------------------

class _SQLiteOutbox:
    def __init__(self, path: str) -> None:
        self.path = str(path)
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=2.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        return conn

    def _init_db(self) -> None:
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with self._lock:
            c = self._conn()
            try:
                c.execute(
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
                c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_outbox_dedupe ON outbox(kind, dedupe_key);")
                c.execute("CREATE INDEX IF NOT EXISTS idx_outbox_next ON outbox(kind, next_ts, created_ts);")
            finally:
                c.close()

    def _file_bytes(self) -> int:
        with contextlib.suppress(Exception):
            return int(os.path.getsize(self.path))
        return 0

    def _row_count(self, kind: str) -> int:
        c = self._conn()
        try:
            cur = c.execute("SELECT COUNT(*) FROM outbox WHERE kind=?", (str(kind),))
            row = cur.fetchone()
            return int(row[0] if row and row[0] is not None else 0)
        finally:
            c.close()

    def enforce_capacity(self, *, kind: str, max_rows: int, max_db_bytes: int, drop_policy: str) -> bool:
        """
        Returns True if inserts are allowed, False if the policy rejects new inserts.
        If drop_policy is drop_oldest, it prunes as needed.
        """
        max_rows = max(1, int(max_rows))
        max_db_bytes = max(1, int(max_db_bytes))
        drop_policy = str(drop_policy or "drop_oldest").lower()

        with self._lock:
            rows = self._row_count(kind)
            fbytes = self._file_bytes()
            over_rows = rows > max_rows
            over_bytes = fbytes > max_db_bytes

            if not over_rows and not over_bytes:
                return True

            if drop_policy == "drop_newest":
                return False
            if drop_policy == "reject_request":
                return False

            # drop_oldest: prune to 90% of limit to reduce churn
            target_rows = int(max_rows * 0.9)
            target_bytes = int(max_db_bytes * 0.9)

            c = self._conn()
            try:
                # prune by rows first
                if rows > target_rows:
                    to_drop = rows - target_rows
                    c.execute(
                        """
                        DELETE FROM outbox
                        WHERE id IN (
                          SELECT id FROM outbox WHERE kind=? ORDER BY created_ts ASC LIMIT ?
                        )
                        """,
                        (str(kind), int(to_drop)),
                    )
                # if still too large in bytes, prune additional oldest rows (bounded loop)
                # (sqlite doesn't easily expose per-row bytes cheaply; prune by chunks)
                for _ in range(8):
                    if self._file_bytes() <= target_bytes:
                        break
                    c.execute(
                        """
                        DELETE FROM outbox
                        WHERE id IN (
                          SELECT id FROM outbox WHERE kind=? ORDER BY created_ts ASC LIMIT 200
                        )
                        """,
                        (str(kind),),
                    )
                return True
            finally:
                c.close()

    def put(self, *, kind: str, dedupe_key: str, payload_json: str, payload_digest: str) -> str:
        """
        Returns: inserted|ignored|updated|rejected
        - inserted: new row
        - ignored: same dedupe_key with same digest already exists
        - updated: same dedupe_key exists but digest differs => update payload (no silent loss)
        - rejected: capacity policy rejected insert (caller decides)
        """
        now = time.time()
        kind = str(kind)
        dedupe_key = str(dedupe_key)

        with self._lock:
            c = self._conn()
            try:
                # Attempt insert.
                c.execute(
                    """
                    INSERT OR IGNORE INTO outbox(kind, dedupe_key, payload_json, payload_digest, attempts, next_ts, created_ts, last_error)
                    VALUES(?, ?, ?, ?, 0, ?, ?, '')
                    """,
                    (kind, dedupe_key, str(payload_json), str(payload_digest), float(now), float(now)),
                )
                if c.total_changes > 0:
                    return "inserted"

                # Conflict: fetch existing digest.
                cur = c.execute(
                    "SELECT payload_digest FROM outbox WHERE kind=? AND dedupe_key=?",
                    (kind, dedupe_key),
                )
                row = cur.fetchone()
                existing = str(row[0]) if row and row[0] is not None else ""
                if existing == str(payload_digest):
                    return "ignored"

                # Digest differs => update payload and digest (no silent loss).
                c.execute(
                    """
                    UPDATE outbox
                    SET payload_json=?, payload_digest=?, last_error=''
                    WHERE kind=? AND dedupe_key=?
                    """,
                    (str(payload_json), str(payload_digest), kind, dedupe_key),
                )
                return "updated"
            finally:
                c.close()

    def peek(self, *, kind: str, now_ts: float, limit: int) -> List[Dict[str, Any]]:
        limit = max(1, min(200, int(limit)))
        with self._lock:
            c = self._conn()
            try:
                cur = c.execute(
                    """
                    SELECT id, dedupe_key, payload_json, payload_digest, attempts, next_ts, created_ts, last_error
                    FROM outbox
                    WHERE kind=? AND next_ts<=?
                    ORDER BY created_ts ASC
                    LIMIT ?
                    """,
                    (str(kind), float(now_ts), int(limit)),
                )
                rows = cur.fetchall()
            finally:
                c.close()
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append(
                {
                    "id": int(r[0]),
                    "dedupe_key": str(r[1]),
                    "payload_json": str(r[2]),
                    "payload_digest": str(r[3]),
                    "attempts": int(r[4]),
                    "next_ts": float(r[5]),
                    "created_ts": float(r[6]),
                    "last_error": str(r[7]),
                }
            )
        return out

    def ack(self, *, kind: str, row_id: int) -> None:
        with self._lock:
            c = self._conn()
            try:
                c.execute("DELETE FROM outbox WHERE kind=? AND id=?", (str(kind), int(row_id)))
            finally:
                c.close()

    def nack(self, *, kind: str, row_id: int, attempts: int, next_ts: float, last_error: str) -> None:
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    """
                    UPDATE outbox
                    SET attempts=?, next_ts=?, last_error=?
                    WHERE kind=? AND id=?
                    """,
                    (int(attempts), float(next_ts), _truncate(_safe_text(last_error, max_len=512), 512), str(kind), int(row_id)),
                )
            finally:
                c.close()

    def stats(self, *, kind: str, now_ts: float) -> Dict[str, Any]:
        with self._lock:
            c = self._conn()
            try:
                cur = c.execute("SELECT COUNT(*), MIN(created_ts) FROM outbox WHERE kind=?", (str(kind),))
                row = cur.fetchone()
            finally:
                c.close()
        total = int(row[0] if row and row[0] is not None else 0)
        oldest_ts = float(row[1] if row and row[1] is not None else 0.0)
        oldest_age = max(0.0, float(now_ts) - oldest_ts) if oldest_ts > 0 else 0.0
        return {"total": total, "oldest_age_s": oldest_age}


# ---------------------------------------------------------------------------
# verify_key policy (format + len + allow/deny; supports hash list entries)
# ---------------------------------------------------------------------------

def _vk_matches_rule(vk: str, rule: str) -> bool:
    """
    rule formats:
    - "prefix:ABC" or "ABC" => vk.startswith(ABC)
    - "hash:deadbeef" or "h:deadbeef" => blake3(vk).startswith(deadbeef)
    """
    r = (rule or "").strip()
    if not r:
        return False
    r_low = r.lower()
    if r_low.startswith("hash:") or r_low.startswith("h:"):
        pref = r.split(":", 1)[1].strip()
        if not pref:
            return False
        digest = _hash_token(vk, ctx="tcd:verify_key", n=64)
        return digest.startswith(pref.lower())
    if r_low.startswith("prefix:"):
        pref2 = r.split(":", 1)[1].strip()
        return bool(pref2) and vk.startswith(pref2)
    return vk.startswith(r)


def _verify_key_allowed(vk: Optional[str], cfg: ApiV1Config) -> bool:
    if not vk:
        return True
    vk_s = str(vk)

    # format/len/charset
    if len(vk_s) > int(cfg.max_verify_key_len):
        return False
    if not _VERIFY_KEY_RE.match(vk_s):
        return False

    deny = cfg.verify_key_denylist or []
    allow = cfg.verify_key_allowlist or []

    for d in deny:
        if _vk_matches_rule(vk_s, d):
            return False

    if allow:
        for a in allow:
            if _vk_matches_rule(vk_s, a):
                return True
        return False

    return True


# ---------------------------------------------------------------------------
# Evidence caps (receipt/body/sig/verify_key)
# ---------------------------------------------------------------------------

def _cap_bytes_like(val: Any, *, max_bytes: int) -> Tuple[Any, bool]:
    """
    Ensures val is <= max_bytes (approx).
    Returns (new_val, truncated).
    Strategy:
      - If bytes-like: slice.
      - If str: truncate by encoded bytes approximation.
      - If dict/list: serialize canonical JSON and drop if too big.
    """
    max_bytes = max(0, int(max_bytes))
    if max_bytes <= 0 or val is None:
        return (val, False)

    try:
        if isinstance(val, (bytes, bytearray, memoryview)):
            b = bytes(val)
            if len(b) <= max_bytes:
                return (val, False)
            return (b[:max_bytes], True)

        if isinstance(val, str):
            b = val.encode("utf-8", errors="ignore")
            if len(b) <= max_bytes:
                return (val, False)
            # truncate conservatively by chars
            return (_truncate(val, max(16, int(max_bytes // 2))), True)

        if isinstance(val, (dict, list)):
            js = _canonical_json(val)
            b2 = js.encode("utf-8", errors="ignore")
            if len(b2) <= max_bytes:
                return (val, False)
            return (None, True)

        # fallback stringify
        s = _safe_text(val, max_len=max(16, int(max_bytes // 2)))
        b3 = s.encode("utf-8", errors="ignore")
        if len(b3) <= max_bytes:
            return (s, False)
        return (_truncate(s, max(16, int(max_bytes // 2))), True)
    except Exception:
        return (None, True)


def _cap_evidence_fields(raw: Dict[str, Any], cfg: ApiV1Config) -> Tuple[Dict[str, Any], bool]:
    """
    Enforces evidence field budgets. Returns (new_raw, evidence_truncated).
    In strict_mode: oversize evidence triggers exception via caller if configured.
    """
    out = dict(raw)
    truncated = False

    # receipt
    if "receipt" in out and out.get("receipt") is not None:
        r = _safe_text(out.get("receipt"), max_len=int(cfg.max_receipt_len))
        if r != str(out.get("receipt")):
            truncated = True
        out["receipt"] = r

    # receipt_body
    rb, t1 = _cap_bytes_like(out.get("receipt_body"), max_bytes=int(cfg.max_receipt_body_bytes))
    if t1:
        truncated = True
    out["receipt_body"] = rb

    # receipt_sig
    rs, t2 = _cap_bytes_like(out.get("receipt_sig"), max_bytes=int(cfg.max_receipt_sig_bytes))
    if t2:
        truncated = True
    out["receipt_sig"] = rs

    # verify_key length enforcement here too (format enforced separately)
    vk = out.get("verify_key")
    if vk is not None:
        vk_s = _safe_text(vk, max_len=int(cfg.max_verify_key_len))
        if vk_s != str(vk):
            truncated = True
        out["verify_key"] = vk_s

    return out, truncated


# ---------------------------------------------------------------------------
# Service class (factory/injection + lifecycle + router)
# ---------------------------------------------------------------------------

class ApiV1Service:
    def __init__(
        self,
        *,
        cfg: ApiV1Config,
        controller: Optional[Any] = None,
        authenticator: Optional[Any] = None,
        attestor: Optional[Any] = None,
        attestor_cfg: Optional[Any] = None,
        ledger: Optional[Any] = None,
        outbox: Optional[_SQLiteOutbox] = None,
    ) -> None:
        self._cfg_lock = threading.Lock()
        self.cfg = cfg
        self.cfg_digest = _compute_cfg_digest(cfg)

        # Identity (stable)
        self.node_id = cfg.node_id or ""
        self.proc_id = cfg.proc_id or str(os.getpid())
        self.build_id = cfg.build_id or ""
        self.image_digest = cfg.image_digest or ""

        # Dependencies (injectable)
        self.controller = controller if controller is not None else AlwaysValidRiskController(AlwaysValidConfig())
        self._ctrl_lock = threading.RLock()

        self.authenticator = authenticator
        self.attestor = attestor
        self.attestor_cfg = attestor_cfg
        self.ledger = ledger

        self._mtls_trusted_nets: List[ipaddress._BaseNetwork] = []
        if cfg.mtls_trusted_proxy_cidrs:
            for cidr in cfg.mtls_trusted_proxy_cidrs:
                with contextlib.suppress(Exception):
                    self._mtls_trusted_nets.append(ipaddress.ip_network(cidr, strict=False))

        # Gate (async)
        self._gate = _AsyncGate(cfg.max_inflight)
        _GATE_LIMIT.labels(cfg.route_name).set(float(cfg.max_inflight))

        # Executors (separated)
        self.exec_auth = _BoundedExecutor(pool="auth", max_workers=cfg.exec_auth_workers, max_queue=cfg.exec_auth_queue)
        self.exec_ctrl = _BoundedExecutor(pool="ctrl", max_workers=cfg.exec_ctrl_workers, max_queue=cfg.exec_ctrl_queue)
        self.exec_evidence = _BoundedExecutor(pool="evidence", max_workers=cfg.exec_evidence_workers, max_queue=cfg.exec_evidence_queue)
        self.exec_sql = _BoundedExecutor(pool="sql", max_workers=cfg.exec_sql_workers, max_queue=cfg.exec_sql_queue)

        # Breakers (per dep)
        self.br_auth = _CircuitBreaker(
            dep="auth",
            threshold=cfg.breaker_failures,
            window_s=cfg.breaker_window_s,
            open_seconds=cfg.breaker_open_seconds,
            probe_jitter_s=cfg.breaker_probe_jitter_s,
            probe_probability=cfg.breaker_probe_probability,
        )
        self.br_ctrl = _CircuitBreaker(
            dep="controller",
            threshold=cfg.breaker_failures,
            window_s=cfg.breaker_window_s,
            open_seconds=cfg.breaker_open_seconds,
            probe_jitter_s=cfg.breaker_probe_jitter_s,
            probe_probability=cfg.breaker_probe_probability,
        )
        self.br_attest = _CircuitBreaker(
            dep="attestor",
            threshold=cfg.breaker_failures,
            window_s=cfg.breaker_window_s,
            open_seconds=cfg.breaker_open_seconds,
            probe_jitter_s=cfg.breaker_probe_jitter_s,
            probe_probability=cfg.breaker_probe_probability,
        )
        self.br_ledger = _CircuitBreaker(
            dep="ledger",
            threshold=cfg.breaker_failures,
            window_s=cfg.breaker_window_s,
            open_seconds=cfg.breaker_open_seconds,
            probe_jitter_s=cfg.breaker_probe_jitter_s,
            probe_probability=cfg.breaker_probe_probability,
        )
        self.br_sql = _CircuitBreaker(
            dep="sqlite",
            threshold=cfg.breaker_failures,
            window_s=cfg.breaker_window_s,
            open_seconds=cfg.breaker_open_seconds,
            probe_jitter_s=cfg.breaker_probe_jitter_s,
            probe_probability=min(1.0, max(0.1, cfg.breaker_probe_probability)),
        )

        # Outbox
        self.outbox = outbox
        if cfg.outbox_enabled and self.outbox is None:
            try:
                self.outbox = _SQLiteOutbox(cfg.outbox_path)
            except Exception:
                logger.error("failed to init api_v1 outbox; disabling", exc_info=True)
                self.outbox = None

        # Background outbox flusher task
        self._flush_task: Optional[asyncio.Task] = None
        self._flush_task_stop = asyncio.Event()

        # Build router
        self.router = self._make_router()

        # Strict-mode presence checks
        if cfg.strict_mode:
            if cfg.require_auth and self.authenticator is None:
                raise RuntimeError("ApiV1Config.strict_mode requires an Authenticator")
            if cfg.require_attestor and self.attestor is None:
                raise RuntimeError("ApiV1Config.strict_mode requires an Attestor")
            if cfg.require_ledger and self.ledger is None:
                raise RuntimeError("ApiV1Config.strict_mode requires an AuditLedger")
            if cfg.require_pq_sig and self.attestor_cfg is not None:
                self._enforce_pq_policy()

    def _enforce_pq_policy(self) -> None:
        """
        PQ enforcement: do NOT rely on substring-only checks.
        """
        cfg = self.cfg
        acfg = self.attestor_cfg
        if acfg is None:
            raise RuntimeError("require_pq_sig set but attestor_cfg missing")

        # Preferred structured fields
        is_pq = getattr(acfg, "is_pq", None)
        sig_family = getattr(acfg, "sig_family", None)
        sig_alg = getattr(acfg, "sig_alg", None)

        if is_pq is True or (isinstance(sig_family, str) and sig_family.lower() == "pq"):
            return

        # Allowed algorithm list (explicit)
        if cfg.allowed_sig_algs and sig_alg is not None:
            alg = str(sig_alg).lower()
            if any(alg == str(a).lower() for a in cfg.allowed_sig_algs):
                return

        # As a last resort, we *refuse* rather than heuristically accept.
        raise RuntimeError("ApiV1Config.require_pq_sig could not be satisfied by structured attestor cfg")

    # -------------------------
    # Lifecycle
    # -------------------------

    async def startup(self) -> None:
        """
        Optional lifecycle hook: starts background outbox flusher if enabled.
        """
        cfg = self.cfg
        if cfg.outbox_background_flush_interval_s and cfg.outbox_background_flush_interval_s > 0 and self._flush_task is None:
            self._flush_task_stop.clear()
            self._flush_task = asyncio.create_task(self._flush_loop(), name="tcd-api-v1-outbox-flush")

    async def shutdown(self) -> None:
        """
        Optional lifecycle hook: stops background flusher + shuts down executors.
        """
        if self._flush_task is not None:
            self._flush_task_stop.set()
            self._flush_task.cancel()
            with contextlib.suppress(Exception):
                await self._flush_task
            self._flush_task = None

        # Executors
        self.exec_auth.shutdown()
        self.exec_ctrl.shutdown()
        self.exec_evidence.shutdown()
        self.exec_sql.shutdown()

    # -------------------------
    # Config hot reload
    # -------------------------

    async def apply_config(self, cfg: ApiV1Config) -> None:
        """
        Hot-reload config:
        - Recomputes digest.
        - Updates gate limit.
        - Emits cfg_reload ledger event (best-effort).
        Note: executors/breakers/outbox path changes are not live-swapped here; for those,
        deploy-time restart is recommended. (We keep semantics safe.)
        """
        with self._cfg_lock:
            self.cfg = cfg
            self.cfg_digest = _compute_cfg_digest(cfg)
        await self._gate.set_limit(cfg.max_inflight)
        _GATE_LIMIT.labels(cfg.route_name).set(float(cfg.max_inflight))

        # Best-effort cfg_reload event
        if self.ledger is not None:
            evt = {
                "schema_version": 1,
                "kind": "api_v1_cfg_reload",
                "ts_ns": time.time_ns(),
                "route": cfg.route_name,
                "node_id": self.node_id,
                "proc_id": self.proc_id,
                "cfg_digest": self.cfg_digest,
            }
            with contextlib.suppress(Exception):
                await self._dep_call(
                    dep="ledger",
                    op="append_cfg_reload",
                    breaker=self.br_ledger,
                    executor=self.exec_evidence,
                    timeout_ms=cfg.ledger_timeout_ms,
                    deadline_mono=None,
                    fn=lambda: self.ledger.append(evt),  # type: ignore[union-attr]
                    idempotent=True,
                )

    # -------------------------
    # Router construction
    # -------------------------

    def _make_route_class(self) -> type[APIRoute]:
        service = self

        class _HardenedJSONRoute(APIRoute):
            def get_route_handler(self) -> Callable[[Request], Awaitable[Response]]:
                original = super().get_route_handler()

                async def _handler(request: Request) -> Response:
                    return await service._route_wrapper(original, request)

                return _handler

        return _HardenedJSONRoute

    def _make_router(self) -> APIRouter:
        route_class = self._make_route_class()
        router = APIRouter(prefix="/v1", tags=["v1"], route_class=route_class)

        async def _diagnose(payload: DiagnoseIn, request: Request) -> DiagnoseOut:
            return await self.handle_diagnose(payload, request)

        router.add_api_route("/diagnose", _diagnose, methods=["POST"], response_model=DiagnoseOut)
        return router

    # -------------------------
    # IDs + envelopes
    # -------------------------

    def _mk_request_id(self, request: Request) -> str:
        rid = (request.headers.get("X-Request-Id") or request.headers.get("x-request-id") or "").strip()
        if rid:
            return _safe_text(rid, max_len=128)
        return f"r-{time.time_ns()}-{os.getpid()}-{os.urandom(4).hex()}"

    def _extract_idempotency_key(self, request: Request) -> Optional[str]:
        k = (request.headers.get("Idempotency-Key") or request.headers.get("idempotency-key") or "").strip()
        if not k:
            return None
        k = _safe_text(k, max_len=128)
        if not _IDEMPOTENCY_KEY_RE.match(k):
            return None
        return k

    def _mk_event_id(self, request: Request, *, body_digest: Optional[str]) -> str:
        cfg = self.cfg
        ik = self._extract_idempotency_key(request)
        if ik:
            return f"idemp:{ik}"

        # deterministic fallback: body_digest + time bucket (prevents infinite dedupe)
        bd = body_digest or "no_body"
        bucket = 0
        if cfg.idempotency_time_bucket_s and cfg.idempotency_time_bucket_s > 0:
            bucket = int(time.time() // int(cfg.idempotency_time_bucket_s))
        return f"bd:{bd[:16]}:{bucket}"

    def _error_detail(
        self,
        request: Request,
        *,
        kind: str,
        message: str,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        rid = getattr(getattr(request, "state", object()), "tcd_request_id", None) or self._mk_request_id(request)
        eid = getattr(getattr(request, "state", object()), "tcd_event_id", None) or ""
        d: Dict[str, Any] = {
            "ok": False,
            "request_id": rid,
            "event_id": eid,
            "error": {
                "kind": str(kind),
                "message": str(message),
                "extra": _sanitize_error_extra(extra),
            },
        }
        if self.cfg.debug_errors:
            d["error"]["breaker"] = {
                "auth": self.br_auth.snapshot(),
                "controller": self.br_ctrl.snapshot(),
                "attestor": self.br_attest.snapshot(),
                "ledger": self.br_ledger.snapshot(),
                "sqlite": self.br_sql.snapshot(),
            }
        return d

    def _json_error_response(
        self,
        request: Request,
        *,
        status_code: int,
        kind: str,
        message: str,
        extra: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> JSONResponse:
        detail = self._error_detail(request, kind=kind, message=message, extra=extra)
        resp = JSONResponse(status_code=int(status_code), content={"detail": detail}, headers=headers or {})
        # harden error responses
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        # platform headers
        resp.headers["X-TCD-ApiV1-Cfg-Digest"] = self.cfg_digest
        resp.headers["X-TCD-Node-Id"] = self.node_id
        if self.build_id:
            resp.headers["X-TCD-Build-Id"] = self.build_id
        if self.image_digest:
            resp.headers["X-TCD-Image-Digest"] = self.image_digest
        rid = getattr(getattr(request, "state", object()), "tcd_request_id", None)
        eid = getattr(getattr(request, "state", object()), "tcd_event_id", None)
        if rid:
            resp.headers["X-TCD-Request-Id"] = str(rid)
        if eid:
            resp.headers["X-TCD-Event-Id"] = str(eid)
        return resp

    # -------------------------
    # Route wrapper (P0): headers/body/json-guards + gate + request state
    # -------------------------

    async def _route_wrapper(self, original: Callable[[Request], Awaitable[Response]], request: Request) -> Response:
        cfg = self.cfg
        route = cfg.route_name
        t0 = time.perf_counter()

        rid = self._mk_request_id(request)
        try:
            request.state.tcd_request_id = rid  # type: ignore[attr-defined]
        except Exception:
            pass

        # Header budgets (count/bytes) from raw scope for accuracy
        raw_headers = request.scope.get("headers") or []
        try:
            header_count = int(len(raw_headers))
            header_bytes = int(sum(len(k) + len(v) for (k, v) in raw_headers))
        except Exception:
            header_count, header_bytes = (0, 0)

        _REQ_HEADER_COUNT.labels(route).observe(float(header_count))
        _REQ_HEADER_BYTES.labels(route).observe(float(header_bytes))

        if cfg.max_header_count > 0 and header_count > int(cfg.max_header_count):
            _REQ_REJECTED.labels(route, "headers_too_many").inc()
            _REQ_TOTAL.labels(route, "rejected").inc()
            dur = time.perf_counter() - t0
            _REQ_LATENCY.labels(route, "reject", "none").observe(dur)
            return self._json_error_response(
                request,
                status_code=HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE,
                kind=ERR_HEADERS_TOO_LARGE,
                message="too many headers",
            )

        if cfg.max_header_bytes > 0 and header_bytes > int(cfg.max_header_bytes):
            _REQ_REJECTED.labels(route, "headers_too_large").inc()
            _REQ_TOTAL.labels(route, "rejected").inc()
            dur = time.perf_counter() - t0
            _REQ_LATENCY.labels(route, "reject", "none").observe(dur)
            return self._json_error_response(
                request,
                status_code=HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE,
                kind=ERR_HEADERS_TOO_LARGE,
                message="headers too large",
            )

        # Gate acquire (async, optional wait)
        wait_s = max(0.0, float(cfg.gate_wait_ms) / 1000.0)
        ok_gate = await self._gate.acquire(timeout_s=wait_s)
        if not ok_gate:
            _GATE_REJECT.labels(route, "limit").inc()
            _REQ_REJECTED.labels(route, "overloaded").inc()
            _REQ_TOTAL.labels(route, "rejected").inc()
            dur = time.perf_counter() - t0
            _REQ_LATENCY.labels(route, "reject", "none").observe(dur)
            return self._json_error_response(
                request,
                status_code=HTTP_429_TOO_MANY_REQUESTS,
                kind=ERR_OVERLOADED,
                message="overloaded",
                headers={"Retry-After": "1"},
            )

        try:
            infl = await self._gate.inflight()
            _REQ_INFLIGHT.labels(route).set(float(infl))

            # Body guard + JSON guards for methods with body
            body = b""
            body_digest = None

            if request.method.upper() in ("POST", "PUT", "PATCH"):
                # Content-Type enforcement
                if cfg.require_json_content_type:
                    ct = (request.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
                    if ct and not (ct == "application/json" or ct.endswith("+json")):
                        _REQ_REJECTED.labels(route, "bad_content_type").inc()
                        _REQ_TOTAL.labels(route, "rejected").inc()
                        dur = time.perf_counter() - t0
                        _REQ_LATENCY.labels(route, "reject", "none").observe(dur)
                        return self._json_error_response(
                            request,
                            status_code=HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                            kind=ERR_UNSUPPORTED_MEDIA,
                            message="unsupported Content-Type",
                        )

                max_bytes = int(cfg.max_payload_bytes)
                if max_bytes > 0:
                    cl = request.headers.get("content-length")
                    if cl is not None:
                        try:
                            if int(cl) > max_bytes:
                                _REQ_REJECTED.labels(route, "body_too_large").inc()
                                _REQ_TOTAL.labels(route, "rejected").inc()
                                dur = time.perf_counter() - t0
                                _REQ_LATENCY.labels(route, "reject", "none").observe(dur)
                                # still set event_id (idempotency-key based or rid-based)
                                try:
                                    request.state.tcd_event_id = self._mk_event_id(request, body_digest=None)  # type: ignore[attr-defined]
                                except Exception:
                                    pass
                                return self._json_error_response(
                                    request,
                                    status_code=HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    kind=ERR_PAYLOAD_TOO_LARGE,
                                    message="payload too large",
                                )
                        except Exception:
                            _REQ_REJECTED.labels(route, "bad_content_length").inc()
                            _REQ_TOTAL.labels(route, "rejected").inc()
                            dur = time.perf_counter() - t0
                            _REQ_LATENCY.labels(route, "reject", "none").observe(dur)
                            return self._json_error_response(
                                request,
                                status_code=HTTP_400_BAD_REQUEST,
                                kind=ERR_BAD_REQUEST,
                                message="invalid Content-Length",
                            )

                    # bounded stream read; avoid peak by checking before extend
                    cached = getattr(request, "_body", None)
                    if cached is not None:
                        body = bytes(cached)
                    else:
                        buf = bytearray()
                        try:
                            async for chunk in request.stream():
                                if not chunk:
                                    continue
                                if len(buf) + len(chunk) > max_bytes:
                                    _REQ_REJECTED.labels(route, "body_too_large").inc()
                                    _REQ_TOTAL.labels(route, "rejected").inc()
                                    dur = time.perf_counter() - t0
                                    _REQ_LATENCY.labels(route, "reject", "none").observe(dur)
                                    try:
                                        request.state.tcd_event_id = self._mk_event_id(request, body_digest=None)  # type: ignore[attr-defined]
                                    except Exception:
                                        pass
                                    return self._json_error_response(
                                        request,
                                        status_code=HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                        kind=ERR_PAYLOAD_TOO_LARGE,
                                        message="payload too large",
                                    )
                                buf.extend(chunk)
                        except Exception:
                            _REQ_REJECTED.labels(route, "bad_body").inc()
                            _REQ_TOTAL.labels(route, "rejected").inc()
                            dur = time.perf_counter() - t0
                            _REQ_LATENCY.labels(route, "reject", "none").observe(dur)
                            return self._json_error_response(
                                request,
                                status_code=HTTP_400_BAD_REQUEST,
                                kind=ERR_BAD_REQUEST,
                                message="invalid request body",
                            )
                        body = bytes(buf)
                        # cache for downstream (avoid double-read)
                        with contextlib.suppress(Exception):
                            setattr(request, "_body", body)
                            if hasattr(request, "_stream_consumed"):
                                setattr(request, "_stream_consumed", True)

                # metrics + state
                _REQ_BODY_BYTES.labels(route).observe(float(len(body)))
                body_digest = _hash_token(_blake3_hex(body or b"", ctx="tcd:api_v1:body"), ctx="tcd:api_v1:body_digest", n=32)
                # Store a proper blake3 digest too (for external audit)
                body_digest_full = _blake3_hex(body or b"", ctx="tcd:api_v1:body")
                with contextlib.suppress(Exception):
                    request.state.tcd_body_bytes = int(len(body))  # type: ignore[attr-defined]
                    request.state.tcd_body_digest = body_digest_full  # type: ignore[attr-defined]

                # JSON guards (depth + complexity) only when it looks like JSON
                max_seen, too_deep = _json_depth_scan(body, max_depth=int(cfg.max_json_depth))
                _REQ_JSON_DEPTH_EST.labels(route).observe(float(max_seen))
                if too_deep:
                    _REQ_REJECTED.labels(route, "json_too_deep").inc()
                    _REQ_TOTAL.labels(route, "rejected").inc()
                    dur = time.perf_counter() - t0
                    _REQ_LATENCY.labels(route, "reject", "none").observe(dur)
                    with contextlib.suppress(Exception):
                        request.state.tcd_event_id = self._mk_event_id(request, body_digest=body_digest_full)  # type: ignore[attr-defined]
                    return self._json_error_response(
                        request,
                        status_code=HTTP_400_BAD_REQUEST,
                        kind=ERR_JSON_TOO_DEEP,
                        message="json too deeply nested",
                        extra={"max_depth_seen": max_seen, "limit": int(cfg.max_json_depth)},
                    )

                stats, too_complex = _json_complexity_scan(
                    body,
                    max_tokens=int(cfg.max_json_tokens),
                    max_string_len=int(cfg.max_json_string_len),
                    max_number_len=int(cfg.max_json_number_len),
                )
                if too_complex:
                    _REQ_REJECTED.labels(route, "json_too_complex").inc()
                    _REQ_TOTAL.labels(route, "rejected").inc()
                    dur = time.perf_counter() - t0
                    _REQ_LATENCY.labels(route, "reject", "none").observe(dur)
                    with contextlib.suppress(Exception):
                        request.state.tcd_event_id = self._mk_event_id(request, body_digest=body_digest_full)  # type: ignore[attr-defined]
                    return self._json_error_response(
                        request,
                        status_code=HTTP_400_BAD_REQUEST,
                        kind=ERR_JSON_TOO_COMPLEX,
                        message="json too complex",
                        extra=stats,
                    )

            # Compute event_id (stable)
            eid = self._mk_event_id(request, body_digest=getattr(getattr(request, "state", object()), "tcd_body_digest", None))
            with contextlib.suppress(Exception):
                request.state.tcd_event_id = eid  # type: ignore[attr-defined]

            # Record "body guard end" timestamp for parse latency approximation.
            with contextlib.suppress(Exception):
                request.state.tcd_body_guard_end = float(time.perf_counter())  # type: ignore[attr-defined]

            # Execute original route handler (pydantic parse + endpoint).
            resp = await original(request)

            # Attach standard response headers
            resp.headers["X-TCD-Request-Id"] = rid
            resp.headers["X-TCD-Event-Id"] = eid
            resp.headers["X-TCD-ApiV1-Cfg-Digest"] = self.cfg_digest
            resp.headers["X-TCD-Node-Id"] = self.node_id
            if self.build_id:
                resp.headers["X-TCD-Build-Id"] = self.build_id
            if self.image_digest:
                resp.headers["X-TCD-Image-Digest"] = self.image_digest

            # Echo Idempotency-Key if valid (helps client retries)
            ik = self._extract_idempotency_key(request)
            if ik:
                resp.headers["Idempotency-Key"] = ik

            return resp
        finally:
            with contextlib.suppress(Exception):
                await self._gate.release()
                infl2 = await self._gate.inflight()
                _REQ_INFLIGHT.labels(route).set(float(infl2))

    # -------------------------
    # Dependency call with breaker + timeout + deadline + retry
    # -------------------------

    def _remaining_ms(self, deadline_mono: Optional[float]) -> Optional[int]:
        if deadline_mono is None:
            return None
        rem = deadline_mono - time.perf_counter()
        if rem <= 0.0:
            return 0
        return int(rem * 1000.0)

    async def _dep_call(
        self,
        *,
        dep: str,
        op: str,
        breaker: _CircuitBreaker,
        executor: _BoundedExecutor,
        timeout_ms: int,
        deadline_mono: Optional[float],
        fn: Callable[[], Any],
        idempotent: bool,
    ) -> Any:
        # Enforced E2E deadline
        rem_ms = self._remaining_ms(deadline_mono)
        if rem_ms is not None and rem_ms <= 0:
            _DEP_ERROR.labels(dep, op, "deadline").inc()
            raise _DepException(dep, op, kind="deadline", phase="deadline")

        # cap timeout by remaining budget
        eff_timeout_ms = int(timeout_ms)
        if rem_ms is not None:
            eff_timeout_ms = max(1, min(eff_timeout_ms, rem_ms))

        allowed, is_probe = breaker.before_call()
        if not allowed:
            _DEP_ERROR.labels(dep, op, "breaker_open").inc()
            raise _DepException(dep, op, kind="breaker_open", phase="breaker")

        t0 = time.perf_counter()
        try:
            res = await executor.run(fn, timeout_s=float(eff_timeout_ms) / 1000.0)
            dt = (time.perf_counter() - t0) * 1000.0
            _DEP_LATENCY.labels(dep, op, "ok").observe(dt)
            breaker.record_success(was_probe=is_probe)
            return res
        except _RejectedExecution:
            dt = (time.perf_counter() - t0) * 1000.0
            _DEP_LATENCY.labels(dep, op, "queue_full").observe(dt)
            _DEP_ERROR.labels(dep, op, "queue_full").inc()
            # IMPORTANT: local overload does NOT count toward dependency breaker
            raise _DepException(dep, op, kind="queue_full", phase="queue")
        except _CallTimeout as exc:
            dt = (time.perf_counter() - t0) * 1000.0
            phase = "run" if exc.started else "queue"
            _DEP_LATENCY.labels(dep, op, "timeout").observe(dt)
            _DEP_ERROR.labels(dep, op, "timeout_run" if exc.started else "timeout_queue").inc()
            # Only run-timeouts poison breaker; queue-timeouts are local overload
            if exc.started:
                breaker.record_failure(was_probe=is_probe)
            raise _DepException(dep, op, kind="timeout", phase=phase)
        except Exception:
            dt = (time.perf_counter() - t0) * 1000.0
            _DEP_LATENCY.labels(dep, op, "error").observe(dt)
            _DEP_ERROR.labels(dep, op, "error").inc()
            breaker.record_failure(was_probe=is_probe)
            raise _DepException(dep, op, kind="error", phase="run")

    async def _dep_call_with_retry(
        self,
        *,
        dep: str,
        op: str,
        breaker: _CircuitBreaker,
        executor: _BoundedExecutor,
        timeout_ms: int,
        deadline_mono: Optional[float],
        fn: Callable[[], Any],
        idempotent: bool,
    ) -> Any:
        cfg = self.cfg
        attempts = 0
        max_retry = int(cfg.dep_retry_max) if idempotent else 0
        last_exc: Optional[_DepException] = None

        while True:
            try:
                return await self._dep_call(
                    dep=dep,
                    op=op,
                    breaker=breaker,
                    executor=executor,
                    timeout_ms=timeout_ms,
                    deadline_mono=deadline_mono,
                    fn=fn,
                    idempotent=idempotent,
                )
            except _DepException as exc:
                last_exc = exc
                attempts += 1
                # retry only for run-timeouts/errors, not for breaker/queue/deadline
                if attempts > max_retry:
                    raise
                if exc.phase != "run":
                    raise
                if exc.kind not in ("timeout", "error"):
                    raise
                # budget check
                rem = self._remaining_ms(deadline_mono)
                if rem is not None and rem < int(cfg.dep_retry_base_ms) + 5:
                    raise
                # jittered backoff
                base = int(cfg.dep_retry_base_ms)
                jitter = int(random.random() * base)
                await _sleep_ms(base + jitter)

    # -------------------------
    # SQLite wrappers (async via SQL executor + breaker + timeout)
    # -------------------------

    async def _sql_call(self, *, op: str, deadline_mono: Optional[float], fn: Callable[[], Any], idempotent: bool) -> Any:
        cfg = self.cfg
        return await self._dep_call_with_retry(
            dep="sqlite",
            op=op,
            breaker=self.br_sql,
            executor=self.exec_sql,
            timeout_ms=cfg.sqlite_timeout_ms,
            deadline_mono=deadline_mono,
            fn=fn,
            idempotent=idempotent,
        )

    # -------------------------
    # Outbox helpers (async)
    # -------------------------

    async def outbox_put(self, *, kind: str, dedupe_key: str, evt: Dict[str, Any], deadline_mono: Optional[float]) -> bool:
        """
        Returns True if stored; False if dropped or rejected by capacity policy.
        """
        cfg = self.cfg
        if self.outbox is None:
            return False

        # ensure payload size bound
        payload_json = _canonical_json(evt)
        payload_bytes = payload_json.encode("utf-8", errors="ignore")
        if cfg.outbox_max_payload_bytes > 0 and len(payload_bytes) > int(cfg.outbox_max_payload_bytes):
            # strip optional big fields
            slim = dict(evt)
            slim.pop("auth", None)
            slim.pop("payload_shape", None)
            slim.pop("cause", None)
            payload_json = _canonical_json(slim)
            payload_bytes = payload_json.encode("utf-8", errors="ignore")
            if cfg.outbox_max_payload_bytes > 0 and len(payload_bytes) > int(cfg.outbox_max_payload_bytes):
                # last resort: core keys only
                core = {k: slim.get(k) for k in ("schema_version", "kind", "stage", "ts_ns", "route", "event_id", "verdict", "score", "threshold", "cfg_digest")}
                payload_json = _canonical_json(core)
                payload_bytes = payload_json.encode("utf-8", errors="ignore")

        payload_digest = _blake3_hex(payload_bytes, ctx="tcd:api_v1:outbox")

        # capacity enforcement
        policy = (cfg.outbox_drop_policy or "drop_oldest").lower()

        def _cap() -> bool:
            assert self.outbox is not None
            return self.outbox.enforce_capacity(
                kind=kind,
                max_rows=cfg.outbox_max_rows,
                max_db_bytes=cfg.outbox_max_db_bytes,
                drop_policy=policy,
            )

        allowed = await self._sql_call(op="capacity", deadline_mono=deadline_mono, fn=_cap, idempotent=True)
        if not allowed:
            _OUTBOX_DROP_TOTAL.labels(kind, policy).inc()
            if policy == "reject_request":
                return False
            # drop_newest or reject => treat as not stored
            return False

        def _put() -> str:
            assert self.outbox is not None
            return self.outbox.put(kind=kind, dedupe_key=dedupe_key, payload_json=payload_json, payload_digest=payload_digest)

        res = await self._sql_call(op="put", deadline_mono=deadline_mono, fn=_put, idempotent=True)
        if res == "updated":
            _OUTBOX_CONFLICT_TOTAL.labels(kind).inc()
        if res in ("inserted", "updated", "ignored"):
            return True
        if res == "rejected":
            _OUTBOX_DROP_TOTAL.labels(kind, policy).inc()
        return False

    async def outbox_stats_update(self, *, kind: str, deadline_mono: Optional[float]) -> None:
        if self.outbox is None:
            return
        now = time.time()

        def _stats() -> Dict[str, Any]:
            assert self.outbox is not None
            return self.outbox.stats(kind=kind, now_ts=now)

        st = await self._sql_call(op="stats", deadline_mono=deadline_mono, fn=_stats, idempotent=True)
        with contextlib.suppress(Exception):
            _OUTBOX_DEPTH.labels(kind).set(float(st.get("total", 0)))
            _OUTBOX_OLDEST_AGE_S.labels(kind).set(float(st.get("oldest_age_s", 0.0)))

    async def outbox_flush_ledger_budget(self, *, deadline_mono: Optional[float], budget_ms: int, max_items: int) -> None:
        """
        Flush outbox->ledger under a tight budget. Does not block event loop.
        """
        cfg = self.cfg
        if self.outbox is None or self.ledger is None:
            return

        budget_ms = max(0, int(budget_ms))
        max_items = max(1, int(max_items))
        t0 = time.perf_counter()
        now = time.time()

        await self.outbox_stats_update(kind="ledger", deadline_mono=deadline_mono)

        def _peek() -> List[Dict[str, Any]]:
            assert self.outbox is not None
            return self.outbox.peek(kind="ledger", now_ts=now, limit=max_items)

        rows = await self._sql_call(op="peek", deadline_mono=deadline_mono, fn=_peek, idempotent=True)

        for row in rows:
            # budget gate
            if budget_ms > 0 and (time.perf_counter() - t0) * 1000.0 > float(budget_ms):
                break

            row_id = int(row["id"])
            attempts = int(row["attempts"])
            payload_json = str(row["payload_json"])

            try:
                evt = json.loads(payload_json)
            except Exception as exc:
                _OUTBOX_FLUSH_TOTAL.labels("ledger", "no").inc()

                def _ack() -> None:
                    assert self.outbox is not None
                    self.outbox.ack(kind="ledger", row_id=row_id)

                with contextlib.suppress(Exception):
                    await self._sql_call(op="ack_bad_json", deadline_mono=deadline_mono, fn=_ack, idempotent=True)
                logger.warning("outbox payload JSON invalid; dropped: %s", _safe_text(exc, max_len=128))
                continue

            # ledger append idempotent by (event_id,stage) fields
            try:
                await self._dep_call_with_retry(
                    dep="ledger",
                    op="append_outbox",
                    breaker=self.br_ledger,
                    executor=self.exec_evidence,
                    timeout_ms=cfg.ledger_timeout_ms,
                    deadline_mono=deadline_mono,
                    fn=lambda e=evt: self.ledger.append(e),  # type: ignore[union-attr]
                    idempotent=True,
                )
                _OUTBOX_FLUSH_TOTAL.labels("ledger", "yes").inc()

                def _ack2() -> None:
                    assert self.outbox is not None
                    self.outbox.ack(kind="ledger", row_id=row_id)

                with contextlib.suppress(Exception):
                    await self._sql_call(op="ack", deadline_mono=deadline_mono, fn=_ack2, idempotent=True)
            except Exception as exc:
                _OUTBOX_FLUSH_TOTAL.labels("ledger", "no").inc()
                # exponential backoff with jitter
                attempts2 = attempts + 1
                base = 0.25 * (2 ** min(attempts2, 7))  # 0.5 .. 32s
                backoff = min(60.0, base)
                jitter = random.random() * 0.25
                next_ts = time.time() + backoff + jitter

                def _nack() -> None:
                    assert self.outbox is not None
                    self.outbox.nack(kind="ledger", row_id=row_id, attempts=attempts2, next_ts=next_ts, last_error=_safe_text(exc, max_len=256))

                with contextlib.suppress(Exception):
                    await self._sql_call(op="nack", deadline_mono=deadline_mono, fn=_nack, idempotent=True)

        await self.outbox_stats_update(kind="ledger", deadline_mono=deadline_mono)

    async def _flush_loop(self) -> None:
        """
        Background flusher (optional). Runs with its own budgets and jitter.
        """
        cfg = self.cfg
        interval = float(cfg.outbox_background_flush_interval_s)
        if interval <= 0:
            return

        while not self._flush_task_stop.is_set():
            # jitter to avoid synchronized flushes
            j = random.random() * min(1.0, interval * 0.2)
            await asyncio.sleep(max(0.1, interval + j))
            # independent budget (no request deadline)
            with contextlib.suppress(Exception):
                await self.outbox_flush_ledger_budget(
                    deadline_mono=None,
                    budget_ms=int(cfg.outbox_flush_budget_ms),
                    max_items=int(cfg.outbox_flush_max_items),
                )

    # -------------------------
    # Controller call (strict thread correctness)
    # -------------------------

    def _controller_step_with_lock(self, request: Request, lock_timeout_s: float) -> Dict[str, Any]:
        route = self.cfg.route_name
        t0 = time.perf_counter()
        acquired = self._ctrl_lock.acquire(timeout=max(0.0, float(lock_timeout_s)))
        wait_ms = (time.perf_counter() - t0) * 1000.0
        _CTRL_LOCK_WAIT_MS.labels(route, "ok" if acquired else "busy").observe(wait_ms)
        if not acquired:
            _CTRL_LOCK_BUSY.labels(route).inc()
            raise RuntimeError("controller lock busy")
        try:
            out = self.controller.step(request)  # type: ignore[attr-defined]
            if not isinstance(out, dict):
                raise RuntimeError("controller returned non-dict")
            return out
        finally:
            self._ctrl_lock.release()

    # -------------------------
    # Attestation issuance (budgeted)
    # -------------------------

    async def _maybe_issue_attestation(
        self,
        *,
        raw: Dict[str, Any],
        payload: DiagnoseIn,
        request: Request,
        auth_ctx: Any,
        deadline_mono: Optional[float],
    ) -> Tuple[Dict[str, Any], bool]:
        cfg = self.cfg
        if not cfg.issue_attestation:
            return raw, False

        # cap evidence fields even if controller provided them (prevents response/ledger blowups)
        raw2, evidence_trunc = _cap_evidence_fields(raw, cfg)

        # If controller already provided attestation fields, enforce verify_key policy and return.
        if raw2.get("receipt") and raw2.get("receipt_body") and raw2.get("receipt_sig"):
            if not _verify_key_allowed(raw2.get("verify_key"), cfg):
                raise HTTPException(
                    status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=self._error_detail(request, kind=ERR_VERIFY_KEY, message="verify_key not allowed"),
                )
            return raw2, evidence_trunc

        if self.attestor is None:
            if cfg.strict_mode and cfg.require_attestor:
                raise HTTPException(
                    status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=self._error_detail(request, kind=ERR_EVIDENCE, message="attestor missing"),
                )
            return raw2, evidence_trunc

        # client disconnect: skip best-effort evidence if disconnected
        with contextlib.suppress(Exception):
            if await request.is_disconnected():
                return raw2, evidence_trunc

        # request_id/event_id
        eid = getattr(getattr(request, "state", object()), "tcd_event_id", None) or ""
        rid = getattr(getattr(request, "state", object()), "tcd_request_id", None) or ""

        client_host = None
        with contextlib.suppress(Exception):
            client_host = request.client.host if request.client else None

        payload_dict = _model_dump(payload)
        keys = sorted(list(payload_dict.keys()))[:128]

        req_obj: Dict[str, Any] = {
            "request_id": eid or rid,
            "http_request_id": rid,
            "path": str(request.url.path),
            "method": str(request.method),
            "client": _safe_text(client_host, max_len=64) if client_host else None,
            "payload_shape": {"keys": keys},
            "node_id": self.node_id,
            "proc_id": self.proc_id,
            "build_id": self.build_id,
            "image_digest": self.image_digest,
        }

        comp_obj: Dict[str, Any] = {
            "controller": type(self.controller).__name__,
            "version": _safe_text(getattr(self.controller, "version", "v1"), max_len=32),
        }

        e_obj: Dict[str, Any] = {
            "score": float(raw2.get("score", 0.0)),
            "threshold": float(raw2.get("threshold", 0.0)),
            "e_value": float(raw2.get("e_value", 1.0)),
            "alpha_alloc": float(raw2.get("alpha_alloc", 0.0)),
            "alpha_spent": float(raw2.get("alpha_spent", 0.0)),
            "budget_remaining": float(raw2.get("budget_remaining", 0.0)),
            "decision": "allow" if raw2.get("allowed", False) else "block",
            "policy_digest": raw2.get("e_policy_digest"),
        }

        segments: List[Dict[str, Any]] = []
        # Bind ledger head if available (best-effort)
        if self.ledger is not None and hasattr(self.ledger, "head"):
            try:
                head = await self._dep_call_with_retry(
                    dep="ledger",
                    op="head",
                    breaker=self.br_ledger,
                    executor=self.exec_evidence,
                    timeout_ms=cfg.ledger_timeout_ms,
                    deadline_mono=deadline_mono,
                    fn=lambda: self.ledger.head(),  # type: ignore[union-attr]
                    idempotent=True,
                )
                segments.append({"kind": "audit_ledger_head", "id": "api-v1", "digest": str(head), "meta": {}})
            except Exception:
                logger.warning("api_v1: ledger head unavailable for attestation", exc_info=True)

        # API cfg digest witness
        segments.append({"kind": "api_cfg", "id": cfg.route_name, "digest": self.cfg_digest, "meta": {}})

        auth_proj = _sanitize_auth_ctx(auth_ctx, cfg)
        if auth_proj.get("policy_digest"):
            segments.append({"kind": "auth_policy", "id": "authenticator", "digest": auth_proj["policy_digest"], "meta": {"mode": auth_proj.get("mode")}})

        witness_tags = ["api_v1", "diagnose", type(self.controller).__name__]

        meta: Dict[str, Any] = {"route": cfg.route_name, "node_id": self.node_id, "proc_id": self.proc_id}
        if auth_proj:
            meta["auth"] = {"mode": auth_proj.get("mode"), "principal_hash": auth_proj.get("principal_hash"), "policy_digest": auth_proj.get("policy_digest")}

        # Issue attestation via evidence executor + breaker
        try:
            att = await self._dep_call_with_retry(
                dep="attestor",
                op="issue",
                breaker=self.br_attest,
                executor=self.exec_evidence,
                timeout_ms=cfg.attestor_timeout_ms,
                deadline_mono=deadline_mono,
                fn=lambda: self.attestor.issue(  # type: ignore[union-attr]
                    req_obj=req_obj,
                    comp_obj=comp_obj,
                    e_obj=e_obj,
                    witness_segments=segments,
                    witness_tags=witness_tags,
                    meta=meta,
                ),
                idempotent=True,  # request_id stable => safe to retry if attestor supports idempotency
            )
        except _DepException as exc:
            # Map dep failures
            _REQ_ERROR.labels(cfg.route_name, f"attestor_{exc.kind}_{exc.phase}").inc()
            if cfg.strict_mode and cfg.require_attestor:
                code = HTTP_503_SERVICE_UNAVAILABLE if exc.kind in ("breaker_open", "timeout") else HTTP_500_INTERNAL_SERVER_ERROR
                raise HTTPException(
                    status_code=code,
                    detail=self._error_detail(
                        request,
                        kind=ERR_TIMEOUT if exc.kind == "timeout" else ERR_DEPENDENCY,
                        message="attestor unavailable",
                        extra={"dep": exc.dep, "op": exc.op, "phase": exc.phase, "kind": exc.kind},
                    ),
                )
            return raw2, evidence_trunc

        if isinstance(att, dict):
            out = dict(raw2)
            out.setdefault("receipt", att.get("receipt"))
            out.setdefault("receipt_body", att.get("receipt_body"))
            out.setdefault("receipt_sig", att.get("receipt_sig"))
            out.setdefault("verify_key", att.get("verify_key"))

            out, t_more = _cap_evidence_fields(out, cfg)
            evidence_trunc = evidence_trunc or t_more

            if not _verify_key_allowed(out.get("verify_key"), cfg):
                raise HTTPException(
                    status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=self._error_detail(request, kind=ERR_VERIFY_KEY, message="verify_key not allowed"),
                )
            return out, evidence_trunc

        return raw2, evidence_trunc

    # -------------------------
    # Ledger events (prepare/commit) with outbox fallback
    # -------------------------

    def _build_ledger_event(
        self,
        *,
        stage: str,
        out: Optional[DiagnoseOut],
        raw: Optional[Dict[str, Any]],
        payload: DiagnoseIn,
        request: Request,
        auth_ctx: Any,
        evidence_truncated: bool,
    ) -> Dict[str, Any]:
        cfg = self.cfg
        eid = getattr(getattr(request, "state", object()), "tcd_event_id", None) or ""
        rid = getattr(getattr(request, "state", object()), "tcd_request_id", None) or ""

        payload_dict = _model_dump(payload)
        keys = sorted(list(payload_dict.keys()))[:128]

        auth_proj = _sanitize_auth_ctx(auth_ctx, cfg)

        base: Dict[str, Any] = {
            "schema_version": 1,
            "kind": "api_v1_diagnose",
            "stage": str(stage),
            "ts_ns": time.time_ns(),
            "route": cfg.route_name,
            "event_id": eid or rid,
            "http_request_id": rid,
            "node_id": self.node_id,
            "proc_id": self.proc_id,
            "build_id": self.build_id,
            "image_digest": self.image_digest,
            "payload_shape": {"keys": keys},
            "cfg_digest": self.cfg_digest,
            "evidence_truncated": bool(evidence_truncated),
        }

        if auth_proj:
            base["auth"] = auth_proj
            if auth_proj.get("policy_digest"):
                base["auth_policy_digest"] = auth_proj["policy_digest"]

        # controller identity
        base["controller"] = {
            "name": type(self.controller).__name__,
            "version": _safe_text(getattr(self.controller, "version", "v1"), max_len=32),
            "state_version": _safe_text(getattr(self.controller, "state_version", ""), max_len=64) if getattr(self.controller, "state_version", None) is not None else "",
        }

        # include decision fields (prepare uses raw; commit uses out)
        if raw is not None:
            base["verdict"] = bool(raw.get("allowed", False))
            base["score"] = float(raw.get("score", 0.0))
            base["threshold"] = float(raw.get("threshold", 0.0))
            base["e_value"] = float(raw.get("e_value", 1.0))
            base["alpha_alloc"] = float(raw.get("alpha_alloc", 0.0))
            base["alpha_spent"] = float(raw.get("alpha_spent", 0.0))
            base["budget_remaining"] = float(raw.get("budget_remaining", 0.0))
            base["action"] = _safe_text(raw.get("action", "none"), max_len=64)
            base["cause"] = _safe_text(raw.get("cause", ""), max_len=256)
            base["receipt"] = raw.get("receipt")
            base["verify_key"] = raw.get("verify_key")

        if out is not None:
            base["verdict"] = bool(out.verdict)
            base["score"] = float(out.score)
            base["threshold"] = float(out.threshold)
            base["e_value"] = float(out.e_value)
            base["alpha_alloc"] = float(out.alpha_alloc)
            base["alpha_spent"] = float(out.alpha_spent)
            base["budget_remaining"] = float(out.budget_remaining)
            base["action"] = _safe_text(out.action, max_len=64)
            base["cause"] = _safe_text(out.cause, max_len=256)
            base["receipt"] = out.receipt
            base["verify_key"] = out.verify_key

        # payload digest binding (if available)
        bd = getattr(getattr(request, "state", object()), "tcd_body_digest", None)
        if bd:
            base["body_digest"] = _safe_text(bd, max_len=96)

        # deterministic digest of event payload itself
        try:
            js = _canonical_json(base).encode("utf-8", errors="ignore")
            base["event_digest"] = _blake3_hex(js, ctx="tcd:api_v1:ledger_evt")
        except Exception:
            pass

        return base

    async def _append_ledger_or_outbox(
        self,
        *,
        evt: Dict[str, Any],
        stage: str,
        request: Request,
        deadline_mono: Optional[float],
        required: bool,
    ) -> None:
        cfg = self.cfg
        route = cfg.route_name

        # If no ledger, outbox only.
        if self.ledger is None:
            if cfg.outbox_enabled and self.outbox is not None:
                eid = evt.get("event_id") or ""
                dedupe_key = f"{eid}:{stage}"
                ok = await self.outbox_put(kind="ledger", dedupe_key=dedupe_key, evt=evt, deadline_mono=deadline_mono)
                if not ok and required:
                    raise HTTPException(
                        status_code=HTTP_503_SERVICE_UNAVAILABLE,
                        detail=self._error_detail(request, kind=ERR_EVIDENCE, message="ledger unavailable (outbox full)"),
                    )
            elif required:
                raise HTTPException(
                    status_code=HTTP_503_SERVICE_UNAVAILABLE,
                    detail=self._error_detail(request, kind=ERR_EVIDENCE, message="ledger unavailable"),
                )
            return

        # client disconnect: skip non-required ledger writes
        if not required:
            with contextlib.suppress(Exception):
                if await request.is_disconnected():
                    return

        try:
            await self._dep_call_with_retry(
                dep="ledger",
                op=f"append_{stage}",
                breaker=self.br_ledger,
                executor=self.exec_evidence,
                timeout_ms=cfg.ledger_timeout_ms,
                deadline_mono=deadline_mono,
                fn=lambda e=evt: self.ledger.append(e),  # type: ignore[union-attr]
                idempotent=True,
            )
        except _DepException as exc:
            _LEDGER_ERROR.labels(route, stage).inc()
            _REQ_ERROR.labels(route, f"ledger_{stage}_{exc.kind}_{exc.phase}").inc()

            # Outbox fallback
            if cfg.outbox_enabled and self.outbox is not None:
                eid = evt.get("event_id") or ""
                dedupe_key = f"{eid}:{stage}"
                ok = await self.outbox_put(kind="ledger", dedupe_key=dedupe_key, evt=evt, deadline_mono=deadline_mono)
                if not ok and required:
                    raise HTTPException(
                        status_code=HTTP_503_SERVICE_UNAVAILABLE,
                        detail=self._error_detail(
                            request,
                            kind=ERR_EVIDENCE,
                            message="ledger unavailable (outbox full)",
                            extra={"phase": exc.phase, "kind": exc.kind},
                        ),
                    )
                return

            if required:
                raise HTTPException(
                    status_code=HTTP_503_SERVICE_UNAVAILABLE,
                    detail=self._error_detail(
                        request,
                        kind=ERR_EVIDENCE,
                        message="ledger unavailable",
                        extra={"phase": exc.phase, "kind": exc.kind},
                    ),
                )

    # -------------------------
    # Normalize controller output to DiagnoseOut (with strict invariants + caps)
    # -------------------------

    def _normalize(self, raw: Dict[str, Any], auth_ctx: Any) -> DiagnoseOut:
        cfg = self.cfg
        components = raw.get("components", {}) or {}
        components = _sanitize_components(components, cfg)

        if cfg.attach_auth_context:
            auth_proj = _sanitize_auth_ctx(auth_ctx, cfg)
            if auth_proj and "auth" not in components:
                components = dict(components)
                components["auth"] = auth_proj

        # Extract e-process numeric invariants
        e_value = float(raw.get("e_value", 1.0))
        alpha_alloc = float(raw.get("alpha_alloc", 0.0))
        alpha_spent = float(raw.get("alpha_spent", 0.0))
        budget_remaining = float(raw.get("budget_remaining", 0.0))

        if cfg.strict_mode:
            if e_value < 0.0 or alpha_alloc < 0.0 or alpha_spent < 0.0 or budget_remaining < 0.0:
                _REQ_ERROR.labels(cfg.route_name, "e_process_invariant").inc()
                raise HTTPException(
                    status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="internal error",
                )

        return DiagnoseOut(
            verdict=bool(raw.get("allowed", False)),
            score=float(raw.get("score", 0.0)),
            threshold=float(raw.get("threshold", 0.0)),
            budget_remaining=budget_remaining,
            components=components,
            cause=_safe_text(raw.get("cause", ""), max_len=256),
            action=_safe_text(raw.get("action", "none"), max_len=64),
            step=int(raw.get("step", 0)),
            e_value=e_value,
            alpha_alloc=alpha_alloc,
            alpha_spent=alpha_spent,
            receipt=raw.get("receipt"),
            receipt_body=raw.get("receipt_body"),
            receipt_sig=raw.get("receipt_sig"),
            verify_key=raw.get("verify_key"),
        )

    # -------------------------
    # Main handler
    # -------------------------

    async def handle_diagnose(self, payload: DiagnoseIn, request: Request) -> DiagnoseOut:
        cfg = self.cfg
        route = cfg.route_name
        t0 = time.perf_counter()

        # Parse latency approximation: time between wrapper finishing body guard and handler entry
        t_guard_end = getattr(getattr(request, "state", object()), "tcd_body_guard_end", None)
        if isinstance(t_guard_end, (int, float)) and t_guard_end > 0:
            _REQ_PARSE_LAT_MS.labels(route).observe(max(0.0, (time.perf_counter() - float(t_guard_end)) * 1000.0))

        # enforced E2E deadline
        deadline = None
        if cfg.max_end_to_end_latency_s and cfg.max_end_to_end_latency_s > 0:
            deadline = t0 + float(cfg.max_end_to_end_latency_s)

        auth_mode_label = "none"
        verdict_label = "error"
        status_label = "error"
        status_code_for_log = 500

        eid = getattr(getattr(request, "state", object()), "tcd_event_id", None) or ""
        rid = getattr(getattr(request, "state", object()), "tcd_request_id", None) or self._mk_request_id(request)

        auth_ctx = None
        auth_reason_code = "unknown"

        try:
            # mTLS header gate (trusted proxy model)
            if cfg.require_mtls_header:
                # only trust header if client IP in trusted proxy cidrs (if configured)
                client_ip = None
                with contextlib.suppress(Exception):
                    client_ip = request.client.host if request.client else None
                if cfg.mtls_trusted_proxy_cidrs:
                    trusted = False
                    if client_ip:
                        with contextlib.suppress(Exception):
                            ip = ipaddress.ip_address(client_ip)
                            trusted = any(ip in net for net in self._mtls_trusted_nets)
                    if not trusted:
                        _REQ_REJECTED.labels(route, "mtls_untrusted_proxy").inc()
                        status_label = "rejected"
                        status_code_for_log = HTTP_401_UNAUTHORIZED
                        raise HTTPException(
                            status_code=HTTP_401_UNAUTHORIZED,
                            detail=self._error_detail(request, kind=ERR_AUTH, message="unauthorized"),
                        )

                val = (request.headers.get(cfg.mtls_verify_header) or "").strip()
                if val != cfg.mtls_verify_value:
                    _REQ_REJECTED.labels(route, "mtls_required").inc()
                    status_label = "rejected"
                    status_code_for_log = HTTP_401_UNAUTHORIZED
                    raise HTTPException(
                        status_code=HTTP_401_UNAUTHORIZED,
                        detail=self._error_detail(request, kind=ERR_AUTH, message="unauthorized"),
                    )

            # AUTH
            if self.authenticator is not None and AuthResult is not None:
                try:
                    auth_result = await self._dep_call_with_retry(
                        dep="auth",
                        op="authenticate",
                        breaker=self.br_auth,
                        executor=self.exec_auth,
                        timeout_ms=cfg.auth_timeout_ms,
                        deadline_mono=deadline,
                        fn=lambda: self.authenticator.authenticate(request),  # type: ignore[call-arg, union-attr]
                        idempotent=True,
                    )
                except _DepException as exc:
                    # queue_* => local overload => 429
                    if exc.phase == "queue" or exc.kind == "queue_full":
                        _REQ_REJECTED.labels(route, "auth_overloaded").inc()
                        status_label = "rejected"
                        status_code_for_log = HTTP_429_TOO_MANY_REQUESTS
                        raise HTTPException(
                            status_code=HTTP_429_TOO_MANY_REQUESTS,
                            detail=self._error_detail(
                                request,
                                kind=ERR_OVERLOADED,
                                message="auth overloaded",
                                extra={"phase": exc.phase, "kind": exc.kind},
                            ),
                        )
                    # breaker/timeout/run error => dependency
                    _REQ_REJECTED.labels(route, "auth_unavailable").inc()
                    status_label = "rejected"
                    status_code_for_log = HTTP_503_SERVICE_UNAVAILABLE
                    raise HTTPException(
                        status_code=HTTP_503_SERVICE_UNAVAILABLE,
                        detail=self._error_detail(
                            request,
                            kind=ERR_DEPENDENCY if exc.kind == "breaker_open" else ERR_TIMEOUT if exc.kind == "timeout" else ERR_DEPENDENCY,
                            message="auth unavailable",
                            extra={"phase": exc.phase, "kind": exc.kind},
                        ),
                    )

                auth_ctx = getattr(auth_result, "ctx", None)
                ok = bool(getattr(auth_result, "ok", False))
                mode = getattr(auth_ctx, "mode", None)
                auth_mode_label = _normalize_auth_mode(mode)

                # optional reason_code (low-card)
                rc = getattr(auth_result, "reason_code", None) or getattr(auth_result, "reason", None) or getattr(auth_result, "code", None)
                if rc is not None:
                    auth_reason_code = _safe_text(rc, max_len=32).lower()
                    if not auth_reason_code:
                        auth_reason_code = "unknown"

                if not ok:
                    _AUTH_REJECT_TOTAL.labels(route, auth_reason_code).inc()
                    _REQ_REJECTED.labels(route, "unauthorized").inc()
                    status_label = "rejected"
                    status_code_for_log = HTTP_401_UNAUTHORIZED
                    raise HTTPException(
                        status_code=HTTP_401_UNAUTHORIZED,
                        detail=self._error_detail(request, kind=ERR_AUTH, message="unauthorized"),
                    )

                # strict allow-list check (compare normalized mode)
                if cfg.strict_mode and cfg.allowed_auth_modes:
                    allowed = set(_normalize_auth_mode(x) for x in cfg.allowed_auth_modes)
                    if auth_mode_label not in allowed:
                        _REQ_REJECTED.labels(route, "auth_mode_forbidden").inc()
                        status_label = "rejected"
                        status_code_for_log = HTTP_401_UNAUTHORIZED
                        raise HTTPException(
                            status_code=HTTP_401_UNAUTHORIZED,
                            detail=self._error_detail(request, kind=ERR_FORBIDDEN, message="unauthorized"),
                        )
            else:
                # No authenticator configured
                if cfg.strict_mode and cfg.require_auth:
                    _REQ_REJECTED.labels(route, "auth_missing").inc()
                    status_label = "rejected"
                    status_code_for_log = HTTP_401_UNAUTHORIZED
                    raise HTTPException(
                        status_code=HTTP_401_UNAUTHORIZED,
                        detail=self._error_detail(request, kind=ERR_AUTH, message="unauthorized"),
                    )

            # client disconnect early stop: if disconnected, skip expensive best-effort steps later
            disconnected = False
            with contextlib.suppress(Exception):
                disconnected = bool(await request.is_disconnected())

            # CONTROLLER
            # lock acquire timeout is itself budgeted by remaining E2E
            rem_ms = self._remaining_ms(deadline)
            lock_timeout_ms = int(cfg.controller_lock_timeout_ms)
            if rem_ms is not None:
                lock_timeout_ms = max(1, min(lock_timeout_ms, rem_ms))
            lock_timeout_s = float(lock_timeout_ms) / 1000.0

            try:
                raw = await self._dep_call_with_retry(
                    dep="controller",
                    op="step",
                    breaker=self.br_ctrl,
                    executor=self.exec_ctrl,
                    timeout_ms=cfg.controller_timeout_ms,
                    deadline_mono=deadline,
                    fn=lambda: self._controller_step_with_lock(request, lock_timeout_s),
                    idempotent=True,
                )
            except _DepException as exc:
                if exc.kind == "queue_full" or exc.phase == "queue":
                    _REQ_REJECTED.labels(route, "controller_overloaded").inc()
                    status_label = "rejected"
                    status_code_for_log = HTTP_429_TOO_MANY_REQUESTS
                    raise HTTPException(
                        status_code=HTTP_429_TOO_MANY_REQUESTS,
                        detail=self._error_detail(
                            request,
                            kind=ERR_OVERLOADED,
                            message="controller overloaded",
                            extra={"phase": exc.phase, "kind": exc.kind},
                        ),
                    )
                status_label = "error"
                status_code_for_log = HTTP_503_SERVICE_UNAVAILABLE
                raise HTTPException(
                    status_code=HTTP_503_SERVICE_UNAVAILABLE,
                    detail=self._error_detail(
                        request,
                        kind=ERR_TIMEOUT if exc.kind == "timeout" else ERR_DEPENDENCY,
                        message="controller unavailable",
                        extra={"phase": exc.phase, "kind": exc.kind},
                    ),
                )
            except Exception:
                # controller lock busy or other runtime
                _REQ_REJECTED.labels(route, "controller_lock_busy").inc()
                status_label = "rejected"
                status_code_for_log = HTTP_429_TOO_MANY_REQUESTS
                raise HTTPException(
                    status_code=HTTP_429_TOO_MANY_REQUESTS,
                    detail=self._error_detail(request, kind=ERR_OVERLOADED, message="controller busy"),
                )

            if not isinstance(raw, dict):
                _REQ_ERROR.labels(route, "controller_type").inc()
                raise HTTPException(
                    status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=self._error_detail(request, kind=ERR_INTERNAL, message="internal error"),
                )

            # PREPARE ledger stage (after controller decision is known)
            evidence_truncated = False
            if self.ledger is not None or self.outbox is not None:
                prepare_evt = self._build_ledger_event(
                    stage="prepare",
                    out=None,
                    raw=raw,
                    payload=payload,
                    request=request,
                    auth_ctx=auth_ctx,
                    evidence_truncated=False,
                )
                await self._append_ledger_or_outbox(
                    evt=prepare_evt,
                    stage="prepare",
                    request=request,
                    deadline_mono=deadline,
                    required=bool(cfg.strict_mode and cfg.ledger_prepare_required and cfg.require_ledger),
                )

            # ATTESTATION (skip if client disconnected; best-effort unless strict requires)
            raw2 = raw
            if not disconnected:
                raw2, evidence_truncated = await self._maybe_issue_attestation(
                    raw=raw,
                    payload=payload,
                    request=request,
                    auth_ctx=auth_ctx,
                    deadline_mono=deadline,
                )

            # Evidence caps + verify_key policy (hard)
            raw2, ev_trunc2 = _cap_evidence_fields(raw2, cfg)
            evidence_truncated = evidence_truncated or ev_trunc2

            if not _verify_key_allowed(raw2.get("verify_key"), cfg):
                raise HTTPException(
                    status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=self._error_detail(request, kind=ERR_VERIFY_KEY, message="verify_key not allowed"),
                )

            # Normalize to output
            out = self._normalize(raw2, auth_ctx)

            # Apply verify_key policy again on normalized output (defense-in-depth)
            if not _verify_key_allowed(out.verify_key, cfg):
                raise HTTPException(
                    status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=self._error_detail(request, kind=ERR_VERIFY_KEY, message="verify_key not allowed"),
                )

            # COMMIT ledger stage (post-normalize; may include receipt)
            if self.ledger is not None or self.outbox is not None:
                commit_evt = self._build_ledger_event(
                    stage="commit",
                    out=out,
                    raw=raw2,
                    payload=payload,
                    request=request,
                    auth_ctx=auth_ctx,
                    evidence_truncated=evidence_truncated,
                )
                await self._append_ledger_or_outbox(
                    evt=commit_evt,
                    stage="commit",
                    request=request,
                    deadline_mono=deadline,
                    required=bool(cfg.strict_mode and cfg.ledger_commit_required and cfg.require_ledger),
                )

            # Opportunistic outbox flush (budgeted + sampled)
            if not disconnected and self.outbox is not None and self.ledger is not None:
                rem = self._remaining_ms(deadline)
                if rem is None or rem >= int(cfg.outbox_flush_min_remaining_ms):
                    if random.random() < float(cfg.outbox_flush_sample_rate):
                        with contextlib.suppress(Exception):
                            await self.outbox_flush_ledger_budget(
                                deadline_mono=deadline,
                                budget_ms=min(int(cfg.outbox_flush_budget_ms), int(rem) if rem is not None else int(cfg.outbox_flush_budget_ms)),
                                max_items=int(cfg.outbox_flush_max_items),
                            )

            verdict_label = "allow" if out.verdict else "block"
            status_label = "ok"
            status_code_for_log = 200
            return out

        except HTTPException as he:
            # classify status label for metrics
            sc = int(he.status_code)
            status_code_for_log = sc
            if sc in (HTTP_400_BAD_REQUEST, HTTP_401_UNAUTHORIZED, HTTP_413_REQUEST_ENTITY_TOO_LARGE, HTTP_429_TOO_MANY_REQUESTS, HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE, HTTP_415_UNSUPPORTED_MEDIA_TYPE):
                status_label = "rejected"
                verdict_label = "reject"
            else:
                status_label = "error"
                verdict_label = "error"
            raise
        except Exception as e:
            _REQ_ERROR.labels(route, "unhandled").inc()
            status_label = "error"
            verdict_label = "error"
            status_code_for_log = 500
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail=self._error_detail(request, kind=ERR_INTERNAL, message="internal error", extra={"err": _safe_text(e, max_len=96)}),
            )
        finally:
            dur = time.perf_counter() - t0

            # Metrics (exactly once)
            _REQ_LATENCY.labels(route, verdict_label if verdict_label else "error", auth_mode_label).observe(dur)
            _REQ_TOTAL.labels(route, status_label).inc()

            # SLA breach observation (strict): no failure, just signal
            if cfg.strict_mode and cfg.max_end_to_end_latency_s and dur > float(cfg.max_end_to_end_latency_s):
                _REQ_ERROR.labels(route, "latency_sla").inc()
                logger.warning(
                    "api_v1 diagnose SLA exceeded: dur=%.3fs limit=%.3fs rid=%s eid=%s",
                    dur,
                    float(cfg.max_end_to_end_latency_s),
                    _safe_text(rid, max_len=96),
                    _safe_text(eid, max_len=96),
                )

            # Structured request log (safe + low-cardinality)
            if cfg.log_requests:
                try:
                    log_obj = {
                        "msg": "api_v1_diagnose",
                        "route": route,
                        "request_id": _safe_text(rid, max_len=96),
                        "event_id": _safe_text(eid, max_len=96),
                        "status": status_label,
                        "status_code": int(status_code_for_log),
                        "verdict": verdict_label,
                        "dur_ms": round(dur * 1000.0, 3),
                        "auth_mode": auth_mode_label,
                        "node_id": self.node_id,
                        "proc_id": self.proc_id,
                        "outbox_depth": None,
                        "outbox_oldest_age_s": None,
                    }
                    if self.outbox is not None:
                        with contextlib.suppress(Exception):
                            st = self.outbox.stats(kind="ledger", now_ts=time.time())
                            log_obj["outbox_depth"] = int(st.get("total", 0))
                            log_obj["outbox_oldest_age_s"] = round(float(st.get("oldest_age_s", 0.0)), 3)
                    logger.info("%s", _canonical_json(log_obj))
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# Factories + default module-level router
# ---------------------------------------------------------------------------

def create_v1_service(
    *,
    cfg: Optional[ApiV1Config] = None,
    controller: Optional[Any] = None,
    authenticator: Optional[Any] = None,
    attestor: Optional[Any] = None,
    attestor_cfg: Optional[Any] = None,
    ledger: Optional[Any] = None,
    outbox: Optional[_SQLiteOutbox] = None,
) -> ApiV1Service:
    """
    Full dependency injection factory (L7 testable).
    """
    cfg2 = cfg if cfg is not None else _build_cfg_from_env()

    # Build optional deps from env if not injected (keeps compatibility)
    auth_obj = authenticator
    if auth_obj is None and build_authenticator_from_env is not None:
        with contextlib.suppress(Exception):
            auth_obj = build_authenticator_from_env()

    att_cfg = attestor_cfg
    att_obj = attestor
    if att_obj is None and AttestorConfig is not None and Attestor is not None:
        with contextlib.suppress(Exception):
            att_cfg = AttestorConfig(
                attestor_id="tcd-api-v1",
                proc_id=cfg2.proc_id or None,
                strict_mode=cfg2.strict_mode,
                default_auth_policy=None,
                default_chain_policy=None,
                default_ledger_policy=None,
                default_cfg_digest=_compute_cfg_digest(cfg2),
            )
            att_obj = Attestor(cfg=att_cfg)

    led_obj = ledger
    if led_obj is None and AuditLedger is not None:
        with contextlib.suppress(Exception):
            led_obj = AuditLedger()

    svc = ApiV1Service(
        cfg=cfg2,
        controller=controller,
        authenticator=auth_obj,
        attestor=att_obj,
        attestor_cfg=att_cfg,
        ledger=led_obj,
        outbox=outbox,
    )
    return svc


def create_v1_router(**kwargs: Any) -> APIRouter:
    """
    Convenience factory returning an APIRouter. For lifecycle hooks, keep the service.
    """
    return create_v1_service(**kwargs).router


# Default global service/router for backwards compatibility
_DEFAULT_SERVICE = create_v1_service()
router = _DEFAULT_SERVICE.router


# Optional hooks for app lifespan integration
async def startup() -> None:
    await _DEFAULT_SERVICE.startup()


async def shutdown() -> None:
    await _DEFAULT_SERVICE.shutdown()