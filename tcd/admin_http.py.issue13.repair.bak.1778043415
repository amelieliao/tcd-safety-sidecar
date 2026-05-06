from __future__ import annotations

"""
Admin-only HTTP surface for policies, verification, receipt access, and runtime
introspection.

Platform-level hardening goals (Definition of Done / DoD)

A) SLO / Budgets (quantifiable; exported via /admin/dod)
- Endpoint classes:
  - Light: /livez /readyz /healthz /runtime /policies /config
  - Heavy: /verify/receipt /verify/chain /receipts/ingest* /receipts/tail
- Latency budgets (defaults; tune via env):
  - Light: p95 <= light_p95_ms, p99 <= light_p99_ms
  - Heavy: p95 <= heavy_p95_ms, p99 <= heavy_p99_ms (bucketed by payload size)
- CPU / wall budget:
  - Heavy verify endpoints enforce a hard wall-time budget (optional subprocess kill).
- Memory budget:
  - Request body bounded even if Content-Length missing.
  - Rate-limit bucket capped + evict; metrics for cap/evict.
- Throughput budget:
  - Per-instance token-bucket rate limiting + heavy in-flight concurrency gating.

B) Consistency semantics (declared via /admin/dod)
- Policies/config: process-local atomic swap; multi-instance propagation is best-effort unless
  you use an external coordinator (out of scope here).
- Receipt store: idempotent writes enforced at the control-plane boundary (no silent overwrite).
  Ordering of tail/page is "storage-view" unless your storage guarantees stronger ordering.
- Audit ledger: declared at-least-once with deterministic event_id for dedupe.

C) Operational failure model
- liveness vs readiness split: /livez is process-only; /readyz checks hard deps.
- Dependency calls have timeout + circuit breaker; fast-fail when unhealthy.
- Error taxonomy: unified JSON envelope across all failures.

Receipt-first upgrades (inference receipt GTM)
- /receipts/ingest and /receipts/ingest_chain: verify-then-store (optional), idempotent writes,
  and explicit conflict on overwrite attempts.
- Optional cursor pagination if storage supports it.
"""

import concurrent.futures
import hmac
import ipaddress
import json
import logging
import multiprocessing
import os
import secrets
import threading
import time
from dataclasses import dataclass, asdict, is_dataclass
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Protocol, Set, Tuple

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.routing import APIRouter
from pydantic import BaseModel, Field, conlist, field_validator, model_validator

from .config import make_reloadable_settings
from .crypto import Blake3Hash
from .policies import BoundPolicy, PolicyRule, PolicyStore
from .verify import verify_chain, verify_receipt

__all__ = [
    "AdminContext",
    "ReceiptStorageProtocol",
    "create_admin_app",
    "ReloadRequest",
    "PolicySet",
    "BindContext",
    "BoundOut",
    "VerifyReceiptIn",
    "VerifyChainIn",
    "VerifyOut",
    "ReceiptGetOut",
    "ReceiptTailOut",
    "AlphaOut",
    "RuntimeOut",
    # receipt-first upgrades
    "ReceiptIngestIn",
    "ReceiptIngestChainIn",
]

# Optional collaborators (kept pluggable)
try:  # pragma: no cover
    from .attest import Attestor, AttestorConfig, canonical_kv_hash
except Exception:  # pragma: no cover
    Attestor = object  # type: ignore[misc,assignment]
    AttestorConfig = None  # type: ignore[assignment]
    canonical_kv_hash = None  # type: ignore[assignment]

try:  # pragma: no cover
    from .audit import AuditLedger
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


logger = logging.getLogger("tcd.admin")

# -----------------------------------------------------------------------------
# Error taxonomy + unified envelopes
# -----------------------------------------------------------------------------


ErrorKind = Literal[
    "AUTH",
    "FORBIDDEN",
    "RATE_LIMIT",
    "PAYLOAD_TOO_LARGE",
    "BAD_REQUEST",
    "VERIFY_FAIL",
    "OVERLOADED",
    "TIMEOUT",
    "CONFLICT",
    "STORAGE_DOWN",
    "LEDGER_DOWN",
    "ATTESTOR_DOWN",
    "SHUTTING_DOWN",
    "INTERNAL",
]


def _now_ms() -> int:
    return int(time.time() * 1000)


def _rid(req: Request) -> str:
    return (
        getattr(getattr(req, "state", object()), "tcd_request_id", None)
        or (req.headers.get("X-Request-Id") or req.headers.get("x-request-id") or "").strip()
        or f"r-{time.time_ns()}-{os.getpid()}-{secrets.token_hex(4)}"
    )


def _err_body(
    *,
    kind: ErrorKind,
    message: str,
    req: Request,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "ok": False,
        "ts_ms": _now_ms(),
        "request_id": _rid(req),
        "error": {
            "kind": kind,
            "message": message,
        },
    }
    if extra:
        body["error"]["extra"] = extra
    return body


def _http_error(
    *,
    status: int,
    kind: ErrorKind,
    message: str,
    extra: Optional[Dict[str, Any]] = None,
) -> HTTPException:
    # detail is structured; handler will render in unified envelope.
    return HTTPException(status_code=int(status), detail={"kind": kind, "message": message, "extra": extra or {}})


# -----------------------------------------------------------------------------
# Protocols / Context
# -----------------------------------------------------------------------------


class ReceiptStorageProtocol(Protocol):
    """Receipt persistence interface used by admin APIs."""

    def put(self, head_hex: str, body_json: str) -> None:
        ...

    def get(self, head_hex: str) -> Optional[str]:
        ...

    def tail(self, n: int) -> List[Tuple[str, str]]:
        ...

    def stats(self) -> Dict[str, Any]:
        ...


@dataclass
class AdminContext:
    """
    Dependencies for admin endpoints.

    attestor / attestor_cfg / ledger are optional but recommended when
    strict control-plane auditing is desired.
    """

    policies: PolicyStore
    storage: Optional[ReceiptStorageProtocol] = None
    attestor: Optional[Attestor] = None
    attestor_cfg: Optional[Any] = None
    ledger: Optional[Any] = None
    runtime_stats_fn: Optional[Callable[[], Dict[str, Any]]] = None
    alpha_probe_fn: Optional[Callable[[str, str, str], Optional[Dict[str, Any]]]] = None


# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------


@dataclass
class AdminAppConfig:
    """
    Security and behavior knobs for the admin HTTP surface.
    """

    api_version: str = "0.10.3"
    enable_docs: bool = False

    # Request-level guards
    max_body_bytes: int = 1 * 1024 * 1024
    max_json_depth: int = 128  # approximate JSON nesting cap (top-level request JSON)

    # Chain payload bounds (platform-level DoS closure)
    max_chain_items: int = 2000
    max_chain_head_bytes: int = 130
    max_chain_body_bytes_each: int = 128 * 1024
    max_chain_total_bytes: int = 8 * 1024 * 1024

    # Token-bucket rate limiting (process-local)
    rps_per_key: float = 10.0
    burst_per_key: int = 20
    bucket_max_entries: int = 50_000
    bucket_idle_seconds: float = 900.0  # idle eviction window (monotonic seconds)

    # Rate limit costs (heavier endpoints consume more tokens)
    cost_default: float = 1.0
    cost_mutation: float = 2.0
    cost_verify_receipt: float = 2.0
    cost_verify_chain: float = 5.0
    cost_receipt_ingest: float = 3.0

    # Endpoint concurrency isolation (per instance)
    max_inflight_verify_receipt: int = 8
    max_inflight_verify_chain: int = 2
    max_inflight_ingest: int = 4
    max_inflight_ingest_chain: int = 2

    # Hard wall-time budgets (ms) for heavy CPU endpoints
    verify_receipt_timeout_ms: int = 2500
    verify_chain_timeout_ms: int = 6000
    hard_timeout_mode: Literal["none", "process"] = "process"  # "process" enables kill-on-timeout

    # Dependency timeouts (ms) + circuit breaker
    dep_timeout_storage_ms: int = 800
    dep_timeout_ledger_ms: int = 800
    dep_timeout_attestor_ms: int = 1200
    breaker_failures: int = 5
    breaker_open_seconds: float = 15.0

    # Auth profile
    strict_mode: bool = False
    require_token: bool = True
    allow_no_auth: bool = False

    # Token maturity: rotation + revoke + scopes (optional)
    # - TCD_ADMIN_TOKEN (legacy) + TCD_ADMIN_TOKENS (comma)
    # - TCD_ADMIN_TOKENS_JSON (JSON list of {"token": "...", "scopes": [...]})
    # - TCD_ADMIN_REVOKED_TOKENS (comma)
    enforce_scopes: bool = False  # when true: mutations require "write", reads require "read"

    # mTLS header mode (for deployments terminating TLS upstream)
    require_mtls_header: bool = False
    mtls_verify_header: str = "X-SSL-Client-Verify"
    mtls_verify_value: str = "SUCCESS"

    # IP allowlist (supports CIDR)
    ip_allowlist: Tuple[str, ...] = ()
    trust_proxy_headers: bool = False
    trusted_proxy_cidrs: Tuple[str, ...] = ()

    require_mfa_header: bool = False
    require_approval_header: bool = False
    require_principal_header: bool = False  # recommended in strict_mode

    # Internal authorization and change governance
    require_change_ticket_header: bool = False
    require_reason_header: bool = False
    approval_system_allowlist: Optional[List[str]] = None
    allowed_principals: Optional[List[str]] = None
    forbidden_actions: Optional[List[str]] = None

    # Attestor / ledger / PQ integration
    attestation_enabled: bool = True
    require_attestor: bool = True
    require_ledger: bool = True
    require_pq_attestor: bool = False
    allowed_sig_algs: Optional[List[str]] = None

    # Verify-key lifecycle (allow/deny by fingerprint; optional)
    verify_key_allowlist: Optional[List[str]] = None  # fingerprints/prefixes
    verify_key_denylist: Optional[List[str]] = None   # fingerprints/prefixes

    # Supply-chain anchors
    node_id: str = ""
    proc_id: str = ""
    supply_chain_label: str = ""
    image_digest: str = ""
    build_id: str = ""

    # Read-path auditing
    audit_read_endpoints: bool = False

    # Policy safety
    max_policy_rules: int = 5000

    # DoD (documented budgets; not enforced here except heavy timeouts/gates)
    light_p95_ms: int = 50
    light_p99_ms: int = 200
    heavy_p95_ms: int = 600
    heavy_p99_ms: int = 2500

    # Shutdown behavior
    shutdown_grace_seconds: float = 10.0

    def digest_material(self) -> Dict[str, Any]:
        """
        Stable material used for the admin config digest. This is referenced
        from receipts / ledger for supply-chain style auditing.
        """
        return {
            "api_version": self.api_version,
            "enable_docs": bool(self.enable_docs),
            "max_body_bytes": int(self.max_body_bytes),
            "max_json_depth": int(self.max_json_depth),
            "max_chain_items": int(self.max_chain_items),
            "max_chain_head_bytes": int(self.max_chain_head_bytes),
            "max_chain_body_bytes_each": int(self.max_chain_body_bytes_each),
            "max_chain_total_bytes": int(self.max_chain_total_bytes),
            "rps_per_key": float(self.rps_per_key),
            "burst_per_key": int(self.burst_per_key),
            "bucket_max_entries": int(self.bucket_max_entries),
            "bucket_idle_seconds": float(self.bucket_idle_seconds),
            "cost_default": float(self.cost_default),
            "cost_mutation": float(self.cost_mutation),
            "cost_verify_receipt": float(self.cost_verify_receipt),
            "cost_verify_chain": float(self.cost_verify_chain),
            "cost_receipt_ingest": float(self.cost_receipt_ingest),
            "max_inflight_verify_receipt": int(self.max_inflight_verify_receipt),
            "max_inflight_verify_chain": int(self.max_inflight_verify_chain),
            "max_inflight_ingest": int(self.max_inflight_ingest),
            "max_inflight_ingest_chain": int(self.max_inflight_ingest_chain),
            "verify_receipt_timeout_ms": int(self.verify_receipt_timeout_ms),
            "verify_chain_timeout_ms": int(self.verify_chain_timeout_ms),
            "hard_timeout_mode": self.hard_timeout_mode,
            "dep_timeout_storage_ms": int(self.dep_timeout_storage_ms),
            "dep_timeout_ledger_ms": int(self.dep_timeout_ledger_ms),
            "dep_timeout_attestor_ms": int(self.dep_timeout_attestor_ms),
            "breaker_failures": int(self.breaker_failures),
            "breaker_open_seconds": float(self.breaker_open_seconds),
            "strict_mode": bool(self.strict_mode),
            "require_token": bool(self.require_token),
            "allow_no_auth": bool(self.allow_no_auth),
            "enforce_scopes": bool(self.enforce_scopes),
            "require_mtls_header": bool(self.require_mtls_header),
            "mtls_verify_header": self.mtls_verify_header,
            "mtls_verify_value": self.mtls_verify_value,
            "ip_allowlist": list(self.ip_allowlist),
            "trust_proxy_headers": bool(self.trust_proxy_headers),
            "trusted_proxy_cidrs": list(self.trusted_proxy_cidrs),
            "require_mfa_header": bool(self.require_mfa_header),
            "require_approval_header": bool(self.require_approval_header),
            "require_principal_header": bool(self.require_principal_header),
            "require_change_ticket_header": bool(self.require_change_ticket_header),
            "require_reason_header": bool(self.require_reason_header),
            "approval_system_allowlist": list(self.approval_system_allowlist or []),
            "allowed_principals": list(self.allowed_principals or []),
            "forbidden_actions": list(self.forbidden_actions or []),
            "audit_read_endpoints": bool(self.audit_read_endpoints),
            "attestation_enabled": bool(self.attestation_enabled),
            "require_attestor": bool(self.require_attestor),
            "require_ledger": bool(self.require_ledger),
            "require_pq_attestor": bool(self.require_pq_attestor),
            "allowed_sig_algs": list(self.allowed_sig_algs or []),
            "verify_key_allowlist": list(self.verify_key_allowlist or []),
            "verify_key_denylist": list(self.verify_key_denylist or []),
            "max_policy_rules": int(self.max_policy_rules),
            "light_p95_ms": int(self.light_p95_ms),
            "light_p99_ms": int(self.light_p99_ms),
            "heavy_p95_ms": int(self.heavy_p95_ms),
            "heavy_p99_ms": int(self.heavy_p99_ms),
            "shutdown_grace_seconds": float(self.shutdown_grace_seconds),
            "node_id": self.node_id,
            "proc_id": self.proc_id,
            "supply_chain_label": self.supply_chain_label,
            "image_digest": self.image_digest,
            "build_id": self.build_id,
        }


def _split_env_list(name: str) -> List[str]:
    raw = os.getenv(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except Exception:
        return int(default)


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except Exception:
        return float(default)


_ADMIN_CFG = AdminAppConfig(
    api_version=os.getenv("TCD_ADMIN_API_VERSION", "0.10.3"),
    enable_docs=os.getenv("TCD_ADMIN_ENABLE_DOCS", "0") == "1",
    max_body_bytes=_env_int("TCD_ADMIN_MAX_BODY_BYTES", 1 * 1024 * 1024),
    max_json_depth=_env_int("TCD_ADMIN_MAX_JSON_DEPTH", 128),
    max_chain_items=_env_int("TCD_ADMIN_MAX_CHAIN_ITEMS", 2000),
    max_chain_head_bytes=_env_int("TCD_ADMIN_MAX_CHAIN_HEAD_BYTES", 130),
    max_chain_body_bytes_each=_env_int("TCD_ADMIN_MAX_CHAIN_BODY_EACH", 128 * 1024),
    max_chain_total_bytes=_env_int("TCD_ADMIN_MAX_CHAIN_TOTAL_BYTES", 8 * 1024 * 1024),
    rps_per_key=_env_float("TCD_ADMIN_RPS", 10.0),
    burst_per_key=_env_int("TCD_ADMIN_BURST", 20),
    bucket_max_entries=_env_int("TCD_ADMIN_BUCKET_MAX_ENTRIES", 50_000),
    bucket_idle_seconds=_env_float("TCD_ADMIN_BUCKET_IDLE_SECONDS", 900.0),
    cost_default=_env_float("TCD_ADMIN_COST_DEFAULT", 1.0),
    cost_mutation=_env_float("TCD_ADMIN_COST_MUTATION", 2.0),
    cost_verify_receipt=_env_float("TCD_ADMIN_COST_VERIFY_RECEIPT", 2.0),
    cost_verify_chain=_env_float("TCD_ADMIN_COST_VERIFY_CHAIN", 5.0),
    cost_receipt_ingest=_env_float("TCD_ADMIN_COST_RECEIPT_INGEST", 3.0),
    max_inflight_verify_receipt=_env_int("TCD_ADMIN_MAX_INFLIGHT_VERIFY_RECEIPT", 8),
    max_inflight_verify_chain=_env_int("TCD_ADMIN_MAX_INFLIGHT_VERIFY_CHAIN", 2),
    max_inflight_ingest=_env_int("TCD_ADMIN_MAX_INFLIGHT_INGEST", 4),
    max_inflight_ingest_chain=_env_int("TCD_ADMIN_MAX_INFLIGHT_INGEST_CHAIN", 2),
    verify_receipt_timeout_ms=_env_int("TCD_ADMIN_VERIFY_RECEIPT_TIMEOUT_MS", 2500),
    verify_chain_timeout_ms=_env_int("TCD_ADMIN_VERIFY_CHAIN_TIMEOUT_MS", 6000),
    hard_timeout_mode=os.getenv("TCD_ADMIN_HARD_TIMEOUT_MODE", "process").strip().lower() in ("process", "1", "true", "yes") and "process" or "none",
    dep_timeout_storage_ms=_env_int("TCD_ADMIN_DEP_TIMEOUT_STORAGE_MS", 800),
    dep_timeout_ledger_ms=_env_int("TCD_ADMIN_DEP_TIMEOUT_LEDGER_MS", 800),
    dep_timeout_attestor_ms=_env_int("TCD_ADMIN_DEP_TIMEOUT_ATTESTOR_MS", 1200),
    breaker_failures=_env_int("TCD_ADMIN_BREAKER_FAILURES", 5),
    breaker_open_seconds=_env_float("TCD_ADMIN_BREAKER_OPEN_SECONDS", 15.0),
    strict_mode=os.getenv("TCD_ADMIN_STRICT_MODE", "0") == "1",
    require_token=True,
    allow_no_auth=os.getenv("TCD_ADMIN_ALLOW_NO_AUTH", "0") == "1",
    enforce_scopes=os.getenv("TCD_ADMIN_ENFORCE_SCOPES", "0") == "1",
    require_mtls_header=os.getenv("TCD_ADMIN_REQUIRE_MTLS_HEADER", "0") == "1",
    mtls_verify_header=os.getenv("TCD_ADMIN_MTLS_VERIFY_HEADER", "X-SSL-Client-Verify"),
    mtls_verify_value=os.getenv("TCD_ADMIN_MTLS_VERIFY_VALUE", "SUCCESS"),
    ip_allowlist=tuple(_split_env_list("TCD_ADMIN_IP_ALLOWLIST")),
    trust_proxy_headers=os.getenv("TCD_ADMIN_TRUST_PROXY_HEADERS", "0") == "1",
    trusted_proxy_cidrs=tuple(_split_env_list("TCD_ADMIN_TRUSTED_PROXY_CIDRS")),
    require_mfa_header=os.getenv("TCD_ADMIN_REQUIRE_MFA", "0") == "1",
    require_approval_header=os.getenv("TCD_ADMIN_REQUIRE_APPROVAL", "0") == "1",
    require_principal_header=os.getenv("TCD_ADMIN_REQUIRE_PRINCIPAL", "0") == "1",
    require_change_ticket_header=os.getenv("TCD_ADMIN_REQUIRE_CHANGE_TICKET", "0") == "1",
    require_reason_header=os.getenv("TCD_ADMIN_REQUIRE_REASON", "0") == "1",
    approval_system_allowlist=_split_env_list("TCD_ADMIN_APPROVAL_SYSTEMS") or None,
    allowed_principals=_split_env_list("TCD_ADMIN_ALLOWED_PRINCIPALS") or None,
    forbidden_actions=_split_env_list("TCD_ADMIN_FORBIDDEN_ACTIONS") or None,
    attestation_enabled=os.getenv("TCD_ADMIN_ATTESTATION_ENABLED", "1") == "1",
    require_attestor=os.getenv("TCD_ADMIN_REQUIRE_ATTESTOR", "1") == "1",
    require_ledger=os.getenv("TCD_ADMIN_REQUIRE_LEDGER", "1") == "1",
    require_pq_attestor=os.getenv("TCD_ADMIN_REQUIRE_PQ_ATTESTOR", "0") == "1",
    allowed_sig_algs=_split_env_list("TCD_ADMIN_ALLOWED_SIG_ALGS") or None,
    verify_key_allowlist=_split_env_list("TCD_ADMIN_VERIFY_KEY_ALLOWLIST") or None,
    verify_key_denylist=_split_env_list("TCD_ADMIN_VERIFY_KEY_DENYLIST") or None,
    node_id=os.getenv("TCD_ADMIN_NODE_ID", ""),
    proc_id=os.getenv("TCD_ADMIN_PROC_ID", ""),
    supply_chain_label=os.getenv("TCD_ADMIN_SUPPLY_CHAIN_LABEL", ""),
    image_digest=os.getenv("TCD_ADMIN_IMAGE_DIGEST", ""),
    build_id=os.getenv("TCD_ADMIN_BUILD_ID", ""),
    audit_read_endpoints=os.getenv("TCD_ADMIN_AUDIT_READS", "0") == "1",
    max_policy_rules=_env_int("TCD_ADMIN_MAX_POLICY_RULES", 5000),
    light_p95_ms=_env_int("TCD_ADMIN_LIGHT_P95_MS", 50),
    light_p99_ms=_env_int("TCD_ADMIN_LIGHT_P99_MS", 200),
    heavy_p95_ms=_env_int("TCD_ADMIN_HEAVY_P95_MS", 600),
    heavy_p99_ms=_env_int("TCD_ADMIN_HEAVY_P99_MS", 2500),
    shutdown_grace_seconds=_env_float("TCD_ADMIN_SHUTDOWN_GRACE_SECONDS", 10.0),
)

_SETTINGS_HOT = make_reloadable_settings()
_ADMIN_LOCK = threading.RLock()

# Config digest for supply-chain anchoring
_cfg_hasher = Blake3Hash()
try:
    cfg_material = _ADMIN_CFG.digest_material()
    if canonical_kv_hash is not None:
        _ADMIN_CFG_DIGEST = canonical_kv_hash(cfg_material, ctx="tcd:admin_cfg", label="tcd_admin_cfg")
    else:
        blob = json.dumps(cfg_material, sort_keys=True).encode("utf-8")
        _ADMIN_CFG_DIGEST = _cfg_hasher.hex(blob, ctx="tcd:admin_cfg")
except Exception:
    _ADMIN_CFG_DIGEST = "admin_cfg:" + repr(_ADMIN_CFG.digest_material())

# -----------------------------------------------------------------------------
# Auth: token registry (rotation/revocation/scopes) + optional mTLS header gate
# -----------------------------------------------------------------------------

# Legacy single token (still supported).
_ADMIN_TOKEN_LEGACY = (os.environ.get("TCD_ADMIN_TOKEN") or "").strip()

_TOKEN_CACHE_LOCK = threading.Lock()
_TOKEN_CACHE_TS = 0.0
_TOKEN_CACHE_TTL_S = 2.0  # cheap; allows rapid revoke/rotate via env reload in orchestrators
_TOKEN_CACHE: Dict[str, Set[str]] = {}


def _parse_tokens_json(raw: str) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    if not raw:
        return out
    try:
        val = json.loads(raw)
    except Exception:
        return out
    if isinstance(val, list):
        for item in val:
            if isinstance(item, str):
                tok = item.strip()
                if tok:
                    out[tok] = {"read", "write", "verify", "danger"}
            elif isinstance(item, dict):
                tok = str(item.get("token") or "").strip()
                if not tok:
                    continue
                scopes_raw = item.get("scopes")
                scopes: Set[str] = set()
                if isinstance(scopes_raw, list):
                    for s in scopes_raw:
                        if isinstance(s, str) and s.strip():
                            scopes.add(s.strip().lower())
                if not scopes:
                    scopes = {"read", "write", "verify", "danger"}
                out[tok] = scopes
    return out


def _load_token_scopes() -> Dict[str, Set[str]]:
    """
    Loads token allowlist + scopes from env.
    Supports rotation by listing multiple tokens and revocation by denylisting.
    """
    toks: Dict[str, Set[str]] = {}

    # JSON form (preferred for scopes)
    toks.update(_parse_tokens_json(os.getenv("TCD_ADMIN_TOKENS_JSON", "").strip()))

    # Comma list form
    for t in _split_env_list("TCD_ADMIN_TOKENS"):
        toks.setdefault(t, {"read", "write", "verify", "danger"})

    # Legacy single token
    if _ADMIN_TOKEN_LEGACY:
        toks.setdefault(_ADMIN_TOKEN_LEGACY, {"read", "write", "verify", "danger"})

    # Revocations
    revoked = set(_split_env_list("TCD_ADMIN_REVOKED_TOKENS"))
    for r in revoked:
        toks.pop(r, None)

    return toks


def _get_token_scopes(token: str) -> Optional[Set[str]]:
    global _TOKEN_CACHE_TS, _TOKEN_CACHE
    now = time.monotonic()
    with _TOKEN_CACHE_LOCK:
        if (now - _TOKEN_CACHE_TS) > _TOKEN_CACHE_TTL_S or not _TOKEN_CACHE:
            _TOKEN_CACHE = _load_token_scopes()
            _TOKEN_CACHE_TS = now
        return _TOKEN_CACHE.get(token)


def _require_mtls(req: Request) -> None:
    if not _ADMIN_CFG.require_mtls_header:
        return
    header = _ADMIN_CFG.mtls_verify_header
    want = _ADMIN_CFG.mtls_verify_value
    got = (req.headers.get(header) or "").strip()
    if got != want:
        raise _http_error(status=403, kind="FORBIDDEN", message="mTLS verification required")


def _require_scope(req: Request, needed: str) -> None:
    if not _ADMIN_CFG.enforce_scopes:
        return
    scopes: Set[str] = set(getattr(getattr(req, "state", object()), "tcd_admin_scopes", set()) or set())
    if needed not in scopes:
        raise _http_error(status=403, kind="FORBIDDEN", message=f"missing required scope: {needed}")


def _require_admin(req: Request, token: Optional[str] = Header(default=None, alias="X-TCD-Admin-Token")) -> None:
    """
    Minimal header token auth with rotation/revocation/scopes.

    In strict_mode, a valid admin token is always required.
    When allow_no_auth is enabled and strict_mode is off, the token may be omitted (local/dev only).

    Also supports optional upstream mTLS verification headers.
    """
    _require_mtls(req)

    token = (token or "").strip()
    scopes = _get_token_scopes(token) if token else None

    if not scopes:
        # No configured tokens -> handle strict/dev behavior.
        if not _TOKEN_CACHE and not _ADMIN_TOKEN_LEGACY:
            # If strict requires token, fail.
            if _ADMIN_CFG.strict_mode and _ADMIN_CFG.require_token:
                raise _http_error(status=401, kind="AUTH", message="admin token required")
            # Dev allow
            if _ADMIN_CFG.allow_no_auth and not _ADMIN_CFG.strict_mode:
                req.state.tcd_admin_scopes = {"read", "write", "verify", "danger"}  # type: ignore[attr-defined]
                return
            raise _http_error(status=401, kind="AUTH", message="admin token required")

        # Tokens exist, but this token missing/invalid.
        if not token:
            raise _http_error(status=401, kind="AUTH", message="admin token required")
        raise _http_error(status=403, kind="FORBIDDEN", message="forbidden")

    # Attach scopes for downstream checks (optional enforcement).
    try:
        req.state.tcd_admin_scopes = scopes  # type: ignore[attr-defined]
        req.state.tcd_admin_token_ok = True  # type: ignore[attr-defined]
    except Exception:
        pass


# -----------------------------------------------------------------------------
# IP allowlist helpers (supports CIDR) + proxy header trust
# -----------------------------------------------------------------------------


def _parse_ip_entries(entries: Iterable[str]) -> Tuple[Set[str], List[Any]]:
    exact: Set[str] = set()
    nets: List[Any] = []
    for raw in entries:
        val = (raw or "").strip()
        if not val:
            continue
        try:
            if "/" in val:
                nets.append(ipaddress.ip_network(val, strict=False))
            else:
                ipaddress.ip_address(val)
                exact.add(val)
        except Exception:
            logger.warning("Invalid IP/CIDR entry ignored: %r", val)
    return exact, nets


_ADMIN_IP_ALLOW_EXACT, _ADMIN_IP_ALLOW_NETS = _parse_ip_entries(_ADMIN_CFG.ip_allowlist)
_TRUST_PROXY_EXACT, _TRUST_PROXY_NETS = _parse_ip_entries(_ADMIN_CFG.trusted_proxy_cidrs)


def _ip_matches(ip: str, exact: Set[str], nets: List[Any]) -> bool:
    if not ip:
        return False
    if ip in exact:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except Exception:
        return False
    for net in nets:
        try:
            if addr in net:
                return True
        except Exception:
            continue
    return False


def _resolve_client_ip(req: Request) -> str:
    """
    Resolve client IP with an optional trusted-proxy mode.

    By default, does NOT trust X-Forwarded-For / Forwarded.
    If trust_proxy_headers is enabled, it only trusts proxy headers when the
    direct peer IP is in trusted_proxy_cidrs.
    """
    peer_ip = (req.client.host if req.client else "") or ""
    if not _ADMIN_CFG.trust_proxy_headers:
        return peer_ip

    if not _ip_matches(peer_ip, _TRUST_PROXY_EXACT, _TRUST_PROXY_NETS):
        return peer_ip

    xff = req.headers.get("X-Forwarded-For") or req.headers.get("x-forwarded-for")
    if xff:
        first = (xff.split(",")[0] or "").strip()
        try:
            ipaddress.ip_address(first)
            return first
        except Exception:
            return peer_ip

    fwd = req.headers.get("Forwarded") or req.headers.get("forwarded")
    if fwd:
        parts = [p.strip() for p in fwd.split(";")]
        for p in parts:
            if p.lower().startswith("for="):
                val = p.split("=", 1)[1].strip().strip('"')
                if val.startswith("[") and val.endswith("]"):
                    val = val[1:-1]
                try:
                    ipaddress.ip_address(val)
                    return val
                except Exception:
                    break

    return peer_ip


def _require_ip_allowlist(client_ip: str) -> None:
    if not _ADMIN_CFG.ip_allowlist:
        return
    if not _ip_matches(client_ip, _ADMIN_IP_ALLOW_EXACT, _ADMIN_IP_ALLOW_NETS):
        raise _http_error(status=403, kind="FORBIDDEN", message="ip not allowed")


# -----------------------------------------------------------------------------
# Metrics
# -----------------------------------------------------------------------------

_ADMIN_REQ_LATENCY = Histogram(
    "tcd_admin_request_latency_ms",
    "Latency of admin HTTP requests (ms)",
    buckets=(1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000),
    labelnames=("path", "method", "status"),
)
_ADMIN_REQ_TOTAL = Counter(
    "tcd_admin_request_total",
    "Total admin HTTP requests",
    labelnames=("path", "method", "status"),
)
_ADMIN_REQ_ERROR = Counter(
    "tcd_admin_request_error_total",
    "Errors in admin HTTP handlers",
    labelnames=("path", "method", "kind"),
)
_ADMIN_RATE_LIMIT_REJECT = Counter(
    "tcd_admin_rate_limit_reject_total",
    "Rate-limited admin HTTP requests",
    labelnames=("key",),  # coarse "token" | "ip" | "dev"
)
_ADMIN_RATE_BUCKETS = Gauge(
    "tcd_admin_rate_limit_bucket_count",
    "Number of live rate limit buckets (process-local)",
)
_ADMIN_RATE_EVICT_TOTAL = Counter(
    "tcd_admin_rate_limit_bucket_evict_total",
    "Rate limit bucket evictions",
)
_ADMIN_MUTATION_AUDIT_ERROR = Counter(
    "tcd_admin_mutation_audit_error_total",
    "Failures when auditing admin operations",
    labelnames=("action", "kind"),
)

_ADMIN_HEAVY_INFLIGHT = Gauge(
    "tcd_admin_heavy_inflight",
    "Current in-flight heavy operations",
    labelnames=("group",),
)
_ADMIN_HEAVY_REJECT = Counter(
    "tcd_admin_heavy_reject_total",
    "Heavy operation rejections",
    labelnames=("group", "reason"),
)

_ADMIN_DEP_LATENCY = Histogram(
    "tcd_admin_dependency_latency_ms",
    "Latency of dependency calls (ms)",
    buckets=(1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000),
    labelnames=("dep", "op", "status"),
)
_ADMIN_DEP_ERROR = Counter(
    "tcd_admin_dependency_error_total",
    "Dependency call errors",
    labelnames=("dep", "op", "kind"),
)
_ADMIN_BREAKER_OPEN = Gauge(
    "tcd_admin_dependency_breaker_open",
    "Circuit breaker open state (1=open, 0=closed)",
    labelnames=("dep",),
)

# -----------------------------------------------------------------------------
# Dependency timeouts + circuit breaker
# -----------------------------------------------------------------------------


class _CircuitBreaker:
    __slots__ = ("name", "failures", "opened_until", "threshold", "open_seconds", "_lock")

    def __init__(self, name: str, threshold: int, open_seconds: float) -> None:
        self.name = name
        self.failures = 0
        self.opened_until = 0.0
        self.threshold = max(1, int(threshold))
        self.open_seconds = max(0.1, float(open_seconds))
        self._lock = threading.Lock()

    def allow(self) -> bool:
        now = time.monotonic()
        with self._lock:
            if self.opened_until and now < self.opened_until:
                return False
            return True

    def record_success(self) -> None:
        with self._lock:
            self.failures = 0
            self.opened_until = 0.0

    def record_failure(self) -> None:
        now = time.monotonic()
        with self._lock:
            self.failures += 1
            if self.failures >= self.threshold:
                self.opened_until = now + self.open_seconds

    def is_open(self) -> bool:
        now = time.monotonic()
        with self._lock:
            return bool(self.opened_until and now < self.opened_until)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "failures": int(self.failures),
                "open": bool(self.opened_until and time.monotonic() < self.opened_until),
                "opened_until_mono": float(self.opened_until),
                "threshold": int(self.threshold),
                "open_seconds": float(self.open_seconds),
            }


_DEP_EXECUTOR = concurrent.futures.ThreadPoolExecutor(
    max_workers=max(4, _env_int("TCD_ADMIN_DEP_EXECUTOR_WORKERS", 8)),
    thread_name_prefix="tcd-admin-dep",
)

_STORAGE_BREAKER = _CircuitBreaker("storage", _ADMIN_CFG.breaker_failures, _ADMIN_CFG.breaker_open_seconds)
_LEDGER_BREAKER = _CircuitBreaker("ledger", _ADMIN_CFG.breaker_failures, _ADMIN_CFG.breaker_open_seconds)
_ATTESTOR_BREAKER = _CircuitBreaker("attestor", _ADMIN_CFG.breaker_failures, _ADMIN_CFG.breaker_open_seconds)


def _dep_call(
    *,
    dep: Literal["storage", "ledger", "attestor"],
    op: str,
    timeout_ms: int,
    breaker: _CircuitBreaker,
    fn: Callable[[], Any],
    err_kind: ErrorKind,
    err_message: str,
) -> Any:
    if not breaker.allow():
        _ADMIN_BREAKER_OPEN.labels(dep).set(1.0)
        _ADMIN_DEP_ERROR.labels(dep, op, "breaker_open").inc()
        raise _http_error(status=503, kind=err_kind, message=f"{dep} unavailable (breaker open)")

    _ADMIN_BREAKER_OPEN.labels(dep).set(0.0)

    t0 = time.perf_counter()
    fut = _DEP_EXECUTOR.submit(fn)
    try:
        res = fut.result(timeout=max(0.001, float(timeout_ms) / 1000.0))
        dt = (time.perf_counter() - t0) * 1000.0
        _ADMIN_DEP_LATENCY.labels(dep, op, "ok").observe(dt)
        breaker.record_success()
        return res
    except concurrent.futures.TimeoutError:
        dt = (time.perf_counter() - t0) * 1000.0
        _ADMIN_DEP_LATENCY.labels(dep, op, "timeout").observe(dt)
        _ADMIN_DEP_ERROR.labels(dep, op, "timeout").inc()
        breaker.record_failure()
        raise _http_error(status=503, kind=err_kind, message=f"{err_message} (timeout)")
    except HTTPException:
        dt = (time.perf_counter() - t0) * 1000.0
        _ADMIN_DEP_LATENCY.labels(dep, op, "http").observe(dt)
        breaker.record_failure()
        raise
    except Exception as e:
        dt = (time.perf_counter() - t0) * 1000.0
        _ADMIN_DEP_LATENCY.labels(dep, op, "error").observe(dt)
        _ADMIN_DEP_ERROR.labels(dep, op, "error").inc()
        breaker.record_failure()
        logger.warning("dep call failed dep=%s op=%s err=%s", dep, op, e, exc_info=True)
        raise _http_error(status=503, kind=err_kind, message=err_message)


# -----------------------------------------------------------------------------
# Heavy endpoint concurrency isolation
# -----------------------------------------------------------------------------


class _HeavyGate:
    __slots__ = ("group", "limit", "_sema", "_inflight", "_lock")

    def __init__(self, group: str, limit: int) -> None:
        self.group = group
        self.limit = max(1, int(limit))
        self._sema = threading.BoundedSemaphore(self.limit)
        self._inflight = 0
        self._lock = threading.Lock()
        _ADMIN_HEAVY_INFLIGHT.labels(group).set(0.0)

    def try_acquire(self) -> bool:
        ok = self._sema.acquire(blocking=False)
        if ok:
            with self._lock:
                self._inflight += 1
                _ADMIN_HEAVY_INFLIGHT.labels(self.group).set(float(self._inflight))
        return ok

    def release(self) -> None:
        try:
            with self._lock:
                self._inflight = max(0, self._inflight - 1)
                _ADMIN_HEAVY_INFLIGHT.labels(self.group).set(float(self._inflight))
        finally:
            try:
                self._sema.release()
            except Exception:
                # bounded semaphore could throw if released too often; ignore.
                pass

    def inflight(self) -> int:
        with self._lock:
            return int(self._inflight)


# -----------------------------------------------------------------------------
# Token-bucket rate limiting (process-local, DoS-safe, evicting)
# -----------------------------------------------------------------------------


class _TokenBucket:
    __slots__ = ("capacity", "rate", "tokens", "updated", "_lock")

    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = max(0.1, float(rate))
        self.capacity = max(1, int(capacity))
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()
        self._lock = threading.Lock()

    def allow(self, cost: float = 1.0) -> bool:
        cost = max(0.0, float(cost))
        if cost <= 0.0:
            return True
        with self._lock:
            now = time.monotonic()
            delta = max(0.0, now - self.updated)
            self.updated = now
            self.tokens = min(self.capacity, self.tokens + delta * self.rate)
            if self.tokens >= cost:
                self.tokens -= cost
                return True
            return False


_BUCKETS: Dict[str, _TokenBucket] = {}
_BUCKETS_LOCK = threading.Lock()
_BUCKET_EVICT_COUNTER = 0


def _hash_bucket_key(raw: str) -> str:
    try:
        h = Blake3Hash()
        return h.hex(raw.encode("utf-8", errors="ignore"), ctx="tcd:admin:rl:key")[:24]
    except Exception:
        return str(abs(hash(raw)))


def _bucket_evict_if_needed(now_mono: float) -> None:
    global _BUCKET_EVICT_COUNTER
    _BUCKET_EVICT_COUNTER += 1

    max_entries = int(_ADMIN_CFG.bucket_max_entries)
    idle_s = float(_ADMIN_CFG.bucket_idle_seconds)
    if max_entries <= 0:
        return

    # amortize eviction work
    if (_BUCKET_EVICT_COUNTER % 256) != 0 and len(_BUCKETS) < max_entries:
        _ADMIN_RATE_BUCKETS.set(float(len(_BUCKETS)))
        return

    evicted = 0

    # 1) evict idle
    if idle_s > 0.0:
        to_delete: List[str] = []
        for k, b in _BUCKETS.items():
            try:
                if (now_mono - float(b.updated)) > idle_s:
                    to_delete.append(k)
            except Exception:
                continue
        for k in to_delete:
            if _BUCKETS.pop(k, None) is not None:
                evicted += 1

    # 2) evict oldest if still too many
    if len(_BUCKETS) > max_entries:
        ordered = sorted(_BUCKETS.items(), key=lambda kv: getattr(kv[1], "updated", 0.0))
        excess = len(_BUCKETS) - max_entries
        for i in range(excess):
            if _BUCKETS.pop(ordered[i][0], None) is not None:
                evicted += 1
        if excess > 0:
            logger.warning("admin rate-limit bucket cap reached; evicted=%d", excess)

    if evicted:
        _ADMIN_RATE_EVICT_TOTAL.inc(float(evicted))
    _ADMIN_RATE_BUCKETS.set(float(len(_BUCKETS)))


def _rate_limit_cost(req: Request) -> float:
    path = req.url.path
    method = req.method.upper()
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        if path.endswith("/verify/chain"):
            return float(_ADMIN_CFG.cost_verify_chain)
        if path.endswith("/verify/receipt"):
            return float(_ADMIN_CFG.cost_verify_receipt)
        if "/receipts/ingest" in path:
            return float(_ADMIN_CFG.cost_receipt_ingest)
        if path.endswith("/policies") or path.endswith("/policies/reload") or path.endswith("/config/reload"):
            return float(_ADMIN_CFG.cost_mutation)
    return float(_ADMIN_CFG.cost_default)


# -----------------------------------------------------------------------------
# Request body bounded streaming + JSON depth guard
# -----------------------------------------------------------------------------


def _scan_json_max_depth(data: bytes, max_depth: int) -> int:
    """
    Approximate max nesting depth of JSON data by scanning brackets/braces,
    ignoring content inside strings.

    This is a defense against extremely deep JSON that can DoS parsers.
    """
    if max_depth <= 0:
        return 0

    depth = 0
    max_seen = 0
    in_str = False
    esc = False

    for b in data:
        c = chr(b)
        if in_str:
            if esc:
                esc = False
                continue
            if c == "\\":
                esc = True
                continue
            if c == '"':
                in_str = False
            continue

        if c == '"':
            in_str = True
            continue
        if c in "{[":
            depth += 1
            if depth > max_seen:
                max_seen = depth
                if max_seen > max_depth:
                    return max_seen
        elif c in "}]":
            depth = max(0, depth - 1)

    return max_seen


async def _read_body_bounded(req: Request, max_bytes: int) -> bytes:
    """
    Stream the request body up to max_bytes and cache it into req._body so downstream
    parsing (pydantic) can still work. This prevents >2x memory spikes for large bodies.
    """
    # If already cached by something, reuse.
    cached = getattr(req, "_body", None)
    if cached is not None:
        if isinstance(cached, (bytes, bytearray)):
            if len(cached) > max_bytes:
                raise _http_error(status=413, kind="PAYLOAD_TOO_LARGE", message="payload too large")
            return bytes(cached)

    buf = bytearray()
    size = 0
    async for chunk in req.stream():
        if not chunk:
            continue
        size += len(chunk)
        if size > max_bytes:
            raise _http_error(status=413, kind="PAYLOAD_TOO_LARGE", message="payload too large")
        buf.extend(chunk)

    body = bytes(buf)
    try:
        req._body = body  # type: ignore[attr-defined]
    except Exception:
        pass
    return body


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------


def _dump_cfg(obj: Any) -> Dict[str, Any]:
    if hasattr(obj, "model_dump"):
        return dict(obj.model_dump())  # pydantic v2
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, dict):
        return obj
    try:
        return {k: v for k, v in vars(obj).items() if not k.startswith("_")}
    except Exception:
        return {}


def _is_hex(s: Optional[str]) -> bool:
    if not s:
        return True
    s = s.strip()
    if s.startswith(("0x", "0X")):
        s = s[2:]
    if len(s) % 2 != 0:
        return False
    try:
        bytes.fromhex(s)
        return True
    except Exception:
        return False


def _canonicalize_hex(s: str) -> str:
    s = (s or "").strip()
    had_prefix = s.startswith(("0x", "0X"))
    s2 = s[2:] if had_prefix else s
    s2 = s2.strip().lower()
    return ("0x" + s2) if had_prefix else s2


def _alt_hex_forms(s: str) -> List[str]:
    s = (s or "").strip()
    if not s:
        return [s]
    forms: List[str] = []
    canon = _canonicalize_hex(s)
    forms.append(canon)
    forms.append(canon[2:] if canon.startswith("0x") else ("0x" + canon))
    if s not in forms:
        forms.append(s)
    return list(dict.fromkeys(forms))


def _key_fingerprint_hex(key_hex: str) -> str:
    """
    Fingerprint a verify key (hex) using BLAKE3 over raw bytes.
    """
    key_hex = (key_hex or "").strip()
    if key_hex.startswith(("0x", "0X")):
        key_hex = key_hex[2:]
    raw = bytes.fromhex(key_hex) if key_hex else b""
    h = Blake3Hash()
    return h.hex(raw, ctx="tcd:verify_key")


def _fingerprint_matches_list(fp: str, items: Optional[List[str]]) -> bool:
    """
    items may contain full fingerprints or prefixes.
    """
    if not items:
        return False
    for it in items:
        it = (it or "").strip().lower()
        if not it:
            continue
        if fp.lower().startswith(it):
            return True
    return False


def _enforce_verify_key_policy(verify_key_hex: Optional[str]) -> None:
    if not verify_key_hex:
        return
    if not _is_hex(verify_key_hex):
        raise _http_error(status=400, kind="BAD_REQUEST", message="invalid verify_key_hex")
    fp = _key_fingerprint_hex(verify_key_hex)
    if _ADMIN_CFG.verify_key_denylist and _fingerprint_matches_list(fp, _ADMIN_CFG.verify_key_denylist):
        raise _http_error(status=403, kind="FORBIDDEN", message="verify key revoked/denied")
    if _ADMIN_CFG.verify_key_allowlist and not _fingerprint_matches_list(fp, _ADMIN_CFG.verify_key_allowlist):
        raise _http_error(status=403, kind="FORBIDDEN", message="verify key not allowed")


# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------


class ReloadRequest(BaseModel):
    source: Literal["env", "file"] = "env"
    path: Optional[str] = None


class PolicySet(BaseModel):
    rules: List[PolicyRule] = Field(default_factory=list)

    @field_validator("rules")
    @classmethod
    def _limit_rules(cls, v: List[PolicyRule]) -> List[PolicyRule]:
        max_rules = int(getattr(_ADMIN_CFG, "max_policy_rules", 5000))
        if max_rules > 0 and len(v) > max_rules:
            raise ValueError(f"too many policy rules (max={max_rules})")
        return v


class BindContext(BaseModel):
    tenant: str = "*"
    user: str = "*"
    session: str = "*"
    model_id: str = "*"
    gpu_id: str = "*"
    task: str = "*"
    lang: str = "*"


class BoundOut(BaseModel):
    name: str
    version: str
    policy_ref: str
    priority: int
    detector_cfg: Dict[str, Any]
    av_cfg: Dict[str, Any]
    routing: Dict[str, Any]
    enable_receipts: bool
    enable_verify_metrics: bool
    slo_latency_ms: Optional[float]
    token_cost_divisor: float
    match: Dict[str, str]


_MAX_BODY_JSON = 128 * 1024  # single receipt body json (string) bound


class VerifyReceiptIn(BaseModel):
    head_hex: str = Field(..., min_length=2, max_length=130)
    body_json: str = Field(..., min_length=2, max_length=_MAX_BODY_JSON)
    sig_hex: Optional[str] = Field(default=None, max_length=200)
    verify_key_hex: Optional[str] = Field(default=None, max_length=4000)  # allow larger keys, bounded by request size
    req_obj: Optional[Dict[str, Any]] = None
    comp_obj: Optional[Dict[str, Any]] = None
    e_obj: Optional[Dict[str, Any]] = None
    witness_segments: Optional[Tuple[List[int], List[int], List[int]]] = None
    label_salt_hex: Optional[str] = Field(default=None, max_length=130)
    strict: bool = True

    @field_validator("head_hex", "sig_hex", "verify_key_hex", "label_salt_hex")
    @classmethod
    def _hex_ok(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _is_hex(v):
            raise ValueError("invalid hex")
        return v


class VerifyChainIn(BaseModel):
    heads: conlist(str, min_length=1, max_length=2000)  # type: ignore[arg-type]
    bodies: conlist(str, min_length=1, max_length=2000)  # type: ignore[arg-type]
    label_salt_hex: Optional[str] = Field(default=None, max_length=130)

    @field_validator("heads")
    @classmethod
    def _heads_hex_and_len(cls, v: List[str]) -> List[str]:
        max_head = int(_ADMIN_CFG.max_chain_head_bytes)
        for x in v:
            if len(x) > max_head:
                raise ValueError("head too long")
            if not _is_hex(x):
                raise ValueError("invalid head hex in list")
        return v

    @field_validator("bodies")
    @classmethod
    def _bodies_each_len(cls, v: List[str]) -> List[str]:
        max_each = int(_ADMIN_CFG.max_chain_body_bytes_each)
        for b in v:
            if len(b) > max_each:
                raise ValueError("body too large (each)")
        return v

    @field_validator("label_salt_hex")
    @classmethod
    def _salt_hex(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _is_hex(v):
            raise ValueError("invalid hex")
        return v

    @model_validator(mode="after")
    def _total_bytes_and_lengths(self) -> "VerifyChainIn":
        if len(self.heads) != len(self.bodies):
            raise ValueError("heads and bodies length mismatch")
        total = sum(len(b) for b in self.bodies)
        if total > int(_ADMIN_CFG.max_chain_total_bytes):
            raise ValueError("chain total bytes too large")
        if len(self.heads) > int(_ADMIN_CFG.max_chain_items):
            raise ValueError("chain too long")
        return self


class VerifyOut(BaseModel):
    ok: bool
    latency_ms: float


class ReceiptGetOut(BaseModel):
    head_hex: str
    body_json: Optional[str] = None
    found: bool


class ReceiptTailOut(BaseModel):
    items: List[Tuple[str, str]]
    total: int


class AlphaOut(BaseModel):
    tenant: str
    user: str
    session: str
    state: Optional[Dict[str, Any]] = None


class RuntimeOut(BaseModel):
    version: str
    config_hash: str
    settings: Dict[str, Any]
    stats: Dict[str, Any]


# Receipt-first upgrades ------------------------------------------------------


class ReceiptIngestIn(BaseModel):
    head_hex: str = Field(..., min_length=2, max_length=130)
    body_json: str = Field(..., min_length=2, max_length=_MAX_BODY_JSON)
    sig_hex: Optional[str] = Field(default=None, max_length=200)
    verify_key_hex: Optional[str] = Field(default=None, max_length=4000)
    label_salt_hex: Optional[str] = Field(default=None, max_length=130)
    strict: bool = True
    verify_before_store: bool = True

    @field_validator("head_hex", "sig_hex", "verify_key_hex", "label_salt_hex")
    @classmethod
    def _hex_ok(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _is_hex(v):
            raise ValueError("invalid hex")
        return v


class ReceiptIngestChainIn(BaseModel):
    heads: conlist(str, min_length=1, max_length=2000)  # type: ignore[arg-type]
    bodies: conlist(str, min_length=1, max_length=2000)  # type: ignore[arg-type]
    label_salt_hex: Optional[str] = Field(default=None, max_length=130)
    verify_before_store: bool = True

    @field_validator("heads")
    @classmethod
    def _heads_hex_and_len(cls, v: List[str]) -> List[str]:
        max_head = int(_ADMIN_CFG.max_chain_head_bytes)
        for x in v:
            if len(x) > max_head:
                raise ValueError("head too long")
            if not _is_hex(x):
                raise ValueError("invalid head hex in list")
        return v

    @field_validator("bodies")
    @classmethod
    def _bodies_each_len(cls, v: List[str]) -> List[str]:
        max_each = int(_ADMIN_CFG.max_chain_body_bytes_each)
        for b in v:
            if len(b) > max_each:
                raise ValueError("body too large (each)")
        return v

    @field_validator("label_salt_hex")
    @classmethod
    def _salt_hex(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _is_hex(v):
            raise ValueError("invalid hex")
        return v

    @model_validator(mode="after")
    def _total_bytes_and_lengths(self) -> "ReceiptIngestChainIn":
        if len(self.heads) != len(self.bodies):
            raise ValueError("heads and bodies length mismatch")
        total = sum(len(b) for b in self.bodies)
        if total > int(_ADMIN_CFG.max_chain_total_bytes):
            raise ValueError("chain total bytes too large")
        if len(self.heads) > int(_ADMIN_CFG.max_chain_items):
            raise ValueError("chain too long")
        return self


# -----------------------------------------------------------------------------
# Subprocess hard timeout runner (kill-on-timeout)
# -----------------------------------------------------------------------------

# IMPORTANT: worker must be top-level for spawn mode.
def _subprocess_worker(q: Any, fn: Callable[..., Any], args: Tuple[Any, ...], kwargs: Dict[str, Any]) -> None:
    try:
        res = fn(*args, **kwargs)
        q.put({"ok": True, "res": res})
    except Exception as e:
        q.put({"ok": False, "err": repr(e)})


def _run_with_hard_timeout_process(fn: Callable[..., Any], *, args: Tuple[Any, ...], kwargs: Dict[str, Any], timeout_ms: int) -> Any:
    """
    Run a callable in a subprocess and terminate on timeout.
    Suitable for CPU-bound verification calls where we need true cancellation.

    Note: uses spawn for portability and safer semantics.
    """
    ctx = multiprocessing.get_context("spawn")
    q = ctx.Queue(maxsize=1)
    p = ctx.Process(target=_subprocess_worker, args=(q, fn, args, kwargs), daemon=True)
    p.start()
    p.join(timeout=max(0.001, float(timeout_ms) / 1000.0))
    if p.is_alive():
        try:
            p.terminate()
        finally:
            p.join(timeout=0.2)
        raise TimeoutError("hard timeout")
    try:
        msg = q.get_nowait()
    except Exception:
        raise RuntimeError("subprocess returned no result")
    if not isinstance(msg, dict) or not msg.get("ok"):
        raise RuntimeError(str(msg.get("err") if isinstance(msg, dict) else "subprocess error"))
    return msg.get("res")


# -----------------------------------------------------------------------------
# Header-based governance (strict-mode mutation controls)
# -----------------------------------------------------------------------------


def _enforce_admin_headers(req: Request, *, action: str) -> None:
    if not _ADMIN_CFG.strict_mode:
        return

    # Action deny list
    if _ADMIN_CFG.forbidden_actions and action in _ADMIN_CFG.forbidden_actions:
        raise _http_error(status=403, kind="FORBIDDEN", message="action forbidden by policy")

    headers = req.headers
    principal = (headers.get("X-TCD-Admin-Principal") or "").strip()
    approval = (headers.get("X-TCD-Admin-Approval") or "").strip()
    mfa_token = (headers.get("X-TCD-Admin-MFA", "") or "").strip()

    if _ADMIN_CFG.require_principal_header and not principal:
        raise _http_error(status=403, kind="FORBIDDEN", message="principal required")

    if _ADMIN_CFG.allowed_principals:
        if not principal:
            raise _http_error(status=403, kind="FORBIDDEN", message="principal required")
        if principal not in _ADMIN_CFG.allowed_principals:
            raise _http_error(status=403, kind="FORBIDDEN", message="principal not allowed")

    if _ADMIN_CFG.require_mfa_header:
        if mfa_token.lower() not in ("1", "true", "yes", "ok"):
            raise _http_error(status=403, kind="FORBIDDEN", message="mfa required")

    if _ADMIN_CFG.require_approval_header:
        if not approval:
            raise _http_error(status=403, kind="FORBIDDEN", message="approval required")
        if principal and approval and principal == approval:
            raise _http_error(status=403, kind="FORBIDDEN", message="approval must differ from principal")
        if _ADMIN_CFG.approval_system_allowlist:
            sys_tag = (headers.get("X-TCD-Admin-Approval-System") or "").strip()
            if sys_tag not in _ADMIN_CFG.approval_system_allowlist:
                raise _http_error(status=403, kind="FORBIDDEN", message="invalid approval system")

    if _ADMIN_CFG.require_change_ticket_header:
        ticket = (headers.get("X-TCD-Admin-Change-Ticket") or "").strip()
        if not ticket:
            raise _http_error(status=403, kind="FORBIDDEN", message="change ticket required")

    if _ADMIN_CFG.require_reason_header:
        reason = (headers.get("X-TCD-Admin-Reason") or "").strip()
        if not reason:
            raise _http_error(status=403, kind="FORBIDDEN", message="change reason required")


# -----------------------------------------------------------------------------
# Middlewares
# -----------------------------------------------------------------------------


async def _req_context_mw(req: Request, call_next: Callable) -> JSONResponse:
    start = time.perf_counter()
    path = req.url.path
    method = req.method.upper()

    rid = (req.headers.get("X-Request-Id") or req.headers.get("x-request-id") or "").strip()
    if not rid:
        rid = f"r-{time.time_ns()}-{os.getpid()}-{secrets.token_hex(4)}"

    client_ip = _resolve_client_ip(req)
    try:
        req.state.tcd_client_ip = client_ip  # type: ignore[attr-defined]
        req.state.tcd_request_id = rid        # type: ignore[attr-defined]
    except Exception:
        pass

    # Graceful shutdown gate (do not accept new work except livez)
    try:
        shutting = bool(getattr(getattr(req, "app", object()), "state", object()).shutting_down)  # type: ignore[attr-defined]
    except Exception:
        shutting = False
    if shutting and not path.endswith("/livez"):
        body = _err_body(kind="SHUTTING_DOWN", message="server shutting down", req=req)
        resp = JSONResponse(status_code=503, content=body)
        resp.headers["X-TCD-Request-Id"] = rid
        resp.headers["X-TCD-Admin-Version"] = _ADMIN_CFG.api_version
        resp.headers["X-TCD-Admin-Cfg-Digest"] = _ADMIN_CFG_DIGEST
        return resp

    # IP allowlist
    try:
        _require_ip_allowlist(client_ip)
    except HTTPException as e:
        status = e.status_code
        _ADMIN_REQ_TOTAL.labels(path, method, str(status)).inc()
        _ADMIN_REQ_LATENCY.labels(path, method, str(status)).observe(0.0)
        detail = e.detail if isinstance(e.detail, dict) else {"kind": "FORBIDDEN", "message": str(e.detail)}
        body = _err_body(kind=detail.get("kind", "FORBIDDEN"), message=detail.get("message", "forbidden"), req=req)
        resp = JSONResponse(status_code=status, content=body)
        resp.headers["X-TCD-Request-Id"] = rid
        resp.headers["X-TCD-Admin-Version"] = _ADMIN_CFG.api_version
        resp.headers["X-TCD-Admin-Cfg-Digest"] = _ADMIN_CFG_DIGEST
        return resp

    status_str = "500"
    try:
        resp = await call_next(req)
        status_str = str(resp.status_code)
    except Exception:
        _ADMIN_REQ_ERROR.labels(path, method, "handler").inc()
        logger.exception("admin request failed: path=%s method=%s rid=%s", path, method, rid)
        raise
    finally:
        dt_ms = (time.perf_counter() - start) * 1000.0
        _ADMIN_REQ_TOTAL.labels(path, method, status_str).inc()
        _ADMIN_REQ_LATENCY.labels(path, method, status_str).observe(dt_ms)
        logger.info(
            "admin.req path=%s method=%s rid=%s status=%s dt_ms=%.3f ip=%s",
            path,
            method,
            rid,
            status_str,
            dt_ms,
            client_ip,
        )

    # Attach standard headers
    resp.headers["X-TCD-Request-Id"] = rid
    resp.headers["X-TCD-Admin-Version"] = _ADMIN_CFG.api_version
    resp.headers["X-TCD-Admin-Cfg-Digest"] = _ADMIN_CFG_DIGEST
    return resp  # type: ignore[return-value]


async def _size_guard_mw(req: Request, call_next: Callable) -> JSONResponse:
    max_bytes = int(_ADMIN_CFG.max_body_bytes)

    # Fast-path content-length
    cl = req.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > max_bytes:
                body = _err_body(kind="PAYLOAD_TOO_LARGE", message="payload too large", req=req)
                return JSONResponse(status_code=413, content=body)
        except Exception:
            body = _err_body(kind="BAD_REQUEST", message="invalid content-length", req=req)
            return JSONResponse(status_code=400, content=body)

    # Stream bounded for payload methods
    if req.method.upper() in ("POST", "PUT", "PATCH"):
        try:
            body_bytes = await _read_body_bounded(req, max_bytes)
        except HTTPException as e:
            detail = e.detail if isinstance(e.detail, dict) else {"kind": "PAYLOAD_TOO_LARGE", "message": str(e.detail)}
            body = _err_body(kind=detail.get("kind", "PAYLOAD_TOO_LARGE"), message=detail.get("message", "payload too large"), req=req)
            return JSONResponse(status_code=e.status_code, content=body)

        # JSON depth guard (approx, only for JSON-ish content types)
        ctype = (req.headers.get("content-type") or "").lower()
        if "application/json" in ctype or ctype.endswith("+json"):
            max_depth = int(_ADMIN_CFG.max_json_depth)
            if max_depth > 0:
                d = _scan_json_max_depth(body_bytes, max_depth)
                if d > max_depth:
                    body = _err_body(
                        kind="BAD_REQUEST",
                        message="json nesting too deep",
                        req=req,
                        extra={"max_depth": max_depth, "seen": d},
                    )
                    return JSONResponse(status_code=400, content=body)

    return await call_next(req)


async def _rate_limit_mw(req: Request, call_next: Callable) -> JSONResponse:
    client_ip = getattr(getattr(req, "state", object()), "tcd_client_ip", None) or _resolve_client_ip(req)

    token = (req.headers.get("X-TCD-Admin-Token") or "").strip()
    principal = (req.headers.get("X-TCD-Admin-Principal") or "").strip()

    # Determine if token is valid without leaking token material into keys.
    scopes = _get_token_scopes(token) if token else None
    token_ok = bool(scopes)

    if token_ok:
        raw_key = f"p:{principal}" if principal and len(principal) <= 128 else "t:admin"
        kind = "token"
    else:
        raw_key = f"ip:{client_ip}"
        kind = "dev" if (_ADMIN_CFG.allow_no_auth and not _ADMIN_CFG.strict_mode) else "ip"

    bucket_key = f"{kind}:{_hash_bucket_key(raw_key)}"
    cost = _rate_limit_cost(req)

    now_mono = time.monotonic()
    with _BUCKETS_LOCK:
        _bucket_evict_if_needed(now_mono)
        bucket = _BUCKETS.get(bucket_key)
        if bucket is None:
            bucket = _TokenBucket(rate=_ADMIN_CFG.rps_per_key, capacity=_ADMIN_CFG.burst_per_key)
            _BUCKETS[bucket_key] = bucket

    if not bucket.allow(cost=cost):
        _ADMIN_RATE_LIMIT_REJECT.labels(kind).inc()
        body = _err_body(kind="RATE_LIMIT", message="rate limit exceeded", req=req, extra={"retry_after_s": 1})
        return JSONResponse(status_code=429, content=body, headers={"Retry-After": "1"})

    return await call_next(req)


# -----------------------------------------------------------------------------
# Factory
# -----------------------------------------------------------------------------


def create_admin_app(ctx: AdminContext) -> FastAPI:
    """
    Build an admin-only FastAPI app.
    All routes mounted under /admin/* and protected by _require_admin.
    """
    # Strict startup checks
    if _ADMIN_CFG.strict_mode:
        if _ADMIN_CFG.attestation_enabled and _ADMIN_CFG.require_attestor and ctx.attestor is None:
            raise RuntimeError("AdminApp strict_mode requires an Attestor instance")
        if _ADMIN_CFG.require_ledger and ctx.ledger is None:
            raise RuntimeError("AdminApp strict_mode requires a ledger")
        if _ADMIN_CFG.attestation_enabled and _ADMIN_CFG.require_pq_attestor:
            if ctx.attestor_cfg is None:
                raise RuntimeError("AdminApp strict_mode requires AttestorConfig for PQ attestor")
            sig_alg = getattr(ctx.attestor_cfg, "sig_alg", None)
            if not sig_alg:
                raise RuntimeError("AdminApp strict_mode requires sig_alg on AttestorConfig")
            if _ADMIN_CFG.allowed_sig_algs and sig_alg not in _ADMIN_CFG.allowed_sig_algs:
                raise RuntimeError(f"Admin Attestor sig_alg {sig_alg!r} not in allowed_sig_algs")
        if _ADMIN_CFG.attestation_enabled and _ADMIN_CFG.allowed_sig_algs and ctx.attestor_cfg is None:
            raise RuntimeError("AdminApp strict_mode with allowed_sig_algs requires AttestorConfig")

    openapi_url = "/openapi.json" if _ADMIN_CFG.enable_docs else None
    docs_url = "/docs" if _ADMIN_CFG.enable_docs else None
    redoc_url = "/redoc" if _ADMIN_CFG.enable_docs else None

    app = FastAPI(
        title="tcd-admin",
        version=_ADMIN_CFG.api_version,
        openapi_url=openapi_url,
        docs_url=docs_url,
        redoc_url=redoc_url,
    )

    # App state for shutdown control
    app.state.shutting_down = False
    app.state.started_at_ms = _now_ms()

    # Exception handlers -> unified envelopes
    @app.exception_handler(HTTPException)
    async def _http_exc_handler(request: Request, exc: HTTPException) -> JSONResponse:
        detail = exc.detail
        if isinstance(detail, dict) and "kind" in detail and "message" in detail:
            kind = detail.get("kind", "INTERNAL")
            msg = detail.get("message", "error")
            extra = detail.get("extra") if isinstance(detail.get("extra"), dict) else None
        else:
            # Map by status
            if exc.status_code == 401:
                kind, msg, extra = "AUTH", "unauthorized", None
            elif exc.status_code == 403:
                kind, msg, extra = "FORBIDDEN", "forbidden", None
            elif exc.status_code == 413:
                kind, msg, extra = "PAYLOAD_TOO_LARGE", "payload too large", None
            elif exc.status_code == 429:
                kind, msg, extra = "RATE_LIMIT", "rate limit exceeded", None
            elif exc.status_code == 409:
                kind, msg, extra = "CONFLICT", "conflict", None
            elif exc.status_code == 503:
                kind, msg, extra = "OVERLOADED", "service unavailable", None
            else:
                kind, msg, extra = "BAD_REQUEST", str(detail), None
        body = _err_body(kind=kind, message=msg, req=request, extra=extra)
        return JSONResponse(status_code=exc.status_code, content=body)

    @app.exception_handler(Exception)
    async def _unhandled_exc_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled admin exception rid=%s", _rid(request))
        body = _err_body(kind="INTERNAL", message="internal error", req=request)
        return JSONResponse(status_code=500, content=body)

    # Middlewares (outermost first)
    app.middleware("http")(_req_context_mw)
    app.middleware("http")(_size_guard_mw)
    app.middleware("http")(_rate_limit_mw)

    # Graceful shutdown: stop accepting new requests then drain heavy in-flight (best effort)
    @app.on_event("shutdown")
    def _on_shutdown() -> None:
        try:
            app.state.shutting_down = True
        except Exception:
            pass
        # Nothing else global; gates will be created below and drained via counters.
        # (We can't block too long in shutdown hook in some servers, but best effort.)
        return

    router = APIRouter(prefix="/admin", dependencies=[Depends(_require_admin)])

    # Gates (per instance)
    gate_verify_receipt = _HeavyGate("verify_receipt", _ADMIN_CFG.max_inflight_verify_receipt)
    gate_verify_chain = _HeavyGate("verify_chain", _ADMIN_CFG.max_inflight_verify_chain)
    gate_ingest = _HeavyGate("receipt_ingest", _ADMIN_CFG.max_inflight_ingest)
    gate_ingest_chain = _HeavyGate("receipt_ingest_chain", _ADMIN_CFG.max_inflight_ingest_chain)

    hasher = Blake3Hash()

    # Cache only the latest policy digest (bounded, avoids leaks)
    _policy_cache_lock = threading.Lock()
    _policy_cache_key: Optional[Tuple[str, ...]] = None
    _policy_cache_digest: Optional[str] = None

    def _policy_digest(rules: List[PolicyRule]) -> str:
        nonlocal _policy_cache_key, _policy_cache_digest
        try:
            key = tuple((r.policy_ref() if hasattr(r, "policy_ref") else repr(r)) for r in rules)
            with _policy_cache_lock:
                if _policy_cache_key == key and _policy_cache_digest:
                    return _policy_cache_digest
            canon = {"rules": [r.model_dump() for r in rules], "version": "1"}
            data = json.dumps(canon, sort_keys=True).encode("utf-8")
            digest = hasher.hex(data, ctx="tcd:policyset")
            with _policy_cache_lock:
                _policy_cache_key = key
                _policy_cache_digest = digest
            return digest
        except Exception as e:  # pragma: no cover
            logger.exception("policy digest failed: %s", e)
            return "0" * 64

    def _current_config_hash() -> str:
        try:
            return _SETTINGS_HOT.get().config_hash()
        except Exception:
            return ""

    def _current_policyset_ref() -> str:
        try:
            with _ADMIN_LOCK:
                rules = ctx.policies.rules()
            digest = _policy_digest(rules)
            return f"set@1#{digest[:12]}"
        except Exception:
            return ""

    def _record_event(
        *,
        action: str,
        req: Request,
        ok: bool,
        started_at: float,
        details: Optional[Dict[str, Any]] = None,
        require_attestation: bool,
        require_ledger: bool,
    ) -> None:
        """
        Record an admin event into attestation and ledger.

        For platform safety, you can require these sinks under strict_mode for mutations.
        """
        duration_ms = (time.perf_counter() - started_at) * 1000.0
        meta_details: Dict[str, Any] = dict(details or {})
        meta_details.setdefault("ok", bool(ok))
        meta_details.setdefault("duration_ms", float(duration_ms))
        meta_details.setdefault("admin_cfg_digest", _ADMIN_CFG_DIGEST)
        meta_details.setdefault("path", str(req.url.path))
        meta_details.setdefault("method", str(req.method))
        meta_details.setdefault("config_hash", _current_config_hash())
        meta_details.setdefault("policyset_ref", _current_policyset_ref())

        principal = (req.headers.get("X-TCD-Admin-Principal") or "").strip()
        approval = (req.headers.get("X-TCD-Admin-Approval") or "").strip()
        mfa_raw = (req.headers.get("X-TCD-Admin-MFA", "") or "").strip()
        mfa_verified = mfa_raw.lower() in ("1", "true", "yes", "ok")

        event_id = f"{action}:{_rid(req)}"

        # Attestation
        if ctx.attestor is not None and _ADMIN_CFG.attestation_enabled:
            try:
                def _issue() -> Dict[str, Any]:
                    req_obj: Dict[str, Any] = {
                        "path": str(req.url.path),
                        "method": str(req.method),
                        "client": getattr(getattr(req, "state", object()), "tcd_client_ip", None) or (req.client.host if req.client else None),
                        "headers": {"principal": principal, "mfa": mfa_verified, "approval": approval},
                        "request_id": _rid(req),
                    }
                    comp_obj: Dict[str, Any] = {
                        "component": "tcd-admin",
                        "action": action,
                        "api_version": _ADMIN_CFG.api_version,
                        "admin_cfg_digest": _ADMIN_CFG_DIGEST,
                        "node_id": _ADMIN_CFG.node_id,
                        "proc_id": _ADMIN_CFG.proc_id,
                        "supply_chain_label": _ADMIN_CFG.supply_chain_label,
                        "image_digest": _ADMIN_CFG.image_digest,
                        "build_id": _ADMIN_CFG.build_id,
                        "event_id": event_id,
                    }
                    e_obj: Dict[str, Any] = {
                        "decision": "success" if ok else "failure",
                        "duration_ms": float(duration_ms),
                        "error": None if ok else "failure",
                        "action": action,
                        "event_id": event_id,
                        "config_hash": meta_details.get("config_hash", ""),
                        "policyset_ref": meta_details.get("policyset_ref", ""),
                    }

                    segments: List[Dict[str, Any]] = [
                        {"kind": "admin_cfg", "id": "tcd_admin", "digest": _ADMIN_CFG_DIGEST, "meta": {}}
                    ]
                    if ctx.ledger is not None and hasattr(ctx.ledger, "head"):
                        try:
                            segments.append(
                                {"kind": "admin_ledger_head", "id": "tcd_admin", "digest": ctx.ledger.head(), "meta": {}}
                            )
                        except Exception:
                            logger.warning("admin ledger head read failed for attestation", exc_info=True)

                    if ctx.attestor_cfg is not None:
                        cfg_digest = getattr(ctx.attestor_cfg, "default_cfg_digest", None)
                        if cfg_digest:
                            segments.append({"kind": "system_cfg", "id": "tcd_system", "digest": cfg_digest, "meta": {}})

                    tags = ["tcd_admin", action]
                    meta_block: Dict[str, Any] = {
                        "ok": bool(ok),
                        "admin_cfg_digest": _ADMIN_CFG_DIGEST,
                        "node_id": _ADMIN_CFG.node_id,
                        "proc_id": _ADMIN_CFG.proc_id,
                        "supply_chain_label": _ADMIN_CFG.supply_chain_label,
                        "event_id": event_id,
                    }
                    if ctx.attestor_cfg is not None and hasattr(ctx.attestor_cfg, "policy_digest"):
                        try:
                            meta_block["attestor_policy_digest"] = ctx.attestor_cfg.policy_digest()
                        except Exception:
                            logger.warning("admin attestor policy_digest failed", exc_info=True)

                    return ctx.attestor.issue(  # type: ignore[call-arg]
                        req_obj=req_obj,
                        comp_obj=comp_obj,
                        e_obj=e_obj,
                        witness_segments=segments,
                        witness_tags=tags,
                        meta=meta_block,
                    )

                att = _dep_call(
                    dep="attestor",
                    op="issue",
                    timeout_ms=_ADMIN_CFG.dep_timeout_attestor_ms,
                    breaker=_ATTESTOR_BREAKER,
                    fn=_issue,
                    err_kind="ATTESTOR_DOWN",
                    err_message="attestor unavailable",
                )
                meta_details["receipt"] = att.get("receipt") if isinstance(att, dict) else None
                meta_details["verify_key"] = att.get("verify_key") if isinstance(att, dict) else None
            except HTTPException:
                _ADMIN_MUTATION_AUDIT_ERROR.labels(action, "attestation").inc()
                if require_attestation:
                    raise
            except Exception:
                _ADMIN_MUTATION_AUDIT_ERROR.labels(action, "attestation").inc()
                if require_attestation:
                    raise _http_error(status=503, kind="ATTESTOR_DOWN", message="attestation failed")

        # Ledger
        if ctx.ledger is not None and hasattr(ctx.ledger, "append"):
            try:
                def _append() -> None:
                    evt: Dict[str, Any] = {
                        "kind": "admin_event",
                        "event_id": event_id,
                        "ts_ns": time.time_ns(),
                        "action": action,
                        "ok": bool(ok),
                        "duration_ms": float(duration_ms),
                        "admin_cfg_digest": _ADMIN_CFG_DIGEST,
                        "node_id": _ADMIN_CFG.node_id,
                        "proc_id": _ADMIN_CFG.proc_id,
                        "supply_chain_label": _ADMIN_CFG.supply_chain_label,
                        "image_digest": _ADMIN_CFG.image_digest,
                        "build_id": _ADMIN_CFG.build_id,
                        "principal": principal,
                        "mfa_verified": mfa_verified,
                        "approval": approval,
                        "details": meta_details,
                    }
                    if ctx.attestor_cfg is not None and hasattr(ctx.attestor_cfg, "policy_digest"):
                        try:
                            evt["attestor_policy_digest"] = ctx.attestor_cfg.policy_digest()
                        except Exception:
                            logger.warning("admin ledger attestor policy_digest failed", exc_info=True)
                    ctx.ledger.append(evt)

                _dep_call(
                    dep="ledger",
                    op="append",
                    timeout_ms=_ADMIN_CFG.dep_timeout_ledger_ms,
                    breaker=_LEDGER_BREAKER,
                    fn=_append,
                    err_kind="LEDGER_DOWN",
                    err_message="ledger unavailable",
                )
            except HTTPException:
                _ADMIN_MUTATION_AUDIT_ERROR.labels(action, "ledger").inc()
                if require_ledger:
                    raise
            except Exception:
                _ADMIN_MUTATION_AUDIT_ERROR.labels(action, "ledger").inc()
                if require_ledger:
                    raise _http_error(status=503, kind="LEDGER_DOWN", message="ledger append failed")

    # ---- DoD / Semantics ----------------------------------------------------

    @router.get("/dod")
    def dod(request: Request):
        _require_scope(request, "read")
        return {
            "ok": True,
            "version": _ADMIN_CFG.api_version,
            "budgets": {
                "light": {"p95_ms": int(_ADMIN_CFG.light_p95_ms), "p99_ms": int(_ADMIN_CFG.light_p99_ms)},
                "heavy": {"p95_ms": int(_ADMIN_CFG.heavy_p95_ms), "p99_ms": int(_ADMIN_CFG.heavy_p99_ms)},
                "verify_receipt_timeout_ms": int(_ADMIN_CFG.verify_receipt_timeout_ms),
                "verify_chain_timeout_ms": int(_ADMIN_CFG.verify_chain_timeout_ms),
                "hard_timeout_mode": _ADMIN_CFG.hard_timeout_mode,
                "max_body_bytes": int(_ADMIN_CFG.max_body_bytes),
                "max_json_depth": int(_ADMIN_CFG.max_json_depth),
                "max_chain": {
                    "items": int(_ADMIN_CFG.max_chain_items),
                    "body_each_bytes": int(_ADMIN_CFG.max_chain_body_bytes_each),
                    "total_bytes": int(_ADMIN_CFG.max_chain_total_bytes),
                },
                "rate_limit": {
                    "rps_per_key": float(_ADMIN_CFG.rps_per_key),
                    "burst_per_key": int(_ADMIN_CFG.burst_per_key),
                    "semantics": "per-instance token bucket (process-local); use edge/global limiter for global semantics",
                },
            },
            "consistency": {
                "policies": "process-local atomic swap; multi-instance is best-effort unless externally coordinated",
                "receipt_store": "idempotent write at boundary; overwrite yields CONFLICT; ordering is storage-view",
                "ledger": "at-least-once with event_id for dedupe; strict_mode can require append to succeed for mutations",
            },
            "operational": {
                "livez": "process liveness only",
                "readyz": "checks hard deps (strict-mode ledger/attestor) + breaker state",
                "dependency_calls": "timeout + circuit breaker (fast fail)",
            },
        }

    # ---- Health / Ready -----------------------------------------------------

    @router.get("/livez")
    def livez():
        return {"ok": True, "ts": time.time(), "version": _ADMIN_CFG.api_version}

    @router.get("/readyz")
    def readyz(request: Request):
        _require_scope(request, "read")
        deps: Dict[str, Any] = {}

        # Settings must be readable
        try:
            s = _SETTINGS_HOT.get()
            deps["settings"] = {"ok": True, "config_hash": s.config_hash()}
        except Exception as e:
            deps["settings"] = {"ok": False, "error": repr(e)}

        # Strict hard deps
        hard_ok = True
        if _ADMIN_CFG.strict_mode:
            if _ADMIN_CFG.require_attestor and ctx.attestor is None:
                deps["attestor"] = {"ok": False, "error": "missing"}
                hard_ok = False
            if _ADMIN_CFG.require_ledger and ctx.ledger is None:
                deps["ledger"] = {"ok": False, "error": "missing"}
                hard_ok = False

        deps["breaker"] = {
            "storage": _STORAGE_BREAKER.status(),
            "ledger": _LEDGER_BREAKER.status(),
            "attestor": _ATTESTOR_BREAKER.status(),
        }

        # If strict requires ledger/attestor, breaker-open is not ready.
        if _ADMIN_CFG.strict_mode and _ADMIN_CFG.require_ledger and _LEDGER_BREAKER.is_open():
            hard_ok = False
        if _ADMIN_CFG.strict_mode and _ADMIN_CFG.attestation_enabled and _ADMIN_CFG.require_attestor and _ATTESTOR_BREAKER.is_open():
            hard_ok = False

        return {"ok": bool(hard_ok), "ts": time.time(), "deps": deps}

    @router.get("/healthz")
    def healthz(request: Request):
        _require_scope(request, "read")
        s = _SETTINGS_HOT.get()
        return {
            "ok": True,
            "ts": time.time(),
            "version": _ADMIN_CFG.api_version,
            "config_hash": s.config_hash(),
            "policyset_ref": _current_policyset_ref(),
            "admin_cfg_digest": _ADMIN_CFG_DIGEST,
        }

    # ---- Runtime ------------------------------------------------------------

    @router.get("/runtime", response_model=RuntimeOut)
    def runtime(request: Request):
        _require_scope(request, "read")
        s = _SETTINGS_HOT.get()
        stats: Dict[str, Any] = {}
        if ctx.runtime_stats_fn:
            try:
                stats = dict(ctx.runtime_stats_fn() or {})
            except Exception as e:
                logger.warning("runtime_stats_fn failed: %s", e)
                stats = {"error": "runtime_stats_fn failed"}
        # Add breaker and gate visibility
        stats.setdefault("breaker", {})
        stats["breaker"]["storage"] = _STORAGE_BREAKER.status()
        stats["breaker"]["ledger"] = _LEDGER_BREAKER.status()
        stats["breaker"]["attestor"] = _ATTESTOR_BREAKER.status()
        stats.setdefault("heavy_inflight", {})
        stats["heavy_inflight"]["verify_receipt"] = gate_verify_receipt.inflight()
        stats["heavy_inflight"]["verify_chain"] = gate_verify_chain.inflight()
        stats["heavy_inflight"]["receipt_ingest"] = gate_ingest.inflight()
        stats["heavy_inflight"]["receipt_ingest_chain"] = gate_ingest_chain.inflight()
        return RuntimeOut(
            version=_ADMIN_CFG.api_version,
            config_hash=s.config_hash(),
            settings=s.model_dump(),
            stats=stats,
        )

    # ---- Policies -----------------------------------------------------------

    @router.get("/policies", response_model=PolicySet)
    def policies_get(request: Request):
        _require_scope(request, "read")
        with _ADMIN_LOCK:
            return PolicySet(rules=ctx.policies.rules())

    @router.get("/policies/ref")
    def policies_ref(request: Request):
        _require_scope(request, "read")
        with _ADMIN_LOCK:
            rules = ctx.policies.rules()
            digest = _policy_digest(rules)
            return {
                "policyset_ref": f"set@1#{digest[:12]}",
                "rules": [r.policy_ref() for r in rules],
                "admin_cfg_digest": _ADMIN_CFG_DIGEST,
            }

    @router.put("/policies", response_model=Dict[str, Any])
    def policies_put(ps: PolicySet, request: Request):
        _require_scope(request, "write")
        started = time.perf_counter()
        _enforce_admin_headers(request, action="policies_put")

        prev_rules: Optional[List[PolicyRule]] = None
        policy_ref = ""
        count = 0
        ok = False

        try:
            with _ADMIN_LOCK:
                prev_rules = list(ctx.policies.rules())
                ctx.policies.replace_rules(ps.rules or [])
                rules = ctx.policies.rules()
                digest = _policy_digest(rules)
                policy_ref = f"set@1#{digest[:12]}"
                count = len(rules)

            ok = True

            # Strict mutations: require ledger/attestation to succeed (platform invariant)
            require_att = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.attestation_enabled and _ADMIN_CFG.require_attestor)
            require_led = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.require_ledger)

            _record_event(
                action="policies_put",
                req=request,
                ok=True,
                started_at=started,
                details={"policyset_ref": policy_ref, "policy_rule_count": count},
                require_attestation=require_att,
                require_ledger=require_led,
            )

            return {"ok": True, "policyset_ref": policy_ref, "count": count}
        except HTTPException:
            # Attempt rollback when mutation can't be fully audited in strict mode
            if _ADMIN_CFG.strict_mode and prev_rules is not None and not ok:
                try:
                    with _ADMIN_LOCK:
                        ctx.policies.replace_rules(prev_rules)
                except Exception:
                    logger.error("policies_put rollback failed", exc_info=True)
            raise
        except Exception as e:
            _ADMIN_REQ_ERROR.labels("/admin/policies", "PUT", "handler").inc()
            logger.exception("policies_put failed: %s", e)
            if _ADMIN_CFG.strict_mode and prev_rules is not None:
                try:
                    with _ADMIN_LOCK:
                        ctx.policies.replace_rules(prev_rules)
                except Exception:
                    logger.error("policies_put rollback failed", exc_info=True)
            raise _http_error(status=500, kind="INTERNAL", message="policies_put failed")

    @router.post("/policies/reload", response_model=Dict[str, Any])
    def policies_reload(req_in: ReloadRequest, request: Request):
        _require_scope(request, "write")
        started = time.perf_counter()
        _enforce_admin_headers(request, action="policies_reload")

        prev_rules: Optional[List[PolicyRule]] = None
        policy_ref = ""
        count = 0

        try:
            with _ADMIN_LOCK:
                prev_rules = list(ctx.policies.rules())
                if req_in.source == "env":
                    new_store = PolicyStore.from_env()
                else:
                    if not req_in.path:
                        raise _http_error(status=400, kind="BAD_REQUEST", message="path required when source=file")
                    new_store = PolicyStore.from_file(req_in.path)
                ctx.policies.replace_rules(new_store.rules())
                rules = ctx.policies.rules()
                digest = _policy_digest(rules)
                policy_ref = f"set@1#{digest[:12]}"
                count = len(rules)

            require_att = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.attestation_enabled and _ADMIN_CFG.require_attestor)
            require_led = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.require_ledger)

            _record_event(
                action="policies_reload",
                req=request,
                ok=True,
                started_at=started,
                details={"policyset_ref": policy_ref, "policy_rule_count": count, "source": req_in.source},
                require_attestation=require_att,
                require_ledger=require_led,
            )

            return {"ok": True, "policyset_ref": policy_ref, "count": count}
        except HTTPException:
            if _ADMIN_CFG.strict_mode and prev_rules is not None:
                try:
                    with _ADMIN_LOCK:
                        ctx.policies.replace_rules(prev_rules)
                except Exception:
                    logger.error("policies_reload rollback failed", exc_info=True)
            raise
        except Exception as e:
            _ADMIN_REQ_ERROR.labels("/admin/policies/reload", "POST", "handler").inc()
            logger.exception("policies_reload failed: %s", e)
            if _ADMIN_CFG.strict_mode and prev_rules is not None:
                try:
                    with _ADMIN_LOCK:
                        ctx.policies.replace_rules(prev_rules)
                except Exception:
                    logger.error("policies_reload rollback failed", exc_info=True)
            raise _http_error(status=500, kind="INTERNAL", message="policies_reload failed")

    @router.post("/policies/bind", response_model=BoundOut)
    def policies_bind(ctx_in: BindContext, request: Request):
        _require_scope(request, "read")
        with _ADMIN_LOCK:
            bound: BoundPolicy = ctx.policies.bind(ctx_in.model_dump())
        return BoundOut(
            name=bound.name,
            version=bound.version,
            policy_ref=bound.policy_ref,
            priority=bound.priority,
            detector_cfg=_dump_cfg(bound.detector_cfg),
            av_cfg=_dump_cfg(bound.av_cfg),
            routing={
                "t_low": bound.t_low,
                "t_high": bound.t_high,
                "top_p_low": bound.top_p_low,
                "top_p_high": bound.top_p_high,
                "fallback_decoder": bound.fallback_decoder,
            },
            enable_receipts=bound.enable_receipts,
            enable_verify_metrics=bound.enable_verify_metrics,
            slo_latency_ms=bound.slo_latency_ms,
            token_cost_divisor=bound.token_cost_divisor,
            match=bound.match,
        )

    # ---- Receipts & Verification -------------------------------------------

    @router.get("/receipts/stats")
    def receipt_stats(request: Request):
        _require_scope(request, "read")
        started = time.perf_counter()
        ok = False
        try:
            if not ctx.storage:
                ok = True
                return {"ok": True, "enabled": False, "stats": {}}

            def _stats() -> Dict[str, Any]:
                return dict(ctx.storage.stats() or {})

            stats = _dep_call(
                dep="storage",
                op="stats",
                timeout_ms=_ADMIN_CFG.dep_timeout_storage_ms,
                breaker=_STORAGE_BREAKER,
                fn=_stats,
                err_kind="STORAGE_DOWN",
                err_message="storage unavailable",
            )
            ok = True
            return {"ok": True, "enabled": True, "stats": stats}
        finally:
            if _ADMIN_CFG.audit_read_endpoints:
                try:
                    _record_event(
                        action="receipt_stats",
                        req=request,
                        ok=ok,
                        started_at=started,
                        details={"enabled": bool(ctx.storage is not None)},
                        require_attestation=False,
                        require_ledger=False,
                    )
                except Exception:
                    logger.warning("receipt_stats audit failed", exc_info=True)

    @router.get("/receipts/tail", response_model=ReceiptTailOut)
    def receipt_tail(n: int = 50, request: Request = None):  # type: ignore[assignment]
        _require_scope(request, "read")  # type: ignore[arg-type]
        started = time.perf_counter()
        ok = False
        n_eff = 0
        try:
            if not ctx.storage:
                ok = True
                return ReceiptTailOut(items=[], total=0)

            n_eff = max(1, min(1000, int(n)))

            def _tail() -> List[Tuple[str, str]]:
                return ctx.storage.tail(n_eff)

            items = _dep_call(
                dep="storage",
                op="tail",
                timeout_ms=_ADMIN_CFG.dep_timeout_storage_ms,
                breaker=_STORAGE_BREAKER,
                fn=_tail,
                err_kind="STORAGE_DOWN",
                err_message="storage unavailable",
            )
            ok = True
            return ReceiptTailOut(items=items, total=len(items))
        finally:
            if _ADMIN_CFG.audit_read_endpoints and request is not None:
                try:
                    _record_event(
                        action="receipt_tail",
                        req=request,
                        ok=ok,
                        started_at=started,
                        details={"n": int(n_eff) if n_eff else int(n)},
                        require_attestation=False,
                        require_ledger=False,
                    )
                except Exception:
                    logger.warning("receipt_tail audit failed", exc_info=True)

    def _storage_get_any(head_hex: str) -> Optional[Tuple[str, str]]:
        """
        Return (key_used, body) if found.
        """
        if not ctx.storage:
            return None
        for form in _alt_hex_forms(head_hex):
            def _get_form() -> Optional[str]:
                return ctx.storage.get(form)
            body = _dep_call(
                dep="storage",
                op="get",
                timeout_ms=_ADMIN_CFG.dep_timeout_storage_ms,
                breaker=_STORAGE_BREAKER,
                fn=_get_form,
                err_kind="STORAGE_DOWN",
                err_message="storage unavailable",
            )
            if body:
                return (form, body)
        return None

    @router.get("/receipts/{head_hex}", response_model=ReceiptGetOut)
    def receipt_get(head_hex: str, request: Request):
        _require_scope(request, "read")
        started = time.perf_counter()
        ok = False
        try:
            if not head_hex or len(head_hex) > 130 or not _is_hex(head_hex):
                raise _http_error(status=400, kind="BAD_REQUEST", message="invalid head_hex")

            if not ctx.storage:
                ok = True
                return ReceiptGetOut(head_hex=head_hex, body_json=None, found=False)

            found = _storage_get_any(head_hex)
            if found:
                ok = True
                key_used, body = found
                return ReceiptGetOut(head_hex=key_used, body_json=body, found=True)

            ok = True
            return ReceiptGetOut(head_hex=_canonicalize_hex(head_hex), body_json=None, found=False)
        finally:
            if _ADMIN_CFG.audit_read_endpoints:
                try:
                    _record_event(
                        action="receipt_get",
                        req=request,
                        ok=ok,
                        started_at=started,
                        details={"head_hex": head_hex[:16] + "..."},
                        require_attestation=False,
                        require_ledger=False,
                    )
                except Exception:
                    logger.warning("receipt_get audit failed", exc_info=True)

    @router.post("/verify/receipt", response_model=VerifyOut)
    def verify_receipt_api(payload: VerifyReceiptIn, request: Request):
        _require_scope(request, "verify")
        _enforce_verify_key_policy(payload.verify_key_hex)

        # Concurrency isolation
        if not gate_verify_receipt.try_acquire():
            _ADMIN_HEAVY_REJECT.labels("verify_receipt", "overloaded").inc()
            raise _http_error(status=503, kind="OVERLOADED", message="too many verify_receipt in-flight")
        started = time.perf_counter()
        ok = False
        try:
            t0 = time.perf_counter()
            if _ADMIN_CFG.hard_timeout_mode == "process":
                try:
                    ok = bool(
                        _run_with_hard_timeout_process(
                            verify_receipt,
                            args=(),
                            kwargs={
                                "receipt_head_hex": payload.head_hex,
                                "receipt_body_json": payload.body_json,
                                "verify_key_hex": payload.verify_key_hex,
                                "receipt_sig_hex": payload.sig_hex,
                                "req_obj": payload.req_obj,
                                "comp_obj": payload.comp_obj,
                                "e_obj": payload.e_obj,
                                "witness_segments": payload.witness_segments,
                                "strict": payload.strict,
                                "label_salt_hex": payload.label_salt_hex,
                            },
                            timeout_ms=int(_ADMIN_CFG.verify_receipt_timeout_ms),
                        )
                    )
                except TimeoutError:
                    _ADMIN_HEAVY_REJECT.labels("verify_receipt", "timeout").inc()
                    raise _http_error(status=503, kind="TIMEOUT", message="verify_receipt timed out")
            else:
                # soft mode (no kill) - still bounded by concurrency, request size, chain limits
                ok = bool(
                    verify_receipt(
                        receipt_head_hex=payload.head_hex,
                        receipt_body_json=payload.body_json,
                        verify_key_hex=payload.verify_key_hex,
                        receipt_sig_hex=payload.sig_hex,
                        req_obj=payload.req_obj,
                        comp_obj=payload.comp_obj,
                        e_obj=payload.e_obj,
                        witness_segments=payload.witness_segments,
                        strict=payload.strict,
                        label_salt_hex=payload.label_salt_hex,
                    )
                )
                if (time.perf_counter() - t0) * 1000.0 > float(_ADMIN_CFG.verify_receipt_timeout_ms):
                    _ADMIN_HEAVY_REJECT.labels("verify_receipt", "timeout_soft").inc()
                    raise _http_error(status=503, kind="TIMEOUT", message="verify_receipt exceeded time budget")

            dt = (time.perf_counter() - t0) * 1000.0
            return VerifyOut(ok=bool(ok), latency_ms=float(dt))
        finally:
            gate_verify_receipt.release()
            if _ADMIN_CFG.audit_read_endpoints:
                try:
                    _record_event(
                        action="verify_receipt",
                        req=request,
                        ok=bool(ok),
                        started_at=started,
                        details={"head_hex": payload.head_hex[:16] + "...", "strict": bool(payload.strict)},
                        require_attestation=False,
                        require_ledger=False,
                    )
                except Exception:
                    logger.warning("verify_receipt audit failed", exc_info=True)

    @router.post("/verify/chain", response_model=VerifyOut)
    def verify_chain_api(payload: VerifyChainIn, request: Request):
        _require_scope(request, "verify")

        if not gate_verify_chain.try_acquire():
            _ADMIN_HEAVY_REJECT.labels("verify_chain", "overloaded").inc()
            raise _http_error(status=503, kind="OVERLOADED", message="too many verify_chain in-flight")

        started = time.perf_counter()
        ok = False
        try:
            t0 = time.perf_counter()
            if _ADMIN_CFG.hard_timeout_mode == "process":
                try:
                    ok = bool(
                        _run_with_hard_timeout_process(
                            verify_chain,
                            args=(payload.heads, payload.bodies),
                            kwargs={"label_salt_hex": payload.label_salt_hex},
                            timeout_ms=int(_ADMIN_CFG.verify_chain_timeout_ms),
                        )
                    )
                except TimeoutError:
                    _ADMIN_HEAVY_REJECT.labels("verify_chain", "timeout").inc()
                    raise _http_error(status=503, kind="TIMEOUT", message="verify_chain timed out")
            else:
                ok = bool(verify_chain(payload.heads, payload.bodies, label_salt_hex=payload.label_salt_hex))
                if (time.perf_counter() - t0) * 1000.0 > float(_ADMIN_CFG.verify_chain_timeout_ms):
                    _ADMIN_HEAVY_REJECT.labels("verify_chain", "timeout_soft").inc()
                    raise _http_error(status=503, kind="TIMEOUT", message="verify_chain exceeded time budget")

            dt = (time.perf_counter() - t0) * 1000.0
            return VerifyOut(ok=bool(ok), latency_ms=float(dt))
        finally:
            gate_verify_chain.release()
            if _ADMIN_CFG.audit_read_endpoints:
                try:
                    _record_event(
                        action="verify_chain",
                        req=request,
                        ok=bool(ok),
                        started_at=started,
                        details={"head_count": int(len(payload.heads)), "total_body_bytes": int(sum(len(b) for b in payload.bodies))},
                        require_attestation=False,
                        require_ledger=False,
                    )
                except Exception:
                    logger.warning("verify_chain audit failed", exc_info=True)

    # Receipt ingestion (verify-first GTM) -----------------------------------

    @router.post("/receipts/ingest", response_model=Dict[str, Any])
    def receipt_ingest(payload: ReceiptIngestIn, request: Request):
        _require_scope(request, "write")
        _enforce_admin_headers(request, action="receipt_ingest")
        _enforce_verify_key_policy(payload.verify_key_hex)

        if not gate_ingest.try_acquire():
            _ADMIN_HEAVY_REJECT.labels("receipt_ingest", "overloaded").inc()
            raise _http_error(status=503, kind="OVERLOADED", message="too many ingest in-flight")

        started = time.perf_counter()
        stored = False
        verified = False
        head_short = payload.head_hex[:16] + "..." if payload.head_hex else ""
        head_store = _canonicalize_hex(payload.head_hex)

        try:
            if not ctx.storage:
                raise _http_error(status=501, kind="STORAGE_DOWN", message="receipt storage not configured")

            # Idempotency / no silent overwrite:
            existing = _storage_get_any(head_store)
            if existing:
                _, old_body = existing
                if old_body == payload.body_json:
                    # idempotent no-op
                    stored = False
                    verified = None if not payload.verify_before_store else True
                    require_att = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.attestation_enabled and _ADMIN_CFG.require_attestor)
                    require_led = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.require_ledger)
                    _record_event(
                        action="receipt_ingest",
                        req=request,
                        ok=True,
                        started_at=started,
                        details={"head_hex": head_short, "idempotent": True, "stored": False, "verify_before_store": bool(payload.verify_before_store)},
                        require_attestation=require_att,
                        require_ledger=require_led,
                    )
                    return {"ok": True, "stored": False, "idempotent": True, "head_hex": head_store}

                # Different body => conflict (must be explicit + audited)
                raise _http_error(status=409, kind="CONFLICT", message="receipt head already exists with different body")

            # Verify before store (optional)
            verify_latency_ms = 0.0
            if payload.verify_before_store:
                t0 = time.perf_counter()
                if _ADMIN_CFG.hard_timeout_mode == "process":
                    try:
                        verified = bool(
                            _run_with_hard_timeout_process(
                                verify_receipt,
                                args=(),
                                kwargs={
                                    "receipt_head_hex": payload.head_hex,
                                    "receipt_body_json": payload.body_json,
                                    "verify_key_hex": payload.verify_key_hex,
                                    "receipt_sig_hex": payload.sig_hex,
                                    "strict": payload.strict,
                                    "label_salt_hex": payload.label_salt_hex,
                                },
                                timeout_ms=int(_ADMIN_CFG.verify_receipt_timeout_ms),
                            )
                        )
                    except TimeoutError:
                        _ADMIN_HEAVY_REJECT.labels("receipt_ingest", "verify_timeout").inc()
                        raise _http_error(status=503, kind="TIMEOUT", message="receipt verification timed out")
                else:
                    verified = bool(
                        verify_receipt(
                            receipt_head_hex=payload.head_hex,
                            receipt_body_json=payload.body_json,
                            verify_key_hex=payload.verify_key_hex,
                            receipt_sig_hex=payload.sig_hex,
                            strict=payload.strict,
                            label_salt_hex=payload.label_salt_hex,
                        )
                    )
                verify_latency_ms = (time.perf_counter() - t0) * 1000.0
                if not verified:
                    raise _http_error(status=400, kind="VERIFY_FAIL", message="receipt verification failed")

            # Store (bounded by dependency timeout + breaker)
            def _put() -> None:
                ctx.storage.put(head_store, payload.body_json)  # type: ignore[union-attr]

            _dep_call(
                dep="storage",
                op="put",
                timeout_ms=_ADMIN_CFG.dep_timeout_storage_ms,
                breaker=_STORAGE_BREAKER,
                fn=_put,
                err_kind="STORAGE_DOWN",
                err_message="storage unavailable",
            )

            stored = True

            # Strict mutations: require ledger/attestation to succeed
            require_att = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.attestation_enabled and _ADMIN_CFG.require_attestor)
            require_led = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.require_ledger)

            _record_event(
                action="receipt_ingest",
                req=request,
                ok=True,
                started_at=started,
                details={
                    "head_hex": head_short,
                    "stored": True,
                    "verify_before_store": bool(payload.verify_before_store),
                    "verified": bool(verified) if payload.verify_before_store else None,
                    "verify_latency_ms": float(verify_latency_ms),
                },
                require_attestation=require_att,
                require_ledger=require_led,
            )

            return {
                "ok": True,
                "stored": True,
                "verified": bool(verified) if payload.verify_before_store else None,
                "head_hex": head_store,
                "verify_latency_ms": float(verify_latency_ms),
            }
        finally:
            gate_ingest.release()

    @router.post("/receipts/ingest_chain", response_model=Dict[str, Any])
    def receipt_ingest_chain(payload: ReceiptIngestChainIn, request: Request):
        _require_scope(request, "write")
        _enforce_admin_headers(request, action="receipt_ingest_chain")

        if not gate_ingest_chain.try_acquire():
            _ADMIN_HEAVY_REJECT.labels("receipt_ingest_chain", "overloaded").inc()
            raise _http_error(status=503, kind="OVERLOADED", message="too many ingest_chain in-flight")

        started = time.perf_counter()
        count = len(payload.heads)

        try:
            if not ctx.storage:
                raise _http_error(status=501, kind="STORAGE_DOWN", message="receipt storage not configured")

            # Verify chain (optional, with hard timeout)
            verify_latency_ms = 0.0
            verified = False
            if payload.verify_before_store:
                t0 = time.perf_counter()
                if _ADMIN_CFG.hard_timeout_mode == "process":
                    try:
                        verified = bool(
                            _run_with_hard_timeout_process(
                                verify_chain,
                                args=(payload.heads, payload.bodies),
                                kwargs={"label_salt_hex": payload.label_salt_hex},
                                timeout_ms=int(_ADMIN_CFG.verify_chain_timeout_ms),
                            )
                        )
                    except TimeoutError:
                        _ADMIN_HEAVY_REJECT.labels("receipt_ingest_chain", "verify_timeout").inc()
                        raise _http_error(status=503, kind="TIMEOUT", message="chain verification timed out")
                else:
                    verified = bool(verify_chain(payload.heads, payload.bodies, label_salt_hex=payload.label_salt_hex))
                verify_latency_ms = (time.perf_counter() - t0) * 1000.0
                if not verified:
                    raise _http_error(status=400, kind="VERIFY_FAIL", message="chain verification failed")

            # Idempotency / conflict check: enforce no silent overwrites
            # Note: potentially expensive for remote stores; this is platform-safety by default.
            conflicts: List[str] = []
            idempotent = 0

            for h, b in zip(payload.heads, payload.bodies):
                head_store = _canonicalize_hex(h)
                existing = _storage_get_any(head_store)
                if existing:
                    _, old_body = existing
                    if old_body == b:
                        idempotent += 1
                        continue
                    conflicts.append(head_store)
                    if len(conflicts) >= 5:
                        break

            if conflicts:
                raise _http_error(
                    status=409,
                    kind="CONFLICT",
                    message="one or more receipt heads already exist with different body",
                    extra={"conflicts": conflicts[:5], "conflict_count": len(conflicts)},
                )

            # Store all (dependency timeout/breaker per put)
            stored = 0
            for h, b in zip(payload.heads, payload.bodies):
                head_store = _canonicalize_hex(h)
                # skip idempotent existing equals
                existing = _storage_get_any(head_store)
                if existing and existing[1] == b:
                    continue

                def _put_one(hs: str = head_store, body: str = b) -> None:
                    ctx.storage.put(hs, body)  # type: ignore[union-attr]

                _dep_call(
                    dep="storage",
                    op="put",
                    timeout_ms=_ADMIN_CFG.dep_timeout_storage_ms,
                    breaker=_STORAGE_BREAKER,
                    fn=_put_one,
                    err_kind="STORAGE_DOWN",
                    err_message="storage unavailable",
                )
                stored += 1

            require_att = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.attestation_enabled and _ADMIN_CFG.require_attestor)
            require_led = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.require_ledger)

            _record_event(
                action="receipt_ingest_chain",
                req=request,
                ok=True,
                started_at=started,
                details={
                    "count": int(count),
                    "stored": int(stored),
                    "idempotent": int(idempotent),
                    "verify_before_store": bool(payload.verify_before_store),
                    "verified": bool(verified) if payload.verify_before_store else None,
                    "verify_latency_ms": float(verify_latency_ms),
                    "total_body_bytes": int(sum(len(x) for x in payload.bodies)),
                },
                require_attestation=require_att,
                require_ledger=require_led,
            )

            return {
                "ok": True,
                "count": int(count),
                "stored": int(stored),
                "idempotent": int(idempotent),
                "verified": bool(verified) if payload.verify_before_store else None,
                "verify_latency_ms": float(verify_latency_ms),
            }
        finally:
            gate_ingest_chain.release()

    # Optional cursor pagination (if storage supports it) ---------------------

    @router.get("/receipts/page")
    def receipt_page(limit: int = 100, cursor: Optional[str] = None, request: Request = None):  # type: ignore[assignment]
        _require_scope(request, "read")  # type: ignore[arg-type]
        if not ctx.storage:
            raise _http_error(status=501, kind="STORAGE_DOWN", message="receipt storage not configured")
        limit = max(1, min(1000, int(limit)))
        if not hasattr(ctx.storage, "page"):
            raise _http_error(status=501, kind="BAD_REQUEST", message="storage does not support cursor paging")
        # Expected storage.page(cursor, limit) -> (items, next_cursor)
        def _page() -> Any:
            return getattr(ctx.storage, "page")(cursor, limit)  # type: ignore[misc]
        res = _dep_call(
            dep="storage",
            op="page",
            timeout_ms=_ADMIN_CFG.dep_timeout_storage_ms,
            breaker=_STORAGE_BREAKER,
            fn=_page,
            err_kind="STORAGE_DOWN",
            err_message="storage unavailable",
        )
        if isinstance(res, tuple) and len(res) == 2:
            items, next_cursor = res
            return {"ok": True, "items": items, "next_cursor": next_cursor}
        return {"ok": True, "result": res}

    # ---- Alpha probe --------------------------------------------------------

    @router.get("/alpha/{tenant}/{user}/{session}", response_model=AlphaOut)
    def alpha_state(tenant: str, user: str, session: str, request: Request):
        _require_scope(request, "read")
        started = time.perf_counter()
        ok = True
        state = None
        try:
            if ctx.alpha_probe_fn:
                try:
                    state = ctx.alpha_probe_fn(tenant, user, session)
                except Exception as e:
                    logger.warning("alpha_probe_fn failed: %s", e)
                    state = {"error": "alpha_probe_fn failed"}
            return AlphaOut(tenant=tenant, user=user, session=session, state=state)
        finally:
            if _ADMIN_CFG.audit_read_endpoints:
                try:
                    _record_event(
                        action="alpha_state",
                        req=request,
                        ok=ok,
                        started_at=started,
                        details={"tenant": tenant, "user": user, "session": session},
                        require_attestation=False,
                        require_ledger=False,
                    )
                except Exception:
                    logger.warning("alpha_state audit failed", exc_info=True)

    # ---- Settings hot-reload ------------------------------------------------

    @router.get("/config")
    def config_get(request: Request):
        _require_scope(request, "read")
        s = _SETTINGS_HOT.get()
        return {"ok": True, "config_hash": s.config_hash(), "settings": s.model_dump(), "admin_cfg_digest": _ADMIN_CFG_DIGEST}

    @router.post("/config/reload")
    def config_reload(request: Request):
        _require_scope(request, "write")
        started = time.perf_counter()
        _enforce_admin_headers(request, action="config_reload")

        cfg_hash = ""
        try:
            try:
                with _ADMIN_LOCK:
                    _SETTINGS_HOT._reload()  # type: ignore[attr-defined]
            except Exception as e:
                logger.exception("settings reload failed: %s", e)
                raise _http_error(status=503, kind="INTERNAL", message="reload failed")
            s = _SETTINGS_HOT.get()
            cfg_hash = s.config_hash()

            require_att = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.attestation_enabled and _ADMIN_CFG.require_attestor)
            require_led = bool(_ADMIN_CFG.strict_mode and _ADMIN_CFG.require_ledger)

            _record_event(
                action="config_reload",
                req=request,
                ok=True,
                started_at=started,
                details={"config_hash": cfg_hash},
                require_attestation=require_att,
                require_ledger=require_led,
            )

            return {"ok": True, "config_hash": cfg_hash}
        except HTTPException:
            raise
        except Exception as e:
            logger.exception("config_reload failed: %s", e)
            raise _http_error(status=500, kind="INTERNAL", message="config_reload failed")

    # ---- Whoami (auth debugging) -------------------------------------------

    @router.get("/whoami")
    def whoami(request: Request):
        _require_scope(request, "read")
        scopes = sorted(list(getattr(getattr(request, "state", object()), "tcd_admin_scopes", set()) or set()))
        principal = (request.headers.get("X-TCD-Admin-Principal") or "").strip()
        return {"ok": True, "principal": principal or None, "scopes": scopes}

    app.include_router(router)
    return app