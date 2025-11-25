from __future__ import annotations

"""
Admin-only HTTP surface for policies, verification, receipt access, and runtime
introspection.

This module is hardened as a control-plane router with:

- Header- and role-based guards against internal misuse.
- Optional IP allowlist and token auth.
- Token-bucket rate limiting per principal.
- Request size limits.
- Attestation + ledger hooks for mutating operations.
- Optional auditing for high-value read endpoints (verify / receipts / alpha).
- Supply-chain anchors and PQ attestor constraints.
"""

import json
import hmac
import logging
import os
import threading
import time
from dataclasses import dataclass, asdict, is_dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple, Protocol, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response
from fastapi.routing import APIRouter
from pydantic import BaseModel, Field, field_validator, conlist

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
    from prometheus_client import Counter, Histogram
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


logger = logging.getLogger("tcd.admin")

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


@dataclass
class AdminAppConfig:
    """
    Security and behavior knobs for the admin HTTP surface.
    """

    api_version: str = "0.10.3"
    enable_docs: bool = False

    # Request-level guards
    max_body_bytes: int = 1 * 1024 * 1024
    rps_per_key: float = 10.0
    burst_per_key: int = 20

    # Auth profile
    strict_mode: bool = False
    require_token: bool = True
    allow_no_auth: bool = False
    ip_allowlist: Tuple[str, ...] = ()
    require_mfa_header: bool = False
    require_approval_header: bool = False

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

    # Supply-chain anchors
    node_id: str = ""
    proc_id: str = ""
    supply_chain_label: str = ""
    image_digest: str = ""
    build_id: str = ""

    # Read-path auditing
    audit_read_endpoints: bool = False

    def digest_material(self) -> Dict[str, Any]:
        """
        Stable material used for the admin config digest. This is referenced
        from receipts / ledger for supply-chain style auditing.
        """
        return {
            "api_version": self.api_version,
            "enable_docs": bool(self.enable_docs),
            "max_body_bytes": int(self.max_body_bytes),
            "rps_per_key": float(self.rps_per_key),
            "burst_per_key": int(self.burst_per_key),
            "strict_mode": bool(self.strict_mode),
            "require_token": bool(self.require_token),
            "allow_no_auth": bool(self.allow_no_auth),
            "ip_allowlist": list(self.ip_allowlist),
            "require_mfa_header": bool(self.require_mfa_header),
            "require_approval_header": bool(self.require_approval_header),
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
            "node_id": self.node_id,
            "proc_id": self.proc_id,
            "supply_chain_label": self.supply_chain_label,
            "image_digest": self.image_digest,
            "build_id": self.build_id,
        }


def _split_env_list(name: str) -> List[str]:
    raw = os.getenv(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]


_ADMIN_CFG = AdminAppConfig(
    api_version=os.getenv("TCD_ADMIN_API_VERSION", "0.10.3"),
    enable_docs=os.getenv("TCD_ADMIN_ENABLE_DOCS", "0") == "1",
    max_body_bytes=int(os.getenv("TCD_ADMIN_MAX_BODY_BYTES", str(1 * 1024 * 1024))),
    rps_per_key=float(os.getenv("TCD_ADMIN_RPS", "10")),
    burst_per_key=int(os.getenv("TCD_ADMIN_BURST", "20")),
    strict_mode=os.getenv("TCD_ADMIN_STRICT_MODE", "0") == "1",
    require_token=True,
    allow_no_auth=os.getenv("TCD_ADMIN_ALLOW_NO_AUTH", "0") == "1",
    ip_allowlist=tuple(_split_env_list("TCD_ADMIN_IP_ALLOWLIST")),
    require_mfa_header=os.getenv("TCD_ADMIN_REQUIRE_MFA", "0") == "1",
    require_approval_header=os.getenv("TCD_ADMIN_REQUIRE_APPROVAL", "0") == "1",
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
    node_id=os.getenv("TCD_ADMIN_NODE_ID", ""),
    proc_id=os.getenv("TCD_ADMIN_PROC_ID", ""),
    supply_chain_label=os.getenv("TCD_ADMIN_SUPPLY_CHAIN_LABEL", ""),
    image_digest=os.getenv("TCD_ADMIN_IMAGE_DIGEST", ""),
    build_id=os.getenv("TCD_ADMIN_BUILD_ID", ""),
    audit_read_endpoints=os.getenv("TCD_ADMIN_AUDIT_READS", "0") == "1",
)

_SETTINGS_HOT = make_reloadable_settings()
_ADMIN_LOCK = threading.RLock()
_ADMIN_TOKEN = (os.environ.get("TCD_ADMIN_TOKEN") or "").strip()

# Config digest for supply-chain anchoring
_cfg_hasher = Blake3Hash()
try:
    cfg_material = _ADMIN_CFG.digest_material()
    if canonical_kv_hash is not None:
        _ADMIN_CFG_DIGEST = canonical_kv_hash(
            cfg_material,
            ctx="tcd:admin_cfg",
            label="tcd_admin_cfg",
        )
    else:
        blob = json.dumps(cfg_material, sort_keys=True).encode("utf-8")
        _ADMIN_CFG_DIGEST = _cfg_hasher.hex(blob, ctx="tcd:admin_cfg")
except Exception:
    _ADMIN_CFG_DIGEST = "admin_cfg:" + repr(_ADMIN_CFG.digest_material())

# Metrics ---------------------------------------------------------------------

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
    labelnames=("key",),
)
_ADMIN_MUTATION_AUDIT_ERROR = Counter(
    "tcd_admin_mutation_audit_error_total",
    "Failures when auditing mutating admin operations",
    labelnames=("action", "kind"),
)

# -----------------------------------------------------------------------------
# Auth & header guards
# -----------------------------------------------------------------------------


def _require_admin(
    token: Optional[str] = Header(default=None, alias="X-TCD-Admin-Token"),
) -> None:
    """
    Minimal header token auth.

    In strict_mode, an admin token is always required. When allow_no_auth is
    enabled and strict_mode is off, the token may be omitted for local/dev use.
    """
    want = _ADMIN_TOKEN
    if not want:
        if _ADMIN_CFG.strict_mode and _ADMIN_CFG.require_token:
            raise HTTPException(status_code=401, detail="admin token required")
        if _ADMIN_CFG.allow_no_auth and not _ADMIN_CFG.strict_mode:
            return
        raise HTTPException(status_code=401, detail="admin token required")

    if not token or len(token) != len(want):
        raise HTTPException(status_code=403, detail="forbidden")

    if not hmac.compare_digest(token, want):
        raise HTTPException(status_code=403, detail="forbidden")


def _require_ip_allowlist(req: Request) -> None:
    """Optional IP allowlist; when configured, only listed client IPs are allowed."""
    if not _ADMIN_CFG.ip_allowlist:
        return
    client_ip = (req.client.host if req.client else "") or ""
    if client_ip not in _ADMIN_CFG.ip_allowlist:
        raise HTTPException(status_code=403, detail="ip not allowed")


def _enforce_admin_headers(req: Request, *, action: str) -> None:
    """
    Header-based guard for mutating operations.

    In strict_mode this enforces:
    - per-action deny list
    - principal allow list
    - MFA tag
    - approval header (distinct from principal) and approval system
    - change ticket and change reason headers
    """
    if not _ADMIN_CFG.strict_mode:
        return

    # Action-level deny list
    if _ADMIN_CFG.forbidden_actions and action in _ADMIN_CFG.forbidden_actions:
        raise HTTPException(status_code=403, detail="action forbidden by policy")

    headers = req.headers
    principal = headers.get("X-TCD-Admin-Principal") or ""
    approval = headers.get("X-TCD-Admin-Approval") or ""
    mfa_token = headers.get("X-TCD-Admin-MFA", "")

    # Principal allow list
    if _ADMIN_CFG.allowed_principals and principal:
        if principal not in _ADMIN_CFG.allowed_principals:
            raise HTTPException(status_code=403, detail="principal not allowed")

    # MFA guard
    if _ADMIN_CFG.require_mfa_header:
        mfa_ok = mfa_token.lower() in ("1", "true", "yes", "ok")
        if not mfa_ok:
            raise HTTPException(status_code=403, detail="mfa required")

    # Approval guard (including system label)
    if _ADMIN_CFG.require_approval_header:
        if not approval:
            raise HTTPException(status_code=403, detail="approval required")
        if principal and approval and principal == approval:
            raise HTTPException(status_code=403, detail="approval must differ from principal")

        if _ADMIN_CFG.approval_system_allowlist:
            sys_tag = headers.get("X-TCD-Admin-Approval-System") or ""
            if sys_tag not in _ADMIN_CFG.approval_system_allowlist:
                raise HTTPException(status_code=403, detail="invalid approval system")

    # Change ticket / reason
    if _ADMIN_CFG.require_change_ticket_header:
        ticket = headers.get("X-TCD-Admin-Change-Ticket")
        if not ticket:
            raise HTTPException(status_code=403, detail="change ticket required")

    if _ADMIN_CFG.require_reason_header:
        reason = headers.get("X-TCD-Admin-Reason")
        if not reason:
            raise HTTPException(status_code=403, detail="change reason required")


# -----------------------------------------------------------------------------
# Middlewares
# -----------------------------------------------------------------------------


class _TokenBucket:
    """Token bucket for rate limiting per caller key."""

    __slots__ = ("capacity", "rate", "tokens", "updated")

    def __init__(self, rate: float, capacity: int) -> None:
        self.rate = max(0.1, rate)
        self.capacity = max(1, capacity)
        self.tokens = float(self.capacity)
        self.updated = time.monotonic()

    def allow(self) -> bool:
        now = time.monotonic()
        delta = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + delta * self.rate)
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


_BUCKETS: Dict[str, _TokenBucket] = {}
_BUCKETS_LOCK = threading.Lock()


async def _req_context_mw(req: Request, call_next: Callable) -> Response:
    """Request context middleware: IP guard, basic metrics, and headers."""
    start = time.perf_counter()
    path = req.url.path
    method = req.method

    # IP allowlist path
    try:
        _require_ip_allowlist(req)
    except HTTPException as e:
        status = e.status_code
        _ADMIN_REQ_TOTAL.labels(path, method, str(status)).inc()
        _ADMIN_REQ_LATENCY.labels(path, method, str(status)).observe(0.0)
        return Response(status_code=e.status_code, content=e.detail)

    rid = req.headers.get("X-Request-Id") or f"r-{int(time.time() * 1000)}-{os.getpid()}"
    status_str = "500"
    try:
        resp = await call_next(req)
        status_str = str(resp.status_code)
    except Exception:
        _ADMIN_REQ_ERROR.labels(path, method, "handler").inc()
        logger.exception("admin request failed: path=%s method=%s", path, method)
        raise
    finally:
        dt_ms = (time.perf_counter() - start) * 1000.0
        _ADMIN_REQ_TOTAL.labels(path, method, status_str).inc()
        _ADMIN_REQ_LATENCY.labels(path, method, status_str).observe(dt_ms)
        logger.info(
            "admin.req path=%s method=%s rid=%s status=%s dt_ms=%.3f",
            path,
            method,
            rid,
            status_str,
            dt_ms,
        )

    resp.headers["X-TCD-Request-Id"] = rid
    resp.headers["X-TCD-Admin-Version"] = _ADMIN_CFG.api_version
    resp.headers["X-TCD-Admin-Cfg-Digest"] = _ADMIN_CFG_DIGEST
    return resp


async def _size_guard_mw(req: Request, call_next: Callable) -> Response:
    """Reject requests with overly large bodies based on Content-Length."""
    cl = req.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > _ADMIN_CFG.max_body_bytes:
                return Response(status_code=413, content="payload too large")
        except Exception:
            return Response(status_code=400, content="invalid content-length")
    return await call_next(req)


async def _rate_limit_mw(req: Request, call_next: Callable) -> Response:
    """Token-bucket rate limiter keyed by admin token or client IP."""
    key = req.headers.get("X-TCD-Admin-Token") or (req.client.host if req.client else "unknown")
    with _BUCKETS_LOCK:
        bucket = _BUCKETS.get(key)
        if bucket is None:
            bucket = _TokenBucket(rate=_ADMIN_CFG.rps_per_key, capacity=_ADMIN_CFG.burst_per_key)
            _BUCKETS[key] = bucket
    if not bucket.allow():
        _ADMIN_RATE_LIMIT_REJECT.labels(key).inc()
        return Response(status_code=429, content="rate limit exceeded")
    return await call_next(req)


# -----------------------------------------------------------------------------
# Utils
# -----------------------------------------------------------------------------


def _dump_cfg(obj: Any) -> Dict[str, Any]:
    """Best-effort, side-effect-free dict dump for config-like objects."""
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
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2 != 0:
        return False
    try:
        bytes.fromhex(s)
        return True
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------


class ReloadRequest(BaseModel):
    source: Literal["env", "file"] = "env"
    path: Optional[str] = None  # when source=file


class PolicySet(BaseModel):
    rules: List[PolicyRule] = Field(default_factory=list)


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


# Length-bounded inputs to avoid DoS
_MAX_BODY_JSON = 128 * 1024  # 128 KiB per receipt body JSON
_MAX_CHAIN = 2000            # max items in chain verification


class VerifyReceiptIn(BaseModel):
    head_hex: str = Field(..., min_length=2, max_length=130)  # "0x"+64 hex typical
    body_json: str = Field(..., min_length=2, max_length=_MAX_BODY_JSON)
    sig_hex: Optional[str] = Field(default=None, max_length=200)
    verify_key_hex: Optional[str] = Field(default=None, max_length=200)
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
    heads: conlist(str, min_length=1, max_length=_MAX_CHAIN)  # type: ignore[arg-type]
    bodies: conlist(str, min_length=1, max_length=_MAX_CHAIN)  # type: ignore[arg-type]
    label_salt_hex: Optional[str] = Field(default=None, max_length=130)

    @field_validator("heads")
    @classmethod
    def _heads_hex(cls, v: List[str]) -> List[str]:
        if not all(_is_hex(x) for x in v):
            raise ValueError("invalid head hex in list")
        return v

    @field_validator("label_salt_hex")
    @classmethod
    def _salt_hex(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _is_hex(v):
            raise ValueError("invalid hex")
        return v


class VerifyOut(BaseModel):
    ok: bool
    latency_ms: float


class ReceiptGetOut(BaseModel):
    head_hex: str
    body_json: Optional[str] = None
    found: bool


class ReceiptTailOut(BaseModel):
    items: List[Tuple[str, str]]  # serialized as list[list[str, str]]
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


# -----------------------------------------------------------------------------
# Factory
# -----------------------------------------------------------------------------


def create_admin_app(ctx: AdminContext) -> FastAPI:
    """
    Build an admin-only FastAPI app.

    All routes are mounted under /admin/* and protected by _require_admin.
    This surface is intended for control-plane only: policies, verification,
    receipts, runtime info, and settings reload.
    """
    # Strict profile startup checks
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

    # Middlewares
    app.middleware("http")(_req_context_mw)
    app.middleware("http")(_size_guard_mw)
    app.middleware("http")(_rate_limit_mw)

    hasher = Blake3Hash()
    router = APIRouter(prefix="/admin", dependencies=[Depends(_require_admin)])

    # Cache digest keyed by rules list identity (avoids re-hashing on frequent GETs)
    _policy_digest_cache: Dict[int, str] = {}

    def _policy_digest(rules: List[PolicyRule]) -> str:
        try:
            key = id(rules)
            if key in _policy_digest_cache:
                return _policy_digest_cache[key]
            canon = {"rules": [r.model_dump() for r in rules], "version": "1"}
            data = json.dumps(canon, sort_keys=True).encode("utf-8")
            digest = hasher.hex(data, ctx="tcd:policyset")
            _policy_digest_cache[key] = digest
            return digest
        except Exception as e:  # pragma: no cover
            logger.exception("policy digest failed: %s", e)
            return "0" * 64

    def _record_mutation(
        *,
        action: str,
        req: Request,
        ok: bool,
        started_at: float,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a mutating admin operation into attestation and ledger.

        This aligns with the TrustAgent control-plane pattern:
        - req_obj / comp_obj / e_obj for attestation;
        - witness segments for config and ledger head;
        - meta block binding node / supply-chain anchors;
        - structured ledger event for later machine auditing.
        """
        duration_ms = (time.perf_counter() - started_at) * 1000.0
        meta_details: Dict[str, Any] = dict(details or {})
        meta_details.setdefault("ok", bool(ok))
        meta_details.setdefault("duration_ms", float(duration_ms))
        meta_details.setdefault("admin_cfg_digest", _ADMIN_CFG_DIGEST)
        meta_details.setdefault("path", str(req.url.path))
        meta_details.setdefault("method", str(req.method))

        principal = req.headers.get("X-TCD-Admin-Principal") or ""
        approval = req.headers.get("X-TCD-Admin-Approval") or ""
        mfa_raw = req.headers.get("X-TCD-Admin-MFA", "")
        mfa_verified = mfa_raw.lower() in ("1", "true", "yes", "ok")

        # Attestation
        if ctx.attestor is not None and _ADMIN_CFG.attestation_enabled:
            try:
                req_obj: Dict[str, Any] = {
                    "path": str(req.url.path),
                    "method": str(req.method),
                    "client": (req.client.host if req.client else None),
                    "headers": {
                        "principal": principal,
                        "mfa": mfa_verified,
                        "approval": approval,
                    },
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
                }
                e_obj: Dict[str, Any] = {
                    "decision": "success" if ok else "failure",
                    "duration_ms": float(duration_ms),
                    "error": None if ok else "failure",
                    "action": action,
                }
                # Policy / config view
                for key in ("policyset_ref", "policy_rule_count", "config_hash"):
                    if key in meta_details:
                        e_obj[key] = meta_details[key]
                # e-process budget view (if caller provided)
                for key in ("e_value", "alpha_spent", "alpha_alloc", "budget_remaining"):
                    if key in meta_details:
                        e_obj[key] = meta_details[key]

                segments: List[Dict[str, Any]] = [
                    {
                        "kind": "admin_cfg",
                        "id": "tcd_admin",
                        "digest": _ADMIN_CFG_DIGEST,
                        "meta": {},
                    }
                ]
                if ctx.ledger is not None and hasattr(ctx.ledger, "head"):
                    try:
                        segments.append(
                            {
                                "kind": "admin_ledger_head",
                                "id": "tcd_admin",
                                "digest": ctx.ledger.head(),
                                "meta": {},
                            }
                        )
                    except Exception:
                        logger.warning("admin ledger head read failed for attestation", exc_info=True)
                # Optional global cfg digest from attestor config
                if ctx.attestor_cfg is not None:
                    cfg_digest = getattr(ctx.attestor_cfg, "default_cfg_digest", None)
                    if cfg_digest:
                        segments.append(
                            {
                                "kind": "system_cfg",
                                "id": "tcd_system",
                                "digest": cfg_digest,
                                "meta": {},
                            }
                        )

                tags = ["tcd_admin", action]

                meta_block: Dict[str, Any] = {
                    "ok": bool(ok),
                    "admin_cfg_digest": _ADMIN_CFG_DIGEST,
                    "node_id": _ADMIN_CFG.node_id,
                    "proc_id": _ADMIN_CFG.proc_id,
                    "supply_chain_label": _ADMIN_CFG.supply_chain_label,
                }
                if ctx.attestor_cfg is not None and hasattr(ctx.attestor_cfg, "policy_digest"):
                    try:
                        meta_block["attestor_policy_digest"] = ctx.attestor_cfg.policy_digest()
                    except Exception:
                        logger.warning("admin attestor policy_digest failed", exc_info=True)

                att = ctx.attestor.issue(  # type: ignore[call-arg]
                    req_obj=req_obj,
                    comp_obj=comp_obj,
                    e_obj=e_obj,
                    witness_segments=segments,
                    witness_tags=tags,
                    meta=meta_block,
                )
                meta_details["receipt"] = att.get("receipt")
                meta_details["verify_key"] = att.get("verify_key")
            except Exception:
                _ADMIN_MUTATION_AUDIT_ERROR.labels(action, "attestation").inc()
                logger.error("admin mutation attestation failed: action=%s", action, exc_info=True)
                if _ADMIN_CFG.strict_mode and _ADMIN_CFG.require_attestor:
                    meta_details.setdefault("attestation_failure", True)

        # Ledger
        if ctx.ledger is not None and hasattr(ctx.ledger, "append"):
            try:
                evt: Dict[str, Any] = {
                    "kind": "admin_mutation",
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
                # Lift e-process fields to top-level for easier analytics
                for key in ("e_value", "alpha_spent", "alpha_alloc", "budget_remaining"):
                    if key in meta_details:
                        evt[key] = meta_details[key]

                ctx.ledger.append(evt)
            except Exception:
                _ADMIN_MUTATION_AUDIT_ERROR.labels(action, "ledger").inc()
                logger.warning("admin mutation ledger append failed: action=%s", action, exc_info=True)

    # ---- Endpoints ----------------------------------------------------------

    @router.get("/healthz")
    def healthz():
        s = _SETTINGS_HOT.get()
        return {
            "ok": True,
            "ts": time.time(),
            "version": _ADMIN_CFG.api_version,
            "config_hash": s.config_hash(),
            "admin_cfg_digest": _ADMIN_CFG_DIGEST,
        }

    @router.get("/runtime", response_model=RuntimeOut)
    def runtime():
        s = _SETTINGS_HOT.get()
        stats: Dict[str, Any] = {}
        if ctx.runtime_stats_fn:
            try:
                stats = dict(ctx.runtime_stats_fn() or {})
            except Exception as e:
                logger.warning("runtime_stats_fn failed: %s", e)
                stats = {"error": "runtime_stats_fn failed"}
        return RuntimeOut(
            version=_ADMIN_CFG.api_version,
            config_hash=s.config_hash(),
            settings=s.model_dump(),
            stats=stats,
        )

    # Policies ---------------------------------------------------------------

    @router.get("/policies", response_model=PolicySet)
    def policies_get():
        with _ADMIN_LOCK:
            return PolicySet(rules=ctx.policies.rules())

    @router.get("/policies/ref")
    def policies_ref():
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
        started = time.perf_counter()
        _enforce_admin_headers(request, action="policies_put")
        ok = True
        policy_ref = ""
        count = 0
        try:
            with _ADMIN_LOCK:
                ctx.policies.replace_rules(ps.rules or [])
                rules = ctx.policies.rules()
                digest = _policy_digest(rules)
                policy_ref = f"set@1#{digest[:12]}"
                count = len(rules)
            return {"ok": True, "policyset_ref": policy_ref, "count": count}
        except HTTPException:
            ok = False
            raise
        except Exception as e:
            ok = False
            _ADMIN_REQ_ERROR.labels("/admin/policies", "PUT", "handler").inc()
            logger.exception("policies_put failed: %s", e)
            raise
        finally:
            try:
                _record_mutation(
                    action="policies_put",
                    req=request,
                    ok=ok,
                    started_at=started,
                    details={
                        "policyset_ref": policy_ref,
                        "policy_rule_count": count,
                    },
                )
            except Exception:
                logger.warning("policies_put mutation audit failed", exc_info=True)

    @router.post("/policies/reload", response_model=Dict[str, Any])
    def policies_reload(req: ReloadRequest, request: Request):
        started = time.perf_counter()
        _enforce_admin_headers(request, action="policies_reload")
        ok = True
        policy_ref = ""
        count = 0
        try:
            with _ADMIN_LOCK:
                if req.source == "env":
                    new_store = PolicyStore.from_env()
                else:
                    if not req.path:
                        raise HTTPException(status_code=400, detail="path required when source=file")
                    new_store = PolicyStore.from_file(req.path)
                ctx.policies.replace_rules(new_store.rules())
                rules = ctx.policies.rules()
                digest = _policy_digest(rules)
                policy_ref = f"set@1#{digest[:12]}"
                count = len(rules)
            return {"ok": True, "policyset_ref": policy_ref, "count": count}
        except HTTPException:
            ok = False
            raise
        except Exception as e:
            ok = False
            _ADMIN_REQ_ERROR.labels("/admin/policies/reload", "POST", "handler").inc()
            logger.exception("policies_reload failed: %s", e)
            raise
        finally:
            try:
                _record_mutation(
                    action="policies_reload",
                    req=request,
                    ok=ok,
                    started_at=started,
                    details={
                        "policyset_ref": policy_ref,
                        "policy_rule_count": count,
                        "source": req.source,
                    },
                )
            except Exception:
                logger.warning("policies_reload mutation audit failed", exc_info=True)

    @router.post("/policies/bind", response_model=BoundOut)
    def policies_bind(ctx_in: BindContext):
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

    # Receipts & Verification -------------------------------------------------

    @router.get("/receipts/{head_hex}", response_model=ReceiptGetOut)
    def receipt_get(head_hex: str, request: Request):
        started = time.perf_counter()
        ok = True
        try:
            if not ctx.storage:
                return ReceiptGetOut(head_hex=head_hex, body_json=None, found=False)
            try:
                body = ctx.storage.get(head_hex)
            except Exception as e:
                logger.exception("storage.get failed: %s", e)
                raise HTTPException(status_code=500, detail="storage error")
            return ReceiptGetOut(head_hex=head_hex, body_json=body, found=bool(body))
        finally:
            if _ADMIN_CFG.audit_read_endpoints:
                try:
                    _record_mutation(
                        action="receipt_get",
                        req=request,
                        ok=ok,
                        started_at=started,
                        details={"head_hex": head_hex[:16] + "..."},
                    )
                except Exception:
                    logger.warning("receipt_get audit failed", exc_info=True)

    @router.get("/receipts/tail", response_model=ReceiptTailOut)
    def receipt_tail(n: int = 50, request: Request = None):
        started = time.perf_counter()
        ok = True
        try:
            if not ctx.storage:
                return ReceiptTailOut(items=[], total=0)
            n = max(1, min(1000, int(n)))
            try:
                items = ctx.storage.tail(n)
            except Exception as e:
                logger.exception("storage.tail failed: %s", e)
                raise HTTPException(status_code=500, detail="storage error")
            return ReceiptTailOut(items=items, total=len(items))
        finally:
            if _ADMIN_CFG.audit_read_endpoints and request is not None:
                try:
                    _record_mutation(
                        action="receipt_tail",
                        req=request,
                        ok=ok,
                        started_at=started,
                        details={"n": int(n)},
                    )
                except Exception:
                    logger.warning("receipt_tail audit failed", exc_info=True)

    @router.post("/verify/receipt", response_model=VerifyOut)
    def verify_receipt_api(payload: VerifyReceiptIn, request: Request):
        started = time.perf_counter()
        ok = False
        try:
            t0 = time.perf_counter()
            ok = verify_receipt(
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
            dt = (time.perf_counter() - t0) * 1000.0
            return VerifyOut(ok=bool(ok), latency_ms=float(dt))
        finally:
            if _ADMIN_CFG.audit_read_endpoints:
                try:
                    _record_mutation(
                        action="verify_receipt",
                        req=request,
                        ok=bool(ok),
                        started_at=started,
                        details={
                            "head_hex": payload.head_hex[:16] + "...",
                            "strict": payload.strict,
                        },
                    )
                except Exception:
                    logger.warning("verify_receipt audit failed", exc_info=True)

    @router.post("/verify/chain", response_model=VerifyOut)
    def verify_chain_api(payload: VerifyChainIn, request: Request):
        started = time.perf_counter()
        ok = False
        try:
            if len(payload.heads) != len(payload.bodies):
                raise HTTPException(status_code=400, detail="heads and bodies length mismatch")
            t0 = time.perf_counter()
            ok = verify_chain(payload.heads, payload.bodies, label_salt_hex=payload.label_salt_hex)
            dt = (time.perf_counter() - t0) * 1000.0
            return VerifyOut(ok=bool(ok), latency_ms=float(dt))
        finally:
            if _ADMIN_CFG.audit_read_endpoints:
                try:
                    _record_mutation(
                        action="verify_chain",
                        req=request,
                        ok=bool(ok),
                        started_at=started,
                        details={
                            "head_count": len(payload.heads),
                        },
                    )
                except Exception:
                    logger.warning("verify_chain audit failed", exc_info=True)

    # Alpha wealth probe (optional) ------------------------------------------

    @router.get("/alpha/{tenant}/{user}/{session}", response_model=AlphaOut)
    def alpha_state(tenant: str, user: str, session: str, request: Request):
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
                    _record_mutation(
                        action="alpha_state",
                        req=request,
                        ok=ok,
                        started_at=started,
                        details={"tenant": tenant, "user": user, "session": session},
                    )
                except Exception:
                    logger.warning("alpha_state audit failed", exc_info=True)

    # Settings hot-reload -----------------------------------------------------

    @router.get("/config")
    def config_get():
        s = _SETTINGS_HOT.get()
        return {
            "config_hash": s.config_hash(),
            "settings": s.model_dump(),
            "admin_cfg_digest": _ADMIN_CFG_DIGEST,
        }

    @router.post("/config/reload")
    def config_reload(request: Request):
        started = time.perf_counter()
        _enforce_admin_headers(request, action="config_reload")
        ok = True
        cfg_hash = ""
        try:
            try:
                with _ADMIN_LOCK:
                    _SETTINGS_HOT._reload()  # type: ignore[attr-defined]
            except Exception as e:
                logger.exception("settings reload failed: %s", e)
                raise HTTPException(status_code=500, detail="reload failed")
            s = _SETTINGS_HOT.get()
            cfg_hash = s.config_hash()
            return {"ok": True, "config_hash": cfg_hash}
        except HTTPException:
            ok = False
            raise
        finally:
            try:
                _record_mutation(
                    action="config_reload",
                    req=request,
                    ok=ok,
                    started_at=started,
                    details={"config_hash": cfg_hash},
                )
            except Exception:
                logger.warning("config_reload mutation audit failed", exc_info=True)

    app.include_router(router)
    return app