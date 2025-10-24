# FILE: tcd/admin_http.py
from __future__ import annotations

"""
Admin-only HTTP surface for policies, verification, receipts access, and runtime info.

Enhancements in this revision:
- Optional IP allowlist (env TCD_ADMIN_IP_ALLOWLIST)
- Lightweight token-bucket rate limiting (env TCD_ADMIN_RPS / TCD_ADMIN_BURST)
- Request size guard middleware (env TCD_ADMIN_MAX_BODY_BYTES)
- Production-safe docs switch (env TCD_ADMIN_ENABLE_DOCS=0 to disable OpenAPI/Docs)
- Request ID propagation via X-Request-Id / X-TCD-Request-Id headers
- Boundaries on input sizes (pydantic max_length / max_items) to prevent DoS
- Optional orjson for faster canonical dumps
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
    # Schemas (useful for typing/tests):
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

# Optional collaborator (kept pluggable)
try:
    from .attest import Attestor  # noqa: F401
except Exception:  # pragma: no cover
    Attestor = object  # type: ignore[misc,assignment]

# Optional fast JSON
try:  # pragma: no cover - perf sugar; correctness covered by json fallback
    import orjson as _orjson

    def _dumps(obj: Any) -> bytes:
        return _orjson.dumps(obj, option=_orjson.OPT_SORT_KEYS)
except Exception:  # pragma: no cover
    def _dumps(obj: Any) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


logger = logging.getLogger("tcd.admin")

# -----------------------------------------------------------------------------

class ReceiptStorageProtocol(Protocol):
    """Optional receipt store used by admin APIs; implementations may be in-memory or persistent."""
    def put(self, head_hex: str, body_json: str) -> None: ...
    def get(self, head_hex: str) -> Optional[str]: ...
    def tail(self, n: int) -> List[Tuple[str, str]]: ...
    def stats(self) -> Dict[str, Any]: ...


@dataclass
class AdminContext:
    """Dependencies for admin endpoints."""
    policies: PolicyStore
    storage: Optional[ReceiptStorageProtocol] = None
    attestor: Optional[Attestor] = None
    runtime_stats_fn: Optional[Callable[[], Dict[str, Any]]] = None
    alpha_probe_fn: Optional[Callable[[str, str, str], Optional[Dict[str, Any]]]] = None


_SETTINGS_HOT = make_reloadable_settings()
_ADMIN_LOCK = threading.RLock()
_ADMIN_API_VERSION = os.getenv("TCD_ADMIN_API_VERSION", "0.10.3")

# Security knobs
_IP_ALLOWLIST = tuple(
    [x.strip() for x in os.getenv("TCD_ADMIN_IP_ALLOWLIST", "").split(",") if x.strip()]
)
_ENABLE_DOCS = os.getenv("TCD_ADMIN_ENABLE_DOCS", "0") == "1"
_MAX_BODY = int(os.getenv("TCD_ADMIN_MAX_BODY_BYTES", str(1 * 1024 * 1024)))  # 1 MiB
_RPS = float(os.getenv("TCD_ADMIN_RPS", "10"))  # per key
_BURST = int(os.getenv("TCD_ADMIN_BURST", "20"))

# -----------------------------------------------------------------------------
# Auth & Guards
# -----------------------------------------------------------------------------

def _require_admin(token: Optional[str] = Header(default=None, alias="X-TCD-Admin-Token")) -> None:
    """
    Minimal token auth:
      - If TCD_ADMIN_TOKEN is set, header must match (constant-time compare).
      - If not set, allow only when TCD_ADMIN_ALLOW_NO_AUTH=1 (local dev/tests).
    """
    want = (os.environ.get("TCD_ADMIN_TOKEN") or "").strip()
    allow_unsafe = os.environ.get("TCD_ADMIN_ALLOW_NO_AUTH", "0") == "1"
    if not want:
        if allow_unsafe:
            return
        raise HTTPException(status_code=401, detail="admin token required")
    if not token or len(token) != len(want):
        raise HTTPException(status_code=403, detail="forbidden")
    if not hmac.compare_digest(token, want):
        raise HTTPException(status_code=403, detail="forbidden")


def _require_ip_allowlist(req: Request) -> None:
    """Optional IP allowlist; when set, only listed client IPs are allowed."""
    if not _IP_ALLOWLIST:
        return
    client_ip = (req.client.host if req.client else "") or ""
    if client_ip not in _IP_ALLOWLIST:
        raise HTTPException(status_code=403, detail="ip not allowed")

# -----------------------------------------------------------------------------
# Middlewares
# -----------------------------------------------------------------------------

class _TokenBucket:
    """Simple token bucket keyed by admin token or client IP."""
    __slots__ = ("capacity", "rate", "tokens", "updated")

    def __init__(self, rate: float, capacity: int):
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


async def _req_context_mw(req: Request, call_next: Callable):
    """Inject X-Request-Id and version headers; basic IP allowlist."""
    # IP allowlist check (fast path)
    try:
        _require_ip_allowlist(req)
    except HTTPException as e:
        return Response(status_code=e.status_code, content=e.detail)

    rid = req.headers.get("X-Request-Id") or f"r-{int(time.time()*1000)}-{os.getpid()}"
    start = time.perf_counter()
    resp: Response
    try:
        resp = await call_next(req)
    finally:
        dt_ms = (time.perf_counter() - start) * 1000.0
        logger.info(
            "admin.req: path=%s method=%s rid=%s dt_ms=%.3f",
            req.url.path, req.method, rid, dt_ms
        )
    resp.headers["X-TCD-Request-Id"] = rid
    resp.headers["X-TCD-Admin-Version"] = _ADMIN_API_VERSION
    return resp


async def _size_guard_mw(req: Request, call_next: Callable):
    """Reject requests with large Content-Length to avoid excessive memory usage."""
    cl = req.headers.get("content-length")
    if cl is not None:
        try:
            if int(cl) > _MAX_BODY:
                return Response(status_code=413, content="payload too large")
        except Exception:
            return Response(status_code=400, content="invalid content-length")
    return await call_next(req)


async def _rate_limit_mw(req: Request, call_next: Callable):
    """In-memory token bucket keyed by admin token or client IP."""
    key = req.headers.get("X-TCD-Admin-Token") or (req.client.host if req.client else "unknown")
    with _BUCKETS_LOCK:
        b = _BUCKETS.get(key)
        if b is None:
            b = _TokenBucket(rate=_RPS, capacity=_BURST)
            _BUCKETS[key] = b
    if not b.allow():
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
    Build an admin-only FastAPI app. All routes are mounted under /admin/* and
    protected by _require_admin. Control-plane only: policies, verification,
    receipts, runtime info, and settings reload.
    """
    openapi_url = "/openapi.json" if _ENABLE_DOCS else None
    docs_url = "/docs" if _ENABLE_DOCS else None
    redoc_url = "/redoc" if _ENABLE_DOCS else None

    app = FastAPI(title="tcd-admin", version=_ADMIN_API_VERSION,
                  openapi_url=openapi_url, docs_url=docs_url, redoc_url=redoc_url)

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
            digest = hasher.hex(_dumps(canon), ctx="tcd:policyset")
            _policy_digest_cache[key] = digest
            return digest
        except Exception as e:  # pragma: no cover
            logger.exception("policy digest failed: %s", e)
            return "0" * 64

    # ---- Endpoints ----------------------------------------------------------

    @router.get("/healthz")
    def healthz():
        s = _SETTINGS_HOT.get()
        return {"ok": True, "ts": time.time(), "version": _ADMIN_API_VERSION, "config_hash": s.config_hash()}

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
        return RuntimeOut(version=_ADMIN_API_VERSION, config_hash=s.config_hash(), settings=s.model_dump(), stats=stats)

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
            return {"policyset_ref": f"set@1#{digest[:12]}", "rules": [r.policy_ref() for r in rules]}

    @router.put("/policies", response_model=Dict[str, Any])
    def policies_put(ps: PolicySet):
        with _ADMIN_LOCK:
            ctx.policies.replace_rules(ps.rules or [])
            digest = _policy_digest(ctx.policies.rules())
            return {"ok": True, "policyset_ref": f"set@1#{digest[:12]}", "count": len(ctx.policies.rules())}

    @router.post("/policies/reload", response_model=Dict[str, Any])
    def policies_reload(req: ReloadRequest):
        with _ADMIN_LOCK:
            if req.source == "env":
                new_store = PolicyStore.from_env()
            else:
                if not req.path:
                    raise HTTPException(status_code=400, detail="path required when source=file")
                new_store = PolicyStore.from_file(req.path)
            ctx.policies.replace_rules(new_store.rules())
            digest = _policy_digest(ctx.policies.rules())
            return {"ok": True, "policyset_ref": f"set@1#{digest[:12]}", "count": len(ctx.policies.rules())}

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
    def receipt_get(head_hex: str):
        if not ctx.storage:
            return ReceiptGetOut(head_hex=head_hex, body_json=None, found=False)
        try:
            body = ctx.storage.get(head_hex)
        except Exception as e:
            logger.exception("storage.get failed: %s", e)
            raise HTTPException(status_code=500, detail="storage error")
        return ReceiptGetOut(head_hex=head_hex, body_json=body, found=bool(body))

    @router.get("/receipts/tail", response_model=ReceiptTailOut)
    def receipt_tail(n: int = 50):
        if not ctx.storage:
            return ReceiptTailOut(items=[], total=0)
        n = max(1, min(1000, int(n)))
        try:
            items = ctx.storage.tail(n)
        except Exception as e:
            logger.exception("storage.tail failed: %s", e)
            raise HTTPException(status_code=500, detail="storage error")
        return ReceiptTailOut(items=items, total=len(items))

    @router.post("/verify/receipt", response_model=VerifyOut)
    def verify_receipt_api(payload: VerifyReceiptIn):
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

    @router.post("/verify/chain", response_model=VerifyOut)
    def verify_chain_api(payload: VerifyChainIn):
        if len(payload.heads) != len(payload.bodies):
            raise HTTPException(status_code=400, detail="heads and bodies length mismatch")
        t0 = time.perf_counter()
        ok = verify_chain(payload.heads, payload.bodies, label_salt_hex=payload.label_salt_hex)
        dt = (time.perf_counter() - t0) * 1000.0
        return VerifyOut(ok=bool(ok), latency_ms=float(dt))

    # Alpha wealth probe (optional) ------------------------------------------

    @router.get("/alpha/{tenant}/{user}/{session}", response_model=AlphaOut)
    def alpha_state(tenant: str, user: str, session: str):
        state = None
        if ctx.alpha_probe_fn:
            try:
                state = ctx.alpha_probe_fn(tenant, user, session)
            except Exception as e:
                logger.warning("alpha_probe_fn failed: %s", e)
                state = {"error": "alpha_probe_fn failed"}
        return AlphaOut(tenant=tenant, user=user, session=session, state=state)

    # Settings hot-reload -----------------------------------------------------

    @router.get("/config")
    def config_get():
        s = _SETTINGS_HOT.get()
        return {"config_hash": s.config_hash(), "settings": s.model_dump()}

    @router.post("/config/reload")
    def config_reload():
        try:
            with _ADMIN_LOCK:
                _SETTINGS_HOT._reload()  # type: ignore[attr-defined]
        except Exception as e:
            logger.exception("settings reload failed: %s", e)
            raise HTTPException(status_code=500, detail="reload failed")
        s = _SETTINGS_HOT.get()
        return {"ok": True, "config_hash": s.config_hash()}

    app.include_router(router)
    return app