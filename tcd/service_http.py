# FILE: tcd/service_http.py
from __future__ import annotations

import hmac
import inspect
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from fastapi import (
    Depends,
    FastAPI,
    Header,
    HTTPException,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, Field, field_validator
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.middleware.cors import CORSMiddleware

from .config import make_reloadable_settings
from .detector import TCDConfig, TraceCollapseDetector
from .exporter import TCDPrometheusExporter
from .multivariate import MultiVarConfig, MultiVarDetector
from .otel_exporter import TCDOtelExporter
from .ratelimit import RateLimiter
from .routing import StrategyRouter
from .signals import DefaultLLMSignals, SignalProvider
from .telemetry_gpu import GpuSampler
from .utils import sanitize_floats
from .middleware import RequestContextMiddleware, RateLimitMiddleware, MetricsMiddleware

# receipts / PQ
from .attest import Attestor
from .kv import RollingHasher
from .receipt_v2 import build_v2_body
from .verify import verify_chain, verify_receipt

# optional structured logging (safe to import; noop if not configured)
try:  # pragma: no cover
    from .logging import bind_request_meta, ensure_request_id, get_logger, log_decision

    _HAS_LOG = True
except Exception:  # pragma: no cover
    _HAS_LOG = False
    bind_request_meta = ensure_request_id = get_logger = log_decision = None  # type: ignore[assignment]

# Always-valid alpha-risk controller (local stats budget)
from tcd.risk_av import AlwaysValidConfig, AlwaysValidRiskController
import tcd.risk_av  # noqa: F401  # side-effect: helps locating the module path in debug

# trust OS modules (best effort)
try:  # pragma: no cover
    from .decision_engine import DecisionContext, DecisionEngine
    from .agent import TrustAgent
    from .rewrite_engine import RewriteEngine
    from .trust_graph import TrustGraph
    from .patch_runtime import PatchRuntime

    _HAS_TRUST_OS = True
except Exception:  # pragma: no cover
    DecisionEngine = DecisionContext = TrustAgent = RewriteEngine = TrustGraph = PatchRuntime = None  # type: ignore
    _HAS_TRUST_OS = False


# ---------------------------------------------------------------------------
# Constants and service HTTP configuration (public plane only)
# ---------------------------------------------------------------------------


@dataclass
class ServiceHttpConfig:
    """
    Configuration for the public HTTP service plane.

    This is explicitly distinct from the admin/control plane:
    - only tenant/user/session-level subjects are exposed;
    - no PQ ledger control, only online inference + receipt endpoints;
    - focused on rate, payload, and e-process budget safety.
    """

    # API / docs
    api_version: str = "0.12.0"
    enable_docs: bool = False

    # Body-level defenses
    max_body_bytes: int = 1 * 1024 * 1024
    max_json_component_bytes: int = 256_000

    # Edge (IP/process) rate limiting (via RateLimitMiddleware)
    edge_rps: float = 10.0
    edge_burst: int = 20

    # Subject-level rate limiting defaults (per tenant/user/session)
    subject_capacity: float = 60.0
    subject_refill_per_s: float = 30.0

    # Verify chain window limits
    verify_window_max: int = 4096
    verify_chain_payload_factor: int = 256

    # Service-level access control (non-admin)
    require_service_token: bool = False
    allow_no_auth_local: bool = True
    service_token_env_var: str = "TCD_HTTP_SERVICE_TOKEN"

    # CORS
    cors_allow_all: bool = False
    cors_origins: Tuple[str, ...] = (
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://localhost",
        "http://localhost:3000",
    )

    # Receipts / PQ hints
    receipts_enable_default: bool = False
    hash_alg: str = "blake3"

    # Statistical budget defaults
    tokens_divisor_default: float = 50.0

    # Alpha budget guard
    alpha_wealth_floor: float = -1.0


@dataclass
class VerifyLimits:
    """
    Verification-specific limits.

    Keeps the verifier input surface tiny and predictable:
    - bounded chain length;
    - bounded hex string lengths;
    - bounded receipt body size.
    """

    max_head_hex_len: int = 130
    max_verify_key_hex_len: int = 200
    max_sig_hex_len: int = 200
    max_receipt_body_bytes: int = 512_000
    max_window: int = 4096
    chain_payload_factor: int = 256

    @property
    def max_chain_payload_bytes(self) -> int:
        return self.max_window * self.chain_payload_factor


def _split_env_list(name: str) -> List[str]:
    raw = os.getenv(name, "")
    return [x.strip() for x in raw.split(",") if x.strip()]


_HTTP_CFG = ServiceHttpConfig(
    api_version=os.getenv("TCD_HTTP_API_VERSION", "0.12.0"),
    enable_docs=os.getenv("TCD_HTTP_ENABLE_DOCS", "0") == "1",
    max_body_bytes=int(os.getenv("TCD_HTTP_MAX_BODY_BYTES", str(1 * 1024 * 1024))),
    max_json_component_bytes=int(os.getenv("TCD_HTTP_MAX_JSON_COMPONENT_BYTES", "256000")),
    edge_rps=float(os.getenv("TCD_HTTP_EDGE_RPS", "10")),
    edge_burst=int(os.getenv("TCD_HTTP_EDGE_BURST", "20")),
    subject_capacity=float(os.getenv("TCD_HTTP_SUBJECT_CAPACITY", "60")),
    subject_refill_per_s=float(os.getenv("TCD_HTTP_SUBJECT_REFILL_PER_S", "30")),
    verify_window_max=int(os.getenv("TCD_HTTP_VERIFY_WINDOW_MAX", "4096")),
    verify_chain_payload_factor=int(os.getenv("TCD_HTTP_VERIFY_CHAIN_PAYLOAD_FACTOR", "256")),
    require_service_token=os.getenv("TCD_HTTP_REQUIRE_TOKEN", "0") == "1",
    allow_no_auth_local=os.getenv("TCD_HTTP_ALLOW_NO_AUTH_LOCAL", "1") == "1",
    service_token_env_var=os.getenv("TCD_HTTP_SERVICE_TOKEN_ENV_VAR", "TCD_HTTP_SERVICE_TOKEN"),
    cors_allow_all=os.getenv("TCD_HTTP_CORS_ALLOW_ALL", "0") == "1",
    cors_origins=tuple(_split_env_list("TCD_HTTP_CORS_ORIGINS"))
    or (
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://localhost",
        "http://localhost:3000",
    ),
    receipts_enable_default=os.getenv("TCD_HTTP_RECEIPTS_ENABLE_DEFAULT", "0") == "1",
    hash_alg=os.getenv("TCD_HASH_ALG", "blake3"),
    tokens_divisor_default=float(os.getenv("TCD_HTTP_TOKENS_DIVISOR_DEFAULT", "50.0")),
    alpha_wealth_floor=float(os.getenv("TCD_HTTP_ALPHA_WEALTH_FLOOR", "-1.0")),
)

_VERIFY_LIMITS = VerifyLimits(
    max_head_hex_len=int(os.getenv("TCD_VERIFY_HEAD_HEX_MAXLEN", "130")),
    max_verify_key_hex_len=int(os.getenv("TCD_VERIFY_KEY_HEX_MAXLEN", "200")),
    max_sig_hex_len=int(os.getenv("TCD_VERIFY_SIG_HEX_MAXLEN", "200")),
    max_receipt_body_bytes=int(os.getenv("TCD_VERIFY_RECEIPT_BODY_MAXBYTES", "512000")),
    max_window=int(os.getenv("TCD_VERIFY_WINDOW_MAX", "4096")),
    chain_payload_factor=int(os.getenv("TCD_VERIFY_CHAIN_PAYLOAD_FACTOR", "256")),
)

_settings = make_reloadable_settings()
_SERVICE_TOKEN = (os.environ.get(_HTTP_CFG.service_token_env_var) or "").strip()

# Data vector bounds
_MAX_TRACE = 4096
_MAX_SPECT = 4096
_MAX_FEATS = 2048
_JSON_COMPONENT_LIMIT = _HTTP_CFG.max_json_component_bytes
_RECEIPT_BODY_LIMIT = _VERIFY_LIMITS.max_receipt_body_bytes
_TOKENS_DIVISOR_DEFAULT = _HTTP_CFG.tokens_divisor_default


# ---------------------------------------------------------------------------
# Pydantic I/O models
# ---------------------------------------------------------------------------


class DiagnoseRequest(BaseModel):
    trace_vector: List[float] = Field(default_factory=list)
    entropy: Optional[float] = None
    spectrum: List[float] = Field(default_factory=list)
    features: List[float] = Field(default_factory=list)
    step_id: Optional[int] = None

    model_id: str = "model0"
    gpu_id: str = "gpu0"
    task: str = "chat"
    lang: str = "en"
    tenant: str = "tenant0"
    user: str = "user0"
    session: str = "sess0"

    context: Dict[str, Any] = Field(default_factory=dict)
    tokens_delta: int = Field(50, ge=-10_000_000, le=10_000_000)
    drift_score: float = Field(0.0)

    @field_validator("trace_vector")
    @classmethod
    def _len_trace(cls, v: List[float]) -> List[float]:
        if len(v) > _MAX_TRACE:
            raise ValueError("trace_vector too large")
        return v

    @field_validator("spectrum")
    @classmethod
    def _len_spectrum(cls, v: List[float]) -> List[float]:
        if len(v) > _MAX_SPECT:
            raise ValueError("spectrum too large")
        return v

    @field_validator("features")
    @classmethod
    def _len_features(cls, v: List[float]) -> List[float]:
        if len(v) > _MAX_FEATS:
            raise ValueError("features too large")
        return v

    class Config:
        extra = "ignore"


class RiskResponse(BaseModel):
    verdict: bool
    score: float
    threshold: float
    budget_remaining: float
    components: Dict[str, Dict[str, Any]]
    cause: Optional[str] = None
    action: Optional[str] = None
    step: int
    e_value: float
    alpha_alloc: float
    alpha_spent: float

    receipt: Optional[str] = None
    receipt_body: Optional[str] = None
    receipt_sig: Optional[str] = None
    verify_key: Optional[str] = None

    class Config:
        extra = "ignore"


class SnapshotState(BaseModel):
    state: Dict[str, Any]

    class Config:
        extra = "ignore"


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


class VerifyRequest(BaseModel):
    receipt_head_hex: Optional[str] = Field(
        default=None,
        max_length=_VERIFY_LIMITS.max_head_hex_len,
    )
    receipt_body_json: Optional[str] = Field(
        default=None,
        max_length=_VERIFY_LIMITS.max_receipt_body_bytes,
    )
    verify_key_hex: Optional[str] = Field(
        default=None,
        max_length=_VERIFY_LIMITS.max_verify_key_hex_len,
    )
    receipt_sig_hex: Optional[str] = Field(
        default=None,
        max_length=_VERIFY_LIMITS.max_sig_hex_len,
    )

    req_obj: Optional[Dict[str, Any]] = None
    comp_obj: Optional[Dict[str, Any]] = None
    e_obj: Optional[Dict[str, Any]] = None
    witness_segments: Optional[Tuple[List[int], List[int], List[int]]] = None

    heads: Optional[List[str]] = None
    bodies: Optional[List[str]] = None

    @field_validator("receipt_head_hex", "verify_key_hex", "receipt_sig_hex")
    @classmethod
    def _hex_ok(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not _is_hex(v):
            raise ValueError("invalid hex")
        return v

    @field_validator("heads")
    @classmethod
    def _heads_hex(cls, v: Optional[List[str]]) -> Optional[List[str]]:
        if v is None:
            return v
        if any(not _is_hex(h) for h in v):
            raise ValueError("invalid head hex in list")
        return v

    class Config:
        extra = "ignore"


class VerifyResponse(BaseModel):
    ok: bool


# ---------------------------------------------------------------------------
# Internal helpers: math, JSON, subject keys
# ---------------------------------------------------------------------------


def _conservative_p_from_score(score: float) -> float:
    s = max(0.0, min(1.0, float(score)))
    p = 1.0 - s
    return max(1e-12, min(1.0, p))


def _quantize_to_u32(xs: List[float], *, scale: float = 1e6, cap: int = 64) -> List[int]:
    out: List[int] = []
    for v in xs[: max(0, cap)]:
        try:
            iv = int(abs(float(v)) * float(scale))
        except Exception:
            iv = 0
        out.append(iv & 0xFFFFFFFF)
    return out


def _safe_context_subset(ctx: Dict[str, Any]) -> Dict[str, Any]:
    allow_keys = {"decoder", "temperature", "top_p", "gpu_util", "gpu_temp_c", "p99_latency_ms"}
    return {k: ctx[k] for k in allow_keys if k in ctx}


def _compact_json(obj: Dict[str, Any]) -> str:
    txt = "" if obj is None else __import__("json").dumps(
        obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    )
    if len(txt.encode("utf-8")) > _JSON_COMPONENT_LIMIT:
        return "{}"
    return txt


def _subject_key(req: DiagnoseRequest) -> Tuple[str, str, str]:
    return (req.tenant, req.user, req.session)


# ---------------------------------------------------------------------------
# Structured helpers: metrics, policies, detectors, receipts, trust, auth
# ---------------------------------------------------------------------------


@dataclass
class HttpMetrics:
    """
    Wrapper over Prometheus HTTP instruments to keep usage structured.
    """

    req_counter: Counter
    req_latency: Histogram
    exporter: TCDPrometheusExporter

    def observe_http_latency(self, route: str, elapsed: float) -> None:
        self.req_latency.labels(route=route).observe(max(0.0, elapsed))

    def mark_request(self, route: str, status_code: int) -> None:
        self.req_counter.labels(route=route, status=str(status_code)).inc()

    def observe_core_latency(self, elapsed: float) -> None:
        self.exporter.observe_latency(max(0.0, elapsed))

    def record_verify_fail(self) -> None:
        self.exporter.slo_violation("verify_fail")


@dataclass
class SubjectPolicy:
    """
    Per-tenant / per-model micro policy for HTTP subject-level rate and token cost.
    """

    token_cost_divisor: float
    capacity: float
    refill_per_s: float

    @classmethod
    def from_base(
        cls,
        *,
        divisor: float,
        capacity: float,
        refill_per_s: float,
    ) -> "SubjectPolicy":
        return cls(
            token_cost_divisor=max(1.0, divisor),
            capacity=max(1.0, capacity),
            refill_per_s=max(0.1, refill_per_s),
        )


@dataclass
class SubjectPolicyManager:
    """
    Stateless view over subject policy table plus global defaults.
    """

    base_divisor: float
    base_capacity: float
    base_refill_per_s: float
    overrides: Dict[Tuple[str, str], SubjectPolicy] = field(default_factory=dict)

    def resolve(self, tenant: str, model_id: str) -> SubjectPolicy:
        override = self.overrides.get((tenant, model_id))
        if override is not None:
            return override
        return SubjectPolicy.from_base(
            divisor=self.base_divisor,
            capacity=self.base_capacity,
            refill_per_s=self.base_refill_per_s,
        )


@dataclass
class DetectorRegistry:
    """
    Thread-safe holders for main detectors and risk controllers.
    """

    settings: Any
    det_lock: threading.RLock = field(default_factory=threading.RLock)
    av_lock: threading.RLock = field(default_factory=threading.RLock)
    mv_lock: threading.RLock = field(default_factory=threading.RLock)

    detectors: Dict[Tuple[str, str, str, str], TraceCollapseDetector] = field(
        default_factory=dict
    )
    av_by_subject: Dict[Tuple[str, str, str], AlwaysValidRiskController] = field(
        default_factory=dict
    )
    mv_by_model: Dict[str, MultiVarDetector] = field(default_factory=dict)

    def get_trace_detector(self, key: Tuple[str, str, str, str]) -> TraceCollapseDetector:
        with self.det_lock:
            if key not in self.detectors:
                self.detectors[key] = TraceCollapseDetector(config=TCDConfig())
            return self.detectors[key]

    def get_alpha_controller(self, subject: Tuple[str, str, str]) -> AlwaysValidRiskController:
        with self.av_lock:
            if subject not in self.av_by_subject:
                self.av_by_subject[subject] = AlwaysValidRiskController(
                    AlwaysValidConfig(alpha_base=self.settings.alpha)
                )
            return self.av_by_subject[subject]

    def get_multivar_detector(self, model_id: str) -> MultiVarDetector:
        with self.mv_lock:
            if model_id not in self.mv_by_model:
                self.mv_by_model[model_id] = MultiVarDetector(
                    MultiVarConfig(estimator="lw", alpha=0.01)
                )
            return self.mv_by_model[model_id]


@dataclass
class RiskBudgetEnvelope:
    """
    Thin wrapper around alpha_budget/e-process outputs, so the HTTP layer can
    express decisions in one place.
    """

    e_value: float
    alpha_alloc: float
    alpha_wealth: float
    alpha_spent: float
    threshold: float
    triggered: bool

    @classmethod
    def from_av_out(cls, av_out: Dict[str, Any]) -> "RiskBudgetEnvelope":
        return cls(
            e_value=float(av_out.get("e_value", 1.0)),
            alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
            alpha_wealth=float(av_out.get("alpha_wealth", 0.0)),
            alpha_spent=float(av_out.get("alpha_spent", 0.0)),
            threshold=float(av_out.get("threshold", 0.0)),
            triggered=bool(av_out.get("trigger", False)),
        )

    def is_budget_exhausted(self, floor: float) -> bool:
        return self.alpha_wealth < floor


@dataclass
class ReceiptManager:
    """
    Encapsulates attestation/receipt issuance for /diagnose responses.
    """

    attestor: Optional[Attestor]
    hash_alg: str

    def issue(
        self,
        *,
        trace: List[float],
        spectrum: List[float],
        features: List[float],
        req: DiagnoseRequest,
        verdict_pack: Dict[str, Any],
        mv_info: Dict[str, Any],
        budget: RiskBudgetEnvelope,
        route: Any,
        p_final: float,
    ) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        if self.attestor is None:
            return None, None, None, None

        w_trace = _quantize_to_u32(trace)
        w_spec = _quantize_to_u32(spectrum)
        w_feat = _quantize_to_u32(features)

        kvh = RollingHasher(alg=self.hash_alg, ctx="tcd:kv")
        kvh.update_ints(w_trace)
        kvh.update_ints(w_spec)
        kvh.update_ints(w_feat)
        kv_digest = kvh.hex()

        meta_v2 = build_v2_body(
            model_hash=f"unknown:{req.model_id}",
            tokenizer_hash=f"unknown:{req.model_id}",
            sampler_cfg={
                "temperature": route.temperature,
                "top_p": route.top_p,
                "decoder": route.decoder,
                "seed": None,
            },
            context_len=len(trace),
            kv_digest=kv_digest,
            rng_seed=None,
            latency_ms=None,
            throughput_tok_s=None,
            batch_index=0,
            batch_size=1,
            e_snapshot={
                "e_value": budget.e_value,
                "p_final": float(p_final),
                "drift_score": float(req.drift_score or 0.0),
            },
        )

        req_obj: Dict[str, Any] = {
            "ts": time.time(),
            "tenant": req.tenant,
            "user": req.user,
            "session": req.session,
            "model_id": req.model_id,
            "gpu_id": req.gpu_id,
            "task": req.task,
            "lang": req.lang,
            "context": _safe_context_subset(req.context),
            "tokens_delta": int(req.tokens_delta),
            "step": int(verdict_pack.get("step", 0)),
        }
        comp_obj: Dict[str, Any] = {
            "score": float(verdict_pack.get("score", 0.0)),
            "p_final": float(p_final),
            "drift_score": float(req.drift_score or 0.0),
            "verdict": bool(verdict_pack.get("verdict", False)),
            "route": {
                "temperature": route.temperature,
                "top_p": route.top_p,
                "decoder": route.decoder,
                "tags": route.tags,
            },
            "components": verdict_pack.get("components", {}),
            "mv": mv_info,
        }
        e_obj: Dict[str, Any] = {
            "e_value": budget.e_value,
            "alpha_alloc": budget.alpha_alloc,
            "alpha_wealth": budget.alpha_wealth,
            "threshold": budget.threshold,
            "trigger": budget.triggered,
        }

        comp_obj = __import__("json").loads(_compact_json(comp_obj))
        req_obj = __import__("json").loads(_compact_json(req_obj))
        e_obj = __import__("json").loads(_compact_json(e_obj))

        rcpt = self.attestor.issue(
            req_obj=req_obj,
            comp_obj=comp_obj,
            e_obj=e_obj,
            witness_segments=(w_trace, w_spec, w_feat),
            witness_tags=("trace", "spectrum", "feat"),
            meta=meta_v2,
        )

        head = rcpt.get("receipt")
        body = rcpt.get("receipt_body")
        sig = rcpt.get("receipt_sig")
        vk = rcpt.get("verify_key")
        return head, body, sig, vk


@dataclass
class TrustRuntimeWrapper:
    """
    Optional wrapper for Trust OS stack: exposes a single `classify` hook.
    """

    runtime: Optional[Dict[str, Any]]

    def classify(self, *, score: float, decision_fail: bool) -> str:
        if not self.runtime or not _HAS_TRUST_OS:
            return "degrade" if decision_fail else "allow"
        try:
            ctx = DecisionContext(score=score, verdict=decision_fail)
            obj = self.runtime["decision_engine"].decide(ctx)
            return getattr(obj, "value", str(obj))
        except Exception:
            return "degrade" if decision_fail else "allow"


class ServiceTokenAuth:
    """
    Service-level token guard (non-admin) for stateful endpoints.

    This is intentionally lightweight: a single shared token for the process,
    plus an option to allow unauthenticated local traffic for simple dev setups.
    """

    def __init__(self, cfg: ServiceHttpConfig, service_token: str) -> None:
        self.cfg = cfg
        self.token = service_token

    def __call__(
        self,
        x_token: Optional[str] = Header(default=None, alias="X-TCD-Service-Token"),
    ) -> None:
        if not self.cfg.require_service_token:
            return

        target = self.token
        if not target:
            if self.cfg.allow_no_auth_local:
                return
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="service token required",
            )

        if not x_token or len(x_token) != len(target):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="forbidden",
            )

        if not hmac.compare_digest(x_token, target):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="forbidden",
            )


# ---------------------------------------------------------------------------
# App factory: public HTTP sidecar surface
# ---------------------------------------------------------------------------


def create_app(*args, **kwargs) -> FastAPI:
    """
    Build the public HTTP sidecar surface.

    This is NOT the admin/control plane; it is strictly subject-facing and
    exposes:

    - /diagnose + /v1/diagnose: risk scoring + routing + receipts;
    - /verify: chain / single-receipt verification;
    - health/readiness/version + minimal state endpoints.

    All heavy PQ ledger, audit, and admin configuration lives elsewhere.
    """
    openapi_url = "/openapi.json" if _HTTP_CFG.enable_docs else None
    docs_url = "/docs" if _HTTP_CFG.enable_docs else None
    redoc_url = "/redoc" if _HTTP_CFG.enable_docs else None

    app = FastAPI(
        title="tcd-sidecar",
        version=_HTTP_CFG.api_version,
        openapi_url=openapi_url,
        docs_url=docs_url,
        redoc_url=redoc_url,
    )

    settings = _settings.get()

    # Respect settings flags (with safe defaults)
    settings.gpu_enable = bool(getattr(settings, "gpu_enable", False))
    settings.otel_enable = bool(getattr(settings, "otel_enable", False))

    prom_exporter = TCDPrometheusExporter(
        port=settings.prometheus_port,
        version=_HTTP_CFG.api_version,
        config_hash=settings.config_hash(),
    )
    if settings.prom_http_enable:
        prom_exporter.ensure_server()

    otel = TCDOtelExporter()
    otel.enabled = settings.otel_enable

    logger = get_logger("tcd.http") if _HAS_LOG else None

    # CORS: explicit allow-list or allow-all
    allowed_origins = ["*"] if _HTTP_CFG.cors_allow_all else list(_HTTP_CFG.cors_origins)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-Request-Id",
            "X-Session-Id",
            "X-TCD-Http-Version",
            "X-TCD-Config-Hash",
        ],
    )

    # Prometheus instruments for HTTP layer (coarse)
    req_counter = Counter(
        "tcd_requests_total",
        "HTTP requests",
        ["route", "status"],
    )
    req_latency = Histogram(
        "tcd_request_latency_seconds",
        "HTTP request latency in seconds",
        ["route"],
    )
    http_metrics = HttpMetrics(
        req_counter=req_counter,
        req_latency=req_latency,
        exporter=prom_exporter,
    )

    # Edge middlewares: body size guard, context, per-IP rate limit, metrics
    @app.middleware("http")
    async def body_size_and_version_guard(request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                cl_v = int(cl)
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="invalid content-length",
                )
            if cl_v > _HTTP_CFG.max_body_bytes:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail="body too large",
                )

        t0 = time.perf_counter()
        route_path = request.scope.get("path", "unknown")

        response = await call_next(request)
        elapsed = max(0.0, time.perf_counter() - t0)

        http_metrics.observe_http_latency(route_path, elapsed)
        http_metrics.mark_request(route_path, response.status_code)

        # Attach version + config hash
        response.headers["X-TCD-Http-Version"] = _HTTP_CFG.api_version
        try:
            response.headers["X-TCD-Config-Hash"] = settings.config_hash()
        except Exception:
            pass
        return response

    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        rate_per_sec=_HTTP_CFG.edge_rps,
        burst=_HTTP_CFG.edge_burst,
    )
    app.add_middleware(
        MetricsMiddleware,
        counter=req_counter,
        histogram=req_latency,
    )

    # /metrics: default registry, used as sidecar scrape target
    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # Signals and GPU sampler (optional)
    signals: SignalProvider = DefaultLLMSignals()
    gpu_sampler = GpuSampler(0) if settings.gpu_enable else None

    # Subject-level token bucket (tenant/user/session)
    rate_limiter = RateLimiter(
        capacity=float(getattr(settings, "http_rate_capacity", _HTTP_CFG.subject_capacity)),
        refill_per_s=float(getattr(settings, "http_rate_refill_per_s", _HTTP_CFG.subject_refill_per_s)),
    )

    # Core registries and helpers
    registry = DetectorRegistry(settings=settings)
    router = StrategyRouter()

    # Receipts
    receipts_enable = os.environ.get(
        "TCD_RECEIPTS_ENABLE",
        "1" if _HTTP_CFG.receipts_enable_default else "0",
    ) == "1"
    attestor = Attestor(hash_alg=_HTTP_CFG.hash_alg) if receipts_enable else None
    receipt_mgr = ReceiptManager(attestor=attestor, hash_alg=_HTTP_CFG.hash_alg)

    # Subject policies: can be wired from settings/admin plane later
    policy_mgr = SubjectPolicyManager(
        base_divisor=float(
            getattr(settings, "token_cost_divisor_default", _TOKENS_DIVISOR_DEFAULT)
            or _TOKENS_DIVISOR_DEFAULT
        ),
        base_capacity=float(getattr(settings, "http_rate_capacity", _HTTP_CFG.subject_capacity)),
        base_refill_per_s=float(
            getattr(settings, "http_rate_refill_per_s", _HTTP_CFG.subject_refill_per_s)
        ),
        overrides={
            # Example override (can be filled by admin plane later):
            # ("tenant_tier1", "gpt-4.1-mini"): SubjectPolicy.from_base(
            #     divisor=25.0,
            #     capacity=30.0,
            #     refill_per_s=10.0,
            # ),
        },
    )

    # Trust runtime (best effort)
    trust_runtime: Optional[Dict[str, Any]] = None
    if _HAS_TRUST_OS:
        try:
            decision_engine = DecisionEngine()
            agent = TrustAgent()
            rewriter = RewriteEngine()
            trust_graph = TrustGraph()
            patch_runtime = PatchRuntime()
            trust_runtime = {
                "decision_engine": decision_engine,
                "agent": agent,
                "rewriter": rewriter,
                "trust_graph": trust_graph,
                "patch_runtime": patch_runtime,
            }
            app.state.trust_runtime = trust_runtime
        except Exception:
            trust_runtime = None

    trust_wrapper = TrustRuntimeWrapper(runtime=trust_runtime)

    # Service-level token guard
    token_guard = ServiceTokenAuth(cfg=_HTTP_CFG, service_token=_SERVICE_TOKEN)

    # -----------------------------------------------------------------------
    # Small internal helpers used only in endpoint scope
    # -----------------------------------------------------------------------

    def _alpha_budget_or_fail(
        av_out: Dict[str, Any],
        tenant: str,
        user: str,
        session: str,
    ) -> RiskBudgetEnvelope:
        budget = RiskBudgetEnvelope.from_av_out(av_out)
        if budget.is_budget_exhausted(_HTTP_CFG.alpha_wealth_floor):
            prom_exporter.throttle(tenant, user, session, reason="alpha_budget")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="alpha budget exhausted",
            )
        return budget

    def _apply_subject_policy_and_charge(
        req: DiagnoseRequest,
    ) -> float:
        tokens_delta = max(0.0, float(req.tokens_delta or 0))
        policy = policy_mgr.resolve(req.tenant, req.model_id)

        # Dynamically adjust subject-level limiter (single shared limiter)
        rate_limiter.capacity = policy.capacity
        rate_limiter.refill_per_s = policy.refill_per_s

        cost = max(1.0, tokens_delta / max(1.0, policy.token_cost_divisor))
        subject_key = _subject_key(req)
        if not rate_limiter.consume(subject_key, cost=cost):
            prom_exporter.throttle(req.tenant, req.user, req.session, reason="rate")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="rate limited",
            )
        return cost

    # -----------------------------------------------------------------------
    # Endpoints: health / ready / version / state
    # -----------------------------------------------------------------------

    @app.get("/healthz")
    def healthz() -> Dict[str, Any]:
        if logger is not None:
            logger.debug(
                "healthz",
                extra={
                    "trust_os_available": _HAS_TRUST_OS,
                    "trust_runtime_present": trust_runtime is not None,
                },
            )
        return {
            "ok": True,
            "config_hash": settings.config_hash(),
            "http_version": _HTTP_CFG.api_version,
            "otel": bool(otel.enabled),
            "prom": True,
            "receipts": bool(receipts_enable),
            "trust_os": bool(trust_runtime is not None),
        }

    @app.get("/readyz")
    def readyz() -> Dict[str, Any]:
        return {
            "ready": True,
            "prom_http": bool(settings.prom_http_enable),
            "http_version": _HTTP_CFG.api_version,
        }

    @app.get("/version")
    def version() -> Dict[str, Any]:
        return {
            "version": _HTTP_CFG.api_version,
            "config_version": settings.config_version,
            "alpha": settings.alpha,
            "slo_latency_ms": settings.slo_latency_ms,
        }

    @app.get("/state/get")
    def state_get(
        model_id: str = "model0",
        gpu_id: str = "gpu0",
        task: str = "chat",
        lang: str = "en",
        _auth: None = Depends(token_guard),
    ) -> Dict[str, Any]:
        det = registry.get_trace_detector((model_id, gpu_id, task, lang))
        return {"detector": det.snapshot_state()}

    @app.post("/state/load")
    def state_load(
        payload: SnapshotState,
        model_id: str = "model0",
        gpu_id: str = "gpu0",
        task: str = "chat",
        lang: str = "en",
        _auth: None = Depends(token_guard),
    ) -> Dict[str, Any]:
        det = registry.get_trace_detector((model_id, gpu_id, task, lang))
        det.load_state(payload.state)
        return {"ok": True}

    # -----------------------------------------------------------------------
    # /diagnose: main risk scoring + routing + receipts
    # -----------------------------------------------------------------------

    @app.post("/diagnose", response_model=RiskResponse)
    def diagnose(
        req: DiagnoseRequest,
        request: Request,
        response: Response,
        _auth: None = Depends(token_guard),
    ) -> RiskResponse:
        t_start = time.perf_counter()

        # request id + logging meta
        if _HAS_LOG and ensure_request_id is not None:
            rid = ensure_request_id(dict(request.headers))
        else:
            rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        response.headers["X-Request-Id"] = rid
        response.headers["X-Session-Id"] = req.session

        if _HAS_LOG and bind_request_meta is not None:
            bind_request_meta(
                tenant=req.tenant,
                user=req.user,
                session=req.session,
                model_id=req.model_id,
                gpu_id=req.gpu_id,
                task=req.task,
                lang=req.lang,
                path="/diagnose",
                method="POST",
            )

        # Subject policy + rate limiting
        _ = _apply_subject_policy_and_charge(req)

        # GPU context enrichment (best effort)
        if gpu_sampler is not None:
            try:
                req.context.update(gpu_sampler.sample())
            except Exception:
                pass

        # Sanitize numeric arrays
        trace_vec = sanitize_floats(req.trace_vector)
        spectrum = sanitize_floats(req.spectrum)
        features = sanitize_floats(req.features)

        # Core detectors
        det_key = (req.model_id, req.gpu_id, req.task, req.lang)
        det = registry.get_trace_detector(det_key)
        verdict_pack = det.diagnose(
            trace_vec,
            req.entropy,
            spectrum,
            step_id=req.step_id,
        )

        mv_info: Dict[str, Any] = {}
        if features:
            try:
                mv = registry.get_multivar_detector(req.model_id)
                mv_info = mv.decision(np.asarray(features, dtype=float))
            except Exception:
                mv_info = {}

        score = float(verdict_pack.get("score", 0.0))
        p_final = _conservative_p_from_score(score)

        # Alpha budget / e-process envelope
        subject = (req.tenant, req.user, req.session)
        av = registry.get_alpha_controller(subject)
        av_out = av.step(request)
        budget = _alpha_budget_or_fail(
            av_out,
            tenant=req.tenant,
            user=req.user,
            session=req.session,
        )

        # Combined decision
        decision_fail = bool(
            verdict_pack.get("verdict", False) or budget.triggered
        )

        # Routing
        route = router.decide(
            decision_fail,
            score,
            base_temp=float(req.context.get("temperature", 0.7)),
            base_top_p=float(req.context.get("top_p", 0.9)),
        )

        # Trust OS label
        action_str = trust_wrapper.classify(score=score, decision_fail=decision_fail)

        # Receipts
        rcpt_head = rcpt_body = rcpt_sig = vk_hex = None
        if receipts_enable:
            try:
                rcpt_head, rcpt_body, rcpt_sig, vk_hex = receipt_mgr.issue(
                    trace=trace_vec,
                    spectrum=spectrum,
                    features=features,
                    req=req,
                    verdict_pack=verdict_pack,
                    mv_info=mv_info,
                    budget=budget,
                    route=route,
                    p_final=p_final,
                )
                if (
                    isinstance(rcpt_body, str)
                    and len(rcpt_body.encode("utf-8")) > _RECEIPT_BODY_LIMIT
                ):
                    rcpt_body = None

                if otel.enabled:
                    try:
                        size_bytes = (
                            len(rcpt_body.encode("utf-8"))
                            if isinstance(rcpt_body, str)
                            else 0
                        )
                        otel.push_metrics(
                            score,
                            attrs={
                                "tcd.receipt.present": rcpt_body is not None,
                                "tcd.receipt.size_bytes": size_bytes,
                                "tcd.decision.verdict": str(decision_fail),
                                "tcd.p_final": float(p_final),
                                "model_id": req.model_id,
                                "gpu_id": req.gpu_id,
                                "tenant": req.tenant,
                                "user": req.user,
                                "session": req.session,
                            },
                        )
                    except Exception:
                        pass
            except Exception:
                if otel.enabled:
                    otel.push_metrics(
                        score,
                        attrs={"tcd.receipt.present": False},
                    )

        # Metrics
        latency_s = max(0.0, time.perf_counter() - t_start)
        http_metrics.observe_core_latency(latency_s)

        prom_exporter.push(
            verdict_pack,
            labels={"model_id": req.model_id, "gpu_id": req.gpu_id},
        )
        prom_exporter.push_eprocess(
            model_id=req.model_id,
            gpu_id=req.gpu_id,
            tenant=req.tenant,
            user=req.user,
            session=req.session,
            e_value=budget.e_value,
            alpha_alloc=budget.alpha_alloc,
            alpha_wealth=budget.alpha_wealth,
        )
        prom_exporter.update_budget_metrics(
            req.tenant,
            req.user,
            req.session,
            remaining=budget.alpha_wealth,
            spent=bool(budget.alpha_spent > 0.0),
        )
        if decision_fail:
            prom_exporter.record_action(req.model_id, req.gpu_id, action="degrade")

        otel.push_metrics(
            score,
            attrs={
                "model_id": req.model_id,
                "gpu_id": req.gpu_id,
                "tenant": req.tenant,
                "user": req.user,
                "session": req.session,
            },
        )

        if (latency_s * 1000.0) > float(settings.slo_latency_ms):
            prom_exporter.slo_violation_by_model(
                "diagnose_latency",
                req.model_id,
                req.gpu_id,
            )

        if _HAS_LOG and log_decision is not None and logger is not None:
            try:
                log_decision(
                    logger,
                    verdict=decision_fail,
                    score=score,
                    e_value=budget.e_value,
                    alpha_alloc=budget.alpha_alloc,
                    message="diagnose",
                    extra={
                        "route_decoder": route.decoder,
                        "route_temp": route.temperature,
                        "route_top_p": route.top_p,
                        "action": action_str,
                        "p_final": float(p_final),
                    },
                )
            except Exception:
                pass

        return RiskResponse(
            verdict=bool(decision_fail),
            score=score,
            threshold=budget.threshold,
            budget_remaining=budget.alpha_wealth,
            components=verdict_pack.get("components", {}),
            cause=(
                "detector"
                if verdict_pack.get("verdict", False)
                else ("av" if budget.triggered else "")
            ),
            action=action_str,
            step=int(verdict_pack.get("step", 0)),
            e_value=budget.e_value,
            alpha_alloc=budget.alpha_alloc,
            alpha_spent=budget.alpha_spent,
            receipt=rcpt_head,
            receipt_body=rcpt_body,
            receipt_sig=rcpt_sig,
            verify_key=vk_hex,
        )

    @app.post("/v1/diagnose", response_model=RiskResponse)
    def diagnose_v1(
        req: DiagnoseRequest,
        request: Request,
        response: Response,
        _auth: None = Depends(token_guard),
    ) -> RiskResponse:
        # Backwards-compatible alias
        return diagnose(req, request, response, _auth=_auth)

    # -----------------------------------------------------------------------
    # /verify: chain verify + single receipt verify with strong guards
    # -----------------------------------------------------------------------

    def _validate_chain_mode(req: VerifyRequest) -> None:
        if (
            not isinstance(req.heads, list)
            or not isinstance(req.bodies, list)
            or len(req.heads) != len(req.bodies)
            or len(req.heads) == 0
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="heads/bodies invalid",
            )
        if len(req.heads) > _VERIFY_LIMITS.max_window:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="window too large",
            )

        total_len = sum(len(h or "") for h in req.heads) + sum(
            len(b or "") for b in req.bodies
        )
        if total_len > _VERIFY_LIMITS.max_chain_payload_bytes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="verify payload too large",
            )

    def _validate_single_mode(req: VerifyRequest) -> None:
        if not req.receipt_head_hex or not req.receipt_body_json:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="missing receipt head/body",
            )
        body_bytes = len(req.receipt_body_json.encode("utf-8"))
        if body_bytes > _VERIFY_LIMITS.max_receipt_body_bytes:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="receipt body too large",
            )

        if req.witness_segments is not None:
            ws = req.witness_segments
            if len(ws) != 3 or any(not isinstance(seg, list) for seg in ws):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="witness_segments must be triple of int lists",
                )
            total = len(ws[0]) + len(ws[1]) + len(ws[2])
            if total > (_MAX_TRACE + _MAX_SPECT + _MAX_FEATS):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="witness too large",
                )

    @app.post("/verify", response_model=VerifyResponse)
    def verify(
        req: VerifyRequest,
        request: Request,
        response: Response,
        _auth: None = Depends(token_guard),
    ) -> VerifyResponse:
        if _HAS_LOG and ensure_request_id is not None:
            rid = ensure_request_id(dict(request.headers))
        else:
            rid = request.headers.get("x-request-id") or uuid.uuid4().hex[:16]
        response.headers["X-Request-Id"] = rid

        t0 = time.perf_counter()
        ok = False
        try:
            if req.heads is not None or req.bodies is not None:
                # chain verify mode
                _validate_chain_mode(req)
                ok = bool(verify_chain(req.heads or [], req.bodies or []))
            else:
                # single receipt verify mode
                _validate_single_mode(req)

                ws: Optional[Tuple[List[int], List[int], List[int]]] = None
                if req.witness_segments is not None:
                    ws = (
                        req.witness_segments[0],
                        req.witness_segments[1],
                        req.witness_segments[2],
                    )

                ok = bool(
                    verify_receipt(
                        receipt_head_hex=req.receipt_head_hex,
                        receipt_body_json=req.receipt_body_json,
                        verify_key_hex=req.verify_key_hex,
                        receipt_sig_hex=req.receipt_sig_hex,
                        req_obj=req.req_obj,
                        comp_obj=req.comp_obj,
                        e_obj=req.e_obj,
                        witness_segments=ws,
                        strict=True,
                    )
                )
        finally:
            latency = max(0.0, time.perf_counter() - t0)
            http_metrics.observe_core_latency(latency)
            if not ok:
                http_metrics.exporter.slo_violation("verify_fail")

        return VerifyResponse(ok=ok)

    # Debug prints are intentionally removed; all debug information should go
    # through the logger if structured logging is enabled.

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        create_app(),
        host="127.0.0.1",
        port=8000,
        reload=True,
    )