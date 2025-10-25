# FILE: tcd/service_grpc.py
"""
gRPC service shim for TCD — mirrors the HTTP semantics (/diagnose, /verify) while
remaining an optional, non-entry dependency. This module:
  - Only activates if `grpcio` and generated stubs (`tcd/proto/*_pb2*.py`) are importable.
  - Reuses the same decision pipeline as HTTP (detector + AV + routing + metrics).
  - Adds production guardrails: deadlines, rate limiting, structured errors, input limits.
  - Exposes `register_grpc_services(server, runtime=None)` that safely no-ops if stubs missing.

Proto expectations (not bundled here):
  service TcdService {
    rpc Diagnose(DiagnoseRequest) returns (RiskResponse);
    rpc Verify(VerifyRequest) returns (VerifyResponse);
  }
"""
from __future__ import annotations

import json
import threading
import time
from typing import Dict, List, Optional, Tuple

# Optional dependency: grpc + generated stubs
try:
    import grpc  # type: ignore
    _HAS_GRPC = True
except Exception:  # pragma: no cover
    grpc = None  # type: ignore
    _HAS_GRPC = False

try:
    # Expect files like: tcd/proto/tcd_pb2.py, tcd/proto/tcd_pb2_grpc.py
    from .proto import tcd_pb2 as pb  # type: ignore
    from .proto import tcd_pb2_grpc as pb_grpc  # type: ignore
    _HAS_STUBS = True
except Exception:  # pragma: no cover
    pb = None  # type: ignore
    pb_grpc = None  # type: ignore
    _HAS_STUBS = False

# Shared pipeline bits (aligned with HTTP service)
from .config import make_reloadable_settings
from .detector import TCDConfig, TraceCollapseDetector
from .exporter import TCDPrometheusExporter
from .multivariate import MultiVarConfig, MultiVarDetector
from .otel_exporter import TCDOtelExporter
from .ratelimit import RateLimiter
from .risk_av import AlwaysValidConfig, AlwaysValidRiskController
from .routing import StrategyRouter
from .utils import sanitize_floats
from .verify import verify_chain, verify_receipt

_settings = make_reloadable_settings()


# ---------- Utilities & Conversions ----------

_MAX_TRACE = 8192
_MAX_SPECT = 8192
_MAX_FEATS = 4096
_JSON_COMPONENT_LIMIT = 256_000  # guard against huge blobs (bytes when utf-8 encoded)

def _p_cons(score: float) -> float:
    """Conservative monotone map score∈[0,1] → p∈(0,1]; higher score = smaller p."""
    s = max(0.0, min(1.0, float(score)))
    return max(1e-12, 1.0 - s)

def _has_field(msg, name: str) -> bool:
    """Proto2/Proto3 friendly presence check."""
    try:
        return msg.HasField(name)  # type: ignore[attr-defined]
    except Exception:
        # Fallback: presence is not guaranteed; treat falsy default as "absent".
        return getattr(msg, name, None) is not None

def _err(context: "grpc.ServicerContext", code, msg: str) -> None:  # type: ignore[name-defined]
    if not _HAS_GRPC:  # pragma: no cover
        return
    context.set_code(code)
    context.set_details(msg)

def _time_ok(context: "grpc.ServicerContext", min_remaining_s: float = 0.001) -> bool:  # type: ignore[name-defined]
    """Check that there is still time before the client's deadline (if any)."""
    try:
        rem = context.time_remaining()
        return (rem is None) or (rem > min_remaining_s)
    except Exception:  # pragma: no cover
        return True

def _canonical_json(obj: Dict) -> str:
    txt = json.dumps(obj or {}, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    # enforce an upper bound to avoid response bloat
    if len(txt.encode("utf-8")) > _JSON_COMPONENT_LIMIT:
        return "{}"
    return txt

def _subject_from_md(context, req) -> Tuple[str, str, str]:
    """
    Resolve (tenant, user, session) with metadata taking precedence, then proto fields, then defaults.
    """
    t = getattr(req, "tenant", "") or ""
    u = getattr(req, "user", "") or ""
    s = getattr(req, "session", "") or ""
    try:
        md = {k.lower(): v for k, v in (context.invocation_metadata() or [])}  # type: ignore[attr-defined]
    except Exception:
        md = {}
    tenant = md.get("x-tenant", "") or t or "tenant0"
    user = md.get("x-user", "") or u or "user0"
    sess = md.get("x-session", "") or s or "sess0"
    return (tenant, user, sess)


# ---------- Core runtime (mirrors HTTP create_app pipeline) ----------

class _Runtime:
    """
    Holds long-lived singletons (detectors, AV controllers, metrics, etc.).
    Allows lightweight test injection and hot-reload of settings.
    """

    def __init__(
        self,
        *,
        prom: Optional[TCDPrometheusExporter] = None,
        otel: Optional[TCDOtelExporter] = None,
        rlim: Optional[RateLimiter] = None,
    ):
        self.settings = _settings.get()

        self.prom = prom or TCDPrometheusExporter(
            port=self.settings.prometheus_port,
            version=self.settings.version or "0.10.2",
            config_hash=self.settings.config_hash(),
        )
        if self.settings.prom_http_enable:
            self.prom.ensure_server()

        self.otel = otel or TCDOtelExporter(endpoint=self.settings.otel_endpoint)

        self.rlim = rlim or RateLimiter(
            capacity=float(getattr(self.settings, "grpc_rate_capacity", 120.0)),
            refill_per_s=float(getattr(self.settings, "grpc_rate_refill_per_s", 60.0)),
        )

        self.det_lock = threading.RLock()
        self.detectors: Dict[Tuple[str, str, str, str], TraceCollapseDetector] = {}

        self.av_lock = threading.RLock()
        self.av_by_subject: Dict[Tuple[str, str, str], AlwaysValidRiskController] = {}

        self.mv_lock = threading.RLock()
        self.mv_by_model: Dict[str, MultiVarDetector] = {}

        self.router = StrategyRouter()

    # Accessors
    def get_detector(self, key: Tuple[str, str, str, str]) -> TraceCollapseDetector:
        with self.det_lock:
            inst = self.detectors.get(key)
            if inst is None:
                inst = TraceCollapseDetector(config=TCDConfig())
                self.detectors[key] = inst
            return inst

    def get_av(self, subject: Tuple[str, str, str]) -> AlwaysValidRiskController:
        with self.av_lock:
            inst = self.av_by_subject.get(subject)
            if inst is None:
                inst = AlwaysValidRiskController(AlwaysValidConfig(alpha_base=self.settings.alpha))
                self.av_by_subject[subject] = inst
            return inst

    def get_mv(self, model_id: str) -> MultiVarDetector:
        with self.mv_lock:
            inst = self.mv_by_model.get(model_id)
            if inst is None:
                inst = MultiVarDetector(MultiVarConfig(estimator="lw", alpha=0.01))
                self.mv_by_model[model_id] = inst
            return inst


_runtime: Optional[_Runtime] = None


def _rt() -> _Runtime:
    global _runtime
    if _runtime is None:
        _runtime = _Runtime()
    return _runtime


# ---------- Service Implementation (only if stubs exist) ----------

if _HAS_GRPC and _HAS_STUBS:

    class TcdService(pb_grpc.TcdServiceServicer):  # type: ignore
        """
        gRPC service implementing Diagnose/Verify with semantics consistent with HTTP endpoints.
        """

        # -------- Diagnose --------
        def Diagnose(self, request: "pb.DiagnoseRequest", context: "grpc.ServicerContext"):  # type: ignore
            rt = _rt()
            t0 = time.perf_counter()

            # Deadline/cancellation pre-check
            if not _time_ok(context):
                _err(context, grpc.StatusCode.DEADLINE_EXCEEDED, "deadline exceeded")  # type: ignore
                return pb.RiskResponse(verdict=False, score=0.0, threshold=0.0, budget_remaining=0.0,  # type: ignore
                                       components="{}", cause="deadline", action="reject", step=0,
                                       e_value=1.0, alpha_alloc=0.0, alpha_spent=0.0)

            # Basic payload limits to guard against abuse
            if (len(request.trace_vector) > _MAX_TRACE or
                len(request.spectrum) > _MAX_SPECT or
                len(request.features) > _MAX_FEATS):
                _err(context, grpc.StatusCode.INVALID_ARGUMENT, "payload too large")  # type: ignore
                return pb.RiskResponse(  # type: ignore
                    verdict=False, score=0.0, threshold=0.0, budget_remaining=0.0,
                    components=_canonical_json({"error": "payload_too_large"}),
                    cause="limit", action="reject", step=0, e_value=1.0, alpha_alloc=0.0, alpha_spent=0.0
                )

            # Subject + rate limit
            subject = _subject_from_md(context, request)
            tokens_delta = float(getattr(request, "tokens_delta", 0.0) or 0.0)
            divisor = float(getattr(rt.settings, "token_cost_divisor_default", 50.0) or 50.0)
            cost = max(1.0, tokens_delta / max(1.0, divisor))
            if not rt.rlim.consume(subject, cost=cost):
                rt.prom.throttle(*subject, reason="rate")
                _err(context, grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limited")  # type: ignore
                return pb.RiskResponse(  # type: ignore
                    verdict=False, score=0.0, threshold=0.0, budget_remaining=0.0,
                    components=_canonical_json({"error": "rate_limited"}),
                    cause="rate", action="reject", step=0, e_value=1.0, alpha_alloc=0.0, alpha_spent=0.0
                )

            # Sanitize arrays
            trace_vec, _ = sanitize_floats(list(request.trace_vector), max_len=_MAX_TRACE)
            spectrum, _ = sanitize_floats(list(request.spectrum), max_len=_MAX_SPECT)
            features, _ = sanitize_floats(list(request.features), max_len=_MAX_FEATS)

            # Diagnose via detector (hysteresis inside)
            dkey = (
                request.model_id or "model0",
                request.gpu_id or "gpu0",
                request.task or "chat",
                request.lang or "en",
            )
            det = rt.get_detector(dkey)

            entropy = None
            if _has_field(request, "entropy"):
                try:
                    entropy = float(request.entropy)
                except Exception:
                    entropy = None

            vp = det.diagnose(trace_vec, entropy, spectrum, step_id=(request.step_id if getattr(request, "step_id", "") else None))

            # Optional multivariate score (aux only)
            mv_info = {}
            if len(features) > 0:
                try:
                    mv = rt.get_mv(request.model_id or "model0")
                    mv_info = mv.decision(features)  # returns dict
                except Exception:
                    mv_info = {}

            # Score → conservative p-value
            score = float(vp.get("score", 0.0))
            p_final = _p_cons(score)

            # AV controller step
            drift_score = 0.0
            if _has_field(request, "drift_score"):
                try:
                    drift_score = float(request.drift_score)
                except Exception:
                    drift_score = 0.0
            drift_w = max(0.0, min(2.0, 1.0 + 0.5 * drift_score))

            av = rt.get_av(subject)
            av_out = av.step(
                policy_key=(request.task or "chat", request.lang or "en", request.model_id or "model0"),
                subject=subject,
                scores={"final": score},
                pvals={"final": p_final},
                drift_weight=drift_w,
            )

            decision_fail = bool(vp.get("verdict", False) or av_out.get("trigger", False))

            # Metrics
            latency_s = max(0.0, time.perf_counter() - t0)
            rt.prom.observe_latency(latency_s)
            rt.prom.push(vp, labels={"model_id": request.model_id or "model0", "gpu_id": request.gpu_id or "gpu0"})
            rt.prom.push_eprocess(
                model_id=request.model_id or "model0",
                gpu_id=request.gpu_id or "gpu0",
                tenant=subject[0],
                user=subject[1],
                session=subject[2],
                e_value=float(av_out.get("e_value", 1.0)),
                alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
                alpha_wealth=float(av_out.get("alpha_wealth", 0.0)),
            )
            rt.prom.update_budget_metrics(
                subject[0], subject[1], subject[2],
                remaining=float(av_out.get("alpha_wealth", 0.0)),
                spent=bool(av_out.get("alpha_spent", 0.0) > 0.0),
            )
            if decision_fail:
                rt.prom.record_action(request.model_id or "model0", request.gpu_id or "gpu0", action="degrade")
            slo_ms = float(getattr(rt.settings, "slo_latency_ms", 0.0) or 0.0)
            if slo_ms and (latency_s * 1000.0) > slo_ms:
                rt.prom.slo_violation_by_model("diagnose_latency", request.model_id or "model0", request.gpu_id or "gpu0")

            # Build response (keep components compact)
            comps = dict(vp.get("components", {}))
            if mv_info:
                comps["mv"] = mv_info  # small aux summary
            comps_json = _canonical_json(comps)
            cause = "detector" if bool(vp.get("verdict", False)) else ("av" if bool(av_out.get("trigger", False)) else "")
            action = "degrade" if decision_fail else "none"

            return pb.RiskResponse(  # type: ignore
                verdict=decision_fail,
                score=score,
                threshold=float(av_out.get("threshold", 0.0)),
                budget_remaining=float(av_out.get("alpha_wealth", 0.0)),
                components=comps_json,
                cause=cause,
                action=action,
                step=int(vp.get("step", 0)),
                e_value=float(av_out.get("e_value", 1.0)),
                alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
                alpha_spent=float(av_out.get("alpha_spent", 0.0)),
            )

        # -------- Verify --------
        def Verify(self, request: "pb.VerifyRequest", context: "grpc.ServicerContext"):  # type: ignore
            rt = _rt()
            t0 = time.perf_counter()

            if not _time_ok(context):
                _err(context, grpc.StatusCode.DEADLINE_EXCEEDED, "deadline exceeded")  # type: ignore
                return pb.VerifyResponse(ok=False)  # type: ignore

            ok = False
            try:
                # Chain verification if heads/bodies present
                has_chain = (len(request.heads) > 0) or (len(request.bodies) > 0)
                if has_chain:
                    if len(request.heads) != len(request.bodies) or len(request.heads) == 0:
                        _err(context, grpc.StatusCode.INVALID_ARGUMENT, "heads/bodies must align and be non-empty")  # type: ignore
                        return pb.VerifyResponse(ok=False)  # type: ignore
                    # lightweight guard: keep arrays within reasonable bounds
                    if len(request.heads) > 4096:
                        _err(context, grpc.StatusCode.INVALID_ARGUMENT, "window too large")  # type: ignore
                        return pb.VerifyResponse(ok=False)  # type: ignore
                    ok = bool(verify_chain(list(request.heads), list(request.bodies)))
                else:
                    if not request.receipt_head_hex or not request.receipt_body_json:
                        _err(context, grpc.StatusCode.INVALID_ARGUMENT, "missing receipt head/body")  # type: ignore
                        return pb.VerifyResponse(ok=False)  # type: ignore

                    # Optional witness segments (trace/spectrum/feat)
                    witness = None
                    wlen = len(request.witness_trace) + len(request.witness_spectrum) + len(request.witness_feat)
                    if wlen > 0:
                        if wlen > (_MAX_TRACE + _MAX_SPECT + _MAX_FEATS):
                            _err(context, grpc.StatusCode.INVALID_ARGUMENT, "witness too large")  # type: ignore
                            return pb.VerifyResponse(ok=False)  # type: ignore
                        witness = (
                            [int(x) for x in request.witness_trace],
                            [int(x) for x in request.witness_spectrum],
                            [int(x) for x in request.witness_feat],
                        )

                    # Optional req/comp/e JSON
                    def _maybe(obj: str) -> Optional[Dict]:
                        if not obj:
                            return None
                        try:
                            return json.loads(obj)
                        except Exception:
                            return None

                    ok = bool(
                        verify_receipt(
                            receipt_head_hex=str(request.receipt_head_hex),
                            receipt_body_json=str(request.receipt_body_json),
                            verify_key_hex=(str(request.verify_key_hex) if request.verify_key_hex else None),
                            receipt_sig_hex=(str(request.receipt_sig_hex) if request.receipt_sig_hex else None),
                            req_obj=_maybe(request.req_json),
                            comp_obj=_maybe(request.comp_json),
                            e_obj=_maybe(request.e_json),
                            witness_segments=witness,
                            strict=True,
                        )
                    )
            except Exception:
                _err(context, grpc.StatusCode.INTERNAL, "verification error")  # type: ignore
                ok = False
            finally:
                rt.prom.observe_latency(max(0.0, time.perf_counter() - t0))
                if not ok:
                    rt.prom.slo_violation("verify_fail")

            return pb.VerifyResponse(ok=bool(ok))  # type: ignore


# ---------- Public API ----------

def grpc_supported() -> bool:
    """Return True if grpcio and generated stubs are importable."""
    return bool(_HAS_GRPC and _HAS_STUBS)


def register_grpc_services(server: "grpc.Server", runtime: Optional[_Runtime] = None) -> bool:  # type: ignore
    """
    Attach TCD gRPC services to an existing `grpc.Server`.
    Returns True if services were registered; False if stubs are unavailable.

    Usage (in your own entrypoint):
        import grpc
        from concurrent import futures
        from tcd.service_grpc import register_grpc_services

        server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
        if not register_grpc_services(server):
            raise RuntimeError("TCD gRPC stubs not found; did you generate and install them?")
        server.add_insecure_port("0.0.0.0:9090")
        server.start(); server.wait_for_termination()
    """
    if not grpc_supported():  # pragma: no cover
        return False

    # Allow tests to inject a pre-built runtime (shared singletons).
    global _runtime
    if runtime is not None:
        _runtime = runtime

    pb_grpc.add_TcdServiceServicer_to_server(TcdService(), server)  # type: ignore
    return True