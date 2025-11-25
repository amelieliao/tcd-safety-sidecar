# FILE: tcd/service_grpc.py
"""
gRPC service shim for TCD.

This module mirrors the HTTP semantics (/diagnose, /verify) while remaining an
optional, non-entry dependency. It:

  - Only activates if `grpcio` and generated stubs (`tcd/proto/*_pb2*.py`) are
    importable.
  - Reuses the same decision pipeline as HTTP (detector + AV + routing +
    metrics).
  - Adds guardrails: deadlines, rate limiting, structured errors, payload limits.
  - Treats routing and risk decisions as deterministic, auditable mappings
    suitable for receipts and PQ signatures.
  - Exposes `register_grpc_services(server, runtime=None)` that safely no-ops
    if stubs are missing.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional, Tuple

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

# ---------- Limits / constants ----------

_MAX_TRACE = 8192
_MAX_SPECT = 8192
_MAX_FEATS = 4096
# Guard against huge JSON blobs (bytes when utf-8 encoded)
_JSON_COMPONENT_LIMIT = 256_000


# ---------- Utilities & Conversions ----------


def _p_cons(score: float) -> float:
    """Conservative monotone map score∈[0,1] → p∈(0,1]; higher score = smaller p."""
    s = max(0.0, min(1.0, float(score)))
    # e-process prefers small p for strong evidence; clamp to avoid zero.
    return max(1e-12, 1.0 - s)


def _has_field(msg: Any, name: str) -> bool:
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


def _canonical_json(obj: Dict[str, Any]) -> str:
    """
    Canonical JSON with length guard.

    This is used for the `components` field in gRPC responses so that callers
    and receipts can rely on a deterministic, compact representation.
    """
    txt = json.dumps(obj or {}, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    # enforce an upper bound to avoid response bloat
    if len(txt.encode("utf-8")) > _JSON_COMPONENT_LIMIT:
        return "{}"
    return txt


def _normalize_threat_kind(raw: Optional[str]) -> Optional[str]:
    """
    Map arbitrary threat labels into a small normalized vocabulary:
      - "apt"
      - "insider"
      - "supply_chain"

    Returns None if the input cannot be mapped.
    """
    if not raw:
        return None
    s = str(raw).strip().lower()
    if not s:
        return None
    # direct matches
    if s in {"apt", "insider", "supply_chain"}:
        return s
    # fuzzy matches
    if "apt" in s:
        return "apt"
    if "insider" in s:
        return "insider"
    if "supply" in s or "supply-chain" in s:
        return "supply_chain"
    return None


def _subject_from_md(context, req) -> Tuple[str, str, str]:
    """
    Resolve (tenant, user, session) with metadata taking precedence, then proto
    fields, then defaults.

    Upstream callers are expected to send opaque identifiers (tenant-scoped
    IDs or hashes) only. Raw personal information (such as full names or email
    addresses) should not be passed through these fields.
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
    # Light format guard for user/session: avoid obvious emails or free-form strings.
    for part_name, part_val, default in (
        ("user", user, "user0"),
        ("session", sess, "sess0"),
    ):
        if "@" in part_val or " " in part_val:
            if part_name == "user":
                user = default
            else:
                sess = default
    return (tenant, user, sess)


def _resolve_security_context(context, req) -> Dict[str, Any]:
    """
    Resolve coarse security context:

      - trust_zone: internet/internal/partner/admin/...
      - route_profile: inference/admin/control/...
      - threat_kind/threat_confidence: from upstream SIEM or request.
      - pq_required: whether PQ-safe receipts/signatures are required.
      - build_id/image_digest/compliance_tags: supply-chain / compliance hints.

    Metadata keys (if present) override request fields:

      x-trust-zone, x-route-profile, x-threat, x-threat-confidence,
      x-pq-required, x-build-id, x-image-digest, x-compliance-tags

    trust_zone and route_profile are normalized into small fixed vocabularies.
    threat_kind is normalized via `_normalize_threat_kind`.
    """
    # Initial values from request fields (if any)
    trust_zone = getattr(req, "trust_zone", "") or "internet"
    route_profile = getattr(req, "route_profile", "") or "inference"

    threat_kind: Optional[str] = None
    threat_conf: Optional[float] = None
    pq_required: bool = False
    build_id: Optional[str] = getattr(req, "build_id", "") or None
    image_digest: Optional[str] = getattr(req, "image_digest", "") or None
    compliance_tags: List[str] = []

    # Request-level hints
    if _has_field(req, "threat_hint"):
        threat_kind = (getattr(req, "threat_hint", "") or "").strip() or None
    if _has_field(req, "threat_kind") and not threat_kind:
        threat_kind = (getattr(req, "threat_kind", "") or "").strip() or None
    if _has_field(req, "threat_confidence"):
        try:
            threat_conf = float(getattr(req, "threat_confidence"))
        except Exception:
            threat_conf = None
    if _has_field(req, "pq_required"):
        try:
            pq_required = bool(getattr(req, "pq_required"))
        except Exception:
            pq_required = False
    if hasattr(req, "compliance_tags"):
        try:
            compliance_tags = list(getattr(req, "compliance_tags"))
        except Exception:
            compliance_tags = []

    # Metadata overrides
    try:
        md = {k.lower(): v for k, v in (context.invocation_metadata() or [])}  # type: ignore[attr-defined]
    except Exception:
        md = {}

    if "x-trust-zone" in md:
        trust_zone = md["x-trust-zone"] or trust_zone
    if "x-route-profile" in md:
        route_profile = md["x-route-profile"] or route_profile
    if "x-threat" in md and not threat_kind:
        threat_kind = md["x-threat"]
    if "x-threat-confidence" in md and threat_conf is None:
        try:
            threat_conf = float(md["x-threat-confidence"])
        except Exception:
            threat_conf = None
    if "x-pq-required" in md:
        v = md["x-pq-required"].strip().lower()
        if v in ("1", "true", "yes", "y"):
            pq_required = True
    if "x-build-id" in md and not build_id:
        build_id = md["x-build-id"]
    if "x-image-digest" in md and not image_digest:
        image_digest = md["x-image-digest"]
    if "x-compliance-tags" in md and not compliance_tags:
        compliance_tags = [t for t in md["x-compliance-tags"].split(",") if t]

    # Normalize zones and profiles into small vocabularies.
    trust_zone = (trust_zone or "internet").strip().lower()
    route_profile = (route_profile or "inference").strip().lower()

    allowed_zones = {"internet", "internal", "partner", "admin"}
    if trust_zone not in allowed_zones:
        trust_zone = "internet"

    allowed_profiles = {"inference", "admin", "control"}
    if route_profile not in allowed_profiles:
        route_profile = "inference"

    # Normalize threat kind
    threat_kind = _normalize_threat_kind(threat_kind)

    # Default PQ requirement: certain zones are always PQ-sensitive unless
    # explicitly disabled upstream.
    if not pq_required and trust_zone in {"admin", "partner"}:
        pq_required = True

    return {
        "trust_zone": trust_zone,
        "route_profile": route_profile,
        "threat_kind": threat_kind,
        "threat_confidence": threat_conf,
        "pq_required": bool(pq_required),
        "build_id": build_id,
        "image_digest": image_digest,
        "compliance_tags": compliance_tags,
    }


# ---------- Core runtime (mirrors HTTP create_app pipeline) ----------


class _Runtime:
    """
    Holds long-lived singletons (detectors, AV controllers, metrics, etc.).

    This is intentionally stateful but content-agnostic. It does not persist any
    raw prompts or completions, only numeric traces, scores and budget states.
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

        # StrategyRouter is deterministic given config and inputs, which makes
        # its output safe to bind into receipts and PQ signatures.
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
        """
        One AV controller per (tenant, user, session).

        The controller remains content-agnostic: it only sees scores, p-values
        and coarse metadata such as policy keys and trust zones.
        """
        with self.av_lock:
            inst = self.av_by_subject.get(subject)
            if inst is None:
                cfg = AlwaysValidConfig(
                    alpha_base=float(getattr(self.settings, "alpha", 0.05) or 0.05),
                    label="grpc",
                    policyset_ref=getattr(self.settings, "policyset_ref", None),
                )
                inst = AlwaysValidRiskController(config=cfg)
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
        gRPC service implementing Diagnose/Verify with semantics consistent with
        HTTP endpoints.

        All decisions are treated as deterministic mappings from
        (config, inputs, metadata) to outputs, making them safe to embed into
        receipts and PQ signatures.

        Note on semantics:
          - RiskResponse.verdict == True means "risk triggered" (not "allow").
          - The action field indicates what the caller should do
            ("none", "degrade", "block").
        """

        # -------- Diagnose --------
        def Diagnose(self, request: "pb.DiagnoseRequest", context: "grpc.ServicerContext"):  # type: ignore
            rt = _rt()
            t0 = time.perf_counter()

            # Deadline/cancellation pre-check
            if not _time_ok(context):
                _err(context, grpc.StatusCode.DEADLINE_EXCEEDED, "deadline exceeded")  # type: ignore
                return pb.RiskResponse(  # type: ignore
                    verdict=False,
                    score=0.0,
                    threshold=0.0,
                    budget_remaining=0.0,
                    components="{}",
                    cause="deadline",
                    action="reject",
                    step=0,
                    e_value=1.0,
                    alpha_alloc=0.0,
                    alpha_spent=0.0,
                )

            # Subject and security context
            subject = _subject_from_md(context, request)
            sec_ctx = _resolve_security_context(context, request)
            trust_zone = sec_ctx["trust_zone"]
            route_profile = sec_ctx["route_profile"]
            threat_kind = sec_ctx["threat_kind"]
            threat_conf = sec_ctx["threat_confidence"]
            pq_required = sec_ctx["pq_required"]

            # Basic payload limits to guard against abuse
            if (
                len(request.trace_vector) > _MAX_TRACE
                or len(request.spectrum) > _MAX_SPECT
                or len(request.features) > _MAX_FEATS
            ):
                _err(context, grpc.StatusCode.INVALID_ARGUMENT, "payload too large")  # type: ignore
                return pb.RiskResponse(  # type: ignore
                    verdict=False,
                    score=0.0,
                    threshold=0.0,
                    budget_remaining=0.0,
                    components=_canonical_json({"error": "payload_too_large"}),
                    cause="limit",
                    action="reject",
                    step=0,
                    e_value=1.0,
                    alpha_alloc=0.0,
                    alpha_spent=0.0,
                )

            # Rate limit with zone-aware cost
            tokens_delta = float(getattr(request, "tokens_delta", 0.0) or 0.0)
            divisor = float(getattr(rt.settings, "token_cost_divisor_default", 50.0) or 50.0)
            base_cost = max(1.0, tokens_delta / max(1.0, divisor))

            zone_multiplier = 1.0
            if trust_zone == "admin":
                zone_multiplier = 2.0
            elif trust_zone == "internal":
                zone_multiplier = 1.5
            elif trust_zone == "partner":
                zone_multiplier = 1.25

            cost = base_cost * zone_multiplier

            # If upstream already labeled this as a strong APT-like scenario,
            # we make rate limiting more aggressive.
            if threat_kind == "apt" and (threat_conf or 0.0) >= 0.9:
                cost *= 3.0

            if not rt.rlim.consume(subject, cost=cost):
                rt.prom.throttle(*subject, reason="rate")
                _err(context, grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limited")  # type: ignore
                return pb.RiskResponse(  # type: ignore
                    verdict=False,
                    score=0.0,
                    threshold=0.0,
                    budget_remaining=0.0,
                    components=_canonical_json({"error": "rate_limited"}),
                    cause="rate",
                    action="reject",
                    step=0,
                    e_value=1.0,
                    alpha_alloc=0.0,
                    alpha_spent=0.0,
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

            entropy: Optional[float] = None
            if _has_field(request, "entropy"):
                try:
                    entropy = float(request.entropy)
                except Exception:
                    entropy = None

            vp = det.diagnose(
                trace_vec,
                entropy,
                spectrum,
                step_id=(request.step_id if getattr(request, "step_id", "") else None),
            )

            det_components = dict(vp.get("components", {}))

            # Optional multivariate score (aux only)
            mv_info: Dict[str, Any] = {}
            if len(features) > 0:
                try:
                    mv = rt.get_mv(request.model_id or "model0")
                    mv_info = mv.decision(features)  # returns dict
                except Exception:
                    mv_info = {}

            # Consolidate threat information from detector outputs (if any)
            det_threat_kind = det_components.get("threat_kind")
            det_threat_conf = det_components.get("threat_confidence")

            det_threat_kind_norm = _normalize_threat_kind(det_threat_kind)
            if threat_kind is None and det_threat_kind_norm is not None:
                threat_kind = det_threat_kind_norm

            if det_threat_conf is not None:
                try:
                    det_conf_f = float(det_threat_conf)
                except Exception:
                    det_conf_f = None
                if det_conf_f is not None:
                    if threat_conf is None:
                        threat_conf = det_conf_f
                    else:
                        threat_conf = max(threat_conf, det_conf_f)

            # Score → conservative p-value
            score = float(vp.get("score", 0.0))
            p_final = _p_cons(score)

            # Drift-adjusted AV weight, modulated by threat/zone
            drift_score = 0.0
            if _has_field(request, "drift_score"):
                try:
                    drift_score = float(request.drift_score)
                except Exception:
                    drift_score = 0.0

            drift_w = 1.0 + 0.5 * drift_score

            # Threat-aware adjustment: stronger weight under high-risk scenarios.
            if threat_kind in ("apt", "supply_chain") and (threat_conf or 0.0) >= 0.5:
                drift_w *= 1.5
            if trust_zone == "admin" and threat_kind == "insider":
                drift_w *= 2.0

            drift_w = max(0.0, min(2.0, drift_w))

            # Build a stable stream_id for the e-process
            stream_id = f"{subject[0]}:{subject[1]}:{request.model_id or 'model0'}"

            # AV controller step (anytime-valid e-process)
            av = rt.get_av(subject)
            av_out = av.step(
                stream_id=stream_id,
                policy_key=(request.task or "chat", request.lang or "en", request.model_id or "model0"),
                subject=subject,
                scores={"final": score},
                pvals={"final": p_final},
                drift_weight=drift_w,
                meta={
                    "trust_zone": trust_zone,
                    "route_profile": route_profile,
                    "threat_kind": threat_kind,
                    "pq_required": pq_required,
                },
            )

            av_trigger = bool(av_out.get("trigger", False))
            det_trigger = bool(vp.get("verdict", False))
            decision_fail = bool(det_trigger or av_trigger)

            # Strategy routing (deterministic, auditable)
            base_temp = float(getattr(request, "base_temp", getattr(rt.settings, "router_base_temp", 1.0)) or 1.0)
            base_top_p = float(
                getattr(request, "base_top_p", getattr(rt.settings, "router_base_top_p", 0.95)) or 0.95
            )
            risk_label = getattr(request, "risk_label", "") or "normal"

            route = rt.router.decide(
                decision_fail=decision_fail,
                score=score,
                base_temp=base_temp,
                base_top_p=base_top_p,
                risk_label=risk_label,
                route_profile=route_profile,
                e_triggered=av_trigger,
                trust_zone=trust_zone,
                threat_kind=threat_kind,
                pq_unhealthy=False,  # gRPC layer itself does not know PQ health; handled upstream
                av_label=getattr(av.config, "label", None),
                av_trigger=av_trigger,
                meta={
                    "model_id": request.model_id or "model0",
                    "gpu_id": request.gpu_id or "gpu0",
                    "tenant": subject[0],
                    "user": subject[1],
                    "session": subject[2],
                    "pq_required": pq_required,
                    "threat_confidence": threat_conf,
                    "build_id": sec_ctx["build_id"],
                    "image_digest": sec_ctx["image_digest"],
                    "compliance_tags": sec_ctx["compliance_tags"],
                },
            )
            route_info: Dict[str, Any] = asdict(route)

            # Metrics
            latency_s = max(0.0, time.perf_counter() - t0)
            rt.prom.observe_latency(latency_s)
            rt.prom.push(
                vp,
                labels={
                    "model_id": request.model_id or "model0",
                    "gpu_id": request.gpu_id or "gpu0",
                },
            )
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
                subject[0],
                subject[1],
                subject[2],
                remaining=float(av_out.get("alpha_wealth", 0.0)),
                spent=bool(av_out.get("alpha_spent", 0.0) > 0.0),
            )
            if decision_fail:
                rt.prom.record_action(request.model_id or "model0", request.gpu_id or "gpu0", action="degrade")
            slo_ms = float(getattr(rt.settings, "slo_latency_ms", 0.0) or 0.0)
            if slo_ms and (latency_s * 1000.0) > slo_ms:
                rt.prom.slo_violation_by_model(
                    "diagnose_latency",
                    request.model_id or "model0",
                    request.gpu_id or "gpu0",
                )

            # Build structured components (compact, content-agnostic)
            comps: Dict[str, Any] = {}

            # Detector-level components
            if det_components:
                comps["detector"] = det_components

            # Multivariate auxiliary decision
            if mv_info:
                comps["multivar"] = mv_info

            # E-process snapshot and security view (if present)
            e_state = av_out.get("e_state") or {}
            security_av = av_out.get("security") or {}

            if e_state:
                comps["e_process"] = e_state

            # Route view (already deterministic and JSON-serializable via asdict)
            comps["route"] = route_info

            # Consolidated security block for receipts / audits
            security_block: Dict[str, Any] = {
                "trust_zone": trust_zone,
                "route_profile": route_profile,
                "threat_kind": threat_kind,
                "threat_confidence": threat_conf,
                "pq_required": route_info.get("pq_required", pq_required),
                "pq_ok": route_info.get("pq_ok"),
                "policy_ref": route_info.get("policy_ref"),
                "route_id": route_info.get("route_id"),
                "stream_hash": (e_state.get("stream", {}) or {}).get("hash"),
                "build_id": sec_ctx["build_id"],
                "image_digest": sec_ctx["image_digest"],
                "compliance_tags": sec_ctx["compliance_tags"],
            }
            # Merge AV security info without overwriting core keys
            for k, v in security_av.items():
                security_block.setdefault(k, v)

            comps["security"] = security_block

            comps_json = _canonical_json(comps)

            cause = "detector" if det_trigger else ("av" if av_trigger else "")
            action = "degrade" if decision_fail else "none"

            # Harder actions in high-risk cases.
            if decision_fail:
                if threat_kind in ("apt", "supply_chain") and (threat_conf or 0.0) >= 0.9:
                    action = "block"
                elif security_block.get("pq_required") and (security_block.get("pq_ok") is False):
                    action = "block"

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

            # Light rate limiting for verification to avoid abuse.
            subject = _subject_from_md(context, request)
            if not rt.rlim.consume(subject, cost=1.0):
                rt.prom.throttle(*subject, reason="rate_verify")
                _err(context, grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limited")  # type: ignore
                return pb.VerifyResponse(ok=False)  # type: ignore

            # Resolve PQ requirement / supply-chain expectations from metadata.
            sec_ctx = _resolve_security_context(context, request)
            pq_required_ctx = bool(sec_ctx["pq_required"])
            runtime_build_id = getattr(rt.settings, "build_id", None)
            runtime_image_digest = getattr(rt.settings, "image_digest", None)

            ok = False
            try:
                # Chain verification if heads/bodies present
                has_chain = (len(request.heads) > 0) or (len(request.bodies) > 0)
                if has_chain:
                    if len(request.heads) != len(request.bodies) or len(request.heads) == 0:
                        _err(
                            context,
                            grpc.StatusCode.INVALID_ARGUMENT,
                            "heads/bodies must align and be non-empty",
                        )  # type: ignore
                        return pb.VerifyResponse(ok=False)  # type: ignore
                    # lightweight guard: keep arrays within reasonable bounds
                    if len(request.heads) > 4096:
                        _err(context, grpc.StatusCode.INVALID_ARGUMENT, "window too large")  # type: ignore
                        return pb.VerifyResponse(ok=False)  # type: ignore
                    ok = bool(verify_chain(list(request.heads), list(request.bodies)))
                else:
                    if not request.receipt_head_hex or not request.receipt_body_json:
                        _err(
                            context,
                            grpc.StatusCode.INVALID_ARGUMENT,
                            "missing receipt head/body",
                        )  # type: ignore
                        return pb.VerifyResponse(ok=False)  # type: ignore

                    # Optional witness segments (trace/spectrum/feat)
                    witness = None
                    wlen = (
                        len(request.witness_trace)
                        + len(request.witness_spectrum)
                        + len(request.witness_feat)
                    )
                    if wlen > 0:
                        if wlen > (_MAX_TRACE + _MAX_SPECT + _MAX_FEATS):
                            _err(
                                context,
                                grpc.StatusCode.INVALID_ARGUMENT,
                                "witness too large",
                            )  # type: ignore
                            return pb.VerifyResponse(ok=False)  # type: ignore
                        witness = (
                            [int(x) for x in request.witness_trace],
                            [int(x) for x in request.witness_spectrum],
                            [int(x) for x in request.witness_feat],
                        )

                    # Optional req/comp/e JSON
                    def _maybe(obj: str) -> Optional[Dict[str, Any]]:
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
                            verify_key_hex=(
                                str(request.verify_key_hex) if request.verify_key_hex else None
                            ),
                            receipt_sig_hex=(
                                str(request.receipt_sig_hex) if request.receipt_sig_hex else None
                            ),
                            req_obj=_maybe(request.req_json),
                            comp_obj=_maybe(request.comp_json),
                            e_obj=_maybe(request.e_json),
                            witness_segments=witness,
                            strict=True,
                        )
                    )

                    # If signature-level verification succeeded, enforce PQ and
                    # supply-chain consistency against the receipt body.
                    if ok:
                        try:
                            body_obj = json.loads(str(request.receipt_body_json))
                        except Exception:
                            body_obj = None

                        sec_block: Dict[str, Any] = {}
                        if isinstance(body_obj, dict):
                            comps = body_obj.get("components")
                            if isinstance(comps, dict):
                                sec_candidate = comps.get("security")
                                if isinstance(sec_candidate, dict):
                                    sec_block = sec_candidate
                            if not sec_block and isinstance(body_obj.get("security"), dict):
                                sec_block = body_obj["security"]

                        # Determine effective PQ requirement and PQ outcome.
                        pq_required_eff = bool(
                            sec_block.get("pq_required")
                            or body_obj.get("pq_required") if isinstance(body_obj, dict) else False
                            or pq_required_ctx
                        )
                        pq_ok_eff = sec_block.get("pq_ok")
                        if pq_required_eff and (pq_ok_eff is False or pq_ok_eff is None):
                            _err(context, grpc.StatusCode.PERMISSION_DENIED, "pq_violation")  # type: ignore
                            ok = False

                        # Supply-chain consistency checks.
                        if ok and isinstance(sec_block, dict):
                            rec_build = sec_block.get("build_id")
                            rec_image = sec_block.get("image_digest")

                            if runtime_build_id and rec_build and rec_build != runtime_build_id:
                                _err(
                                    context,
                                    grpc.StatusCode.PERMISSION_DENIED,
                                    "supply_chain_mismatch_build",
                                )  # type: ignore
                                ok = False

                            if runtime_image_digest and rec_image and rec_image != runtime_image_digest:
                                _err(
                                    context,
                                    grpc.StatusCode.PERMISSION_DENIED,
                                    "supply_chain_mismatch_image",
                                )  # type: ignore
                                ok = False

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
        server.start()
        server.wait_for_termination()
    """
    if not grpc_supported():  # pragma: no cover
        return False

    # Allow tests or embedding code to inject a pre-built runtime (shared singletons).
    global _runtime
    if runtime is not None:
        _runtime = runtime

    pb_grpc.add_TcdServiceServicer_to_server(TcdService(), server)  # type: ignore
    return True