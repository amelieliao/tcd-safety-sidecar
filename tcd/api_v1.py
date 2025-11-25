# FILE: tcd/api_v1.py
from __future__ import annotations

import dataclasses
import logging
import time
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from starlette.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_401_UNAUTHORIZED,
    HTTP_500_INTERNAL_SERVER_ERROR,
)

from prometheus_client import Counter, Histogram

from .schemas import DiagnoseIn, DiagnoseOut
from .risk_av import AlwaysValidRiskController, AlwaysValidConfig

# Optional higher-layer integrations. These are imported in a soft way so that
# this module can still be used in minimal setups; in a hardened deployment
# they are expected to be present and wired.
try:  # Authenticator / AuthContext
    from .auth import Authenticator, AuthResult, build_authenticator_from_env  # type: ignore
except Exception:  # pragma: no cover - optional
    Authenticator = None  # type: ignore[assignment]
    AuthResult = None  # type: ignore[assignment]
    build_authenticator_from_env = None  # type: ignore[assignment]

try:  # Attestor / AttestorConfig / canonical_kv_hash
    from .attest import Attestor, AttestorConfig, canonical_kv_hash  # type: ignore
except Exception:  # pragma: no cover - optional
    Attestor = None  # type: ignore[assignment]
    AttestorConfig = None  # type: ignore[assignment]
    canonical_kv_hash = None  # type: ignore[assignment]

try:  # Local audit ledger
    from .audit import AuditLedger  # type: ignore
except Exception:  # pragma: no cover - optional
    AuditLedger = None  # type: ignore[assignment]


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# API-level config / governance
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ApiV1Config:
    """
    API v1 surface configuration.

    This config is intentionally small and stable; it can be extended over time
    but should remain low-cardinality and carefully versioned so that:

      - deployment-time policy changes are explicit;
      - e-process / attestation / receipts can reference a single digest.

    Fields:
      - max_payload_bytes: soft limit on incoming request body size; requests
                           with a larger Content-Length are rejected early.
      - issue_attestation: if True, route will ensure that an attestation
                           record is attached to the decision (either from
                           the risk controller or by generating one via
                           the Attestor singleton).
      - attach_auth_context: if True, normalized DiagnoseOut.components will
                             include a small auth context view
                             (principal/mode/scopes).
      - route_name: logical route identifier used in metrics and attestation.
      - strict_mode: when True, the route enforces stronger guarantees and
                     will fail fast if required components are missing.
      - require_auth: require a configured Authenticator in strict_mode.
      - require_attestor: require a configured Attestor in strict_mode.
      - require_ledger: require a local AuditLedger in strict_mode.
      - require_pq_sig: if True, strict_mode additionally requires the
                        Attestor to use a PQ-capable signature algorithm.
      - max_end_to_end_latency_s: soft SLA for request handling; in
                        strict_mode, violations are recorded in metrics.
      - allowed_auth_modes: optional allow-list for auth_ctx.mode in
                        strict_mode; if non-empty, any other mode is rejected.
    """

    max_payload_bytes: int = 256 * 1024  # 256 KiB
    issue_attestation: bool = True
    attach_auth_context: bool = True
    route_name: str = "v1.diagnose"

    # Security profile
    strict_mode: bool = False
    require_auth: bool = True
    require_attestor: bool = True
    require_ledger: bool = True
    require_pq_sig: bool = False
    max_end_to_end_latency_s: float = 1.0
    allowed_auth_modes: Optional[List[str]] = None

    def digest_material(self) -> Dict[str, Any]:
        """
        Material suitable for a higher-level policy digest, if desired.
        (We keep this local to avoid circular imports.)
        """
        return {
            "max_payload_bytes": int(self.max_payload_bytes),
            "issue_attestation": bool(self.issue_attestation),
            "attach_auth_context": bool(self.attach_auth_context),
            "route_name": self.route_name,
            "strict_mode": bool(self.strict_mode),
            "require_auth": bool(self.require_auth),
            "require_attestor": bool(self.require_attestor),
            "require_ledger": bool(self.require_ledger),
            "require_pq_sig": bool(self.require_pq_sig),
            "max_end_to_end_latency_s": float(self.max_end_to_end_latency_s),
            "allowed_auth_modes": list(self.allowed_auth_modes or []),
        }


# Global config instance (can be overridden at import time or via a higher
# layer that sets module-level state before app startup).
_API_CFG = ApiV1Config()

# API config digest: used as a witness and as part of the global policy graph.
if canonical_kv_hash is not None:
    try:
        _API_CFG_DIGEST: str = canonical_kv_hash(
            _API_CFG.digest_material(),
            ctx="tcd:api_v1_cfg",
            label="api_v1_cfg",
        )
    except Exception:  # pragma: no cover - very defensive
        logger.error("failed to compute ApiV1Config digest; falling back to repr()")
        _API_CFG_DIGEST = "api_v1_cfg:" + repr(_API_CFG.digest_material())
else:  # pragma: no cover - minimal install
    _API_CFG_DIGEST = "api_v1_cfg:" + repr(_API_CFG.digest_material())


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


_REQ_LATENCY = Histogram(
    "tcd_api_v1_request_latency_seconds",
    "Latency of /v1/diagnose requests",
    buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20, 0.50, 1.0),
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
    labelnames=("route",),
)


# ---------------------------------------------------------------------------
# Singletons: controller, auth, attestor, ledger
# ---------------------------------------------------------------------------


router = APIRouter(prefix="/v1", tags=["v1"])

# Single risk controller instance – treated as a process-local state machine.
_av = AlwaysValidRiskController(AlwaysValidConfig())

# Authenticator: in hardened deployments this is expected to be present and
# configured via environment / config-plane. In minimal demos it may be None.
if build_authenticator_from_env is not None:
    try:
        _AUTH: Optional[Authenticator] = build_authenticator_from_env()
    except Exception as e:  # pragma: no cover - startup log only
        logger.error("failed to build Authenticator; running without auth: %s", e)
        _AUTH = None
else:  # pragma: no cover - demo mode
    _AUTH = None

# Attestor singleton: used to generate attestations when the risk controller
# does not produce one. In many deployments the risk controller itself will
# own attestation; this layer simply ensures there is *always* a structured
# attestation for the decision path.
_ATTESTOR_CFG: Optional[AttestorConfig]
if AttestorConfig is not None and Attestor is not None:
    try:
        _ATTESTOR_CFG = AttestorConfig(
            attestor_id="tcd-api-v1",
            proc_id=None,  # can be injected at deploy time (build digest)
            strict_mode=_API_CFG.strict_mode,
            default_auth_policy=None,       # filled by higher layer if desired
            default_chain_policy=None,
            default_ledger_policy=None,
            default_cfg_digest=_API_CFG_DIGEST,
        )
        _ATTESTOR: Optional[Attestor] = Attestor(cfg=_ATTESTOR_CFG)
    except Exception as e:  # pragma: no cover - startup log only
        logger.error("failed to build Attestor; running without attestation: %s", e)
        _ATTESTOR = None
        _ATTESTOR_CFG = None  # type: ignore[assignment]
else:  # pragma: no cover
    _ATTESTOR = None
    _ATTESTOR_CFG = None  # type: ignore[assignment]

# Optional local audit ledger. We only rely on the minimal interface:
#   - head() -> str
#   - append(record: Dict[str, Any]) -> str
if AuditLedger is not None:
    try:
        _LEDGER: Optional[AuditLedger] = AuditLedger()
    except Exception as e:  # pragma: no cover
        logger.error("failed to build AuditLedger; running without local ledger: %s", e)
        _LEDGER = None
else:  # pragma: no cover
    _LEDGER = None

# Strict profile: enforce presence of core components at startup.
if _API_CFG.strict_mode:
    if _API_CFG.require_auth and _AUTH is None:
        raise RuntimeError("ApiV1Config.strict_mode requires an Authenticator")
    if _API_CFG.require_attestor and (_ATTESTOR is None or _ATTESTOR_CFG is None):
        raise RuntimeError("ApiV1Config.strict_mode requires an Attestor")
    if _API_CFG.require_ledger and _LEDGER is None:
        raise RuntimeError("ApiV1Config.strict_mode requires an AuditLedger")
    # Optional PQ enforcement: rely on AttestorConfig.sig_alg if available.
    if _API_CFG.require_pq_sig and _ATTESTOR_CFG is not None:
        sig_alg = getattr(_ATTESTOR_CFG, "sig_alg", None)
        if not sig_alg or "dilithium" not in str(sig_alg).lower():
            raise RuntimeError("ApiV1Config.require_pq_sig expects a PQ-capable sig_alg on AttestorConfig")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _auth_context_for_components(auth_ctx: Any) -> Dict[str, Any]:
    """
    Project AuthContext (if present) into a compact dict to embed under
    DiagnoseOut.components["auth"].

    This assumes a minimal contract consistent with tcd.auth.AuthContext:
      - mode: str
      - principal: str
      - scopes: Sequence[str]
      - key_id: Optional[str]
      - policy_digest_hex: Optional[str]
      - issued_at: float (epoch seconds)
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
        out["mode"] = str(mode)
    if principal is not None:
        out["principal"] = str(principal)
    if scopes:
        out["scopes"] = list(scopes)
    if key_id is not None:
        out["key_id"] = str(key_id)
    if policy_digest_hex is not None:
        out["policy_digest"] = str(policy_digest_hex)
    if issued_at is not None:
        out["issued_at"] = float(issued_at)

    return out


def _normalize(raw: Dict[str, Any], auth_ctx: Any) -> DiagnoseOut:
    """
    Normalize raw controller output and attach a minimal, type-stable
    representation of the auth context (if configured to do so).

    This function is the main “contract boundary” between the internal risk
    controller semantics and the public API schema.
    """
    components = raw.get("components", {}) or {}
    if _API_CFG.attach_auth_context:
        auth_proj = _auth_context_for_components(auth_ctx)
        if auth_proj:
            # Avoid overwriting an existing "auth" key unless the controller
            # explicitly annotated it.
            if "auth" not in components:
                components = dict(components)
                components["auth"] = auth_proj

    # Extract e-process related quantities with basic invariants.
    e_value = float(raw.get("e_value", 1.0))
    alpha_alloc = float(raw.get("alpha_alloc", 0.0))
    alpha_spent = float(raw.get("alpha_spent", 0.0))
    budget_remaining = float(raw.get("budget_remaining", 0.0))

    if _API_CFG.strict_mode:
        if (
            e_value < 0.0
            or alpha_alloc < 0.0
            or alpha_spent < 0.0
            or budget_remaining < 0.0
        ):
            _REQ_ERROR.labels(_API_CFG.route_name, "e_process_invariant").inc()
            logger.error(
                "e-process invariant violated in controller output: "
                "e_value=%r alpha_alloc=%r alpha_spent=%r budget_remaining=%r",
                e_value,
                alpha_alloc,
                alpha_spent,
                budget_remaining,
            )
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
        cause=str(raw.get("cause", "")),
        action=str(raw.get("action", "none")),
        step=int(raw.get("step", 0)),
        e_value=e_value,
        alpha_alloc=alpha_alloc,
        alpha_spent=alpha_spent,
        receipt=raw.get("receipt"),
        receipt_body=raw.get("receipt_body"),
        receipt_sig=raw.get("receipt_sig"),
        verify_key=raw.get("verify_key"),
    )


def _maybe_issue_attestation(
    *,
    raw: Dict[str, Any],
    payload: DiagnoseIn,
    request: Request,
    auth_ctx: Any,
) -> Dict[str, Any]:
    """
    Ensure there is a structured attestation bound to this decision.

    If the risk controller already emitted "receipt"/"receipt_body"/"receipt_sig",
    we leave them in place. Otherwise, if an Attestor singleton is available and
    attestation issuing is enabled, we generate a new attestation and attach it
    to the raw dict.

    The attestation ties together:
      - request metadata (path/method/client + a coarse view of DiagnoseIn);
      - computation description (controller name/version);
      - e-process view (score/threshold/e_value/alpha_* etc.);
      - witness segments (local audit ledger head, controller receipt head,
        API config digest, auth policy digest);
      - a small meta block (route name, auth principal, auth mode).
    """
    if not _API_CFG.issue_attestation:
        return raw
    if _ATTESTOR is None:
        if _API_CFG.strict_mode and _API_CFG.require_attestor:
            # Treat this as a hard configuration error in strict profiles.
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail="attestation failure",
            )
        return raw
    if raw.get("receipt") and raw.get("receipt_body") and raw.get("receipt_sig"):
        # Controller already provided an attestation; we simply keep it.
        return raw

    # Build request object for attestation (coarse, privacy-preserving).
    try:
        client_host = request.client.host if request.client else None
    except Exception:  # pragma: no cover
        client_host = None

    try:
        # For DiagnoseIn we assume a .dict() method exists (pydantic model).
        payload_dict = payload.dict()
    except Exception:
        payload_dict = {}

    req_obj: Dict[str, Any] = {
        "path": str(request.url.path),
        "method": str(request.method),
        "client": client_host,
        "payload_shape": {
            "keys": sorted(list(payload_dict.keys())),
        },
    }

    # Computation descriptor: keep it compact and low-cardinality.
    comp_obj: Dict[str, Any] = {
        "controller": type(_av).__name__,
        "version": getattr(_av, "version", "v1"),
    }

    # e-process view reconstructed from raw fields.
    e_obj: Dict[str, Any] = {
        "score": float(raw.get("score", 0.0)),
        "threshold": float(raw.get("threshold", 0.0)),
        "e_value": float(raw.get("e_value", 1.0)),
        "alpha_alloc": float(raw.get("alpha_alloc", 0.0)),
        "alpha_spent": float(raw.get("alpha_spent", 0.0)),
        "budget_remaining": float(raw.get("budget_remaining", 0.0)),
        "decision": "allow" if raw.get("allowed", False) else "block",
        "policy_digest": raw.get("e_policy_digest"),
    }

    # Witness segments: always include local audit ledger head (if present),
    # API config digest, and optionally auth / controller receipts.
    segments = []

    if _LEDGER is not None:
        try:
            segments.append(
                {
                    "kind": "audit_ledger_head",
                    "id": "api-v1",
                    "digest": _LEDGER.head(),
                    "meta": {},
                }
            )
        except Exception:  # pragma: no cover
            # We do not fail the request if the ledger is temporarily unreachable.
            logger.warning("failed to read AuditLedger head for attestation", exc_info=True)

    if raw.get("receipt"):
        segments.append(
            {
                "kind": "receipt_head",
                "id": "risk-controller",
                "digest": str(raw.get("receipt")),
                "meta": {},
            }
        )

    # API config digest.
    segments.append(
        {
            "kind": "api_cfg",
            "id": _API_CFG.route_name,
            "digest": _API_CFG_DIGEST,
            "meta": {},
        }
    )

    # Auth policy digest (if present).
    auth_proj = _auth_context_for_components(auth_ctx)
    auth_policy_digest = auth_proj.get("policy_digest")
    if auth_policy_digest:
        segments.append(
            {
                "kind": "auth_policy",
                "id": "authenticator",
                "digest": auth_policy_digest,
                "meta": {"mode": auth_proj.get("mode")},
            }
        )

    witness_tags = [
        "api_v1",
        "diagnose",
        type(_av).__name__,
    ]

    # Meta: include route name and a small auth projection.
    meta: Dict[str, Any] = {
        "route": _API_CFG.route_name,
    }
    if auth_proj:
        meta["auth"] = {
            # Only the minimal, low-cardinality subset.
            "mode": auth_proj.get("mode"),
            "principal": auth_proj.get("principal"),
            "policy_digest": auth_policy_digest,
        }

    try:
        att = _ATTESTOR.issue(
            req_obj=req_obj,
            comp_obj=comp_obj,
            e_obj=e_obj,
            witness_segments=segments,
            witness_tags=witness_tags,
            meta=meta,
        )
    except HTTPException:
        # Let route-level handler propagate it.
        raise
    except Exception as e:  # pragma: no cover
        logger.error("attestation issuance failed; proceeding under policy", exc_info=True)
        if _API_CFG.strict_mode and _API_CFG.require_attestor:
            raise HTTPException(
                status_code=HTTP_500_INTERNAL_SERVER_ERROR,
                detail="attestation failure",
            )
        return raw

    # Attach attestation outputs to raw dict for normalization.
    out = dict(raw)
    out.setdefault("receipt", att.get("receipt"))
    out.setdefault("receipt_body", att.get("receipt_body"))
    out.setdefault("receipt_sig", att.get("receipt_sig"))
    out.setdefault("verify_key", att.get("verify_key"))
    return out


def _append_ledger_event(
    *,
    out: DiagnoseOut,
    payload: DiagnoseIn,
    request: Request,
    auth_ctx: Any,
) -> None:
    """
    Append a compact audit event to the local ledger, if present.

    This is non-blocking for the main control path: any failure is logged and
    reflected in metrics but does not affect the HTTP response.
    """
    route = _API_CFG.route_name

    if _LEDGER is None:
        # In strict_mode this should not happen (startup would have failed),
        # but we keep the guard for completeness.
        return

    try:
        try:
            payload_dict = payload.dict()
        except Exception:
            payload_dict = {}

        evt: Dict[str, Any] = {
            "kind": "api_v1_diagnose",
            "ts_ns": time.time_ns(),
            "route": route,
            "verdict": bool(out.verdict),
            "score": float(out.score),
            "threshold": float(out.threshold),
            "budget_remaining": float(out.budget_remaining),
            "e_value": float(out.e_value),
            "alpha_alloc": float(out.alpha_alloc),
            "alpha_spent": float(out.alpha_spent),
            "action": str(out.action),
            "cause": str(out.cause),
            "payload_shape": {
                "keys": sorted(list(payload_dict.keys())),
            },
            "receipt": out.receipt,
            "verify_key": out.verify_key,
            "api_cfg_digest": _API_CFG_DIGEST,
        }

        # Attach a tiny auth projection if available.
        auth_proj = _auth_context_for_components(auth_ctx)
        if auth_proj:
            evt["auth"] = auth_proj
            if auth_proj.get("policy_digest"):
                evt["auth_policy_digest"] = auth_proj["policy_digest"]

        # Attach attestor policy digest if available.
        if _ATTESTOR_CFG is not None and hasattr(_ATTESTOR_CFG, "policy_digest"):
            try:
                evt["attestor_policy_digest"] = _ATTESTOR_CFG.policy_digest()
            except Exception:  # pragma: no cover
                logger.warning("failed to compute attestor policy digest for ledger event", exc_info=True)

        _LEDGER.append(evt)
    except Exception:  # pragma: no cover
        _LEDGER_ERROR.labels(route).inc()
        logger.warning("failed to append audit event to AuditLedger", exc_info=True)


# ---------------------------------------------------------------------------
# Route
# ---------------------------------------------------------------------------


@router.post("/diagnose", response_model=DiagnoseOut)
async def diagnose(payload: DiagnoseIn, request: Request) -> DiagnoseOut:
    """
    Core risk-diagnosis entrypoint.

    Steps:
      1. Soft body-size check using Content-Length (if present).
      2. Authenticate request (if an Authenticator is configured).
      3. Delegate to risk controller (_av.step(request)).
      4. Ensure an attestation record is attached (controller-provided or
         generated via Attestor).
      5. Normalize into DiagnoseOut, optionally enriching components["auth"].
      6. Append a compact event to the local AuditLedger (if present).
      7. Export metrics for latency / status / errors.

    Any unexpected error from internal components is converted into a 4xx/5xx
    while preserving a clean, low-cardinality metrics surface.
    """
    route = _API_CFG.route_name
    t0 = time.perf_counter()

    # 1) Soft body-size guard (based on Content-Length).
    cl = request.headers.get("content-length")
    if cl is not None and _API_CFG.max_payload_bytes > 0:
        try:
            size = int(cl)
            if size > _API_CFG.max_payload_bytes:
                _REQ_REJECTED.labels(route, "body_too_large").inc()
                raise HTTPException(
                    status_code=HTTP_400_BAD_REQUEST,
                    detail="request body too large for this endpoint",
                )
        except ValueError:
            # Non-integer Content-Length; treat as malformed.
            _REQ_REJECTED.labels(route, "bad_content_length").inc()
            raise HTTPException(
                status_code=HTTP_400_BAD_REQUEST,
                detail="invalid Content-Length header",
            )

    # 2) Authentication (if configured).
    auth_ctx = None
    auth_mode_label = "none"
    if _AUTH is not None and AuthResult is not None:
        try:
            auth_result: AuthResult = _AUTH.authenticate(request)  # type: ignore[call-arg]
            auth_ctx = getattr(auth_result, "ctx", None)
            if not getattr(auth_result, "ok", False):
                _REQ_REJECTED.labels(route, "unauthorized").inc()
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="unauthorized",
                )
            mode = getattr(auth_ctx, "mode", None)
            if mode is not None:
                auth_mode_label = str(mode)

            # In strict profiles, enforce an allow-list over auth modes if set.
            if (
                _API_CFG.strict_mode
                and _API_CFG.allowed_auth_modes
                and auth_mode_label not in _API_CFG.allowed_auth_modes
            ):
                _REQ_REJECTED.labels(route, "auth_mode_forbidden").inc()
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="unauthorized",
                )
        except HTTPException:
            # Already labeled above.
            raise
        except Exception as e:
            _REQ_ERROR.labels(route, "auth").inc()
            logger.error("auth failed in /v1/diagnose: %s", e, exc_info=True)
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
            )
    else:
        # No authenticator configured. In strict profiles with require_auth,
        # this should have been rejected at startup; this branch exists for
        # demo / minimal setups.
        if _API_CFG.strict_mode and _API_CFG.require_auth:
            _REQ_REJECTED.labels(route, "auth_missing").inc()
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
            )

    # 3) Delegate to risk controller.
    try:
        raw = _av.step(request)
    except HTTPException:
        # Let FastAPI propagate it unchanged.
        raise
    except Exception as e:
        _REQ_ERROR.labels(route, "controller").inc()
        logger.error("risk controller raised in /v1/diagnose: %s", e, exc_info=True)
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail="internal error",
        )

    if not isinstance(raw, dict):
        _REQ_ERROR.labels(route, "controller_type").inc()
        logger.error("risk controller returned non-dict: %r", type(raw))
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail="internal error",
        )

    # 4) Ensure there is an attestation attached.
    raw = _maybe_issue_attestation(raw=raw, payload=payload, request=request, auth_ctx=auth_ctx)

    # 5) Normalize into DiagnoseOut.
    out = _normalize(raw, auth_ctx)

    # 6) Append local ledger event (best-effort).
    _append_ledger_event(out=out, payload=payload, request=request, auth_ctx=auth_ctx)

    # 7) Metrics.
    dur = time.perf_counter() - t0
    verdict_label = "allow" if out.verdict else "block"
    _REQ_LATENCY.labels(route, verdict_label, auth_mode_label).observe(dur)
    _REQ_TOTAL.labels(route, "ok").inc()

    # SLA monitoring in strict profiles: record slow responses.
    if _API_CFG.strict_mode and dur > _API_CFG.max_end_to_end_latency_s:
        _REQ_ERROR.labels(route, "latency_sla").inc()
        logger.warning(
            "diagnose request exceeded max_end_to_end_latency_s: dur=%.3fs limit=%.3fs",
            dur,
            _API_CFG.max_end_to_end_latency_s,
        )

    return out