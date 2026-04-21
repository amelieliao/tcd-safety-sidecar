from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import hmac
import inspect
import ipaddress
import json
import logging
import math
import os
import re
import threading
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

import numpy as np
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.middleware.cors import CORSMiddleware

from .attest import Attestor
from .config import make_reloadable_settings
from .exporter import TCDPrometheusExporter
from .kv import RollingHasher
from .multivariate import MultiVarConfig, MultiVarDetector
from .otel_exporter import TCDOtelExporter
from .receipt_v2 import build_v2_body
from .routing import StrategyRouter
from .telemetry_gpu import GpuSampler
from .utils import sanitize_floats
from .verify import verify_chain, verify_receipt_ex

try:  # formal detector runtime
    from .detector import DetectRequest, build_default_detector
except Exception:  # pragma: no cover
    DetectRequest = None  # type: ignore[assignment]
    build_default_detector = None  # type: ignore[assignment]

try:
    from .schemas import ReceiptView
except Exception:  # pragma: no cover
    ReceiptView = None  # type: ignore[assignment]

try:
    from .ratelimit import RateLimiter
except ImportError:  # pragma: no cover
    RateLimiter = Any  # type: ignore[misc,assignment]

try:
    from .ratelimit import RateKey, RateLimitConfig, RateLimitZoneConfig
except ImportError:  # pragma: no cover
    RateKey = None  # type: ignore[assignment]
    RateLimitConfig = None  # type: ignore[assignment]
    RateLimitZoneConfig = None  # type: ignore[assignment]

try:
    from .policies import PolicyStore
except ImportError:  # pragma: no cover
    PolicyStore = Any  # type: ignore[misc,assignment]

try:
    from .security_router import SecurityRouter, SecurityContext as RouterSecurityContext, SecuritySignalEnvelope
except ImportError:  # pragma: no cover
    SecurityRouter = None  # type: ignore[assignment]
    RouterSecurityContext = Any  # type: ignore[misc,assignment]
    SecuritySignalEnvelope = Any  # type: ignore[misc,assignment]

try:
    from .trust_graph import SubjectKey
except ImportError:  # pragma: no cover
    @dataclass(frozen=True)
    class SubjectKey:  # type: ignore[misc]
        tenant: str = ""
        user: str = ""
        session: str = ""
        model_id: str = ""

        def as_id(self) -> str:
            return "|".join(
                [
                    f"tenant={self.tenant or '*'}",
                    f"user={self.user or '*'}",
                    f"session={self.session or '*'}",
                    f"model={self.model_id or '*'}",
                ]
            )

try:  # pragma: no cover
    from .auth import build_authenticator_from_env
except ImportError:  # pragma: no cover
    build_authenticator_from_env = None  # type: ignore[assignment]

try:  # pragma: no cover
    from .logging import bind_request_meta, ensure_request_id, get_logger, log_decision

    _HAS_LOG = True
except ImportError:  # pragma: no cover
    _HAS_LOG = False
    bind_request_meta = None  # type: ignore[assignment]
    ensure_request_id = None  # type: ignore[assignment]
    get_logger = None  # type: ignore[assignment]
    log_decision = None  # type: ignore[assignment]

from tcd.risk_av import AlwaysValidConfig, AlwaysValidRiskController
import tcd.risk_av  # noqa: F401

try:  # pragma: no cover
    from .decision_engine import DecisionContext, DecisionEngine
    from .agent import TrustAgent
    from .rewrite_engine import RewriteEngine
    from .trust_graph import TrustGraph
    from .patch_runtime import PatchRuntime

    _HAS_TRUST_OS = True
except ImportError:  # pragma: no cover
    DecisionEngine = None  # type: ignore[assignment]
    DecisionContext = None  # type: ignore[assignment]
    TrustAgent = None  # type: ignore[assignment]
    RewriteEngine = None  # type: ignore[assignment]
    TrustGraph = None  # type: ignore[assignment]
    PatchRuntime = None  # type: ignore[assignment]
    _HAS_TRUST_OS = False

__all__ = [
    "ServiceHttpConfig",
    "VerifyLimits",
    "DiagnoseRequest",
    "RiskResponse",
    "VerifyRequest",
    "VerifyResponse",
    "create_http_runtime",
    "create_app",
]

_LOG = logging.getLogger(__name__)
_SETTINGS = make_reloadable_settings()

_SCHEMA = "tcd.http.service.v5"
_EVENT_ID_VERSION = "hev3"
_CFG_FP_VERSION = "hcfg3"
_SAFE_DIGEST_ALG = "sha256"

_ALLOWED_TRUST_ZONES = frozenset({"internet", "internal", "partner", "admin", "ops"})
_ALLOWED_ROUTE_PROFILES = frozenset({"inference", "batch", "admin", "control", "metrics", "health"})
_ALLOWED_RISK_LABELS = frozenset({"low", "normal", "elevated", "high", "critical"})
_ALLOWED_ACTIONS = frozenset({"none", "allow", "degrade", "block", "reject", "advisory"})
_ALLOWED_HASH_ALGS = frozenset({"sha256", "blake3"})
_ALLOWED_AUTH_MODES = frozenset({"none", "disabled", "service_token", "bearer", "jwt", "hmac", "mtls", "loopback_bypass"})
_ALLOWED_CORS_SCHEMES = ("http://", "https://")

_ASCII_CTRL_RE = re.compile(r"[\x00-\x1F\x7F]")
_SAFE_LABEL_RE = re.compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.:\-]{0,127}$")
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#/+=]{0,255}$")
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:\-]{1,128}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_MAX_TRACE = 4096
_MAX_SPECT = 4096
_MAX_FEATS = 2048
_DEFAULT_MAX_BODY_BYTES = 1 * 1024 * 1024
_DEFAULT_MAX_JSON_COMPONENT_BYTES = 256_000
_DEFAULT_MAX_HEADERS_BYTES = 32 * 1024
_DEFAULT_MAX_HEADER_COUNT = 128
_DEFAULT_RECEIPT_BODY_LIMIT = 512_000
_DEFAULT_VERIFY_CHAIN_FACTOR = 256
_DEFAULT_MAX_JSON_DEPTH = 16


# ---------------------------------------------------------------------------
# Low-level hardening helpers
# ---------------------------------------------------------------------------

def _has_unsafe_unicode(s: str) -> bool:
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False


def _strip_unsafe_text(v: Any, *, max_len: int) -> str:
    if not isinstance(v, str):
        return ""
    s = unicodedata.normalize("NFC", v[:max_len])
    if s.isascii():
        if _ASCII_CTRL_RE.search(s):
            s = _ASCII_CTRL_RE.sub("", s)
        return s.strip()

    if not _ASCII_CTRL_RE.search(s) and not _has_unsafe_unicode(s):
        if any(0x80 <= ord(ch) <= 0x9F for ch in s):
            pass
        else:
            return s.strip()

    out: List[str] = []
    for ch in s:
        o = ord(ch)
        if ch in ("\u2028", "\u2029"):
            continue
        if o < 0x20 or o == 0x7F:
            continue
        if 0x80 <= o <= 0x9F:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            continue
        out.append(ch)
    return "".join(out).strip()


def _safe_label(v: Any, *, default: str) -> str:
    s = _strip_unsafe_text(v, max_len=64).lower()
    if not s or not _SAFE_LABEL_RE.fullmatch(s):
        return default
    return s


def _safe_name(v: Any, *, default: str) -> str:
    s = _strip_unsafe_text(v, max_len=128)
    if not s or not _SAFE_NAME_RE.fullmatch(s):
        return default
    return s


def _safe_id(v: Any, *, default: Optional[str], max_len: int = 256) -> Optional[str]:
    s = _strip_unsafe_text(v, max_len=max_len)
    if not s or not _SAFE_ID_RE.fullmatch(s):
        return default
    return s


def _safe_text(v: Any, *, max_len: int = 256) -> str:
    if isinstance(v, str):
        return _strip_unsafe_text(v, max_len=max_len)
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "<bytes>"
    return f"<{type(v).__name__}>"


def _opaque_text(v: Any, *, max_bytes: int) -> Optional[str]:
    """
    Opaque text path for receipt_body: NEVER sanitize, normalize, or truncate.
    """
    if not isinstance(v, str):
        return None
    try:
        b = v.encode("utf-8", errors="strict")
    except Exception:
        return None
    if len(b) > max_bytes:
        return None
    return v


def _opaque_handle(v: Any, *, max_len: int = 4096) -> Optional[str]:
    if not isinstance(v, str):
        return None
    s = v.strip()
    if not s or len(s) > max_len:
        return None
    return s


def _coerce_float(v: Any) -> Optional[float]:
    if type(v) is bool:
        return None
    if isinstance(v, (int, float)):
        try:
            x = float(v)
        except Exception:
            return None
        return x if math.isfinite(x) else None
    if isinstance(v, str):
        s = v.strip()
        if not s or len(s) > 64:
            return None
        try:
            x = float(s)
        except Exception:
            return None
        return x if math.isfinite(x) else None
    return None


def _coerce_int(v: Any) -> Optional[int]:
    if type(v) is int:
        return int(v)
    if isinstance(v, str):
        s = v.strip()
        if not s or len(s) > 64:
            return None
        if s.startswith(("+", "-")):
            sign, digits = s[0], s[1:]
        else:
            sign, digits = "", s
        if not digits.isdigit():
            return None
        try:
            return int(sign + digits, 10)
        except Exception:
            return None
    return None


def _coerce_bool(v: Any, *, default: bool = False) -> bool:
    if type(v) is bool:
        return v
    if type(v) is int:
        if v == 0:
            return False
        if v == 1:
            return True
    if isinstance(v, str):
        s = v.strip().lower()
        if s in {"1", "true", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "no", "n", "off"}:
            return False
    return default


def _clamp_float(v: Any, *, default: float, lo: float, hi: float) -> float:
    x = _coerce_float(v)
    if x is None:
        return float(default)
    return float(min(hi, max(lo, x)))


def _clamp_int(v: Any, *, default: int, lo: int, hi: int) -> int:
    x = _coerce_int(v)
    if x is None:
        return int(default)
    return int(min(hi, max(lo, x)))


def _stable_float(x: float) -> str:
    if not math.isfinite(float(x)):
        return "0"
    s = f"{float(x):.12f}".rstrip("0").rstrip(".")
    return s or "0"


def _stable_jsonable(obj: Any) -> Any:
    if obj is None or isinstance(obj, (bool, int)):
        return obj
    if isinstance(obj, float):
        return _stable_float(obj)
    if isinstance(obj, str):
        return obj
    if isinstance(obj, Mapping):
        return {str(k): _stable_jsonable(obj[k]) for k in sorted(obj.keys(), key=lambda x: str(x))}
    if isinstance(obj, (list, tuple)):
        return [_stable_jsonable(x) for x in obj]
    if isinstance(obj, (set, frozenset)):
        xs = [_stable_jsonable(x) for x in obj]
        try:
            return sorted(xs)
        except Exception:
            return xs
    return _safe_name(type(obj).__name__, default="object")


def _canon_json_bytes(obj: Any) -> bytes:
    return json.dumps(
        _stable_jsonable(obj),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")


def _hash_hex(*, ctx: str, payload: Mapping[str, Any], out_hex: int = 32, alg: str = "sha256") -> str:
    raw = ctx.encode("utf-8", errors="strict") + b"\x00" + _canon_json_bytes(payload)
    if alg == "blake3":
        try:
            from .crypto import Blake3Hash  # type: ignore
            return Blake3Hash().hex(raw, ctx=ctx)[:out_hex]
        except Exception:
            pass
    return hashlib.sha256(raw).hexdigest()[:out_hex]


def _body_digest(body: bytes, *, alg: str) -> str:
    if alg == "blake3":
        try:
            from .crypto import Blake3Hash  # type: ignore
            return f"body:blake3:{Blake3Hash().hex(body, ctx='tcd:http:body')[:32]}"
        except Exception:
            pass
    return f"body:sha256:{hashlib.sha256(body).hexdigest()[:32]}"


def _compact_json(obj: Any, *, max_bytes: int) -> str:
    try:
        txt = json.dumps(_stable_jsonable(obj), ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)
    except Exception:
        return "{}"
    return txt if len(txt.encode("utf-8", errors="strict")) <= max_bytes else "{}"


def _is_hex(s: Optional[str]) -> bool:
    if not s:
        return True
    ss = s[2:] if s.startswith("0x") else s
    if len(ss) % 2 != 0:
        return False
    return bool(_HEX_RE.fullmatch(ss))


def _loopback_host(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return bool(ip.is_loopback)
    except Exception:
        return host in {"localhost", "unix", "127.0.0.1", "::1"}


def _client_host(request: Request) -> str:
    try:
        return _safe_text(request.client.host if request.client else "", max_len=128) or "unknown"
    except Exception:
        return "unknown"


def _sanitize_numeric_array(values: Sequence[Any], *, max_len: int) -> List[float]:
    xs = list(values)[: max(0, int(max_len))]
    try:
        out = sanitize_floats(xs, max_len=max_len)
    except TypeError:
        out = sanitize_floats(xs)  # type: ignore[misc]
    if isinstance(out, tuple):
        out = out[0]
    if isinstance(out, np.ndarray):
        arr = out.astype(float).tolist()
    else:
        arr = list(out)
    safe: List[float] = []
    for x in arr:
        fx = _coerce_float(x)
        if fx is None:
            continue
        safe.append(float(fx))
    return safe[:max_len]


def _json_depth_exceeds(raw: bytes, *, max_depth: int) -> bool:
    try:
        text = raw.decode("utf-8", errors="strict")
    except Exception:
        return True
    depth = 0
    in_str = False
    esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch in "{[":
            depth += 1
            if depth > max_depth:
                return True
        elif ch in "}]":
            depth = max(0, depth - 1)
    return False


class _JsonBudget:
    __slots__ = ("max_nodes", "max_items", "max_depth", "max_str_total", "nodes", "str_used")

    def __init__(self, *, max_nodes: int, max_items: int, max_depth: int, max_str_total: int) -> None:
        self.max_nodes = max_nodes
        self.max_items = max_items
        self.max_depth = max_depth
        self.max_str_total = max_str_total
        self.nodes = 0
        self.str_used = 0

    def take_node(self) -> bool:
        self.nodes += 1
        return self.nodes <= self.max_nodes

    def take_str(self, n: int) -> bool:
        self.str_used += n
        return self.str_used <= self.max_str_total


def _safe_json_value(obj: Any, *, budget: _JsonBudget, depth: int, max_str_len: int) -> Any:
    if not budget.take_node():
        return "[truncated]"
    t = type(obj)
    if obj is None:
        return None
    if t is bool:
        return bool(obj)
    if t is int:
        if obj.bit_length() > 256:
            return "[int:oversize]"
        return int(obj)
    if t is float:
        return float(obj) if math.isfinite(obj) else None
    if t is str:
        s = _strip_unsafe_text(obj, max_len=max_str_len)
        if not budget.take_str(len(s)):
            return "[truncated]"
        return s
    if t in (bytes, bytearray, memoryview):
        return f"[bytes:{len(obj)}]"
    if depth >= budget.max_depth:
        return "[truncated-depth]"
    if t is dict:
        out: Dict[str, Any] = {}
        n = 0
        for k, v in obj.items():
            if n >= budget.max_items:
                out["_truncated"] = True
                break
            if type(k) is not str:
                continue
            kk = _safe_id(k, default=None, max_len=128)
            if not kk:
                continue
            out[kk] = _safe_json_value(v, budget=budget, depth=depth + 1, max_str_len=max_str_len)
            n += 1
        return out
    if t in (list, tuple):
        out_list: List[Any] = []
        for idx, item in enumerate(obj):
            if idx >= budget.max_items:
                out_list.append("[truncated]")
                break
            out_list.append(_safe_json_value(item, budget=budget, depth=depth + 1, max_str_len=max_str_len))
        return out_list
    return f"[type:{t.__name__}]"


def _sanitize_json_mapping(
    obj: Any,
    *,
    max_depth: int,
    max_items: int,
    max_str_len: int,
    max_total_bytes: int,
) -> Dict[str, Any]:
    if type(obj) is not dict:
        return {}
    budget = _JsonBudget(
        max_nodes=max(64, max_items * 8),
        max_items=max_items,
        max_depth=max_depth,
        max_str_total=max_total_bytes,
    )
    out = _safe_json_value(dict(obj), budget=budget, depth=0, max_str_len=max_str_len)
    return out if isinstance(out, dict) else {}


def _safe_context_subset(ctx: Dict[str, Any]) -> Dict[str, Any]:
    allow_keys = {
        "decoder",
        "temperature",
        "top_p",
        "gpu_util",
        "gpu_temp_c",
        "p99_latency_ms",
        "trust_zone",
        "route_profile",
        "risk_label",
        "threat_kind",
        "detector_text",
    }
    out: Dict[str, Any] = {}
    for k in allow_keys:
        if k not in ctx:
            continue
        v = ctx[k]
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[k] = v
    return out


def _filtered_kwargs_for(callable_obj: Any, kwargs: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        sig = inspect.signature(callable_obj)
    except Exception:
        return dict(kwargs)
    allowed = set(sig.parameters.keys())
    return {k: v for k, v in kwargs.items() if k in allowed}


def _call_prom(exporter: Any, method: str, *args: Any, **kwargs: Any) -> None:
    fn = getattr(exporter, method, None)
    if callable(fn):
        with contextlib.suppress(Exception):
            fn(*args, **kwargs)


def _call_otel(otel: Any, score: float, attrs: Mapping[str, Any]) -> None:
    if otel is None:
        return
    fn = getattr(otel, "push_metrics", None)
    if callable(fn):
        with contextlib.suppress(Exception):
            fn(score, attrs=dict(attrs))


def _extract_receipt_like(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if isinstance(obj, Mapping):
        return dict(obj)
    if hasattr(obj, "to_dict"):
        with contextlib.suppress(Exception):
            out = obj.to_dict()
            if isinstance(out, Mapping):
                return dict(out)
    if dataclasses.is_dataclass(obj):
        with contextlib.suppress(Exception):
            return dataclasses.asdict(obj)
    return {}


def _extract_route_dict(route: Any) -> Dict[str, Any]:
    if route is None:
        return {}
    if hasattr(route, "to_dict"):
        with contextlib.suppress(Exception):
            out = route.to_dict()
            if isinstance(out, Mapping):
                return dict(out)
    if dataclasses.is_dataclass(route):
        with contextlib.suppress(Exception):
            return dataclasses.asdict(route)
    if isinstance(route, Mapping):
        return dict(route)
    return {}


def _extract_security_public(decision: Any) -> Dict[str, Any]:
    if decision is None:
        return {}
    for meth in ("to_public_view", "to_dict"):
        fn = getattr(decision, meth, None)
        if callable(fn):
            with contextlib.suppress(Exception):
                out = fn()
                if isinstance(out, Mapping):
                    return dict(out)
    if dataclasses.is_dataclass(decision):
        with contextlib.suppress(Exception):
            return dataclasses.asdict(decision)
    return {}


def _route_required_action(route: Any) -> str:
    route_dict = _extract_route_dict(route)
    val = _safe_label(route_dict.get("required_action"), default="")
    if val in {"allow", "degrade", "block"}:
        return val
    action_hint = _safe_label(route_dict.get("action_hint"), default="")
    if action_hint in {"allow", "degrade", "block"}:
        return action_hint
    return "allow"


def _route_enforcement_mode(route: Any) -> str:
    route_dict = _extract_route_dict(route)
    val = _safe_label(route_dict.get("enforcement_mode"), default="")
    if val in {"advisory", "must_enforce", "fail_closed"}:
        return val
    return "advisory"


def _route_decide_compat(
    router: Any,
    *,
    decision_fail: bool,
    score: float,
    base_temp: float,
    base_top_p: float,
    base_max_tokens: Optional[int],
    risk_label: str,
    route_profile: str,
    trust_zone: str,
    threat_kind: Optional[str],
    threat_confidence: Optional[float],
    pq_required: bool,
    pq_unhealthy: bool,
    av_label: Optional[str],
    av_trigger: bool,
    controller_mode: Optional[str],
    guarantee_scope: Optional[str],
    request_id: Optional[str],
    trace_id: Optional[str],
    tenant_id: Optional[str],
    principal_id: Optional[str],
    meta: Mapping[str, Any],
) -> Any:
    if router is None:
        return None

    kwargs: Dict[str, Any] = {
        "decision_fail": bool(decision_fail),
        "score": float(score),
        "base_temp": float(base_temp),
        "base_top_p": float(base_top_p),
        "risk_label": risk_label,
        "route_profile": route_profile,
        "e_triggered": bool(av_trigger),
        "trust_zone": trust_zone,
        "threat_kind": threat_kind,
        "threat_kinds": [threat_kind] if threat_kind else None,
        "pq_unhealthy": bool(pq_unhealthy),
        "av_label": av_label,
        "av_trigger": bool(av_trigger),
        "controller_mode": controller_mode,
        "guarantee_scope": guarantee_scope,
        "max_tokens": base_max_tokens,
        "meta": dict(meta),
    }

    try:
        from .routing import StrategyRouteContext, StrategySignalEnvelope  # type: ignore
        kwargs["route_context"] = StrategyRouteContext(
            request_id=request_id,
            trace_id=trace_id,
            tenant_id=tenant_id,
            principal_id=principal_id,
            trust_zone=trust_zone,
            route_profile=route_profile,
        )
        kwargs["signal_envelope"] = StrategySignalEnvelope(
            source="http_service",
            trusted=True,
            signed=False,
            signer_kid=None,
            source_cfg_fp=None,
            source_policy_ref=None,
            freshness_ms=None,
            replay_checked=None,
        )
    except Exception:
        pass

    try:
        return router.decide(**_filtered_kwargs_for(router.decide, kwargs))
    except TypeError:
        try:
            return router.decide(
                decision_fail,
                score,
                base_temp=base_temp,
                base_top_p=base_top_p,
                risk_label=risk_label,
                route_profile=route_profile,
                e_triggered=bool(av_trigger),
                trust_zone=trust_zone,
                threat_kind=threat_kind,
                pq_unhealthy=bool(pq_unhealthy),
                av_label=av_label,
                av_trigger=bool(av_trigger),
                meta=dict(meta),
            )
        except Exception:
            return None
    except Exception:
        return None


def _av_step_compat(
    av: Any,
    *,
    req: Any,
    subject: Tuple[str, str, str],
    model_id: str,
    gpu_id: str,
    task: str,
    lang: str,
    score: float,
    p_value: float,
    drift_weight: float,
    meta: Mapping[str, Any],
) -> Dict[str, Any]:
    if av is None:
        return {}
    kwargs = {
        "request": req,
        "stream_id": f"{subject[0]}:{subject[1]}:{subject[2]}:{model_id}",
        "p_value": float(p_value),
        "score": float(score),
        "weight": float(drift_weight),
        "meta": dict(meta),
        "subject": subject,
        "policy_key": (task, lang, model_id),
        "scores": {"final": float(score)},
        "pvals": {"final": float(p_value)},
        "drift_weight": float(drift_weight),
    }
    step_fn = getattr(av, "step", None)
    if not callable(step_fn):
        return {}
    try:
        out = step_fn(**_filtered_kwargs_for(step_fn, kwargs))
        return dict(out) if isinstance(out, Mapping) else {}
    except TypeError:
        pass
    with contextlib.suppress(Exception):
        out = step_fn(req)
        if isinstance(out, Mapping):
            return dict(out)
    return {}


def _build_attestor_compat(*, hash_alg: str) -> Optional[Any]:
    if Attestor is None:
        return None
    ctor = Attestor
    kwargs = _filtered_kwargs_for(ctor, {"hash_alg": hash_alg})
    with contextlib.suppress(Exception):
        return ctor(**kwargs)
    with contextlib.suppress(Exception):
        return ctor()
    return None


def _build_security_router_compat(
    *,
    policy_store: Any,
    rate_limiter: Any,
    attestor: Any,
    detector_runtime: Any,
    strategy_router: Any,
) -> Optional[Any]:
    if SecurityRouter is None or policy_store is None:
        return None
    kwargs = {
        "policy_store": policy_store,
        "rate_limiter": rate_limiter,
        "attestor": attestor,
        "detector_runtime": detector_runtime,
        "base_av": AlwaysValidConfig(),
        "strategy_router": strategy_router,
    }
    with contextlib.suppress(Exception):
        return SecurityRouter(**_filtered_kwargs_for(SecurityRouter, kwargs))
    with contextlib.suppress(Exception):
        return SecurityRouter(policy_store, rate_limiter, attestor=attestor, detector_runtime=detector_runtime)
    return None


def _security_context_compat(
    *,
    req: "DiagnoseRequest",
    request: Request,
    body_digest: str,
    request_id: str,
    trace_id: Optional[str],
    event_id: str,
    security_signal_envelope: Optional[Any],
) -> Any:
    if RouterSecurityContext is Any:
        return None
    ctx_map = {
        "tenant": req.tenant,
        "user": req.user,
        "session": req.session,
        "model_id": req.model_id,
        "gpu_id": req.gpu_id,
        "task": req.task,
        "lang": req.lang,
        "trust_zone": req.trust_zone or "internet",
        "route": req.route_profile or "inference",
        "access_channel": "http",
        "client_app": "http",
        "env": _safe_label(req.context.get("env", ""), default="") if isinstance(req.context, Mapping) else "",
    }
    kwargs = {
        "subject": SubjectKey(
            tenant=req.tenant,
            user=req.user,
            session=req.session,
            model_id=req.model_id,
        ),
        "ctx": ctx_map,
        "tokens_in": max(0, int(req.tokens_delta)),
        "tokens_out": max(0, int(req.base_max_tokens or 0)),
        "ip": _client_host(request),
        "kind": "inference",
        "request_id": request_id,
        "trace_id": trace_id,
        "event_id": event_id,
        "idempotency_key": req.idempotency_key,
        "body_digest": body_digest,
        "tenant_id": req.tenant,
        "principal_id": _safe_text(getattr(request.state, "auth_principal", None), max_len=128) or req.user,
        "trust_zone": req.trust_zone,
        "route_profile": req.route_profile,
        "base_temp": req.base_temp,
        "base_top_p": req.base_top_p,
        "base_max_tokens": req.base_max_tokens,
        "pq_required": req.pq_required,
        "pq_unhealthy": False,
        "signal_envelope": security_signal_envelope,
        "meta": {
            "build_id": req.build_id,
            "image_digest": req.image_digest,
            "compliance_tags": list(req.compliance_tags),
            "request_path": request.url.path,
            "auth_mode": _safe_text(getattr(request.state, "auth_mode", None), max_len=64) or None,
        },
    }
    try:
        return RouterSecurityContext(**_filtered_kwargs_for(RouterSecurityContext, kwargs))
    except Exception:
        return None


def _hash_handle_public(handle: Optional[str]) -> Optional[str]:
    if not handle:
        return None
    return "vk1:" + _hash_hex(ctx="tcd:http:verify_key_handle", payload={"handle": handle}, out_hex=24)


def _receipt_view_model(payload: Mapping[str, Any]) -> Any:
    if ReceiptView is None:
        return None
    try:
        if hasattr(ReceiptView, "model_validate"):
            return ReceiptView.model_validate(dict(payload))
        return ReceiptView(**dict(payload))
    except Exception:
        return None


def _fallback_receipt_public(payload: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "schema": payload.get("schema"),
        "head": payload.get("receipt") or payload.get("head"),
        "receipt_ref": payload.get("receipt_ref") or payload.get("receipt") or payload.get("head"),
        "audit_ref": payload.get("audit_ref"),
        "event_id": payload.get("event_id"),
        "decision_id": payload.get("decision_id"),
        "route_plan_id": payload.get("route_plan_id"),
        "policy_ref": payload.get("policy_ref"),
        "policyset_ref": payload.get("policyset_ref"),
        "cfg_fp": payload.get("cfg_fp"),
        "verify_key_id": payload.get("verify_key_id"),
        "verify_key_fp": payload.get("verify_key_fp"),
        "receipt_integrity": payload.get("receipt_integrity"),
        "pq_signature_required": payload.get("pq_signature_required"),
        "pq_signature_ok": payload.get("pq_signature_ok"),
        "integrity_ok": payload.get("integrity_ok"),
        "integrity_errors": payload.get("integrity_errors") or [],
    }


def _fallback_receipt_verification(payload: Mapping[str, Any], *, include_verify_key: bool) -> Dict[str, Any]:
    return {
        "schema": payload.get("schema"),
        "head": payload.get("receipt") or payload.get("head"),
        "body": payload.get("receipt_body") or payload.get("body"),
        "sig": payload.get("receipt_sig") or payload.get("sig"),
        "verify_key": payload.get("verify_key") if include_verify_key else None,
        "verify_key_id": payload.get("verify_key_id"),
        "verify_key_fp": payload.get("verify_key_fp"),
        "receipt_integrity": payload.get("receipt_integrity"),
        "body_kind": payload.get("body_kind"),
        "body_digest": payload.get("body_digest"),
        "head_verified": payload.get("head_verified"),
        "body_canonical_verified": payload.get("body_canonical_verified"),
        "integrity_hash_verified": payload.get("integrity_hash_verified"),
        "signature_verified": payload.get("signature_verified"),
        "verify_key_allowed": payload.get("verify_key_allowed"),
        "policy_binding_verified": payload.get("policy_binding_verified"),
        "cfg_binding_verified": payload.get("cfg_binding_verified"),
        "integrity_ok": payload.get("integrity_ok"),
        "integrity_errors": payload.get("integrity_errors") or [],
    }


def _build_receipt_surfaces(
    payload: Mapping[str, Any],
    *,
    expose_verification_bundle_public: bool,
    expose_verify_key_public: bool,
) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
    rv = _receipt_view_model(payload)
    if rv is not None:
        with contextlib.suppress(Exception):
            pub = rv.to_public_dict(strict=False)
            ver = rv.to_verification_dict(strict=False, include_verify_key=bool(expose_verify_key_public))
            return dict(pub or {}), (dict(ver or {}) if expose_verification_bundle_public else None)
    pub2 = _fallback_receipt_public(payload)
    ver2 = _fallback_receipt_verification(payload, include_verify_key=bool(expose_verify_key_public))
    return pub2, (ver2 if expose_verification_bundle_public else None)


def _compute_array_digest(trace: Sequence[float], spectrum: Sequence[float], features: Sequence[float], *, alg: str) -> str:
    if RollingHasher is not None:
        with contextlib.suppress(Exception):
            rh = RollingHasher(alg=alg, ctx="tcd:http:array_digest")
            rh.update_ints([int(round(float(x) * 1_000_000.0)) for x in list(trace)[:1024]])
            rh.update_ints([int(round(float(x) * 1_000_000.0)) for x in list(spectrum)[:1024]])
            rh.update_ints([int(round(float(x) * 1_000_000.0)) for x in list(features)[:1024]])
            return rh.hex()
    raw = _canon_json_bytes(
        {
            "trace": [round(float(x), 6) for x in list(trace)[:1024]],
            "spectrum": [round(float(x), 6) for x in list(spectrum)[:1024]],
            "features": [round(float(x), 6) for x in list(features)[:1024]],
        }
    )
    if alg == "blake3":
        try:
            from .crypto import Blake3Hash  # type: ignore
            return Blake3Hash().hex(raw, ctx="tcd:http:array_digest")
        except Exception:
            pass
    return hashlib.sha256(raw).hexdigest()


# ---------------------------------------------------------------------------
# Config and response models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ServiceHttpConfig:
    api_version: str = "0.15.0"
    enable_docs: bool = False
    strict_mode: bool = False

    max_body_bytes: int = _DEFAULT_MAX_BODY_BYTES
    max_json_component_bytes: int = _DEFAULT_MAX_JSON_COMPONENT_BYTES
    max_headers_bytes: int = _DEFAULT_MAX_HEADERS_BYTES
    max_header_count: int = _DEFAULT_MAX_HEADER_COUNT
    max_inbound_json_depth: int = _DEFAULT_MAX_JSON_DEPTH
    max_component_depth: int = 6
    max_component_items: int = 128
    max_component_str_len: int = 1024

    edge_rps: float = 10.0
    edge_burst: int = 20

    subject_capacity: float = 60.0
    subject_refill_per_s: float = 30.0
    tokens_divisor_default: float = 50.0

    verify_window_max: int = 4096
    verify_chain_payload_factor: int = _DEFAULT_VERIFY_CHAIN_FACTOR

    require_service_token: bool = False
    allow_no_auth_local: bool = True
    service_token_env_var: str = "TCD_HTTP_SERVICE_TOKEN"

    enable_authenticator: bool = True
    require_authenticator: bool = False
    allow_service_token_fallback: bool = True
    allowed_auth_modes: Tuple[str, ...] = ()

    cors_allow_all: bool = False
    cors_origins: Tuple[str, ...] = (
        "http://127.0.0.1",
        "http://127.0.0.1:3000",
        "http://localhost",
        "http://localhost:3000",
    )

    receipts_enable_default: bool = True
    require_receipts_on_fail: bool = True
    require_receipts_when_pq: bool = True
    require_security_router_when_strict: bool = False
    require_attestor_when_receipt_required: bool = False
    require_finalized_receipt_surface_when_strict: bool = True

    expose_verify_key_public: bool = False
    expose_verification_bundle_public: bool = False
    expose_legacy_receipt_aliases: bool = False

    allow_detector_text_synthesis_for_compat: bool = False

    hash_alg: str = "blake3"
    alpha_wealth_floor: float = -1.0

    build_id: Optional[str] = None
    image_digest: Optional[str] = None

    def normalized_copy(self) -> "ServiceHttpConfig":
        api_version = _safe_text(self.api_version, max_len=32) or "0.15.0"
        hash_alg = _safe_label(self.hash_alg, default="sha256")
        if hash_alg not in _ALLOWED_HASH_ALGS:
            hash_alg = "sha256"

        cors: List[str] = []
        for item in self.cors_origins:
            s = _safe_text(item, max_len=256)
            if not s:
                continue
            if not any(s.startswith(p) for p in _ALLOWED_CORS_SCHEMES):
                continue
            cors.append(s)
        if not cors:
            cors = [
                "http://127.0.0.1",
                "http://127.0.0.1:3000",
                "http://localhost",
                "http://localhost:3000",
            ]

        modes: List[str] = []
        for x in self.allowed_auth_modes:
            s = _safe_label(x, default="")
            if s and s in _ALLOWED_AUTH_MODES and s not in modes:
                modes.append(s)

        return ServiceHttpConfig(
            api_version=api_version,
            enable_docs=bool(self.enable_docs),
            strict_mode=bool(self.strict_mode),
            max_body_bytes=_clamp_int(self.max_body_bytes, default=_DEFAULT_MAX_BODY_BYTES, lo=1024, hi=64 * 1024 * 1024),
            max_json_component_bytes=_clamp_int(self.max_json_component_bytes, default=_DEFAULT_MAX_JSON_COMPONENT_BYTES, lo=1024, hi=4 * 1024 * 1024),
            max_headers_bytes=_clamp_int(self.max_headers_bytes, default=_DEFAULT_MAX_HEADERS_BYTES, lo=1024, hi=256 * 1024),
            max_header_count=_clamp_int(self.max_header_count, default=_DEFAULT_MAX_HEADER_COUNT, lo=8, hi=1024),
            max_inbound_json_depth=_clamp_int(self.max_inbound_json_depth, default=_DEFAULT_MAX_JSON_DEPTH, lo=2, hi=64),
            max_component_depth=_clamp_int(self.max_component_depth, default=6, lo=2, hi=16),
            max_component_items=_clamp_int(self.max_component_items, default=128, lo=8, hi=2048),
            max_component_str_len=_clamp_int(self.max_component_str_len, default=1024, lo=64, hi=16 * 1024),
            edge_rps=_clamp_float(self.edge_rps, default=10.0, lo=0.1, hi=10_000.0),
            edge_burst=_clamp_int(self.edge_burst, default=20, lo=1, hi=100_000),
            subject_capacity=_clamp_float(self.subject_capacity, default=60.0, lo=1.0, hi=10_000_000.0),
            subject_refill_per_s=_clamp_float(self.subject_refill_per_s, default=30.0, lo=0.1, hi=10_000_000.0),
            tokens_divisor_default=_clamp_float(self.tokens_divisor_default, default=50.0, lo=1.0, hi=10_000_000.0),
            verify_window_max=_clamp_int(self.verify_window_max, default=4096, lo=1, hi=100_000),
            verify_chain_payload_factor=_clamp_int(self.verify_chain_payload_factor, default=_DEFAULT_VERIFY_CHAIN_FACTOR, lo=16, hi=4096),
            require_service_token=bool(self.require_service_token),
            allow_no_auth_local=bool(self.allow_no_auth_local),
            service_token_env_var=_safe_name(self.service_token_env_var, default="TCD_HTTP_SERVICE_TOKEN"),
            enable_authenticator=bool(self.enable_authenticator),
            require_authenticator=bool(self.require_authenticator),
            allow_service_token_fallback=bool(self.allow_service_token_fallback),
            allowed_auth_modes=tuple(modes),
            cors_allow_all=bool(self.cors_allow_all),
            cors_origins=tuple(cors),
            receipts_enable_default=bool(self.receipts_enable_default),
            require_receipts_on_fail=bool(self.require_receipts_on_fail),
            require_receipts_when_pq=bool(self.require_receipts_when_pq),
            require_security_router_when_strict=bool(self.require_security_router_when_strict),
            require_attestor_when_receipt_required=bool(self.require_attestor_when_receipt_required),
            require_finalized_receipt_surface_when_strict=bool(self.require_finalized_receipt_surface_when_strict),
            expose_verify_key_public=bool(self.expose_verify_key_public),
            expose_verification_bundle_public=bool(self.expose_verification_bundle_public),
            expose_legacy_receipt_aliases=bool(self.expose_legacy_receipt_aliases),
            allow_detector_text_synthesis_for_compat=bool(self.allow_detector_text_synthesis_for_compat),
            hash_alg=hash_alg,
            alpha_wealth_floor=_clamp_float(self.alpha_wealth_floor, default=-1.0, lo=-10_000.0, hi=10_000.0),
            build_id=_safe_text(self.build_id, max_len=128) or None,
            image_digest=_safe_text(self.image_digest, max_len=256) or None,
        )

    def fingerprint(self) -> str:
        cfg = self.normalized_copy()
        payload = {
            "api_version": cfg.api_version,
            "enable_docs": cfg.enable_docs,
            "strict_mode": cfg.strict_mode,
            "max_body_bytes": cfg.max_body_bytes,
            "max_json_component_bytes": cfg.max_json_component_bytes,
            "max_headers_bytes": cfg.max_headers_bytes,
            "max_header_count": cfg.max_header_count,
            "max_inbound_json_depth": cfg.max_inbound_json_depth,
            "max_component_depth": cfg.max_component_depth,
            "max_component_items": cfg.max_component_items,
            "max_component_str_len": cfg.max_component_str_len,
            "edge_rps": _stable_float(cfg.edge_rps),
            "edge_burst": cfg.edge_burst,
            "subject_capacity": _stable_float(cfg.subject_capacity),
            "subject_refill_per_s": _stable_float(cfg.subject_refill_per_s),
            "tokens_divisor_default": _stable_float(cfg.tokens_divisor_default),
            "verify_window_max": cfg.verify_window_max,
            "verify_chain_payload_factor": cfg.verify_chain_payload_factor,
            "require_service_token": cfg.require_service_token,
            "allow_no_auth_local": cfg.allow_no_auth_local,
            "service_token_env_var": cfg.service_token_env_var,
            "enable_authenticator": cfg.enable_authenticator,
            "require_authenticator": cfg.require_authenticator,
            "allow_service_token_fallback": cfg.allow_service_token_fallback,
            "allowed_auth_modes": list(cfg.allowed_auth_modes),
            "cors_allow_all": cfg.cors_allow_all,
            "cors_origins": list(cfg.cors_origins),
            "receipts_enable_default": cfg.receipts_enable_default,
            "require_receipts_on_fail": cfg.require_receipts_on_fail,
            "require_receipts_when_pq": cfg.require_receipts_when_pq,
            "require_security_router_when_strict": cfg.require_security_router_when_strict,
            "require_attestor_when_receipt_required": cfg.require_attestor_when_receipt_required,
            "require_finalized_receipt_surface_when_strict": cfg.require_finalized_receipt_surface_when_strict,
            "expose_verify_key_public": cfg.expose_verify_key_public,
            "expose_verification_bundle_public": cfg.expose_verification_bundle_public,
            "expose_legacy_receipt_aliases": cfg.expose_legacy_receipt_aliases,
            "allow_detector_text_synthesis_for_compat": cfg.allow_detector_text_synthesis_for_compat,
            "hash_alg": cfg.hash_alg,
            "alpha_wealth_floor": _stable_float(cfg.alpha_wealth_floor),
            "build_id": cfg.build_id,
            "image_digest": cfg.image_digest,
        }
        return f"{_CFG_FP_VERSION}:{_SAFE_DIGEST_ALG}:{_hash_hex(ctx='tcd:http:cfg', payload=payload, out_hex=48, alg='sha256')}"


@dataclass(frozen=True)
class VerifyLimits:
    max_head_hex_len: int = 130
    max_verify_key_len: int = 512
    max_sig_hex_len: int = 200
    max_receipt_body_bytes: int = _DEFAULT_RECEIPT_BODY_LIMIT
    max_window: int = 4096
    chain_payload_factor: int = _DEFAULT_VERIFY_CHAIN_FACTOR

    def normalized_copy(self) -> "VerifyLimits":
        return VerifyLimits(
            max_head_hex_len=_clamp_int(self.max_head_hex_len, default=130, lo=16, hi=4096),
            max_verify_key_len=_clamp_int(self.max_verify_key_len, default=512, lo=16, hi=32768),
            max_sig_hex_len=_clamp_int(self.max_sig_hex_len, default=200, lo=16, hi=32768),
            max_receipt_body_bytes=_clamp_int(self.max_receipt_body_bytes, default=_DEFAULT_RECEIPT_BODY_LIMIT, lo=256, hi=8 * 1024 * 1024),
            max_window=_clamp_int(self.max_window, default=4096, lo=1, hi=100_000),
            chain_payload_factor=_clamp_int(self.chain_payload_factor, default=_DEFAULT_VERIFY_CHAIN_FACTOR, lo=16, hi=8192),
        )

    @property
    def max_chain_payload_bytes(self) -> int:
        return self.max_window * self.chain_payload_factor


@dataclass(frozen=True)
class _CompiledHttpBundle:
    version: int
    updated_at_unix_ns: int
    cfg_fp: str
    config: ServiceHttpConfig
    verify_limits: VerifyLimits
    warnings: Tuple[str, ...]
    errors: Tuple[str, ...]


def _build_http_cfg_from_env() -> Tuple[ServiceHttpConfig, VerifyLimits]:
    cfg = ServiceHttpConfig(
        api_version=os.getenv("TCD_HTTP_API_VERSION", "0.15.0"),
        enable_docs=_coerce_bool(os.getenv("TCD_HTTP_ENABLE_DOCS", "0"), default=False),
        strict_mode=_coerce_bool(os.getenv("TCD_HTTP_STRICT_MODE", "0"), default=False),
        max_body_bytes=_coerce_int(os.getenv("TCD_HTTP_MAX_BODY_BYTES")) or _DEFAULT_MAX_BODY_BYTES,
        max_json_component_bytes=_coerce_int(os.getenv("TCD_HTTP_MAX_JSON_COMPONENT_BYTES")) or _DEFAULT_MAX_JSON_COMPONENT_BYTES,
        max_headers_bytes=_coerce_int(os.getenv("TCD_HTTP_MAX_HEADERS_BYTES")) or _DEFAULT_MAX_HEADERS_BYTES,
        max_header_count=_coerce_int(os.getenv("TCD_HTTP_MAX_HEADER_COUNT")) or _DEFAULT_MAX_HEADER_COUNT,
        max_inbound_json_depth=_coerce_int(os.getenv("TCD_HTTP_MAX_JSON_DEPTH")) or _DEFAULT_MAX_JSON_DEPTH,
        max_component_depth=_coerce_int(os.getenv("TCD_HTTP_MAX_COMPONENT_DEPTH")) or 6,
        max_component_items=_coerce_int(os.getenv("TCD_HTTP_MAX_COMPONENT_ITEMS")) or 128,
        max_component_str_len=_coerce_int(os.getenv("TCD_HTTP_MAX_COMPONENT_STR_LEN")) or 1024,
        edge_rps=_coerce_float(os.getenv("TCD_HTTP_EDGE_RPS")) or 10.0,
        edge_burst=_coerce_int(os.getenv("TCD_HTTP_EDGE_BURST")) or 20,
        subject_capacity=_coerce_float(os.getenv("TCD_HTTP_SUBJECT_CAPACITY")) or 60.0,
        subject_refill_per_s=_coerce_float(os.getenv("TCD_HTTP_SUBJECT_REFILL_PER_S")) or 30.0,
        verify_window_max=_coerce_int(os.getenv("TCD_HTTP_VERIFY_WINDOW_MAX")) or 4096,
        verify_chain_payload_factor=_coerce_int(os.getenv("TCD_HTTP_VERIFY_CHAIN_PAYLOAD_FACTOR")) or _DEFAULT_VERIFY_CHAIN_FACTOR,
        require_service_token=_coerce_bool(os.getenv("TCD_HTTP_REQUIRE_TOKEN"), default=False),
        allow_no_auth_local=_coerce_bool(os.getenv("TCD_HTTP_ALLOW_NO_AUTH_LOCAL"), default=True),
        service_token_env_var=os.getenv("TCD_HTTP_SERVICE_TOKEN_ENV_VAR", "TCD_HTTP_SERVICE_TOKEN"),
        enable_authenticator=_coerce_bool(os.getenv("TCD_HTTP_ENABLE_AUTHENTICATOR"), default=True),
        require_authenticator=_coerce_bool(os.getenv("TCD_HTTP_REQUIRE_AUTHENTICATOR"), default=False),
        allow_service_token_fallback=_coerce_bool(os.getenv("TCD_HTTP_ALLOW_SERVICE_TOKEN_FALLBACK"), default=True),
        allowed_auth_modes=tuple([x.strip() for x in (os.getenv("TCD_HTTP_ALLOWED_AUTH_MODES", "") or "").split(",") if x.strip()]),
        cors_allow_all=_coerce_bool(os.getenv("TCD_HTTP_CORS_ALLOW_ALL"), default=False),
        cors_origins=tuple([x.strip() for x in (os.getenv("TCD_HTTP_CORS_ORIGINS", "") or "").split(",") if x.strip()]) or (
            "http://127.0.0.1",
            "http://127.0.0.1:3000",
            "http://localhost",
            "http://localhost:3000",
        ),
        receipts_enable_default=_coerce_bool(os.getenv("TCD_HTTP_RECEIPTS_ENABLE_DEFAULT"), default=True),
        require_receipts_on_fail=_coerce_bool(os.getenv("TCD_HTTP_REQUIRE_RECEIPTS_ON_FAIL"), default=True),
        require_receipts_when_pq=_coerce_bool(os.getenv("TCD_HTTP_REQUIRE_RECEIPTS_WHEN_PQ"), default=True),
        require_security_router_when_strict=_coerce_bool(os.getenv("TCD_HTTP_REQUIRE_SECURITY_ROUTER_WHEN_STRICT"), default=False),
        require_attestor_when_receipt_required=_coerce_bool(os.getenv("TCD_HTTP_REQUIRE_ATTESTOR_WHEN_RECEIPT_REQUIRED"), default=False),
        require_finalized_receipt_surface_when_strict=_coerce_bool(os.getenv("TCD_HTTP_REQUIRE_FINAL_RECEIPT_SURFACE_STRICT"), default=True),
        expose_verify_key_public=_coerce_bool(os.getenv("TCD_HTTP_EXPOSE_VERIFY_KEY_PUBLIC"), default=False),
        expose_verification_bundle_public=_coerce_bool(os.getenv("TCD_HTTP_EXPOSE_VERIFICATION_BUNDLE_PUBLIC"), default=False),
        expose_legacy_receipt_aliases=_coerce_bool(os.getenv("TCD_HTTP_EXPOSE_LEGACY_RECEIPT_ALIASES"), default=False),
        allow_detector_text_synthesis_for_compat=_coerce_bool(os.getenv("TCD_HTTP_ALLOW_DETECTOR_TEXT_SYNTHESIS"), default=False),
        hash_alg=os.getenv("TCD_HASH_ALG", "blake3"),
        tokens_divisor_default=_coerce_float(os.getenv("TCD_HTTP_TOKENS_DIVISOR_DEFAULT")) or 50.0,
        alpha_wealth_floor=_coerce_float(os.getenv("TCD_HTTP_ALPHA_WEALTH_FLOOR")) or -1.0,
        build_id=os.getenv("TCD_BUILD_ID", "") or None,
        image_digest=os.getenv("TCD_IMAGE_DIGEST", "") or None,
    ).normalized_copy()

    verify_limits = VerifyLimits(
        max_head_hex_len=_coerce_int(os.getenv("TCD_VERIFY_HEAD_HEX_MAXLEN")) or 130,
        max_verify_key_len=_coerce_int(os.getenv("TCD_VERIFY_KEY_MAXLEN")) or 512,
        max_sig_hex_len=_coerce_int(os.getenv("TCD_VERIFY_SIG_HEX_MAXLEN")) or 200,
        max_receipt_body_bytes=_coerce_int(os.getenv("TCD_VERIFY_RECEIPT_BODY_MAXBYTES")) or _DEFAULT_RECEIPT_BODY_LIMIT,
        max_window=_coerce_int(os.getenv("TCD_VERIFY_WINDOW_MAX")) or 4096,
        chain_payload_factor=_coerce_int(os.getenv("TCD_VERIFY_CHAIN_PAYLOAD_FACTOR")) or _DEFAULT_VERIFY_CHAIN_FACTOR,
    ).normalized_copy()

    return cfg, verify_limits


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True, str_strip_whitespace=True)


class DiagnoseRequest(_Model):
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

    request_id: Optional[str] = None
    trace_id: Optional[str] = None
    idempotency_key: Optional[str] = None

    trust_zone: str = "internet"
    route_profile: str = "inference"
    risk_label: str = "normal"
    threat_kind: Optional[str] = None
    threat_confidence: Optional[float] = None
    pq_required: Optional[bool] = None
    build_id: Optional[str] = None
    image_digest: Optional[str] = None
    compliance_tags: List[str] = Field(default_factory=list)

    base_temp: float = 0.7
    base_top_p: float = 0.9
    base_max_tokens: Optional[int] = None

    context: Dict[str, Any] = Field(default_factory=dict)
    tokens_delta: int = Field(50, ge=-10_000_000, le=10_000_000)
    drift_score: float = Field(0.0)

    @field_validator("trace_vector", mode="before")
    @classmethod
    def _len_trace(cls, v: Any) -> List[float]:
        xs = list(v or [])
        if len(xs) > _MAX_TRACE:
            raise ValueError("trace_vector too large")
        return xs

    @field_validator("spectrum", mode="before")
    @classmethod
    def _len_spectrum(cls, v: Any) -> List[float]:
        xs = list(v or [])
        if len(xs) > _MAX_SPECT:
            raise ValueError("spectrum too large")
        return xs

    @field_validator("features", mode="before")
    @classmethod
    def _len_features(cls, v: Any) -> List[float]:
        xs = list(v or [])
        if len(xs) > _MAX_FEATS:
            raise ValueError("features too large")
        return xs

    @field_validator("entropy", "threat_confidence", "base_temp", "base_top_p", "drift_score", mode="before")
    @classmethod
    def _floatish(cls, v: Any) -> Any:
        if v is None:
            return None
        x = _coerce_float(v)
        return None if x is None else float(x)

    @field_validator("step_id", "base_max_tokens", mode="before")
    @classmethod
    def _intish(cls, v: Any) -> Any:
        if v is None:
            return None
        x = _coerce_int(v)
        return None if x is None else int(x)

    @field_validator("model_id", "gpu_id", "task", "lang", "tenant", "user", "session", "request_id", "trace_id", "build_id", "image_digest", mode="before")
    @classmethod
    def _ids(cls, v: Any) -> Any:
        if v is None:
            return None
        return _safe_text(v, max_len=128)

    @field_validator("idempotency_key", mode="before")
    @classmethod
    def _idem(cls, v: Any) -> Any:
        if v is None:
            return None
        s = _safe_text(v, max_len=128)
        if not s or not _IDEMPOTENCY_KEY_RE.fullmatch(s):
            return None
        return s

    @field_validator("trust_zone", mode="before")
    @classmethod
    def _tz(cls, v: Any) -> str:
        s = _safe_label(v, default="internet")
        return s if s in _ALLOWED_TRUST_ZONES else "internet"

    @field_validator("route_profile", mode="before")
    @classmethod
    def _rp(cls, v: Any) -> str:
        s = _safe_label(v, default="inference")
        return s if s in _ALLOWED_ROUTE_PROFILES else "inference"

    @field_validator("risk_label", mode="before")
    @classmethod
    def _rl(cls, v: Any) -> str:
        s = _safe_label(v, default="normal")
        return s if s in _ALLOWED_RISK_LABELS else "normal"

    @field_validator("threat_kind", mode="before")
    @classmethod
    def _threat(cls, v: Any) -> Any:
        if v is None:
            return None
        s = _safe_label(v, default="")
        return s or None

    @field_validator("pq_required", mode="before")
    @classmethod
    def _pq_req(cls, v: Any) -> Any:
        if v is None:
            return None
        return _coerce_bool(v)

    @field_validator("compliance_tags", mode="before")
    @classmethod
    def _tags(cls, v: Any) -> List[str]:
        if v is None:
            return []
        seq = [v] if isinstance(v, str) else list(v)
        out: List[str] = []
        seen = set()
        for item in seq[:32]:
            s = _safe_label(item, default="")
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    @field_validator("context", mode="before")
    @classmethod
    def _ctx(cls, v: Any) -> Dict[str, Any]:
        return _sanitize_json_mapping(v or {}, max_depth=4, max_items=64, max_str_len=256, max_total_bytes=32_000)

    @model_validator(mode="after")
    def _normalize_ranges(self) -> "DiagnoseRequest":
        base_temp = self.base_temp
        if base_temp is None or not math.isfinite(base_temp):
            base_temp = 0.7
        base_temp = max(0.0, min(10.0, float(base_temp)))

        base_top_p = self.base_top_p
        if base_top_p is None or not math.isfinite(base_top_p):
            base_top_p = 0.9
        base_top_p = max(0.0, min(1.0, float(base_top_p)))

        base_max_tokens = self.base_max_tokens
        if base_max_tokens is not None:
            base_max_tokens = max(1, min(int(base_max_tokens), 10_000_000))

        threat_confidence = self.threat_confidence
        if threat_confidence is not None:
            threat_confidence = max(0.0, min(1.0, float(threat_confidence)))

        object.__setattr__(self, "base_temp", base_temp)
        object.__setattr__(self, "base_top_p", base_top_p)
        object.__setattr__(self, "base_max_tokens", base_max_tokens)
        object.__setattr__(self, "threat_confidence", threat_confidence)
        return self


class RiskResponse(_Model):
    verdict: bool
    allowed: Optional[bool] = None
    decision: Optional[str] = None
    required_action: Optional[str] = None
    enforcement_mode: Optional[str] = None

    score: float
    threshold: float
    budget_remaining: float
    components: Dict[str, Any]

    cause: Optional[str] = None
    action: Optional[str] = None
    step: int
    e_value: float
    alpha_alloc: float
    alpha_spent: float

    request_id: Optional[str] = None
    event_id: Optional[str] = None
    decision_id: Optional[str] = None
    route_plan_id: Optional[str] = None

    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None
    config_fingerprint: Optional[str] = None
    bundle_version: Optional[int] = None
    state_domain_id: Optional[str] = None
    controller_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None
    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None

    trust_zone: Optional[str] = None
    route_profile: Optional[str] = None
    threat_kind: Optional[str] = None
    pq_required: Optional[bool] = None
    pq_ok: Optional[bool] = None

    receipt_public: Dict[str, Any] = Field(default_factory=dict)
    receipt_verification: Optional[Dict[str, Any]] = None
    evidence_identity: Dict[str, Any] = Field(default_factory=dict)
    artifacts: Dict[str, Any] = Field(default_factory=dict)

    # Deprecated compatibility aliases. Kept only so older clients do not hard-break.
    receipt: Optional[str] = None
    receipt_body: Optional[str] = None
    receipt_sig: Optional[str] = None
    verify_key: Optional[str] = None

    @field_validator(
        "decision",
        "required_action",
        "enforcement_mode",
        "cause",
        "action",
        "request_id",
        "event_id",
        "decision_id",
        "route_plan_id",
        "policy_ref",
        "policyset_ref",
        "config_fingerprint",
        "state_domain_id",
        "controller_mode",
        "statistical_guarantee_scope",
        "audit_ref",
        "receipt_ref",
        "trust_zone",
        "route_profile",
        "threat_kind",
        "receipt",
        "receipt_body",
        "receipt_sig",
        "verify_key",
        mode="before",
    )
    @classmethod
    def _txt(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, str):
            return v if len(v) <= 256_000 else v[:256_000]
        return _safe_text(v, max_len=4096)

    @field_validator("score", "threshold", "budget_remaining", "e_value", "alpha_alloc", "alpha_spent", mode="before")
    @classmethod
    def _floats(cls, v: Any) -> Any:
        x = _coerce_float(v)
        return 0.0 if x is None else float(x)

    @field_validator("step", "bundle_version", mode="before")
    @classmethod
    def _ints(cls, v: Any) -> Any:
        x = _coerce_int(v)
        return 0 if x is None else max(0, int(x))

    @field_validator("components", "receipt_public", "evidence_identity", "artifacts", mode="before")
    @classmethod
    def _maps(cls, v: Any) -> Dict[str, Any]:
        return _sanitize_json_mapping(v or {}, max_depth=6, max_items=128, max_str_len=1024, max_total_bytes=_DEFAULT_MAX_JSON_COMPONENT_BYTES)

    @field_validator("receipt_verification", mode="before")
    @classmethod
    def _maybe_verification(cls, v: Any) -> Any:
        if v is None:
            return None
        return _sanitize_json_mapping(v, max_depth=6, max_items=128, max_str_len=2048, max_total_bytes=_DEFAULT_RECEIPT_BODY_LIMIT)

    @field_validator("verdict", "allowed", "pq_required", "pq_ok", mode="before")
    @classmethod
    def _bools(cls, v: Any) -> Any:
        if v is None:
            return None
        return _coerce_bool(v)


class SnapshotState(_Model):
    state: Dict[str, Any]

    @field_validator("state", mode="before")
    @classmethod
    def _state(cls, v: Any) -> Dict[str, Any]:
        return _sanitize_json_mapping(v or {}, max_depth=8, max_items=256, max_str_len=2048, max_total_bytes=256_000)


class VerifyRequest(_Model):
    receipt_head_hex: Optional[str] = Field(default=None)
    receipt_body_json: Optional[str] = Field(default=None)
    verify_key: Optional[str] = Field(default=None)
    verify_key_hex: Optional[str] = Field(default=None)  # legacy alias
    receipt_sig_hex: Optional[str] = Field(default=None)

    req_obj: Optional[Dict[str, Any]] = None
    comp_obj: Optional[Dict[str, Any]] = None
    e_obj: Optional[Dict[str, Any]] = None
    witness_segments: Optional[List[Dict[str, Any]]] = None

    heads: Optional[List[str]] = None
    bodies: Optional[List[str]] = None

    pq_required: Optional[bool] = None
    require_signature: Optional[bool] = None

    expected_policy_ref: Optional[str] = None
    expected_policyset_ref: Optional[str] = None
    expected_policy_digest: Optional[str] = None
    expected_cfg_fp: Optional[str] = None
    expected_build_id: Optional[str] = None
    expected_image_digest: Optional[str] = None

    @field_validator("receipt_head_hex", "receipt_sig_hex", mode="before")
    @classmethod
    def _hex_ok(cls, v: Any) -> Any:
        if v is None:
            return None
        s = _safe_text(v, max_len=32_768)
        if not _is_hex(s):
            raise ValueError("invalid hex")
        return s

    @field_validator("verify_key", "verify_key_hex", mode="before")
    @classmethod
    def _verify_key(cls, v: Any) -> Any:
        if v is None:
            return None
        s = _opaque_handle(v, max_len=4096)
        return s

    @field_validator("receipt_body_json", mode="before")
    @classmethod
    def _receipt_body(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, (dict, list)):
            return _compact_json(v, max_bytes=_DEFAULT_RECEIPT_BODY_LIMIT)
        if not isinstance(v, str):
            raise ValueError("receipt_body_json must be string or JSON object")
        try:
            if len(v.encode("utf-8", errors="strict")) > (_DEFAULT_RECEIPT_BODY_LIMIT * 2):
                raise ValueError("receipt_body_json too large")
        except Exception as e:
            raise ValueError(str(e)) from e
        return v

    @field_validator("req_obj", "comp_obj", "e_obj", mode="before")
    @classmethod
    def _jsons(cls, v: Any) -> Any:
        if v is None:
            return None
        return _sanitize_json_mapping(v, max_depth=8, max_items=256, max_str_len=2048, max_total_bytes=256_000)

    @field_validator("heads", mode="before")
    @classmethod
    def _heads_hex(cls, v: Any) -> Any:
        if v is None:
            return None
        xs = list(v)
        if any(not _is_hex(_safe_text(h, max_len=512)) for h in xs):
            raise ValueError("invalid head hex in list")
        return [_safe_text(x, max_len=512) for x in xs]

    @field_validator("bodies", mode="before")
    @classmethod
    def _bodies(cls, v: Any) -> Any:
        if v is None:
            return None
        out: List[str] = []
        for x in list(v):
            if not isinstance(x, str):
                raise ValueError("invalid chain body")
            out.append(x)
        return out

    @field_validator("witness_segments", mode="before")
    @classmethod
    def _wit(cls, v: Any) -> Any:
        if v is None:
            return None
        if not isinstance(v, (tuple, list)):
            raise ValueError("witness_segments must be list")
        out: List[Dict[str, Any]] = []
        for item in list(v)[:512]:
            if not isinstance(item, Mapping):
                raise ValueError("witness segment must be mapping")
            out.append(_sanitize_json_mapping(dict(item), max_depth=4, max_items=32, max_str_len=512, max_total_bytes=32_000))
        return out

    @field_validator(
        "expected_policy_ref",
        "expected_policyset_ref",
        "expected_policy_digest",
        "expected_cfg_fp",
        "expected_build_id",
        "expected_image_digest",
        mode="before",
    )
    @classmethod
    def _exp(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, str):
            return v
        return _safe_text(v, max_len=256)

    @field_validator("pq_required", "require_signature", mode="before")
    @classmethod
    def _pq(cls, v: Any) -> Any:
        if v is None:
            return None
        return _coerce_bool(v)


class VerifyResponse(_Model):
    ok: bool
    request_id: Optional[str] = None
    reason: Optional[str] = None
    report: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("request_id", "reason", mode="before")
    @classmethod
    def _txt(cls, v: Any) -> Any:
        if v is None:
            return None
        return _safe_text(v, max_len=256)

    @field_validator("report", mode="before")
    @classmethod
    def _report(cls, v: Any) -> Dict[str, Any]:
        return _sanitize_json_mapping(v or {}, max_depth=6, max_items=128, max_str_len=1024, max_total_bytes=64_000)


# ---------------------------------------------------------------------------
# Metrics and runtime helpers
# ---------------------------------------------------------------------------

_REQ_COUNTER = Counter("tcd_http_requests_total", "HTTP requests", ["route", "status"])
_REQ_LATENCY = Histogram(
    "tcd_http_request_latency_seconds",
    "HTTP request latency in seconds",
    ["route"],
    buckets=(0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0),
)
_REQ_REJECTED = Counter("tcd_http_rejected_total", "HTTP request rejections", ["route", "reason"])
_REQ_BODY_BYTES = Histogram(
    "tcd_http_request_body_bytes",
    "HTTP request body bytes",
    ["route"],
    buckets=(0, 128, 512, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304),
)
_REQ_HEADERS_BYTES = Histogram(
    "tcd_http_request_headers_bytes",
    "HTTP request header bytes",
    ["route"],
    buckets=(0, 128, 512, 1024, 4096, 8192, 16384, 32768, 65536),
)


@dataclass
class HttpMetrics:
    req_counter: Counter
    req_latency: Histogram
    exporter: TCDPrometheusExporter

    def observe_http_latency(self, route: str, elapsed: float) -> None:
        self.req_latency.labels(route=route).observe(max(0.0, elapsed))

    def mark_request(self, route: str, status_code: int) -> None:
        self.req_counter.labels(route=route, status=str(status_code)).inc()

    def observe_core_latency(self, elapsed: float) -> None:
        _call_prom(self.exporter, "observe_latency", max(0.0, elapsed))

    def record_verify_fail(self) -> None:
        _call_prom(self.exporter, "slo_violation", "verify_fail")

    def throttle(self, tenant: str, user: str, session: str, *, reason: str) -> None:
        _call_prom(self.exporter, "throttle", tenant, user, session, reason=reason)

    def record_action(self, model_id: str, gpu_id: str, *, action: str) -> None:
        _call_prom(self.exporter, "record_action", model_id, gpu_id, action=action)

    def push_verdict(self, verdict_pack: Mapping[str, Any], *, labels: Mapping[str, str]) -> None:
        _call_prom(self.exporter, "push", dict(verdict_pack), labels=dict(labels))

    def push_eprocess(self, **kwargs: Any) -> None:
        _call_prom(self.exporter, "push_eprocess", **kwargs)

    def update_budget_metrics(self, tenant: str, user: str, session: str, *, remaining: float, spent: bool) -> None:
        _call_prom(self.exporter, "update_budget_metrics", tenant, user, session, remaining=remaining, spent=spent)

    def record_slo_by_model(self, metric: str, model_id: str, gpu_id: str) -> None:
        _call_prom(self.exporter, "slo_violation_by_model", metric, model_id, gpu_id)


@dataclass(frozen=True)
class SubjectPolicy:
    token_cost_divisor: float
    capacity: float
    refill_per_s: float

    @classmethod
    def from_base(cls, *, divisor: float, capacity: float, refill_per_s: float) -> "SubjectPolicy":
        return cls(
            token_cost_divisor=max(1.0, float(divisor)),
            capacity=max(1.0, float(capacity)),
            refill_per_s=max(0.1, float(refill_per_s)),
        )


@dataclass
class SubjectPolicyManager:
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


class SubjectLimiterPool:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._cache: Dict[Tuple[float, float], Any] = {}

    def _build(self, *, capacity: float, refill_per_s: float) -> Any:
        if RateLimitConfig is not None and RateLimitZoneConfig is not None:
            cfg = RateLimitConfig(
                zones={"default": RateLimitZoneConfig(capacity=capacity, refill_per_s=refill_per_s)},
                default_zone="default",
                enable_audit=False,
                enable_metrics=False,
                allow_dynamic_zones=False,
            )
            return RateLimiter(cfg)
        try:
            return RateLimiter(capacity=capacity, refill_per_s=refill_per_s)  # type: ignore[call-arg]
        except Exception:
            return RateLimiter()  # type: ignore[call-arg]

    def _get(self, policy: SubjectPolicy) -> Any:
        key = (float(policy.capacity), float(policy.refill_per_s))
        with self._lock:
            inst = self._cache.get(key)
            if inst is None:
                inst = self._build(capacity=policy.capacity, refill_per_s=policy.refill_per_s)
                self._cache[key] = inst
            return inst

    def _subject_rate_key(self, *, tenant: str, user: str, session: str, model_id: str) -> Any:
        if RateKey is not None:
            with contextlib.suppress(Exception):
                return RateKey(
                    tenant_id=tenant,
                    principal_id=user,
                    subject_id=f"tenant={tenant}|user={user}|session={session}|model={model_id}",
                    session_id=session,
                    resource_id=model_id,
                    route_id="http_subject",
                )
        return (tenant, user, session, model_id)

    def consume(self, *, tenant: str, user: str, session: str, model_id: str, cost: float, policy: SubjectPolicy) -> Tuple[bool, Optional[Any]]:
        limiter = self._get(policy)
        key = self._subject_rate_key(tenant=tenant, user=user, session=session, model_id=model_id)
        if hasattr(limiter, "consume_decision"):
            with contextlib.suppress(Exception):
                dec = limiter.consume_decision(key=key, cost=float(cost), zone="default")
                return bool(getattr(dec, "allowed", True)), dec
        with contextlib.suppress(Exception):
            ok = bool(limiter.consume(key, cost=float(cost)))
            return ok, None
        return True, None


class EdgeLimiter:
    def __init__(self, *, capacity: float, refill_per_s: float) -> None:
        self._pool = SubjectLimiterPool()
        self._policy = SubjectPolicy.from_base(divisor=1.0, capacity=capacity, refill_per_s=refill_per_s)

    def consume(self, ip_key: str) -> bool:
        limiter = self._pool._get(self._policy)
        key = ip_key if RateKey is None else RateKey(
            tenant_id="edge",
            principal_id=ip_key,
            subject_id=ip_key,
            session_id="",
            resource_id="http_edge",
            route_id="http_edge",
        )
        if hasattr(limiter, "consume_decision"):
            with contextlib.suppress(Exception):
                dec = limiter.consume_decision(key=key, cost=1.0, zone="default")
                return bool(getattr(dec, "allowed", True))
        with contextlib.suppress(Exception):
            return bool(limiter.consume(key, cost=1.0))
        return True


class _DetectorRuntimeUnavailable:
    def __init__(self, *, reason: str = "formal_detector_unavailable") -> None:
        self.reason = _safe_text(reason, max_len=128) or "formal_detector_unavailable"

    def detect(self, req: Any) -> Dict[str, Any]:
        return {
            "ok": False,
            "decision": "block",
            "action_hint": "BLOCK",
            "reason_code": "FORMAL_DETECTOR_UNAVAILABLE",
            "error_code": "INTERNAL_ERROR",
            "score_raw": 1.0,
            "p_value": 1e-12,
            "risk": 1.0,
            "latency_ms": 0.0,
            "budget_left_ms": 0.0,
            "engine_version": "detector_unavailable",
            "config_hash": f"detcfg:{_hash_hex(ctx='tcd:http:det_unavailable_cfg', payload={'reason': self.reason}, out_hex=32)}",
            "policy_digest": f"detpol:{_hash_hex(ctx='tcd:http:det_unavailable_policy', payload={'reason': self.reason}, out_hex=32)}",
            "state_digest": f"detstate:{_hash_hex(ctx='tcd:http:det_unavailable_state', payload={'reason': self.reason}, out_hex=32)}",
            "decision_id": f"detdec:{_hash_hex(ctx='tcd:http:det_unavailable_decision', payload={'reason': self.reason}, out_hex=32)}",
            "evidence_hash": f"detev:{_hash_hex(ctx='tcd:http:det_unavailable_evidence', payload={'reason': self.reason}, out_hex=32)}",
            "evidence": {"error": self.reason},
        }

    def state_snapshot(self) -> Dict[str, Any]:
        return {"mode": "unavailable", "reason": self.reason}

    def snapshot_state(self) -> Dict[str, Any]:
        return self.state_snapshot()

    def load_state(self, state: Mapping[str, Any]) -> None:
        return None


@dataclass
class DetectorRegistry:
    settings: Any
    det_lock: threading.RLock = field(default_factory=threading.RLock)
    av_lock: threading.RLock = field(default_factory=threading.RLock)
    mv_lock: threading.RLock = field(default_factory=threading.RLock)
    detectors: Dict[Tuple[str, str, str, str], Any] = field(default_factory=dict)
    av_by_subject: Dict[Tuple[str, str, str], AlwaysValidRiskController] = field(default_factory=dict)
    mv_by_model: Dict[str, MultiVarDetector] = field(default_factory=dict)

    def get_detector_runtime(self, key: Tuple[str, str, str, str]) -> Any:
        with self.det_lock:
            inst = self.detectors.get(key)
            if inst is None:
                inst = None
                if callable(build_default_detector):
                    with contextlib.suppress(Exception):
                        inst = build_default_detector()
                if inst is None:
                    inst = _DetectorRuntimeUnavailable(reason="formal_detector_build_failed")
                self.detectors[key] = inst
            return inst

    def get_alpha_controller(self, subject: Tuple[str, str, str]) -> AlwaysValidRiskController:
        with self.av_lock:
            inst = self.av_by_subject.get(subject)
            if inst is None:
                alpha = float(getattr(self.settings, "alpha", 0.05) or 0.05)
                inst = AlwaysValidRiskController(AlwaysValidConfig(alpha_base=alpha))
                self.av_by_subject[subject] = inst
            return inst

    def get_multivar_detector(self, model_id: str) -> MultiVarDetector:
        with self.mv_lock:
            inst = self.mv_by_model.get(model_id)
            if inst is None:
                inst = MultiVarDetector(MultiVarConfig(estimator="lw", alpha=0.01))
                self.mv_by_model[model_id] = inst
            return inst


@dataclass(frozen=True)
class RiskBudgetEnvelope:
    e_value: float
    alpha_alloc: float
    alpha_wealth: float
    alpha_spent: float
    threshold: float
    triggered: bool
    controller_mode: Optional[str] = None
    statistical_guarantee_scope: Optional[str] = None
    state_domain_id: Optional[str] = None
    adapter_registry_fp: Optional[str] = None

    @classmethod
    def from_av_out(cls, av_out: Mapping[str, Any]) -> "RiskBudgetEnvelope":
        e_state = av_out.get("e_state") if isinstance(av_out.get("e_state"), Mapping) else {}
        controller = e_state.get("controller") if isinstance(e_state, Mapping) and isinstance(e_state.get("controller"), Mapping) else {}
        validity = e_state.get("validity") if isinstance(e_state, Mapping) and isinstance(e_state.get("validity"), Mapping) else {}
        security = av_out.get("security") if isinstance(av_out.get("security"), Mapping) else {}
        controller_mode = _safe_text(security.get("controller_mode", ""), max_len=64) or None
        if controller_mode is None and isinstance(controller, Mapping):
            controller_mode = _safe_text(controller.get("controller_mode", ""), max_len=64) or None
        guarantee_scope = _safe_text(security.get("statistical_guarantee_scope", ""), max_len=128) or None
        if guarantee_scope is None and isinstance(validity, Mapping):
            guarantee_scope = _safe_text(validity.get("statistical_guarantee_scope", ""), max_len=128) or None
        state_domain_id = _safe_text(controller.get("state_domain_id", ""), max_len=128) or None if isinstance(controller, Mapping) else None
        adapter_registry_fp = _safe_text(controller.get("adapter_registry_fp", ""), max_len=128) or None if isinstance(controller, Mapping) else None
        return cls(
            e_value=float(_coerce_float(av_out.get("e_value")) or 1.0),
            alpha_alloc=float(_coerce_float(av_out.get("alpha_alloc")) or 0.0),
            alpha_wealth=float(_coerce_float(av_out.get("alpha_wealth")) or 0.0),
            alpha_spent=float(_coerce_float(av_out.get("alpha_spent")) or 0.0),
            threshold=float(_coerce_float(av_out.get("threshold")) or 0.0),
            triggered=bool(_coerce_bool(av_out.get("trigger"), default=False)),
            controller_mode=controller_mode,
            statistical_guarantee_scope=guarantee_scope,
            state_domain_id=state_domain_id,
            adapter_registry_fp=adapter_registry_fp,
        )

    def is_budget_exhausted(self, floor: float) -> bool:
        return float(self.alpha_wealth) < float(floor)


@dataclass
class ReceiptBundle:
    raw: Dict[str, Any]
    public: Dict[str, Any]
    verification: Optional[Dict[str, Any]]
    self_check_ok: Optional[bool]


@dataclass
class ReceiptManager:
    attestor: Optional[Any]
    hash_alg: str
    expose_verify_key_public: bool
    expose_verification_bundle_public: bool

    def issue_local_final(
        self,
        *,
        trace: Sequence[float],
        spectrum: Sequence[float],
        features: Sequence[float],
        req: DiagnoseRequest,
        request_id: str,
        event_id: str,
        body_digest: str,
        score: float,
        p_final: float,
        route_info: Mapping[str, Any],
        final_action: str,
        required_action: str,
        enforcement_mode: str,
        allowed: bool,
        cause: str,
        policy_ref: Optional[str],
        policyset_ref: Optional[str],
        policy_digest: Optional[str],
        cfg_fp: str,
        decision_id: str,
        route_plan_id: str,
        audit_ref: Optional[str],
        state_domain_id: Optional[str],
        adapter_registry_fp: Optional[str],
        budget: RiskBudgetEnvelope,
        detector_components: Mapping[str, Any],
        mv_info: Mapping[str, Any],
        security_block: Mapping[str, Any],
        artifacts: Mapping[str, Any],
        evidence_identity: Mapping[str, Any],
        pq_ok: Optional[bool],
    ) -> ReceiptBundle:
        if self.attestor is None:
            return ReceiptBundle(raw={}, public={}, verification=None, self_check_ok=None)

        array_digest = _compute_array_digest(trace, spectrum, features, alg=self.hash_alg)
        meta_v2 = build_v2_body(
            model_hash=f"unknown:{req.model_id}",
            tokenizer_hash=f"unknown:{req.model_id}",
            sampler_cfg={
                "temperature": float(_coerce_float(route_info.get("temperature")) or req.base_temp),
                "top_p": float(_coerce_float(route_info.get("top_p")) or req.base_top_p),
                "decoder": _safe_text(route_info.get("decoder", req.context.get("decoder", "default")), max_len=64) or "default",
                "seed": None,
            },
            context_len=len(trace),
            kv_digest=array_digest,
            rng_seed=None,
            latency_ms=None,
            throughput_tok_s=None,
            batch_index=0,
            batch_size=1,
            e_snapshot={
                "e_value": budget.e_value,
                "p_final": float(p_final),
                "drift_score": float(req.drift_score or 0.0),
                "event_id": event_id,
                "request_id": request_id,
                "body_digest": body_digest,
            },
        )

        req_obj = {
            "ts_ns": time.time_ns(),
            "request_id": request_id,
            "event_id": event_id,
            "tenant": req.tenant,
            "user": req.user,
            "session": req.session,
            "model_id": req.model_id,
            "gpu_id": req.gpu_id,
            "task": req.task,
            "lang": req.lang,
            "trust_zone": req.trust_zone,
            "route_profile": req.route_profile,
            "risk_label": req.risk_label,
            "threat_kind": req.threat_kind,
            "pq_required": req.pq_required,
            "context": _safe_context_subset(req.context),
            "tokens_delta": int(req.tokens_delta),
            "body_digest": body_digest,
        }

        comp_obj = {
            "score": float(score),
            "p_final": float(p_final),
            "allowed": bool(allowed),
            "action": final_action,
            "required_action": required_action,
            "enforcement_mode": enforcement_mode,
            "cause": cause,
            "decision_id": decision_id,
            "route_plan_id": route_plan_id,
            "policy_ref": policy_ref,
            "policyset_ref": policyset_ref,
            "cfg_fp": cfg_fp,
            "policy_digest": policy_digest,
            "audit_ref": audit_ref,
            "route": dict(route_info),
            "security": dict(security_block),
            "artifacts": dict(artifacts),
            "evidence_identity": dict(evidence_identity),
            "detector": _sanitize_json_mapping(dict(detector_components), max_depth=5, max_items=64, max_str_len=512, max_total_bytes=64_000),
            "multivariate": _sanitize_json_mapping(dict(mv_info), max_depth=4, max_items=64, max_str_len=512, max_total_bytes=64_000),
        }

        e_obj = {
            "e_value": budget.e_value,
            "alpha_alloc": budget.alpha_alloc,
            "alpha_wealth": budget.alpha_wealth,
            "alpha_spent": budget.alpha_spent,
            "threshold": budget.threshold,
            "trigger": budget.triggered,
            "controller_mode": budget.controller_mode,
            "statistical_guarantee_scope": budget.statistical_guarantee_scope,
            "state_domain_id": budget.state_domain_id,
            "adapter_registry_fp": budget.adapter_registry_fp,
        }

        witness_segments = [
            {
                "kind": "external",
                "id": "http_array_digest",
                "digest": array_digest,
                "meta": {
                    "trace_len": len(trace),
                    "spectrum_len": len(spectrum),
                    "feature_len": len(features),
                },
            },
            {
                "kind": "external",
                "id": "route_plan",
                "digest": route_plan_id,
                "meta": {"decision_id": decision_id, "policy_ref": policy_ref},
            },
        ]
        if policy_digest:
            witness_segments.append(
                {
                    "kind": "external",
                    "id": "policy_digest",
                    "digest": policy_digest,
                    "meta": {"policy_ref": policy_ref, "policyset_ref": policyset_ref},
                }
            )

        witness_tags = ["service_http", required_action, final_action]

        issue_fn = getattr(self.attestor, "issue", None)
        if not callable(issue_fn):
            return ReceiptBundle(raw={}, public={}, verification=None, self_check_ok=None)

        kwargs = {
            "req_obj": req_obj,
            "comp_obj": comp_obj,
            "e_obj": e_obj,
            "witness_segments": witness_segments,
            "witness_tags": witness_tags,
            "meta": {
                **meta_v2,
                "event_type": "service_http.final_decision",
                "event_id": event_id,
                "request_id": request_id,
                "decision_id": decision_id,
                "route_plan_id": route_plan_id,
                "policy_ref": policy_ref,
                "policyset_ref": policyset_ref,
                "policy_digest": policy_digest,
                "config_fingerprint": cfg_fp,
                "audit_ref": audit_ref,
            },
        }

        try:
            raw = issue_fn(**_filtered_kwargs_for(issue_fn, kwargs))
        except Exception:
            return ReceiptBundle(raw={}, public={}, verification=None, self_check_ok=None)

        if not isinstance(raw, Mapping):
            return ReceiptBundle(raw={}, public={}, verification=None, self_check_ok=None)

        raw_bundle = dict(raw)
        head = _opaque_handle(raw_bundle.get("receipt"), max_len=1024)
        body = _opaque_text(raw_bundle.get("receipt_body"), max_bytes=_DEFAULT_RECEIPT_BODY_LIMIT)
        sig = _opaque_handle(raw_bundle.get("receipt_sig"), max_len=8192)
        verify_key = _opaque_handle(raw_bundle.get("verify_key"), max_len=4096)
        receipt_ref = _opaque_handle(raw_bundle.get("receipt_ref"), max_len=512) or head
        receipt_integrity = _opaque_handle(raw_bundle.get("receipt_integrity"), max_len=256)

        self_check_ok: Optional[bool] = None
        verify_report: Any = None
        if head and body:
            with contextlib.suppress(Exception):
                verify_report = verify_receipt_ex(
                    receipt_head_hex=head,
                    receipt_body_json=body,
                    verify_key_hex=verify_key,
                    receipt_sig_hex=sig,
                    req_obj=req_obj,
                    comp_obj=comp_obj,
                    e_obj=e_obj,
                    witness_segments=witness_segments,
                    strict=True,
                    expected_policy_ref=policy_ref,
                    expected_policyset_ref=policyset_ref,
                    expected_policy_digest=policy_digest,
                    expected_cfg_fp=cfg_fp,
                    expected_build_id=req.build_id,
                    expected_image_digest=req.image_digest,
                )
                self_check_ok = bool(getattr(verify_report, "ok", False))

        enriched = {
            "schema": "tcd.receipt.http.v1",
            "receipt_kind": "inference_decision",
            "event_type": "service_http.final_decision",
            "receipt": head,
            "receipt_body": body,
            "receipt_sig": sig,
            "verify_key": verify_key,
            "verify_key_id": verify_key if (verify_key and _safe_id(verify_key, default=None, max_len=256)) else None,
            "verify_key_fp": _hash_handle_public(verify_key),
            "receipt_ref": receipt_ref,
            "audit_ref": audit_ref,
            "receipt_integrity": receipt_integrity,
            "event_id": event_id,
            "decision_id": decision_id,
            "route_plan_id": route_plan_id,
            "policy_ref": policy_ref,
            "policyset_ref": policyset_ref,
            "policy_digest": policy_digest,
            "cfg_fp": cfg_fp,
            "state_domain_id": state_domain_id,
            "adapter_registry_fp": adapter_registry_fp,
            "build_id": req.build_id,
            "image_digest": req.image_digest,
            "pq_required": req.pq_required,
            "pq_ok": pq_ok,
            "body_kind": "canonical_json" if body else None,
            "body_digest": ("sha256:" + hashlib.sha256(body.encode("utf-8", errors="strict")).hexdigest()) if body else None,
            "head_verified": getattr(verify_report, "head_verified", None),
            "body_canonical_verified": getattr(verify_report, "body_canonical_verified", None),
            "integrity_hash_verified": getattr(verify_report, "integrity_hash_verified", None),
            "signature_verified": getattr(verify_report, "signature_verified", None),
            "verify_key_allowed": getattr(verify_report, "verify_key_allowed", None),
            "policy_binding_verified": getattr(verify_report, "policy_binding_verified", None),
            "cfg_binding_verified": getattr(verify_report, "cfg_binding_verified", None),
            "integrity_ok": bool(self_check_ok) if self_check_ok is not None else True,
            "integrity_errors": list(getattr(verify_report, "errors", []) or []),
            "meta": {
                "request_id": request_id,
                "event_id": event_id,
                "decision_id": decision_id,
                "route_plan_id": route_plan_id,
                "cause": cause,
            },
        }

        public_view, verification_view = _build_receipt_surfaces(
            enriched,
            expose_verification_bundle_public=self.expose_verification_bundle_public,
            expose_verify_key_public=self.expose_verify_key_public,
        )

        return ReceiptBundle(
            raw=enriched,
            public=public_view,
            verification=verification_view,
            self_check_ok=self_check_ok,
        )


@dataclass
class TrustRuntimeWrapper:
    runtime: Optional[Dict[str, Any]]

    def classify(self, *, score: float, decision_fail: bool) -> str:
        if not self.runtime or not _HAS_TRUST_OS or DecisionContext is None:
            return "degrade" if decision_fail else "allow"
        try:
            ctx = DecisionContext(score=score, verdict=decision_fail)
            obj = self.runtime["decision_engine"].decide(ctx)
            val = getattr(obj, "value", str(obj))
            s = _safe_text(val, max_len=32).lower()
            if s in {"allow", "degrade", "block"}:
                return s
        except Exception:
            pass
        return "degrade" if decision_fail else "allow"


class ServiceTokenAuth:
    def __init__(self, cfg: ServiceHttpConfig, service_token: str) -> None:
        self.cfg = cfg
        self.token = service_token

    def __call__(
        self,
        request: Request,
        x_token: Optional[str] = Header(default=None, alias="X-TCD-Service-Token"),
    ) -> None:
        request.state.auth_mode = "none"
        request.state.auth_trusted = False
        if not self.cfg.require_service_token:
            request.state.auth_mode = "disabled"
            request.state.auth_trusted = True
            return

        target = self.token
        if not target:
            if self.cfg.allow_no_auth_local and _loopback_host(_client_host(request)):
                request.state.auth_mode = "loopback_bypass"
                request.state.auth_trusted = True
                return
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="service token required")

        if not x_token or len(x_token) != len(target):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
        if not hmac.compare_digest(x_token, target):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")

        request.state.auth_mode = "service_token"
        request.state.auth_trusted = True


@dataclass(frozen=True)
class _AuthProjection:
    ok: bool
    mode: str
    principal: Optional[str]
    scopes: Tuple[str, ...]
    key_id: Optional[str]
    policy_digest: Optional[str]
    authn_strength: Optional[str]
    reason: Optional[str]

    @staticmethod
    def from_auth_result(res: Any) -> "_AuthProjection":
        if res is None:
            return _AuthProjection(False, "none", None, tuple(), None, None, None, "missing")
        ok = bool(getattr(res, "ok", False))
        ctx = getattr(res, "ctx", None)
        if not ok or ctx is None:
            return _AuthProjection(False, "none", None, tuple(), None, None, None, _safe_text(getattr(res, "reason", None), max_len=64) or "auth_failed")
        mode = _safe_label(getattr(ctx, "mode", None), default="none")
        if mode not in _ALLOWED_AUTH_MODES:
            mode = "none"
        principal = _safe_text(getattr(ctx, "principal", None), max_len=256) or None
        scopes_raw = getattr(ctx, "scopes", None)
        scopes: List[str] = []
        try:
            for item in list(scopes_raw or [])[:32]:
                s = _safe_text(item, max_len=64)
                if s:
                    scopes.append(s)
        except Exception:
            scopes = []
        key_id = _safe_text(getattr(ctx, "key_id", None), max_len=128) or None
        policy_digest = _safe_text(getattr(ctx, "policy_digest", None), max_len=128) or None
        authn_strength = _safe_text(getattr(ctx, "authn_strength", None), max_len=64) or None
        return _AuthProjection(True, mode, principal, tuple(scopes), key_id, policy_digest, authn_strength, None)

    def public_view(self, *, expose_principal: bool = False) -> Dict[str, Any]:
        out: Dict[str, Any] = {"mode": self.mode, "trusted": bool(self.ok)}
        if self.principal:
            out["principal_hash"] = f"ap1:{_hash_hex(ctx='tcd:http:principal', payload={'principal': self.principal}, out_hex=24)}"
            if expose_principal:
                out["principal"] = self.principal
        if self.scopes:
            out["scopes"] = list(self.scopes)
        if self.key_id:
            out["key_id_hash"] = f"ak1:{_hash_hex(ctx='tcd:http:key_id', payload={'key_id': self.key_id}, out_hex=24)}"
        if self.policy_digest:
            out["policy_digest"] = self.policy_digest
        if self.authn_strength:
            out["authn_strength"] = self.authn_strength
        if self.reason:
            out["reason"] = self.reason
        return out


class _HttpDetectorRuntime:
    def __init__(self) -> None:
        self._local = threading.local()

    @contextlib.contextmanager
    def bind(self, payload: Mapping[str, Any]) -> Any:
        old = getattr(self._local, "current", None)
        self._local.current = dict(payload)
        try:
            yield
        finally:
            self._local.current = old

    def evaluate(self, ctx: Any, policy: Any) -> Mapping[str, Any]:
        cur = getattr(self._local, "current", None)
        if isinstance(cur, Mapping):
            return dict(cur)
        return {}

    def update_security(self, ctx: Any, policy: Any) -> Mapping[str, Any]:
        return self.evaluate(ctx, policy)

    def preview(self, ctx: Any, policy: Any) -> Mapping[str, Any]:
        return self.evaluate(ctx, policy)


@dataclass
class _Runtime:
    bundle: _CompiledHttpBundle
    settings_provider: Any
    settings: Any
    prom_exporter: TCDPrometheusExporter
    otel: TCDOtelExporter
    logger: Optional[Any]
    detector_registry: DetectorRegistry
    router: Any
    security_router: Optional[Any]
    detector_adapter: _HttpDetectorRuntime
    receipt_mgr: ReceiptManager
    subject_policy_mgr: SubjectPolicyManager
    subject_limiters: SubjectLimiterPool
    edge_limiter: EdgeLimiter
    trust_wrapper: TrustRuntimeWrapper
    gpu_sampler: Optional[GpuSampler]
    service_token: str
    authenticator: Optional[Any]
    subject_key_factory: Any

    def public_view(self) -> Dict[str, Any]:
        return {
            "schema": _SCHEMA,
            "api_version": self.bundle.config.api_version,
            "cfg_fp": self.bundle.cfg_fp,
            "bundle_version": self.bundle.version,
            "bundle_updated_at_unix_ns": self.bundle.updated_at_unix_ns,
            "strict_mode": self.bundle.config.strict_mode,
            "receipts_enable_default": self.bundle.config.receipts_enable_default,
            "has_security_router": self.security_router is not None,
            "has_attestor": self.receipt_mgr.attestor is not None,
            "has_authenticator": self.authenticator is not None,
            "has_trust_runtime": bool(self.trust_wrapper.runtime),
            "build_id": self.bundle.config.build_id,
            "image_digest": self.bundle.config.image_digest,
            "warnings": list(self.bundle.warnings),
            "errors": list(self.bundle.errors),
        }

    def diagnostics(self) -> Dict[str, Any]:
        return {
            **self.public_view(),
            "settings_config_hash": getattr(self.settings, "config_hash", lambda: None)(),
            "settings_version": getattr(self.settings, "config_version", None),
            "prom_enabled": True,
            "otel_enabled": bool(getattr(self.otel, "enabled", False)),
            "gpu_enabled": bool(getattr(self.settings, "gpu_enable", False)),
            "subject_rate_overrides": len(self.subject_policy_mgr.overrides),
            "detector_count": len(self.detector_registry.detectors),
            "alpha_controller_count": len(self.detector_registry.av_by_subject),
            "multivar_count": len(self.detector_registry.mv_by_model),
        }


_RUNTIME_LOCK = threading.RLock()
_RUNTIME_SINGLETON: Optional[_Runtime] = None


def create_http_runtime(
    *,
    cfg: Optional[ServiceHttpConfig] = None,
    verify_limits: Optional[VerifyLimits] = None,
    settings_provider: Any = None,
    prom_exporter: Optional[TCDPrometheusExporter] = None,
    otel_exporter: Optional[TCDOtelExporter] = None,
    policy_store: Optional[Any] = None,
    security_router: Optional[Any] = None,
    strategy_router: Optional[Any] = None,
    attestor: Optional[Any] = None,
    authenticator: Optional[Any] = None,
    logger: Optional[Any] = None,
    trust_runtime: Optional[Dict[str, Any]] = None,
    subject_policy_mgr: Optional[SubjectPolicyManager] = None,
) -> _Runtime:
    settings_provider = settings_provider or _SETTINGS
    settings = settings_provider.get()

    cfg0, v0 = _build_http_cfg_from_env()
    cfg_norm = (cfg or cfg0).normalized_copy()
    verify_norm = (verify_limits or v0).normalized_copy()

    warnings: List[str] = []
    errors: List[str] = []

    if cfg_norm.hash_alg == "blake3":
        try:
            from .crypto import Blake3Hash  # type: ignore # noqa: F401
        except Exception:
            warnings.append("hash_alg_blake3_unavailable_fallback_to_sha256")

    bundle = _CompiledHttpBundle(
        version=1,
        updated_at_unix_ns=time.time_ns(),
        cfg_fp=cfg_norm.fingerprint(),
        config=cfg_norm,
        verify_limits=verify_norm,
        warnings=tuple(warnings),
        errors=tuple(errors),
    )

    prom = prom_exporter or TCDPrometheusExporter(
        port=int(getattr(settings, "prometheus_port", 8001) or 8001),
        version=cfg_norm.api_version,
        config_hash=getattr(settings, "config_hash", lambda: bundle.cfg_fp)(),
    )
    if bool(getattr(settings, "prom_http_enable", False)):
        with contextlib.suppress(Exception):
            prom.ensure_server()

    otel = otel_exporter or TCDOtelExporter()
    otel.enabled = bool(getattr(settings, "otel_enable", False))

    app_logger = logger or (get_logger("tcd.http") if _HAS_LOG and get_logger is not None else _LOG)
    registry = DetectorRegistry(settings=settings)
    router = strategy_router or StrategyRouter()

    if authenticator is None and cfg_norm.enable_authenticator and build_authenticator_from_env is not None:
        with contextlib.suppress(Exception):
            authenticator = build_authenticator_from_env()

    trust_rt = trust_runtime
    if trust_rt is None and _HAS_TRUST_OS:
        with contextlib.suppress(Exception):
            trust_rt = {
                "decision_engine": DecisionEngine(),
                "agent": TrustAgent(),
                "rewriter": RewriteEngine(),
                "trust_graph": TrustGraph(),
                "patch_runtime": PatchRuntime(),
            }

    service_token = (os.environ.get(cfg_norm.service_token_env_var) or "").strip()

    if attestor is None and (
        cfg_norm.receipts_enable_default
        or cfg_norm.require_receipts_on_fail
        or cfg_norm.require_receipts_when_pq
    ):
        attestor = _build_attestor_compat(hash_alg=cfg_norm.hash_alg)

    receipt_mgr = ReceiptManager(
        attestor=attestor,
        hash_alg=cfg_norm.hash_alg,
        expose_verify_key_public=cfg_norm.expose_verify_key_public,
        expose_verification_bundle_public=cfg_norm.expose_verification_bundle_public,
    )

    spm = subject_policy_mgr or SubjectPolicyManager(
        base_divisor=float(getattr(settings, "token_cost_divisor_default", cfg_norm.tokens_divisor_default) or cfg_norm.tokens_divisor_default),
        base_capacity=float(getattr(settings, "http_rate_capacity", cfg_norm.subject_capacity) or cfg_norm.subject_capacity),
        base_refill_per_s=float(getattr(settings, "http_rate_refill_per_s", cfg_norm.subject_refill_per_s) or cfg_norm.subject_refill_per_s),
        overrides={},
    )

    subject_limiters = SubjectLimiterPool()
    edge_limiter = EdgeLimiter(capacity=cfg_norm.edge_burst, refill_per_s=cfg_norm.edge_rps)
    detector_adapter = _HttpDetectorRuntime()

    sec_router = security_router
    if sec_router is None and policy_store is not None:
        compat_rate_limiter = subject_limiters._build(capacity=cfg_norm.subject_capacity, refill_per_s=cfg_norm.subject_refill_per_s)
        sec_router = _build_security_router_compat(
            policy_store=policy_store,
            rate_limiter=compat_rate_limiter,
            attestor=attestor,
            detector_runtime=detector_adapter,
            strategy_router=router,
        )

    return _Runtime(
        bundle=bundle,
        settings_provider=settings_provider,
        settings=settings,
        prom_exporter=prom,
        otel=otel,
        logger=app_logger,
        detector_registry=registry,
        router=router,
        security_router=sec_router,
        detector_adapter=detector_adapter,
        receipt_mgr=receipt_mgr,
        subject_policy_mgr=spm,
        subject_limiters=subject_limiters,
        edge_limiter=edge_limiter,
        trust_wrapper=TrustRuntimeWrapper(runtime=trust_rt),
        gpu_sampler=GpuSampler(0) if bool(getattr(settings, "gpu_enable", False)) else None,
        service_token=service_token,
        authenticator=authenticator,
        subject_key_factory=lambda req: SubjectKey(
            tenant=req.tenant,
            user=req.user,
            session=req.session,
            model_id=req.model_id,
        ),
    )


def _get_singleton_runtime() -> _Runtime:
    global _RUNTIME_SINGLETON
    with _RUNTIME_LOCK:
        if _RUNTIME_SINGLETON is None:
            _RUNTIME_SINGLETON = create_http_runtime()
        return _RUNTIME_SINGLETON


def _build_auth_dependency(rt: _Runtime, cfgb: ServiceHttpConfig):
    token_guard = ServiceTokenAuth(cfg=cfgb, service_token=rt.service_token)

    async def _auth(
        request: Request,
        x_token: Optional[str] = Header(default=None, alias="X-TCD-Service-Token"),
    ) -> None:
        request.state.auth_mode = "none"
        request.state.auth_trusted = False
        request.state.auth_principal = None
        request.state.auth_scopes = []
        request.state.auth_key_id = None
        request.state.auth_policy_digest = None
        request.state.auth_reason = None

        auth_proj: Optional[_AuthProjection] = None
        if cfgb.enable_authenticator and rt.authenticator is not None:
            verify_fn = getattr(rt.authenticator, "verify", None)
            if callable(verify_fn):
                try:
                    out = verify_fn(request)
                    if inspect.isawaitable(out):
                        out = await out
                    auth_proj = _AuthProjection.from_auth_result(out)
                except Exception as e:
                    auth_proj = _AuthProjection(False, "none", None, tuple(), None, None, None, _safe_text(e, max_len=64) or "authenticator_error")

        if auth_proj is not None and auth_proj.ok:
            if cfgb.allowed_auth_modes and auth_proj.mode not in set(cfgb.allowed_auth_modes):
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="forbidden")
            request.state.auth_mode = auth_proj.mode
            request.state.auth_trusted = True
            request.state.auth_principal = auth_proj.principal
            request.state.auth_scopes = list(auth_proj.scopes)
            request.state.auth_key_id = auth_proj.key_id
            request.state.auth_policy_digest = auth_proj.policy_digest
            request.state.auth_reason = auth_proj.reason
            request.state.auth_projection = auth_proj
            return

        if cfgb.require_authenticator and not cfgb.allow_service_token_fallback:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")

        token_guard(request, x_token)
        if auth_proj is not None:
            request.state.auth_reason = auth_proj.reason
            request.state.auth_projection = auth_proj

    return _auth


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app(
    *,
    runtime: Optional[_Runtime] = None,
    cfg: Optional[ServiceHttpConfig] = None,
    verify_limits: Optional[VerifyLimits] = None,
    settings_provider: Any = None,
    policy_store: Optional[Any] = None,
    security_router: Optional[Any] = None,
    strategy_router: Optional[Any] = None,
    attestor: Optional[Any] = None,
    authenticator: Optional[Any] = None,
    logger: Optional[Any] = None,
    trust_runtime: Optional[Dict[str, Any]] = None,
) -> FastAPI:
    rt = runtime or create_http_runtime(
        cfg=cfg,
        verify_limits=verify_limits,
        settings_provider=settings_provider or _SETTINGS,
        policy_store=policy_store,
        security_router=security_router,
        strategy_router=strategy_router,
        attestor=attestor,
        authenticator=authenticator,
        logger=logger,
        trust_runtime=trust_runtime,
    )
    cfgb = rt.bundle.config
    verify_limits = rt.bundle.verify_limits

    openapi_url = "/openapi.json" if cfgb.enable_docs else None
    docs_url = "/docs" if cfgb.enable_docs else None
    redoc_url = "/redoc" if cfgb.enable_docs else None

    app = FastAPI(
        title="tcd-sidecar",
        version=cfgb.api_version,
        openapi_url=openapi_url,
        docs_url=docs_url,
        redoc_url=redoc_url,
    )
    app.state.runtime = rt

    allowed_origins = ["*"] if cfgb.cors_allow_all else list(cfgb.cors_origins)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-Request-Id",
            "X-TCD-Event-Id",
            "X-TCD-Http-Version",
            "X-TCD-Config-Fingerprint",
            "X-TCD-Bundle-Version",
            "X-TCD-Decision-Id",
            "X-TCD-Route-Plan-Id",
        ],
    )

    http_metrics = HttpMetrics(req_counter=_REQ_COUNTER, req_latency=_REQ_LATENCY, exporter=rt.prom_exporter)
    auth_dependency = _build_auth_dependency(rt, cfgb)

    @app.middleware("http")
    async def request_envelope_middleware(request: Request, call_next):
        route_path = _safe_text(request.scope.get("path", "unknown"), max_len=128) or "unknown"
        t0 = time.perf_counter()
        request_id = ""
        status_code = 500

        try:
            headers_dict = {k: v for k, v in request.headers.items()}
            request_id = (
                ensure_request_id(headers_dict)
                if (_HAS_LOG and ensure_request_id is not None)
                else (_safe_text(request.headers.get("x-request-id"), max_len=128) or uuid.uuid4().hex[:16])
            )
            request.state.request_id = request_id
            request.state.trace_id = _safe_text(request.headers.get("x-trace-id"), max_len=128) or None
            idem = _safe_text(request.headers.get("idempotency-key"), max_len=128) or None
            request.state.idempotency_key = idem if idem and _IDEMPOTENCY_KEY_RE.fullmatch(idem) else None

            header_items = sum(1 for _ in request.headers.items())
            header_bytes = sum(len(k.encode("utf-8", errors="ignore")) + len(v.encode("utf-8", errors="ignore")) for k, v in request.headers.items())
            _REQ_HEADERS_BYTES.labels(route_path).observe(float(header_bytes))
            if header_items > cfgb.max_header_count or header_bytes > cfgb.max_headers_bytes:
                _REQ_REJECTED.labels(route_path, "headers_too_large").inc()
                return JSONResponse(
                    status_code=status.HTTP_431_REQUEST_HEADER_FIELDS_TOO_LARGE,
                    content={"detail": "headers too large", "request_id": request_id, "config_fingerprint": rt.bundle.cfg_fp, "bundle_version": rt.bundle.version},
                    headers={"X-Request-Id": request_id, "X-TCD-Http-Version": cfgb.api_version, "X-TCD-Config-Fingerprint": rt.bundle.cfg_fp, "X-TCD-Bundle-Version": str(rt.bundle.version)},
                )

            need_body = request.method.upper() in {"POST", "PUT", "PATCH"} and route_path in {"/diagnose", "/v1/diagnose", "/verify", "/v1/verify", "/state/load"}
            if need_body:
                ct = _safe_text(request.headers.get("content-type"), max_len=256).lower()
                if ct and ("application/json" not in ct and not ct.endswith("+json")):
                    _REQ_REJECTED.labels(route_path, "unsupported_media_type").inc()
                    return JSONResponse(
                        status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                        content={"detail": "unsupported media type", "request_id": request_id, "config_fingerprint": rt.bundle.cfg_fp, "bundle_version": rt.bundle.version},
                        headers={"X-Request-Id": request_id, "X-TCD-Http-Version": cfgb.api_version, "X-TCD-Config-Fingerprint": rt.bundle.cfg_fp, "X-TCD-Bundle-Version": str(rt.bundle.version)},
                    )

                cl = request.headers.get("content-length")
                if cl is not None:
                    try:
                        cl_v = int(cl)
                    except ValueError:
                        _REQ_REJECTED.labels(route_path, "invalid_content_length").inc()
                        return JSONResponse(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            content={"detail": "invalid content-length", "request_id": request_id, "config_fingerprint": rt.bundle.cfg_fp, "bundle_version": rt.bundle.version},
                            headers={"X-Request-Id": request_id, "X-TCD-Http-Version": cfgb.api_version, "X-TCD-Config-Fingerprint": rt.bundle.cfg_fp, "X-TCD-Bundle-Version": str(rt.bundle.version)},
                        )
                    if cl_v > cfgb.max_body_bytes:
                        _REQ_REJECTED.labels(route_path, "body_too_large").inc()
                        return JSONResponse(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            content={"detail": "body too large", "request_id": request_id, "config_fingerprint": rt.bundle.cfg_fp, "bundle_version": rt.bundle.version},
                            headers={"X-Request-Id": request_id, "X-TCD-Http-Version": cfgb.api_version, "X-TCD-Config-Fingerprint": rt.bundle.cfg_fp, "X-TCD-Bundle-Version": str(rt.bundle.version)},
                        )

                body = await request.body()
                if len(body) > cfgb.max_body_bytes:
                    _REQ_REJECTED.labels(route_path, "body_too_large").inc()
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"detail": "body too large", "request_id": request_id, "config_fingerprint": rt.bundle.cfg_fp, "bundle_version": rt.bundle.version},
                        headers={"X-Request-Id": request_id, "X-TCD-Http-Version": cfgb.api_version, "X-TCD-Config-Fingerprint": rt.bundle.cfg_fp, "X-TCD-Bundle-Version": str(rt.bundle.version)},
                    )
                if _json_depth_exceeds(body, max_depth=cfgb.max_inbound_json_depth):
                    _REQ_REJECTED.labels(route_path, "json_too_deep").inc()
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={"detail": "json too deep", "request_id": request_id, "config_fingerprint": rt.bundle.cfg_fp, "bundle_version": rt.bundle.version},
                        headers={"X-Request-Id": request_id, "X-TCD-Http-Version": cfgb.api_version, "X-TCD-Config-Fingerprint": rt.bundle.cfg_fp, "X-TCD-Bundle-Version": str(rt.bundle.version)},
                    )
                request.state.body_bytes = body
                request.state.body_digest = _body_digest(body, alg=cfgb.hash_alg)
                _REQ_BODY_BYTES.labels(route_path).observe(float(len(body)))
                with contextlib.suppress(Exception):
                    request._body = body  # type: ignore[attr-defined]

            if route_path in {"/diagnose", "/v1/diagnose", "/verify", "/v1/verify"}:
                peer = _client_host(request)
                if not rt.edge_limiter.consume(peer):
                    _REQ_REJECTED.labels(route_path, "edge_rate_limited").inc()
                    return JSONResponse(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        content={"detail": "rate limited", "request_id": request_id, "config_fingerprint": rt.bundle.cfg_fp, "bundle_version": rt.bundle.version},
                        headers={"X-Request-Id": request_id, "X-TCD-Http-Version": cfgb.api_version, "X-TCD-Config-Fingerprint": rt.bundle.cfg_fp, "X-TCD-Bundle-Version": str(rt.bundle.version)},
                    )

            response = await call_next(request)
            status_code = int(getattr(response, "status_code", 200))
            response.headers["X-Request-Id"] = request_id
            response.headers["X-TCD-Http-Version"] = cfgb.api_version
            response.headers["X-TCD-Config-Fingerprint"] = rt.bundle.cfg_fp
            response.headers["X-TCD-Bundle-Version"] = str(rt.bundle.version)
            if getattr(request.state, "event_id", None):
                response.headers["X-TCD-Event-Id"] = str(request.state.event_id)
            if getattr(request.state, "decision_id", None):
                response.headers["X-TCD-Decision-Id"] = str(request.state.decision_id)
            if getattr(request.state, "route_plan_id", None):
                response.headers["X-TCD-Route-Plan-Id"] = str(request.state.route_plan_id)
            return response
        finally:
            elapsed = max(0.0, time.perf_counter() - t0)
            http_metrics.observe_http_latency(route_path, elapsed)
            http_metrics.mark_request(route_path, status_code)

    @app.exception_handler(HTTPException)
    async def _http_exc_handler(request: Request, exc: HTTPException):
        request_id = _safe_text(getattr(request.state, "request_id", None), max_len=128) or uuid.uuid4().hex[:16]
        return JSONResponse(
            status_code=int(exc.status_code),
            content={"detail": exc.detail, "request_id": request_id, "config_fingerprint": rt.bundle.cfg_fp, "bundle_version": rt.bundle.version},
            headers={"X-Request-Id": request_id, "X-TCD-Http-Version": cfgb.api_version, "X-TCD-Config-Fingerprint": rt.bundle.cfg_fp, "X-TCD-Bundle-Version": str(rt.bundle.version)},
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_exc_handler(request: Request, exc: RequestValidationError):
        request_id = _safe_text(getattr(request.state, "request_id", None), max_len=128) or uuid.uuid4().hex[:16]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": "validation error", "errors": exc.errors(), "request_id": request_id, "config_fingerprint": rt.bundle.cfg_fp, "bundle_version": rt.bundle.version},
            headers={"X-Request-Id": request_id, "X-TCD-Http-Version": cfgb.api_version, "X-TCD-Config-Fingerprint": rt.bundle.cfg_fp, "X-TCD-Bundle-Version": str(rt.bundle.version)},
        )

    @app.exception_handler(Exception)
    async def _generic_exc_handler(request: Request, exc: Exception):
        request_id = _safe_text(getattr(request.state, "request_id", None), max_len=128) or uuid.uuid4().hex[:16]
        with contextlib.suppress(Exception):
            _LOG.error(
                "unhandled_exception request_id=%s path=%s exc_type=%s",
                request_id,
                _safe_text(getattr(getattr(request, "url", None), "path", ""), max_len=128) or "unknown",
                type(exc).__name__,
                exc_info=(type(exc), exc, exc.__traceback__),
            )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "internal server error",
                "request_id": request_id,
                "config_fingerprint": rt.bundle.cfg_fp,
                "bundle_version": rt.bundle.version,
            },
            headers={
                "X-Request-Id": request_id,
                "X-TCD-Http-Version": cfgb.api_version,
                "X-TCD-Config-Fingerprint": rt.bundle.cfg_fp,
                "X-TCD-Bundle-Version": str(rt.bundle.version),
            },
        )

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.get("/healthz")
    def healthz() -> Dict[str, Any]:
        return {
            "ok": True,
            "schema": _SCHEMA,
            "http_version": cfgb.api_version,
            "config_fingerprint": rt.bundle.cfg_fp,
            "bundle_version": rt.bundle.version,
            "build_id": cfgb.build_id,
            "image_digest": cfgb.image_digest,
            "receipts": bool(rt.receipt_mgr.attestor is not None),
            "security_router": bool(rt.security_router is not None),
            "authenticator": bool(rt.authenticator is not None),
            "trust_os": bool(rt.trust_wrapper.runtime is not None),
            "otel": bool(getattr(rt.otel, "enabled", False)),
            "prom": True,
        }

    @app.get("/readyz")
    def readyz() -> Dict[str, Any]:
        return {
            "ready": True,
            "schema": _SCHEMA,
            "http_version": cfgb.api_version,
            "config_fingerprint": rt.bundle.cfg_fp,
            "bundle_version": rt.bundle.version,
        }

    @app.get("/version")
    def version() -> Dict[str, Any]:
        return {
            "schema": _SCHEMA,
            "http_version": cfgb.api_version,
            "config_fingerprint": rt.bundle.cfg_fp,
            "bundle_version": rt.bundle.version,
            "config_version": getattr(rt.settings, "config_version", None),
            "settings_config_hash": getattr(rt.settings, "config_hash", lambda: None)(),
            "alpha": getattr(rt.settings, "alpha", None),
            "slo_latency_ms": getattr(rt.settings, "slo_latency_ms", None),
        }

    @app.get("/dod")
    def dod() -> Dict[str, Any]:
        return {
            "schema": _SCHEMA,
            "surface": "public_http_inference",
            "http_version": cfgb.api_version,
            "config_fingerprint": rt.bundle.cfg_fp,
            "bundle_version": rt.bundle.version,
            "contracts": {
                "input_contract": "DiagnoseRequest/VerifyRequest strict",
                "response_contract": "RiskResponse/VerifyResponse bounded",
                "evidence_contract": "request_id,event_id,decision_id,route_plan_id,receipt_ref,audit_ref",
                "receipt_surface": "public+optional_verification_bundle",
            },
            "limits": {
                "max_body_bytes": cfgb.max_body_bytes,
                "max_headers_bytes": cfgb.max_headers_bytes,
                "max_header_count": cfgb.max_header_count,
                "max_inbound_json_depth": cfgb.max_inbound_json_depth,
                "max_json_component_bytes": cfgb.max_json_component_bytes,
                "verify_window_max": verify_limits.max_window,
                "verify_receipt_body_max_bytes": verify_limits.max_receipt_body_bytes,
            },
            "consistency": {
                "event_identity": "deterministic_per_request",
                "rate_limit_scope": "local_or_backend_dependent",
                "receipt_delivery": "security_router_finalized_when_available__local_attestation_only_when_explicitly_degraded",
                "security_router_required_when_strict": cfgb.require_security_router_when_strict,
            },
            "dependencies": {
                "security_router_present": rt.security_router is not None,
                "attestor_present": rt.receipt_mgr.attestor is not None,
                "authenticator_present": rt.authenticator is not None,
                "trust_runtime_present": rt.trust_wrapper.runtime is not None,
            },
        }

    @app.get("/runtime/public")
    def runtime_public(_auth: None = Depends(auth_dependency)) -> Dict[str, Any]:
        return rt.public_view()

    @app.get("/runtime/diagnostics")
    def runtime_diagnostics(_auth: None = Depends(auth_dependency)) -> Dict[str, Any]:
        return rt.diagnostics()

    def _detector_state_snapshot_public(det: Any) -> Dict[str, Any]:
        for attr in ("state_snapshot", "snapshot_state"):
            fn = getattr(det, attr, None)
            if callable(fn):
                with contextlib.suppress(Exception):
                    out = fn()
                    if isinstance(out, Mapping):
                        return _sanitize_json_mapping(dict(out), max_depth=6, max_items=128, max_str_len=1024, max_total_bytes=64_000)
        return {}

    def _detector_state_load_compat(det: Any, state: Mapping[str, Any]) -> bool:
        load_fn = getattr(det, "load_state", None)
        if callable(load_fn):
            with contextlib.suppress(Exception):
                load_fn(dict(state))
                return True
        restore_fn = getattr(det, "restore_state", None)
        if callable(restore_fn):
            with contextlib.suppress(Exception):
                restore_fn(dict(state))
                return True
        return False

    @app.get("/state/get")
    def state_get(
        model_id: str = "model0",
        gpu_id: str = "gpu0",
        task: str = "chat",
        lang: str = "en",
        _auth: None = Depends(auth_dependency),
    ) -> Dict[str, Any]:
        det = rt.detector_registry.get_detector_runtime((model_id, gpu_id, task, lang))
        return {"detector": _detector_state_snapshot_public(det)}

    @app.post("/state/load")
    def state_load(
        payload: SnapshotState,
        model_id: str = "model0",
        gpu_id: str = "gpu0",
        task: str = "chat",
        lang: str = "en",
        _auth: None = Depends(auth_dependency),
    ) -> Dict[str, Any]:
        det = rt.detector_registry.get_detector_runtime((model_id, gpu_id, task, lang))
        ok = _detector_state_load_compat(det, payload.state)
        return {"ok": bool(ok), "loaded": bool(ok), "detector_state_supported": bool(ok)}

    def _request_identity(request: Request, req: DiagnoseRequest) -> Tuple[str, str, str]:
        request_id = _safe_text(getattr(request.state, "request_id", None), max_len=128) or (req.request_id or uuid.uuid4().hex[:16])
        body_digest = _safe_text(getattr(request.state, "body_digest", None), max_len=128)
        if not body_digest:
            raw = getattr(request.state, "body_bytes", None)
            if isinstance(raw, (bytes, bytearray)):
                body_digest = _body_digest(bytes(raw), alg=cfgb.hash_alg)
            else:
                body_digest = _body_digest(_canon_json_bytes(req.model_dump()), alg=cfgb.hash_alg)
        payload = {
            "request_id": request_id,
            "idempotency_key": req.idempotency_key,
            "body_digest": body_digest,
            "tenant": req.tenant,
            "user": req.user,
            "session": req.session,
            "model_id": req.model_id,
            "path": request.url.path,
            "cfg_fp": rt.bundle.cfg_fp,
        }
        event_id = f"{_EVENT_ID_VERSION}:{_SAFE_DIGEST_ALG}:{_hash_hex(ctx='tcd:http:event', payload=payload, out_hex=32, alg='sha256')}"
        request.state.event_id = event_id
        return request_id, body_digest, event_id

    def _alpha_budget_or_fail(av_out: Dict[str, Any], tenant: str, user: str, session: str) -> RiskBudgetEnvelope:
        budget = RiskBudgetEnvelope.from_av_out(av_out)
        if budget.is_budget_exhausted(cfgb.alpha_wealth_floor):
            http_metrics.throttle(tenant, user, session, reason="alpha_budget")
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="alpha budget exhausted")
        return budget

    def _apply_subject_policy_and_charge(req: DiagnoseRequest) -> Tuple[float, Optional[Any]]:
        tokens_delta = max(0.0, float(req.tokens_delta or 0))
        policy = rt.subject_policy_mgr.resolve(req.tenant, req.model_id)
        cost = max(1.0, tokens_delta / max(1.0, policy.token_cost_divisor))
        allowed, decision = rt.subject_limiters.consume(
            tenant=req.tenant,
            user=req.user,
            session=req.session,
            model_id=req.model_id,
            cost=cost,
            policy=policy,
        )
        if not allowed:
            http_metrics.throttle(req.tenant, req.user, req.session, reason="rate")
            raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="rate limited")
        return cost, decision

    def _build_detector_compat_text(
        req: DiagnoseRequest,
        *,
        trace_vec: Sequence[float],
        spectrum: Sequence[float],
        features: Sequence[float],
    ) -> Optional[str]:
        raw_text = ""
        if isinstance(req.context, Mapping):
            raw_text = _safe_text(req.context.get("detector_text"), max_len=16_384)
        if raw_text:
            return raw_text
        if not cfgb.allow_detector_text_synthesis_for_compat:
            return None
        payload = {
            "trace_vector": [round(float(x), 6) for x in list(trace_vec)[:256]],
            "entropy": _coerce_float(req.entropy),
            "spectrum": [round(float(x), 6) for x in list(spectrum)[:256]],
            "features": [round(float(x), 6) for x in list(features)[:256]],
            "task": req.task,
            "gpu_id": req.gpu_id,
            "drift_score": _coerce_float(req.drift_score),
            "step_id": _coerce_int(req.step_id) if req.step_id is not None else None,
            "context": _safe_context_subset(dict(req.context or {})),
        }
        txt = _compact_json(payload, max_bytes=16_384)
        return txt or None

    def _make_detector_request(
        req: DiagnoseRequest,
        *,
        trace_vec: Sequence[float],
        spectrum: Sequence[float],
        features: Sequence[float],
    ) -> Any:
        if DetectRequest is None:
            return None
        detector_text = _build_detector_compat_text(req, trace_vec=trace_vec, spectrum=spectrum, features=features)
        if not detector_text:
            return None
        meta = {
            "entropy": _coerce_float(req.entropy),
            "step_id": _coerce_int(req.step_id) if req.step_id is not None else None,
            "task": req.task,
            "gpu_id": req.gpu_id,
            "trust_zone": req.trust_zone,
            "route_profile": req.route_profile,
            "risk_label": req.risk_label,
            "drift_score": _coerce_float(req.drift_score),
            "trace_len": len(trace_vec),
            "spectrum_len": len(spectrum),
            "feature_len": len(features),
            "context": _safe_context_subset(dict(req.context or {})),
        }
        kwargs = {
            "tenant": req.tenant,
            "user": req.user,
            "session": req.session,
            "model_id": req.model_id,
            "lang": req.lang,
            "kind": "completion",
            "text": detector_text,
            "meta": meta,
        }
        with contextlib.suppress(Exception):
            return DetectRequest(**kwargs)
        return None

    def _normalize_detector_runtime_out(out: Any) -> Dict[str, Any]:
        if out is None:
            return {}
        if isinstance(out, Mapping):
            return dict(out)
        if hasattr(out, "model_dump"):
            with contextlib.suppress(Exception):
                dumped = out.model_dump()
                if isinstance(dumped, Mapping):
                    return dict(dumped)
        if dataclasses.is_dataclass(out):
            with contextlib.suppress(Exception):
                dumped = dataclasses.asdict(out)
                if isinstance(dumped, Mapping):
                    return dict(dumped)
        return {}

    def _detector_runtime_to_verdict_pack(out: Any, *, step_id: Optional[int]) -> Dict[str, Any]:
        raw = _normalize_detector_runtime_out(out)
        if not raw:
            return {"verdict": True, "score": 1.0, "p_value": 1e-12, "decision": "block", "action": "block", "step": int(step_id or 0), "components": {"reason": "detector_runtime_empty"}}

        decision = _safe_text(raw.get("decision"), max_len=32).lower()
        if decision not in {"allow", "throttle", "block"}:
            decision = "block" if not _coerce_bool(raw.get("ok"), default=True) else "allow"

        action = "degrade" if decision == "throttle" else decision
        risk = _coerce_float(raw.get("risk"))
        if risk is None:
            risk = _coerce_float(raw.get("score"))
        if risk is None:
            risk = _coerce_float(raw.get("score_raw"))
        if risk is None:
            risk = 1.0 if decision != "allow" else 0.0
        risk = max(0.0, min(1.0, float(risk)))

        p_value = _coerce_float(raw.get("p_value"))
        if p_value is None:
            p_value = max(1e-12, min(1.0, 1.0 - risk))
        p_value = max(1e-12, min(1.0, float(p_value)))

        components = {
            "detector_runtime": True,
            "decision": decision,
            "action": action,
            "action_hint": _safe_text(raw.get("action_hint"), max_len=32) or None,
            "reason_code": _safe_text(raw.get("reason_code"), max_len=128) or None,
            "error_code": _safe_text(raw.get("error_code"), max_len=128) or None,
            "risk": risk,
            "p_value": p_value,
            "score_raw": _coerce_float(raw.get("score_raw")),
            "latency_ms": _coerce_float(raw.get("latency_ms")),
            "budget_left_ms": _coerce_float(raw.get("budget_left_ms")),
            "engine_version": _safe_text(raw.get("engine_version"), max_len=64) or None,
            "config_hash": _safe_text(raw.get("config_hash"), max_len=128) or None,
            "policy_digest": _safe_text(raw.get("policy_digest"), max_len=128) or None,
            "state_digest": _safe_text(raw.get("state_digest"), max_len=128) or None,
            "decision_id": _safe_text(raw.get("decision_id"), max_len=128) or None,
            "evidence_hash": _safe_text(raw.get("evidence_hash"), max_len=128) or None,
            "thresholds": raw.get("thresholds") if isinstance(raw.get("thresholds"), Mapping) else {},
            "calibrator": raw.get("calibrator") if isinstance(raw.get("calibrator"), Mapping) else {},
            "calibrator_state": raw.get("calibrator_state") if isinstance(raw.get("calibrator_state"), Mapping) else {},
            "model": raw.get("model") if isinstance(raw.get("model"), Mapping) else {},
            "evidence": raw.get("evidence") if isinstance(raw.get("evidence"), Mapping) else {},
        }

        return {
            "verdict": decision != "allow",
            "score": risk,
            "risk": risk,
            "p_value": p_value,
            "decision": decision,
            "action": action,
            "reason_code": _safe_text(raw.get("reason_code"), max_len=128) or None,
            "error_code": _safe_text(raw.get("error_code"), max_len=128) or None,
            "decision_id": _safe_text(raw.get("decision_id"), max_len=128) or None,
            "config_hash": _safe_text(raw.get("config_hash"), max_len=128) or None,
            "policy_digest": _safe_text(raw.get("policy_digest"), max_len=128) or None,
            "state_digest": _safe_text(raw.get("state_digest"), max_len=128) or None,
            "step": int(step_id or 0),
            "components": components,
        }

    def _run_detector_runtime(
        det: Any,
        *,
        req: DiagnoseRequest,
        trace_vec: Sequence[float],
        spectrum: Sequence[float],
        features: Sequence[float],
    ) -> Dict[str, Any]:
        detect_fn = getattr(det, "detect", None)
        if callable(detect_fn):
            dreq = _make_detector_request(req, trace_vec=trace_vec, spectrum=spectrum, features=features)
            if dreq is not None:
                with contextlib.suppress(Exception):
                    return _detector_runtime_to_verdict_pack(detect_fn(dreq), step_id=req.step_id)
            return {
                "verdict": True,
                "score": 1.0,
                "p_value": 1e-12,
                "decision": "block",
                "action": "block",
                "step": int(req.step_id or 0),
                "reason_code": "FORMAL_DETECTOR_INPUT_UNAVAILABLE",
                "components": {"reason": "formal_detector_input_unavailable"},
            }

        diagnose_fn = getattr(det, "diagnose", None)
        if callable(diagnose_fn):
            with contextlib.suppress(Exception):
                vp = diagnose_fn(trace_vec, req.entropy, spectrum, step_id=req.step_id)
                if isinstance(vp, Mapping):
                    out = dict(vp)
                    if "p_value" not in out:
                        score0 = float(_coerce_float(out.get("score")) or 0.0)
                        out["p_value"] = max(1e-12, min(1.0, 1.0 - max(0.0, min(1.0, score0))))
                    if "action" not in out:
                        out["action"] = "block" if _coerce_bool(out.get("verdict"), default=False) else "allow"
                    return out

        return {"verdict": True, "score": 1.0, "p_value": 1e-12, "decision": "block", "action": "block", "step": int(req.step_id or 0), "components": {"reason": "detector_runtime_unavailable"}}

    def _extract_detector_signal(verdict_pack: Mapping[str, Any]) -> Dict[str, Any]:
        decision = _safe_text(verdict_pack.get("decision"), max_len=32).lower()
        action = _safe_text(verdict_pack.get("action"), max_len=32).lower()
        if decision not in {"allow", "throttle", "block"}:
            decision = ""
        if action not in {"allow", "degrade", "block", "deny", "advisory"}:
            if decision == "throttle":
                action = "degrade"
            elif decision == "block":
                action = "block"
            else:
                action = "allow"

        risk_score = _coerce_float(verdict_pack.get("risk"))
        if risk_score is None:
            risk_score = _coerce_float(verdict_pack.get("score"))
        if risk_score is None:
            risk_score = 1.0 if _coerce_bool(verdict_pack.get("verdict"), default=False) else 0.0
        risk_score = max(0.0, min(1.0, float(risk_score)))

        p_value = _coerce_float(verdict_pack.get("p_value"))
        if p_value is None:
            p_value = max(1e-12, min(1.0, 1.0 - risk_score))
        p_value = max(1e-12, min(1.0, float(p_value)))

        decision_fail = bool(
            _coerce_bool(verdict_pack.get("verdict"), default=False)
            or decision in {"block", "throttle"}
            or action in {"block", "degrade", "deny", "advisory"}
        )
        return {
            "decision": decision,
            "action": action,
            "risk_score": risk_score,
            "p_value": p_value,
            "decision_fail": decision_fail,
            "reason_code": _safe_text(verdict_pack.get("reason_code"), max_len=128) or None,
            "error_code": _safe_text(verdict_pack.get("error_code"), max_len=128) or None,
            "decision_id": _safe_text(verdict_pack.get("decision_id"), max_len=128) or None,
            "config_hash": _safe_text(verdict_pack.get("config_hash"), max_len=128) or None,
            "policy_digest": _safe_text(verdict_pack.get("policy_digest"), max_len=128) or None,
            "state_digest": _safe_text(verdict_pack.get("state_digest"), max_len=128) or None,
        }

    def _manual_route_action(
        route: Any,
        decision_fail: bool,
        *,
        threat_kind: Optional[str],
        threat_conf: Optional[float],
        pq_required: bool,
        pq_ok: Optional[bool],
    ) -> str:
        req_action = _safe_text(getattr(route, "required_action", ""), max_len=32).lower() if route is not None else ""
        if req_action == "block":
            return "block"
        if req_action == "degrade":
            return "degrade"
        if decision_fail:
            if threat_kind in ("apt", "supply_chain") and (threat_conf or 0.0) >= 0.9:
                return "block"
            if pq_required and pq_ok is False:
                return "block"
            return "degrade"
        return "none"

    def _build_synthetic_route_contract(
        *,
        req: DiagnoseRequest,
        request_id: str,
        event_id: str,
        score: float,
        decision_fail: bool,
        av_trigger: bool,
        controller_mode: Optional[str],
        guarantee_scope: Optional[str],
        av_label: Optional[str],
        threat_kind: Optional[str],
    ) -> Dict[str, Any]:
        required_action = "block" if (
            decision_fail
            and (
                req.risk_label == "critical"
                or (threat_kind in {"apt", "supply_chain"} and (_coerce_float(req.threat_confidence) or 0.0) >= 0.9)
            )
        ) else ("degrade" if (decision_fail or cfgb.strict_mode) else "allow")
        return {
            "schema": "tcd.route.synthetic.v1",
            "router": "tcd.service_http",
            "version": "1.0.0",
            "config_fingerprint": rt.bundle.cfg_fp,
            "bundle_version": rt.bundle.version,
            "router_mode": "degraded",
            "route_id_kind": "plan",
            "route_plan_id": "rp1:sha256:" + _hash_hex(ctx="tcd:http:route_plan", payload={"event_id": event_id, "reason": "route_unavailable"}, out_hex=32),
            "route_id": None,
            "decision_id": "rd1:sha256:" + _hash_hex(ctx="tcd:http:route_decision", payload={"event_id": event_id, "reason": "route_unavailable"}, out_hex=32),
            "decision_ts_unix_ns": time.time_ns(),
            "decision_ts_mono_ns": time.monotonic_ns(),
            "safety_tier": "strict" if required_action == "block" else ("elevated" if required_action == "degrade" else "normal"),
            "required_action": required_action,
            "action_hint": required_action,
            "enforcement_mode": "fail_closed" if required_action == "block" else ("must_enforce" if required_action == "degrade" and cfgb.strict_mode else "advisory"),
            "temperature": 0.2 if required_action == "block" else (0.4 if required_action == "degrade" else req.base_temp),
            "top_p": 0.4 if required_action == "block" else (0.6 if required_action == "degrade" else req.base_top_p),
            "decoder": "safe" if required_action != "allow" else "default",
            "latency_hint": "high_safety" if required_action != "allow" else "normal",
            "trust_zone": req.trust_zone,
            "route_profile": req.route_profile,
            "risk_label": req.risk_label,
            "score": score,
            "decision_fail": decision_fail,
            "e_triggered": av_trigger,
            "pq_unhealthy": False,
            "av_label": av_label,
            "av_trigger": av_trigger,
            "threat_tags": [threat_kind] if threat_kind else [],
            "controller_mode": controller_mode,
            "guarantee_scope": guarantee_scope,
            "signal_digest": "sg1:sha256:" + _hash_hex(ctx="tcd:http:signal", payload={"score": score, "decision_fail": decision_fail, "e_triggered": av_trigger, "threat_kind": threat_kind}, out_hex=32),
            "context_digest": "cx1:sha256:" + _hash_hex(ctx="tcd:http:context", payload={"trust_zone": req.trust_zone, "route_profile": req.route_profile, "request_id": request_id}, out_hex=32),
            "primary_reason_code": "ROUTE_UNAVAILABLE",
            "reason_codes": ["ROUTE_UNAVAILABLE"],
            "degraded_reason_codes": ["ROUTE_UNAVAILABLE"],
            "reason": "route_unavailable",
        }

    def _build_detector_payload(
        *,
        req: DiagnoseRequest,
        score: float,
        decision_fail: bool,
        verdict_pack: Mapping[str, Any],
        av_out: Mapping[str, Any],
        threat_kind: Optional[str],
        event_id: str,
        request_id: str,
        body_digest: str,
    ) -> Dict[str, Any]:
        e_state = av_out.get("e_state") if isinstance(av_out.get("e_state"), Mapping) else {}
        security = av_out.get("security") if isinstance(av_out.get("security"), Mapping) else {}
        det_signal = _extract_detector_signal(verdict_pack)
        action = det_signal.get("action") or ("block" if decision_fail and req.risk_label == "critical" else ("degrade" if decision_fail else "allow"))
        if action == "deny":
            action = "block"
        return {
            "risk_score": float(det_signal.get("risk_score") if det_signal.get("risk_score") is not None else score),
            "risk_label": req.risk_label,
            "action": action,
            "trigger": bool(decision_fail),
            "reason": _safe_text(det_signal.get("reason_code") or verdict_pack.get("reason_code"), max_len=128) or None,
            "controller_mode": _safe_text(security.get("controller_mode", ""), max_len=64) or None,
            "guarantee_scope": _safe_text(security.get("statistical_guarantee_scope", ""), max_len=128) or None,
            "av_label": _safe_text(getattr(getattr(rt.detector_registry.get_alpha_controller((req.tenant, req.user, req.session)), "config", None), "label", None), max_len=64) or None,
            "av_trigger": bool(av_out.get("trigger", False)),
            "threat_tags": [threat_kind] if threat_kind else [],
            "decision_id": det_signal.get("decision_id"),
            "config_hash": det_signal.get("config_hash"),
            "policy_digest": det_signal.get("policy_digest"),
            "state_digest": det_signal.get("state_digest"),
            "e_state": dict(e_state) if isinstance(e_state, Mapping) else {},
            "security": {
                **(dict(security) if isinstance(security, Mapping) else {}),
                "request_id": request_id,
                "event_id": event_id,
                "body_digest": body_digest,
            },
        }

    def _security_router_decision(
        *,
        req: DiagnoseRequest,
        request: Request,
        body_digest: str,
        request_id: str,
        event_id: str,
        score: float,
        decision_fail: bool,
        verdict_pack: Mapping[str, Any],
        av_out: Mapping[str, Any],
        threat_kind: Optional[str],
    ) -> Any:
        if rt.security_router is None:
            return None
        sig_env = None
        if SecuritySignalEnvelope is not Any:
            try:
                sig_env = SecuritySignalEnvelope(
                    **_filtered_kwargs_for(
                        SecuritySignalEnvelope,
                        {
                            "source": "http_service",
                            "trusted": bool(getattr(request.state, "auth_trusted", False)),
                            "signed": False,
                            "signer_kid": None,
                            "source_cfg_fp": rt.bundle.cfg_fp,
                            "source_policy_ref": None,
                            "freshness_ms": None,
                            "replay_checked": None,
                        },
                    )
                )
            except Exception:
                sig_env = None

        sctx = _security_context_compat(
            req=req,
            request=request,
            body_digest=body_digest,
            request_id=request_id,
            trace_id=req.trace_id or _safe_text(getattr(request.state, "trace_id", None), max_len=128) or None,
            event_id=event_id,
            security_signal_envelope=sig_env,
        )
        if sctx is None:
            if cfgb.strict_mode and cfgb.require_security_router_when_strict:
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="security router unavailable")
            return None

        detector_payload = _build_detector_payload(
            req=req,
            score=score,
            decision_fail=decision_fail,
            verdict_pack=verdict_pack,
            av_out=av_out,
            threat_kind=threat_kind,
            event_id=event_id,
            request_id=request_id,
            body_digest=body_digest,
        )
        try:
            with rt.detector_adapter.bind(detector_payload):
                return rt.security_router.route(sctx)
        except Exception as e:
            if cfgb.strict_mode and cfgb.require_security_router_when_strict:
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="security router failure") from e
            return None

    def _verify_pq_from_body_and_request(req: VerifyRequest) -> None:
        if not req.receipt_body_json:
            return
        try:
            body_obj = json.loads(req.receipt_body_json)
        except Exception:
            return
        if not isinstance(body_obj, dict):
            return

        sec_block: Dict[str, Any] = {}
        comps = body_obj.get("components")
        if isinstance(comps, dict):
            sec_candidate = comps.get("security")
            if isinstance(sec_candidate, dict):
                sec_block = sec_candidate
        if not sec_block and isinstance(body_obj.get("security"), dict):
            sec_block = body_obj["security"]

        pq_required_eff = bool(sec_block.get("pq_required") or body_obj.get("pq_required") or bool(req.pq_required))
        pq_ok_eff = sec_block.get("pq_ok")
        if pq_required_eff and (pq_ok_eff is False or pq_ok_eff is None):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="pq_violation")

    @app.post("/diagnose", response_model=RiskResponse)
    def diagnose(
        req: DiagnoseRequest,
        request: Request,
        response: Response,
        _auth: None = Depends(auth_dependency),
    ) -> RiskResponse:
        t_start = time.perf_counter()
        request_id, body_digest, event_id = _request_identity(request, req)

        if cfgb.strict_mode and (req.tenant == "tenant0" or req.user == "user0" or req.session == "sess0"):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="subject identity required")

        response.headers["X-Request-Id"] = request_id
        response.headers["X-TCD-Event-Id"] = event_id
        response.headers["X-TCD-Http-Version"] = cfgb.api_version
        response.headers["X-TCD-Config-Fingerprint"] = rt.bundle.cfg_fp
        response.headers["X-TCD-Bundle-Version"] = str(rt.bundle.version)

        if _HAS_LOG and bind_request_meta is not None:
            with contextlib.suppress(Exception):
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

        subject = (req.tenant, req.user, req.session)
        _subject_cost, rate_decision = _apply_subject_policy_and_charge(req)

        if rt.gpu_sampler is not None:
            with contextlib.suppress(Exception):
                req.context.update(rt.gpu_sampler.sample())

        trace_vec = _sanitize_numeric_array(req.trace_vector, max_len=_MAX_TRACE)
        spectrum = _sanitize_numeric_array(req.spectrum, max_len=_MAX_SPECT)
        features = _sanitize_numeric_array(req.features, max_len=_MAX_FEATS)

        det_key = (req.model_id, req.gpu_id, req.task, req.lang)
        det = rt.detector_registry.get_detector_runtime(det_key)
        verdict_pack = _run_detector_runtime(det, req=req, trace_vec=trace_vec, spectrum=spectrum, features=features)
        if not isinstance(verdict_pack, Mapping):
            verdict_pack = {"verdict": True, "score": 1.0, "p_value": 1e-12, "decision": "block", "action": "block", "components": {"reason": "detector_runtime_invalid"}, "step": int(req.step_id or 0)}
        verdict_pack = dict(verdict_pack)
        det_signal = _extract_detector_signal(verdict_pack)

        mv_info: Dict[str, Any] = {}
        if features:
            with contextlib.suppress(Exception):
                mv = rt.detector_registry.get_multivar_detector(req.model_id)
                mv_info = mv.decision(np.asarray(features, dtype=float))  # type: ignore[assignment]
                if not isinstance(mv_info, Mapping):
                    mv_info = {}

        score = float(det_signal.get("risk_score") if det_signal.get("risk_score") is not None else 0.0)
        p_final = float(det_signal.get("p_value") if det_signal.get("p_value") is not None else max(1e-12, min(1.0, 1.0 - max(0.0, min(1.0, score)))))
        drift_w = max(0.0, min(2.0, 1.0 + 0.5 * float(req.drift_score or 0.0)))

        av = rt.detector_registry.get_alpha_controller(subject)
        av_out = _av_step_compat(
            av,
            req=req,
            subject=subject,
            model_id=req.model_id,
            gpu_id=req.gpu_id,
            task=req.task,
            lang=req.lang,
            score=score,
            p_value=p_final,
            drift_weight=drift_w,
            meta={
                "trust_zone": req.trust_zone,
                "route_profile": req.route_profile,
                "risk_label": req.risk_label,
                "threat_kind": req.threat_kind,
                "pq_required": req.pq_required,
                "request_id": request_id,
                "event_id": event_id,
                "body_digest": body_digest,
            },
        )
        budget = _alpha_budget_or_fail(av_out, tenant=req.tenant, user=req.user, session=req.session)
        decision_fail = bool(det_signal.get("decision_fail") or budget.triggered)

        route = _route_decide_compat(
            rt.router,
            decision_fail=decision_fail,
            score=score,
            base_temp=req.base_temp,
            base_top_p=req.base_top_p,
            base_max_tokens=req.base_max_tokens,
            risk_label=req.risk_label,
            route_profile=req.route_profile,
            trust_zone=req.trust_zone,
            threat_kind=req.threat_kind,
            threat_confidence=req.threat_confidence,
            pq_required=bool(req.pq_required),
            pq_unhealthy=False,
            av_label=_safe_text(getattr(getattr(av, "config", None), "label", None), max_len=64) or None,
            av_trigger=budget.triggered,
            controller_mode=budget.controller_mode,
            guarantee_scope=budget.statistical_guarantee_scope,
            request_id=request_id,
            trace_id=req.trace_id,
            tenant_id=req.tenant,
            principal_id=_safe_text(getattr(request.state, "auth_principal", None), max_len=128) or req.user,
            meta={
                "event_id": event_id,
                "request_id": request_id,
                "body_digest": body_digest,
                "build_id": req.build_id,
                "image_digest": req.image_digest,
                "compliance_tags": list(req.compliance_tags),
                "rate_reason": getattr(rate_decision, "reason", None) if rate_decision is not None else None,
                "auth_mode": _safe_text(getattr(request.state, "auth_mode", None), max_len=64) or None,
            },
        )

        security_decision = _security_router_decision(
            req=req,
            request=request,
            body_digest=body_digest,
            request_id=request_id,
            event_id=event_id,
            score=score,
            decision_fail=decision_fail,
            verdict_pack=verdict_pack,
            av_out=av_out,
            threat_kind=req.threat_kind,
        )

        route_info = _extract_route_dict(route)
        if not route_info:
            route_info = _build_synthetic_route_contract(
                req=req,
                request_id=request_id,
                event_id=event_id,
                score=score,
                decision_fail=decision_fail,
                av_trigger=budget.triggered,
                controller_mode=budget.controller_mode,
                guarantee_scope=budget.statistical_guarantee_scope,
                av_label=_safe_text(getattr(getattr(av, "config", None), "label", None), max_len=64) or None,
                threat_kind=req.threat_kind,
            )

        allowed = True
        required_action = _route_required_action(route_info)
        enforcement_mode = _route_enforcement_mode(route_info)
        action_str = "none"
        cause = _safe_text(det_signal.get("reason_code") or ("detector" if det_signal.get("decision_fail") else ("av" if budget.triggered else "")), max_len=128) or ("detector" if det_signal.get("decision_fail") else ("av" if budget.triggered else ""))
        policy_ref: Optional[str] = _safe_text(route_info.get("policy_ref"), max_len=128) or None
        policyset_ref: Optional[str] = _safe_text(route_info.get("policyset_ref"), max_len=128) or None
        config_fingerprint: Optional[str] = _safe_text(route_info.get("config_fingerprint"), max_len=128) or None
        bundle_version: Optional[int] = _coerce_int(route_info.get("bundle_version"))
        state_domain_id: Optional[str] = budget.state_domain_id
        controller_mode: Optional[str] = budget.controller_mode
        guarantee_scope: Optional[str] = budget.statistical_guarantee_scope
        decision_id: Optional[str] = _safe_text(route_info.get("decision_id"), max_len=128) or None
        route_plan_id: Optional[str] = _safe_text(route_info.get("route_plan_id") or route_info.get("route_id"), max_len=128) or None
        security_block: Dict[str, Any] = {}
        security_public: Dict[str, Any] = {}
        evidence_identity: Dict[str, Any] = {}
        artifacts: Dict[str, Any] = {}
        audit_ref: Optional[str] = None
        receipt_ref: Optional[str] = None
        raw_receipt_payload: Dict[str, Any] = {}

        if security_decision is not None:
            security_public = _extract_security_public(security_decision)
            allowed = bool(getattr(security_decision, "allowed", True))
            required_action = _safe_text(getattr(security_decision, "required_action", required_action), max_len=32).lower() or required_action
            action_taken = _safe_text(getattr(security_decision, "action", ""), max_len=32).lower()
            if action_taken in {"allow", "degrade", "block", "deny"}:
                action_str = "block" if action_taken == "deny" else action_taken
            else:
                action_str = "block" if required_action == "block" else ("degrade" if required_action == "degrade" else "none")
            enforcement_mode = _safe_text(getattr(security_decision, "enforcement_mode", enforcement_mode), max_len=32).lower() or enforcement_mode
            cause = _safe_text(getattr(security_decision, "primary_reason_code", cause), max_len=128) or cause

            route_obj = getattr(security_decision, "route", None)
            route_info = _extract_route_dict(route_obj) if route_obj is not None else route_info

            policy_ref = _safe_text(getattr(security_decision, "policy_ref", policy_ref), max_len=128) or policy_ref
            policyset_ref = _safe_text(getattr(security_decision, "policyset_ref", policyset_ref), max_len=128) or policyset_ref
            config_fingerprint = _safe_text(getattr(security_decision, "config_fingerprint", config_fingerprint), max_len=128) or config_fingerprint
            bundle_version = _coerce_int(getattr(security_decision, "bundle_version", bundle_version)) or bundle_version
            state_domain_id = _safe_text(getattr(security_decision, "state_domain_id", state_domain_id), max_len=128) or state_domain_id
            controller_mode = _safe_text(getattr(security_decision, "controller_mode", controller_mode), max_len=64) or controller_mode
            guarantee_scope = _safe_text(getattr(security_decision, "guarantee_scope", guarantee_scope), max_len=128) or guarantee_scope
            decision_id = _safe_text(getattr(security_decision, "decision_id", decision_id), max_len=128) or decision_id
            route_plan_id = _safe_text(getattr(security_decision, "route_plan_id", route_plan_id), max_len=128) or route_plan_id

            audit_ref = _safe_text(getattr(security_decision, "audit_ref", None), max_len=256) or None
            receipt_ref = _safe_text(getattr(security_decision, "receipt_ref", None), max_len=256) or None

            raw_receipt_payload = _extract_receipt_like(getattr(security_decision, "receipt", None))
            security_block = _sanitize_json_mapping(getattr(security_decision, "security", {}), max_depth=5, max_items=64, max_str_len=512, max_total_bytes=64_000)
            evidence_identity = _sanitize_json_mapping(getattr(security_decision, "evidence_identity", {}), max_depth=4, max_items=32, max_str_len=256, max_total_bytes=16_000)
            artifacts = _sanitize_json_mapping(getattr(security_decision, "artifacts", {}), max_depth=4, max_items=32, max_str_len=256, max_total_bytes=16_000)
        else:
            required_action = required_action if required_action in {"allow", "degrade", "block"} else (
                "block" if (cfgb.strict_mode and req.risk_label == "critical" and decision_fail) else ("degrade" if (decision_fail or cfgb.strict_mode) else "allow")
            )
            action_str = _manual_route_action(
                route,
                decision_fail,
                threat_kind=req.threat_kind,
                threat_conf=req.threat_confidence,
                pq_required=bool(req.pq_required),
                pq_ok=_coerce_bool(route_info.get("pq_ok"), default=False) if route_info.get("pq_ok") is not None else None,
            )
            if action_str not in _ALLOWED_ACTIONS:
                action_str = "degrade" if (decision_fail or cfgb.strict_mode) else "none"
            if required_action == "block":
                action_str = "block"
                allowed = False
            elif required_action == "degrade":
                if action_str in {"allow", "none"}:
                    action_str = "degrade"
                allowed = True
            else:
                if action_str == "allow":
                    action_str = "none"
                allowed = action_str != "block"

            enforcement_mode = _safe_text(route_info.get("enforcement_mode"), max_len=32).lower() or (
                "fail_closed" if (required_action == "block" and cfgb.strict_mode) else ("must_enforce" if (required_action != "allow" and cfgb.strict_mode) else "advisory")
            )

            security_block = {
                "trust_zone": req.trust_zone,
                "route_profile": req.route_profile,
                "risk_label": req.risk_label,
                "threat_kind": req.threat_kind,
                "threat_confidence": req.threat_confidence,
                "pq_required": req.pq_required,
                "pq_ok": route_info.get("pq_ok"),
                "policy_ref": policy_ref,
                "route_id": route_plan_id,
                "build_id": req.build_id,
                "image_digest": req.image_digest,
                "compliance_tags": list(req.compliance_tags),
                "request_id": request_id,
                "event_id": event_id,
                "body_digest": body_digest,
                "surface_kind": "local_http_fallback",
            }
            artifacts = {
                "receipt_required": bool(cfgb.receipts_enable_default or (cfgb.require_receipts_on_fail and required_action == "block") or (cfgb.require_receipts_when_pq and bool(req.pq_required))),
                "ledger_required": False,
                "attestation_required": bool(cfgb.require_attestor_when_receipt_required),
                "ledger_stage": "skipped",
                "outbox_status": "none",
                "receipt_surface_kind": "local_attestation",
                "durability": "ephemeral_local_only",
            }
            evidence_identity = {
                "request_id": request_id,
                "event_id": event_id,
                "decision_id": decision_id,
                "route_plan_id": route_plan_id,
                "config_fingerprint": config_fingerprint or rt.bundle.cfg_fp,
                "policy_ref": policy_ref,
                "policyset_ref": policyset_ref,
                "state_domain_id": state_domain_id,
                "controller_mode": controller_mode,
                "statistical_guarantee_scope": guarantee_scope,
                "receipt_ref": receipt_ref,
                "audit_ref": audit_ref,
                "produced_by": "service_http.local",
            }

        if cfgb.strict_mode and cfgb.require_finalized_receipt_surface_when_strict:
            receipt_needed_strict = bool(cfgb.receipts_enable_default or (cfgb.require_receipts_on_fail and required_action == "block") or (cfgb.require_receipts_when_pq and bool(req.pq_required)))
            if receipt_needed_strict and rt.security_router is None and raw_receipt_payload == {}:
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="finalized receipt surface unavailable")

        if not raw_receipt_payload:
            need_local_receipt = (
                rt.receipt_mgr.attestor is not None
                and (
                    cfgb.receipts_enable_default
                    or (cfgb.require_receipts_on_fail and required_action == "block")
                    or (cfgb.require_receipts_when_pq and bool(req.pq_required))
                )
            )
            if need_local_receipt:
                rb = rt.receipt_mgr.issue_local_final(
                    trace=trace_vec,
                    spectrum=spectrum,
                    features=features,
                    req=req,
                    request_id=request_id,
                    event_id=event_id,
                    body_digest=body_digest,
                    score=score,
                    p_final=p_final,
                    route_info=route_info,
                    final_action=action_str,
                    required_action=required_action,
                    enforcement_mode=enforcement_mode,
                    allowed=allowed,
                    cause=cause,
                    policy_ref=policy_ref,
                    policyset_ref=policyset_ref,
                    policy_digest=det_signal.get("policy_digest"),
                    cfg_fp=config_fingerprint or rt.bundle.cfg_fp,
                    decision_id=decision_id or "",
                    route_plan_id=route_plan_id or "",
                    audit_ref=audit_ref,
                    state_domain_id=state_domain_id,
                    adapter_registry_fp=budget.adapter_registry_fp,
                    budget=budget,
                    detector_components=dict(verdict_pack.get("components", {})) if isinstance(verdict_pack.get("components"), Mapping) else {},
                    mv_info=mv_info,
                    security_block=security_block,
                    artifacts=artifacts,
                    evidence_identity=evidence_identity,
                    pq_ok=_coerce_bool(route_info.get("pq_ok"), default=False) if route_info.get("pq_ok") is not None else None,
                )
                raw_receipt_payload = dict(rb.raw)
                receipt_ref = _safe_text(raw_receipt_payload.get("receipt_ref"), max_len=256) or receipt_ref
                if receipt_ref is None:
                    receipt_ref = _safe_text(raw_receipt_payload.get("receipt"), max_len=256) or None
                evidence_identity["receipt_ref"] = receipt_ref
                evidence_identity["audit_ref"] = audit_ref

        if cfgb.strict_mode and cfgb.require_attestor_when_receipt_required and (
            (cfgb.require_receipts_on_fail and required_action == "block")
            or (cfgb.require_receipts_when_pq and bool(req.pq_required))
        ):
            if not raw_receipt_payload:
                raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="receipt unavailable")

        decision_id = decision_id or f"hd1:{_SAFE_DIGEST_ALG}:{_hash_hex(ctx='tcd:http:decision', payload={'event_id': event_id, 'request_id': request_id, 'required_action': required_action, 'route_plan_id': route_plan_id, 'subject': [req.tenant, req.user, req.session]}, out_hex=32)}"
        route_plan_id = route_plan_id or f"hr1:{_SAFE_DIGEST_ALG}:{_hash_hex(ctx='tcd:http:route_plan', payload={'risk_label': req.risk_label, 'trust_zone': req.trust_zone, 'route_profile': req.route_profile, 'score': _stable_float(score), 'required_action': required_action}, out_hex=32)}"
        request.state.decision_id = decision_id
        request.state.route_plan_id = route_plan_id

        raw_receipt_payload = {
            **raw_receipt_payload,
            "receipt_ref": raw_receipt_payload.get("receipt_ref") or receipt_ref or raw_receipt_payload.get("receipt"),
            "audit_ref": raw_receipt_payload.get("audit_ref") or audit_ref,
            "event_id": raw_receipt_payload.get("event_id") or event_id,
            "decision_id": raw_receipt_payload.get("decision_id") or decision_id,
            "route_plan_id": raw_receipt_payload.get("route_plan_id") or route_plan_id,
            "policy_ref": raw_receipt_payload.get("policy_ref") or policy_ref,
            "policyset_ref": raw_receipt_payload.get("policyset_ref") or policyset_ref,
            "cfg_fp": raw_receipt_payload.get("cfg_fp") or config_fingerprint or rt.bundle.cfg_fp,
            "state_domain_id": raw_receipt_payload.get("state_domain_id") or state_domain_id,
            "adapter_registry_fp": raw_receipt_payload.get("adapter_registry_fp") or budget.adapter_registry_fp,
            "build_id": raw_receipt_payload.get("build_id") or req.build_id,
            "image_digest": raw_receipt_payload.get("image_digest") or req.image_digest,
            "pq_required": raw_receipt_payload.get("pq_required") if raw_receipt_payload.get("pq_required") is not None else req.pq_required,
            "pq_ok": raw_receipt_payload.get("pq_ok") if raw_receipt_payload.get("pq_ok") is not None else (_coerce_bool(route_info.get("pq_ok"), default=False) if route_info.get("pq_ok") is not None else None),
        }

        receipt_public, receipt_verification = _build_receipt_surfaces(
            raw_receipt_payload,
            expose_verification_bundle_public=cfgb.expose_verification_bundle_public,
            expose_verify_key_public=cfgb.expose_verify_key_public,
        )

        identity_status = "ok"
        if req.tenant == "tenant0" or req.user == "user0" or req.session == "sess0":
            identity_status = "defaulted"

        auth_proj = getattr(request.state, "auth_projection", None)
        auth_public = auth_proj.public_view(expose_principal=False) if isinstance(auth_proj, _AuthProjection) else {
            "mode": _safe_text(getattr(request.state, "auth_mode", None), max_len=64) or "none",
            "trusted": bool(getattr(request.state, "auth_trusted", False)),
        }

        evidence_identity = {
            **evidence_identity,
            "request_id": request_id,
            "event_id": event_id,
            "decision_id": decision_id,
            "route_plan_id": route_plan_id,
            "policy_ref": policy_ref,
            "policyset_ref": policyset_ref,
            "config_fingerprint": config_fingerprint or rt.bundle.cfg_fp,
            "bundle_version": bundle_version or rt.bundle.version,
            "state_domain_id": state_domain_id,
            "audit_ref": audit_ref,
            "receipt_ref": receipt_public.get("receipt_ref") or receipt_ref,
            "controller_mode": controller_mode,
            "statistical_guarantee_scope": guarantee_scope,
        }

        components: Dict[str, Any] = {
            "detector": _sanitize_json_mapping(
                {
                    **(dict(verdict_pack.get("components", {})) if isinstance(verdict_pack.get("components"), Mapping) else {}),
                    "decision": verdict_pack.get("decision"),
                    "action": verdict_pack.get("action"),
                    "risk": verdict_pack.get("risk"),
                    "p_value": verdict_pack.get("p_value"),
                    "reason_code": verdict_pack.get("reason_code"),
                    "error_code": verdict_pack.get("error_code"),
                    "decision_id": verdict_pack.get("decision_id"),
                    "config_hash": verdict_pack.get("config_hash"),
                    "policy_digest": verdict_pack.get("policy_digest"),
                    "state_digest": verdict_pack.get("state_digest"),
                },
                max_depth=5,
                max_items=64,
                max_str_len=512,
                max_total_bytes=64_000,
            ),
            "multivariate": _sanitize_json_mapping(mv_info, max_depth=4, max_items=64, max_str_len=512, max_total_bytes=64_000),
            "e_process": _sanitize_json_mapping(av_out.get("e_state", {}), max_depth=6, max_items=128, max_str_len=1024, max_total_bytes=96_000),
            "route": _sanitize_json_mapping(route_info, max_depth=5, max_items=96, max_str_len=512, max_total_bytes=64_000),
            "security": _sanitize_json_mapping(security_block, max_depth=5, max_items=96, max_str_len=512, max_total_bytes=64_000),
            "security_router": _sanitize_json_mapping(security_public, max_depth=5, max_items=96, max_str_len=512, max_total_bytes=64_000),
            "artifacts": _sanitize_json_mapping(artifacts, max_depth=4, max_items=32, max_str_len=256, max_total_bytes=16_000),
            "receipt": _sanitize_json_mapping(receipt_public, max_depth=4, max_items=32, max_str_len=512, max_total_bytes=32_000),
            "evidence_identity": _sanitize_json_mapping(evidence_identity, max_depth=4, max_items=32, max_str_len=256, max_total_bytes=16_000),
            "auth": _sanitize_json_mapping(auth_public, max_depth=4, max_items=32, max_str_len=256, max_total_bytes=16_000),
            "identity": {
                "status": identity_status,
                "tenant": req.tenant,
                "user": req.user,
                "session": req.session,
                "model_id": req.model_id,
            },
            "request": {
                "body_digest": body_digest,
                "tenant": req.tenant,
                "user": req.user,
                "session": req.session,
                "model_id": req.model_id,
                "gpu_id": req.gpu_id,
                "task": req.task,
                "lang": req.lang,
            },
        }
        if receipt_verification is not None:
            components["receipt_verification_exposed"] = True

        latency_s = max(0.0, time.perf_counter() - t_start)
        http_metrics.observe_core_latency(latency_s)
        http_metrics.push_verdict(verdict_pack, labels={"model_id": req.model_id, "gpu_id": req.gpu_id})
        http_metrics.push_eprocess(
            model_id=req.model_id,
            gpu_id=req.gpu_id,
            tenant=req.tenant,
            user=req.user,
            session=req.session,
            e_value=budget.e_value,
            alpha_alloc=budget.alpha_alloc,
            alpha_wealth=budget.alpha_wealth,
        )
        http_metrics.update_budget_metrics(req.tenant, req.user, req.session, remaining=budget.alpha_wealth, spent=bool(budget.alpha_spent > 0.0))
        if required_action != "allow":
            http_metrics.record_action(req.model_id, req.gpu_id, action=required_action)

        _call_otel(
            rt.otel,
            score,
            {
                "model_id": req.model_id,
                "gpu_id": req.gpu_id,
                "tenant": req.tenant,
                "user": req.user,
                "session": req.session,
                "tcd.event_id": event_id,
                "tcd.decision_id": decision_id,
                "tcd.route_plan_id": route_plan_id,
                "tcd.required_action": required_action,
                "tcd.allowed": str(bool(allowed)),
                "tcd.controller_mode": controller_mode or "",
                "tcd.statistical_guarantee_scope": guarantee_scope or "",
            },
        )

        slo_ms = float(getattr(rt.settings, "slo_latency_ms", 0.0) or 0.0)
        if slo_ms and (latency_s * 1000.0) > slo_ms:
            http_metrics.record_slo_by_model("diagnose_latency", req.model_id, req.gpu_id)

        if _HAS_LOG and log_decision is not None and rt.logger is not None:
            with contextlib.suppress(Exception):
                log_decision(
                    rt.logger,
                    verdict=bool(required_action != "allow"),
                    score=score,
                    e_value=budget.e_value,
                    alpha_alloc=budget.alpha_alloc,
                    message="diagnose",
                    extra={
                        "request_id": request_id,
                        "event_id": event_id,
                        "decision_id": decision_id,
                        "route_plan_id": route_plan_id,
                        "route_decoder": route_info.get("decoder"),
                        "route_temp": route_info.get("temperature"),
                        "route_top_p": route_info.get("top_p"),
                        "action": action_str,
                        "required_action": required_action,
                        "p_final": float(p_final),
                    },
                )

        response.headers["X-TCD-Decision-Id"] = decision_id
        response.headers["X-TCD-Route-Plan-Id"] = route_plan_id

        decision_label = "block" if action_str == "block" else ("degrade" if action_str in {"degrade", "advisory"} or required_action == "degrade" else "allow")

        legacy_receipt = receipt_public.get("head") if cfgb.expose_legacy_receipt_aliases else None
        legacy_body = receipt_verification.get("body") if (cfgb.expose_legacy_receipt_aliases and receipt_verification) else None
        legacy_sig = receipt_verification.get("sig") if (cfgb.expose_legacy_receipt_aliases and receipt_verification) else None
        legacy_vk = receipt_verification.get("verify_key") if (cfgb.expose_legacy_receipt_aliases and receipt_verification) else None

        return RiskResponse(
            verdict=bool(required_action != "allow"),
            allowed=bool(allowed),
            decision=decision_label,
            required_action=required_action,
            enforcement_mode=enforcement_mode,
            score=score,
            threshold=budget.threshold,
            budget_remaining=budget.alpha_wealth,
            components=_sanitize_json_mapping(
                components,
                max_depth=cfgb.max_component_depth,
                max_items=cfgb.max_component_items,
                max_str_len=cfgb.max_component_str_len,
                max_total_bytes=cfgb.max_json_component_bytes,
            ),
            cause=_safe_text(cause, max_len=128) or None,
            action=action_str,
            step=int(_coerce_int(verdict_pack.get("step")) or 0),
            e_value=budget.e_value,
            alpha_alloc=budget.alpha_alloc,
            alpha_spent=budget.alpha_spent,
            request_id=request_id,
            event_id=event_id,
            decision_id=decision_id,
            route_plan_id=route_plan_id,
            policy_ref=policy_ref,
            policyset_ref=policyset_ref,
            config_fingerprint=config_fingerprint or rt.bundle.cfg_fp,
            bundle_version=bundle_version or rt.bundle.version,
            state_domain_id=state_domain_id,
            controller_mode=controller_mode,
            statistical_guarantee_scope=guarantee_scope,
            audit_ref=audit_ref,
            receipt_ref=receipt_public.get("receipt_ref") or receipt_ref,
            trust_zone=req.trust_zone,
            route_profile=req.route_profile,
            threat_kind=req.threat_kind,
            pq_required=req.pq_required,
            pq_ok=_coerce_bool(route_info.get("pq_ok"), default=False) if route_info.get("pq_ok") is not None else None,
            receipt_public=receipt_public,
            receipt_verification=receipt_verification,
            evidence_identity=evidence_identity,
            artifacts=artifacts,
            receipt=legacy_receipt,
            receipt_body=legacy_body,
            receipt_sig=legacy_sig,
            verify_key=legacy_vk,
        )

    @app.post("/v1/diagnose", response_model=RiskResponse)
    def diagnose_v1(
        req: DiagnoseRequest,
        request: Request,
        response: Response,
        _auth: None = Depends(auth_dependency),
    ) -> RiskResponse:
        return diagnose(req, request, response, _auth=_auth)

    def _validate_chain_mode(req: VerifyRequest) -> None:
        if not isinstance(req.heads, list) or not isinstance(req.bodies, list) or len(req.heads) != len(req.bodies) or len(req.heads) == 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="heads/bodies invalid")
        if len(req.heads) > verify_limits.max_window:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="window too large")
        total_len = sum(len(h or "") for h in req.heads) + sum(len(b or "") for b in req.bodies)
        if total_len > verify_limits.max_chain_payload_bytes:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="verify payload too large")

    def _validate_single_mode(req: VerifyRequest) -> None:
        if not req.receipt_head_hex or not req.receipt_body_json:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="missing receipt head/body")
        body_bytes = len(req.receipt_body_json.encode("utf-8", errors="strict"))
        if body_bytes > verify_limits.max_receipt_body_bytes:
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="receipt body too large")
        verify_key = req.verify_key or req.verify_key_hex
        if verify_key is not None and len(verify_key) > verify_limits.max_verify_key_len:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="verify key too large")

    @app.post("/verify", response_model=VerifyResponse)
    def verify(
        req: VerifyRequest,
        request: Request,
        response: Response,
        _auth: None = Depends(auth_dependency),
    ) -> VerifyResponse:
        request_id = _safe_text(getattr(request.state, "request_id", None), max_len=128) or (
            ensure_request_id(dict(request.headers)) if (_HAS_LOG and ensure_request_id is not None) else uuid.uuid4().hex[:16]
        )
        response.headers["X-Request-Id"] = request_id
        response.headers["X-TCD-Http-Version"] = cfgb.api_version
        response.headers["X-TCD-Config-Fingerprint"] = rt.bundle.cfg_fp
        response.headers["X-TCD-Bundle-Version"] = str(rt.bundle.version)

        t0 = time.perf_counter()
        ok = False
        reason = "verify_fail"
        report_dict: Dict[str, Any] = {}
        try:
            if req.heads is not None or req.bodies is not None:
                _validate_chain_mode(req)
                ok = bool(verify_chain(req.heads or [], req.bodies or []))
                reason = "chain"
            else:
                _validate_single_mode(req)
                verify_key = req.verify_key or req.verify_key_hex
                report = verify_receipt_ex(
                    receipt_head_hex=req.receipt_head_hex or "",
                    receipt_body_json=req.receipt_body_json or "",
                    verify_key_hex=verify_key,
                    receipt_sig_hex=req.receipt_sig_hex,
                    req_obj=req.req_obj,
                    comp_obj=req.comp_obj,
                    e_obj=req.e_obj,
                    witness_segments=req.witness_segments,
                    strict=True,
                    expected_policy_ref=req.expected_policy_ref,
                    expected_policyset_ref=req.expected_policyset_ref,
                    expected_policy_digest=req.expected_policy_digest,
                    expected_cfg_fp=req.expected_cfg_fp,
                    expected_build_id=req.expected_build_id,
                    expected_image_digest=req.expected_image_digest,
                    require_signature=req.require_signature,
                )
                ok = bool(getattr(report, "ok", False))
                reason = "receipt"
                report_dict = {
                    "head_verified": getattr(report, "head_verified", None),
                    "body_canonical_verified": getattr(report, "body_canonical_verified", None),
                    "integrity_hash_verified": getattr(report, "integrity_hash_verified", None),
                    "signature_verified": getattr(report, "signature_verified", None),
                    "verify_key_allowed": getattr(report, "verify_key_allowed", None),
                    "policy_binding_verified": getattr(report, "policy_binding_verified", None),
                    "cfg_binding_verified": getattr(report, "cfg_binding_verified", None),
                    "integrity_ok": getattr(report, "ok", None),
                    "errors": list(getattr(report, "errors", []) or []),
                    "warnings": list(getattr(report, "warnings", []) or []),
                }
                if ok:
                    _verify_pq_from_body_and_request(req)
        finally:
            latency = max(0.0, time.perf_counter() - t0)
            http_metrics.observe_core_latency(latency)
            if not ok:
                http_metrics.record_verify_fail()

        return VerifyResponse(ok=ok, request_id=request_id, reason=reason, report=report_dict)

    @app.post("/v1/verify", response_model=VerifyResponse)
    def verify_v1(
        req: VerifyRequest,
        request: Request,
        response: Response,
        _auth: None = Depends(auth_dependency),
    ) -> VerifyResponse:
        return verify(req, request, response, _auth=_auth)

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        create_app(runtime=_get_singleton_runtime()),
        host="127.0.0.1",
        port=8000,
        reload=True,
    )