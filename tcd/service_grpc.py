from __future__ import annotations

"""
tcd/service_grpc.py

Platform-grade gRPC service shim for TCD.

This module is intentionally a transport/control-plane adapter, not a policy
engine. It aligns the gRPC surface with the stronger contracts already present
in auth.py, routing.py, risk_av.py, security_router.py, attest.py, audit.py,
schemas.py, and api_v1.py.

Core properties:
- bounded metadata / payload / vector / verify-chain budgets
- deterministic request_id / event_id / body_digest semantics
- protocol compatibility policy (api_version / compatibility_epoch / capabilities)
- strong subject identity parsing with explicit degraded / rejected states
- method-scoped authz with peer/mTLS awareness
- bounded executors + queue rejection + dependency breakers
- detector + multivariate + AlwaysValidRiskController pipeline
- optional SecurityRouter v3 integration for policy, routing, receipts, audit, ledger
- prepare/commit evidence flow with outbox fallback
- process-isolated verify option
- safe no-op registration when grpcio or generated stubs are unavailable
"""

import asyncio
import concurrent.futures
import contextlib
import dataclasses
import hashlib
import inspect
import ipaddress
import json
import logging
import math
import multiprocessing as mp
import os
import random
import re
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Protocol, Sequence, Tuple, Literal

# ---------------------------------------------------------------------------
# Optional dependencies
# ---------------------------------------------------------------------------

try:
    import grpc  # type: ignore
    _HAS_GRPC = True
except Exception:  # pragma: no cover
    grpc = None  # type: ignore
    _HAS_GRPC = False

try:
    from .proto import tcd_pb2 as pb  # type: ignore
    from .proto import tcd_pb2_grpc as pb_grpc  # type: ignore
    _HAS_STUBS = True
except Exception:  # pragma: no cover
    pb = None  # type: ignore
    pb_grpc = None  # type: ignore
    _HAS_STUBS = False

try:
    from starlette.requests import Request as StarletteRequest  # type: ignore
    _HAS_STARLETTE = True
except Exception:  # pragma: no cover
    StarletteRequest = Any  # type: ignore
    _HAS_STARLETTE = False

# ---------------------------------------------------------------------------
# TCD imports
# ---------------------------------------------------------------------------

from .config import make_reloadable_settings
from .detector import TCDConfig, TraceCollapseDetector
from .exporter import TCDPrometheusExporter
from .multivariate import MultiVarConfig, MultiVarDetector
from .otel_exporter import TCDOtelExporter
from .risk_av import AlwaysValidConfig, AlwaysValidRiskController
from .routing import StrategyRouter
from .utils import sanitize_floats
from .verify import verify_chain, verify_receipt

try:
    from .ratelimit import RateLimiter, RateLimitConfig, RateLimitZoneConfig, RateKey
except Exception:  # pragma: no cover
    from .ratelimit import RateLimiter  # type: ignore
    RateLimitConfig = Any  # type: ignore
    RateLimitZoneConfig = Any  # type: ignore
    RateKey = Any  # type: ignore

try:
    from .auth import Authenticator, build_authenticator_from_env  # type: ignore
except Exception:  # pragma: no cover
    Authenticator = None  # type: ignore[assignment]
    build_authenticator_from_env = None  # type: ignore[assignment]

try:
    from .attest import Attestor, AttestorConfig, canonical_kv_hash  # type: ignore
except Exception:  # pragma: no cover
    Attestor = None  # type: ignore[assignment]
    AttestorConfig = None  # type: ignore[assignment]
    canonical_kv_hash = None  # type: ignore[assignment]

try:
    from .audit import AuditLedger  # type: ignore
except Exception:  # pragma: no cover
    AuditLedger = None  # type: ignore[assignment]

try:
    from .security_router import (
        SecurityRouter,
        SecurityContext,
        SecurityAuthContext,
        SecuritySignalEnvelope,
    )
except Exception:  # pragma: no cover
    SecurityRouter = None  # type: ignore[assignment]
    SecurityContext = Any  # type: ignore[misc]
    SecurityAuthContext = Any  # type: ignore[misc]
    SecuritySignalEnvelope = Any  # type: ignore[misc]

try:
    from .trust_graph import SubjectKey
except Exception:  # pragma: no cover
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

try:
    from .policies import PolicyStore  # type: ignore
except Exception:  # pragma: no cover
    PolicyStore = Any  # type: ignore[misc]

try:
    from .schemas import DiagnoseOut, ReceiptPublicView  # type: ignore
except Exception:  # pragma: no cover
    DiagnoseOut = None  # type: ignore[assignment]
    ReceiptPublicView = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)
_settings = make_reloadable_settings()

# ---------------------------------------------------------------------------
# Constants / regex
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
ERR_VERIFY = "VERIFY"
ERR_HEADERS_TOO_LARGE = "HEADERS_TOO_LARGE"
ERR_UNAVAILABLE = "UNAVAILABLE"

_MAX_TRACE = 8192
_MAX_SPECT = 8192
_MAX_FEATS = 4096
_JSON_COMPONENT_LIMIT = 256_000

_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 ]+-----")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[a-z0-9._-]{10,}")
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=_-]{80,}$")
_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_SAFE_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_SAFE_KID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_ALLOWED_AUTH_METADATA = frozenset(
    {
        "authorization",
        "x-tcd-signature",
        "x-tcd-key-id",
        "x-forwarded-client-cert",
        "x-request-id",
        "request-id",
        "x-trace-id",
        "idempotency-key",
        "content-length",
        "content-type",
        "x-tcd-api-version",
        "x-client-version",
        "x-tcd-compatibility-epoch",
        "x-client-capabilities",
        "x-tenant",
        "x-user",
        "x-session",
        "x-principal-id",
        "x-trust-zone",
        "x-route-profile",
        "x-threat",
        "x-threat-confidence",
        "x-pq-required",
        "x-build-id",
        "x-image-digest",
        "x-compliance-tags",
        "x-approval-id",
        "x-approval-system",
        "x-mfa-verified",
        "x-classification",
        "x-region",
        "x-cluster",
    }
)

# ---------------------------------------------------------------------------
# Prometheus metrics (safe stubs if missing)
# ---------------------------------------------------------------------------

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

_GRPC_REQ_LATENCY = Histogram(
    "tcd_service_grpc_request_latency_seconds",
    "Latency of gRPC calls through TCD service shim",
    buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20, 0.50, 1.0, 2.0, 5.0, 10.0),
    labelnames=("method", "status", "action"),
)
_GRPC_REQ_TOTAL = Counter(
    "tcd_service_grpc_request_total",
    "Total gRPC calls by status",
    labelnames=("method", "status"),
)
_GRPC_REQ_ERROR = Counter(
    "tcd_service_grpc_error_total",
    "Internal gRPC handler errors",
    labelnames=("method", "kind"),
)
_GRPC_REQ_REJECTED = Counter(
    "tcd_service_grpc_rejected_total",
    "Rejected gRPC requests",
    labelnames=("method", "reason"),
)
_GRPC_INFLIGHT = Gauge(
    "tcd_service_grpc_inflight",
    "Current in-flight gRPC calls",
    labelnames=("method",),
)
_GRPC_GATE_REJECT = Counter(
    "tcd_service_grpc_gate_reject_total",
    "gRPC gate rejections",
    labelnames=("method", "reason"),
)
_GRPC_REQ_PAYLOAD_BYTES = Histogram(
    "tcd_service_grpc_payload_bytes",
    "gRPC request payload bytes",
    buckets=(0, 128, 512, 1024, 4096, 16384, 65536, 262144, 1048576),
    labelnames=("method",),
)
_GRPC_METADATA_BYTES = Histogram(
    "tcd_service_grpc_metadata_bytes",
    "gRPC metadata bytes",
    buckets=(0, 128, 512, 1024, 4096, 8192, 16384, 32768),
    labelnames=("method",),
)
_GRPC_DEP_LATENCY = Histogram(
    "tcd_service_grpc_dependency_latency_ms",
    "Dependency latency in gRPC shim (ms)",
    buckets=(1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000),
    labelnames=("dep", "op", "status"),
)
_GRPC_DEP_ERROR = Counter(
    "tcd_service_grpc_dependency_error_total",
    "Dependency errors in gRPC shim",
    labelnames=("dep", "op", "kind"),
)
_GRPC_BREAKER_STATE = Gauge(
    "tcd_service_grpc_breaker_state",
    "Breaker state: 0=CLOSED 1=OPEN 2=HALF_OPEN",
    labelnames=("dep",),
)
_GRPC_BREAKER_PROBE_TOTAL = Counter(
    "tcd_service_grpc_breaker_probe_total",
    "Breaker probes",
    labelnames=("dep", "ok"),
)
_GRPC_EXEC_RESERVED = Gauge(
    "tcd_service_grpc_executor_reserved",
    "Reserved slots in bounded executors",
    labelnames=("pool",),
)
_GRPC_EXEC_REJECT = Counter(
    "tcd_service_grpc_executor_reject_total",
    "Rejected submissions to bounded executors",
    labelnames=("pool",),
)
_GRPC_OUTBOX_DEPTH = Gauge(
    "tcd_service_grpc_outbox_depth",
    "Outbox pending depth",
    labelnames=("kind",),
)
_GRPC_OUTBOX_OLDEST_AGE_S = Gauge(
    "tcd_service_grpc_outbox_oldest_age_seconds",
    "Outbox oldest pending age",
    labelnames=("kind",),
)
_GRPC_OUTBOX_CONFLICT = Counter(
    "tcd_service_grpc_outbox_conflict_total",
    "Outbox dedupe conflicts",
    labelnames=("kind",),
)
_GRPC_LEDGER_ERROR = Counter(
    "tcd_service_grpc_ledger_error_total",
    "Ledger errors in gRPC shim",
    labelnames=("method", "stage"),
)
_GRPC_PROTO_REJECT = Counter(
    "tcd_service_grpc_protocol_reject_total",
    "Protocol compatibility rejections",
    labelnames=("method", "reason"),
)
_GRPC_SUBJECT_STATUS = Counter(
    "tcd_service_grpc_subject_status_total",
    "Subject identity outcomes",
    labelnames=("method", "status"),
)
_GRPC_REPLAY_REJECT = Counter(
    "tcd_service_grpc_replay_reject_total",
    "Replay/idempotency rejections",
    labelnames=("reason",),
)

# ---------------------------------------------------------------------------
# Small helpers
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
        v = float(raw)
    except Exception:
        return float(default)
    return v if math.isfinite(v) else float(default)


def _split_env_list(name: str) -> Optional[List[str]]:
    raw = os.getenv(name, "")
    xs = [x.strip() for x in raw.split(",") if x.strip()]
    return xs or None


def _truncate(s: str, n: int) -> str:
    if n <= 0:
        return ""
    if len(s) <= n:
        return s
    return s[: max(0, n - 3)] + "..."


def _safe_text(v: Any, *, max_len: int = 256) -> str:
    try:
        if isinstance(v, bytes):
            s = v.decode("utf-8", errors="replace")
        else:
            s = str(v)
    except Exception:
        s = "<unprintable>"
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = _CTRL_CHARS_RE.sub("", s)
    s = s.strip()
    return _truncate(s, max_len)


def _safe_taglike(v: Any, *, max_len: int = 128) -> Optional[str]:
    s = _safe_text(v, max_len=max_len)
    if not s:
        return None
    if not _SAFE_TAG_RE.fullmatch(s):
        return None
    return s


def _normalize_auth_mode(v: Any) -> str:
    s = _safe_text(v, max_len=32).strip().lower()
    if s in {"", "none", "disabled"}:
        return "none"
    if s in {"bearer", "token"}:
        return "bearer"
    if s in {"jwt"}:
        return "jwt"
    if s in {"hmac", "signature"}:
        return "hmac"
    if s in {"mtls", "m_tls", "m-tls", "tls"}:
        return "mtls"
    return "other"


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


def _canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _canonical_json_bytes(obj: Any) -> bytes:
    return _canonical_json(obj).encode("utf-8", errors="strict")


def _blake3_hex(data: bytes, *, ctx: str) -> str:
    try:
        from .crypto import Blake3Hash  # type: ignore
        return Blake3Hash().hex(data, ctx=ctx)
    except Exception:
        h = hashlib.sha256()
        h.update(ctx.encode("utf-8", errors="ignore"))
        h.update(b"\x00")
        h.update(data)
        return h.hexdigest()


def _hash_token(s: str, *, ctx: str, n: int = 16) -> str:
    return _blake3_hex(s.encode("utf-8", errors="ignore"), ctx=ctx)[: max(8, min(64, int(n)))]


def _model_dump(obj: Any) -> Dict[str, Any]:
    if obj is None:
        return {}
    if hasattr(obj, "model_dump"):
        with contextlib.suppress(Exception):
            return dict(obj.model_dump())  # type: ignore[attr-defined]
    if hasattr(obj, "dict"):
        with contextlib.suppress(Exception):
            return dict(obj.dict())  # type: ignore[attr-defined]
    if dataclasses.is_dataclass(obj):
        with contextlib.suppress(Exception):
            return dataclasses.asdict(obj)
    return {}


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
        try:
            return int(s, 10)
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
    if x < lo:
        return float(lo)
    if x > hi:
        return float(hi)
    return float(x)


def _clamp_int(v: Any, *, default: int, lo: int, hi: int) -> int:
    x = _coerce_int(v)
    if x is None:
        return int(default)
    if x < lo:
        return int(lo)
    if x > hi:
        return int(hi)
    return int(x)


def _p_cons(score: float) -> float:
    s = max(0.0, min(1.0, float(score)))
    return max(1e-12, 1.0 - s)


def _status_label_for_code(code: Any) -> str:
    if code is None:
        return "ok"
    s = _safe_text(code, max_len=64).lower()
    if "resource_exhausted" in s:
        return "rate_limited"
    if "deadline_exceeded" in s:
        return "timeout"
    if "unauthenticated" in s:
        return "unauthenticated"
    if "permission_denied" in s:
        return "forbidden"
    if "invalid_argument" in s:
        return "bad_request"
    if "already_exists" in s:
        return "conflict"
    if "unavailable" in s:
        return "unavailable"
    return "error"


def _deterministic_proto_bytes(msg: Any) -> bytes:
    try:
        return msg.SerializeToString(deterministic=True)  # type: ignore[attr-defined]
    except TypeError:
        with contextlib.suppress(Exception):
            return msg.SerializeToString()  # type: ignore[attr-defined]
        return b""
    except Exception:
        with contextlib.suppress(Exception):
            return msg.SerializeToString()  # type: ignore[attr-defined]
        return b""


def _has_field(msg: Any, name: str) -> bool:
    try:
        return msg.HasField(name)  # type: ignore[attr-defined]
    except Exception:
        return getattr(msg, name, None) is not None


def _metadata_pairs(context: Any) -> List[Tuple[str, str]]:
    try:
        items = list(context.invocation_metadata() or [])  # type: ignore[attr-defined]
    except Exception:
        return []
    out: List[Tuple[str, str]] = []
    for k, v in items:
        ks = _safe_text(k, max_len=128).lower()
        vs = _safe_text(v, max_len=4096)
        if not ks:
            continue
        out.append((ks, vs))
    return out


def _metadata_dict(context: Any) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in _metadata_pairs(context):
        out[k] = v
    return out


def _metadata_size_bytes(md: Mapping[str, str]) -> int:
    total = 0
    for k, v in md.items():
        total += len(str(k).encode("utf-8", errors="ignore"))
        total += len(str(v).encode("utf-8", errors="ignore"))
    return total


def _peer_ip(context: Any) -> str:
    try:
        peer = str(context.peer())  # type: ignore[attr-defined]
    except Exception:
        peer = ""
    if not peer:
        return "unknown"
    if peer.startswith("ipv4:"):
        rest = peer[5:]
        return rest.rsplit(":", 1)[0] or "unknown"
    if peer.startswith("ipv6:"):
        rest = peer[5:]
        if rest.startswith("["):
            end = rest.find("]")
            if end > 1:
                return rest[1:end]
        return rest.rsplit(":", 1)[0] or "unknown"
    if peer.startswith("unix:"):
        return "unix"
    return peer[:128]


def _has_time_remaining(context: Any, min_remaining_s: float = 0.001) -> bool:
    try:
        rem = context.time_remaining()
        return (rem is None) or (float(rem) > min_remaining_s)
    except Exception:
        return True


def _time_remaining_s(context: Any) -> Optional[float]:
    try:
        rem = context.time_remaining()
        if rem is None:
            return None
        remf = float(rem)
        return remf if math.isfinite(remf) and remf >= 0.0 else None
    except Exception:
        return None


def _client_active(context: Any) -> bool:
    try:
        return bool(context.is_active())  # type: ignore[attr-defined]
    except Exception:
        return True


def _set_trailing_metadata(
    context: Any,
    *,
    request_id: Optional[str],
    event_id: Optional[str],
    api_version: Optional[str],
    schema_version: Optional[str],
) -> None:
    pairs: List[Tuple[str, str]] = []
    if request_id:
        pairs.append(("x-tcd-request-id", request_id))
    if event_id:
        pairs.append(("x-tcd-event-id", event_id))
    if api_version:
        pairs.append(("x-tcd-api-version", api_version))
    if schema_version:
        pairs.append(("x-tcd-schema-version", schema_version))
    if not pairs:
        return
    with contextlib.suppress(Exception):
        context.set_trailing_metadata(tuple(pairs))


def _set_grpc_error(
    context: Any,
    code: Any,
    msg: str,
    *,
    request_id: Optional[str] = None,
    event_id: Optional[str] = None,
    api_version: Optional[str] = None,
    schema_version: Optional[str] = None,
) -> None:
    if not _HAS_GRPC:
        return
    with contextlib.suppress(Exception):
        context.set_code(code)
        context.set_details(msg)
    _set_trailing_metadata(
        context,
        request_id=request_id,
        event_id=event_id,
        api_version=api_version,
        schema_version=schema_version,
    )


def _bounded_json_dumps(obj: Any, *, max_bytes: int) -> str:
    txt = _canonical_json(obj or {})
    if len(txt.encode("utf-8", errors="strict")) <= max_bytes:
        return txt
    return "{}"


def _safe_json_value(
    v: Any,
    *,
    max_depth: int,
    max_items: int,
    max_str_len: int,
    total_budget: List[int],
) -> Any:
    if total_budget[0] <= 0:
        return "[truncated]"
    if max_depth <= 0:
        return "[truncated]"
    if v is None or isinstance(v, (bool, int, float)):
        return v
    if isinstance(v, (bytes, bytearray, memoryview)):
        return "[bytes]"
    if isinstance(v, str):
        s = _redact_if_needed(_safe_text(v, max_len=max_str_len))
        total_budget[0] -= len(s.encode("utf-8", errors="ignore"))
        return s
    if isinstance(v, Mapping):
        out: Dict[str, Any] = {}
        for i, (k, vv) in enumerate(list(v.items())[: max_items]):
            if total_budget[0] <= 0:
                break
            out[_redact_if_needed(_safe_text(k, max_len=64))] = _safe_json_value(
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
        out: List[Any] = []
        for vv in list(v)[: max_items]:
            if total_budget[0] <= 0:
                break
            out.append(
                _safe_json_value(
                    vv,
                    max_depth=max_depth - 1,
                    max_items=max_items,
                    max_str_len=max_str_len,
                    total_budget=total_budget,
                )
            )
        if len(v) > max_items:
            out.append("[truncated]")
        return out
    s2 = _redact_if_needed(_safe_text(v, max_len=max_str_len))
    total_budget[0] -= len(s2.encode("utf-8", errors="ignore"))
    return s2


def _sanitize_components(components: Any, *, max_depth: int, max_items: int, max_str_len: int, max_total_bytes: int) -> Dict[str, Any]:
    if not isinstance(components, Mapping):
        return {}
    budget = [max(256, int(max_total_bytes))]
    out = _safe_json_value(dict(components), max_depth=max_depth, max_items=max_items, max_str_len=max_str_len, total_budget=budget)
    return out if isinstance(out, dict) else {}


def _normalize_out(raw: Dict[str, Any]) -> Dict[str, Any]:
    if DiagnoseOut is None:
        return raw
    try:
        if hasattr(DiagnoseOut, "model_validate"):
            out = DiagnoseOut.model_validate(raw)  # type: ignore[attr-defined]
            return out.model_dump(exclude_none=True)  # type: ignore[attr-defined]
        out = DiagnoseOut(**raw)  # type: ignore
        return out.dict(exclude_none=True)  # type: ignore[attr-defined]
    except Exception:
        return raw


# ---------------------------------------------------------------------------
# Protocol / identity policy
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GrpcProtocolCompatPolicy:
    api_version: str = "grpc.v1"
    schema_version: str = "1"
    compatibility_epoch: str = "2026-04"
    require_api_version: bool = False
    require_compatibility_epoch: bool = False
    require_client_capabilities: bool = False
    required_capabilities_diagnose: Tuple[str, ...] = ()
    required_capabilities_verify: Tuple[str, ...] = ()

    def normalized(self) -> "GrpcProtocolCompatPolicy":
        return GrpcProtocolCompatPolicy(
            api_version=_safe_text(self.api_version, max_len=32) or "grpc.v1",
            schema_version=_safe_text(self.schema_version, max_len=16) or "1",
            compatibility_epoch=_safe_text(self.compatibility_epoch, max_len=32) or "2026-04",
            require_api_version=bool(self.require_api_version),
            require_compatibility_epoch=bool(self.require_compatibility_epoch),
            require_client_capabilities=bool(self.require_client_capabilities),
            required_capabilities_diagnose=tuple(sorted({_safe_text(x, max_len=64).lower() for x in self.required_capabilities_diagnose if _safe_text(x, max_len=64)})),
            required_capabilities_verify=tuple(sorted({_safe_text(x, max_len=64).lower() for x in self.required_capabilities_verify if _safe_text(x, max_len=64)})),
        )


@dataclass(frozen=True)
class MethodAuthzPolicy:
    require_auth: bool = False
    allowed_auth_modes: Tuple[str, ...] = ()
    required_scopes: Tuple[str, ...] = ()
    required_roles: Tuple[str, ...] = ()
    require_mtls: bool = False
    require_trusted_identity: bool = False

    def normalized(self) -> "MethodAuthzPolicy":
        return MethodAuthzPolicy(
            require_auth=bool(self.require_auth),
            allowed_auth_modes=tuple(sorted({_normalize_auth_mode(x) for x in self.allowed_auth_modes if _normalize_auth_mode(x) != "none"})),
            required_scopes=tuple(sorted({_safe_text(x, max_len=64) for x in self.required_scopes if _safe_text(x, max_len=64)})),
            required_roles=tuple(sorted({_safe_text(x, max_len=64) for x in self.required_roles if _safe_text(x, max_len=64)})),
            require_mtls=bool(self.require_mtls),
            require_trusted_identity=bool(self.require_trusted_identity),
        )


@dataclass(frozen=True)
class SubjectIdentityPolicy:
    allow_pseudonymized_subject: bool = True
    on_missing: str = "pseudonymize"   # reject | pseudonymize
    on_invalid: str = "pseudonymize"   # reject | pseudonymize
    max_part_bytes: int = 128

    def normalized(self) -> "SubjectIdentityPolicy":
        on_missing = _safe_text(self.on_missing, max_len=32).lower() or "pseudonymize"
        on_invalid = _safe_text(self.on_invalid, max_len=32).lower() or "pseudonymize"
        if on_missing not in {"reject", "pseudonymize"}:
            on_missing = "pseudonymize"
        if on_invalid not in {"reject", "pseudonymize"}:
            on_invalid = "pseudonymize"
        return SubjectIdentityPolicy(
            allow_pseudonymized_subject=bool(self.allow_pseudonymized_subject),
            on_missing=on_missing,
            on_invalid=on_invalid,
            max_part_bytes=max(32, min(1024, int(self.max_part_bytes))),
        )


@dataclass(frozen=True)
class GrpcServiceDOD:
    schema: str
    light_rpc_p95_ms: int
    light_rpc_p99_ms: int
    heavy_rpc_p95_ms: int
    heavy_rpc_p99_ms: int
    max_proto_bytes: int
    max_metadata_bytes: int
    max_verify_total_bytes: int
    consistency_level: str
    evidence_delivery: str
    verify_isolation: str


@dataclass(frozen=True)
class GrpcPeerIdentity:
    peer_ip: str
    peer_raw: str
    transport_security_type: Optional[str]
    security_level: Optional[str]
    common_name: Optional[str]
    sans: Tuple[str, ...]
    spiffe_ids: Tuple[str, ...]
    mtls_present: bool
    peer_hash: str


@dataclass(frozen=True)
class ProtocolCompatResult:
    ok: bool
    api_version: Optional[str]
    client_version: Optional[str]
    compatibility_epoch: Optional[str]
    client_capabilities: Tuple[str, ...]
    warnings: Tuple[str, ...]
    reason: Optional[str]


@dataclass(frozen=True)
class SubjectIdentityParseResult:
    ok: bool
    status: str
    subject: Tuple[str, str, str]
    asserted: Dict[str, Optional[str]]
    trusted: Dict[str, Optional[str]]
    warnings: Tuple[str, ...]
    subject_hash: Optional[str]


def _extract_peer_identity(context: Any) -> GrpcPeerIdentity:
    peer_raw = ""
    with contextlib.suppress(Exception):
        peer_raw = str(context.peer())
    peer_ip = _peer_ip(context)
    auth_ctx = {}
    with contextlib.suppress(Exception):
        auth_ctx = dict(context.auth_context())  # type: ignore[attr-defined]

    def _vals(key: str) -> List[str]:
        vals = auth_ctx.get(key) or auth_ctx.get(key.encode()) or []
        out: List[str] = []
        for v in vals:
            if isinstance(v, bytes):
                out.append(v.decode("utf-8", errors="ignore"))
            else:
                out.append(str(v))
        return out

    transport_security_type = _safe_text((_vals("transport_security_type") or [None])[0], max_len=64) or None
    security_level = _safe_text((_vals("security_level") or [None])[0], max_len=64) or None
    sans = tuple(sorted({_safe_text(v, max_len=256) for v in _vals("x509_subject_alternative_name") if _safe_text(v, max_len=256)}))
    common_name = _safe_text((_vals("x509_common_name") or [None])[0], max_len=256) or None
    spiffe = tuple(sorted({s for s in sans if s.startswith("spiffe://")}))
    mtls_present = bool(sans or common_name or (transport_security_type and transport_security_type.lower() in {"ssl", "tls"}))
    peer_hash = _hash_token(f"{peer_ip}|{transport_security_type}|{common_name}", ctx="tcd:grpc:peer", n=16)
    return GrpcPeerIdentity(
        peer_ip=peer_ip,
        peer_raw=_safe_text(peer_raw, max_len=256),
        transport_security_type=transport_security_type,
        security_level=security_level,
        common_name=common_name,
        sans=sans,
        spiffe_ids=spiffe,
        mtls_present=mtls_present,
        peer_hash=peer_hash,
    )


def _resolve_protocol_compat(method: str, req: Any, md: Mapping[str, str], policy: GrpcProtocolCompatPolicy) -> ProtocolCompatResult:
    api_version = md.get("x-tcd-api-version") or getattr(req, "api_version", None)
    client_version = md.get("x-client-version") or getattr(req, "client_version", None)
    compat_epoch = md.get("x-tcd-compatibility-epoch") or getattr(req, "compatibility_epoch", None)
    caps_raw = md.get("x-client-capabilities") or getattr(req, "client_capabilities", None)

    if isinstance(caps_raw, str):
        caps = tuple(sorted({c.strip().lower() for c in caps_raw.split(",") if c.strip()}))
    elif isinstance(caps_raw, (list, tuple)):
        caps = tuple(sorted({_safe_text(c, max_len=64).lower() for c in caps_raw if _safe_text(c, max_len=64)}))
    else:
        caps = tuple()

    warnings: List[str] = []

    if policy.require_api_version and not api_version:
        return ProtocolCompatResult(False, None, _safe_text(client_version, max_len=64) or None, _safe_text(compat_epoch, max_len=64) or None, caps, tuple(warnings), "missing_api_version")
    if api_version and str(api_version) != str(policy.api_version):
        return ProtocolCompatResult(False, str(api_version), _safe_text(client_version, max_len=64) or None, _safe_text(compat_epoch, max_len=64) or None, caps, tuple(warnings), "api_version_mismatch")

    if policy.require_compatibility_epoch and not compat_epoch:
        return ProtocolCompatResult(False, _safe_text(api_version, max_len=64) or None, _safe_text(client_version, max_len=64) or None, None, caps, tuple(warnings), "missing_compatibility_epoch")
    if compat_epoch and str(compat_epoch) != str(policy.compatibility_epoch):
        return ProtocolCompatResult(False, _safe_text(api_version, max_len=64) or None, _safe_text(client_version, max_len=64) or None, str(compat_epoch), caps, tuple(warnings), "compatibility_epoch_mismatch")

    required = policy.required_capabilities_diagnose if method == "Diagnose" else policy.required_capabilities_verify
    if policy.require_client_capabilities and not caps:
        return ProtocolCompatResult(False, _safe_text(api_version, max_len=64) or None, _safe_text(client_version, max_len=64) or None, _safe_text(compat_epoch, max_len=64) or None, caps, tuple(warnings), "missing_client_capabilities")
    if required:
        capset = set(caps)
        missing = [c for c in required if c.lower() not in capset]
        if missing:
            return ProtocolCompatResult(False, _safe_text(api_version, max_len=64) or None, _safe_text(client_version, max_len=64) or None, _safe_text(compat_epoch, max_len=64) or None, caps, tuple(warnings), "missing_required_capability")

    return ProtocolCompatResult(True, _safe_text(api_version, max_len=64) or None, _safe_text(client_version, max_len=64) or None, _safe_text(compat_epoch, max_len=64) or None, caps, tuple(warnings), None)


def _subject_part(v: Optional[str], *, policy: SubjectIdentityPolicy) -> Tuple[Optional[str], Optional[str]]:
    if v is None:
        return None, "missing"
    s = _safe_text(v, max_len=policy.max_part_bytes)
    if not s:
        return None, "missing"
    if len(s.encode("utf-8", errors="ignore")) > policy.max_part_bytes:
        return None, "too_long"
    if "@" in s or " " in s or not _SAFE_TAG_RE.fullmatch(s):
        return None, "invalid"
    return s, None


def _pseudonymize_subject(*, request_id: str, body_digest: str, peer: GrpcPeerIdentity, cfg_fp: str) -> Tuple[str, str, str]:
    base = _blake3_hex(
        _canonical_json_bytes({"rid": request_id, "body": body_digest, "peer": peer.peer_hash, "cfg_fp": cfg_fp}),
        ctx="tcd:grpc:subject",
    )[:18]
    return (f"tenant-h-{base[:12]}", f"user-h-{base[2:14]}", f"sess-h-{base[6:18]}")


def _parse_subject_identity(
    context: Any,
    req: Any,
    *,
    policy: SubjectIdentityPolicy,
    request_id: str,
    body_digest: str,
    peer: GrpcPeerIdentity,
    cfg_fp: str,
) -> SubjectIdentityParseResult:
    md = _metadata_dict(context)
    asserted = {
        "tenant": md.get("x-tenant") or getattr(req, "tenant", None),
        "user": md.get("x-user") or getattr(req, "user", None),
        "session": md.get("x-session") or getattr(req, "session", None),
    }
    trusted = dict(asserted)

    parts: Dict[str, Optional[str]] = {}
    issues: List[str] = []
    for name in ("tenant", "user", "session"):
        val, err = _subject_part(asserted.get(name), policy=policy)
        parts[name] = val
        if err:
            issues.append(f"{name}:{err}")

    if not issues and all(parts.get(p) for p in ("tenant", "user", "session")):
        sub = (parts["tenant"] or "", parts["user"] or "", parts["session"] or "")
        return SubjectIdentityParseResult(
            True,
            "ok",
            sub,
            asserted,
            trusted,
            tuple(),
            _hash_token("|".join(sub), ctx="tcd:grpc:subject", n=16),
        )

    mode = policy.on_invalid if any(":invalid" in i or ":too_long" in i for i in issues) else policy.on_missing
    if mode == "reject" or not policy.allow_pseudonymized_subject:
        return SubjectIdentityParseResult(False, "rejected", ("", "", ""), asserted, trusted, tuple(sorted(set(issues))), None)

    sub = _pseudonymize_subject(request_id=request_id, body_digest=body_digest, peer=peer, cfg_fp=cfg_fp)
    status = "degraded_invalid_subject" if any(":invalid" in i or ":too_long" in i for i in issues) else "pseudonymized"
    return SubjectIdentityParseResult(
        True,
        status,
        sub,
        asserted,
        trusted,
        tuple(sorted(set(issues))),
        _hash_token("|".join(sub), ctx="tcd:grpc:subject", n=16),
    )


# ---------------------------------------------------------------------------
# Executor / breaker / gates
# ---------------------------------------------------------------------------

class _AsyncLoopThread:
    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._thread: Optional[threading.Thread] = None
        self._ready = threading.Event()
        self._closed = False
        self._start()

    def _start(self) -> None:
        if self._thread is not None:
            return

        def _runner() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop
            self._ready.set()
            loop.run_forever()
            with contextlib.suppress(Exception):
                pending = asyncio.all_tasks(loop)
                for t in pending:
                    t.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            with contextlib.suppress(Exception):
                loop.close()

        self._thread = threading.Thread(target=_runner, name="tcd-grpc-async", daemon=True)
        self._thread.start()
        self._ready.wait(timeout=5.0)

    def run(self, awaitable: Any, *, timeout_s: float) -> Any:
        if self._loop is None:
            raise RuntimeError("async runner unavailable")
        fut = asyncio.run_coroutine_threadsafe(awaitable, self._loop)
        return fut.result(timeout=max(0.001, float(timeout_s)))

    def stop(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._loop is not None:
            with contextlib.suppress(Exception):
                self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            with contextlib.suppress(Exception):
                self._thread.join(timeout=2.0)


class _RejectedExecution(RuntimeError):
    pass


@dataclass
class _TaskMeta:
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


class _CallTimeout(RuntimeError):
    def __init__(self, msg: str, *, started: bool, cancelled: bool) -> None:
        super().__init__(msg)
        self.started = bool(started)
        self.cancelled = bool(cancelled)


class _BoundedExecutor:
    def __init__(self, *, pool: str, max_workers: int, max_queue: int) -> None:
        self.pool = str(pool)
        self.max_workers = max(1, int(max_workers))
        self.max_queue = max(0, int(max_queue))
        self.capacity = self.max_workers + self.max_queue
        self._sem = threading.BoundedSemaphore(self.capacity)
        self._reserved = 0
        self._reserved_lock = threading.Lock()
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix=f"tcd-grpc-{self.pool}")
        _GRPC_EXEC_RESERVED.labels(self.pool).set(0.0)

    def _inc_reserved(self) -> None:
        with self._reserved_lock:
            self._reserved += 1
            _GRPC_EXEC_RESERVED.labels(self.pool).set(float(self._reserved))

    def _dec_reserved(self) -> None:
        with self._reserved_lock:
            self._reserved = max(0, self._reserved - 1)
            _GRPC_EXEC_RESERVED.labels(self.pool).set(float(self._reserved))

    def submit(self, fn: Callable[[], Any]) -> Tuple[concurrent.futures.Future, _TaskMeta]:
        if not self._sem.acquire(blocking=False):
            _GRPC_EXEC_REJECT.labels(self.pool).inc()
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
            with contextlib.suppress(Exception):
                self._sem.release()
            self._dec_reserved()

        fut.add_done_callback(_release)
        return fut, meta

    def run_blocking(self, fn: Callable[[], Any], *, timeout_s: float) -> Any:
        fut, meta = self.submit(fn)
        try:
            return fut.result(timeout=max(0.001, float(timeout_s)))
        except concurrent.futures.TimeoutError as exc:
            started = meta.started_evt.is_set()
            cancelled = False
            if not started:
                with contextlib.suppress(Exception):
                    cancelled = fut.cancel()
            raise _CallTimeout("call timed out", started=started, cancelled=cancelled) from exc

    def shutdown(self) -> None:
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except TypeError:
            self._executor.shutdown(wait=False)
        except Exception:
            pass


class _BreakerState:
    CLOSED = 0
    OPEN = 1
    HALF_OPEN = 2


class _CircuitBreaker:
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
        self.dep = dep
        self.threshold = max(1, int(threshold))
        self.window_s = max(0.5, float(window_s))
        self.open_seconds = max(0.1, float(open_seconds))
        self.probe_jitter_s = max(0.0, float(probe_jitter_s))
        self.probe_probability = min(1.0, max(0.01, float(probe_probability)))
        self._state = _BreakerState.CLOSED
        self._fail_times: deque[float] = deque()
        self._opened_until = 0.0
        self._probe_inflight = False
        self._next_probe_at = 0.0
        self._lock = threading.Lock()
        _GRPC_BREAKER_STATE.labels(self.dep).set(float(self._state))

    def snapshot(self) -> Dict[str, Any]:
        now = time.monotonic()
        with self._lock:
            st = self._state
            open_rem = max(0.0, self._opened_until - now) if st == _BreakerState.OPEN else 0.0
            probe_rem = max(0.0, self._next_probe_at - now) if st == _BreakerState.HALF_OPEN else 0.0
        return {
            "state": {0: "CLOSED", 1: "OPEN", 2: "HALF_OPEN"}.get(st, "UNKNOWN"),
            "open_remaining_s": round(open_rem, 3),
            "probe_delay_s": round(probe_rem, 3),
        }

    def before_call(self) -> Tuple[bool, bool]:
        now = time.monotonic()
        with self._lock:
            if self._state == _BreakerState.OPEN:
                if now < self._opened_until:
                    return False, False
                self._state = _BreakerState.HALF_OPEN
                _GRPC_BREAKER_STATE.labels(self.dep).set(float(self._state))
                self._probe_inflight = False
                self._next_probe_at = now + (random.random() * self.probe_jitter_s)
            if self._state == _BreakerState.HALF_OPEN:
                if now < self._next_probe_at:
                    return False, False
                if self._probe_inflight:
                    return False, False
                if random.random() > self.probe_probability:
                    return False, False
                self._probe_inflight = True
                return True, True
            return True, False

    def record_success(self, *, was_probe: bool) -> None:
        now = time.monotonic()
        with self._lock:
            if was_probe and self._state == _BreakerState.HALF_OPEN:
                _GRPC_BREAKER_PROBE_TOTAL.labels(self.dep, "yes").inc()
                self._fail_times.clear()
                self._probe_inflight = False
                self._opened_until = 0.0
                self._next_probe_at = 0.0
                self._state = _BreakerState.CLOSED
                _GRPC_BREAKER_STATE.labels(self.dep).set(float(self._state))
                return
            while self._fail_times and (now - self._fail_times[0]) > self.window_s:
                self._fail_times.popleft()

    def record_failure(self, *, was_probe: bool) -> None:
        now = time.monotonic()
        with self._lock:
            if was_probe and self._state == _BreakerState.HALF_OPEN:
                _GRPC_BREAKER_PROBE_TOTAL.labels(self.dep, "no").inc()
                self._probe_inflight = False
                self._opened_until = now + self.open_seconds
                self._state = _BreakerState.OPEN
                _GRPC_BREAKER_STATE.labels(self.dep).set(float(self._state))
                self._fail_times.clear()
                self._fail_times.append(now)
                return
            self._fail_times.append(now)
            while self._fail_times and (now - self._fail_times[0]) > self.window_s:
                self._fail_times.popleft()
            if len(self._fail_times) >= self.threshold:
                self._opened_until = now + self.open_seconds
                self._state = _BreakerState.OPEN
                _GRPC_BREAKER_STATE.labels(self.dep).set(float(self._state))


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 2
    base_backoff_ms: int = 40
    max_backoff_ms: int = 250
    jitter: float = 0.2


def _sleep_backoff(attempt: int, *, policy: RetryPolicy) -> None:
    base = max(1, int(policy.base_backoff_ms))
    cap = max(base, int(policy.max_backoff_ms))
    ms = min(cap, base * (2 ** max(0, attempt - 1)))
    if policy.jitter > 0:
        ms = int(ms * (1.0 + random.uniform(-policy.jitter, policy.jitter)))
        ms = max(0, ms)
    time.sleep(ms / 1000.0)


class _DepException(RuntimeError):
    def __init__(self, dep: str, op: str, *, kind: str, phase: str) -> None:
        super().__init__(f"{dep}.{op}: {kind} ({phase})")
        self.dep = dep
        self.op = op
        self.kind = kind
        self.phase = phase


def _remaining_ms(deadline_mono: Optional[float]) -> Optional[int]:
    if deadline_mono is None:
        return None
    rem = deadline_mono - time.perf_counter()
    if rem <= 0:
        return 0
    return int(rem * 1000.0)


def _dep_call(
    *,
    dep: str,
    op: str,
    breaker: _CircuitBreaker,
    executor: _BoundedExecutor,
    timeout_ms: int,
    deadline_mono: Optional[float],
    fn: Callable[[], Any],
) -> Any:
    rem_ms = _remaining_ms(deadline_mono)
    if rem_ms is not None and rem_ms <= 0:
        _GRPC_DEP_ERROR.labels(dep, op, "deadline").inc()
        raise _DepException(dep, op, kind="deadline", phase="deadline")

    eff_timeout_ms = int(timeout_ms)
    if rem_ms is not None:
        eff_timeout_ms = max(1, min(eff_timeout_ms, rem_ms))

    allow, probe = breaker.before_call()
    if not allow:
        _GRPC_DEP_ERROR.labels(dep, op, "breaker_open").inc()
        raise _DepException(dep, op, kind="breaker_open", phase="breaker")

    t0 = time.perf_counter()
    try:
        out = executor.run_blocking(fn, timeout_s=float(eff_timeout_ms) / 1000.0)
        _GRPC_DEP_LATENCY.labels(dep, op, "ok").observe((time.perf_counter() - t0) * 1000.0)
        breaker.record_success(was_probe=probe)
        return out
    except _RejectedExecution:
        _GRPC_DEP_LATENCY.labels(dep, op, "queue_full").observe((time.perf_counter() - t0) * 1000.0)
        _GRPC_DEP_ERROR.labels(dep, op, "queue_full").inc()
        raise _DepException(dep, op, kind="queue_full", phase="queue")
    except _CallTimeout as exc:
        _GRPC_DEP_LATENCY.labels(dep, op, "timeout").observe((time.perf_counter() - t0) * 1000.0)
        _GRPC_DEP_ERROR.labels(dep, op, "timeout_run" if exc.started else "timeout_queue").inc()
        if exc.started:
            breaker.record_failure(was_probe=probe)
        raise _DepException(dep, op, kind="timeout", phase="run" if exc.started else "queue")
    except Exception:
        _GRPC_DEP_LATENCY.labels(dep, op, "error").observe((time.perf_counter() - t0) * 1000.0)
        _GRPC_DEP_ERROR.labels(dep, op, "error").inc()
        breaker.record_failure(was_probe=probe)
        raise _DepException(dep, op, kind="error", phase="run")


def _dep_call_with_retry(
    *,
    dep: str,
    op: str,
    breaker: _CircuitBreaker,
    executor: _BoundedExecutor,
    timeout_ms: int,
    deadline_mono: Optional[float],
    policy: RetryPolicy,
    fn: Callable[[], Any],
    idempotent: bool,
) -> Any:
    attempts = 0
    max_retry = max(0, int(policy.max_attempts) - 1) if idempotent else 0
    while True:
        try:
            return _dep_call(
                dep=dep,
                op=op,
                breaker=breaker,
                executor=executor,
                timeout_ms=timeout_ms,
                deadline_mono=deadline_mono,
                fn=fn,
            )
        except _DepException:
            attempts += 1
            if attempts > max_retry:
                raise
            rem = _remaining_ms(deadline_mono)
            if rem is not None and rem <= int(policy.base_backoff_ms) + 5:
                raise
            _sleep_backoff(attempts, policy=policy)


class _InFlightGate:
    def __init__(self, method: str, limit: int) -> None:
        self.method = method
        self.limit = max(1, int(limit))
        self._sema = threading.BoundedSemaphore(self.limit)
        self._lock = threading.Lock()
        self._inflight = 0
        _GRPC_INFLIGHT.labels(self.method).set(0.0)

    def acquire(self, wait_ms: int) -> bool:
        if wait_ms > 0:
            ok = self._sema.acquire(timeout=max(0.0, float(wait_ms) / 1000.0))
        else:
            ok = self._sema.acquire(blocking=False)
        if ok:
            with self._lock:
                self._inflight += 1
                _GRPC_INFLIGHT.labels(self.method).set(float(self._inflight))
        return ok

    def release(self) -> None:
        try:
            with self._lock:
                self._inflight = max(0, self._inflight - 1)
                _GRPC_INFLIGHT.labels(self.method).set(float(self._inflight))
        finally:
            with contextlib.suppress(Exception):
                self._sema.release()


# ---------------------------------------------------------------------------
# Outbox / registry
# ---------------------------------------------------------------------------

class _SQLiteOutbox:
    def __init__(self, path: str, *, max_rows: int, max_db_bytes: int, max_payload_bytes: int, drop_policy: str) -> None:
        self.path = str(path)
        self.max_rows = max(1, int(max_rows))
        self.max_db_bytes = max(1, int(max_db_bytes))
        self.max_payload_bytes = max(1024, int(max_payload_bytes))
        self.drop_policy = str(drop_policy or "drop_oldest").lower()
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._init_db()
        with contextlib.suppress(Exception):
            os.chmod(self.path, 0o600)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=2.0, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA synchronous=NORMAL;")
        c.execute("PRAGMA temp_store=MEMORY;")
        return c

    def _init_db(self) -> None:
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
                        conflict_count INTEGER NOT NULL DEFAULT 0,
                        attempts INTEGER NOT NULL DEFAULT 0,
                        next_ts REAL NOT NULL,
                        created_ts REAL NOT NULL,
                        updated_ts REAL NOT NULL,
                        last_error TEXT NOT NULL DEFAULT ''
                    )
                    """
                )
                c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_tcd_grpc_outbox_dedupe ON outbox(kind,dedupe_key)")
                c.execute("CREATE INDEX IF NOT EXISTS idx_tcd_grpc_outbox_next ON outbox(kind,next_ts,created_ts)")
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

    def enforce_capacity(self, *, kind: str) -> bool:
        with self._lock:
            rows = self._row_count(kind)
            fbytes = self._file_bytes()
            if rows <= self.max_rows and fbytes <= self.max_db_bytes:
                return True
            if self.drop_policy in {"drop_newest", "reject_request"}:
                return False
            target_rows = int(self.max_rows * 0.9)
            target_bytes = int(self.max_db_bytes * 0.9)
            c = self._conn()
            try:
                if rows > target_rows:
                    to_drop = rows - target_rows
                    c.execute(
                        """
                        DELETE FROM outbox
                        WHERE id IN (SELECT id FROM outbox WHERE kind=? ORDER BY created_ts ASC LIMIT ?)
                        """,
                        (str(kind), int(to_drop)),
                    )
                    _GRPC_OUTBOX_CONFLICT.labels(kind).inc(float(max(0, to_drop)))
                for _ in range(8):
                    if self._file_bytes() <= target_bytes:
                        break
                    c.execute(
                        """
                        DELETE FROM outbox
                        WHERE id IN (SELECT id FROM outbox WHERE kind=? ORDER BY created_ts ASC LIMIT 200)
                        """,
                        (str(kind),),
                    )
                return self._row_count(kind) <= self.max_rows and self._file_bytes() <= self.max_db_bytes
            finally:
                c.close()

    def put(self, *, kind: str, dedupe_key: str, payload_json: str, payload_digest: str) -> str:
        if len(payload_json.encode("utf-8", errors="strict")) > self.max_payload_bytes:
            return "rejected"
        now = time.time()
        with self._lock:
            if not self.enforce_capacity(kind=kind):
                return "rejected"
            c = self._conn()
            try:
                c.execute(
                    """
                    INSERT OR IGNORE INTO outbox(kind,dedupe_key,payload_json,payload_digest,conflict_count,attempts,next_ts,created_ts,updated_ts,last_error)
                    VALUES(?,?,?,?,0,0,?,?,?, '')
                    """,
                    (str(kind), str(dedupe_key), payload_json, payload_digest, now, now, now),
                )
                cur = c.execute("SELECT payload_digest, conflict_count FROM outbox WHERE kind=? AND dedupe_key=?", (str(kind), str(dedupe_key)))
                row = cur.fetchone()
                if row is None:
                    return "rejected"
                old_digest = str(row[0])
                conflicts = int(row[1] or 0)
                if old_digest == payload_digest:
                    return "ignored"
                c.execute(
                    """
                    UPDATE outbox
                    SET payload_json=?, payload_digest=?, conflict_count=?, updated_ts=?, attempts=0, next_ts=?
                    WHERE kind=? AND dedupe_key=?
                    """,
                    (payload_json, payload_digest, conflicts + 1, now, now, str(kind), str(dedupe_key)),
                )
                _GRPC_OUTBOX_CONFLICT.labels(kind).inc()
                return "updated"
            finally:
                c.close()

    def stats(self, *, kind: str, now_ts: float) -> Dict[str, Any]:
        c = self._conn()
        try:
            cur = c.execute("SELECT COUNT(*), MIN(created_ts) FROM outbox WHERE kind=?", (str(kind),))
            row = cur.fetchone()
        finally:
            c.close()
        total = int(row[0] if row and row[0] is not None else 0)
        oldest_ts = float(row[1] if row and row[1] is not None else 0.0)
        oldest_age = max(0.0, float(now_ts) - oldest_ts) if oldest_ts > 0 else 0.0
        _GRPC_OUTBOX_DEPTH.labels(kind).set(float(total))
        _GRPC_OUTBOX_OLDEST_AGE_S.labels(kind).set(float(oldest_age))
        return {"total": total, "oldest_age_s": oldest_age}


class _SQLiteControlRegistry:
    def __init__(self, path: str, *, replay_ttl_s: int) -> None:
        self.path = str(path)
        self.replay_ttl_s = max(1, int(replay_ttl_s))
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._init_db()
        with contextlib.suppress(Exception):
            os.chmod(self.path, 0o600)

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=2.0, isolation_level=None)
        c.execute("PRAGMA journal_mode=WAL;")
        c.execute("PRAGMA synchronous=NORMAL;")
        return c

    def _init_db(self) -> None:
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    """
                    CREATE TABLE IF NOT EXISTS event_registry(
                        scope TEXT NOT NULL,
                        event_id TEXT NOT NULL,
                        event_digest TEXT NOT NULL,
                        method TEXT NOT NULL,
                        tenant_hash TEXT,
                        principal_hash TEXT,
                        request_id TEXT,
                        created_ts REAL NOT NULL,
                        PRIMARY KEY(scope,event_id)
                    )
                    """
                )
                c.execute(
                    """
                    CREATE TABLE IF NOT EXISTS replay_registry(
                        scope TEXT NOT NULL,
                        token TEXT NOT NULL,
                        expires_ts REAL NOT NULL,
                        created_ts REAL NOT NULL,
                        PRIMARY KEY(scope,token)
                    )
                    """
                )
                c.execute("CREATE INDEX IF NOT EXISTS idx_tcd_grpc_replay_exp ON replay_registry(expires_ts)")
            finally:
                c.close()

    def register_event(
        self,
        *,
        scope: str,
        event_id: str,
        event_digest: str,
        method: str,
        tenant_hash: Optional[str],
        principal_hash: Optional[str],
        request_id: Optional[str],
    ) -> Tuple[bool, str]:
        now = time.time()
        with self._lock:
            c = self._conn()
            try:
                c.execute(
                    """
                    INSERT OR IGNORE INTO event_registry(scope,event_id,event_digest,method,tenant_hash,principal_hash,request_id,created_ts)
                    VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (str(scope), str(event_id), str(event_digest), str(method), tenant_hash, principal_hash, request_id, now),
                )
                cur = c.execute("SELECT event_digest FROM event_registry WHERE scope=? AND event_id=?", (str(scope), str(event_id)))
                row = cur.fetchone()
                if row is None:
                    return False, "registry_error"
                old = str(row[0])
                if old == str(event_digest):
                    return True, "ok"
                return False, "conflict"
            finally:
                c.close()

    def check_and_store_replay(self, *, scope: str, token: str) -> bool:
        now = time.time()
        exp = now + float(self.replay_ttl_s)
        with self._lock:
            c = self._conn()
            try:
                c.execute("DELETE FROM replay_registry WHERE expires_ts<=?", (now,))
                c.execute(
                    "INSERT OR IGNORE INTO replay_registry(scope,token,expires_ts,created_ts) VALUES(?,?,?,?)",
                    (str(scope), str(token), exp, now),
                )
                cur = c.execute("SELECT created_ts FROM replay_registry WHERE scope=? AND token=?", (str(scope), str(token)))
                row = cur.fetchone()
                if row is None:
                    return False
                return abs(float(row[0]) - now) < 0.001
            finally:
                c.close()

# ---------------------------------------------------------------------------
# Verify worker
# ---------------------------------------------------------------------------

def _verify_worker_entry(args_json_path: str, result_json_path: str) -> None:
    result: Dict[str, Any] = {"ok": False, "kind": ERR_VERIFY}
    try:
        with open(args_json_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        mode = payload.get("mode")
        if mode == "chain":
            heads = list(payload.get("heads") or [])
            bodies = list(payload.get("bodies") or [])
            ok = bool(verify_chain(heads, bodies))
            result = {"ok": ok, "kind": "ok" if ok else "verify_false"}
        elif mode == "receipt":
            ok = bool(
                verify_receipt(
                    receipt_head_hex=str(payload["receipt_head_hex"]),
                    receipt_body_json=str(payload["receipt_body_json"]),
                    verify_key_hex=(str(payload["verify_key_hex"]) if payload.get("verify_key_hex") else None),
                    receipt_sig_hex=(str(payload["receipt_sig_hex"]) if payload.get("receipt_sig_hex") else None),
                    req_obj=payload.get("req_obj"),
                    comp_obj=payload.get("comp_obj"),
                    e_obj=payload.get("e_obj"),
                    witness_segments=payload.get("witness_segments"),
                    strict=True,
                )
            )
            result = {"ok": ok, "kind": "ok" if ok else "verify_false"}
        else:
            result = {"ok": False, "kind": "bad_input"}
    except Exception as e:
        result = {"ok": False, "kind": "exception", "error": _safe_text(e, max_len=256)}
    try:
        with open(result_json_path, "w", encoding="utf-8") as f:
            json.dump(result, f, sort_keys=True, ensure_ascii=False)
    except Exception:
        pass


def _verify_via_process(payload: Mapping[str, Any], *, timeout_s: float, start_method: str = "spawn") -> Dict[str, Any]:
    tmpdir = tempfile.mkdtemp(prefix="tcd-grpc-verify-")
    args_path = os.path.join(tmpdir, "args.json")
    res_path = os.path.join(tmpdir, "res.json")
    try:
        with open(args_path, "w", encoding="utf-8") as f:
            json.dump(dict(payload), f, sort_keys=True, ensure_ascii=False)
        ctx = mp.get_context(start_method if start_method in {"spawn", "fork", "forkserver"} else "spawn")
        proc = ctx.Process(target=_verify_worker_entry, args=(args_path, res_path), daemon=True)
        proc.start()
        proc.join(timeout=max(0.001, float(timeout_s)))
        if proc.is_alive():
            with contextlib.suppress(Exception):
                proc.terminate()
            proc.join(timeout=1.0)
            if proc.is_alive():
                with contextlib.suppress(Exception):
                    proc.kill()  # type: ignore[attr-defined]
            return {"ok": False, "kind": "timeout"}
        if not os.path.exists(res_path):
            return {"ok": False, "kind": "missing_result"}
        with open(res_path, "r", encoding="utf-8") as f:
            out = json.load(f)
        return out if isinstance(out, dict) else {"ok": False, "kind": "bad_result"}
    finally:
        with contextlib.suppress(Exception):
            shutil.rmtree(tmpdir)

# ---------------------------------------------------------------------------
# gRPC auth adapter
# ---------------------------------------------------------------------------

class _GrpcReceiveOnce:
    def __init__(self, body: bytes) -> None:
        self._body = body
        self._sent = False

    async def __call__(self) -> Dict[str, Any]:
        if self._sent:
            return {"type": "http.request", "body": b"", "more_body": False}
        self._sent = True
        return {"type": "http.request", "body": self._body, "more_body": False}


def _build_request_like_for_auth(*, method_name: str, metadata: Mapping[str, str], peer_ip: str, body: bytes) -> Optional[Any]:
    if not _HAS_STARLETTE:
        return None
    headers: List[Tuple[bytes, bytes]] = []
    for k, v in metadata.items():
        try:
            kb = str(k).lower().encode("ascii", errors="ignore")
            vb = str(v).encode("utf-8", errors="ignore")
        except Exception:
            continue
        headers.append((kb, vb))
    path = f"/grpc/{_safe_text(method_name, max_len=128)}"
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": path,
        "raw_path": path.encode("utf-8", errors="strict"),
        "query_string": b"",
        "headers": headers,
        "client": (peer_ip or "127.0.0.1", 0),
        "server": ("grpc", 443),
    }
    req = StarletteRequest(scope, receive=_GrpcReceiveOnce(body))
    with contextlib.suppress(Exception):
        setattr(req, "_body", body)
    return req


@dataclass
class _AuthProjection:
    ok: bool
    mode: str
    principal: Optional[str]
    scopes: Tuple[str, ...]
    roles: Tuple[str, ...]
    key_id: Optional[str]
    policy_digest: Optional[str]
    authn_strength: Optional[str]
    trusted: bool
    reason: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_auth_result(res: Any) -> "_AuthProjection":
        if res is None:
            return _AuthProjection(False, "none", None, tuple(), tuple(), None, None, None, False, "missing")
        ok = bool(getattr(res, "ok", False))
        ctx = getattr(res, "ctx", None)
        if not ok or ctx is None:
            return _AuthProjection(False, "none", None, tuple(), tuple(), None, None, None, False, getattr(res, "reason", None) or "denied")
        mode = _normalize_auth_mode(getattr(ctx, "mode", None))
        principal = _safe_text(getattr(ctx, "principal", None), max_len=256) or None
        key_id = _safe_text(getattr(ctx, "key_id", None), max_len=128) or None
        policy_digest = _safe_text(getattr(ctx, "policy_digest", None) or getattr(ctx, "policy_digest_hex", None), max_len=128) or None
        authn_strength = _safe_text(getattr(ctx, "authn_strength", None), max_len=64) or None

        scopes_raw = getattr(ctx, "scopes", None)
        roles_raw = getattr(ctx, "roles", None)
        try:
            scopes = tuple(sorted({_safe_text(x, max_len=64) for x in list(scopes_raw or []) if _safe_text(x, max_len=64)}))
        except Exception:
            scopes = tuple()
        try:
            roles = tuple(sorted({_safe_text(x, max_len=64) for x in list(roles_raw or []) if _safe_text(x, max_len=64)}))
        except Exception:
            roles = tuple()

        raw = {}
        raw_ctx = getattr(ctx, "raw", None)
        if isinstance(raw_ctx, Mapping):
            raw = {str(k): raw_ctx[k] for k in raw_ctx.keys()}

        trusted = True
        if raw:
            trusted = _coerce_bool(raw.get("trusted"), default=True)
        return _AuthProjection(True, mode, principal, scopes, roles, key_id, policy_digest, authn_strength, trusted, None, raw)

    def to_public_dict(self, *, record_principal: bool, record_key_id: bool) -> Dict[str, Any]:
        out: Dict[str, Any] = {"mode": self.mode, "trusted": bool(self.trusted)}
        if self.principal:
            if record_principal:
                out["principal"] = self.principal
            out["principal_hash"] = _hash_token(self.principal, ctx="tcd:grpc:auth:principal", n=16)
        if self.scopes:
            out["scopes"] = list(self.scopes[:32])
        if self.roles:
            out["roles"] = list(self.roles[:32])
        if self.key_id:
            if record_key_id:
                out["key_id"] = self.key_id
            out["key_id_hash"] = _hash_token(self.key_id, ctx="tcd:grpc:auth:key", n=16)
        if self.policy_digest:
            out["policy_digest"] = self.policy_digest
        if self.authn_strength:
            out["authn_strength"] = self.authn_strength
        return out


class GrpcAuthAdapter:
    def __init__(self, *, runtime: "_Runtime") -> None:
        self._rt = runtime

    def authenticate(
        self,
        *,
        method_name: str,
        metadata: Mapping[str, str],
        peer: GrpcPeerIdentity,
        body_bytes: bytes,
        request_id: str,
        event_id: str,
        api_version: Optional[str],
        compatibility_epoch: Optional[str],
        deadline_mono: Optional[float],
    ) -> _AuthProjection:
        authn = self._rt.authenticator
        if authn is None:
            return _AuthProjection(False, "none", None, tuple(), tuple(), None, None, None, False, "missing")

        # Preferred native gRPC entrypoints
        for meth_name in ("authenticate_grpc", "verify_grpc"):
            meth = getattr(authn, meth_name, None)
            if not callable(meth):
                continue

            def _run_native() -> Any:
                return meth(
                    method_name=method_name,
                    metadata=dict(metadata),
                    peer={
                        "peer_ip": peer.peer_ip,
                        "peer_raw": peer.peer_raw,
                        "transport_security_type": peer.transport_security_type,
                        "security_level": peer.security_level,
                        "common_name": peer.common_name,
                        "sans": list(peer.sans),
                        "spiffe_ids": list(peer.spiffe_ids),
                        "mtls_present": peer.mtls_present,
                    },
                    body_bytes=body_bytes,
                    body_digest=_blake3_hex(body_bytes, ctx="tcd:grpc:auth:body"),
                    request_id=request_id,
                    event_id=event_id,
                    api_version=api_version,
                    compatibility_epoch=compatibility_epoch,
                )

            try:
                res = _dep_call_with_retry(
                    dep="auth",
                    op=meth_name,
                    breaker=self._rt.br_auth,
                    executor=self._rt.exec_auth,
                    timeout_ms=self._rt.cfg.auth_timeout_ms,
                    deadline_mono=deadline_mono,
                    policy=RetryPolicy(max_attempts=max(1, self._rt.cfg.dep_retry_max), base_backoff_ms=self._rt.cfg.dep_retry_base_ms),
                    fn=_run_native,
                    idempotent=True,
                )
                if inspect.isawaitable(res):
                    res = self._rt.async_runner.run(res, timeout_s=max(0.001, self._rt.cfg.auth_timeout_ms / 1000.0))
                return _AuthProjection.from_auth_result(res)
            except Exception as e:
                logger.warning("grpc native auth failed method=%s err=%s", meth_name, _safe_text(e, max_len=128), exc_info=self._rt.cfg.debug_errors)

        if self._rt.cfg.grpc_auth_fallback_mode != "compat":
            return _AuthProjection(False, "none", None, tuple(), tuple(), None, None, None, False, "adapter_missing")

        req = _build_request_like_for_auth(method_name=method_name, metadata=metadata, peer_ip=peer.peer_ip, body=body_bytes)
        if req is None:
            return _AuthProjection(False, "none", None, tuple(), tuple(), None, None, None, False, "request_adapter_missing")

        meth = getattr(authn, "authenticate", None)
        if not callable(meth):
            meth = getattr(authn, "verify", None)
        if not callable(meth):
            return _AuthProjection(False, "none", None, tuple(), tuple(), None, None, None, False, "adapter_missing")

        def _run_compat() -> Any:
            return meth(req)

        try:
            res = _dep_call_with_retry(
                dep="auth",
                op="compat",
                breaker=self._rt.br_auth,
                executor=self._rt.exec_auth,
                timeout_ms=self._rt.cfg.auth_timeout_ms,
                deadline_mono=deadline_mono,
                policy=RetryPolicy(max_attempts=max(1, self._rt.cfg.dep_retry_max), base_backoff_ms=self._rt.cfg.dep_retry_base_ms),
                fn=_run_compat,
                idempotent=True,
            )
            if inspect.isawaitable(res):
                res = self._rt.async_runner.run(res, timeout_s=max(0.001, self._rt.cfg.auth_timeout_ms / 1000.0))
            return _AuthProjection.from_auth_result(res)
        except Exception as e:
            return _AuthProjection(False, "none", None, tuple(), tuple(), None, None, None, False, _safe_text(e, max_len=64))


class _GrpcDetectorRuntime:
    def __init__(self) -> None:
        self._local = threading.local()

    @contextlib.contextmanager
    def bind(self, result: Mapping[str, Any]) -> Any:
        old = getattr(self._local, "current", None)
        self._local.current = dict(result)
        try:
            yield
        finally:
            self._local.current = old

    def evaluate(self, ctx: Any, policy: Any) -> Mapping[str, Any]:
        cur = getattr(self._local, "current", None)
        if isinstance(cur, Mapping):
            return dict(cur)
        return {}


class SecurityRouterAdapterV3:
    def __init__(self, router: Any) -> None:
        self._router = router

    def route(self, sctx: Any) -> Any:
        return self._router.route(sctx)

    @staticmethod
    def to_diagnose_dict(decision: Any) -> Dict[str, Any]:
        if decision is None:
            return {}
        if hasattr(decision, "to_diagnose_out"):
            with contextlib.suppress(Exception):
                out = decision.to_diagnose_out()
                if isinstance(out, Mapping):
                    return dict(out)
        return {}

# ---------------------------------------------------------------------------
# Runtime config
# ---------------------------------------------------------------------------

@dataclass
class GrpcServiceConfig:
    route_name: str = "grpc.diagnose"
    strict_mode: bool = False
    max_end_to_end_latency_s: float = 2.0

    protocol: GrpcProtocolCompatPolicy = field(default_factory=GrpcProtocolCompatPolicy)
    subject_policy: SubjectIdentityPolicy = field(default_factory=SubjectIdentityPolicy)
    diagnose_authz: MethodAuthzPolicy = field(default_factory=lambda: MethodAuthzPolicy(require_auth=True))
    verify_authz: MethodAuthzPolicy = field(default_factory=lambda: MethodAuthzPolicy(require_auth=False))

    metadata_allowlist: Tuple[str, ...] = tuple(sorted(_ALLOWED_AUTH_METADATA))
    max_metadata_items: int = 96
    max_metadata_bytes: int = 16 * 1024

    max_trace: int = _MAX_TRACE
    max_spectrum: int = _MAX_SPECT
    max_features: int = _MAX_FEATS
    max_proto_bytes: int = 2 * 1024 * 1024
    max_components_bytes: int = _JSON_COMPONENT_LIMIT

    max_verify_chain_items: int = 4096
    max_verify_body_bytes: int = 256 * 1024
    max_verify_total_bytes: int = 8 * 1024 * 1024
    verify_hard_timeout_mode: str = "thread"  # thread | process
    verify_process_start_method: str = "spawn"

    max_inflight_diagnose: int = 64
    max_inflight_verify: int = 16
    gate_wait_ms: int = 0

    exec_auth_workers: int = 8
    exec_auth_queue: int = 64
    exec_verify_workers: int = 4
    exec_verify_queue: int = 32
    exec_controller_workers: int = 8
    exec_controller_queue: int = 64
    exec_attest_workers: int = 4
    exec_attest_queue: int = 32
    exec_ledger_workers: int = 4
    exec_ledger_queue: int = 64

    auth_timeout_ms: int = 350
    controller_timeout_ms: int = 1200
    verify_timeout_ms: int = 5000
    attestor_timeout_ms: int = 1200
    ledger_timeout_ms: int = 600

    breaker_failures: int = 5
    breaker_window_s: float = 30.0
    breaker_open_seconds: float = 15.0
    breaker_probe_jitter_s: float = 2.0
    breaker_probe_probability: float = 0.25

    dep_retry_max: int = 1
    dep_retry_base_ms: int = 40

    grpc_auth_fallback_mode: str = "compat"
    allowed_auth_modes: Optional[List[str]] = None
    allowed_sig_algs: Optional[List[str]] = None
    require_pq_sig: bool = False

    use_security_router: bool = True
    require_security_router_when_strict: bool = False
    pq_required_zones: Tuple[str, ...] = ("admin", "partner")

    require_attestor: bool = False
    require_ledger: bool = False

    outbox_enabled: bool = True
    outbox_path: str = "tcd_service_grpc_outbox.sqlite3"
    outbox_per_process: bool = True
    outbox_max_payload_bytes: int = 48 * 1024
    outbox_max_rows: int = 50_000
    outbox_max_db_bytes: int = 128 * 1024 * 1024
    outbox_drop_policy: str = "drop_oldest"

    event_registry_path: str = "tcd_service_grpc_registry.sqlite3"
    replay_ttl_s: int = 900

    edge_rate_capacity: float = 120.0
    edge_rate_refill_per_s: float = 60.0
    token_cost_divisor_default: float = 50.0

    node_id: str = ""
    proc_id: str = ""
    build_id: str = ""
    image_digest: str = ""

    record_raw_principal: bool = False
    record_raw_key_id: bool = False
    log_requests: bool = True
    debug_errors: bool = False

    idempotency_time_bucket_s: int = 60

    recommended_server_max_receive_bytes: int = 4 * 1024 * 1024
    recommended_server_max_send_bytes: int = 4 * 1024 * 1024
    recommended_max_concurrent_rpcs: int = 256

    def normalized(self) -> "GrpcServiceConfig":
        cfg = dataclasses.replace(self)
        cfg.protocol = self.protocol.normalized()
        cfg.subject_policy = self.subject_policy.normalized()
        cfg.diagnose_authz = self.diagnose_authz.normalized()
        cfg.verify_authz = self.verify_authz.normalized()
        cfg.route_name = _safe_text(self.route_name, max_len=64) or "grpc.diagnose"
        cfg.strict_mode = bool(self.strict_mode)
        cfg.max_end_to_end_latency_s = _clamp_float(self.max_end_to_end_latency_s, default=2.0, lo=0.1, hi=60.0)

        cfg.metadata_allowlist = tuple(sorted({x for x in self.metadata_allowlist if isinstance(x, str) and x in _ALLOWED_AUTH_METADATA})) or tuple(sorted(_ALLOWED_AUTH_METADATA))
        cfg.max_metadata_items = _clamp_int(self.max_metadata_items, default=96, lo=8, hi=1024)
        cfg.max_metadata_bytes = _clamp_int(self.max_metadata_bytes, default=16 * 1024, lo=512, hi=512 * 1024)

        cfg.max_trace = _clamp_int(self.max_trace, default=_MAX_TRACE, lo=1, hi=65_536)
        cfg.max_spectrum = _clamp_int(self.max_spectrum, default=_MAX_SPECT, lo=1, hi=65_536)
        cfg.max_features = _clamp_int(self.max_features, default=_MAX_FEATS, lo=1, hi=65_536)
        cfg.max_proto_bytes = _clamp_int(self.max_proto_bytes, default=2 * 1024 * 1024, lo=4096, hi=32 * 1024 * 1024)
        cfg.max_components_bytes = _clamp_int(self.max_components_bytes, default=_JSON_COMPONENT_LIMIT, lo=1024, hi=4 * 1024 * 1024)

        cfg.max_verify_chain_items = _clamp_int(self.max_verify_chain_items, default=4096, lo=1, hi=100_000)
        cfg.max_verify_body_bytes = _clamp_int(self.max_verify_body_bytes, default=256 * 1024, lo=1024, hi=8 * 1024 * 1024)
        cfg.max_verify_total_bytes = _clamp_int(self.max_verify_total_bytes, default=8 * 1024 * 1024, lo=4096, hi=128 * 1024 * 1024)
        cfg.verify_hard_timeout_mode = _safe_text(self.verify_hard_timeout_mode, max_len=16).lower() or "thread"
        if cfg.verify_hard_timeout_mode not in {"thread", "process"}:
            cfg.verify_hard_timeout_mode = "thread"
        cfg.verify_process_start_method = _safe_text(self.verify_process_start_method, max_len=16).lower() or "spawn"
        if cfg.verify_process_start_method not in {"spawn", "fork", "forkserver"}:
            cfg.verify_process_start_method = "spawn"

        cfg.max_inflight_diagnose = _clamp_int(self.max_inflight_diagnose, default=64, lo=1, hi=10_000)
        cfg.max_inflight_verify = _clamp_int(self.max_inflight_verify, default=16, lo=1, hi=10_000)
        cfg.gate_wait_ms = _clamp_int(self.gate_wait_ms, default=0, lo=0, hi=10_000)

        cfg.exec_auth_workers = _clamp_int(self.exec_auth_workers, default=8, lo=1, hi=512)
        cfg.exec_auth_queue = _clamp_int(self.exec_auth_queue, default=64, lo=0, hi=100_000)
        cfg.exec_verify_workers = _clamp_int(self.exec_verify_workers, default=4, lo=1, hi=128)
        cfg.exec_verify_queue = _clamp_int(self.exec_verify_queue, default=32, lo=0, hi=100_000)
        cfg.exec_controller_workers = _clamp_int(self.exec_controller_workers, default=8, lo=1, hi=512)
        cfg.exec_controller_queue = _clamp_int(self.exec_controller_queue, default=64, lo=0, hi=100_000)
        cfg.exec_attest_workers = _clamp_int(self.exec_attest_workers, default=4, lo=1, hi=128)
        cfg.exec_attest_queue = _clamp_int(self.exec_attest_queue, default=32, lo=0, hi=100_000)
        cfg.exec_ledger_workers = _clamp_int(self.exec_ledger_workers, default=4, lo=1, hi=128)
        cfg.exec_ledger_queue = _clamp_int(self.exec_ledger_queue, default=64, lo=0, hi=100_000)

        cfg.auth_timeout_ms = _clamp_int(self.auth_timeout_ms, default=350, lo=1, hi=60_000)
        cfg.controller_timeout_ms = _clamp_int(self.controller_timeout_ms, default=1200, lo=1, hi=60_000)
        cfg.verify_timeout_ms = _clamp_int(self.verify_timeout_ms, default=5000, lo=1, hi=120_000)
        cfg.attestor_timeout_ms = _clamp_int(self.attestor_timeout_ms, default=1200, lo=1, hi=60_000)
        cfg.ledger_timeout_ms = _clamp_int(self.ledger_timeout_ms, default=600, lo=1, hi=60_000)

        cfg.breaker_failures = _clamp_int(self.breaker_failures, default=5, lo=1, hi=1000)
        cfg.breaker_window_s = _clamp_float(self.breaker_window_s, default=30.0, lo=1.0, hi=3600.0)
        cfg.breaker_open_seconds = _clamp_float(self.breaker_open_seconds, default=15.0, lo=0.1, hi=3600.0)
        cfg.breaker_probe_jitter_s = _clamp_float(self.breaker_probe_jitter_s, default=2.0, lo=0.0, hi=60.0)
        cfg.breaker_probe_probability = _clamp_float(self.breaker_probe_probability, default=0.25, lo=0.01, hi=1.0)

        cfg.dep_retry_max = _clamp_int(self.dep_retry_max, default=1, lo=0, hi=8)
        cfg.dep_retry_base_ms = _clamp_int(self.dep_retry_base_ms, default=40, lo=1, hi=5000)

        cfg.grpc_auth_fallback_mode = _safe_text(self.grpc_auth_fallback_mode, max_len=16).lower() or "compat"
        if cfg.grpc_auth_fallback_mode not in {"compat", "disabled"}:
            cfg.grpc_auth_fallback_mode = "compat"
        cfg.allowed_auth_modes = [m for m in (_normalize_auth_mode(x) for x in (self.allowed_auth_modes or [])) if m != "none"] or None
        cfg.allowed_sig_algs = [str(x).strip() for x in (self.allowed_sig_algs or []) if str(x).strip()] or None
        cfg.require_pq_sig = bool(self.require_pq_sig)

        cfg.use_security_router = bool(self.use_security_router)
        cfg.require_security_router_when_strict = bool(self.require_security_router_when_strict)
        cfg.pq_required_zones = tuple(sorted({_safe_text(x, max_len=32).lower() for x in self.pq_required_zones if _safe_text(x, max_len=32)})) or ("admin", "partner")

        cfg.require_attestor = bool(self.require_attestor)
        cfg.require_ledger = bool(self.require_ledger)

        cfg.outbox_enabled = bool(self.outbox_enabled)
        cfg.outbox_path = _safe_text(self.outbox_path, max_len=512) or "tcd_service_grpc_outbox.sqlite3"
        cfg.outbox_per_process = bool(self.outbox_per_process)
        cfg.outbox_max_payload_bytes = _clamp_int(self.outbox_max_payload_bytes, default=48 * 1024, lo=1024, hi=2 * 1024 * 1024)
        cfg.outbox_max_rows = _clamp_int(self.outbox_max_rows, default=50_000, lo=1, hi=10_000_000)
        cfg.outbox_max_db_bytes = _clamp_int(self.outbox_max_db_bytes, default=128 * 1024 * 1024, lo=1024 * 1024, hi=8 * 1024 * 1024 * 1024)
        cfg.outbox_drop_policy = _safe_text(self.outbox_drop_policy, max_len=32).lower() or "drop_oldest"
        if cfg.outbox_drop_policy not in {"drop_oldest", "drop_newest", "reject_request"}:
            cfg.outbox_drop_policy = "drop_oldest"

        cfg.event_registry_path = _safe_text(self.event_registry_path, max_len=512) or "tcd_service_grpc_registry.sqlite3"
        cfg.replay_ttl_s = _clamp_int(self.replay_ttl_s, default=900, lo=1, hi=86400)

        cfg.edge_rate_capacity = _clamp_float(self.edge_rate_capacity, default=120.0, lo=1.0, hi=10_000_000.0)
        cfg.edge_rate_refill_per_s = _clamp_float(self.edge_rate_refill_per_s, default=60.0, lo=0.1, hi=10_000_000.0)
        cfg.token_cost_divisor_default = _clamp_float(self.token_cost_divisor_default, default=50.0, lo=1.0, hi=1_000_000.0)

        cfg.node_id = _safe_text(self.node_id, max_len=128)
        cfg.proc_id = _safe_text(self.proc_id, max_len=64)
        cfg.build_id = _safe_text(self.build_id, max_len=128)
        cfg.image_digest = _safe_text(self.image_digest, max_len=128)

        cfg.record_raw_principal = bool(self.record_raw_principal)
        cfg.record_raw_key_id = bool(self.record_raw_key_id)
        cfg.log_requests = bool(self.log_requests)
        cfg.debug_errors = bool(self.debug_errors)
        cfg.idempotency_time_bucket_s = _clamp_int(self.idempotency_time_bucket_s, default=60, lo=1, hi=86400)

        cfg.recommended_server_max_receive_bytes = _clamp_int(self.recommended_server_max_receive_bytes, default=4 * 1024 * 1024, lo=1024, hi=128 * 1024 * 1024)
        cfg.recommended_server_max_send_bytes = _clamp_int(self.recommended_server_max_send_bytes, default=4 * 1024 * 1024, lo=1024, hi=128 * 1024 * 1024)
        cfg.recommended_max_concurrent_rpcs = _clamp_int(self.recommended_max_concurrent_rpcs, default=256, lo=1, hi=100_000)

        return cfg

    def digest_material(self) -> Dict[str, Any]:
        c = self.normalized()
        return {
            "route_name": c.route_name,
            "strict_mode": c.strict_mode,
            "max_end_to_end_latency_s": c.max_end_to_end_latency_s,
            "protocol": dataclasses.asdict(c.protocol),
            "subject_policy": dataclasses.asdict(c.subject_policy),
            "diagnose_authz": dataclasses.asdict(c.diagnose_authz),
            "verify_authz": dataclasses.asdict(c.verify_authz),
            "metadata_allowlist": list(c.metadata_allowlist),
            "max_metadata_items": c.max_metadata_items,
            "max_metadata_bytes": c.max_metadata_bytes,
            "max_trace": c.max_trace,
            "max_spectrum": c.max_spectrum,
            "max_features": c.max_features,
            "max_proto_bytes": c.max_proto_bytes,
            "max_components_bytes": c.max_components_bytes,
            "max_verify_chain_items": c.max_verify_chain_items,
            "max_verify_body_bytes": c.max_verify_body_bytes,
            "max_verify_total_bytes": c.max_verify_total_bytes,
            "verify_hard_timeout_mode": c.verify_hard_timeout_mode,
            "verify_process_start_method": c.verify_process_start_method,
            "max_inflight_diagnose": c.max_inflight_diagnose,
            "max_inflight_verify": c.max_inflight_verify,
            "gate_wait_ms": c.gate_wait_ms,
            "auth_timeout_ms": c.auth_timeout_ms,
            "controller_timeout_ms": c.controller_timeout_ms,
            "verify_timeout_ms": c.verify_timeout_ms,
            "attestor_timeout_ms": c.attestor_timeout_ms,
            "ledger_timeout_ms": c.ledger_timeout_ms,
            "breaker_failures": c.breaker_failures,
            "breaker_window_s": c.breaker_window_s,
            "breaker_open_seconds": c.breaker_open_seconds,
            "breaker_probe_jitter_s": c.breaker_probe_jitter_s,
            "breaker_probe_probability": c.breaker_probe_probability,
            "dep_retry_max": c.dep_retry_max,
            "dep_retry_base_ms": c.dep_retry_base_ms,
            "grpc_auth_fallback_mode": c.grpc_auth_fallback_mode,
            "allowed_auth_modes": list(c.allowed_auth_modes or []),
            "allowed_sig_algs": list(c.allowed_sig_algs or []),
            "require_pq_sig": c.require_pq_sig,
            "use_security_router": c.use_security_router,
            "require_security_router_when_strict": c.require_security_router_when_strict,
            "pq_required_zones": list(c.pq_required_zones),
            "require_attestor": c.require_attestor,
            "require_ledger": c.require_ledger,
            "outbox_enabled": c.outbox_enabled,
            "outbox_path": c.outbox_path,
            "outbox_per_process": c.outbox_per_process,
            "outbox_max_payload_bytes": c.outbox_max_payload_bytes,
            "outbox_max_rows": c.outbox_max_rows,
            "outbox_max_db_bytes": c.outbox_max_db_bytes,
            "outbox_drop_policy": c.outbox_drop_policy,
            "event_registry_path": c.event_registry_path,
            "replay_ttl_s": c.replay_ttl_s,
            "edge_rate_capacity": c.edge_rate_capacity,
            "edge_rate_refill_per_s": c.edge_rate_refill_per_s,
            "token_cost_divisor_default": c.token_cost_divisor_default,
            "node_id": c.node_id,
            "proc_id": c.proc_id,
            "build_id": c.build_id,
            "image_digest": c.image_digest,
            "record_raw_principal": c.record_raw_principal,
            "record_raw_key_id": c.record_raw_key_id,
            "log_requests": c.log_requests,
            "debug_errors": c.debug_errors,
            "idempotency_time_bucket_s": c.idempotency_time_bucket_s,
            "recommended_server_max_receive_bytes": c.recommended_server_max_receive_bytes,
            "recommended_server_max_send_bytes": c.recommended_server_max_send_bytes,
            "recommended_max_concurrent_rpcs": c.recommended_max_concurrent_rpcs,
        }


def _build_cfg_from_env() -> GrpcServiceConfig:
    require_auth = _env_bool("TCD_GRPC_REQUIRE_AUTH", True)
    cfg = GrpcServiceConfig(
        route_name=os.getenv("TCD_GRPC_ROUTE_NAME", "grpc.diagnose"),
        strict_mode=_env_bool("TCD_GRPC_STRICT_MODE", False),
        max_end_to_end_latency_s=_env_float("TCD_GRPC_MAX_E2E_LATENCY_S", 2.0),

        protocol=GrpcProtocolCompatPolicy(
            api_version=os.getenv("TCD_GRPC_API_VERSION", "grpc.v1"),
            schema_version=os.getenv("TCD_GRPC_SCHEMA_VERSION", "1"),
            compatibility_epoch=os.getenv("TCD_GRPC_COMPAT_EPOCH", "2026-04"),
            require_api_version=_env_bool("TCD_GRPC_REQUIRE_API_VERSION", False),
            require_compatibility_epoch=_env_bool("TCD_GRPC_REQUIRE_COMPAT_EPOCH", False),
            require_client_capabilities=_env_bool("TCD_GRPC_REQUIRE_CAPS", False),
            required_capabilities_diagnose=tuple(_split_env_list("TCD_GRPC_REQUIRED_CAPS_DIAGNOSE") or []),
            required_capabilities_verify=tuple(_split_env_list("TCD_GRPC_REQUIRED_CAPS_VERIFY") or []),
        ),
        subject_policy=SubjectIdentityPolicy(
            allow_pseudonymized_subject=_env_bool("TCD_GRPC_ALLOW_PSEUDONYMIZED_SUBJECT", True),
            on_missing=os.getenv("TCD_GRPC_SUBJECT_ON_MISSING", "pseudonymize"),
            on_invalid=os.getenv("TCD_GRPC_SUBJECT_ON_INVALID", "pseudonymize"),
            max_part_bytes=_env_int("TCD_GRPC_SUBJECT_MAX_PART_BYTES", 128),
        ),
        diagnose_authz=MethodAuthzPolicy(
            require_auth=require_auth,
            allowed_auth_modes=tuple(_split_env_list("TCD_GRPC_ALLOWED_AUTH_MODES") or []),
            required_scopes=tuple(_split_env_list("TCD_GRPC_DIAGNOSE_REQUIRED_SCOPES") or []),
            required_roles=tuple(_split_env_list("TCD_GRPC_DIAGNOSE_REQUIRED_ROLES") or []),
            require_mtls=_env_bool("TCD_GRPC_DIAGNOSE_REQUIRE_MTLS", False),
            require_trusted_identity=_env_bool("TCD_GRPC_DIAGNOSE_REQUIRE_TRUSTED_ID", False),
        ),
        verify_authz=MethodAuthzPolicy(
            require_auth=_env_bool("TCD_GRPC_VERIFY_REQUIRE_AUTH", False),
            allowed_auth_modes=tuple(_split_env_list("TCD_GRPC_VERIFY_ALLOWED_AUTH_MODES") or []),
            required_scopes=tuple(_split_env_list("TCD_GRPC_VERIFY_REQUIRED_SCOPES") or []),
            required_roles=tuple(_split_env_list("TCD_GRPC_VERIFY_REQUIRED_ROLES") or []),
            require_mtls=_env_bool("TCD_GRPC_VERIFY_REQUIRE_MTLS", False),
            require_trusted_identity=_env_bool("TCD_GRPC_VERIFY_REQUIRE_TRUSTED_ID", False),
        ),

        max_metadata_items=_env_int("TCD_GRPC_MAX_METADATA_ITEMS", 96),
        max_metadata_bytes=_env_int("TCD_GRPC_MAX_METADATA_BYTES", 16 * 1024),
        max_trace=_env_int("TCD_GRPC_MAX_TRACE", _MAX_TRACE),
        max_spectrum=_env_int("TCD_GRPC_MAX_SPECTRUM", _MAX_SPECT),
        max_features=_env_int("TCD_GRPC_MAX_FEATURES", _MAX_FEATS),
        max_proto_bytes=_env_int("TCD_GRPC_MAX_PROTO_BYTES", 2 * 1024 * 1024),
        max_components_bytes=_env_int("TCD_GRPC_MAX_COMPONENTS_BYTES", _JSON_COMPONENT_LIMIT),

        max_verify_chain_items=_env_int("TCD_GRPC_MAX_VERIFY_CHAIN_ITEMS", 4096),
        max_verify_body_bytes=_env_int("TCD_GRPC_MAX_VERIFY_BODY_BYTES", 256 * 1024),
        max_verify_total_bytes=_env_int("TCD_GRPC_MAX_VERIFY_TOTAL_BYTES", 8 * 1024 * 1024),
        verify_hard_timeout_mode=os.getenv("TCD_GRPC_VERIFY_TIMEOUT_MODE", "thread"),
        verify_process_start_method=os.getenv("TCD_GRPC_VERIFY_PROCESS_START_METHOD", "spawn"),

        max_inflight_diagnose=_env_int("TCD_GRPC_MAX_INFLIGHT_DIAGNOSE", 64),
        max_inflight_verify=_env_int("TCD_GRPC_MAX_INFLIGHT_VERIFY", 16),
        gate_wait_ms=_env_int("TCD_GRPC_GATE_WAIT_MS", 0),

        exec_auth_workers=_env_int("TCD_GRPC_EXEC_AUTH_WORKERS", 8),
        exec_auth_queue=_env_int("TCD_GRPC_EXEC_AUTH_QUEUE", 64),
        exec_verify_workers=_env_int("TCD_GRPC_EXEC_VERIFY_WORKERS", 4),
        exec_verify_queue=_env_int("TCD_GRPC_EXEC_VERIFY_QUEUE", 32),
        exec_controller_workers=_env_int("TCD_GRPC_EXEC_CONTROLLER_WORKERS", 8),
        exec_controller_queue=_env_int("TCD_GRPC_EXEC_CONTROLLER_QUEUE", 64),
        exec_attest_workers=_env_int("TCD_GRPC_EXEC_ATTEST_WORKERS", 4),
        exec_attest_queue=_env_int("TCD_GRPC_EXEC_ATTEST_QUEUE", 32),
        exec_ledger_workers=_env_int("TCD_GRPC_EXEC_LEDGER_WORKERS", 4),
        exec_ledger_queue=_env_int("TCD_GRPC_EXEC_LEDGER_QUEUE", 64),

        auth_timeout_ms=_env_int("TCD_GRPC_AUTH_TIMEOUT_MS", 350),
        controller_timeout_ms=_env_int("TCD_GRPC_CONTROLLER_TIMEOUT_MS", 1200),
        verify_timeout_ms=_env_int("TCD_GRPC_VERIFY_TIMEOUT_MS", 5000),
        attestor_timeout_ms=_env_int("TCD_GRPC_ATTESTOR_TIMEOUT_MS", 1200),
        ledger_timeout_ms=_env_int("TCD_GRPC_LEDGER_TIMEOUT_MS", 600),

        breaker_failures=_env_int("TCD_GRPC_BREAKER_FAILURES", 5),
        breaker_window_s=_env_float("TCD_GRPC_BREAKER_WINDOW_S", 30.0),
        breaker_open_seconds=_env_float("TCD_GRPC_BREAKER_OPEN_SECONDS", 15.0),
        breaker_probe_jitter_s=_env_float("TCD_GRPC_BREAKER_PROBE_JITTER_S", 2.0),
        breaker_probe_probability=_env_float("TCD_GRPC_BREAKER_PROBE_PROBABILITY", 0.25),

        dep_retry_max=_env_int("TCD_GRPC_DEP_RETRY_MAX", 1),
        dep_retry_base_ms=_env_int("TCD_GRPC_DEP_RETRY_BASE_MS", 40),

        grpc_auth_fallback_mode=os.getenv("TCD_GRPC_AUTH_FALLBACK_MODE", "compat"),
        allowed_auth_modes=_split_env_list("TCD_GRPC_ALLOWED_AUTH_MODES"),
        allowed_sig_algs=_split_env_list("TCD_GRPC_ALLOWED_SIG_ALGS"),
        require_pq_sig=_env_bool("TCD_GRPC_REQUIRE_PQ_SIG", False),

        use_security_router=_env_bool("TCD_GRPC_USE_SECURITY_ROUTER", True),
        require_security_router_when_strict=_env_bool("TCD_GRPC_REQUIRE_SECURITY_ROUTER_WHEN_STRICT", False),
        pq_required_zones=tuple(_split_env_list("TCD_GRPC_PQ_REQUIRED_ZONES") or ("admin", "partner")),

        require_attestor=_env_bool("TCD_GRPC_REQUIRE_ATTESTOR", False),
        require_ledger=_env_bool("TCD_GRPC_REQUIRE_LEDGER", False),

        outbox_enabled=_env_bool("TCD_GRPC_OUTBOX_ENABLED", True),
        outbox_path=os.getenv("TCD_GRPC_OUTBOX_PATH", "tcd_service_grpc_outbox.sqlite3"),
        outbox_per_process=_env_bool("TCD_GRPC_OUTBOX_PER_PROCESS", True),
        outbox_max_payload_bytes=_env_int("TCD_GRPC_OUTBOX_MAX_PAYLOAD_BYTES", 48 * 1024),
        outbox_max_rows=_env_int("TCD_GRPC_OUTBOX_MAX_ROWS", 50_000),
        outbox_max_db_bytes=_env_int("TCD_GRPC_OUTBOX_MAX_DB_BYTES", 128 * 1024 * 1024),
        outbox_drop_policy=os.getenv("TCD_GRPC_OUTBOX_DROP_POLICY", "drop_oldest"),

        event_registry_path=os.getenv("TCD_GRPC_EVENT_REGISTRY_PATH", "tcd_service_grpc_registry.sqlite3"),
        replay_ttl_s=_env_int("TCD_GRPC_REPLAY_TTL_S", 900),

        edge_rate_capacity=_env_float("TCD_GRPC_RATE_CAPACITY", 120.0),
        edge_rate_refill_per_s=_env_float("TCD_GRPC_RATE_REFILL_PER_S", 60.0),
        token_cost_divisor_default=_env_float("TCD_GRPC_TOKEN_COST_DIVISOR_DEFAULT", 50.0),

        node_id=os.getenv("TCD_NODE_ID", os.getenv("HOSTNAME", ""))[:128],
        proc_id=os.getenv("TCD_PROC_ID", str(os.getpid()))[:64],
        build_id=os.getenv("TCD_BUILD_ID", "")[:128],
        image_digest=os.getenv("TCD_IMAGE_DIGEST", "")[:128],

        record_raw_principal=_env_bool("TCD_GRPC_RECORD_RAW_PRINCIPAL", False),
        record_raw_key_id=_env_bool("TCD_GRPC_RECORD_RAW_KEY_ID", False),
        log_requests=_env_bool("TCD_GRPC_LOG_REQUESTS", True),
        debug_errors=_env_bool("TCD_GRPC_DEBUG_ERRORS", False),

        idempotency_time_bucket_s=_env_int("TCD_GRPC_IDEMPOTENCY_BUCKET_S", 60),
        recommended_server_max_receive_bytes=_env_int("TCD_GRPC_SERVER_MAX_RECV", 4 * 1024 * 1024),
        recommended_server_max_send_bytes=_env_int("TCD_GRPC_SERVER_MAX_SEND", 4 * 1024 * 1024),
        recommended_max_concurrent_rpcs=_env_int("TCD_GRPC_SERVER_MAX_CONCURRENT_RPCS", 256),
    )

    cfg = cfg.normalized()
    if cfg.outbox_enabled and cfg.outbox_per_process:
        p = cfg.outbox_path
        if "{pid}" in p or "{proc_id}" in p:
            p = p.replace("{pid}", str(os.getpid())).replace("{proc_id}", cfg.proc_id or str(os.getpid()))
        else:
            p = f"{p}.{os.getpid()}"
        cfg.outbox_path = p
    return cfg

# ---------------------------------------------------------------------------
# Security router glue
# ---------------------------------------------------------------------------

class _SecurityAuditSinkAdapter:
    def __init__(self, ledger: Any) -> None:
        self._ledger = ledger

    def emit(self, event_type: str, payload: Mapping[str, Any]) -> Optional[str]:
        if self._ledger is None:
            return None
        record = {"kind": "grpc_security_audit", "event_type": str(event_type), "payload": dict(payload)}
        try:
            if hasattr(self._ledger, "append_ex"):
                out = self._ledger.append_ex(record, stage="event")  # type: ignore[attr-defined]
                return getattr(out, "head", None) or None
            out2 = self._ledger.append(record)  # type: ignore[attr-defined]
            return getattr(out2, "head", None) if out2 is not None else None
        except Exception:
            return None


class _Runtime:
    def __init__(
        self,
        *,
        cfg: Optional[GrpcServiceConfig] = None,
        prom: Optional[TCDPrometheusExporter] = None,
        otel: Optional[TCDOtelExporter] = None,
        policy_store: Optional[Any] = None,
        rate_limiter: Optional[Any] = None,
        authenticator: Optional[Any] = None,
        attestor: Optional[Any] = None,
        attestor_cfg: Optional[Any] = None,
        ledger: Optional[Any] = None,
        outbox: Optional[_SQLiteOutbox] = None,
        security_router: Optional[Any] = None,
        strategy_router: Optional[Any] = None,
    ) -> None:
        self.settings = _settings.get()
        self.cfg = (cfg or _build_cfg_from_env()).normalized()
        self.cfg_fp = self._compute_cfg_digest(self.cfg)

        self.node_id = self.cfg.node_id or _safe_text(getattr(self.settings, "node_id", ""), max_len=128)
        self.proc_id = self.cfg.proc_id or str(os.getpid())
        self.build_id = self.cfg.build_id or _safe_text(getattr(self.settings, "build_id", ""), max_len=128)
        self.image_digest = self.cfg.image_digest or _safe_text(getattr(self.settings, "image_digest", ""), max_len=128)

        self.prom = prom or TCDPrometheusExporter(
            port=int(getattr(self.settings, "prometheus_port", 8001) or 8001),
            version=str(getattr(self.settings, "version", "0.0.0") or "0.0.0"),
            config_hash=self.cfg_fp,
        )
        if bool(getattr(self.settings, "prom_http_enable", False)):
            with contextlib.suppress(Exception):
                self.prom.ensure_server()

        self.otel = otel or TCDOtelExporter(endpoint=getattr(self.settings, "otel_endpoint", None))
        self.async_runner = _AsyncLoopThread()

        self.det_lock = threading.RLock()
        self.detectors: Dict[Tuple[str, str, str, str], TraceCollapseDetector] = {}
        self.av_lock = threading.RLock()
        self.av_by_subject: Dict[Tuple[str, str, str], AlwaysValidRiskController] = {}
        self.mv_lock = threading.RLock()
        self.mv_by_model: Dict[str, MultiVarDetector] = {}

        self.exec_auth = _BoundedExecutor(pool="auth", max_workers=self.cfg.exec_auth_workers, max_queue=self.cfg.exec_auth_queue)
        self.exec_verify = _BoundedExecutor(pool="verify", max_workers=self.cfg.exec_verify_workers, max_queue=self.cfg.exec_verify_queue)
        self.exec_controller = _BoundedExecutor(pool="controller", max_workers=self.cfg.exec_controller_workers, max_queue=self.cfg.exec_controller_queue)
        self.exec_attest = _BoundedExecutor(pool="attest", max_workers=self.cfg.exec_attest_workers, max_queue=self.cfg.exec_attest_queue)
        self.exec_ledger = _BoundedExecutor(pool="ledger", max_workers=self.cfg.exec_ledger_workers, max_queue=self.cfg.exec_ledger_queue)

        self.br_auth = _CircuitBreaker(
            dep="auth",
            threshold=self.cfg.breaker_failures,
            window_s=self.cfg.breaker_window_s,
            open_seconds=self.cfg.breaker_open_seconds,
            probe_jitter_s=self.cfg.breaker_probe_jitter_s,
            probe_probability=self.cfg.breaker_probe_probability,
        )
        self.br_verify = _CircuitBreaker(
            dep="verify",
            threshold=self.cfg.breaker_failures,
            window_s=self.cfg.breaker_window_s,
            open_seconds=self.cfg.breaker_open_seconds,
            probe_jitter_s=self.cfg.breaker_probe_jitter_s,
            probe_probability=self.cfg.breaker_probe_probability,
        )
        self.br_controller = _CircuitBreaker(
            dep="controller",
            threshold=self.cfg.breaker_failures,
            window_s=self.cfg.breaker_window_s,
            open_seconds=self.cfg.breaker_open_seconds,
            probe_jitter_s=self.cfg.breaker_probe_jitter_s,
            probe_probability=self.cfg.breaker_probe_probability,
        )
        self.br_attestor = _CircuitBreaker(
            dep="attestor",
            threshold=self.cfg.breaker_failures,
            window_s=self.cfg.breaker_window_s,
            open_seconds=self.cfg.breaker_open_seconds,
            probe_jitter_s=self.cfg.breaker_probe_jitter_s,
            probe_probability=self.cfg.breaker_probe_probability,
        )
        self.br_ledger = _CircuitBreaker(
            dep="ledger",
            threshold=self.cfg.breaker_failures,
            window_s=self.cfg.breaker_window_s,
            open_seconds=self.cfg.breaker_open_seconds,
            probe_jitter_s=self.cfg.breaker_probe_jitter_s,
            probe_probability=self.cfg.breaker_probe_probability,
        )

        self.gate_diagnose = _InFlightGate("Diagnose", self.cfg.max_inflight_diagnose)
        self.gate_verify = _InFlightGate("Verify", self.cfg.max_inflight_verify)

        self.rate_limiter = rate_limiter or self._build_rate_limiter()

        self.authenticator = authenticator
        if self.authenticator is None and build_authenticator_from_env is not None:
            with contextlib.suppress(Exception):
                self.authenticator = build_authenticator_from_env()

        self.attestor_cfg = attestor_cfg
        self.attestor = attestor
        if self.attestor is None and Attestor is not None and AttestorConfig is not None:
            with contextlib.suppress(Exception):
                self.attestor_cfg = AttestorConfig(
                    attestor_id="tcd-grpc",
                    proc_id=self.proc_id or None,
                    strict_mode=self.cfg.strict_mode,
                    default_auth_policy=None,
                    default_chain_policy=None,
                    default_ledger_policy=None,
                    default_cfg_digest=self.cfg_fp,
                )
                self.attestor = Attestor(cfg=self.attestor_cfg)

        self.ledger = ledger
        if self.ledger is None and AuditLedger is not None:
            with contextlib.suppress(Exception):
                self.ledger = AuditLedger()

        self.outbox = outbox
        if self.outbox is None and self.cfg.outbox_enabled:
            with contextlib.suppress(Exception):
                self.outbox = _SQLiteOutbox(
                    self.cfg.outbox_path,
                    max_rows=self.cfg.outbox_max_rows,
                    max_db_bytes=self.cfg.outbox_max_db_bytes,
                    max_payload_bytes=self.cfg.outbox_max_payload_bytes,
                    drop_policy=self.cfg.outbox_drop_policy,
                )

        self.registry = _SQLiteControlRegistry(self.cfg.event_registry_path, replay_ttl_s=self.cfg.replay_ttl_s)

        self.strategy_router = strategy_router or StrategyRouter()
        self.detector_adapter = _GrpcDetectorRuntime()

        self.security_router = security_router
        if self.security_router is None and self.cfg.use_security_router and policy_store is not None and SecurityRouter is not None:
            self.security_router = self._build_security_router(policy_store)

        self.auth_adapter = GrpcAuthAdapter(runtime=self)

    def _compute_cfg_digest(self, cfg: GrpcServiceConfig) -> str:
        if canonical_kv_hash is not None:
            with contextlib.suppress(Exception):
                return canonical_kv_hash(cfg.digest_material(), ctx="tcd:service_grpc_cfg", label="grpc_cfg")
        return _blake3_hex(_canonical_json_bytes(cfg.digest_material()), ctx="tcd:service_grpc_cfg")

    def _build_rate_limiter(self) -> Any:
        with contextlib.suppress(Exception):
            if RateLimitConfig is not Any and RateLimitZoneConfig is not Any:
                rlc = RateLimitConfig(
                    zones={"default": RateLimitZoneConfig(capacity=self.cfg.edge_rate_capacity, refill_per_s=self.cfg.edge_rate_refill_per_s)},
                    default_zone="default",
                )
                return RateLimiter(rlc)
        try:
            return RateLimiter(capacity=self.cfg.edge_rate_capacity, refill_per_s=self.cfg.edge_rate_refill_per_s)  # type: ignore[call-arg]
        except Exception:
            return RateLimiter()  # type: ignore[call-arg]

    def _build_security_router(self, policy_store: Any) -> Optional[Any]:
        if SecurityRouter is None:
            return None
        candidates = [
            {
                "policy_store": policy_store,
                "rate_limiter": self.rate_limiter,
                "attestor": self.attestor,
                "detector_runtime": self.detector_adapter,
                "base_av": AlwaysValidConfig(),
                "strategy_router": self.strategy_router,
                "audit_sink": _SecurityAuditSinkAdapter(self.ledger) if self.ledger is not None else None,
            },
            {
                "policy_store": policy_store,
                "rate_limiter": self.rate_limiter,
                "attestor": self.attestor,
                "detector_runtime": self.detector_adapter,
                "base_av": AlwaysValidConfig(),
                "strategy_router": self.strategy_router,
            },
            {
                "policy_store": policy_store,
                "rate_limiter": self.rate_limiter,
                "attestor": self.attestor,
                "detector_runtime": self.detector_adapter,
                "base_av": AlwaysValidConfig(),
            },
            {
                "policy_store": policy_store,
                "rate_limiter": self.rate_limiter,
                "attestor": self.attestor,
                "detector_runtime": self.detector_adapter,
            },
        ]
        for kwargs in candidates:
            try:
                return SecurityRouter(**kwargs)
            except Exception:
                continue
        return None

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

    def shutdown(self) -> None:
        for ex in (self.exec_auth, self.exec_verify, self.exec_controller, self.exec_attest, self.exec_ledger):
            with contextlib.suppress(Exception):
                ex.shutdown()
        with contextlib.suppress(Exception):
            self.async_runner.stop()

    def dod(self) -> GrpcServiceDOD:
        return GrpcServiceDOD(
            schema="grpc.dod.v1",
            light_rpc_p95_ms=200,
            light_rpc_p99_ms=1000,
            heavy_rpc_p95_ms=1200,
            heavy_rpc_p99_ms=5000,
            max_proto_bytes=int(self.cfg.max_proto_bytes),
            max_metadata_bytes=int(self.cfg.max_metadata_bytes),
            max_verify_total_bytes=int(self.cfg.max_verify_total_bytes),
            consistency_level="local_best_effort_with_deterministic_event_identity",
            evidence_delivery="prepare_commit_with_outbox_fallback",
            verify_isolation=self.cfg.verify_hard_timeout_mode,
        )

    def runtime_public_view(self) -> Dict[str, Any]:
        sec_public = None
        sec_diag = None
        if self.security_router is not None:
            with contextlib.suppress(Exception):
                pub = getattr(self.security_router, "public_config_view", None)
                if callable(pub):
                    sec_public = _model_dump(pub())
            with contextlib.suppress(Exception):
                diag = getattr(self.security_router, "bundle_diagnostics", None)
                if callable(diag):
                    sec_diag = _model_dump(diag())
        return {
            "schema": "grpc.runtime.v1",
            "cfg_fp": self.cfg_fp,
            "node_id": self.node_id,
            "proc_id": self.proc_id,
            "build_id": self.build_id,
            "image_digest": self.image_digest,
            "api_version": self.cfg.protocol.api_version,
            "schema_version": self.cfg.protocol.schema_version,
            "compatibility_epoch": self.cfg.protocol.compatibility_epoch,
            "dod": dataclasses.asdict(self.dod()),
            "security_router": {"public": sec_public, "diagnostics": sec_diag},
        }

# ---------------------------------------------------------------------------
# Global runtime
# ---------------------------------------------------------------------------

_RUNTIME: Optional[_Runtime] = None
_RUNTIME_LOCK = threading.Lock()


def _rt() -> _Runtime:
    global _RUNTIME
    with _RUNTIME_LOCK:
        if _RUNTIME is None:
            _RUNTIME = _Runtime()
        return _RUNTIME


def create_grpc_runtime(
    *,
    cfg: Optional[GrpcServiceConfig] = None,
    prom: Optional[TCDPrometheusExporter] = None,
    otel: Optional[TCDOtelExporter] = None,
    policy_store: Optional[Any] = None,
    rate_limiter: Optional[Any] = None,
    authenticator: Optional[Any] = None,
    attestor: Optional[Any] = None,
    attestor_cfg: Optional[Any] = None,
    ledger: Optional[Any] = None,
    outbox: Optional[_SQLiteOutbox] = None,
    security_router: Optional[Any] = None,
    strategy_router: Optional[Any] = None,
) -> _Runtime:
    return _Runtime(
        cfg=cfg,
        prom=prom,
        otel=otel,
        policy_store=policy_store,
        rate_limiter=rate_limiter,
        authenticator=authenticator,
        attestor=attestor,
        attestor_cfg=attestor_cfg,
        ledger=ledger,
        outbox=outbox,
        security_router=security_router,
        strategy_router=strategy_router,
    )


def grpc_supported() -> bool:
    return bool(_HAS_GRPC and _HAS_STUBS)


def grpc_server_options(cfg: Optional[GrpcServiceConfig] = None) -> Tuple[Tuple[str, int], ...]:
    c = (cfg or _build_cfg_from_env()).normalized()
    return (
        ("grpc.max_receive_message_length", int(c.recommended_server_max_receive_bytes)),
        ("grpc.max_send_message_length", int(c.recommended_server_max_send_bytes)),
        ("grpc.max_concurrent_streams", int(c.recommended_max_concurrent_rpcs)),
        ("grpc.keepalive_time_ms", 30_000),
        ("grpc.keepalive_timeout_ms", 10_000),
        ("grpc.http2.max_pings_without_data", 0),
    )

# ---------------------------------------------------------------------------
# Shared service helpers
# ---------------------------------------------------------------------------

def _request_summary_digest(req: Any, *, method_name: str, sec_ctx: Mapping[str, Any]) -> str:
    payload = {
        "method": method_name,
        "model_id": _safe_text(getattr(req, "model_id", None), max_len=128),
        "gpu_id": _safe_text(getattr(req, "gpu_id", None), max_len=128),
        "task": _safe_text(getattr(req, "task", None), max_len=64),
        "lang": _safe_text(getattr(req, "lang", None), max_len=32),
        "trace_len": len(getattr(req, "trace_vector", []) or []),
        "spectrum_len": len(getattr(req, "spectrum", []) or []),
        "features_len": len(getattr(req, "features", []) or []),
        "tokens_delta": _coerce_float(getattr(req, "tokens_delta", None)),
        "base_temp": _coerce_float(getattr(req, "base_temp", None)),
        "base_top_p": _coerce_float(getattr(req, "base_top_p", None)),
        "trust_zone": sec_ctx.get("trust_zone"),
        "route_profile": sec_ctx.get("route_profile"),
    }
    return _blake3_hex(_canonical_json_bytes(payload), ctx="tcd:grpc:reqsum")


def _derive_event_id(
    *,
    cfg_fp: str,
    method_name: str,
    subject_hash: Optional[str],
    principal_hash: Optional[str],
    request_id: str,
    idempotency_key: Optional[str],
    body_digest: str,
    bucket_s: int,
) -> str:
    if idempotency_key:
        payload = {
            "cfg_fp": cfg_fp,
            "method": method_name,
            "subject_hash": subject_hash,
            "principal_hash": principal_hash,
            "idempotency_key": idempotency_key,
        }
    else:
        bucket = int(time.time() // max(1, int(bucket_s)))
        payload = {
            "cfg_fp": cfg_fp,
            "method": method_name,
            "subject_hash": subject_hash,
            "principal_hash": principal_hash,
            "body_digest": body_digest,
            "bucket": bucket,
        }
    return "gev2:" + _blake3_hex(_canonical_json_bytes(payload), ctx="tcd:grpc:event")[:40]


def _event_fingerprint(
    *,
    event_id: str,
    request_id: str,
    method_name: str,
    body_digest: str,
    canonical_request_digest: str,
) -> str:
    payload = {
        "event_id": event_id,
        "request_id": request_id,
        "method": method_name,
        "body_digest": body_digest,
        "request_digest": canonical_request_digest,
    }
    return _blake3_hex(_canonical_json_bytes(payload), ctx="tcd:grpc:event_fingerprint")


def _normalize_security_context(context: Any, req: Any, cfg: GrpcServiceConfig) -> Dict[str, Any]:
    md = _metadata_dict(context)
    trust_zone = md.get("x-trust-zone") or getattr(req, "trust_zone", "") or "internet"
    route_profile = md.get("x-route-profile") or getattr(req, "route_profile", "") or "inference"

    threat_kind: Optional[str] = None
    if _has_field(req, "threat_hint"):
        threat_kind = getattr(req, "threat_hint", "") or None
    if _has_field(req, "threat_kind") and not threat_kind:
        threat_kind = getattr(req, "threat_kind", "") or None
    if md.get("x-threat") and not threat_kind:
        threat_kind = md["x-threat"]
    threat_kind = _normalize_threat_kind(threat_kind)

    threat_conf = None
    if _has_field(req, "threat_confidence"):
        threat_conf = _coerce_float(getattr(req, "threat_confidence"))
    if threat_conf is None:
        threat_conf = _coerce_float(md.get("x-threat-confidence"))

    pq_required = False
    if _has_field(req, "pq_required"):
        pq_required = _coerce_bool(getattr(req, "pq_required"), default=False)
    if md.get("x-pq-required"):
        pq_required = _coerce_bool(md.get("x-pq-required"), default=pq_required)

    tz = _safe_text(trust_zone, max_len=32).lower() or "internet"
    if tz not in {"internet", "internal", "partner", "admin", "ops"}:
        tz = "internet"
    rp = _safe_text(route_profile, max_len=32).lower() or "inference"
    if rp not in {"inference", "batch", "admin", "control", "metrics", "health", "restricted"}:
        rp = "inference"
    if not pq_required and tz in set(cfg.pq_required_zones or ()):
        pq_required = True

    comp_tags: List[str] = []
    if hasattr(req, "compliance_tags"):
        with contextlib.suppress(Exception):
            comp_tags = [str(x).strip() for x in list(getattr(req, "compliance_tags")) if str(x).strip()]
    if not comp_tags and md.get("x-compliance-tags"):
        comp_tags = [x.strip() for x in md.get("x-compliance-tags", "").split(",") if x.strip()]

    return {
        "trust_zone": tz,
        "route_profile": rp,
        "threat_kind": threat_kind,
        "threat_confidence": threat_conf,
        "pq_required": bool(pq_required),
        "build_id": _safe_text(md.get("x-build-id") or getattr(req, "build_id", None), max_len=128) or None,
        "image_digest": _safe_text(md.get("x-image-digest") or getattr(req, "image_digest", None), max_len=256) or None,
        "compliance_tags": tuple(comp_tags[:32]),
    }


def _rate_limit_cost(cfg: GrpcServiceConfig, sec_ctx: Mapping[str, Any], req: Any, threat_kind: Optional[str], threat_conf: Optional[float]) -> float:
    tokens_delta = float(getattr(req, "tokens_delta", 0.0) or 0.0)
    divisor = float(cfg.token_cost_divisor_default or 50.0)
    base_cost = max(1.0, tokens_delta / max(1.0, divisor))
    tz = sec_ctx.get("trust_zone")
    mult = 1.0
    if tz == "admin":
        mult = 2.0
    elif tz == "internal":
        mult = 1.5
    elif tz == "partner":
        mult = 1.25
    cost = base_cost * mult
    if threat_kind == "apt" and (threat_conf or 0.0) >= 0.9:
        cost *= 3.0
    return cost


def _consume_rate(rt: _Runtime, *, subject: Tuple[str, str, str], principal_id: Optional[str], model_id: str, cost: float) -> bool:
    try:
        if RateKey is not Any:
            rk = RateKey(
                tenant_id=subject[0],
                principal_id=principal_id or subject[1],
                subject_id=f"tenant={subject[0]}|user={subject[1]}|session={subject[2]}|model={model_id}",
                session_id=subject[2],
                resource_id=model_id,
                route_id="grpc",
            )
        else:
            rk = (subject[0], subject[1], subject[2], model_id)
        dec = rt.rate_limiter.consume_decision(key=rk, cost=cost, zone="default")
        return bool(getattr(dec, "allowed", True))
    except Exception:
        try:
            return bool(rt.rate_limiter.consume(subject, cost=cost))  # type: ignore[attr-defined]
        except Exception:
            return True


def _decision_to_action(decision: Any) -> str:
    req_action = _safe_text(getattr(decision, "required_action", ""), max_len=32).lower()
    if req_action == "block":
        return "block"
    if req_action == "degrade":
        return "degrade"
    return "none"


def _manual_route_action(route: Any, decision_fail: bool, *, threat_kind: Optional[str], threat_conf: Optional[float], pq_required: bool, pq_ok: Optional[bool]) -> str:
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


def _receipt_public_from_mapping(att: Mapping[str, Any]) -> Dict[str, Any]:
    out = {
        "head": att.get("receipt") or att.get("receipt_ref"),
        "receipt_ref": att.get("receipt_ref") or att.get("receipt"),
        "audit_ref": att.get("audit_ref"),
        "event_id": att.get("event_id"),
        "decision_id": att.get("decision_id"),
        "route_plan_id": att.get("route_plan_id"),
        "policy_ref": att.get("policy_ref"),
        "policyset_ref": att.get("policyset_ref"),
        "cfg_fp": att.get("cfg_fp"),
        "state_domain_id": att.get("state_domain_id"),
        "verify_key_id": att.get("verify_key_id") or att.get("sig_key_id"),
        "verify_key_fp": att.get("verify_key_fp"),
        "receipt_integrity": att.get("receipt_integrity"),
        "pq_signature_required": att.get("pq_signature_required"),
        "pq_signature_ok": att.get("pq_signature_ok"),
        "integrity_ok": att.get("integrity_ok", True),
        "integrity_errors": list(att.get("integrity_errors", ()) or ()),
    }
    if ReceiptPublicView is not None:
        with contextlib.suppress(Exception):
            if hasattr(ReceiptPublicView, "model_validate"):
                m = ReceiptPublicView.model_validate(out)  # type: ignore[attr-defined]
                return m.model_dump(exclude_none=True)  # type: ignore[attr-defined]
    return {k: v for k, v in out.items() if v is not None}

# ---------------------------------------------------------------------------
# Main runtime singleton
# ---------------------------------------------------------------------------

# Already defined above: _rt(), create_grpc_runtime(), grpc_supported(), grpc_server_options

# ---------------------------------------------------------------------------
# gRPC service
# ---------------------------------------------------------------------------

if _HAS_GRPC and _HAS_STUBS:

    class TcdService(pb_grpc.TcdServiceServicer):  # type: ignore[misc]
        def __init__(self, runtime: Optional[_Runtime] = None) -> None:
            self._rt = runtime or _rt()

        def Diagnose(self, request: Any, context: Any) -> Any:
            rt = self._rt
            cfg = rt.cfg
            method = "Diagnose"
            t0 = time.perf_counter()
            status_label = "ok"
            action_label = "none"
            request_id = ""
            event_id = ""
            gate_ok = False

            try:
                if not _has_time_remaining(context):
                    status_label = "timeout"
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.DEADLINE_EXCEEDED,
                        "deadline exceeded",
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
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

                gate_ok = rt.gate_diagnose.acquire(cfg.gate_wait_ms)
                if not gate_ok:
                    status_label = "overloaded"
                    _GRPC_GATE_REJECT.labels(method, "inflight").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.RESOURCE_EXHAUSTED,
                        "server overloaded",
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
                        verdict=False,
                        score=0.0,
                        threshold=0.0,
                        budget_remaining=0.0,
                        components=_bounded_json_dumps({"error": "overloaded"}, max_bytes=cfg.max_components_bytes),
                        cause="overloaded",
                        action="reject",
                        step=0,
                        e_value=1.0,
                        alpha_alloc=0.0,
                        alpha_spent=0.0,
                    )

                md = _metadata_dict(context)
                md_bytes = _metadata_size_bytes(md)
                _GRPC_METADATA_BYTES.labels(method).observe(float(md_bytes))
                if len(md) > cfg.max_metadata_items or md_bytes > cfg.max_metadata_bytes:
                    status_label = "bad_request"
                    _GRPC_REQ_REJECTED.labels(method, "metadata_too_large").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        "metadata too large",
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
                        verdict=False,
                        score=0.0,
                        threshold=0.0,
                        budget_remaining=0.0,
                        components=_bounded_json_dumps({"error": "metadata_too_large"}, max_bytes=cfg.max_components_bytes),
                        cause="metadata",
                        action="reject",
                        step=0,
                        e_value=1.0,
                        alpha_alloc=0.0,
                        alpha_spent=0.0,
                    )

                body_bytes = _deterministic_proto_bytes(request)
                _GRPC_REQ_PAYLOAD_BYTES.labels(method).observe(float(len(body_bytes)))
                if len(body_bytes) > cfg.max_proto_bytes:
                    status_label = "payload_too_large"
                    _GRPC_REQ_REJECTED.labels(method, "payload_too_large").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        "payload too large",
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
                        verdict=False,
                        score=0.0,
                        threshold=0.0,
                        budget_remaining=0.0,
                        components=_bounded_json_dumps({"error": "payload_too_large"}, max_bytes=cfg.max_components_bytes),
                        cause="limit",
                        action="reject",
                        step=0,
                        e_value=1.0,
                        alpha_alloc=0.0,
                        alpha_spent=0.0,
                    )

                peer = _extract_peer_identity(context)
                subject_legacy, request_id, trace_id, idem, principal_hint = _resolve_subject_and_request(context, request)
                sec_ctx = _normalize_security_context(context, request, cfg)
                body_digest = _blake3_hex(body_bytes, ctx="tcd:grpc:transport_body")

                compat = _resolve_protocol_compat(method, request, md, cfg.protocol)
                if not compat.ok:
                    status_label = "bad_request"
                    _GRPC_PROTO_REJECT.labels(method, compat.reason or "protocol").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        "protocol compatibility rejected",
                        request_id=request_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
                        verdict=False,
                        score=0.0,
                        threshold=0.0,
                        budget_remaining=0.0,
                        components=_bounded_json_dumps(
                            {
                                "error": "protocol_rejected",
                                "reason": compat.reason,
                                "server_api_version": cfg.protocol.api_version,
                                "server_schema_version": cfg.protocol.schema_version,
                                "server_compatibility_epoch": cfg.protocol.compatibility_epoch,
                            },
                            max_bytes=cfg.max_components_bytes,
                        ),
                        cause="protocol",
                        action="reject",
                        step=0,
                        e_value=1.0,
                        alpha_alloc=0.0,
                        alpha_spent=0.0,
                    )

                subject_result = _parse_subject_identity(
                    context,
                    request,
                    policy=cfg.subject_policy,
                    request_id=request_id,
                    body_digest=body_digest,
                    peer=peer,
                    cfg_fp=rt.cfg_fp,
                )
                _GRPC_SUBJECT_STATUS.labels(method, subject_result.status).inc()
                if not subject_result.ok:
                    status_label = "bad_request"
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        "invalid subject identity",
                        request_id=request_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
                        verdict=False,
                        score=0.0,
                        threshold=0.0,
                        budget_remaining=0.0,
                        components=_bounded_json_dumps({"error": "invalid_subject", "status": subject_result.status, "warnings": list(subject_result.warnings)}, max_bytes=cfg.max_components_bytes),
                        cause="identity",
                        action="reject",
                        step=0,
                        e_value=1.0,
                        alpha_alloc=0.0,
                        alpha_spent=0.0,
                    )

                tenant, user, sess = subject_result.subject
                principal_hash = _hash_token(user, ctx="tcd:grpc:principal", n=16)
                event_id = _derive_event_id(
                    cfg_fp=rt.cfg_fp,
                    method_name=method,
                    subject_hash=subject_result.subject_hash,
                    principal_hash=principal_hash,
                    request_id=request_id,
                    idempotency_key=idem,
                    body_digest=body_digest,
                    bucket_s=cfg.idempotency_time_bucket_s,
                )
                _set_trailing_metadata(
                    context,
                    request_id=request_id,
                    event_id=event_id,
                    api_version=cfg.protocol.api_version,
                    schema_version=cfg.protocol.schema_version,
                )

                event_fingerprint = _event_fingerprint(
                    event_id=event_id,
                    request_id=request_id,
                    method_name=method,
                    body_digest=body_digest,
                    canonical_request_digest=_request_summary_digest(request, method_name=method, sec_ctx=sec_ctx),
                )
                reg_ok, reg_reason = rt.registry.register_event(
                    scope="grpc:event",
                    event_id=event_id,
                    event_digest=event_fingerprint,
                    method=method,
                    tenant_hash=_hash_token(tenant, ctx="tcd:grpc:tenant", n=16),
                    principal_hash=principal_hash,
                    request_id=request_id,
                )
                if not reg_ok:
                    _GRPC_REPLAY_REJECT.labels("event_id_conflict").inc()
                    status_label = "conflict"
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.ALREADY_EXISTS,
                        "idempotency conflict",
                        request_id=request_id,
                        event_id=event_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
                        verdict=False,
                        score=0.0,
                        threshold=0.0,
                        budget_remaining=0.0,
                        components=_bounded_json_dumps({"error": "idempotency_conflict", "reason": reg_reason}, max_bytes=cfg.max_components_bytes),
                        cause="conflict",
                        action="reject",
                        step=0,
                        e_value=1.0,
                        alpha_alloc=0.0,
                        alpha_spent=0.0,
                    )

                auth = rt.auth_adapter.authenticate(
                    method_name=method,
                    metadata={k: v for k, v in md.items() if k in set(cfg.metadata_allowlist)},
                    peer=peer,
                    body_bytes=body_bytes,
                    request_id=request_id,
                    event_id=event_id,
                    api_version=compat.api_version,
                    compatibility_epoch=compat.compatibility_epoch,
                    deadline_mono=(time.perf_counter() + (rem if (rem := (_time_remaining_s(context) or 0.0)) > 0 else 0.0)) if _time_remaining_s(context) is not None else None,
                )
                if not _enforce_method_authz(auth, cfg.diagnose_authz, peer):
                    status_label = "unauthenticated" if not auth.ok else "forbidden"
                    reason = "auth" if not auth.ok else "method_authz"
                    _GRPC_REQ_REJECTED.labels(method, reason).inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.UNAUTHENTICATED if not auth.ok else grpc.StatusCode.PERMISSION_DENIED,
                        "unauthorized" if not auth.ok else "forbidden",
                        request_id=request_id,
                        event_id=event_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
                        verdict=False,
                        score=0.0,
                        threshold=0.0,
                        budget_remaining=0.0,
                        components=_bounded_json_dumps({"error": reason, "reason": auth.reason or reason}, max_bytes=cfg.max_components_bytes),
                        cause="auth",
                        action="reject",
                        step=0,
                        e_value=1.0,
                        alpha_alloc=0.0,
                        alpha_spent=0.0,
                    )

                if len(request.trace_vector) > cfg.max_trace or len(request.spectrum) > cfg.max_spectrum or len(request.features) > cfg.max_features:
                    status_label = "payload_too_large"
                    _GRPC_REQ_REJECTED.labels(method, "vector_too_large").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        "payload too large",
                        request_id=request_id,
                        event_id=event_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
                        verdict=False,
                        score=0.0,
                        threshold=0.0,
                        budget_remaining=0.0,
                        components=_bounded_json_dumps({"error": "vector_too_large"}, max_bytes=cfg.max_components_bytes),
                        cause="limit",
                        action="reject",
                        step=0,
                        e_value=1.0,
                        alpha_alloc=0.0,
                        alpha_spent=0.0,
                    )

                cost = _rate_limit_cost(cfg, sec_ctx, request, sec_ctx.get("threat_kind"), sec_ctx.get("threat_confidence"))
                if not _consume_rate(rt, subject=subject_result.subject, principal_id=auth.principal, model_id=_safe_text(getattr(request, "model_id", "model0"), max_len=128) or "model0", cost=cost):
                    status_label = "rate_limited"
                    _GRPC_REQ_REJECTED.labels(method, "rate_limited").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.RESOURCE_EXHAUSTED,
                        "rate limited",
                        request_id=request_id,
                        event_id=event_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
                        verdict=False,
                        score=0.0,
                        threshold=0.0,
                        budget_remaining=0.0,
                        components=_bounded_json_dumps({"error": "rate_limited"}, max_bytes=cfg.max_components_bytes),
                        cause="rate",
                        action="reject",
                        step=0,
                        e_value=1.0,
                        alpha_alloc=0.0,
                        alpha_spent=0.0,
                    )

                trace_vec, _ = sanitize_floats(list(request.trace_vector), max_len=cfg.max_trace)
                spectrum, _ = sanitize_floats(list(request.spectrum), max_len=cfg.max_spectrum)
                features, _ = sanitize_floats(list(request.features), max_len=cfg.max_features)

                model_id = _safe_text(getattr(request, "model_id", "") or "model0", max_len=128)
                gpu_id = _safe_text(getattr(request, "gpu_id", "") or "gpu0", max_len=128)
                task = _safe_text(getattr(request, "task", "") or "chat", max_len=64)
                lang = _safe_text(getattr(request, "lang", "") or "en", max_len=32)
                risk_label = _safe_text(getattr(request, "risk_label", "") or "normal", max_len=32).lower() or "normal"
                base_temp = _clamp_float(getattr(request, "base_temp", None), default=float(getattr(rt.settings, "router_base_temp", 1.0) or 1.0), lo=0.0, hi=10.0)
                base_top_p = _clamp_float(getattr(request, "base_top_p", None), default=float(getattr(rt.settings, "router_base_top_p", 0.95) or 0.95), lo=0.0, hi=1.0)
                tokens_delta = float(getattr(request, "tokens_delta", 0.0) or 0.0)
                entropy = _coerce_float(getattr(request, "entropy", None)) if _has_field(request, "entropy") else None
                drift_score = _coerce_float(getattr(request, "drift_score", None)) or 0.0

                deadline_mono = None
                rem = _time_remaining_s(context)
                if rem is not None:
                    deadline_mono = time.perf_counter() + rem

                def _run_detector() -> Dict[str, Any]:
                    det = rt.get_detector((model_id, gpu_id, task, lang))
                    vp = det.diagnose(trace_vec, entropy, spectrum, step_id=(request.step_id if getattr(request, "step_id", "") else None))
                    return dict(vp) if isinstance(vp, Mapping) else {}

                try:
                    vp = _dep_call_with_retry(
                        dep="controller",
                        op="detector",
                        breaker=rt.br_controller,
                        executor=rt.exec_controller,
                        timeout_ms=cfg.controller_timeout_ms,
                        deadline_mono=deadline_mono,
                        policy=RetryPolicy(max_attempts=max(1, cfg.dep_retry_max), base_backoff_ms=cfg.dep_retry_base_ms),
                        fn=_run_detector,
                        idempotent=True,
                    )
                except _DepException as exc:
                    status_label = "unavailable" if exc.kind == "breaker_open" else "error"
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.UNAVAILABLE if exc.kind == "breaker_open" else grpc.StatusCode.INTERNAL,
                        "detector unavailable",
                        request_id=request_id,
                        event_id=event_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.RiskResponse(  # type: ignore[misc]
                        verdict=False,
                        score=0.0,
                        threshold=0.0,
                        budget_remaining=0.0,
                        components=_bounded_json_dumps({"error": "detector_unavailable", "kind": exc.kind, "phase": exc.phase}, max_bytes=cfg.max_components_bytes),
                        cause="detector",
                        action="reject",
                        step=0,
                        e_value=1.0,
                        alpha_alloc=0.0,
                        alpha_spent=0.0,
                    )

                det_components = dict(vp.get("components", {})) if isinstance(vp, Mapping) else {}
                score = float(vp.get("score", 0.0)) if isinstance(vp, Mapping) else 0.0
                det_trigger = bool(vp.get("verdict", False)) if isinstance(vp, Mapping) else False
                det_step = int(vp.get("step", 0)) if isinstance(vp, Mapping) else 0

                mv_info: Dict[str, Any] = {}
                if len(features) > 0:
                    with contextlib.suppress(Exception):
                        mv_info = dict(rt.get_mv(model_id).decision(features))

                threat_kind = sec_ctx.get("threat_kind")
                threat_conf = sec_ctx.get("threat_confidence")
                det_threat_kind = _normalize_threat_kind(det_components.get("threat_kind")) if isinstance(det_components.get("threat_kind"), str) else None
                det_threat_conf = _coerce_float(det_components.get("threat_confidence"))
                if threat_kind is None and det_threat_kind is not None:
                    threat_kind = det_threat_kind
                if det_threat_conf is not None:
                    threat_conf = max(threat_conf or 0.0, det_threat_conf) if threat_conf is not None else det_threat_conf

                drift_weight = 1.0 + 0.5 * drift_score
                if threat_kind in ("apt", "supply_chain") and (threat_conf or 0.0) >= 0.5:
                    drift_weight *= 1.5
                if sec_ctx["trust_zone"] == "admin" and threat_kind == "insider":
                    drift_weight *= 2.0
                drift_weight = max(0.0, min(2.0, drift_weight))

                av = rt.get_av(subject_result.subject)
                stream_id = f"{tenant}:{user}:{model_id}"
                av_out = av.step(
                    stream_id=stream_id,
                    policy_key=(task, lang, model_id),
                    subject=subject_result.subject,
                    scores={"final": score},
                    pvals={"final": _p_cons(score)},
                    drift_weight=drift_weight,
                    meta={
                        "trust_zone": sec_ctx["trust_zone"],
                        "route_profile": sec_ctx["route_profile"],
                        "threat_kind": threat_kind,
                        "pq_required": sec_ctx["pq_required"],
                        "asserted_tenant": subject_result.asserted.get("tenant"),
                        "asserted_user": subject_result.asserted.get("user"),
                        "asserted_session": subject_result.asserted.get("session"),
                        "identity_status": subject_result.status,
                    },
                )
                av_out = dict(av_out) if isinstance(av_out, Mapping) else {}
                av_trigger = bool(av_out.get("trigger", False))
                decision_fail = bool(det_trigger or av_trigger)
                e_state = av_out.get("e_state") if isinstance(av_out.get("e_state"), Mapping) else {}
                security_av = av_out.get("security") if isinstance(av_out.get("security"), Mapping) else {}
                controller_mode = _safe_text(security_av.get("controller_mode") if security_av else None, max_len=64) or None
                guarantee_scope = _safe_text(security_av.get("statistical_guarantee_scope") if security_av else None, max_len=64) or None
                if not controller_mode and isinstance(e_state, Mapping):
                    ctrl = e_state.get("controller")
                    if isinstance(ctrl, Mapping):
                        controller_mode = _safe_text(ctrl.get("controller_mode"), max_len=64) or None
                    validity = e_state.get("validity")
                    if isinstance(validity, Mapping):
                        guarantee_scope = guarantee_scope or (_safe_text(validity.get("statistical_guarantee_scope"), max_len=64) or None)

                detector_action = "block" if (decision_fail and threat_kind in ("apt", "supply_chain") and (threat_conf or 0.0) >= 0.9) else ("degrade" if decision_fail else "allow")

                security_decision = None
                route_dict: Dict[str, Any] = {}
                if rt.security_router is not None:
                    sig_env = None
                    if SecuritySignalEnvelope is not Any:
                        sig_env = SecuritySignalEnvelope(
                            source="grpc_service",
                            trusted=bool(auth.ok and auth.trusted),
                            signed=(auth.mode in {"hmac", "jwt", "mtls"}),
                            signer_kid=auth.key_id,
                            source_cfg_fp=None,
                            source_policy_ref=auth.policy_digest,
                            freshness_ms=None,
                            replay_checked=None,
                        )
                    auth_ctx = None
                    if SecurityAuthContext is not Any:
                        with contextlib.suppress(Exception):
                            auth_ctx = SecurityAuthContext(
                                principal_id=auth.principal,
                                roles=tuple(auth.roles),
                                scopes=tuple(auth.scopes),
                                access_channel="grpc",
                                approval_id=md.get("x-approval-id"),
                                approval_system=md.get("x-approval-system"),
                                mfa_verified=_coerce_bool(md.get("x-mfa-verified"), default=False),
                                trusted=bool(auth.trusted),
                                auth_strength=auth.authn_strength,
                            )

                    detector_packet = {
                        "risk_score": score,
                        "risk_label": risk_label,
                        "action": detector_action,
                        "trigger": decision_fail,
                        "controller_mode": controller_mode,
                        "guarantee_scope": guarantee_scope,
                        "av_label": _safe_text(getattr(getattr(av, "config", None), "label", None), max_len=64) or None,
                        "av_trigger": av_trigger,
                        "threat_tags": [threat_kind] if threat_kind else [],
                        "e_state": dict(e_state) if isinstance(e_state, Mapping) else {},
                        "security": dict(security_av) if isinstance(security_av, Mapping) else {},
                    }

                    sctx_kwargs: Dict[str, Any] = {
                        "subject": SubjectKey(tenant=tenant, user=user, session=sess, model_id=model_id),
                        "ctx": {
                            "tenant": tenant,
                            "user": user,
                            "session": sess,
                            "model_id": model_id,
                            "gpu_id": gpu_id,
                            "task": task,
                            "lang": lang,
                            "trust_zone": sec_ctx["trust_zone"],
                            "route": sec_ctx["route_profile"],
                            "client_app": "grpc",
                            "access_channel": "grpc",
                        },
                        "tokens_in": max(0, int(tokens_delta)),
                        "tokens_out": 0,
                        "ip": peer.peer_ip,
                        "kind": "inference",
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "event_id": event_id,
                        "tenant_id": tenant,
                        "principal_id": auth.principal or principal_hint,
                        "trust_zone": sec_ctx["trust_zone"],
                        "route_profile": sec_ctx["route_profile"],
                        "base_temp": base_temp,
                        "base_top_p": base_top_p,
                        "base_max_tokens": None,
                        "pq_required": bool(sec_ctx["pq_required"]),
                        "pq_unhealthy": False,
                        "signal_envelope": sig_env,
                        "auth_context": auth_ctx,
                        "meta": {
                            "classification": _safe_text(md.get("x-classification", ""), max_len=64) or None,
                            "client_app": "grpc",
                            "channel": "grpc",
                            "region": _safe_text(md.get("x-region", ""), max_len=64) or None,
                            "cluster": _safe_text(md.get("x-cluster", ""), max_len=64) or None,
                            "risk_source": "grpc_detector",
                            "workflow": "diagnose",
                            "compat_api_version": compat.api_version,
                            "compat_epoch": compat.compatibility_epoch,
                        },
                    }

                    if SecurityContext is not Any:
                        sctx = None
                        for drop_keys in ((), ("auth_context",), ("signal_envelope", "auth_context")):
                            try_kwargs = dict(sctx_kwargs)
                            for dk in drop_keys:
                                try_kwargs.pop(dk, None)
                            try:
                                sctx = SecurityContext(**try_kwargs)
                                break
                            except Exception:
                                continue
                        if sctx is not None:
                            with rt.detector_adapter.bind(detector_packet):
                                security_decision = rt.security_router.route(sctx)
                            if getattr(security_decision, "route", None) is not None and hasattr(security_decision.route, "to_dict"):
                                with contextlib.suppress(Exception):
                                    route_dict = dict(security_decision.route.to_dict())

                if security_decision is None:
                    # Fallback local route or synthetic degraded contract
                    try:
                        route_obj = rt.strategy_router.decide(
                            decision_fail=decision_fail,
                            score=score,
                            base_temp=base_temp,
                            base_top_p=base_top_p,
                            risk_label=risk_label,
                            route_profile=sec_ctx["route_profile"],
                            e_triggered=av_trigger,
                            trust_zone=sec_ctx["trust_zone"],
                            threat_kind=threat_kind,
                            pq_unhealthy=False,
                            av_label=_safe_text(getattr(getattr(av, "config", None), "label", None), max_len=64) or None,
                            av_trigger=av_trigger,
                            meta={
                                "request_id": request_id,
                                "trace_id": trace_id,
                                "event_id": event_id,
                                "tenant": tenant,
                                "user": user,
                                "session": sess,
                                "pq_required": sec_ctx["pq_required"],
                                "threat_confidence": threat_conf,
                                "build_id": sec_ctx["build_id"],
                                "image_digest": sec_ctx["image_digest"],
                            },
                        )
                        if hasattr(route_obj, "to_dict"):
                            with contextlib.suppress(Exception):
                                route_dict = dict(route_obj.to_dict())
                        elif dataclasses.is_dataclass(route_obj):
                            route_dict = dataclasses.asdict(route_obj)
                    except Exception:
                        route_dict = {
                            "schema": "tcd.route.synthetic.v1",
                            "router": "tcd.service_grpc",
                            "version": "1.0.0",
                            "config_fingerprint": rt.cfg_fp,
                            "bundle_version": 0,
                            "router_mode": "degraded",
                            "route_id_kind": "plan",
                            "route_plan_id": "rp1:sha256:" + _blake3_hex(_canonical_json_bytes({"event_id": event_id, "reason": "route_unavailable"}), ctx="tcd:grpc:route_plan")[:32],
                            "route_id": None,
                            "decision_id": "rd1:sha256:" + _blake3_hex(_canonical_json_bytes({"event_id": event_id, "reason": "route_unavailable"}), ctx="tcd:grpc:route_decision")[:32],
                            "decision_ts_unix_ns": time.time_ns(),
                            "decision_ts_mono_ns": time.monotonic_ns(),
                            "safety_tier": "strict" if decision_fail else "normal",
                            "required_action": "block" if decision_fail else "allow",
                            "action_hint": "block" if decision_fail else "allow",
                            "enforcement_mode": "fail_closed" if decision_fail else "advisory",
                            "temperature": 0.2 if decision_fail else base_temp,
                            "top_p": 0.4 if decision_fail else base_top_p,
                            "decoder": "safe" if decision_fail else "default",
                            "latency_hint": "high_safety" if decision_fail else "normal",
                            "trust_zone": sec_ctx["trust_zone"],
                            "route_profile": sec_ctx["route_profile"],
                            "risk_label": risk_label,
                            "score": score,
                            "decision_fail": decision_fail,
                            "e_triggered": av_trigger,
                            "pq_unhealthy": False,
                            "av_label": _safe_text(getattr(getattr(av, "config", None), "label", None), max_len=64) or None,
                            "av_trigger": av_trigger,
                            "threat_tags": [threat_kind] if threat_kind else [],
                            "controller_mode": controller_mode,
                            "guarantee_scope": guarantee_scope,
                            "signal_digest": "sg1:sha256:" + _blake3_hex(_canonical_json_bytes({"score": score, "decision_fail": decision_fail, "e_triggered": av_trigger, "threat_kind": threat_kind}), ctx="tcd:grpc:signal")[:32],
                            "context_digest": "cx1:sha256:" + _blake3_hex(_canonical_json_bytes({"trust_zone": sec_ctx["trust_zone"], "route_profile": sec_ctx["route_profile"], "request_id": request_id}), ctx="tcd:grpc:context")[:32],
                            "primary_reason_code": "ROUTE_UNAVAILABLE",
                            "reason_codes": ["ROUTE_UNAVAILABLE"],
                            "degraded_reason_codes": ["ROUTE_UNAVAILABLE"],
                            "reason": "route_unavailable",
                        }

                # Final decision surfaces
                if security_decision is not None:
                    required_action = _safe_text(getattr(security_decision, "required_action", None), max_len=16).lower() or "allow"
                    response_verdict = required_action != "allow"
                    action_label = _decision_to_action(security_decision)
                    cause = _safe_text(
                        getattr(security_decision, "primary_reason_code", None)
                        or getattr(security_decision, "reason", None)
                        or ("av" if av_trigger else "detector"),
                        max_len=128,
                    )
                    score_out = float(getattr(security_decision, "risk_score", None) if getattr(security_decision, "risk_score", None) is not None else score)
                    step_out = int(getattr(security_decision, "decision_seq", 0) or 0)
                    policy_ref = getattr(security_decision, "policy_ref", None)
                    policyset_ref = getattr(security_decision, "policyset_ref", None)
                    config_fp = getattr(security_decision, "config_fingerprint", None)
                    bundle_version = getattr(security_decision, "bundle_version", None)
                    decision_id = getattr(security_decision, "decision_id", None)
                    route_plan_id = getattr(security_decision, "route_plan_id", None)
                    audit_ref = getattr(security_decision, "audit_ref", None)
                    receipt_ref = getattr(security_decision, "receipt_ref", None)
                    route_public = None
                    if getattr(security_decision, "route", None) is not None and hasattr(security_decision.route, "to_dict"):
                        with contextlib.suppress(Exception):
                            route_public = dict(security_decision.route.to_dict())
                    components = {
                        "detector": det_components,
                        "multivariate": mv_info,
                        "e_process": e_state,
                        "route": route_public or route_dict,
                        "security_router": security_decision.to_public_view() if hasattr(security_decision, "to_public_view") else {},
                        "security": dict(getattr(security_decision, "security", {}) or {}),
                        "evidence_identity": dict(getattr(security_decision, "evidence_identity", {}) or {}),
                        "artifacts": dict(getattr(security_decision, "artifacts", {}) or {}),
                        "auth": auth.to_public_dict(record_principal=cfg.record_raw_principal, record_key_id=cfg.record_raw_key_id) if auth.ok else {},
                        "peer": {
                            "peer_hash": peer.peer_hash,
                            "mtls_present": peer.mtls_present,
                            "spiffe_ids": list(peer.spiffe_ids[:8]),
                        },
                        "request": {
                            "request_id": request_id,
                            "trace_id": trace_id,
                            "event_id": event_id,
                            "body_digest": body_digest,
                            "peer_ip_hash": _hash_token(peer.peer_ip, ctx="tcd:grpc:peer", n=12) if peer.peer_ip not in {"", "unknown"} else None,
                            "subject_status": subject_result.status,
                        },
                    }
                else:
                    required_action = _safe_text(route_dict.get("required_action"), max_len=16).lower() or ("block" if decision_fail else "allow")
                    response_verdict = required_action != "allow"
                    action_label = _manual_route_action(None, decision_fail, threat_kind=threat_kind, threat_conf=threat_conf, pq_required=sec_ctx["pq_required"], pq_ok=route_dict.get("pq_ok"))
                    cause = _safe_text(route_dict.get("primary_reason_code") or ("detector" if det_trigger else ("av" if av_trigger else "balanced")), max_len=128)
                    score_out = score
                    step_out = det_step
                    policy_ref = route_dict.get("policy_ref")
                    policyset_ref = route_dict.get("policyset_ref")
                    config_fp = route_dict.get("config_fingerprint")
                    bundle_version = route_dict.get("bundle_version")
                    decision_id = route_dict.get("decision_id")
                    route_plan_id = route_dict.get("route_plan_id") or route_dict.get("route_id")
                    audit_ref = None
                    receipt_ref = None
                    components = {
                        "detector": det_components,
                        "multivariate": mv_info,
                        "e_process": e_state,
                        "route": route_dict,
                        "security": {
                            "trust_zone": sec_ctx["trust_zone"],
                            "route_profile": sec_ctx["route_profile"],
                            "threat_kind": threat_kind,
                            "threat_confidence": threat_conf,
                            "pq_required": sec_ctx["pq_required"],
                            "pq_ok": route_dict.get("pq_ok"),
                            "policy_ref": policy_ref,
                            "route_id": route_plan_id,
                            "build_id": sec_ctx["build_id"],
                            "image_digest": sec_ctx["image_digest"],
                            "compliance_tags": list(sec_ctx["compliance_tags"]),
                        },
                        "auth": auth.to_public_dict(record_principal=cfg.record_raw_principal, record_key_id=cfg.record_raw_key_id) if auth.ok else {},
                        "peer": {
                            "peer_hash": peer.peer_hash,
                            "mtls_present": peer.mtls_present,
                            "spiffe_ids": list(peer.spiffe_ids[:8]),
                        },
                        "request": {
                            "request_id": request_id,
                            "trace_id": trace_id,
                            "event_id": event_id,
                            "body_digest": body_digest,
                            "peer_ip_hash": _hash_token(peer.peer_ip, ctx="tcd:grpc:peer", n=12) if peer.peer_ip not in {"", "unknown"} else None,
                            "subject_status": subject_result.status,
                        },
                    }

                # Service-level evidence closure: prepare -> attest -> commit
                ledger_stage = "skipped"
                outbox_status = "none"
                receipt_public = None

                receipt_required = bool(route_dict.get("receipt_required")) or bool(cfg.require_attestor) or bool(response_verdict)
                ledger_required = bool(route_dict.get("ledger_required")) or bool(cfg.require_ledger)
                attestation_required = bool(route_dict.get("attestation_required")) or bool(cfg.require_attestor)

                if _client_active(context) or receipt_required or ledger_required or attestation_required:
                    evidence_identity = {
                        "event_id": event_id,
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "decision_id": decision_id,
                        "route_plan_id": route_plan_id,
                        "policy_ref": policy_ref,
                        "policyset_ref": policyset_ref,
                        "config_fingerprint": config_fp,
                        "bundle_version": bundle_version,
                    }
                    prepare_payload = {
                        "type": "grpc.diagnose.prepare",
                        "event_id": event_id,
                        "request_id": request_id,
                        "trace_id": trace_id,
                        "method": method,
                        "cfg_fp": rt.cfg_fp,
                        "request_body_digest": body_digest,
                        "event_fingerprint": event_fingerprint,
                        "peer_hash": peer.peer_hash,
                        "subject_hash": subject_result.subject_hash,
                        "principal_hash": _hash_token(auth.principal, ctx="tcd:grpc:principal", n=16) if auth.principal else None,
                        "trust_zone": sec_ctx["trust_zone"],
                        "route_profile": sec_ctx["route_profile"],
                        "action": action_label,
                        "required_action": required_action,
                        "score": score_out,
                        "evidence_identity": evidence_identity,
                    }

                    if rt.ledger is not None:
                        try:
                            def _ledger_prepare() -> Any:
                                if hasattr(rt.ledger, "append_ex"):
                                    return rt.ledger.append_ex(prepare_payload, stage="prepare")  # type: ignore[attr-defined]
                                return rt.ledger.append(prepare_payload)  # type: ignore[attr-defined]

                            remaining = _time_remaining_s(context)
                            deadline_mono = (time.perf_counter() + remaining) if remaining is not None else None
                            res = _dep_call_with_retry(
                                dep="ledger",
                                op="prepare",
                                breaker=rt.br_ledger,
                                executor=rt.exec_ledger,
                                timeout_ms=cfg.ledger_timeout_ms,
                                deadline_mono=deadline_mono,
                                policy=RetryPolicy(max_attempts=max(1, cfg.dep_retry_max), base_backoff_ms=cfg.dep_retry_base_ms),
                                fn=_ledger_prepare,
                                idempotent=True,
                            )
                            ledger_stage = "prepared"
                            audit_ref = getattr(res, "head", None) or audit_ref
                        except _DepException:
                            ledger_stage = "prepare_failed"
                            _GRPC_LEDGER_ERROR.labels(method, "prepare").inc()
                            if ledger_required or cfg.strict_mode:
                                status_label = "unavailable"
                                _set_grpc_error(
                                    context,
                                    grpc.StatusCode.UNAVAILABLE,
                                    "ledger prepare failed",
                                    request_id=request_id,
                                    event_id=event_id,
                                    api_version=cfg.protocol.api_version,
                                    schema_version=cfg.protocol.schema_version,
                                )
                                return pb.RiskResponse(  # type: ignore[misc]
                                    verdict=True,
                                    score=score_out,
                                    threshold=float(av_out.get("threshold", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                    budget_remaining=float(av_out.get("alpha_wealth", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                    components=_bounded_json_dumps({"error": "ledger_prepare_failed", "event_id": event_id}, max_bytes=cfg.max_components_bytes),
                                    cause="ledger",
                                    action="reject",
                                    step=step_out,
                                    e_value=float(av_out.get("e_value", 1.0)) if isinstance(av_out, Mapping) else 1.0,
                                    alpha_alloc=float(av_out.get("alpha_alloc", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                    alpha_spent=float(av_out.get("alpha_spent", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                )
                            elif rt.outbox is not None:
                                outbox_payload = {"type": "grpc.ledger.prepare", "event_id": event_id, "payload": prepare_payload}
                                payload_json = _canonical_json(outbox_payload)
                                payload_digest = _blake3_hex(payload_json.encode("utf-8", errors="strict"), ctx="tcd:grpc:outbox")
                                outbox_status = rt.outbox.put(kind="ledger", dedupe_key=f"{event_id}:prepare", payload_json=payload_json, payload_digest=payload_digest)

                    if receipt_required and rt.attestor is not None:
                        req_obj = {
                            "ts_ns": time.time_ns(),
                            "request_id": request_id,
                            "trace_id": trace_id,
                            "event_id": event_id,
                            "peer_hash": peer.peer_hash,
                            "subject_hash": subject_result.subject_hash,
                            "subject_status": subject_result.status,
                        }
                        comp_obj = {
                            "kind": "grpc_diagnose",
                            "action": action_label,
                            "required_action": required_action,
                            "reason": cause,
                            "score": score_out,
                            "policy_ref": policy_ref,
                            "policyset_ref": policyset_ref,
                            "route_plan_id": route_plan_id,
                            "decision_id": decision_id,
                        }
                        e_obj = {
                            "e_state": dict(e_state) if isinstance(e_state, Mapping) else {},
                            "controller_mode": controller_mode,
                            "guarantee_scope": guarantee_scope,
                        }
                        witness_segments = [
                            {
                                "kind": "grpc_request",
                                "id": event_id,
                                "digest": body_digest,
                                "meta": {"request_id": request_id, "trace_id": trace_id},
                            }
                        ]
                        if route_plan_id:
                            witness_segments.append(
                                {
                                    "kind": "route_plan",
                                    "id": route_plan_id,
                                    "digest": route_plan_id,
                                    "meta": {"decision_id": decision_id, "policy_ref": policy_ref},
                                }
                            )
                        att_meta = {
                            "event_id": event_id,
                            "request_id": request_id,
                            "trace_id": trace_id,
                            "cfg_fp": rt.cfg_fp,
                            "policy_ref": policy_ref,
                            "policyset_ref": policyset_ref,
                            "state_domain_id": (e_state.get("controller", {}) or {}).get("state_domain_id") if isinstance(e_state, Mapping) else None,
                            "adapter_registry_fp": (e_state.get("controller", {}) or {}).get("adapter_registry_fp") if isinstance(e_state, Mapping) else None,
                            "route_profile": sec_ctx["route_profile"],
                            "trust_zone": sec_ctx["trust_zone"],
                            "audit_ref": audit_ref,
                            "build_id": rt.build_id,
                            "image_digest": rt.image_digest,
                        }

                        try:
                            def _attest_issue() -> Any:
                                return rt.attestor.issue(  # type: ignore[attr-defined]
                                    req_obj=req_obj,
                                    comp_obj=comp_obj,
                                    e_obj=e_obj,
                                    witness_segments=witness_segments,
                                    witness_tags=["grpc", method.lower(), action_label],
                                    meta=att_meta,
                                )

                            remaining = _time_remaining_s(context)
                            deadline_mono = (time.perf_counter() + remaining) if remaining is not None else None
                            att_payload = _dep_call_with_retry(
                                dep="attestor",
                                op="issue",
                                breaker=rt.br_attestor,
                                executor=rt.exec_attest,
                                timeout_ms=cfg.attestor_timeout_ms,
                                deadline_mono=deadline_mono,
                                policy=RetryPolicy(max_attempts=max(1, cfg.dep_retry_max), base_backoff_ms=cfg.dep_retry_base_ms),
                                fn=_attest_issue,
                                idempotent=True,
                            )
                            if isinstance(att_payload, Mapping):
                                receipt_ref = att_payload.get("receipt") or att_payload.get("receipt_ref") or receipt_ref
                                receipt_public = _receipt_public_from_mapping(att_payload)
                        except _DepException:
                            if attestation_required or cfg.strict_mode:
                                status_label = "unavailable"
                                _set_grpc_error(
                                    context,
                                    grpc.StatusCode.UNAVAILABLE,
                                    "attestation failed",
                                    request_id=request_id,
                                    event_id=event_id,
                                    api_version=cfg.protocol.api_version,
                                    schema_version=cfg.protocol.schema_version,
                                )
                                return pb.RiskResponse(  # type: ignore[misc]
                                    verdict=True,
                                    score=score_out,
                                    threshold=float(av_out.get("threshold", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                    budget_remaining=float(av_out.get("alpha_wealth", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                    components=_bounded_json_dumps({"error": "attestation_failed", "event_id": event_id}, max_bytes=cfg.max_components_bytes),
                                    cause="attestation",
                                    action="reject",
                                    step=step_out,
                                    e_value=float(av_out.get("e_value", 1.0)) if isinstance(av_out, Mapping) else 1.0,
                                    alpha_alloc=float(av_out.get("alpha_alloc", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                    alpha_spent=float(av_out.get("alpha_spent", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                )
                            elif rt.outbox is not None:
                                payload = {"type": "grpc.attest.issue", "event_id": event_id, "meta": att_meta}
                                pj = _canonical_json(payload)
                                pd = _blake3_hex(pj.encode("utf-8", errors="strict"), ctx="tcd:grpc:outbox")
                                outbox_status = rt.outbox.put(kind="evidence", dedupe_key=f"{event_id}:attest", payload_json=pj, payload_digest=pd)

                    if rt.ledger is not None and ledger_stage == "prepared":
                        commit_payload = {
                            "type": "grpc.diagnose.commit",
                            "event_id": event_id,
                            "request_id": request_id,
                            "trace_id": trace_id,
                            "cfg_fp": rt.cfg_fp,
                            "action": action_label,
                            "score": score_out,
                            "route_plan_id": route_plan_id,
                            "decision_id": decision_id,
                            "receipt_ref": receipt_ref,
                            "audit_ref": audit_ref,
                        }
                        try:
                            def _ledger_commit() -> Any:
                                if hasattr(rt.ledger, "append_ex"):
                                    return rt.ledger.append_ex(commit_payload, stage="commit")  # type: ignore[attr-defined]
                                return rt.ledger.append(commit_payload)  # type: ignore[attr-defined]

                            remaining = _time_remaining_s(context)
                            deadline_mono = (time.perf_counter() + remaining) if remaining is not None else None
                            res2 = _dep_call_with_retry(
                                dep="ledger",
                                op="commit",
                                breaker=rt.br_ledger,
                                executor=rt.exec_ledger,
                                timeout_ms=cfg.ledger_timeout_ms,
                                deadline_mono=deadline_mono,
                                policy=RetryPolicy(max_attempts=max(1, cfg.dep_retry_max), base_backoff_ms=cfg.dep_retry_base_ms),
                                fn=_ledger_commit,
                                idempotent=True,
                            )
                            ledger_stage = "committed"
                            audit_ref = getattr(res2, "head", None) or audit_ref
                        except _DepException:
                            ledger_stage = "commit_failed"
                            _GRPC_LEDGER_ERROR.labels(method, "commit").inc()
                            if ledger_required or cfg.strict_mode:
                                status_label = "unavailable"
                                _set_grpc_error(
                                    context,
                                    grpc.StatusCode.UNAVAILABLE,
                                    "ledger commit failed",
                                    request_id=request_id,
                                    event_id=event_id,
                                    api_version=cfg.protocol.api_version,
                                    schema_version=cfg.protocol.schema_version,
                                )
                                return pb.RiskResponse(  # type: ignore[misc]
                                    verdict=True,
                                    score=score_out,
                                    threshold=float(av_out.get("threshold", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                    budget_remaining=float(av_out.get("alpha_wealth", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                    components=_bounded_json_dumps({"error": "ledger_commit_failed", "event_id": event_id}, max_bytes=cfg.max_components_bytes),
                                    cause="ledger",
                                    action="reject",
                                    step=step_out,
                                    e_value=float(av_out.get("e_value", 1.0)) if isinstance(av_out, Mapping) else 1.0,
                                    alpha_alloc=float(av_out.get("alpha_alloc", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                    alpha_spent=float(av_out.get("alpha_spent", 0.0)) if isinstance(av_out, Mapping) else 0.0,
                                )
                            elif rt.outbox is not None:
                                payload = {"type": "grpc.ledger.commit", "event_id": event_id, "payload": commit_payload}
                                pj = _canonical_json(payload)
                                pd = _blake3_hex(pj.encode("utf-8", errors="strict"), ctx="tcd:grpc:outbox")
                                outbox_status = rt.outbox.put(kind="ledger", dedupe_key=f"{event_id}:commit", payload_json=pj, payload_digest=pd)

                components["decision"] = {
                    "request_id": request_id,
                    "trace_id": trace_id,
                    "event_id": event_id,
                    "policy_ref": policy_ref,
                    "policyset_ref": policyset_ref,
                    "config_fingerprint": config_fp,
                    "bundle_version": bundle_version,
                    "decision_id": decision_id,
                    "route_plan_id": route_plan_id,
                    "receipt_ref": receipt_ref,
                    "audit_ref": audit_ref,
                    "controller_mode": controller_mode,
                    "statistical_guarantee_scope": guarantee_scope,
                    "ledger_stage": ledger_stage,
                    "outbox_status": outbox_status,
                    "protocol": {
                        "api_version": compat.api_version,
                        "client_version": compat.client_version,
                        "compatibility_epoch": compat.compatibility_epoch,
                        "client_capabilities": list(compat.client_capabilities),
                    },
                }
                components.setdefault("security", {})
                if isinstance(components["security"], dict):
                    components["security"].update(
                        {
                            "trust_zone": sec_ctx["trust_zone"],
                            "route_profile": sec_ctx["route_profile"],
                            "threat_kind": threat_kind,
                            "threat_confidence": threat_conf,
                            "pq_required": sec_ctx["pq_required"],
                            "build_id": sec_ctx["build_id"],
                            "image_digest": sec_ctx["image_digest"],
                            "compliance_tags": list(sec_ctx["compliance_tags"]),
                        }
                    )
                if receipt_public is not None:
                    components["receipt_public"] = receipt_public

                components_json = _bounded_json_dumps(
                    _sanitize_components(
                        components,
                        max_depth=6,
                        max_items=128,
                        max_str_len=1024,
                        max_total_bytes=cfg.max_components_bytes,
                    ),
                    max_bytes=cfg.max_components_bytes,
                )

                raw_out = {
                    "verdict": bool(response_verdict),
                    "decision": "block" if action_label == "block" else ("degrade" if action_label == "degrade" else "allow"),
                    "cause": _safe_text(cause, max_len=128),
                    "action": action_label if action_label in {"block", "degrade"} else "none",
                    "score": float(score_out),
                    "threshold": float(av_out.get("threshold", 0.0)),
                    "budget_remaining": float(av_out.get("alpha_wealth", 0.0)),
                    "step": int(step_out),
                    "e_value": float(av_out.get("e_value", 1.0)),
                    "alpha_alloc": float(av_out.get("alpha_alloc", 0.0)),
                    "alpha_spent": float(av_out.get("alpha_spent", 0.0)),
                    "components": _sanitize_components(
                        components,
                        max_depth=6,
                        max_items=128,
                        max_str_len=1024,
                        max_total_bytes=cfg.max_components_bytes,
                    ),
                    "e_state": e_state,
                    "route": route_dict,
                    "trust_zone": sec_ctx["trust_zone"],
                    "route_profile": sec_ctx["route_profile"],
                    "threat_kind": threat_kind,
                    "threat_confidence": threat_conf,
                    "pq_required": bool(sec_ctx["pq_required"]),
                    "pq_ok": route_dict.get("pq_ok") if isinstance(route_dict, Mapping) else None,
                    "policy_ref": policy_ref,
                    "policyset_ref": policyset_ref,
                    "config_fingerprint": config_fp,
                    "bundle_version": bundle_version,
                    "decision_id": decision_id,
                    "route_plan_id": route_plan_id,
                    "event_id": event_id,
                    "audit_ref": audit_ref,
                    "receipt_ref": receipt_ref,
                    "controller_mode": controller_mode,
                    "statistical_guarantee_scope": guarantee_scope,
                }
                _ = _normalize_out(raw_out)

                with contextlib.suppress(Exception):
                    rt.prom.observe_latency(max(0.0, time.perf_counter() - t0))
                with contextlib.suppress(Exception):
                    rt.prom.push(vp, labels={"model_id": model_id, "gpu_id": gpu_id})
                with contextlib.suppress(Exception):
                    rt.prom.push_eprocess(
                        model_id=model_id,
                        gpu_id=gpu_id,
                        tenant=tenant,
                        user=user,
                        session=sess,
                        e_value=float(av_out.get("e_value", 1.0)),
                        alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
                        alpha_wealth=float(av_out.get("alpha_wealth", 0.0)),
                    )
                with contextlib.suppress(Exception):
                    rt.prom.update_budget_metrics(tenant, user, sess, remaining=float(av_out.get("alpha_wealth", 0.0)), spent=bool(av_out.get("alpha_spent", 0.0) > 0.0))
                with contextlib.suppress(Exception):
                    if action_label in {"degrade", "block"}:
                        rt.prom.record_action(model_id, gpu_id, action=action_label)
                with contextlib.suppress(Exception):
                    slo_ms = float(getattr(rt.settings, "slo_latency_ms", 0.0) or 0.0)
                    lat_ms = (time.perf_counter() - t0) * 1000.0
                    if slo_ms and lat_ms > slo_ms:
                        rt.prom.slo_violation_by_model("diagnose_latency", model_id, gpu_id)

                return pb.RiskResponse(  # type: ignore[misc]
                    verdict=bool(response_verdict),
                    score=float(score_out),
                    threshold=float(av_out.get("threshold", 0.0)),
                    budget_remaining=float(av_out.get("alpha_wealth", 0.0)),
                    components=components_json,
                    cause=_safe_text(cause, max_len=128),
                    action=action_label if action_label in {"block", "degrade"} else "none",
                    step=int(step_out),
                    e_value=float(av_out.get("e_value", 1.0)),
                    alpha_alloc=float(av_out.get("alpha_alloc", 0.0)),
                    alpha_spent=float(av_out.get("alpha_spent", 0.0)),
                )

            except Exception as e:
                status_label = "error"
                _GRPC_REQ_ERROR.labels(method, ERR_INTERNAL).inc()
                if cfg.debug_errors:
                    logger.exception("grpc diagnose failed")
                _set_grpc_error(
                    context,
                    grpc.StatusCode.INTERNAL,
                    "internal error",
                    request_id=request_id or None,
                    event_id=event_id or None,
                    api_version=cfg.protocol.api_version,
                    schema_version=cfg.protocol.schema_version,
                )
                return pb.RiskResponse(  # type: ignore[misc]
                    verdict=False,
                    score=0.0,
                    threshold=0.0,
                    budget_remaining=0.0,
                    components=_bounded_json_dumps({"error": "internal", "detail": _safe_text(e, max_len=96)}, max_bytes=cfg.max_components_bytes),
                    cause="internal",
                    action="reject",
                    step=0,
                    e_value=1.0,
                    alpha_alloc=0.0,
                    alpha_spent=0.0,
                )
            finally:
                dur = time.perf_counter() - t0
                _GRPC_REQ_LATENCY.labels(method, status_label, action_label).observe(dur)
                _GRPC_REQ_TOTAL.labels(method, status_label).inc()
                if gate_ok:
                    with contextlib.suppress(Exception):
                        rt.gate_diagnose.release()
                if cfg.log_requests:
                    try:
                        log_obj = {
                            "msg": "grpc_diagnose",
                            "method": method,
                            "request_id": _safe_text(request_id, max_len=96),
                            "event_id": _safe_text(event_id, max_len=96),
                            "status": status_label,
                            "action": action_label,
                            "dur_ms": round(dur * 1000.0, 3),
                            "node_id": rt.node_id,
                            "proc_id": rt.proc_id,
                            "peer_ip_hash": _hash_token(_peer_ip(context), ctx="tcd:grpc:peer", n=12),
                        }
                        if rt.outbox is not None:
                            st = rt.outbox.stats(kind="ledger", now_ts=time.time())
                            log_obj["outbox_depth"] = int(st.get("total", 0))
                            log_obj["outbox_oldest_age_s"] = round(float(st.get("oldest_age_s", 0.0)), 3)
                        logger.info("%s", _canonical_json(log_obj))
                    except Exception:
                        pass

        def Verify(self, request: Any, context: Any) -> Any:
            rt = self._rt
            cfg = rt.cfg
            method = "Verify"
            t0 = time.perf_counter()
            status_label = "ok"
            gate_ok = False
            request_id = ""

            try:
                if not _has_time_remaining(context):
                    status_label = "timeout"
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.DEADLINE_EXCEEDED,
                        "deadline exceeded",
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.VerifyResponse(ok=False)  # type: ignore[misc]

                gate_ok = rt.gate_verify.acquire(cfg.gate_wait_ms)
                if not gate_ok:
                    status_label = "overloaded"
                    _GRPC_GATE_REJECT.labels(method, "inflight").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.RESOURCE_EXHAUSTED,
                        "server overloaded",
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.VerifyResponse(ok=False)  # type: ignore[misc]

                md = _metadata_dict(context)
                md_bytes = _metadata_size_bytes(md)
                _GRPC_METADATA_BYTES.labels(method).observe(float(md_bytes))
                if len(md) > cfg.max_metadata_items or md_bytes > cfg.max_metadata_bytes:
                    status_label = "bad_request"
                    _GRPC_REQ_REJECTED.labels(method, "metadata_too_large").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        "metadata too large",
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.VerifyResponse(ok=False)  # type: ignore[misc]

                body_bytes = _deterministic_proto_bytes(request)
                _GRPC_REQ_PAYLOAD_BYTES.labels(method).observe(float(len(body_bytes)))
                if len(body_bytes) > cfg.max_proto_bytes:
                    status_label = "payload_too_large"
                    _GRPC_REQ_REJECTED.labels(method, "payload_too_large").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        "payload too large",
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.VerifyResponse(ok=False)  # type: ignore[misc]

                peer = _extract_peer_identity(context)
                subject_legacy, request_id, trace_id, idem, principal_hint = _resolve_subject_and_request(context, request)
                compat = _resolve_protocol_compat(method, request, md, cfg.protocol)
                if not compat.ok:
                    status_label = "bad_request"
                    _GRPC_PROTO_REJECT.labels(method, compat.reason or "protocol").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        "protocol compatibility rejected",
                        request_id=request_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.VerifyResponse(ok=False)  # type: ignore[misc]

                subject_result = _parse_subject_identity(
                    context,
                    request,
                    policy=cfg.subject_policy,
                    request_id=request_id,
                    body_digest=_blake3_hex(body_bytes, ctx="tcd:grpc:verify:body"),
                    peer=peer,
                    cfg_fp=rt.cfg_fp,
                )
                _GRPC_SUBJECT_STATUS.labels(method, subject_result.status).inc()
                if not subject_result.ok:
                    status_label = "bad_request"
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        "invalid subject identity",
                        request_id=request_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.VerifyResponse(ok=False)  # type: ignore[misc]

                auth = rt.auth_adapter.authenticate(
                    method_name=method,
                    metadata={k: v for k, v in md.items() if k in set(cfg.metadata_allowlist)},
                    peer=peer,
                    body_bytes=body_bytes,
                    request_id=request_id,
                    event_id="",
                    api_version=compat.api_version,
                    compatibility_epoch=compat.compatibility_epoch,
                    deadline_mono=(time.perf_counter() + (rem if (rem := (_time_remaining_s(context) or 0.0)) > 0 else 0.0)) if _time_remaining_s(context) is not None else None,
                )
                if not _enforce_method_authz(auth, cfg.verify_authz, peer):
                    status_label = "unauthenticated" if not auth.ok else "forbidden"
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.UNAUTHENTICATED if not auth.ok else grpc.StatusCode.PERMISSION_DENIED,
                        "unauthorized" if not auth.ok else "forbidden",
                        request_id=request_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.VerifyResponse(ok=False)  # type: ignore[misc]

                subject = subject_result.subject
                if not _consume_rate(rt, subject=subject, principal_id=auth.principal, model_id="verify", cost=1.0):
                    status_label = "rate_limited"
                    _GRPC_REQ_REJECTED.labels(method, "rate_limited").inc()
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.RESOURCE_EXHAUSTED,
                        "rate limited",
                        request_id=request_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.VerifyResponse(ok=False)  # type: ignore[misc]

                sec_ctx = _normalize_security_context(context, request, cfg)

                def _build_verify_payload() -> Dict[str, Any]:
                    has_chain = (len(request.heads) > 0) or (len(request.bodies) > 0)
                    if has_chain:
                        if len(request.heads) != len(request.bodies) or len(request.heads) == 0:
                            raise ValueError("heads/bodies must align and be non-empty")
                        if len(request.heads) > cfg.max_verify_chain_items:
                            raise ValueError("window too large")
                        total_bytes = 0
                        heads: List[str] = []
                        bodies: List[str] = []
                        for h, b in zip(list(request.heads), list(request.bodies)):
                            hs = _safe_text(h, max_len=130)
                            bs = _safe_text(b, max_len=cfg.max_verify_body_bytes * 2)
                            total_bytes += len(hs.encode("utf-8", errors="ignore")) + len(bs.encode("utf-8", errors="ignore"))
                            if total_bytes > cfg.max_verify_total_bytes:
                                raise ValueError("chain too large")
                            heads.append(hs)
                            bodies.append(bs)
                        return {"mode": "chain", "heads": heads, "bodies": bodies}

                    if not request.receipt_head_hex or not request.receipt_body_json:
                        raise ValueError("missing receipt head/body")

                    body_json = str(request.receipt_body_json)
                    if len(body_json.encode("utf-8", errors="ignore")) > cfg.max_verify_body_bytes:
                        raise ValueError("receipt body too large")

                    witness = None
                    wlen = len(request.witness_trace) + len(request.witness_spectrum) + len(request.witness_feat)
                    if wlen > (_MAX_TRACE + _MAX_SPECT + _MAX_FEATS):
                        raise ValueError("witness too large")
                    if wlen > 0:
                        witness = (
                            [int(x) for x in request.witness_trace],
                            [int(x) for x in request.witness_spectrum],
                            [int(x) for x in request.witness_feat],
                        )

                    def _maybe(obj: str) -> Optional[Dict[str, Any]]:
                        if not obj:
                            return None
                        parsed = json.loads(obj)
                        return parsed if isinstance(parsed, dict) else None

                    return {
                        "mode": "receipt",
                        "receipt_head_hex": str(request.receipt_head_hex),
                        "receipt_body_json": body_json,
                        "verify_key_hex": str(request.verify_key_hex) if request.verify_key_hex else None,
                        "receipt_sig_hex": str(request.receipt_sig_hex) if request.receipt_sig_hex else None,
                        "req_obj": _maybe(request.req_json),
                        "comp_obj": _maybe(request.comp_json),
                        "e_obj": _maybe(request.e_json),
                        "witness_segments": witness,
                    }

                try:
                    verify_payload = _build_verify_payload()
                except ValueError as e:
                    status_label = "bad_request"
                    _set_grpc_error(
                        context,
                        grpc.StatusCode.INVALID_ARGUMENT,
                        _safe_text(e, max_len=128),
                        request_id=request_id,
                        api_version=cfg.protocol.api_version,
                        schema_version=cfg.protocol.schema_version,
                    )
                    return pb.VerifyResponse(ok=False)  # type: ignore[misc]

                remaining = _time_remaining_s(context)
                verify_timeout_ms = cfg.verify_timeout_ms
                if remaining is not None:
                    verify_timeout_ms = min(verify_timeout_ms, max(1, int(remaining * 1000.0) - 25))

                if cfg.verify_hard_timeout_mode == "process":
                    timeout_s = max(0.001, verify_timeout_ms / 1000.0)
                    res = _verify_via_process(verify_payload, timeout_s=timeout_s, start_method=cfg.verify_process_start_method)
                    if not bool(res.get("ok", False)):
                        kind = _safe_text(res.get("kind", "verify_false"), max_len=32)
                        if kind == "timeout":
                            status_label = "timeout"
                            _set_grpc_error(context, grpc.StatusCode.DEADLINE_EXCEEDED, "verification timeout", request_id=request_id)
                            return pb.VerifyResponse(ok=False)  # type: ignore[misc]
                        status_label = "error" if kind in {"exception", "missing_result"} else "bad_request"
                        _set_grpc_error(
                            context,
                            grpc.StatusCode.INTERNAL if status_label == "error" else grpc.StatusCode.INVALID_ARGUMENT,
                            "verification failed",
                            request_id=request_id,
                        )
                        return pb.VerifyResponse(ok=False)  # type: ignore[misc]
                    ok = True
                else:
                    deadline_mono = (time.perf_counter() + remaining) if remaining is not None else None

                    def _verify_impl() -> bool:
                        if verify_payload["mode"] == "chain":
                            return bool(verify_chain(verify_payload["heads"], verify_payload["bodies"]))
                        ok_local = bool(
                            verify_receipt(
                                receipt_head_hex=str(verify_payload["receipt_head_hex"]),
                                receipt_body_json=str(verify_payload["receipt_body_json"]),
                                verify_key_hex=(str(verify_payload["verify_key_hex"]) if verify_payload.get("verify_key_hex") else None),
                                receipt_sig_hex=(str(verify_payload["receipt_sig_hex"]) if verify_payload.get("receipt_sig_hex") else None),
                                req_obj=verify_payload.get("req_obj"),
                                comp_obj=verify_payload.get("comp_obj"),
                                e_obj=verify_payload.get("e_obj"),
                                witness_segments=verify_payload.get("witness_segments"),
                                strict=True,
                            )
                        )
                        if not ok_local:
                            return False
                        try:
                            body_obj = json.loads(str(verify_payload["receipt_body_json"]))
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

                        pq_required_eff = bool(
                            (sec_block.get("pq_required") if isinstance(sec_block, dict) else False)
                            or (body_obj.get("pq_required") if isinstance(body_obj, dict) else False)
                            or bool(sec_ctx.get("pq_required"))
                        )
                        pq_ok_eff = sec_block.get("pq_ok") if isinstance(sec_block, dict) else None
                        if pq_required_eff and (pq_ok_eff is False or pq_ok_eff is None):
                            raise PermissionError("pq_violation")

                        runtime_build_id = rt.build_id or None
                        runtime_image_digest = rt.image_digest or None
                        if isinstance(sec_block, dict):
                            rec_build = sec_block.get("build_id")
                            rec_image = sec_block.get("image_digest")
                            if runtime_build_id and rec_build and rec_build != runtime_build_id:
                                raise PermissionError("supply_chain_mismatch_build")
                            if runtime_image_digest and rec_image and rec_image != runtime_image_digest:
                                raise PermissionError("supply_chain_mismatch_image")
                        return True

                    try:
                        ok = bool(
                            _dep_call_with_retry(
                                dep="verify",
                                op="receipt_or_chain",
                                breaker=rt.br_verify,
                                executor=rt.exec_verify,
                                timeout_ms=verify_timeout_ms,
                                deadline_mono=deadline_mono,
                                policy=RetryPolicy(max_attempts=1, base_backoff_ms=cfg.dep_retry_base_ms),
                                fn=_verify_impl,
                                idempotent=False,
                            )
                        )
                    except _DepException as exc:
                        if exc.kind == "timeout":
                            status_label = "timeout"
                            _set_grpc_error(context, grpc.StatusCode.DEADLINE_EXCEEDED, "verification timeout", request_id=request_id)
                        elif exc.kind == "queue_full":
                            status_label = "overloaded"
                            _set_grpc_error(context, grpc.StatusCode.RESOURCE_EXHAUSTED, "verify overloaded", request_id=request_id)
                        elif exc.kind == "breaker_open":
                            status_label = "unavailable"
                            _set_grpc_error(context, grpc.StatusCode.UNAVAILABLE, "verify unavailable", request_id=request_id)
                        else:
                            status_label = "error"
                            _set_grpc_error(context, grpc.StatusCode.INTERNAL, "verification error", request_id=request_id)
                        return pb.VerifyResponse(ok=False)  # type: ignore[misc]
                    except PermissionError as e:
                        status_label = "forbidden"
                        _set_grpc_error(context, grpc.StatusCode.PERMISSION_DENIED, _safe_text(e, max_len=128), request_id=request_id)
                        return pb.VerifyResponse(ok=False)  # type: ignore[misc]

                return pb.VerifyResponse(ok=bool(ok))  # type: ignore[misc]

            except Exception as e:
                status_label = "error"
                _GRPC_REQ_ERROR.labels(method, ERR_INTERNAL).inc()
                if cfg.debug_errors:
                    logger.exception("grpc verify failed")
                _set_grpc_error(
                    context,
                    grpc.StatusCode.INTERNAL,
                    "verification error",
                    request_id=request_id or None,
                    api_version=cfg.protocol.api_version,
                    schema_version=cfg.protocol.schema_version,
                )
                return pb.VerifyResponse(ok=False)  # type: ignore[misc]
            finally:
                dur = time.perf_counter() - t0
                _GRPC_REQ_LATENCY.labels(method, status_label, "verify").observe(dur)
                _GRPC_REQ_TOTAL.labels(method, status_label).inc()
                if gate_ok:
                    with contextlib.suppress(Exception):
                        rt.gate_verify.release()

else:

    class TcdService:  # pragma: no cover
        def __init__(self, runtime: Optional[_Runtime] = None) -> None:
            self._rt = runtime or _rt()

# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_grpc_services(server: "grpc.Server", runtime: Optional[_Runtime] = None) -> bool:  # type: ignore[name-defined]
    """
    Attach TCD gRPC services to an existing grpc.Server.

    Returns True if services were registered; False if grpcio/stubs are unavailable.
    """
    if not grpc_supported():  # pragma: no cover
        return False

    global _RUNTIME
    if runtime is not None:
        with _RUNTIME_LOCK:
            _RUNTIME = runtime

    pb_grpc.add_TcdServiceServicer_to_server(TcdService(runtime=runtime), server)  # type: ignore[attr-defined]
    return True