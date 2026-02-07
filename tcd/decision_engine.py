# FILE: tcd/decision_engine.py
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import re
import threading
import time
from dataclasses import dataclass, asdict, field
from enum import Enum
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, List, Set, Tuple, Literal


logger = logging.getLogger(__name__)

try:
    from .kv import canonical_kv_hash  # type: ignore
except Exception:  # pragma: no cover
    canonical_kv_hash = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Versioning / canonicalization identity (digest anchor)
# ---------------------------------------------------------------------------

# Bump when semantics change (normalization rules, missing-data policy, priority rules, receipt redaction, etc.)
_DECISION_ENGINE_VERSION = "decision_v3"

# Legacy versions that may appear in configs; we do NOT execute legacy vulnerable semantics.
# In non-strict build paths we can "migrate" to v3 and audit that migration.
_LEGACY_ENGINE_VERSIONS: Set[str] = {"decision_v2"}

_SUPPORTED_ENGINE_VERSIONS: Set[str] = {_DECISION_ENGINE_VERSION}

_CANONICALIZATION_VERSION = "canonjson_v1"


# ---------------------------------------------------------------------------
# Optional metrics/audit hooks (pure-core by default, but governance hardened)
# ---------------------------------------------------------------------------

class DecisionMetricsSink:
    """
    Minimal metrics hook for platform integration (Prometheus/OTEL/etc.).
    Must use low-cardinality labels only.
    """
    def inc(self, name: str, value: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
        raise NotImplementedError

    def observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        raise NotImplementedError


class DecisionAuditSink:
    """
    Structured audit hook for decision events. Must NOT include sensitive payloads.
    """
    def emit(self, event_type: str, metadata: Dict[str, Any]) -> None:
        raise NotImplementedError


_METRICS_SINK: Optional[DecisionMetricsSink] = None
_AUDIT_SINK: Optional[DecisionAuditSink] = None

# FIX (0.1): logging.Lock() does not exist -> use threading.RLock()
_HOOK_LOCK = threading.RLock()
_HOOKS_SEALED = False  # governance: after sealed, sinks cannot be replaced


def seal_decision_hooks() -> None:
    """
    Seal hook registration. After sealing, sinks can no longer be registered/replaced.
    This is a governance primitive to prevent runtime sink swapping.
    """
    global _HOOKS_SEALED
    with _HOOK_LOCK:
        _HOOKS_SEALED = True


def register_decision_metrics_sink(sink: DecisionMetricsSink) -> None:
    global _METRICS_SINK
    with _HOOK_LOCK:
        if _HOOKS_SEALED or _METRICS_SINK is not None:
            _emit_audit("DecisionHooksRegistrationRejected", {"kind": "metrics"})
            return
        _METRICS_SINK = sink
        _emit_audit("DecisionHooksRegistered", {"kind": "metrics"})


def register_decision_audit_sink(sink: DecisionAuditSink) -> None:
    global _AUDIT_SINK
    with _HOOK_LOCK:
        if _HOOKS_SEALED or _AUDIT_SINK is not None:
            # If audit sink is already set, do not allow replacement
            # (prevents exfil / observability drift).
            return
        _AUDIT_SINK = sink
        # Can't emit audit about audit sink registration unless sink exists now; safe to do.
        _emit_audit("DecisionHooksRegistered", {"kind": "audit"})


def _m_inc(name: str, value: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
    sink = _METRICS_SINK
    if sink is None:
        return
    try:
        sink.inc(name, value=value, labels=labels)
    except Exception:
        logger.exception("DecisionMetricsSink.inc failed")


def _m_obs(name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
    sink = _METRICS_SINK
    if sink is None:
        return
    try:
        sink.observe(name, value=value, labels=labels)
    except Exception:
        logger.exception("DecisionMetricsSink.observe failed")


_ALLOWED_AUDIT_EVENTS: Set[str] = {
    "DecisionEngineInitialized",
    "DecisionEngineVersionFallback",
    "DecisionLegacyConfigMigrated",
    "DecisionConfigNormalized",
    "DecisionConfigRejected",
    "DecisionHooksRegistered",
    "DecisionHooksRegistrationRejected",
    "DecisionMade",
    "DecisionFailSafe",
    "DecisionInvariantViolation",
    "DecisionHashFallbackUsed",
}


# ---------------------------------------------------------------------------
# Sanitizers / redaction
# ---------------------------------------------------------------------------

_CTRL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+")
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
_LONG_HEX_RE = re.compile(r"(?i)\b[0-9a-f]{32,}\b")


def _safe_text(x: Any, *, max_len: int) -> str:
    """
    Log/receipt safe text:
      - strips control chars
      - normalizes whitespace
      - truncates
      - redacts obvious secrets/tokens
    """
    s = "" if x is None else str(x)
    s = _CTRL_RE.sub("", s).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    if len(s) > max_len:
        s = s[:max_len]

    low = s.lower()
    # PEM key guard
    if "begin private key" in low or "begin encrypted private key" in low:
        return "<redacted>"
    # Authorization/bearer style tokens
    if "authorization:" in low or low.startswith("bearer ") or " bearer " in low:
        return "<redacted>"
    # JWT-like token
    if _JWT_RE.match(s) and len(s) >= 32:
        return "<redacted>"
    # Long hex tokens (api keys, hashes, etc.)
    if _LONG_HEX_RE.search(s) is not None and len(s) >= 32:
        return "<redacted>"

    return s


def _sanitize_audit_metadata(md: Dict[str, Any]) -> Dict[str, Any]:
    """
    Audit metadata must be small, scalar, and non-sensitive.
    """
    out: Dict[str, Any] = {}
    for k, v in md.items():
        kk = _safe_text(k, max_len=64)
        if not kk:
            continue
        if isinstance(v, str):
            out[kk] = _safe_text(v, max_len=256)
        elif isinstance(v, (int, float, bool)) or v is None:
            # ensure finite float
            if isinstance(v, float) and not math.isfinite(v):
                out[kk] = None
            else:
                out[kk] = v
        else:
            out[kk] = "<omitted>"
    return out


def _emit_audit(event_type: str, md: Dict[str, Any]) -> None:
    sink = _AUDIT_SINK
    if sink is None:
        return
    et = _safe_text(event_type, max_len=64)
    if et not in _ALLOWED_AUDIT_EVENTS:
        et = "DecisionMade"
        md = dict(md)
        md["original_event"] = _safe_text(event_type, max_len=64)
    try:
        sink.emit(et, _sanitize_audit_metadata(md))
    except Exception:
        logger.exception("DecisionAuditSink.emit failed")


# ---------------------------------------------------------------------------
# Privacy helpers (tenant/route hashing + route template)
# ---------------------------------------------------------------------------

_UUID_RE = re.compile(
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_NUM_RE = re.compile(r"^\d+$")
_LONG_SEG_RE = re.compile(r"^[A-Za-z0-9_-]{16,}$")
_HEX_SEG_RE = re.compile(r"(?i)^[0-9a-f]{16,}$")


def _strip_query_fragment(route: str) -> str:
    # Remove query and fragments to reduce token leakage and cardinality.
    s = route.split("?", 1)[0].split("#", 1)[0]
    return s


def _sanitize_route(route: Any, *, max_len: int = 256) -> str:
    r = _safe_text(route, max_len=max_len)
    r = _strip_query_fragment(r)
    if not r:
        return "/"
    # normalize repeated slashes
    while "//" in r:
        r = r.replace("//", "/")
    return r


def _route_template(route_path: str, *, max_len: int = 256) -> str:
    """
    Reduce route cardinality by templating typical IDs.
    """
    path = _strip_query_fragment(route_path)
    if not path.startswith("/"):
        path = "/" + path
    parts = [p for p in path.split("/") if p != ""]
    templated: List[str] = []
    for seg in parts:
        if len(seg) > 128:
            templated.append(":seg")
            continue
        if _UUID_RE.match(seg):
            templated.append(":uuid")
        elif _NUM_RE.match(seg):
            templated.append(":n")
        elif _HEX_SEG_RE.match(seg):
            templated.append(":hex")
        elif _LONG_SEG_RE.match(seg):
            templated.append(":tok")
        else:
            # keep small safe segment
            templated.append(_safe_text(seg, max_len=32) or ":seg")

    out = "/" + "/".join(templated)
    if len(out) > max_len:
        out = out[:max_len]
    return out


def _pii_hash(value: str, *, key: Optional[bytes], label: str) -> str:
    """
    Deterministic 128-bit identifier:
      - HMAC-SHA256 if key is provided
      - SHA256 if key is None (weaker; still removes raw PII from receipts)
    """
    v = value.encode("utf-8", errors="replace")
    tag = f"tcd:decision:{label}:v1|".encode("utf-8")
    if key:
        d = hmac.new(key, tag + v, hashlib.sha256).digest()
    else:
        d = hashlib.sha256(tag + v).digest()
    return d[:16].hex()  # 128-bit


# ---------------------------------------------------------------------------
# Hashing (canonical hash with stable fallback)
# ---------------------------------------------------------------------------

def _float_to_canon_str(x: float) -> str:
    # stable-ish float string; dev fallback only; production should prefer canonical_kv_hash
    # use fixed precision then strip trailing zeros/dot
    s = f"{x:.12f}"
    s = s.rstrip("0").rstrip(".")
    return s if s else "0"


def _canon_json(obj: Any) -> Any:
    """
    Canonicalize to JSON-serializable structure with deterministic key ordering.
    """
    if obj is None or isinstance(obj, bool) or isinstance(obj, int):
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            return None
        return _float_to_canon_str(obj)
    if isinstance(obj, str):
        return obj
    if isinstance(obj, Mapping):
        items: Dict[str, Any] = {}
        for k, v in obj.items():
            ks = str(k)
            items[ks] = _canon_json(v)
        # sort keys at dump time; keep dict form
        return items
    if isinstance(obj, (list, tuple)):
        return [_canon_json(x) for x in obj]
    if isinstance(obj, (set, frozenset)):
        # sets are unordered; sort canonicalized repr
        arr = [_canon_json(x) for x in obj]
        arr_sorted = sorted(arr, key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        return arr_sorted
    # unknown types -> type tag only (no repr side effects)
    return f"<{type(obj).__name__}>"


def _canonical_hash(payload: Dict[str, Any], *, ctx: str, label: str, require_kv: bool) -> str:
    """
    Preferred: canonical_kv_hash.
    Fallback (dev only): canonical JSON -> SHA256(ctx|label|json)
    """
    if canonical_kv_hash is not None:
        return str(canonical_kv_hash(payload, ctx=ctx, label=label))

    if require_kv:
        # L6/L7: do not silently degrade hashing semantics in strict mode.
        raise RuntimeError("canonical_kv_hash unavailable (strict hashing required)")

    # Explicitly observable fallback (metrics/audit)
    _m_inc("tcd_decision_hash_fallback_total", 1, {"kind": "canonjson"})
    _emit_audit("DecisionHashFallbackUsed", {"ctx": ctx, "label": label})

    canon = _canon_json(payload)
    raw = json.dumps(
        canon,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256((ctx + "|" + label + "|").encode("utf-8") + raw).hexdigest()


# ---------------------------------------------------------------------------
# Public enums
# ---------------------------------------------------------------------------

class DecisionAction(str, Enum):
    """
    Canonical action set for the TCD decision engine.
    """
    ALLOW = "allow"
    BLOCK = "block"
    DEGRADE = "degrade"
    THROTTLE = "throttle"
    ASK_FOR_REVIEW = "ask_for_review"
    ESCALATE_TO_HUMAN = "escalate_to_human"


# Low-cardinality reason codes
DecisionReasonCode = Literal[
    "HARD_BLOCK_RISK",
    "SOFT_BLOCK_RISK",
    "INVALID_RISK_ESCALATE",
    "INVALID_RISK_THROTTLE",
    "INVALID_RISK_BLOCK",
    "DEGRADE_HARD_SLO",
    "THROTTLE_MODERATE_RISK_SLO",
    "REVIEW_MODERATE_RISK",
    "THROTTLE_SOFT_SLO",
    "ALLOW_CAUTION",
    "ALLOW_NORMAL",
    "FAIL_SAFE_INTERNAL_ERROR",
    "INVARIANT_VIOLATION",
]


_REASON_ACTION_INVARIANTS: Dict[str, DecisionAction] = {
    "HARD_BLOCK_RISK": DecisionAction.BLOCK,
    "SOFT_BLOCK_RISK": DecisionAction.ESCALATE_TO_HUMAN,
    "INVALID_RISK_ESCALATE": DecisionAction.ESCALATE_TO_HUMAN,
    "INVALID_RISK_THROTTLE": DecisionAction.THROTTLE,
    "INVALID_RISK_BLOCK": DecisionAction.BLOCK,
    "DEGRADE_HARD_SLO": DecisionAction.DEGRADE,
    "THROTTLE_MODERATE_RISK_SLO": DecisionAction.THROTTLE,
    "REVIEW_MODERATE_RISK": DecisionAction.ASK_FOR_REVIEW,
    "THROTTLE_SOFT_SLO": DecisionAction.THROTTLE,
    "ALLOW_CAUTION": DecisionAction.ALLOW,
    "ALLOW_NORMAL": DecisionAction.ALLOW,
    "FAIL_SAFE_INTERNAL_ERROR": DecisionAction.THROTTLE,
    "INVARIANT_VIOLATION": DecisionAction.THROTTLE,
}


# ---------------------------------------------------------------------------
# Policies (missing-data policy etc.)
# ---------------------------------------------------------------------------

MissingSloPolicy = Literal[
    "ignore",
    "assume_pressure_soft",
    "assume_pressure_hard",
    "risk_bump",
]

InvalidRiskPolicy = Literal[
    "escalate",   # default: treat invalid risk as SOFT_BLOCK
    "throttle",   # treat invalid risk as THROTTLE threshold
    "block",      # treat invalid risk as HARD_BLOCK
]


@dataclass(frozen=True, slots=True)
class DecisionDataQualityPolicy:
    """
    L6/L7: missing/invalid telemetry must have explicit semantics (and be in policy digest).
    """
    missing_slo_policy: MissingSloPolicy = "assume_pressure_soft"
    missing_slo_risk_bump: float = 0.10  # only used when missing_slo_policy == "risk_bump"
    invalid_risk_policy: InvalidRiskPolicy = "escalate"

    def normalized(self) -> "DecisionDataQualityPolicy":
        bump = float(self.missing_slo_risk_bump)
        if not math.isfinite(bump):
            bump = 0.10
        bump = 0.0 if bump < 0.0 else 1.0 if bump > 1.0 else bump
        ms = self.missing_slo_policy
        if ms not in ("ignore", "assume_pressure_soft", "assume_pressure_hard", "risk_bump"):
            ms = "assume_pressure_soft"
        ir = self.invalid_risk_policy
        if ir not in ("escalate", "throttle", "block"):
            ir = "escalate"
        return DecisionDataQualityPolicy(missing_slo_policy=ms, missing_slo_risk_bump=bump, invalid_risk_policy=ir)


# ---------------------------------------------------------------------------
# Thresholds / Snapshot / Result (immutable & sealed)
# ---------------------------------------------------------------------------

# Extra governance: allowlist keys (move from blocklist to allowlist)
_DEFAULT_EXTRA_ALLOWLIST: Set[str] = {
    "request_id",
    "trace_id",
    "span_id",
    "model_id",
    "model_version",
    "risk_model_version",
    "detector_version",
    "region",
    "cluster",
    "env",
    "user_tier",
    "tenant_tier",
    "pq_required",
    "pq_scheme",
    "override_flag",
}

_FORBIDDEN_EXTRA_KEYS: Set[str] = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "messages",
    "content",
    "body",
    "raw",
    "request_body",
    "response_body",
    "headers",
    "cookies",
}

_SENSITIVE_KEY_SUBSTRS: Tuple[str, ...] = (
    "token",
    "apikey",
    "api_key",
    "secret",
    "authorization",
    "passwd",
    "password",
    "session",
)

_MAX_EXTRA_KEYS: int = 32
_MAX_EXTRA_SCAN: int = 256
_MAX_EXTRA_KEY_LEN: int = 64
_MAX_EXTRA_STRING: int = 256

_ALLOWED_METHODS: Set[str] = {
    "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "RPC", "BATCH",
    "OTHER",
}

_MIN_RISK_BAND: float = 0.05

_MAX_LAT_MS: int = 60_000
_MIN_LAT_MS: int = 0
_MAX_INFLIGHT: int = 1_000_000
_MIN_INFLIGHT: int = 0


def _to_float_or_none(x: Any) -> Optional[float]:
    if x is None:
        return None
    # bool is a foot-gun in config/telemetry; treat as invalid
    if isinstance(x, bool):
        return None
    try:
        v = float(x)
    except Exception:
        return None
    if not math.isfinite(v):
        return None
    return v


def _to_int_or_none(x: Any) -> Optional[int]:
    if x is None:
        return None
    if isinstance(x, bool):
        return None
    try:
        v = int(x)
    except Exception:
        return None
    return v


def _clamp01_or_none(x: Optional[float]) -> Optional[float]:
    if x is None:
        return None
    if not math.isfinite(x):
        return None
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


def _bounded_int(value: Any, default: int, min_v: int, max_v: int) -> Tuple[int, bool]:
    """
    Returns (bounded_value, valid_input).
    bool is treated as invalid input (avoids YAML true -> 1ms).
    """
    if isinstance(value, bool):
        return default, False
    try:
        v = int(value)
    except Exception:
        return default, False
    if v < min_v:
        return min_v, True
    if v > max_v:
        return max_v, True
    return v, True


@dataclass(frozen=True, slots=True)
class DecisionThresholds:
    """
    Threshold configuration for mapping risk + environment into actions.

    NOTE: Field name `degrade_risk` is historically kept but its semantics in v3 are:
      - >= degrade_risk => ALLOW (caution lane) with reason_code=ALLOW_CAUTION
    This avoids confusing/incorrect "swap semantics" changes; for true degrade, use hard SLO or other gates.
    """
    # risk in [0, 1]
    hard_block_risk: float = 0.98
    soft_block_risk: float = 0.92
    throttle_risk: float = 0.80
    degrade_risk: float = 0.65  # semantic: allow-caution threshold (legacy name)

    # latency / error based gates
    p95_latency_ms_soft: int = 800
    p95_latency_ms_hard: int = 1500
    error_rate_soft: float = 0.05
    error_rate_hard: float = 0.15

    # load / concurrency
    in_flight_soft: int = 512
    in_flight_hard: int = 2048

    # heuristic bump
    anomaly_risk_bump: float = 0.10

    @property
    def caution_risk(self) -> float:
        return float(self.degrade_risk)


@dataclass(frozen=True, slots=True)
class ThresholdNormalizationReport:
    mode: Literal["strict", "lenient"]
    rejected: bool
    changed_fields: Tuple[str, ...]
    before_hash: str
    after_hash: str


@dataclass(frozen=True, slots=True)
class ExtraSanitizeStats:
    scanned: int
    kept: int
    dropped_forbidden: int
    dropped_sensitive: int
    dropped_unknown: int
    truncated_scan: bool
    truncated_max_keys: bool


def _sanitize_extra(
    extra: Any,
    *,
    allowlist: Set[str],
) -> Tuple[Dict[str, Any], ExtraSanitizeStats]:
    """
    L6/L7:
      - accept Any, never throw
      - allowlist-based key selection
      - bounded scan + bounded keep
      - avoid repr side effects
      - drop sensitive-key-like entries
    """
    if not isinstance(extra, Mapping):
        stats = ExtraSanitizeStats(
            scanned=0, kept=0,
            dropped_forbidden=0, dropped_sensitive=0, dropped_unknown=0,
            truncated_scan=False, truncated_max_keys=False
        )
        return {}, stats

    scanned = 0
    dropped_forbidden = 0
    dropped_sensitive = 0
    dropped_unknown = 0
    truncated_scan = False

    pairs: List[Tuple[str, Any]] = []
    for k, v in extra.items():
        scanned += 1
        if scanned > _MAX_EXTRA_SCAN:
            truncated_scan = True
            break

        ks = _safe_text(k, max_len=_MAX_EXTRA_KEY_LEN)
        if not ks:
            continue
        kl = ks.lower()

        # forbid known sensitive payload carriers
        if kl in _FORBIDDEN_EXTRA_KEYS:
            dropped_forbidden += 1
            continue

        # drop obvious secret-ish keys by substring
        if any(sub in kl for sub in _SENSITIVE_KEY_SUBSTRS):
            dropped_sensitive += 1
            continue

        # allowlist enforcement
        if kl not in allowlist:
            dropped_unknown += 1
            continue

        pairs.append((kl, v))

    pairs.sort(key=lambda kv: kv[0])

    out: Dict[str, Any] = {}
    kept = 0
    truncated_max_keys = False
    for kl, v in pairs:
        if kept >= _MAX_EXTRA_KEYS:
            truncated_max_keys = True
            break

        # scalar-ish values only
        if isinstance(v, str):
            out[kl] = _safe_text(v, max_len=_MAX_EXTRA_STRING)
        elif isinstance(v, (int, bool)) or v is None:
            out[kl] = v
        elif isinstance(v, float):
            out[kl] = v if math.isfinite(v) else None
        else:
            out[kl] = f"<{type(v).__name__}>"

        kept += 1

    stats = ExtraSanitizeStats(
        scanned=scanned if scanned <= _MAX_EXTRA_SCAN else _MAX_EXTRA_SCAN,
        kept=kept,
        dropped_forbidden=dropped_forbidden,
        dropped_sensitive=dropped_sensitive,
        dropped_unknown=dropped_unknown,
        truncated_scan=truncated_scan,
        truncated_max_keys=truncated_max_keys,
    )
    return out, stats


@dataclass(frozen=True, slots=True)
class EnvironmentSnapshot:
    """
    Immutable, sanitized snapshot captured at decision time.

    L6/L7 changes:
      - risk invalid => mark risk_input_valid=False (do NOT silently treat as low risk)
      - extra: allowlist + bounded + MappingProxyType
      - route: query/fragment stripped (reduces token leakage)
      - includes data-quality flags so fail-safe can be explicit and observable
    """
    risk_score: float
    tenant_id: str
    route: str
    method: str

    p95_latency_ms: Optional[int] = None
    error_rate: Optional[float] = None
    in_flight_requests: Optional[int] = None

    is_anomalous: bool = False

    extra: Mapping[str, Any] = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    # data quality flags (derived; caller-supplied values are overwritten)
    risk_input_valid: bool = True
    latency_input_valid: bool = True
    error_rate_input_valid: bool = True
    inflight_input_valid: bool = True
    extra_stats: ExtraSanitizeStats = field(
        default_factory=lambda: ExtraSanitizeStats(0, 0, 0, 0, 0, False, False)
    )

    def __post_init__(self) -> None:
        tenant_id = _safe_text(self.tenant_id, max_len=128) or "unknown"
        route = _sanitize_route(self.route, max_len=256)
        method_raw = _safe_text(self.method, max_len=32).upper() or "OTHER"
        method = method_raw if method_raw in _ALLOWED_METHODS else "OTHER"

        # risk: conservative semantics (1.1)
        risk_valid = True
        rv = _to_float_or_none(self.risk_score)
        if rv is None:
            risk_valid = False
            risk = 1.0  # conservative baseline; policy will decide final action (escalate/throttle/block)
        else:
            risk = 0.0 if rv < 0.0 else 1.0 if rv > 1.0 else rv

        # telemetry parse (invalid -> None and validity flag false)
        lat_valid = True
        latency = _to_int_or_none(self.p95_latency_ms)
        if self.p95_latency_ms is not None and latency is None:
            lat_valid = False
        if latency is not None:
            latency = max(0, latency)

        err_valid = True
        err = _to_float_or_none(self.error_rate)
        if self.error_rate is not None and err is None:
            err_valid = False
        err = _clamp01_or_none(err)

        inf_valid = True
        inflight = _to_int_or_none(self.in_flight_requests)
        if self.in_flight_requests is not None and inflight is None:
            inf_valid = False
        if inflight is not None:
            inflight = max(0, inflight)

        # timestamp normalization: finite, bounded future
        now = time.time()
        ts_v = _to_float_or_none(self.ts)
        if ts_v is None:
            ts_v = now
        if ts_v > now + 24 * 3600:
            ts_v = now
        if ts_v < 946684800.0:  # 2000-01-01
            ts_v = now

        # extra allowlist-based sanitization
        sanitized_extra, stats = _sanitize_extra(self.extra, allowlist=_DEFAULT_EXTRA_ALLOWLIST)
        sealed_extra = MappingProxyType(dict(sanitized_extra))

        object.__setattr__(self, "tenant_id", tenant_id)
        object.__setattr__(self, "route", route)
        object.__setattr__(self, "method", method)

        object.__setattr__(self, "risk_score", float(risk))
        object.__setattr__(self, "risk_input_valid", bool(risk_valid))

        object.__setattr__(self, "p95_latency_ms", latency)
        object.__setattr__(self, "latency_input_valid", bool(lat_valid))

        object.__setattr__(self, "error_rate", err)
        object.__setattr__(self, "error_rate_input_valid", bool(err_valid))

        object.__setattr__(self, "in_flight_requests", inflight)
        object.__setattr__(self, "inflight_input_valid", bool(inf_valid))

        object.__setattr__(self, "ts", float(ts_v))
        object.__setattr__(self, "extra_stats", stats)
        object.__setattr__(self, "extra", sealed_extra)


@dataclass(frozen=True, slots=True)
class DecisionResult:
    """
    Immutable result of a single decision.

    Provides three output layers (15):
      - to_receipt_dict(strict=True): long-lived receipts (no raw tenant/route)
      - to_log_dict(): log-friendly (can optionally include raw)
      - to_internal_debug(): richer factors (still bounded)
    """
    engine_version: str
    action: DecisionAction
    reason_code: DecisionReasonCode
    reason: str

    policy_version: str
    policy_digest: str
    config_hash: str

    snapshot: EnvironmentSnapshot
    thresholds: DecisionThresholds
    created_at: float

    factors: Mapping[str, Any] = field(default_factory=dict)

    def to_receipt_dict(self, *, strict: bool = True, pii_hmac_key: Optional[bytes] = None) -> Dict[str, Any]:
        snap = snapshot_view(self.snapshot, strict=strict, pii_hmac_key=pii_hmac_key)
        thr = thresholds_view(self.thresholds)

        base: Dict[str, Any] = {
            "engine_version": self.engine_version,
            "action": self.action.value,
            "reason_code": self.reason_code,
            "reason": _safe_text(self.reason, max_len=512),
            "policy_version": _safe_text(self.policy_version, max_len=64),
            "created_at": float(self.created_at),
            "snapshot": snap,
            "thresholds": thr,
            "config_hash": self.config_hash,
            "policy_digest": self.policy_digest,
            "canonicalization_version": _CANONICALIZATION_VERSION,
        }

        # decision_id: deterministic but with lower collision risk (5.2)
        decision_id = _canonical_hash(
            {
                "engine_version": base["engine_version"],
                "policy_digest": base["policy_digest"],
                "config_hash": base["config_hash"],
                "action": base["action"],
                "reason_code": base["reason_code"],
                "snapshot_hash": base["snapshot"]["snapshot_hash"],
                "ts": base["snapshot"]["ts"],
            },
            ctx="tcd:decision",
            label="decision_id",
            require_kv=False,
        )
        base["decision_id"] = decision_id

        # include bounded factors if present
        if self.factors:
            base["factors"] = dict(self.factors)

        return base

    def to_log_dict(self, *, include_raw: bool = False, pii_hmac_key: Optional[bytes] = None) -> Dict[str, Any]:
        strict = not include_raw
        d = self.to_receipt_dict(strict=strict, pii_hmac_key=pii_hmac_key)
        if include_raw:
            d["snapshot"]["tenant_id"] = _safe_text(self.snapshot.tenant_id, max_len=128)
            d["snapshot"]["route"] = _safe_text(self.snapshot.route, max_len=256)
        return d

    def to_internal_debug(self, *, pii_hmac_key: Optional[bytes] = None) -> Dict[str, Any]:
        d = self.to_log_dict(include_raw=True, pii_hmac_key=pii_hmac_key)
        # attach extra_stats (bounded and low-sensitivity)
        d["snapshot"]["extra_stats"] = asdict(self.snapshot.extra_stats)
        return d

    # Backward-compatible name; receipts should default to strict mode (7.1)
    def to_dict(self) -> Dict[str, Any]:
        return self.to_receipt_dict(strict=True, pii_hmac_key=None)


# ---------------------------------------------------------------------------
# Views / receipt shaping
# ---------------------------------------------------------------------------

def thresholds_view(t: DecisionThresholds) -> Dict[str, Any]:
    # Always clamp on output
    def c01(v: float) -> float:
        if not math.isfinite(v):
            return 0.0
        return 0.0 if v < 0.0 else 1.0 if v > 1.0 else float(v)

    return {
        "hard_block_risk": c01(float(t.hard_block_risk)),
        "soft_block_risk": c01(float(t.soft_block_risk)),
        "throttle_risk": c01(float(t.throttle_risk)),
        "degrade_risk": c01(float(t.degrade_risk)),
        "p95_latency_ms_soft": max(_MIN_LAT_MS, min(_MAX_LAT_MS, int(t.p95_latency_ms_soft))),
        "p95_latency_ms_hard": max(_MIN_LAT_MS, min(_MAX_LAT_MS, int(t.p95_latency_ms_hard))),
        "error_rate_soft": c01(float(t.error_rate_soft)),
        "error_rate_hard": c01(float(t.error_rate_hard)),
        "in_flight_soft": max(_MIN_INFLIGHT, min(_MAX_INFLIGHT, int(t.in_flight_soft))),
        "in_flight_hard": max(_MIN_INFLIGHT, min(_MAX_INFLIGHT, int(t.in_flight_hard))),
        "anomaly_risk_bump": c01(float(t.anomaly_risk_bump)),
    }


def snapshot_view(s: EnvironmentSnapshot, *, strict: bool, pii_hmac_key: Optional[bytes]) -> Dict[str, Any]:
    route_path = _sanitize_route(s.route, max_len=256)
    route_tmpl = _route_template(route_path, max_len=256)

    tenant_hash = _pii_hash(s.tenant_id, key=pii_hmac_key, label="tenant")
    route_hash = _pii_hash(route_path, key=pii_hmac_key, label="route_path")
    route_tmpl_hash = _pii_hash(route_tmpl, key=pii_hmac_key, label="route_tmpl")

    # Stable snapshot hash excludes raw PII in strict mode (7.1)
    snap_payload = {
        "risk_score": float(s.risk_score),
        "method": s.method,
        "tenant_hash": tenant_hash,
        "route_template": route_tmpl,
        "route_template_hash": route_tmpl_hash,
        "route_hash": route_hash,
        "p95_latency_ms": s.p95_latency_ms,
        "error_rate": s.error_rate,
        "in_flight_requests": s.in_flight_requests,
        "is_anomalous": bool(s.is_anomalous),
        "ts": float(s.ts),
        "extra": dict(s.extra) if s.extra else {},
        "dq": {
            "risk_input_valid": bool(s.risk_input_valid),
            "latency_input_valid": bool(s.latency_input_valid),
            "error_rate_input_valid": bool(s.error_rate_input_valid),
            "inflight_input_valid": bool(s.inflight_input_valid),
        },
    }

    snap_hash = _canonical_hash(snap_payload, ctx="tcd:decision", label="snapshot_hash", require_kv=False)

    out: Dict[str, Any] = {
        "risk_score": float(s.risk_score),
        "method": s.method,
        "tenant_hash": tenant_hash,
        "route_template": route_tmpl,
        "route_template_hash": route_tmpl_hash,
        "route_hash": route_hash,
        "p95_latency_ms": s.p95_latency_ms,
        "error_rate": s.error_rate,
        "in_flight_requests": s.in_flight_requests,
        "is_anomalous": bool(s.is_anomalous),
        "ts": float(s.ts),
        "extra": dict(s.extra) if s.extra else {},
        "snapshot_hash": snap_hash,
        "dq_flags": {
            "risk_input_valid": bool(s.risk_input_valid),
            "latency_input_valid": bool(s.latency_input_valid),
            "error_rate_input_valid": bool(s.error_rate_input_valid),
            "inflight_input_valid": bool(s.inflight_input_valid),
        },
    }

    if not strict:
        out["tenant_id"] = _safe_text(s.tenant_id, max_len=128)
        out["route"] = _safe_text(route_path, max_len=256)

    return out


# ---------------------------------------------------------------------------
# Threshold normalization (2.1 / 2.2 / 2.3)
# ---------------------------------------------------------------------------

def _normalize_thresholds(
    t: DecisionThresholds,
    *,
    mode: Literal["strict", "lenient"],
    log: Optional[logging.Logger],
    require_kv_hash: bool,
) -> Tuple[DecisionThresholds, ThresholdNormalizationReport]:
    """
    L6/L7 normalization:
      - NO sorting that loses field identity (2.1)
      - NO swapping soft/hard (2.2)
      - only "tighten" (make thresholds more conservative) when repairing order/spacing
      - strict mode can reject pathological configs (2.3)
    """
    lg = log or logger
    defaults = DecisionThresholds()

    before = thresholds_view(t)
    before_hash = _canonical_hash(before, ctx="tcd:decision", label="thresholds_before", require_kv=require_kv_hash)

    changed: List[str] = []
    rejected = False

    def clamp01(v: Any, default: float, name: str) -> float:
        vv = _to_float_or_none(v)
        if vv is None:
            changed.append(name)
            return default
        if vv < 0.0:
            changed.append(name)
            return 0.0
        if vv > 1.0:
            changed.append(name)
            return 1.0
        return float(vv)

    # 1) clamp individual
    hb = clamp01(t.hard_block_risk, defaults.hard_block_risk, "hard_block_risk")
    sb = clamp01(t.soft_block_risk, defaults.soft_block_risk, "soft_block_risk")
    tr = clamp01(t.throttle_risk, defaults.throttle_risk, "throttle_risk")
    dr = clamp01(t.degrade_risk, defaults.degrade_risk, "degrade_risk")

    ers = clamp01(t.error_rate_soft, defaults.error_rate_soft, "error_rate_soft")
    erh = clamp01(t.error_rate_hard, defaults.error_rate_hard, "error_rate_hard")

    bump = clamp01(t.anomaly_risk_bump, defaults.anomaly_risk_bump, "anomaly_risk_bump")

    # ints bounded (reject bool input already at parsing sites; still clamp here)
    lat_s, _ = _bounded_int(t.p95_latency_ms_soft, defaults.p95_latency_ms_soft, _MIN_LAT_MS, _MAX_LAT_MS)
    lat_h, _ = _bounded_int(t.p95_latency_ms_hard, defaults.p95_latency_ms_hard, _MIN_LAT_MS, _MAX_LAT_MS)
    inf_s, _ = _bounded_int(t.in_flight_soft, defaults.in_flight_soft, _MIN_INFLIGHT, _MAX_INFLIGHT)
    inf_h, _ = _bounded_int(t.in_flight_hard, defaults.in_flight_hard, _MIN_INFLIGHT, _MAX_INFLIGHT)

    # 2) enforce monotonic ladder WITHOUT swap (tighten-only)
    # risk: degrade <= throttle <= soft_block <= hard_block
    if sb > hb:
        sb = hb
        changed.append("soft_block_risk")
    if tr > sb:
        tr = sb
        changed.append("throttle_risk")
    if dr > tr:
        dr = tr
        changed.append("degrade_risk")

    # enforce spacing (tighten-only, top-down)
    # hard - soft >= band => soft <= hard - band
    if hb - sb < _MIN_RISK_BAND:
        sb2 = max(0.0, hb - _MIN_RISK_BAND)
        if sb2 != sb:
            sb = sb2
            changed.append("soft_block_risk")
    if sb - tr < _MIN_RISK_BAND:
        tr2 = max(0.0, sb - _MIN_RISK_BAND)
        if tr2 != tr:
            tr = tr2
            changed.append("throttle_risk")
    if tr - dr < _MIN_RISK_BAND:
        dr2 = max(0.0, tr - _MIN_RISK_BAND)
        if dr2 != dr:
            dr = dr2
            changed.append("degrade_risk")

    # error_rate: soft <= hard (no swap; tighten soft)
    if ers > erh:
        ers = erh
        changed.append("error_rate_soft")

    # latency: soft <= hard (no swap; tighten soft)
    if lat_s > lat_h:
        lat_s = lat_h
        changed.append("p95_latency_ms_soft")

    # inflight: soft <= hard (no swap; tighten soft)
    if inf_s > inf_h:
        inf_s = inf_h
        changed.append("in_flight_soft")

    # detect degenerate ladders where spacing couldn't be satisfied meaningfully
    degenerate = (hb <= 0.0) or (hb < _MIN_RISK_BAND)
    if degenerate and mode == "strict":
        rejected = True

    if rejected:
        # reject and fall back to defaults (explicitly observable; not silent)
        normalized = defaults
        changed = ["<rejected_to_defaults>"]
        _m_inc("tcd_decision_thresholds_rejected_total", 1, {"mode": mode})
        _emit_audit("DecisionConfigRejected", {"engine_version": _DECISION_ENGINE_VERSION, "mode": mode})
        lg.error("Decision thresholds rejected in strict mode; falling back to defaults")
    else:
        normalized = DecisionThresholds(
            hard_block_risk=hb,
            soft_block_risk=sb,
            throttle_risk=tr,
            degrade_risk=dr,
            p95_latency_ms_soft=int(lat_s),
            p95_latency_ms_hard=int(lat_h),
            error_rate_soft=ers,
            error_rate_hard=erh,
            in_flight_soft=int(inf_s),
            in_flight_hard=int(inf_h),
            anomaly_risk_bump=bump,
        )

    after = thresholds_view(normalized)
    after_hash = _canonical_hash(after, ctx="tcd:decision", label="thresholds_after", require_kv=require_kv_hash)

    if after_hash != before_hash:
        _m_inc("tcd_decision_thresholds_normalized_total", 1, {"mode": mode})
        _emit_audit(
            "DecisionConfigNormalized",
            {
                "engine_version": _DECISION_ENGINE_VERSION,
                "mode": mode,
                "changed_fields_count": str(len(set(changed))),
                "before_hash": before_hash[:16],
                "after_hash": after_hash[:16],
            },
        )

    rep = ThresholdNormalizationReport(
        mode=mode,
        rejected=rejected,
        changed_fields=tuple(sorted(set(changed)))[:64],
        before_hash=before_hash,
        after_hash=after_hash,
    )
    return normalized, rep


# ---------------------------------------------------------------------------
# Decision engine
# ---------------------------------------------------------------------------

class DecisionEngine:
    """
    Core policy engine for TCD.

    L6/L7 invariants:
      - never-throw decide() (4.1/4.2)
      - conservative invalid-risk semantics (1.1)
      - explicit missing-data policy (1.2)
      - normalization preserves field identity, no swap/sort wash (2.1/2.2)
      - hard SLO degrade not shadowed by moderate risk lane (3.1)
      - stable policy/state digests (5.3)
      - receipts are strict by default (7.1), debug logs are level-guarded (8.1)
    """

    def __init__(
        self,
        thresholds: Optional[DecisionThresholds] = None,
        policy_version: str = "v1",
        logger: Optional[logging.Logger] = None,
        *,
        engine_version: str = _DECISION_ENGINE_VERSION,
        normalization_mode: Literal["strict", "lenient"] = "strict",
        data_quality_policy: Optional[DecisionDataQualityPolicy] = None,
        extra_allowlist: Optional[Set[str]] = None,
        pii_hmac_key: Optional[bytes] = None,
        strict_hashing: bool = True,
        allow_legacy_engine_version: bool = True,
        strict_engine_version: bool = True,
    ) -> None:
        self._log = logger or logging.getLogger(__name__)
        self._loaded_at = time.time()

        ev = _safe_text(engine_version, max_len=64) or _DECISION_ENGINE_VERSION
        if ev in _LEGACY_ENGINE_VERSIONS and allow_legacy_engine_version and not strict_engine_version:
            # migrate to v3 semantics explicitly (13.1)
            _emit_audit("DecisionLegacyConfigMigrated", {"from": ev, "to": _DECISION_ENGINE_VERSION})
            _m_inc("tcd_decision_engine_version_fallback_total", 1, {"from": ev, "to": _DECISION_ENGINE_VERSION})
            ev = _DECISION_ENGINE_VERSION

        if ev not in _SUPPORTED_ENGINE_VERSIONS:
            if strict_engine_version:
                raise ValueError(f"Unsupported decision engine version: {ev}")
            _emit_audit("DecisionEngineVersionFallback", {"from": ev, "to": _DECISION_ENGINE_VERSION})
            ev = _DECISION_ENGINE_VERSION

        self._engine_version = ev
        self._policy_version = _safe_text(policy_version, max_len=64) or "v1"

        dq = (data_quality_policy or DecisionDataQualityPolicy()).normalized()
        self._dq = dq

        # allowlist governance (10.1): allowlist is lowercased
        if extra_allowlist is None:
            allowlist = set(_DEFAULT_EXTRA_ALLOWLIST)
        else:
            allowlist = {str(x).lower() for x in extra_allowlist if str(x).strip()}
        self._extra_allowlist = frozenset(allowlist)

        self._pii_hmac_key = pii_hmac_key
        self._strict_hashing = bool(strict_hashing)

        raw_thr = thresholds or DecisionThresholds()
        self._thresholds, self._thr_norm_report = _normalize_thresholds(
            raw_thr,
            mode=normalization_mode,
            log=self._log,
            require_kv_hash=self._strict_hashing,
        )

        # policy snapshot (5.3) includes semantics version + dq policy + allowlist hash + privacy mode
        allowlist_hash = _canonical_hash(
            {"keys": sorted(self._extra_allowlist)},
            ctx="tcd:decision",
            label="extra_allowlist",
            require_kv=self._strict_hashing,
        )

        policy_snapshot = {
            "engine_version": self._engine_version,
            "policy_version": self._policy_version,
            "canonicalization_version": _CANONICALIZATION_VERSION,
            "normalization_mode": normalization_mode,
            "thresholds_hash": self._thr_norm_report.after_hash,
            "thresholds": thresholds_view(self._thresholds),
            "data_quality_policy": asdict(self._dq),
            "extra_allowlist_hash": allowlist_hash,
            "pii_hash_mode": "hmac_sha256" if self._pii_hmac_key else "sha256",
        }

        self._policy_digest = _canonical_hash(
            policy_snapshot,
            ctx="tcd:decision",
            label="policy_digest",
            require_kv=self._strict_hashing,
        )

        # config_hash: narrower (thresholds + policy_version + engine_version)
        cfg_payload = {
            "engine_version": self._engine_version,
            "policy_version": self._policy_version,
            "thresholds": thresholds_view(self._thresholds),
        }
        self._config_hash = _canonical_hash(
            cfg_payload,
            ctx="tcd:decision",
            label="decision_cfg",
            require_kv=self._strict_hashing,
        )

        _emit_audit(
            "DecisionEngineInitialized",
            {
                "engine_version": self._engine_version,
                "policy_version": self._policy_version,
                "config_hash": self._config_hash[:16],
                "policy_digest": self._policy_digest[:16],
            },
        )

        self._log.info(
            "DecisionEngine initialized: engine_version=%s policy_version=%s cfg_hash=%s policy_digest=%s",
            self._engine_version,
            self._policy_version,
            self._config_hash,
            self._policy_digest,
        )

    # ---------------- policy/state digests (5.3) ----------------

    @property
    def thresholds(self) -> DecisionThresholds:
        return self._thresholds

    @property
    def policy_version(self) -> str:
        return self._policy_version

    @property
    def engine_version(self) -> str:
        return self._engine_version

    @property
    def config_hash(self) -> str:
        return self._config_hash

    @property
    def policy_digest(self) -> str:
        return self._policy_digest

    def state_digest(self, *, revision: int = 0) -> str:
        """
        State digest: policy_digest + loaded_at + hook presence + revision.
        """
        payload = {
            "engine_version": self._engine_version,
            "policy_digest": self._policy_digest,
            "loaded_at": float(self._loaded_at),
            "revision": int(revision),
            "hooks": {
                "metrics": _METRICS_SINK is not None,
                "audit": _AUDIT_SINK is not None,
                "sealed": bool(_HOOKS_SEALED),
            },
        }
        return _canonical_hash(payload, ctx="tcd:decision", label="state_digest", require_kv=False)

    def policy_snapshot(self) -> Dict[str, Any]:
        """
        Secret-free policy snapshot.
        """
        return {
            "engine_version": self._engine_version,
            "policy_version": self._policy_version,
            "config_hash": self._config_hash,
            "policy_digest": self._policy_digest,
            "thresholds": thresholds_view(self._thresholds),
            "data_quality_policy": asdict(self._dq),
            "extra_allowlist": sorted(self._extra_allowlist),
            "normalization_report": {
                "mode": self._thr_norm_report.mode,
                "rejected": bool(self._thr_norm_report.rejected),
                "changed_fields": list(self._thr_norm_report.changed_fields),
                "before_hash": self._thr_norm_report.before_hash,
                "after_hash": self._thr_norm_report.after_hash,
            },
        }

    # ---------------- official input constructor (15) ----------------

    @classmethod
    def make_snapshot(
        cls,
        *,
        risk_score: Any,
        tenant_id: Any,
        route: Any,
        method: Any,
        p95_latency_ms: Any = None,
        error_rate: Any = None,
        in_flight_requests: Any = None,
        is_anomalous: Any = False,
        extra: Any = None,
        ts: Any = None,
    ) -> EnvironmentSnapshot:
        """
        Official constructor: never throws, always returns a valid EnvironmentSnapshot.
        """
        try:
            return EnvironmentSnapshot(
                risk_score=risk_score,
                tenant_id=tenant_id,
                route=route,
                method=method,
                p95_latency_ms=p95_latency_ms,
                error_rate=error_rate,
                in_flight_requests=in_flight_requests,
                is_anomalous=bool(is_anomalous),
                extra=extra if extra is not None else {},
                ts=ts if ts is not None else time.time(),
            )
        except Exception:
            # never-throw fallback
            return EnvironmentSnapshot(
                risk_score=1.0,
                tenant_id="unknown",
                route="/",
                method="OTHER",
                p95_latency_ms=None,
                error_rate=None,
                in_flight_requests=None,
                is_anomalous=True,
                extra={},
                ts=time.time(),
            )

    # ---------------- decision API ----------------

    def decide(self, snapshot: Any) -> DecisionResult:
        """
        Compute action for a snapshot. Never-throw and fail-safe closed.
        """
        start = time.perf_counter()
        try:
            snap = self._coerce_snapshot(snapshot)

            t = self._thresholds
            dq = self._dq

            # Base risk (already clamped in snapshot), but we keep conservative invalid-risk policy at decision time (1.1)
            risk = float(snap.risk_score)
            effective_risk = risk

            # Track data quality for observability (6.2)
            if not snap.risk_input_valid:
                _m_inc("tcd_decision_input_invalid_total", 1, {"field": "risk"})
                if dq.invalid_risk_policy == "block":
                    effective_risk = 1.0
                elif dq.invalid_risk_policy == "throttle":
                    effective_risk = max(effective_risk, float(t.throttle_risk))
                else:
                    # default escalate
                    effective_risk = max(effective_risk, float(t.soft_block_risk))

            # anomaly bump
            if bool(snap.is_anomalous):
                effective_risk = min(1.0, effective_risk + float(t.anomaly_risk_bump))

            # Missing/invalid SLO policy (1.2)
            missing_latency = (snap.p95_latency_ms is None) or (not snap.latency_input_valid)
            missing_err = (snap.error_rate is None) or (not snap.error_rate_input_valid)
            missing_inflight = (snap.in_flight_requests is None) or (not snap.inflight_input_valid)

            any_missing = bool(missing_latency or missing_err or missing_inflight)
            if any_missing:
                _m_inc("tcd_decision_input_missing_total", 1, {"kind": "slo"})
                if dq.missing_slo_policy == "assume_pressure_soft":
                    # handled as soft-pressure below via pressure flags
                    pass
                elif dq.missing_slo_policy == "assume_pressure_hard":
                    # handled as hard-pressure below
                    pass
                elif dq.missing_slo_policy == "risk_bump":
                    effective_risk = min(1.0, effective_risk + float(dq.missing_slo_risk_bump))
                else:
                    # ignore
                    pass

            effective_risk = 0.0 if effective_risk < 0.0 else 1.0 if effective_risk > 1.0 else effective_risk

            # Compute pressure flags (hard-first to avoid shadowing; 3.1)
            hard_pressure = False
            soft_pressure = False

            lat = snap.p95_latency_ms
            err = snap.error_rate
            inf = snap.in_flight_requests

            if lat is not None and lat >= t.p95_latency_ms_hard:
                hard_pressure = True
            if err is not None and err >= t.error_rate_hard:
                hard_pressure = True
            if inf is not None and inf >= t.in_flight_hard:
                hard_pressure = True

            if lat is not None and lat >= t.p95_latency_ms_soft:
                soft_pressure = True
            if err is not None and err >= t.error_rate_soft:
                soft_pressure = True
            if inf is not None and inf >= t.in_flight_soft:
                soft_pressure = True

            # missing policy can force pressures
            if any_missing and dq.missing_slo_policy == "assume_pressure_soft":
                soft_pressure = True
            if any_missing and dq.missing_slo_policy == "assume_pressure_hard":
                hard_pressure = True

            # Build stable reason parts + structured factors (3.3)
            reason_parts: List[str] = [
                f"risk={risk:.3f}",
                f"effective_risk={effective_risk:.3f}",
            ]
            if not snap.risk_input_valid:
                reason_parts.append(f"risk_invalid(policy={dq.invalid_risk_policy})")
            if any_missing:
                reason_parts.append(f"missing_slo(policy={dq.missing_slo_policy})")
            if snap.is_anomalous:
                reason_parts.append("anomalous=1")

            # 1) Hard/soft risk cutoffs
            if effective_risk >= float(t.hard_block_risk):
                action = DecisionAction.BLOCK
                reason_code: DecisionReasonCode = "HARD_BLOCK_RISK"
                reason_parts.append(f"≥ hard_block_risk({t.hard_block_risk:.2f})")

            elif effective_risk >= float(t.soft_block_risk):
                action = DecisionAction.ESCALATE_TO_HUMAN
                # If invalid risk caused this, separate reason_code for observability
                if not snap.risk_input_valid and dq.invalid_risk_policy == "escalate":
                    reason_code = "INVALID_RISK_ESCALATE"
                else:
                    reason_code = "SOFT_BLOCK_RISK"
                reason_parts.append(f"≥ soft_block_risk({t.soft_block_risk:.2f})")

            # 2) Hard SLO degrade MUST be evaluated before moderate-risk lane (3.1)
            elif hard_pressure:
                action = DecisionAction.DEGRADE
                reason_code = "DEGRADE_HARD_SLO"
                reason_parts.append("hard_slo_pressure=1")

            # 3) Moderate risk lane
            elif effective_risk >= float(t.throttle_risk):
                reason_parts.append(f"≥ throttle_risk({t.throttle_risk:.2f})")
                if soft_pressure:
                    action = DecisionAction.THROTTLE
                    reason_code = "THROTTLE_MODERATE_RISK_SLO"
                    reason_parts.append("soft_slo_pressure=1")
                else:
                    action = DecisionAction.ASK_FOR_REVIEW
                    reason_code = "REVIEW_MODERATE_RISK"

            # 4) Low risk but soft pressure -> throttle
            elif soft_pressure:
                action = DecisionAction.THROTTLE
                reason_code = "THROTTLE_SOFT_SLO"
                reason_parts.append("soft_slo_pressure=1")

            # 5) Allow lanes (degrade_risk is caution threshold; 3.2)
            elif effective_risk >= float(t.degrade_risk):
                action = DecisionAction.ALLOW
                reason_code = "ALLOW_CAUTION"
                reason_parts.append(f"≥ degrade_risk({t.degrade_risk:.2f}), allow_caution")

            else:
                action = DecisionAction.ALLOW
                reason_code = "ALLOW_NORMAL"
                reason_parts.append("within_normal_bounds")

            # Invariant enforcement (12.1)
            expected = _REASON_ACTION_INVARIANTS.get(reason_code, DecisionAction.THROTTLE)
            if action != expected:
                _m_inc("tcd_decision_invariant_violation_total", 1, {"reason_code": reason_code})
                _emit_audit("DecisionInvariantViolation", {"reason_code": reason_code})
                action = DecisionAction.THROTTLE
                reason_code = "INVARIANT_VIOLATION"
                reason_parts.append("invariant_violation")

            # Build factors (bounded)
            factors = MappingProxyType(
                {
                    "risk": float(risk),
                    "effective_risk": float(effective_risk),
                    "hard_pressure": bool(hard_pressure),
                    "soft_pressure": bool(soft_pressure),
                    "missing_latency": bool(missing_latency),
                    "missing_error_rate": bool(missing_err),
                    "missing_inflight": bool(missing_inflight),
                    "risk_input_valid": bool(snap.risk_input_valid),
                }
            )

            reason = "; ".join(reason_parts)
            created_at = float(snap.ts)

            # Metrics (6.1, 6.2)
            _m_inc("tcd_decision_total", 1, {"action": action.value, "reason_code": reason_code})
            # latency metric
            dt = max(0.0, time.perf_counter() - start)
            _m_obs("tcd_decision_latency_seconds", dt, {"result": "ok"})

            # audit: include correlatable IDs but not raw tenant/route (6.3 / 7.1)
            snap_pub = snapshot_view(snap, strict=True, pii_hmac_key=self._pii_hmac_key)
            tmp_result = DecisionResult(
                engine_version=self._engine_version,
                action=action,
                reason_code=reason_code,
                reason=reason,
                policy_version=self._policy_version,
                policy_digest=self._policy_digest,
                config_hash=self._config_hash,
                snapshot=snap,
                thresholds=t,
                created_at=created_at,
                factors=factors,
            )
            receipt = tmp_result.to_receipt_dict(strict=True, pii_hmac_key=self._pii_hmac_key)

            _emit_audit(
                "DecisionMade",
                {
                    "engine_version": self._engine_version,
                    "policy_version": self._policy_version,
                    "action": action.value,
                    "reason_code": reason_code,
                    "decision_id": str(receipt.get("decision_id", ""))[:32],
                    "config_hash": self._config_hash[:16],
                    "snapshot_hash": str(snap_pub.get("snapshot_hash", ""))[:16],
                },
            )

            # Debug log: level-guard + no raw PII/high-cardinality by default (8.1 / 7.1)
            if self._log.isEnabledFor(logging.DEBUG):
                self._log.debug(
                    "TCD decision",
                    extra={
                        "action": action.value,
                        "reason_code": reason_code,
                        "policy_version": self._policy_version,
                        "engine_version": self._engine_version,
                        "config_hash": self._config_hash,
                        "policy_digest": self._policy_digest,
                        "tenant_hash": snap_pub.get("tenant_hash"),
                        "route_template": snap_pub.get("route_template"),
                        "snapshot_hash": snap_pub.get("snapshot_hash"),
                        "risk": snap_pub.get("risk_score"),
                        "effective_risk": factors.get("effective_risk"),
                    },
                )

            return tmp_result

        except Exception as e:
            # fail-safe must be closed and must return a result that can be serialized (4.1)
            dt = max(0.0, time.perf_counter() - start)
            _m_obs("tcd_decision_latency_seconds", dt, {"result": "failsafe"})
            _m_inc("tcd_decision_total", 1, {"action": DecisionAction.THROTTLE.value, "reason_code": "FAIL_SAFE_INTERNAL_ERROR"})

            _emit_audit(
                "DecisionFailSafe",
                {
                    "engine_version": getattr(self, "_engine_version", _DECISION_ENGINE_VERSION),
                    "policy_version": getattr(self, "_policy_version", "v?"),
                    "error": _safe_text(e, max_len=128),
                },
            )

            safe_snap = self.make_snapshot(
                risk_score=1.0,
                tenant_id="unknown",
                route="/",
                method="OTHER",
                is_anomalous=True,
                extra={"dq": "fail_safe"},
                ts=time.time(),
            )

            return DecisionResult(
                engine_version=getattr(self, "_engine_version", _DECISION_ENGINE_VERSION),
                action=DecisionAction.THROTTLE,
                reason_code="FAIL_SAFE_INTERNAL_ERROR",
                reason="fail_safe_internal_error",
                policy_version=getattr(self, "_policy_version", "v?"),
                policy_digest=getattr(self, "_policy_digest", ""),
                config_hash=getattr(self, "_config_hash", ""),
                snapshot=safe_snap,
                thresholds=getattr(self, "_thresholds", DecisionThresholds()),
                created_at=float(safe_snap.ts),
                factors=MappingProxyType({"fail_safe": True}),
            )

    def _coerce_snapshot(self, snapshot: Any) -> EnvironmentSnapshot:
        """
        Defensive coercion: if snapshot is not an EnvironmentSnapshot, attempt to build one.
        Never throws; always returns a valid snapshot (4.1).
        """
        if isinstance(snapshot, EnvironmentSnapshot):
            # ensure extra allowlist policy is applied (snapshot itself uses default allowlist).
            # If you want per-engine allowlist, build snapshots via engine.make_snapshot.
            return snapshot

        if isinstance(snapshot, Mapping):
            return self.make_snapshot(
                risk_score=snapshot.get("risk_score"),
                tenant_id=snapshot.get("tenant_id", "unknown"),
                route=snapshot.get("route", "/"),
                method=snapshot.get("method", "OTHER"),
                p95_latency_ms=snapshot.get("p95_latency_ms"),
                error_rate=snapshot.get("error_rate"),
                in_flight_requests=snapshot.get("in_flight_requests"),
                is_anomalous=snapshot.get("is_anomalous", False),
                extra=snapshot.get("extra", {}),
                ts=snapshot.get("ts", time.time()),
            )

        # fallback
        return self.make_snapshot(
            risk_score=1.0,
            tenant_id="unknown",
            route="/",
            method="OTHER",
            is_anomalous=True,
            extra={"dq": "invalid_snapshot_type"},
            ts=time.time(),
        )


# ---------------------------------------------------------------------------
# Convenience factory (never-throw path with explicit governance knobs)
# ---------------------------------------------------------------------------

def build_decision_engine_from_config(
    cfg: Mapping[str, Any],
    logger: Optional[logging.Logger] = None,
    *,
    engine_version: Optional[str] = None,
    normalization_mode: Literal["strict", "lenient"] = "strict",
    strict_engine_version: bool = True,
    allow_legacy_engine_version: bool = True,
    strict_hashing: bool = True,
) -> DecisionEngine:
    """
    Build a DecisionEngine from a flat config mapping.

    L6/L7 changes:
      - supports engine_version migration/fallback (13.1)
      - thresholds normalization is identity-preserving (2.1/2.2)
      - never forget to return engine (hard bug)
    """
    defaults = DecisionThresholds()
    thresholds_kwargs: Dict[str, Any] = {}

    pv = _safe_text(cfg.get("policy_version", "v1"), max_len=64) or "v1"
    ev_cfg = _safe_text(cfg.get("engine_version", ""), max_len=64)
    ev = _safe_text(engine_version or ev_cfg or _DECISION_ENGINE_VERSION, max_len=64)

    # Backward compatible alias (3.2 / 13.1): allow "caution_risk" -> degrade_risk
    if "caution_risk" in cfg and "degrade_risk" not in cfg:
        thresholds_kwargs["degrade_risk"] = cfg.get("caution_risk")
        _emit_audit("DecisionLegacyConfigMigrated", {"field": "caution_risk->degrade_risk"})

    # Only accept known threshold fields
    for field_name in DecisionThresholds.__dataclass_fields__.keys():
        if field_name not in cfg:
            continue
        v = cfg[field_name]

        if field_name in ("p95_latency_ms_soft", "p95_latency_ms_hard"):
            default_v = getattr(defaults, field_name)
            v, _ = _bounded_int(v, default_v, min_v=_MIN_LAT_MS, max_v=_MAX_LAT_MS)
        elif field_name in ("in_flight_soft", "in_flight_hard"):
            default_v = getattr(defaults, field_name)
            v, _ = _bounded_int(v, default_v, min_v=_MIN_INFLIGHT, max_v=_MAX_INFLIGHT)

        thresholds_kwargs[field_name] = v

    thr = DecisionThresholds(**thresholds_kwargs)

    # Data quality policy (optional)
    dq_cfg = cfg.get("data_quality_policy")
    dq = None
    if isinstance(dq_cfg, Mapping):
        dq = DecisionDataQualityPolicy(
            missing_slo_policy=str(dq_cfg.get("missing_slo_policy", "assume_pressure_soft")),
            missing_slo_risk_bump=float(dq_cfg.get("missing_slo_risk_bump", 0.10)) if dq_cfg.get("missing_slo_risk_bump") is not None else 0.10,
            invalid_risk_policy=str(dq_cfg.get("invalid_risk_policy", "escalate")),
        ).normalized()

    # Never-throw by default is *not* appropriate for strict hashing; but caller can choose.
    # If strict_hashing=True and canonical_kv_hash is missing, DecisionEngine will raise explicitly.
    return DecisionEngine(
        thresholds=thr,
        policy_version=pv,
        logger=logger,
        engine_version=ev,
        normalization_mode=normalization_mode,
        data_quality_policy=dq,
        strict_hashing=strict_hashing,
        allow_legacy_engine_version=allow_legacy_engine_version,
        strict_engine_version=strict_engine_version,
    )