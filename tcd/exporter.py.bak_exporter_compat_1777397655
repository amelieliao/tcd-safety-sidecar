# FILE: tcd/exporter.py
# Prometheus exporter wrapper for TCD.
#
# L6/L7 hardening upgrades included in this build:
# - Never-throw public API: metric update failures are contained and counted.
# - Strong label governance:
#     * schema-driven metric surface (single source of truth),
#     * strict metric/label whitelist (unknown metric updates are dropped),
#     * per-label value-domain constraints (enums/regex/template),
#     * profile-aware privacy (internal vs external),
#     * optional PII/high-cardinality label hashing (tenant/user/session + selected keys).
# - Safe string handling:
#     * context-aware sanitization (hash/id vs label vs token),
#     * avoids calling str() on arbitrary objects (prevents __str__ side effects/DoS),
#     * control-char stripping + whitespace collapsing + bounded output.
# - Safe numeric handling:
#     * rejects non-finite values,
#     * metric-specific range checks / clamps (no NaN metrics),
#     * latency unit sanity guard (seconds vs ms) with explicit configuration,
#     * external risk quantization option (reduces precision leakage/noise).
# - Robust multi-instance behavior:
#     * schema-driven registration with duplicate reuse ONLY when safe,
#     * collector conflict detection (type/labelnames mismatch => disable that metric + count it),
#     * Info churn protection: Info labels are process/registry-stabilized (no series leak on repeated .info()).
# - Cardinality hard-stop (L7 must-have):
#     * per-metric and global "new series" budgets (process-wide per registry),
#     * prevents unbounded child-metric growth / OOM on label drift or attacker input,
#     * does NOT evict admitted series (Prom can't delete series; eviction would be unsafe).
# - Standalone server:
#     * single-start per (bind_addr, port, registry_id) with bind-occupancy guard,
#     * uses provided registry (fixes "custom registry not exported" bug),
#     * ACK gate (default required) to prevent accidental exposure.
# - Exporter self-health metrics:
#     dropped samples, observe errors, last success timestamp, enabled/init_ok,
#     init errors, cardinality budget hits, last error timestamp, last error code.
# - Diagnostics:
#     health_snapshot() provides a one-shot structured answer to "why no data".
#
# Environment knobs (read at exporter construction; no import-time config coupling):
# - TCD_METRICS_DISABLE                      "1"/"true"/"yes" disables exporter backend (no-op).
# - TCD_PROM_STANDALONE_SERVER               "1"/"true"/"yes" starts standalone HTTP server.
# - TCD_PROM_STANDALONE_SERVER_ACK           required ACK string by default to start server.
#     Expected: "I_UNDERSTAND_TCD_PROM_STANDALONE_SERVER_<surface>"
# - TCD_PROM_STANDALONE_SERVER_REQUIRE_ACK   default "1" (set "0" to allow without ACK).
# - TCD_PROM_BIND_ADDR                       bind addr (default "0.0.0.0").
# - TCD_METRICS_PROFILE                      "internal" (default) or "external"
#     external => aggressively hashes + minimizes leakage; unknown codes can be dropped.
# - TCD_METRIC_SURFACE_VERSION               "v1" (default) or "minimal"
# - TCD_METRICS_HASH_PII_LABELS              default "1"
# - TCD_METRICS_ALLOW_RAW_PII_LABELS         default "0" (NOT recommended)
# - TCD_METRICS_REQUIRE_HMAC_EXTERNAL        default "1" (external profile requires HMAC)
# - TCD_METRICS_EXTERNAL_HMAC_MISSING_MODE   "star"(default) or "fail"
#     star => replace hashed labels with "*" and continue; fail => disable exporter backend (no throw).
# - TCD_METRICS_LABEL_HMAC_KEY_HEX           active key hex
# - TCD_METRICS_LABEL_HMAC_KEY_ID            active key id (short)
# - TCD_METRICS_LABEL_HMAC_OLD_KEY_HEX       optional old/retiring key hex
# - TCD_METRICS_LABEL_HMAC_OLD_KEY_ID        optional old/retiring key id
# - TCD_METRICS_LABEL_HMAC_KEY_USE           "auto"(default) | "active" | "old"
# - TCD_METRICS_LABEL_HMAC_ROTATE_AFTER_EPOCH  optional epoch seconds; auto uses old until this time.
# - TCD_METRICS_HASH_CACHE_SIZE              default 4096 (bounded)
# - TCD_METRICS_MAX_LABEL_INPUT_KEYS         default 32 (drop updates with huge label dicts)
# - TCD_METRICS_MAX_PAYLOAD_KEYS             default 128 (drop push payloads with huge dicts)
# - TCD_METRICS_MAX_SERIES_PER_METRIC        default 5000 internal / 1000 external
# - TCD_METRICS_MAX_SERIES_TOTAL             default 20000 internal / 5000 external
# - TCD_METRICS_EXTERNAL_DROP_UNKNOWN_CODES  default "1" (drop events with unknown stage/reason/etc)
# - TCD_METRICS_LATENCY_UNIT                 "seconds"(default) or "ms"
# - TCD_METRICS_LATENCY_AUTO_CONVERT_MS      "1" converts suspicious seconds->ms inputs (default "0")
# - TCD_METRICS_EXTERNAL_RISK_QUANTIZE        default "1" (quantize risk observations in external)
# - TCD_METRICS_EXTERNAL_RISK_QUANTIZE_STEP   default 0.2 (clamped to [0.05, 0.5])
#
# NOTE:
# - Labels MUST be low cardinality. This module enforces structure + budgets,
#   but upstream should still pass stable, low-card enums/IDs (prefer pre-hashed IDs).

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import math
import os
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, FrozenSet, Tuple, Literal

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional Prometheus backend
# ---------------------------------------------------------------------------

try:
    from prometheus_client import (
        Counter,
        Histogram,
        Gauge,
        Info,
        CollectorRegistry,
        start_http_server,
        REGISTRY,
    )

    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover
    Counter = Histogram = Gauge = Info = CollectorRegistry = None  # type: ignore[assignment]
    start_http_server = None  # type: ignore[assignment]
    REGISTRY = None  # type: ignore[assignment]
    _PROM_AVAILABLE = False
    logger.info("prometheus_client not available; TCDPrometheusExporter will act as a no-op backend.")

# Optional repo canonical hashing (nice-to-have governance anchor; never required at runtime)
try:
    from .kv import canonical_kv_hash  # type: ignore
except Exception:  # pragma: no cover
    canonical_kv_hash = None  # type: ignore[assignment]

__all__ = ["TCDPrometheusExporter", "ExporterConfig", "DecisionMetricsEvent"]

# ---------------------------------------------------------------------------
# Env helpers (never-throw)
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    s = str(raw).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = int(str(raw).strip())
    except Exception:
        return default
    if v < min_v:
        return min_v
    if v > max_v:
        return max_v
    return v


def _env_float(name: str, default: float, *, min_v: float, max_v: float) -> float:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        v = float(str(raw).strip())
    except Exception:
        return default
    if not math.isfinite(v):
        return default
    if v < min_v:
        return min_v
    if v > max_v:
        return max_v
    return v


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip()


# ---------------------------------------------------------------------------
# Sanitization primitives (context-aware; avoids str() on arbitrary objects)
# ---------------------------------------------------------------------------

_CTRL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+")
_WS_RE = re.compile(r"\s+")

# Token/secret heuristics: ONLY used for kind="token" (and a tiny subset of strict safety checks)
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_LONG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")
_PEM_RE = re.compile(r"BEGIN (?:ENCRYPTED )?PRIVATE KEY", re.IGNORECASE)

_SafeKind = Literal["label", "hash", "id", "token"]


def _safe_text(value: Any, *, max_len: int, kind: _SafeKind) -> str:
    """
    Convert values to bounded strings safely.

    L7 rule: do NOT call str() on arbitrary objects (can trigger expensive / side-effectful __str__).
    Allowed conversions:
      - str/int/float/bool/None
      - bytes/bytearray/memoryview -> "<bytes>" (labels should never carry raw bytes)

    kind:
      - "hash"/"id": allow long hex; NO token redaction (prevents mis-redaction of config hashes).
      - "label": low-risk cleaning; bounded; no long-hex redaction.
      - "token": strong redaction (JWT/long-hex/PEM markers/auth fragments).
    """
    if value is None:
        return ""

    s: str
    if isinstance(value, str):
        s = value
    elif isinstance(value, bool):
        s = "true" if value else "false"
    elif isinstance(value, int):
        s = str(value)
    elif isinstance(value, float):
        if not math.isfinite(value):
            return ""
        s = f"{value:.12g}"
    elif isinstance(value, (bytes, bytearray, memoryview)):
        return "<bytes>"
    else:
        # avoid arbitrary __str__
        return f"<{type(value).__name__}>"

    s = _CTRL_RE.sub("", s)
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = _WS_RE.sub(" ", s).strip()

    if kind == "token":
        low = s.lower()
        if _PEM_RE.search(s) or "authorization:" in low or "bearer " in low:
            return "<redacted>"
        if _JWT_RE.search(s) or _LONG_HEX_RE.search(s):
            return "<redacted>"

    # Minimal safety: if it clearly contains an auth header fragment or PEM marker, redact even in "label".
    # (We intentionally do NOT redact long-hex in label/hash/id; to avoid killing config/ruleset hashes.)
    if kind in {"label"}:
        low = s.lower()
        if _PEM_RE.search(s) or "authorization:" in low or "bearer " in low:
            return "<redacted>"

    if max_len > 0 and len(s) > max_len:
        s = s[:max_len]
    return s


def _clamp01(x: float) -> float:
    if not math.isfinite(x):
        return 0.0
    if x < 0.0:
        return 0.0
    if x > 1.0:
        return 1.0
    return x


# ---------------------------------------------------------------------------
# Label hashing with bounded cache + key rotation support
# ---------------------------------------------------------------------------

_HmacKeyUse = Literal["auto", "active", "old"]


@dataclass(frozen=True, slots=True)
class _HmacKeyring:
    active_key: Optional[bytes]
    active_kid: str
    old_key: Optional[bytes]
    old_kid: str
    use: _HmacKeyUse
    rotate_after_epoch: float

    def has_any_hmac(self) -> bool:
        return (self.active_key is not None) or (self.old_key is not None)

    def select(self) -> Tuple[Optional[bytes], str, str]:
        """
        Returns (key_bytes, kid, key_tag) where key_tag is "a" or "o" for cache key segregation.
        """
        now = time.time()
        if self.use == "active":
            if self.active_key is not None:
                return self.active_key, self.active_kid, "a"
            if self.old_key is not None:
                return self.old_key, self.old_kid, "o"
            return None, self.active_kid or self.old_kid, "n"

        if self.use == "old":
            if self.old_key is not None:
                return self.old_key, self.old_kid, "o"
            if self.active_key is not None:
                return self.active_key, self.active_kid, "a"
            return None, self.old_kid or self.active_kid, "n"

        # auto
        if self.old_key is not None and now < self.rotate_after_epoch:
            return self.old_key, self.old_kid, "o"
        if self.active_key is not None:
            return self.active_key, self.active_kid, "a"
        if self.old_key is not None:
            return self.old_key, self.old_kid, "o"
        return None, self.active_kid or self.old_kid, "n"


class _LabelHasher:
    """
    Bounded cache of label hashes. Cache does NOT retain raw label values.

    Domain prefix is aligned to: "tcd:v1:metrics:{ctx}:"
    Output format: "h-<kid>-<32hex>" (128-bit fingerprint)
    """

    def __init__(self, *, keyring: _HmacKeyring, cache_size: int) -> None:
        self._keyring = keyring
        self._cache_size = max(0, int(cache_size))
        self._lock = threading.Lock()
        self._cache: Dict[bytes, str] = {}
        self._order: deque[bytes] = deque()

    def hmac_present(self) -> bool:
        return self._keyring.has_any_hmac()

    def hash(self, value: str, *, ctx: str) -> str:
        v = value.encode("utf-8", errors="replace")
        prefix = f"tcd:v1:metrics:{ctx}:".encode("utf-8")

        key, kid, key_tag = self._keyring.select()
        kid_s = _safe_text(kid, max_len=16, kind="id")

        # Cache key includes key_tag so cache doesn't go stale across rotation.
        cache_key = hashlib.sha256(key_tag.encode("utf-8") + b"|" + prefix + v).digest()[:16]

        if self._cache_size > 0:
            with self._lock:
                hit = self._cache.get(cache_key)
                if hit is not None:
                    return hit

        if key is not None:
            dig = hmac.new(key, prefix + v, hashlib.sha256).digest()
        else:
            # Weak hash fallback (caller MUST gate for external when HMAC required).
            dig = hashlib.sha256(prefix + v).digest()

        short = dig[:16].hex()
        out = f"h-{kid_s}-{short}" if kid_s else f"h-{short}"

        if self._cache_size > 0:
            with self._lock:
                if cache_key in self._cache:
                    return self._cache[cache_key]
                if len(self._order) >= self._cache_size:
                    old = self._order.popleft()
                    self._cache.pop(old, None)
                self._cache[cache_key] = out
                self._order.append(cache_key)

        return out


# ---------------------------------------------------------------------------
# Metric surface (schema-driven single source of truth)
# ---------------------------------------------------------------------------

MetricKind = Literal["counter", "gauge", "histogram", "info"]


@dataclass(frozen=True, slots=True)
class MetricSpec:
    name: str
    kind: MetricKind
    documentation: str
    labelnames: Tuple[str, ...] = ()
    buckets: Optional[Tuple[float, ...]] = None


# v1 surface
_METRIC_SPECS_V1: Mapping[str, MetricSpec] = MappingProxyType(
    {
        # Core decision / latency / SLO
        "tcd_request_latency_seconds": MetricSpec(
            name="tcd_request_latency_seconds",
            kind="histogram",
            documentation="Latency of requests passing through TCD",
            labelnames=("action",),
            buckets=(0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0),
        ),
        "tcd_decision_total": MetricSpec(
            name="tcd_decision_total",
            kind="counter",
            documentation="Number of decisions taken by TCD",
            labelnames=("action", "model_id"),
        ),
        "tcd_decision_risk": MetricSpec(
            name="tcd_decision_risk",
            kind="histogram",
            documentation="Distribution of risk scores at decision time",
            labelnames=("action",),
            buckets=(0.0, 0.1, 0.2, 0.4, 0.6, 0.8, 0.9, 0.95, 0.99, 1.0),
        ),
        "tcd_action_total": MetricSpec(
            name="tcd_action_total",
            kind="counter",
            documentation="Actions taken by TCD, broken down by model and GPU",
            labelnames=("model_id", "gpu_id", "action"),
        ),
        "tcd_slo_violation_total": MetricSpec(
            name="tcd_slo_violation_total",
            kind="counter",
            documentation="SLO violations observed by TCD",
            labelnames=("key", "model_id", "gpu_id"),
        ),
        "tcd_decision_seq_total": MetricSpec(
            name="tcd_decision_seq_total",
            kind="gauge",
            documentation="Monotone decision sequence index for TCD (per tenant/policy)",
            labelnames=("tenant", "policy"),
        ),
        # Statistical control / budget
        "tcd_eprocess_wealth": MetricSpec(
            name="tcd_eprocess_wealth",
            kind="gauge",
            documentation="Current e-process / alpha-wealth for the safety controller",
            labelnames=("tenant", "policy"),
        ),
        "tcd_eprocess_pvalue": MetricSpec(
            name="tcd_eprocess_pvalue",
            kind="gauge",
            documentation="Last p-value / test statistic snapshot for the safety controller",
            labelnames=("tenant", "policy"),
        ),
        "tcd_budget_remaining": MetricSpec(
            name="tcd_budget_remaining",
            kind="gauge",
            documentation="Remaining safety / call budget per tenant-user-session",
            labelnames=("tenant", "user", "session"),
        ),
        "tcd_budget_spent_total": MetricSpec(
            name="tcd_budget_spent_total",
            kind="counter",
            documentation="Number of times budget was spent/exhausted",
            labelnames=("tenant", "user", "session"),
        ),
        # Alpha/FDR control
        "tcd_alpha_budget_initial": MetricSpec(
            name="tcd_alpha_budget_initial",
            kind="gauge",
            documentation="Initial alpha budget for a tenant/policy",
            labelnames=("tenant", "policy"),
        ),
        "tcd_alpha_budget_used": MetricSpec(
            name="tcd_alpha_budget_used",
            kind="gauge",
            documentation="Used alpha budget for a tenant/policy",
            labelnames=("tenant", "policy"),
        ),
        "tcd_alpha_budget_reset_total": MetricSpec(
            name="tcd_alpha_budget_reset_total",
            kind="counter",
            documentation="Number of times alpha budget was reset",
            labelnames=("tenant", "policy", "reason"),
        ),
        "tcd_fdr_estimate": MetricSpec(
            name="tcd_fdr_estimate",
            kind="gauge",
            documentation="Current FDR estimate under the safety controller",
            labelnames=("tenant", "policy"),
        ),
        # Safety / threat taxonomy
        "tcd_safety_event_total": MetricSpec(
            name="tcd_safety_event_total",
            kind="counter",
            documentation="Categorized safety events observed by TCD",
            labelnames=("event_type", "stage", "severity", "policy", "scenario_id", "traffic_class"),
        ),
        "tcd_decision_path_total": MetricSpec(
            name="tcd_decision_path_total",
            kind="counter",
            documentation="Decision paths taken by TCD (allow/slow/degrade/block + path)",
            labelnames=("path", "fallback_used", "policy"),
        ),
        "tcd_fail_open_total": MetricSpec(
            name="tcd_fail_open_total",
            kind="counter",
            documentation="Fail-open events in TCD",
            labelnames=("reason", "policy"),
        ),
        "tcd_fail_closed_total": MetricSpec(
            name="tcd_fail_closed_total",
            kind="counter",
            documentation="Fail-closed events in TCD",
            labelnames=("reason", "policy"),
        ),
        "tcd_detector_fallback_total": MetricSpec(
            name="tcd_detector_fallback_total",
            kind="counter",
            documentation="Detector / calibrator fallback usage in TCD",
            labelnames=("stage", "reason", "policy"),
        ),
        "tcd_adversarial_pattern_total": MetricSpec(
            name="tcd_adversarial_pattern_total",
            kind="counter",
            documentation="Adversarial pattern detections (e.g., probing, injection attempts)",
            labelnames=("pattern_type", "tenant", "policy"),
        ),
        # Governance: prevent Info churn from becoming a labelset leak
        "tcd_config_hash_changed_total": MetricSpec(
            name="tcd_config_hash_changed_total",
            kind="counter",
            documentation="Number of times an attempt was made to change config_hash (Info churn prevented)",
        ),
        "tcd_config_hash_last_changed_timestamp": MetricSpec(
            name="tcd_config_hash_last_changed_timestamp",
            kind="gauge",
            documentation="Unix timestamp of the last attempted config_hash change (Info churn prevented)",
        ),
        "tcd_ruleset_hash_changed_total": MetricSpec(
            name="tcd_ruleset_hash_changed_total",
            kind="counter",
            documentation="Number of times an attempt was made to change ruleset_hash (Info churn prevented)",
        ),
        "tcd_ruleset_hash_last_changed_timestamp": MetricSpec(
            name="tcd_ruleset_hash_last_changed_timestamp",
            kind="gauge",
            documentation="Unix timestamp of the last attempted ruleset_hash change (Info churn prevented)",
        ),
        # Exporter self-health
        "tcd_metrics_dropped_samples_total": MetricSpec(
            name="tcd_metrics_dropped_samples_total",
            kind="counter",
            documentation="Number of dropped/ignored metric updates",
            labelnames=("reason",),
        ),
        "tcd_metrics_observe_errors_total": MetricSpec(
            name="tcd_metrics_observe_errors_total",
            kind="counter",
            documentation="Number of errors while updating metrics",
            labelnames=("metric_name",),
        ),
        "tcd_metrics_last_success_timestamp": MetricSpec(
            name="tcd_metrics_last_success_timestamp",
            kind="gauge",
            documentation="Unix timestamp of the last successful metric update",
        ),
        "tcd_metrics_enabled": MetricSpec(
            name="tcd_metrics_enabled",
            kind="gauge",
            documentation="1 if metrics backend is enabled and available, else 0",
        ),
        "tcd_metrics_init_ok": MetricSpec(
            name="tcd_metrics_init_ok",
            kind="gauge",
            documentation="1 if exporter initialized successfully, else 0",
        ),
        "tcd_metrics_init_error_total": MetricSpec(
            name="tcd_metrics_init_error_total",
            kind="counter",
            documentation="Number of metric initialization errors",
            labelnames=("code",),
        ),
        "tcd_metrics_cardinality_budget_hit_total": MetricSpec(
            name="tcd_metrics_cardinality_budget_hit_total",
            kind="counter",
            documentation="Number of times a new labelset was rejected due to cardinality budgets",
            labelnames=("metric_name",),
        ),
        "tcd_metrics_unknown_code_total": MetricSpec(
            name="tcd_metrics_unknown_code_total",
            kind="counter",
            documentation="Number of times an unknown code value was provided for a code-enforced label",
            labelnames=("label_key", "metric_name"),
        ),
        "tcd_metrics_last_error_timestamp": MetricSpec(
            name="tcd_metrics_last_error_timestamp",
            kind="gauge",
            documentation="Unix timestamp of the last metric update error",
        ),
        "tcd_metrics_last_error_code": MetricSpec(
            name="tcd_metrics_last_error_code",
            kind="gauge",
            documentation="Gauge with code label indicating the last error class (1=current, 0=not current)",
            labelnames=("code",),
        ),
        "tcd_metrics_standalone_server_started": MetricSpec(
            name="tcd_metrics_standalone_server_started",
            kind="gauge",
            documentation="1 if a standalone Prometheus HTTP server was started by this process",
        ),
        # Info metrics
        "tcd_build_info": MetricSpec(
            name="tcd_build_info",
            kind="info",
            documentation="TCD build metadata (stabilized; no churn)",
        ),
        "tcd_metrics_backend_info": MetricSpec(
            name="tcd_metrics_backend_info",
            kind="info",
            documentation="TCD metrics backend status and profile (stabilized; static)",
        ),
    }
)

_KNOWN_SURFACES: FrozenSet[str] = frozenset({"v1", "minimal"})


def _minimal_surface(specs: Mapping[str, MetricSpec]) -> Mapping[str, MetricSpec]:
    # External / unknown => minimal: self-health + build/backend info + governance anti-churn counters
    keep = {
        "tcd_build_info",
        "tcd_metrics_backend_info",
        "tcd_config_hash_changed_total",
        "tcd_config_hash_last_changed_timestamp",
        "tcd_ruleset_hash_changed_total",
        "tcd_ruleset_hash_last_changed_timestamp",
    }
    return MappingProxyType({k: v for k, v in specs.items() if k.startswith("tcd_metrics_") or k in keep})


_METRIC_SPECS_MINIMAL: Mapping[str, MetricSpec] = _minimal_surface(_METRIC_SPECS_V1)


def _select_metric_surface(surface: str, *, profile: str) -> Mapping[str, MetricSpec]:
    s = (surface or "v1").strip().lower()
    if s not in _KNOWN_SURFACES:
        # Unknown surface => minimal for BOTH internal and external (safe default)
        return _METRIC_SPECS_MINIMAL
    if s == "minimal":
        return _METRIC_SPECS_MINIMAL
    return _METRIC_SPECS_V1


# ---------------------------------------------------------------------------
# Label domain constraints (value-domain enforcement)
# ---------------------------------------------------------------------------

_ALLOWED_ACTIONS: FrozenSet[str] = frozenset(
    {
        "allow",
        "block",
        "degrade",
        "throttle",
        "slow",
        "cool",
        "review",
        "ask_for_review",
        "escalate_to_human",
        "unknown",
        "error",
        "other",
    }
)
_ALLOWED_SEVERITIES: FrozenSet[str] = frozenset({"low", "medium", "high", "critical", "other"})
_ALLOWED_TRAFFIC_CLASSES: FrozenSet[str] = frozenset({"prod", "shadow", "replay", "test", "canary", "unknown", "other"})
_ALLOWED_FALLBACK_USED: FrozenSet[str] = frozenset(
    {"none", "detector", "decision_engine", "calibrator", "conformal", "fail_closed", "fail_open", "unknown", "other"}
)
_ALLOWED_SLO_KEYS: FrozenSet[str] = frozenset(
    {
        "latency_p95",
        "latency_p99",
        "latency_slo",
        "error_rate",
        "risk_budget",
        "fdr_violation",
        "alpha_budget_overshoot",
        "pq_violation",
        "unknown",
        "other",
    }
)
_ALLOWED_REASONS: FrozenSet[str] = frozenset(
    {
        "timeout",
        "model_error",
        "calibrator_error",
        "bad_input",
        "fallback",
        "policy_override",
        "unknown",
        "unspecified",
        "other",
    }
)
_ALLOWED_STAGES: FrozenSet[str] = frozenset(
    {
        "pre_filter",
        "post_model",
        "calibrator",
        "conformal",
        "decision_engine",
        "exporter",
        "unknown",
        "other",
    }
)
_ALLOWED_EVENT_TYPES: FrozenSet[str] = frozenset(
    {
        "prompt_injection",
        "jailbreak",
        "exfiltration",
        "policy_violation",
        "abuse",
        "probing",
        "anomaly",
        "system_error",
        "unknown",
        "other",
    }
)
_ALLOWED_PATTERN_TYPES: FrozenSet[str] = frozenset(
    {
        "probing",
        "prompt_injection",
        "exfiltration",
        "jailbreak",
        "evasion",
        "dos",
        "unknown",
        "other",
    }
)

# Requested regex hardening
_MODEL_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_POLICY_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,31}$")
_GPU_ID_RE = re.compile(r"^(?:gpu|mig)\d{1,4}$")
_SCENARIO_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,16}$")

# Sentinel for "drop this update" (must not be a valid label value)
_DROP = "\u0000__TCD_DROP__\u0000"

# Code-enforced label keys (for unknown_code_total)
_CODE_KEYS: FrozenSet[str] = frozenset(
    {"action", "severity", "traffic_class", "fallback_used", "key", "reason", "stage", "event_type", "pattern_type"}
)


def _template_path(s: str) -> str:
    """
    Reduce path-like strings to a low-cardinality template.
    Example:
      "/v1/chat/completions/123" -> "/v1/*/completions/*"
    """
    if not s:
        return ""
    s = s.strip()
    if not s.startswith("/"):
        return s[:64]
    parts = [p for p in s.split("/") if p]
    out: list[str] = []
    for p in parts[:6]:
        if not p:
            continue
        # mask numeric-ish / long-ish / hex-ish
        if p.isdigit() or (len(p) > 24) or _LONG_HEX_RE.fullmatch(p):
            out.append("*")
            continue
        # UUID-ish
        if p.count("-") >= 3 and len(p) >= 16:
            out.append("*")
            continue
        out.append(p)
    if len(parts) > 6:
        out.append("*")
    return "/" + "/".join(out)


# ---------------------------------------------------------------------------
# Cardinality budgets (process-wide per registry)
# ---------------------------------------------------------------------------

@dataclass
class _CardinalityBudget:
    max_series_per_metric: int
    max_series_total: int


class _CardinalityTracker:
    """
    Prevents unbounded growth of Prometheus child series.

    IMPORTANT: we do NOT evict admitted series.
      - Prom cannot delete series.
      - Eviction would allow infinite series creation (unsafe).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._budget = _CardinalityBudget(max_series_per_metric=5000, max_series_total=20000)
        self._admitted_per_metric: Dict[str, set[str]] = defaultdict(set)
        self._admitted_total: set[Tuple[str, str]] = set()

    def configure_min(self, budget: _CardinalityBudget) -> None:
        with self._lock:
            self._budget = _CardinalityBudget(
                max_series_per_metric=min(self._budget.max_series_per_metric, budget.max_series_per_metric),
                max_series_total=min(self._budget.max_series_total, budget.max_series_total),
            )

    def admit(self, metric_name: str, sig: str) -> bool:
        with self._lock:
            key = (metric_name, sig)
            if key in self._admitted_total:
                return True
            if len(self._admitted_total) >= self._budget.max_series_total:
                return False

            s = self._admitted_per_metric[metric_name]
            if sig in s:
                return True
            if len(s) >= self._budget.max_series_per_metric:
                return False

            s.add(sig)
            self._admitted_total.add(key)
            return True


_TRACKERS: Dict[int, _CardinalityTracker] = {}
_TRACKERS_LOCK = threading.Lock()


def _tracker_for_registry(registry: Any) -> _CardinalityTracker:
    rid = id(registry)
    with _TRACKERS_LOCK:
        t = _TRACKERS.get(rid)
        if t is None:
            t = _CardinalityTracker()
            _TRACKERS[rid] = t
        return t


# ---------------------------------------------------------------------------
# Standalone server state (process-wide) with (addr,port,registry_id) keying
# ---------------------------------------------------------------------------

@dataclass
class _ServerState:
    started: bool = False
    port: int = 0
    bind_addr: str = "0.0.0.0"
    registry_id: int = 0
    start_time: float = 0.0
    started_by: str = ""
    last_error: str = ""


_SERVER_LOCK = threading.Lock()
_SERVER_STATE: Dict[Tuple[str, int, int], _ServerState] = {}
_BIND_OCCUPANCY: Dict[Tuple[str, int], int] = {}  # (addr,port)->registry_id


# ---------------------------------------------------------------------------
# Info stabilization (prevents Info churn => series leak)
# ---------------------------------------------------------------------------

_INFO_LOCK = threading.Lock()
_INFO_VALUES: Dict[Tuple[int, str], Dict[str, str]] = {}  # (registry_id, metric_name) -> stable labels


# ---------------------------------------------------------------------------
# Exporter config (immutable snapshot; env parsed here)
# ---------------------------------------------------------------------------

LatencyUnit = Literal["seconds", "ms"]
HmacMissingMode = Literal["star", "fail"]


@dataclass(frozen=True, slots=True)
class ExporterConfig:
    metrics_disabled: bool
    profile: Literal["internal", "external"]
    metric_surface_version: str

    # Label hashing / privacy
    hash_pii_labels: bool
    allow_raw_pii_labels: bool
    require_hmac_external: bool
    external_hmac_missing_mode: HmacMissingMode

    # Keyring + caching
    hmac_keyring: _HmacKeyring
    label_hash_cache_size: int

    # Input hardening
    max_label_input_keys: int
    max_payload_keys: int

    # Cardinality budgets
    max_series_per_metric: int
    max_series_total: int

    # Standalone server
    standalone_server: bool
    bind_addr: str
    standalone_ack: str
    standalone_require_ack: bool

    # Numeric policies
    latency_unit: LatencyUnit
    latency_auto_convert_ms: bool

    # External strictness
    external_drop_unknown_codes: bool
    external_risk_quantize: bool
    external_risk_quantize_step: float

    @staticmethod
    def from_env(*, profile: Optional[str] = None, metric_surface_version: Optional[str] = None) -> "ExporterConfig":
        metrics_disabled = _env_bool("TCD_METRICS_DISABLE", False)

        prof = (profile or _env_str("TCD_METRICS_PROFILE", "internal")).strip().lower()
        if prof not in ("internal", "external"):
            prof = "internal"
        profile_norm: Literal["internal", "external"] = "external" if prof == "external" else "internal"

        surface = (metric_surface_version or _env_str("TCD_METRIC_SURFACE_VERSION", "v1")).strip().lower()
        if surface not in _KNOWN_SURFACES:
            surface = "minimal"

        hash_pii = _env_bool("TCD_METRICS_HASH_PII_LABELS", True)
        allow_raw = _env_bool("TCD_METRICS_ALLOW_RAW_PII_LABELS", False)
        require_hmac_external = _env_bool("TCD_METRICS_REQUIRE_HMAC_EXTERNAL", True)

        hmac_missing_mode_raw = _env_str("TCD_METRICS_EXTERNAL_HMAC_MISSING_MODE", "star").strip().lower()
        external_hmac_missing_mode: HmacMissingMode = "fail" if hmac_missing_mode_raw == "fail" else "star"

        # Active key
        active_kid = _env_str("TCD_METRICS_LABEL_HMAC_KEY_ID", "")[:32]
        active_hex = _env_str("TCD_METRICS_LABEL_HMAC_KEY_HEX", "")
        active_key: Optional[bytes] = None
        if active_hex:
            try:
                if len(active_hex) >= 32 and (len(active_hex) % 2 == 0):
                    active_key = bytes.fromhex(active_hex)
            except Exception:
                active_key = None

        # Old/retiring key
        old_kid = _env_str("TCD_METRICS_LABEL_HMAC_OLD_KEY_ID", "")[:32]
        old_hex = _env_str("TCD_METRICS_LABEL_HMAC_OLD_KEY_HEX", "")
        old_key: Optional[bytes] = None
        if old_hex:
            try:
                if len(old_hex) >= 32 and (len(old_hex) % 2 == 0):
                    old_key = bytes.fromhex(old_hex)
            except Exception:
                old_key = None

        use_raw = _env_str("TCD_METRICS_LABEL_HMAC_KEY_USE", "auto").strip().lower()
        use: _HmacKeyUse = "active" if use_raw == "active" else ("old" if use_raw == "old" else "auto")
        rotate_after = _env_float(
            "TCD_METRICS_LABEL_HMAC_ROTATE_AFTER_EPOCH",
            default=0.0,
            min_v=0.0,
            max_v=4_000_000_000.0,
        )
        if rotate_after <= 0.0:
            # If unset, default to "now" so auto will prefer active (if present)
            rotate_after = time.time()

        keyring = _HmacKeyring(
            active_key=active_key,
            active_kid=_safe_text(active_kid, max_len=16, kind="id"),
            old_key=old_key,
            old_kid=_safe_text(old_kid, max_len=16, kind="id"),
            use=use,
            rotate_after_epoch=rotate_after,
        )

        cache_size = _env_int("TCD_METRICS_HASH_CACHE_SIZE", 4096, min_v=0, max_v=100_000)

        max_label_input_keys = _env_int("TCD_METRICS_MAX_LABEL_INPUT_KEYS", 32, min_v=4, max_v=256)
        max_payload_keys = _env_int("TCD_METRICS_MAX_PAYLOAD_KEYS", 128, min_v=16, max_v=10_000)

        # Cardinality budgets default by profile
        if profile_norm == "external":
            per_metric_default = 1000
            total_default = 5000
        else:
            per_metric_default = 5000
            total_default = 20000

        max_series_per_metric = _env_int(
            "TCD_METRICS_MAX_SERIES_PER_METRIC", per_metric_default, min_v=100, max_v=1_000_000
        )
        max_series_total = _env_int("TCD_METRICS_MAX_SERIES_TOTAL", total_default, min_v=500, max_v=5_000_000)

        standalone_server = _env_bool("TCD_PROM_STANDALONE_SERVER", False)
        bind_addr = _env_str("TCD_PROM_BIND_ADDR", "0.0.0.0") or "0.0.0.0"
        standalone_ack = _env_str("TCD_PROM_STANDALONE_SERVER_ACK", "")
        standalone_require_ack = _env_bool("TCD_PROM_STANDALONE_SERVER_REQUIRE_ACK", True)

        latency_unit_raw = _env_str("TCD_METRICS_LATENCY_UNIT", "seconds").strip().lower()
        latency_unit: LatencyUnit = "ms" if latency_unit_raw == "ms" else "seconds"
        latency_auto_convert_ms = _env_bool("TCD_METRICS_LATENCY_AUTO_CONVERT_MS", False)

        external_drop_unknown_codes = _env_bool("TCD_METRICS_EXTERNAL_DROP_UNKNOWN_CODES", True)
        external_risk_quantize = _env_bool("TCD_METRICS_EXTERNAL_RISK_QUANTIZE", True)
        step = _env_float("TCD_METRICS_EXTERNAL_RISK_QUANTIZE_STEP", 0.2, min_v=0.05, max_v=0.5)

        return ExporterConfig(
            metrics_disabled=bool(metrics_disabled),
            profile=profile_norm,
            metric_surface_version=surface,
            hash_pii_labels=bool(hash_pii),
            allow_raw_pii_labels=bool(allow_raw),
            require_hmac_external=bool(require_hmac_external),
            external_hmac_missing_mode=external_hmac_missing_mode,
            hmac_keyring=keyring,
            label_hash_cache_size=int(cache_size),
            max_label_input_keys=int(max_label_input_keys),
            max_payload_keys=int(max_payload_keys),
            max_series_per_metric=int(max_series_per_metric),
            max_series_total=int(max_series_total),
            standalone_server=bool(standalone_server),
            bind_addr=bind_addr,
            standalone_ack=standalone_ack,
            standalone_require_ack=bool(standalone_require_ack),
            latency_unit=latency_unit,
            latency_auto_convert_ms=bool(latency_auto_convert_ms),
            external_drop_unknown_codes=bool(external_drop_unknown_codes),
            external_risk_quantize=bool(external_risk_quantize),
            external_risk_quantize_step=float(step),
        )


# ---------------------------------------------------------------------------
# Recommended structured input type (prevents payload ambiguity)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class DecisionMetricsEvent:
    action: str = "unknown"
    risk: Optional[float] = None
    model_id: str = ""
    gpu_id: str = ""
    tenant: str = ""
    user: str = ""
    session: str = ""
    policy: str = ""
    decision_seq: Optional[float] = None
    path: str = ""
    fallback_used: str = "none"
    scenario_id: str = ""
    traffic_class: str = "prod"
    # Optional safety event taxonomy
    event_type: str = ""
    stage: str = ""
    severity: str = "low"


# ---------------------------------------------------------------------------
# Drop reasons (strict enumeration)
# ---------------------------------------------------------------------------

_DroppedReason = Literal[
    "label_filtered",
    "unknown_metric",
    "invalid_value",
    "invalid_unit",
    "label_input_too_large",
    "payload_input_too_large",
    "cardinality_budget",
    "collector_conflict",
    "invalid_payload",
    "hmac_required_missing",
    "unknown_code",
    "backend_unavailable",
    "metrics_disabled",
    "info_churn",
]


_DROPPED_REASONS: FrozenSet[str] = frozenset(
    {
        "label_filtered",
        "unknown_metric",
        "invalid_value",
        "invalid_unit",
        "label_input_too_large",
        "payload_input_too_large",
        "cardinality_budget",
        "collector_conflict",
        "invalid_payload",
        "hmac_required_missing",
        "unknown_code",
        "backend_unavailable",
        "metrics_disabled",
        "info_churn",
    }
)


# ---------------------------------------------------------------------------
# Exporter
# ---------------------------------------------------------------------------

class TCDPrometheusExporter:
    """
    Threat-aware Prometheus exporter for TCD.

    Backwards compatible constructor:
        exporter = TCDPrometheusExporter(port=9100, version="1.0.0", config_hash="abc123")

    Notes:
    - Pass a custom registry to isolate metrics in tests/multiprocess setups.
    - profile="external" enforces minimal leakage and strict code-domain behavior.
    """

    def __init__(
        self,
        port: int,
        version: str,
        config_hash: str,
        *,
        profile: Optional[str] = None,
        policy_version: Optional[str] = None,
        ruleset_hash: Optional[str] = None,
        metric_surface_version: Optional[str] = None,
        registry: Optional["CollectorRegistry"] = None,
    ) -> None:
        # Defensive port clamp
        try:
            p = int(port)
        except Exception:
            p = 9100
        if p < 1 or p > 65535:
            p = 9100
        self.port = p

        self._cfg = ExporterConfig.from_env(profile=profile, metric_surface_version=metric_surface_version)
        self._registry = registry if registry is not None else REGISTRY

        # Hard-disable policy if requested (never throw)
        self._disabled_reason: str = ""
        if self._cfg.metrics_disabled:
            self._disabled_reason = "metrics_disabled"

        # Governance / build fields (do NOT token-redact hashes)
        self.version = _safe_text(version, max_len=64, kind="id") or "unknown"
        self.config_hash_value = _safe_text(config_hash, max_len=128, kind="hash")
        self.policy_version = _safe_text(policy_version or _env_str("TCD_POLICY_VERSION", ""), max_len=64, kind="id")
        self.ruleset_hash = _safe_text(ruleset_hash or _env_str("TCD_RULESET_HASH", ""), max_len=128, kind="hash")
        self.metric_surface_version = _safe_text(self._cfg.metric_surface_version, max_len=32, kind="id") or "minimal"

        # Hasher
        self._hasher = _LabelHasher(keyring=self._cfg.hmac_keyring, cache_size=self._cfg.label_hash_cache_size)

        # External HMAC requirement enforcement (choose star vs fail; never throw)
        if (
            self._cfg.profile == "external"
            and self._cfg.require_hmac_external
            and (not self._cfg.allow_raw_pii_labels)
            and self._cfg.hash_pii_labels
            and (not self._hasher.hmac_present())
        ):
            if self._cfg.external_hmac_missing_mode == "fail":
                self._disabled_reason = "hmac_required_missing"
            else:
                # star mode: continue but with "*" substitution for would-be hashed labels
                pass

        # Surface selection driven by metric_surface_version and profile
        self._specs: Mapping[str, MetricSpec] = _select_metric_surface(self._cfg.metric_surface_version, profile=self._cfg.profile)

        # Init state
        self._lock = threading.Lock()
        self._initialized = False
        self._init_had_errors = False

        # Collector map
        self._m: Dict[str, Any] = {}

        # Local diagnostics (even when disabled/unavailable)
        self._local_counts: Dict[str, int] = defaultdict(int)
        self._last_success_ts_local: float = 0.0
        self._last_error_ts_local: float = 0.0
        self._last_error_code_local: str = "none"

        # Track last error code gauge state
        self._last_error_code_set: Optional[str] = None

        # Configure global cardinality tracker (min-merge budgets)
        if self._registry is not None:
            tracker = _tracker_for_registry(self._registry)
            tracker.configure_min(_CardinalityBudget(self._cfg.max_series_per_metric, self._cfg.max_series_total))

    # -----------------------------------------------------------------------
    # Backend availability
    # -----------------------------------------------------------------------

    def _metrics_enabled(self) -> bool:
        if self._disabled_reason:
            return False
        if not _PROM_AVAILABLE:
            return False
        if self._registry is None:
            return False
        return True

    def _disabled_reason_str(self) -> str:
        if self._disabled_reason:
            return self._disabled_reason
        if not _PROM_AVAILABLE:
            return "backend_unavailable"
        if self._registry is None:
            return "backend_unavailable"
        return ""

    # -----------------------------------------------------------------------
    # Collector lookup / reuse with strict compatibility checks
    # -----------------------------------------------------------------------

    def _lookup_existing_collector(self, name: str) -> Optional[Any]:
        reg = self._registry
        if reg is None:
            return None
        try:
            mapping = getattr(reg, "_names_to_collectors", None)
            if not isinstance(mapping, dict):
                return None

            # Try exact + common derived names / suffix variations
            candidates = [name]
            suffixes = ["_total", "_created", "_sum", "_count", "_bucket"]
            for suf in suffixes:
                candidates.append(name + suf)
            if name.endswith("_total"):
                base = name[: -len("_total")]
                candidates.append(base)
                for suf in suffixes:
                    candidates.append(base + suf)

            for c in candidates:
                ex = mapping.get(c)
                if ex is not None:
                    return ex

            # Last resort: scan mapping for prefix match (init-time only)
            for k, ex in mapping.items():
                if k == name or (isinstance(k, str) and (k.startswith(name + "_") or k.startswith(name))):
                    return ex
        except Exception:
            return None
        return None

    def _collector_ok(self, existing: Any, spec: MetricSpec) -> bool:
        if existing is None:
            return False

        # Type check (best-effort)
        try:
            if spec.kind == "counter" and Counter is not None and not isinstance(existing, Counter):
                return False
            if spec.kind == "gauge" and Gauge is not None and not isinstance(existing, Gauge):
                return False
            if spec.kind == "histogram" and Histogram is not None and not isinstance(existing, Histogram):
                return False
            if spec.kind == "info" and Info is not None and not isinstance(existing, Info):
                return False
        except Exception:
            return False

        # Labelnames check (Info has no static labelnames at ctor)
        if spec.kind != "info":
            try:
                ln = getattr(existing, "_labelnames", None)
                if ln is None or tuple(ln) != tuple(spec.labelnames):
                    return False
            except Exception:
                return False

        # Help/doc check (optional; warn only)
        try:
            doc = getattr(existing, "_documentation", None)
            if isinstance(doc, str) and doc and doc != spec.documentation:
                logger.warning(
                    "Collector doc mismatch for %s (existing=%r spec=%r) - reusing existing",
                    spec.name,
                    doc[:120],
                    spec.documentation[:120],
                )
        except Exception:
            pass

        return True

    def _record_init_error(self, code: str) -> None:
        self._init_had_errors = True
        self._local_counts[f"init_error:{code}"] += 1
        # If self-health metric exists, increment it (best-effort; never throw).
        c = self._m.get("tcd_metrics_init_error_total")
        if c is None:
            return
        try:
            labels = self._metric_labels("tcd_metrics_init_error_total", {"code": code})
            if labels is None:
                return
            if not self._admit_series("tcd_metrics_init_error_total", labels, collector=c):
                return
            c.labels(**labels).inc()
        except Exception:
            return

    def _get_or_create(self, spec: MetricSpec) -> Optional[Any]:
        if not self._metrics_enabled():
            return None

        if spec.kind == "info":
            try:
                return Info(spec.name, spec.documentation, registry=self._registry)  # type: ignore[misc]
            except ValueError:
                existing = self._lookup_existing_collector(spec.name)
                if self._collector_ok(existing, spec):
                    return existing
                self._record_init_error("collector_conflict")
                self._record_dropped_sample("collector_conflict")
                return None
            except Exception:
                self._record_init_error("init_exception")
                return None

        factory = {"counter": Counter, "gauge": Gauge, "histogram": Histogram}.get(spec.kind)
        if factory is None:
            self._record_init_error("unknown_kind")
            return None

        try:
            if spec.kind == "histogram":
                return factory(
                    spec.name,
                    spec.documentation,
                    spec.labelnames,
                    buckets=spec.buckets,
                    registry=self._registry,
                )
            return factory(spec.name, spec.documentation, spec.labelnames, registry=self._registry)
        except ValueError:
            existing = self._lookup_existing_collector(spec.name)
            if self._collector_ok(existing, spec):
                return existing
            self._record_init_error("collector_conflict")
            self._record_dropped_sample("collector_conflict")
            return None
        except Exception:
            self._record_init_error("init_exception")
            return None

    # -----------------------------------------------------------------------
    # Policy digest + config hash (auditable governance anchors)
    # -----------------------------------------------------------------------

    def _exporter_config_payload(self) -> Dict[str, Any]:
        # Full immutable snapshot (only primitive JSON-serializable + non-secret)
        return {
            "profile": self._cfg.profile,
            "surface": self._cfg.metric_surface_version,
            "metrics_disabled": bool(self._cfg.metrics_disabled),
            "hash_pii_labels": bool(self._cfg.hash_pii_labels),
            "allow_raw_pii_labels": bool(self._cfg.allow_raw_pii_labels),
            "require_hmac_external": bool(self._cfg.require_hmac_external),
            "external_hmac_missing_mode": self._cfg.external_hmac_missing_mode,
            "hmac_present": bool(self._hasher.hmac_present()),
            "active_kid": _safe_text(self._cfg.hmac_keyring.active_kid, max_len=16, kind="id"),
            "old_kid": _safe_text(self._cfg.hmac_keyring.old_kid, max_len=16, kind="id"),
            "hmac_key_use": self._cfg.hmac_keyring.use,
            "hmac_rotate_after_epoch": float(self._cfg.hmac_keyring.rotate_after_epoch),
            "hash_cache_size": int(self._cfg.label_hash_cache_size),
            "max_label_input_keys": int(self._cfg.max_label_input_keys),
            "max_payload_keys": int(self._cfg.max_payload_keys),
            "max_series_per_metric": int(self._cfg.max_series_per_metric),
            "max_series_total": int(self._cfg.max_series_total),
            "standalone_server": bool(self._cfg.standalone_server),
            "bind_addr": _safe_text(self._cfg.bind_addr, max_len=64, kind="id"),
            "standalone_require_ack": bool(self._cfg.standalone_require_ack),
            "latency_unit": self._cfg.latency_unit,
            "latency_auto_convert_ms": bool(self._cfg.latency_auto_convert_ms),
            "external_drop_unknown_codes": bool(self._cfg.external_drop_unknown_codes),
            "external_risk_quantize": bool(self._cfg.external_risk_quantize),
            "external_risk_quantize_step": float(self._cfg.external_risk_quantize_step),
        }

    def _hash_payload(self, payload: Dict[str, Any], *, label: str) -> str:
        if canonical_kv_hash is not None:
            try:
                return str(canonical_kv_hash(payload, ctx="tcd:metrics", label=label))
            except Exception:
                pass
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8", errors="replace")
        return hashlib.sha256(b"tcd:metrics|" + label.encode("utf-8") + b"|" + raw).hexdigest()

    def _exporter_config_hash(self) -> str:
        return self._hash_payload(self._exporter_config_payload(), label="exporter_cfg")

    def _exporter_policy_digest(self) -> str:
        # Policy digest is a governance-focused subset (still stable)
        payload = self._exporter_config_payload()
        # Slightly reduce for policy digest stability
        payload.pop("bind_addr", None)
        payload.pop("standalone_server", None)
        payload.pop("standalone_require_ack", None)
        payload.pop("hmac_rotate_after_epoch", None)
        return self._hash_payload(payload, label="exporter_policy")

    # -----------------------------------------------------------------------
    # Init: create metrics + stabilize Info + validate schema consistency
    # -----------------------------------------------------------------------

    def _init_metrics_if_needed(self) -> None:
        if not self._metrics_enabled():
            # Not silent: count locally for "why no data"
            self._local_counts[f"disabled:{self._disabled_reason_str()}"] += 1
            return
        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            # Create collectors from schema
            for name, spec in self._specs.items():
                col = self._get_or_create(spec)
                if col is not None:
                    self._m[name] = col

            # Validate labelnames consistency (defensive)
            for name, spec in self._specs.items():
                if spec.kind == "info":
                    continue
                col = self._m.get(name)
                if col is None:
                    continue
                try:
                    ln = getattr(col, "_labelnames", ())
                    if tuple(ln) != tuple(spec.labelnames):
                        self._record_init_error("schema_mismatch")
                        self._record_dropped_sample("collector_conflict")
                        self._m.pop(name, None)
                except Exception:
                    # if we can't validate, keep but mark init error
                    self._record_init_error("schema_validate_failed")

            # Set enabled gauge (backend is enabled here)
            try:
                g = self._m.get("tcd_metrics_enabled")
                if g is not None:
                    g.set(1.0)
            except Exception:
                pass

            # Set init_ok gauge (0 if we saw any init errors)
            try:
                g = self._m.get("tcd_metrics_init_ok")
                if g is not None:
                    g.set(0.0 if self._init_had_errors else 1.0)
            except Exception:
                pass

            # Stabilize & set Info metrics ONCE per (registry_id, name)
            cfg_hash = _safe_text(self._exporter_config_hash(), max_len=128, kind="hash")
            policy_digest = _safe_text(self._exporter_policy_digest(), max_len=128, kind="hash")

            self._set_info_once(
                "tcd_build_info",
                {
                    "version": self.version,
                    # keep these stable; if later mismatched, churn is prevented and change counters increment
                    "config_hash": self.config_hash_value,
                    "policy_version": self.policy_version,
                    "ruleset_hash": self.ruleset_hash,
                    "metric_surface_version": self.metric_surface_version,
                    "exporter_config_hash": cfg_hash,
                    "exporter_policy_digest": policy_digest,
                },
            )

            self._set_info_once(
                "tcd_metrics_backend_info",
                {
                    "prom_available": "1" if _PROM_AVAILABLE else "0",
                    "profile": self._cfg.profile,
                    "surface": self._cfg.metric_surface_version,
                    "metrics_disabled_config": "1" if self._cfg.metrics_disabled else "0",
                    "hash_pii_labels": "1" if self._cfg.hash_pii_labels else "0",
                    "allow_raw_pii_labels": "1" if self._cfg.allow_raw_pii_labels else "0",
                    "require_hmac_external": "1" if self._cfg.require_hmac_external else "0",
                    "external_hmac_missing_mode": self._cfg.external_hmac_missing_mode,
                    "hmac_present": "1" if self._hasher.hmac_present() else "0",
                    "active_kid": _safe_text(self._cfg.hmac_keyring.active_kid, max_len=16, kind="id"),
                    "old_kid": _safe_text(self._cfg.hmac_keyring.old_kid, max_len=16, kind="id"),
                    "hmac_key_use": self._cfg.hmac_keyring.use,
                    "external_drop_unknown_codes": "1" if self._cfg.external_drop_unknown_codes else "0",
                    "external_risk_quantize": "1" if self._cfg.external_risk_quantize else "0",
                },
            )

            self._initialized = True

    def _set_info_once(self, metric_name: str, labels: Dict[str, str]) -> None:
        """
        Sets Info metric exactly once per (registry, metric_name).
        Prevents series leaks from Info churn on repeated .info() calls.
        On mismatch:
          - Info update is skipped,
          - churn is counted (tcd_config_hash_changed_total / tcd_ruleset_hash_changed_total),
          - dropped_samples{reason="info_churn"} is incremented.
        """
        if not self._metrics_enabled():
            return
        col = self._m.get(metric_name)
        if col is None:
            return
        if self._registry is None:
            return
        rid = id(self._registry)
        key = (rid, metric_name)

        # sanitize label values for Info (ids/hashes only; never token-redact)
        clean: Dict[str, str] = {}
        for k, v in labels.items():
            kind: _SafeKind = "hash" if ("hash" in k or "digest" in k) else "id"
            clean[k] = _safe_text(v, max_len=128, kind=kind)

        with _INFO_LOCK:
            existing = _INFO_VALUES.get(key)
            if existing is None:
                _INFO_VALUES[key] = dict(clean)
                try:
                    col.info(clean)
                except Exception as e:
                    self._record_init_error("info_set_failed")
                    self._record_observe_error("info_set_failed", e)
                return

            if existing == clean:
                return

            # Mismatch => prevent churn + record governance counters
            try:
                if existing.get("config_hash", "") != clean.get("config_hash", ""):
                    self._counter_inc_nolabel("tcd_config_hash_changed_total")
                    self._gauge_set_nolabel("tcd_config_hash_last_changed_timestamp", time.time())
                if existing.get("ruleset_hash", "") != clean.get("ruleset_hash", ""):
                    self._counter_inc_nolabel("tcd_ruleset_hash_changed_total")
                    self._gauge_set_nolabel("tcd_ruleset_hash_last_changed_timestamp", time.time())
            except Exception:
                pass

            self._record_dropped_sample("info_churn")
            self._record_init_error("info_churn_prevented")

    # -----------------------------------------------------------------------
    # Label normalization + whitelist enforcement
    # -----------------------------------------------------------------------

    def _metric_labels(self, metric_name: str, label_values: Mapping[str, Any]) -> Optional[Dict[str, str]]:
        spec = self._specs.get(metric_name)
        if spec is None:
            self._record_dropped_sample("unknown_metric")
            return None

        if spec.kind == "info":
            self._record_dropped_sample("unknown_metric")
            return None

        # DoS guard: huge label dicts
        try:
            if label_values is not None and len(label_values) > self._cfg.max_label_input_keys:
                self._record_dropped_sample("label_input_too_large")
                return None
        except Exception:
            self._record_dropped_sample("invalid_payload")
            return None

        expected = spec.labelnames
        expected_set = set(expected)

        # Extra labels detection (bounded by max_label_input_keys; safe)
        try:
            if label_values is not None and len(label_values) > len(expected):
                self._record_dropped_sample("label_filtered")
            else:
                # If same size, we still detect unknown keys (bounded)
                for k in label_values.keys():
                    if isinstance(k, str) and k not in expected_set:
                        self._record_dropped_sample("label_filtered")
                        break
        except Exception:
            self._record_dropped_sample("invalid_payload")
            return None

        out: Dict[str, str] = {}
        for k in expected:
            v = self._normalize_label_value(metric_name, k, label_values.get(k, ""))
            if v == _DROP:
                # external strict mode may request dropping unknown codes
                self._record_dropped_sample("unknown_code")
                return None
            out[k] = v
        return out

    def _record_unknown_code(self, *, label_key: str, metric_name: str) -> None:
        if not self._metrics_enabled() or not self._initialized:
            return
        c = self._m.get("tcd_metrics_unknown_code_total")
        if c is None:
            return
        lk = label_key if label_key in _CODE_KEYS else "other"
        mn = metric_name if metric_name in self._specs else "unknown"
        try:
            labels = self._metric_labels("tcd_metrics_unknown_code_total", {"label_key": lk, "metric_name": mn})
            if labels is None:
                return
            if not self._admit_series("tcd_metrics_unknown_code_total", labels, collector=c):
                return
            c.labels(**labels).inc()
        except Exception:
            return

    def _hash_or_fallback(self, s: str, *, ctx: str, fallback: str) -> str:
        """
        Hash using HMAC if available. If HMAC is required but missing (external), return fallback.
        Never throws.
        """
        if self._cfg.profile == "external" and self._cfg.require_hmac_external and not self._hasher.hmac_present():
            # Enforce "no silent SHA256 in external when HMAC required"
            self._record_dropped_sample("hmac_required_missing")
            return fallback
        return self._hasher.hash(s, ctx=ctx)

    def _normalize_code(
        self,
        *,
        metric_name: str,
        key: str,
        value: str,
        allowed: FrozenSet[str],
        default: str = "other",
    ) -> str:
        vv = value.strip().lower()
        if vv in allowed:
            return vv
        self._record_unknown_code(label_key=key, metric_name=metric_name)
        if self._cfg.profile == "external" and self._cfg.external_drop_unknown_codes:
            return _DROP
        return default

    def _normalize_label_value(self, metric_name: str, key: str, value: Any) -> str:
        # Convert safely (label context)
        s = _safe_text(value, max_len=256, kind="label")
        if not s:
            return ""

        k = key
        v = s.strip()

        # PII-ish labels (tenant/user/session)
        if k in {"tenant", "user", "session"}:
            low = v.lower()
            if low in {"", "*", "unknown", "anon"}:
                # External collapses to "*" to reduce semantics leakage
                return "*" if self._cfg.profile == "external" else (v if v else "")
            if self._cfg.allow_raw_pii_labels:
                return _safe_text(v, max_len=64, kind="id")
            # If external requires HMAC and it's missing, either star or exporter is disabled earlier (fail mode)
            if self._cfg.profile == "external" and self._cfg.require_hmac_external and not self._hasher.hmac_present():
                self._record_dropped_sample("hmac_required_missing")
                return "*"
            if self._cfg.hash_pii_labels:
                return self._hash_or_fallback(_safe_text(v, max_len=128, kind="id"), ctx=k, fallback="*")
            return "*" if self._cfg.profile == "external" else _safe_text(v, max_len=64, kind="id")

        # Enumerated / code-enforced labels
        if k == "action":
            # normalize common synonyms into stable actions
            vv = v.strip().lower()
            if vv == "ask_for_review":
                vv = "ask_for_review"
            return self._normalize_code(metric_name=metric_name, key=k, value=vv, allowed=_ALLOWED_ACTIONS, default="other")

        if k == "severity":
            return self._normalize_code(metric_name=metric_name, key=k, value=v, allowed=_ALLOWED_SEVERITIES, default="other")

        if k == "traffic_class":
            return self._normalize_code(metric_name=metric_name, key=k, value=v, allowed=_ALLOWED_TRAFFIC_CLASSES, default="other")

        if k == "fallback_used":
            return self._normalize_code(metric_name=metric_name, key=k, value=v, allowed=_ALLOWED_FALLBACK_USED, default="other")

        if k == "key":  # SLO key
            return self._normalize_code(metric_name=metric_name, key=k, value=v, allowed=_ALLOWED_SLO_KEYS, default="other")

        if k == "reason":
            return self._normalize_code(metric_name=metric_name, key=k, value=v, allowed=_ALLOWED_REASONS, default="other")

        if k == "stage":
            return self._normalize_code(metric_name=metric_name, key=k, value=v, allowed=_ALLOWED_STAGES, default="other")

        if k == "event_type":
            return self._normalize_code(metric_name=metric_name, key=k, value=v, allowed=_ALLOWED_EVENT_TYPES, default="other")

        if k == "pattern_type":
            return self._normalize_code(metric_name=metric_name, key=k, value=v, allowed=_ALLOWED_PATTERN_TYPES, default="other")

        # Structured identifiers
        if k == "gpu_id":
            vv = v.lower()
            if _GPU_ID_RE.fullmatch(vv):
                return vv
            # Do NOT hash unknown gpu ids; map to other to avoid host leakage
            return "other"

        if k == "model_id":
            vv = _safe_text(v, max_len=64, kind="id")
            if not _MODEL_ID_RE.fullmatch(vv):
                return "other"
            # external: hash model_id by default (min leakage + limit high-card drift)
            if self._cfg.profile == "external":
                return self._hash_or_fallback(vv.lower(), ctx="model_id", fallback="other")
            return vv

        if k == "policy":
            vv = _safe_text(v, max_len=32, kind="id").lower()
            if not _POLICY_RE.fullmatch(vv):
                return "other"
            # external: hash
            if self._cfg.profile == "external":
                return self._hash_or_fallback(vv, ctx="policy", fallback="other")
            return vv

        if k == "scenario_id":
            vv = _safe_text(v, max_len=32, kind="id")
            if self._cfg.profile == "external":
                return self._hash_or_fallback(vv, ctx="scenario_id", fallback="other")
            if _SCENARIO_ID_RE.fullmatch(vv):
                return vv
            return self._hash_or_fallback(vv, ctx="scenario_id", fallback="other")

        if k == "path":
            vv = _safe_text(v, max_len=256, kind="label")
            if self._cfg.profile == "external":
                return self._hash_or_fallback(vv, ctx="path", fallback="other")
            return _template_path(vv)[:128]

        if k == "metric_name":
            # strictly bound to known metrics (prevents label drift)
            vv = _safe_text(v, max_len=64, kind="id")
            return vv if vv in self._specs else "unknown"

        if k == "code":
            # init error codes are exporter-defined and low-card; still normalize
            return _safe_text(v, max_len=32, kind="id").lower()

        # Default: external hashes non-enum keys; internal keeps bounded + normalized (no ellipsis leakage)
        vv = _safe_text(v, max_len=64, kind="label")
        if self._cfg.profile == "external":
            return self._hash_or_fallback(vv, ctx=k, fallback="other")
        return vv.replace(" ", "_")

    # -----------------------------------------------------------------------
    # Cardinality admission (before calling .labels())
    # -----------------------------------------------------------------------

    def _sig_for_labels(self, metric_name: str, labels: Mapping[str, str]) -> str:
        spec = self._specs.get(metric_name)
        if spec is None or not spec.labelnames:
            return "nolabels"
        parts = [metric_name]
        for k in spec.labelnames:
            parts.append(labels.get(k, ""))
        msg = "\0".join(parts).encode("utf-8", errors="replace")
        return hashlib.sha256(msg).digest()[:16].hex()

    def _series_exists(self, collector: Any, metric_name: str, labels: Mapping[str, str]) -> bool:
        spec = self._specs.get(metric_name)
        if spec is None or not spec.labelnames:
            return True
        try:
            m = getattr(collector, "_metrics", None)
            if not isinstance(m, dict):
                return False
            key = tuple(labels.get(k, "") for k in spec.labelnames)
            return key in m
        except Exception:
            return False

    def _admit_series(self, metric_name: str, labels: Mapping[str, str], *, collector: Any) -> bool:
        spec = self._specs.get(metric_name)
        if spec is None or not spec.labelnames:
            return True

        # Existing series always allowed (even after budgets hit)
        if self._series_exists(collector, metric_name, labels):
            return True

        if self._registry is None:
            self._record_dropped_sample("backend_unavailable")
            return False

        sig = self._sig_for_labels(metric_name, labels)
        tracker = _tracker_for_registry(self._registry)
        ok = tracker.admit(metric_name, sig)
        if not ok:
            self._record_cardinality_hit(metric_name)
            self._record_dropped_sample("cardinality_budget")
        return ok

    # -----------------------------------------------------------------------
    # Self-health recording
    # -----------------------------------------------------------------------

    def _set_last_error_code(self, code: str) -> None:
        self._last_error_code_local = code
        if not self._metrics_enabled() or not self._initialized:
            return
        g = self._m.get("tcd_metrics_last_error_code")
        if g is None:
            return
        # Only touch previous and current (low overhead, low cardinality)
        try:
            if self._last_error_code_set and self._last_error_code_set != code:
                prev = self._metric_labels("tcd_metrics_last_error_code", {"code": self._last_error_code_set})
                if prev is not None and self._admit_series("tcd_metrics_last_error_code", prev, collector=g):
                    g.labels(**prev).set(0.0)
            cur = self._metric_labels("tcd_metrics_last_error_code", {"code": code})
            if cur is not None and self._admit_series("tcd_metrics_last_error_code", cur, collector=g):
                g.labels(**cur).set(1.0)
            self._last_error_code_set = code
        except Exception:
            return

    def _record_dropped_sample(self, reason: str) -> None:
        r = _safe_text(reason, max_len=32, kind="id")
        if r not in _DROPPED_REASONS:
            r = "invalid_value"
        self._local_counts[f"dropped:{r}"] += 1

        if not self._metrics_enabled() or not self._initialized:
            return
        c = self._m.get("tcd_metrics_dropped_samples_total")
        if c is None:
            return
        try:
            labels = self._metric_labels("tcd_metrics_dropped_samples_total", {"reason": r})
            if labels is None:
                return
            if not self._admit_series("tcd_metrics_dropped_samples_total", labels, collector=c):
                return
            c.labels(**labels).inc()
        except Exception:
            return

    def _record_cardinality_hit(self, metric_name: str) -> None:
        if not self._metrics_enabled() or not self._initialized:
            return
        c = self._m.get("tcd_metrics_cardinality_budget_hit_total")
        if c is None:
            return
        try:
            labels = self._metric_labels("tcd_metrics_cardinality_budget_hit_total", {"metric_name": metric_name})
            if labels is None:
                return
            if not self._admit_series("tcd_metrics_cardinality_budget_hit_total", labels, collector=c):
                return
            c.labels(**labels).inc()
        except Exception:
            return

    def _record_observe_error(self, metric_name: str, exc: Exception) -> None:
        self._local_counts[f"observe_error:{metric_name}"] += 1
        self._last_error_ts_local = time.time()
        self._set_last_error_code("observe_error")

        if not self._metrics_enabled() or not self._initialized:
            return

        c = self._m.get("tcd_metrics_observe_errors_total")
        if c is not None:
            try:
                labels = self._metric_labels("tcd_metrics_observe_errors_total", {"metric_name": metric_name})
                if labels is not None and self._admit_series("tcd_metrics_observe_errors_total", labels, collector=c):
                    c.labels(**labels).inc()
            except Exception:
                pass

        g = self._m.get("tcd_metrics_last_error_timestamp")
        if g is not None:
            try:
                g.set(self._last_error_ts_local)
            except Exception:
                pass

        logger.debug("Metric update error for %s: %s", metric_name, exc)

    def _mark_success(self) -> None:
        ts = time.time()
        self._last_success_ts_local = ts
        if not self._metrics_enabled() or not self._initialized:
            return
        g = self._m.get("tcd_metrics_last_success_timestamp")
        if g is None:
            return
        try:
            g.set(ts)
        except Exception:
            return

    # -----------------------------------------------------------------------
    # Numeric parsing / policy
    # -----------------------------------------------------------------------

    def _safe_float(self, x: Any) -> Optional[float]:
        try:
            v = float(x)
        except Exception:
            return None
        if not math.isfinite(v):
            return None
        return v

    def _safe_nonneg_float(self, x: Any, *, max_v: float) -> Optional[float]:
        v = self._safe_float(x)
        if v is None or v < 0.0 or v > max_v:
            return None
        return v

    def _safe_clamp01(self, x: Any) -> Optional[float]:
        v = self._safe_float(x)
        if v is None:
            return None
        return _clamp01(v)

    def _quantize_risk_external(self, r: float) -> float:
        # Quantize to steps to reduce precision leakage; keep in [0,1]
        step = self._cfg.external_risk_quantize_step
        if step <= 0.0:
            return _clamp01(r)
        q = round(_clamp01(r) / step) * step
        return _clamp01(q)

    # -----------------------------------------------------------------------
    # Server management (ACK-gated; registry-aware)
    # -----------------------------------------------------------------------

    def ensure_server(self) -> bool:
        """
        Optionally start a standalone Prometheus HTTP server.

        L7 guarantees:
        - Uses self._registry (fixes custom-registry export bug).
        - Single-start per (bind_addr, port, registry_id) with bind occupancy guard.
        - ACK gate required by default to avoid accidental exposure.
        """
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return False

        self._init_metrics_if_needed()

        if not self._cfg.standalone_server:
            return True
        if start_http_server is None:
            self._record_dropped_sample("backend_unavailable")
            return False
        if self._registry is None:
            self._record_dropped_sample("backend_unavailable")
            return False

        bind_addr = self._cfg.bind_addr
        reg_id = id(self._registry)
        key = (bind_addr, self.port, reg_id)
        bind_key = (bind_addr, self.port)

        expected_ack = f"I_UNDERSTAND_TCD_PROM_STANDALONE_SERVER_{self._cfg.metric_surface_version}"
        if self._cfg.standalone_require_ack:
            if self._cfg.standalone_ack != expected_ack:
                self._record_dropped_sample("invalid_payload")
                self._set_last_error_code("server_ack_missing")
                logger.warning(
                    "Standalone server not started: ACK required. Expected %r but got %r",
                    expected_ack,
                    self._cfg.standalone_ack,
                )
                return False

        with _SERVER_LOCK:
            st = _SERVER_STATE.get(key)
            if st is not None and st.started:
                g = self._m.get("tcd_metrics_standalone_server_started")
                if g is not None:
                    try:
                        g.set(1.0)
                    except Exception:
                        pass
                return True

            occ = _BIND_OCCUPANCY.get(bind_key)
            if occ is not None and occ != reg_id:
                # Hard mismatch: server already bound for a different registry; your metrics are not exported.
                self._record_dropped_sample("collector_conflict")
                self._set_last_error_code("server_registry_mismatch")
                logger.warning(
                    "Prometheus server already started on %s:%d with a different registry (existing=%s, requested=%s).",
                    bind_addr,
                    self.port,
                    occ,
                    reg_id,
                )
                return False

            try:
                start_http_server(self.port, addr=bind_addr, registry=self._registry)  # type: ignore[misc]
                _SERVER_STATE[key] = _ServerState(
                    started=True,
                    port=self.port,
                    bind_addr=bind_addr,
                    registry_id=reg_id,
                    start_time=time.time(),
                    started_by=f"{self.__class__.__name__}@{id(self)}",
                    last_error="",
                )
                _BIND_OCCUPANCY[bind_key] = reg_id
                logger.info("TCD Prometheus standalone server started on %s:%d", bind_addr, self.port)

                g = self._m.get("tcd_metrics_standalone_server_started")
                if g is not None:
                    try:
                        g.set(1.0)
                    except Exception:
                        pass
                return True
            except Exception as e:  # pragma: no cover
                _SERVER_STATE[key] = _ServerState(
                    started=False,
                    port=self.port,
                    bind_addr=bind_addr,
                    registry_id=reg_id,
                    start_time=time.time(),
                    started_by=f"{self.__class__.__name__}@{id(self)}",
                    last_error=type(e).__name__,
                )
                self._record_observe_error("ensure_server", e)
                self._set_last_error_code("server_start_failed")
                logger.error("Failed to start Prometheus standalone server on %s:%d: %s", bind_addr, self.port, e)
                return False

    # -----------------------------------------------------------------------
    # Core update helpers (centralize whitelist + cardinality + try/except)
    # -----------------------------------------------------------------------

    def _counter_inc(self, metric_name: str, label_values: Mapping[str, Any]) -> None:
        c = self._m.get(metric_name)
        if c is None:
            return
        labels = self._metric_labels(metric_name, label_values)
        if labels is None:
            return
        if not self._admit_series(metric_name, labels, collector=c):
            return
        try:
            c.labels(**labels).inc()
            self._mark_success()
        except Exception as e:
            self._record_observe_error(metric_name, e)

    def _counter_inc_nolabel(self, metric_name: str) -> None:
        c = self._m.get(metric_name)
        if c is None:
            return
        try:
            c.inc()
            self._mark_success()
        except Exception as e:
            self._record_observe_error(metric_name, e)

    def _gauge_set(self, metric_name: str, label_values: Mapping[str, Any], value: float) -> None:
        g = self._m.get(metric_name)
        if g is None:
            return
        labels = self._metric_labels(metric_name, label_values)
        if labels is None:
            return
        if not self._admit_series(metric_name, labels, collector=g):
            return
        try:
            g.labels(**labels).set(float(value))
            self._mark_success()
        except Exception as e:
            self._record_observe_error(metric_name, e)

    def _gauge_set_nolabel(self, metric_name: str, value: float) -> None:
        g = self._m.get(metric_name)
        if g is None:
            return
        try:
            g.set(float(value))
            self._mark_success()
        except Exception as e:
            self._record_observe_error(metric_name, e)

    def _hist_observe(self, metric_name: str, label_values: Mapping[str, Any], value: float) -> None:
        h = self._m.get(metric_name)
        if h is None:
            return
        labels = self._metric_labels(metric_name, label_values)
        if labels is None:
            return
        if not self._admit_series(metric_name, labels, collector=h):
            return
        try:
            h.labels(**labels).observe(float(value))
            self._mark_success()
        except Exception as e:
            self._record_observe_error(metric_name, e)

    # -----------------------------------------------------------------------
    # Public API: never-throw, always-governed
    # -----------------------------------------------------------------------

    def observe_latency(self, s: float, action: str = "unknown") -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()

        v = self._safe_float(s)
        if v is None:
            self._record_dropped_sample("invalid_value")
            return

        # Unit handling + misuse detection
        if self._cfg.latency_unit == "ms":
            v = v / 1000.0
        else:
            # seconds: guard against common ms-as-seconds mistake
            if 60.0 < v < 60_000.0:
                if self._cfg.latency_auto_convert_ms:
                    v = v / 1000.0
                else:
                    self._record_dropped_sample("invalid_unit")
                    return

        # bounds: 0 <= latency <= 1 hour
        if v < 0.0 or v > 3600.0:
            self._record_dropped_sample("invalid_value")
            return

        self._hist_observe("tcd_request_latency_seconds", {"action": action}, float(v))

    def push_decision(self, event: DecisionMetricsEvent, *, labels: Optional[Dict[str, Any]] = None) -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()

        base = labels or {}

        action = base.get("action", event.action)
        model_id = base.get("model_id", event.model_id)
        gpu_id = base.get("gpu_id", event.gpu_id)
        tenant = base.get("tenant", event.tenant)
        policy = base.get("policy", event.policy)
        path = base.get("path", event.path)
        fallback_used = base.get("fallback_used", event.fallback_used)
        scenario_id = base.get("scenario_id", event.scenario_id)
        traffic_class = base.get("traffic_class", event.traffic_class)

        # Decision counter
        self._counter_inc("tcd_decision_total", {"action": action, "model_id": model_id})

        # Risk histogram (0..1) with external quantization option
        if event.risk is not None:
            rv = self._safe_clamp01(event.risk)
            if rv is None:
                self._record_dropped_sample("invalid_value")
            else:
                if self._cfg.profile == "external" and self._cfg.external_risk_quantize:
                    rv = self._quantize_risk_external(rv)
                self._hist_observe("tcd_decision_risk", {"action": action}, float(rv))

        # Generic action counter
        self._counter_inc("tcd_action_total", {"model_id": model_id, "gpu_id": gpu_id, "action": action})

        # Decision sequence gauge
        if event.decision_seq is not None:
            sv = self._safe_nonneg_float(event.decision_seq, max_v=1e18)
            if sv is None:
                self._record_dropped_sample("invalid_value")
            else:
                self._gauge_set("tcd_decision_seq_total", {"tenant": tenant, "policy": policy}, float(sv))

        # Decision path
        if path or fallback_used:
            self._counter_inc(
                "tcd_decision_path_total",
                {"path": path or "unknown", "fallback_used": fallback_used or "none", "policy": policy},
            )

        # Optional categorized safety event
        if event.event_type and event.stage:
            self._counter_inc(
                "tcd_safety_event_total",
                {
                    "event_type": event.event_type,
                    "stage": event.stage,
                    "severity": event.severity or "low",
                    "policy": policy,
                    "scenario_id": scenario_id,
                    "traffic_class": traffic_class,
                },
            )

    def push(self, verdict_pack: Any, labels: Optional[Dict[str, Any]] = None) -> None:
        """
        Backwards-compatible entry point.

        L7 hardening:
        - Avoids getattr(property) side effects (uses __dict__ only),
        - Avoids copying huge dict payloads,
        - Caps payload key count to prevent DoS.
        """
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()

        payload: Optional[Mapping[str, Any]] = None
        if isinstance(verdict_pack, Mapping):
            payload = verdict_pack
        else:
            try:
                d = getattr(verdict_pack, "__dict__", None)
                if isinstance(d, dict):
                    payload = d
            except Exception:
                payload = None

        if payload is None:
            self._record_dropped_sample("invalid_payload")
            return

        # Payload size cap (DoS guard)
        try:
            if len(payload) > self._cfg.max_payload_keys:
                self._record_dropped_sample("payload_input_too_large")
                return
        except Exception:
            self._record_dropped_sample("invalid_payload")
            return

        def get(field: str, default: Any = "") -> Any:
            try:
                return payload.get(field, default)
            except Exception:
                return default

        ev = DecisionMetricsEvent(
            action=_safe_text(get("action", get("decision_action", "unknown")), max_len=64, kind="label"),
            risk=self._safe_clamp01(get("risk", None)) if get("risk", None) is not None else None,
            model_id=_safe_text(get("model_id", ""), max_len=64, kind="id"),
            gpu_id=_safe_text(get("gpu_id", ""), max_len=32, kind="id"),
            tenant=_safe_text(get("tenant", ""), max_len=128, kind="id"),
            user=_safe_text(get("user", ""), max_len=128, kind="id"),
            session=_safe_text(get("session", ""), max_len=128, kind="id"),
            policy=_safe_text(get("policy", ""), max_len=64, kind="id"),
            decision_seq=self._safe_float(get("decision_seq", None)) if get("decision_seq", None) is not None else None,
            path=_safe_text(get("path", ""), max_len=256, kind="label"),
            fallback_used=_safe_text(get("fallback_used", "none"), max_len=64, kind="label"),
            scenario_id=_safe_text(get("scenario_id", ""), max_len=64, kind="id"),
            traffic_class=_safe_text(get("traffic_class", "prod"), max_len=32, kind="label"),
            event_type=_safe_text(get("event_type", ""), max_len=64, kind="label"),
            stage=_safe_text(get("stage", get("stage_code", "")), max_len=64, kind="label"),
            severity=_safe_text(get("severity", "low"), max_len=16, kind="label"),
        )
        self.push_decision(ev, labels=labels)

    def push_eprocess(self, *, tenant: str = "", policy: str = "", wealth: float = 0.0, p_value: Optional[float] = None) -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()

        w = self._safe_nonneg_float(wealth, max_v=1e12)
        if w is None:
            self._record_dropped_sample("invalid_value")
            return
        self._gauge_set("tcd_eprocess_wealth", {"tenant": tenant, "policy": policy}, float(w))

        if p_value is not None:
            pv = self._safe_clamp01(p_value)
            if pv is None:
                self._record_dropped_sample("invalid_value")
                return
            self._gauge_set("tcd_eprocess_pvalue", {"tenant": tenant, "policy": policy}, float(pv))

    def update_budget_metrics(self, tenant: str, user: str, session: str, *, remaining: float, spent: bool) -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()

        r = self._safe_nonneg_float(remaining, max_v=1e12)
        if r is None:
            self._record_dropped_sample("invalid_value")
        else:
            self._gauge_set("tcd_budget_remaining", {"tenant": tenant, "user": user, "session": session}, float(r))

        if spent:
            self._counter_inc("tcd_budget_spent_total", {"tenant": tenant, "user": user, "session": session})

    def record_action(self, model_id: str, gpu_id: str, action: str) -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()
        self._counter_inc("tcd_action_total", {"model_id": model_id, "gpu_id": gpu_id, "action": action})

    def slo_violation_by_model(self, key: str, model_id: str, gpu_id: str) -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()
        self._counter_inc("tcd_slo_violation_total", {"key": key, "model_id": model_id, "gpu_id": gpu_id})

    def slo_violation(self, key: str) -> None:
        self.slo_violation_by_model(key=key, model_id="", gpu_id="")

    # -----------------------------------------------------------------------
    # Threat / control plane helpers
    # -----------------------------------------------------------------------

    def record_fail_open(self, *, reason: str = "", policy: str = "") -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()
        self._counter_inc("tcd_fail_open_total", {"reason": reason or "unspecified", "policy": policy})

    def record_fail_closed(self, *, reason: str = "", policy: str = "") -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()
        self._counter_inc("tcd_fail_closed_total", {"reason": reason or "unspecified", "policy": policy})

    def record_detector_fallback(self, *, stage: str, reason: str = "", policy: str = "") -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()
        self._counter_inc("tcd_detector_fallback_total", {"stage": stage, "reason": reason or "unspecified", "policy": policy})

    def record_safety_event(
        self,
        *,
        event_type: str,
        stage: str,
        severity: str = "low",
        policy: str = "",
        scenario_id: str = "",
        traffic_class: str = "prod",
    ) -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()
        self._counter_inc(
            "tcd_safety_event_total",
            {
                "event_type": event_type,
                "stage": stage,
                "severity": severity,
                "policy": policy,
                "scenario_id": scenario_id,
                "traffic_class": traffic_class,
            },
        )

    def record_adversarial_pattern(self, *, pattern_type: str, tenant: str = "", policy: str = "") -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()
        self._counter_inc("tcd_adversarial_pattern_total", {"pattern_type": pattern_type, "tenant": tenant, "policy": policy})

    def update_alpha_budget(
        self,
        *,
        tenant: str,
        policy: str,
        initial: Optional[float] = None,
        used: Optional[float] = None,
        fdr_estimate: Optional[float] = None,
        reset_reason: Optional[str] = None,
    ) -> None:
        if not self._metrics_enabled():
            self._record_dropped_sample(self._disabled_reason_str() or "backend_unavailable")
            return
        self._init_metrics_if_needed()

        if initial is not None:
            iv = self._safe_clamp01(initial)
            if iv is None:
                self._record_dropped_sample("invalid_value")
            else:
                self._gauge_set("tcd_alpha_budget_initial", {"tenant": tenant, "policy": policy}, float(iv))

        if used is not None:
            uv = self._safe_clamp01(used)
            if uv is None:
                self._record_dropped_sample("invalid_value")
            else:
                self._gauge_set("tcd_alpha_budget_used", {"tenant": tenant, "policy": policy}, float(uv))

        if fdr_estimate is not None:
            fv = self._safe_clamp01(fdr_estimate)
            if fv is None:
                self._record_dropped_sample("invalid_value")
            else:
                self._gauge_set("tcd_fdr_estimate", {"tenant": tenant, "policy": policy}, float(fv))

        if reset_reason is not None:
            rr = _safe_text(reset_reason, max_len=32, kind="id") or "unspecified"
            self._counter_inc("tcd_alpha_budget_reset_total", {"tenant": tenant, "policy": policy, "reason": rr})

    # -----------------------------------------------------------------------
    # Diagnostics helper (one-shot "why no data" answer)
    # -----------------------------------------------------------------------

    def health_snapshot(self) -> Dict[str, Any]:
        """
        Structured status snapshot for debugging "why no metrics".
        Never throws; contains no raw PII.
        """
        enabled = bool(self._metrics_enabled())
        reason = self._disabled_reason_str() if not enabled else ""
        return {
            "prom_available": bool(_PROM_AVAILABLE),
            "enabled": enabled,
            "disabled_reason": reason,
            "profile": self._cfg.profile,
            "surface": self._cfg.metric_surface_version,
            "registry_present": self._registry is not None,
            "initialized": bool(self._initialized),
            "init_had_errors": bool(self._init_had_errors),
            "hash_pii_labels": bool(self._cfg.hash_pii_labels),
            "allow_raw_pii_labels": bool(self._cfg.allow_raw_pii_labels),
            "require_hmac_external": bool(self._cfg.require_hmac_external),
            "external_hmac_missing_mode": self._cfg.external_hmac_missing_mode,
            "hmac_present": bool(self._hasher.hmac_present()),
            "active_kid": _safe_text(self._cfg.hmac_keyring.active_kid, max_len=16, kind="id"),
            "old_kid": _safe_text(self._cfg.hmac_keyring.old_kid, max_len=16, kind="id"),
            "hmac_key_use": self._cfg.hmac_keyring.use,
            "external_drop_unknown_codes": bool(self._cfg.external_drop_unknown_codes),
            "external_risk_quantize": bool(self._cfg.external_risk_quantize),
            "external_risk_quantize_step": float(self._cfg.external_risk_quantize_step),
            "cardinality_budgets": {
                "max_series_per_metric": int(self._cfg.max_series_per_metric),
                "max_series_total": int(self._cfg.max_series_total),
            },
            "limits": {
                "max_label_input_keys": int(self._cfg.max_label_input_keys),
                "max_payload_keys": int(self._cfg.max_payload_keys),
            },
            "timestamps": {
                "last_success_ts": float(self._last_success_ts_local),
                "last_error_ts": float(self._last_error_ts_local),
            },
            "last_error_code": self._last_error_code_local,
            "local_counters": dict(self._local_counts),
        }