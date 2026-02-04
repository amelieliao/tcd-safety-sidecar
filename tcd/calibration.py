from __future__ import annotations
"""
Predictable calibration core: score -> conservative p-value.

This module is the statistical control layer for runtime safety:
    - It converts [0,1] scores into conservative p-values;
    - It enforces a strict "previous block only" regime (no look-ahead);
    - It exposes stable digests for configuration and state so that
      receipts, e-process engines, and attestation layers can reference
      a concrete calibration state.

IMPORTANT semantic notes (L6/L7 hardening):
    - Tail direction is configurable: tail="upper" means larger score => more extreme.
      If your score is "higher is safer", you MUST set tail="lower".
    - "Conservative" here is statistical-conservative for false-positive control:
      CP upper bounds tend to produce *larger* p-values than raw empirical tails.
      Whether that is "safer" depends on your downstream policy (e.g. trigger if p small).
      This module exposes explicit config fields so the meaning cannot remain implicit.

Design contract:
    - predict uses ONLY prev block (previous completed block), never cur block;
    - feed_and_predict is the atomic primitive.
    - privileged operations are capability-gated and auditable.
"""

import bisect
import collections
import hashlib
import hmac  # (1.1) required: used for salted digests and snapshot signing
import math
import os
import re
import struct
import threading
import time
from array import array
from dataclasses import dataclass, asdict
from typing import Any, Callable, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .kv import canonical_kv_hash

# ---------------------------------------------------------------------------
# Versioning / policy identity (snapshot migration hinge)
# ---------------------------------------------------------------------------

# Bump whenever calibration math / semantics / digest protocol changes.
_CALIB_ENGINE_VERSION = "calib_v3"

# ---------------------------------------------------------------------------
# Utilities and constants
# ---------------------------------------------------------------------------

# Scope constraints for metrics labels / logs.
_MAX_SCOPE_LEN = 80
_SCOPE_RE = re.compile(r"[^a-zA-Z0-9:_\-./]+")

# Config / policy bounds.
_MIN_BLOCK_SIZE = 16
_MAX_BLOCK_SIZE = 1_000_000

_MIN_MIN_TRAIN = 8
_MIN_TRAIN_FRACTION = 0.10  # min_train >= this * block_size (capped by block_size)

_MIN_ALPHA_CP = 1e-4
_MAX_ALPHA_CP = 0.25

# Recommended lower bound for quantization epsilon (approx 2^-40).
_MIN_QUANT_EPS = max(0.0, 2.0 ** -40)

# Digest bounds.
_DEFAULT_MAX_PREV_DIGEST_ITEMS = 1024
_MAX_PREV_DIGEST_ITEMS = 1_000_000

# Restore bounds (separate from runtime block bounds).
_DEFAULT_MAX_RESTORE_SCORES = 200_000
_MAX_RESTORE_SCORES_HARD = 1_000_000

# Allowed calibration modes.
_ALLOWED_MODES = frozenset({"auto", "cp_only", "conformal_only"})

# Allowed tail directions.
_ALLOWED_TAILS = frozenset({"upper", "lower"})

# Tie-breaking modes.
_ALLOWED_TIE_MODES = frozenset({"inclusive", "strict", "randomized"})

# Fallback bound methods for CP fallback.
_ALLOWED_FALLBACK_BOUNDS = frozenset({"hoeffding", "kl"})

# Invalid policies
_ALLOWED_INVALID_PREDICT = frozenset({"clip_to_edge", "fail_open", "fail_closed"})
_ALLOWED_INVALID_UPDATE = frozenset({"clip", "drop"})

# State digest inclusion policy.
_ALLOWED_STATE_DIGEST = frozenset({"anchor_only", "full"})

# Metrics scope governance
_ALLOWED_SCOPE_LABEL_MODE = frozenset({"raw", "bucket", "allowlist", "fixed"})

# Prometheus label enums (bounded)
_ROTATE_MODES = frozenset({"count", "time", "forced"})
_FALLBACK_REASONS = frozenset({"insufficient", "forced_drift", "drift_detected"})  # extended (6.2/7.2)
_METHODS = frozenset({"cp", "conformal", "invalid"})  # bounded (6.2)

# CP exact numeric stability defaults
_DEFAULT_CP_EXACT_MAX_N = 200_000  # configurable (3.2)
_CP_EXACT_SANITY_EPS = 1e-10


# ---------------------------------------------------------------------------
# Optional prometheus (multi-instance safe registry integration)
# ---------------------------------------------------------------------------

try:
    from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram  # type: ignore

    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False


# ---------------------------------------------------------------------------
# Env parsing helpers (11.1)
# ---------------------------------------------------------------------------

def _is_finite(x: float) -> bool:
    try:
        return math.isfinite(float(x))
    except Exception:
        return False


def _parse_bool_env(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def _parse_int_env(name: str, default: int) -> int:
    v = os.environ.get(name)
    if v is None:
        return int(default)
    try:
        return int(str(v).strip())
    except Exception:
        return int(default)


def _parse_float_env(name: str, default: float) -> float:
    v = os.environ.get(name)
    if v is None:
        return float(default)
    try:
        x = float(str(v).strip())
        return x if _is_finite(x) else float(default)
    except Exception:
        return float(default)


def _parse_str_env(name: str, default: str = "") -> str:
    v = os.environ.get(name)
    return default if v is None else str(v)


_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _hex_bytes_limited(s: str, *, max_hex_chars: int) -> Optional[bytes]:
    """
    Robust hex parser (1.3):
      - supports 0x/0X prefix;
      - odd length auto left-pad with '0';
      - bounded length;
      - returns None on invalid.
    """
    ss = (s or "").strip()
    if ss.startswith(("0x", "0X")):
        ss = ss[2:]
    if ss == "":
        return None
    if len(ss) > int(max_hex_chars):
        return None
    if len(ss) % 2 == 1:
        ss = "0" + ss
        if len(ss) > int(max_hex_chars):
            return None
    if not _HEX_RE.fullmatch(ss):
        return None
    try:
        return bytes.fromhex(ss)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Scope label governance (6.1)
# ---------------------------------------------------------------------------

def _sanitize_scope(scope: str) -> str:
    raw = (scope or "").strip()
    if not raw:
        raw = "default"

    cleaned = _SCOPE_RE.sub("_", raw).strip("_")
    if not cleaned:
        cleaned = "default"

    if len(cleaned) > _MAX_SCOPE_LEN:
        cleaned = cleaned[:_MAX_SCOPE_LEN].strip("_") or "default"

    # NOTE: sanitation alone does NOT prevent high cardinality (UUIDs are "clean").
    return cleaned


def _scope_bucket(raw_scope: str, buckets: int) -> str:
    b = max(1, min(4096, int(buckets)))
    h = hashlib.sha256(raw_scope.encode("utf-8", errors="replace")).digest()
    n = int.from_bytes(h[:8], "big", signed=False)
    idx = n % b
    width = max(2, len(str(b - 1)))
    return f"b{idx:0{width}d}"


def _metrics_scope_label(
    *,
    scope: str,
    mode: str,
    buckets: int,
    allowlist: Optional[Tuple[str, ...]],
) -> str:
    """
    Produce a bounded-cardinality metrics label for scope (6.1).
    """
    s = _sanitize_scope(scope)

    m = (mode or "").strip().lower()
    if m not in _ALLOWED_SCOPE_LABEL_MODE:
        m = "bucket"

    if m == "fixed":
        return "default"

    if m == "allowlist":
        if allowlist and s in allowlist:
            return s
        return "other"

    if m == "raw":
        # WARNING: can explode cardinality if scope is tenant_id/uuid
        return s

    # default: bucket
    return _scope_bucket(s, buckets=buckets)


# ---------------------------------------------------------------------------
# Prometheus metrics (SRE / forensics) - multi-instance safe registration
# ---------------------------------------------------------------------------

if not _HAS_PROM:  # pragma: no cover
    class _No:
        def labels(self, *_, **__):
            return self
        def set(self, *_):
            pass
        def inc(self, *_):
            pass
        def observe(self, *_):
            pass

    class _MetricsFamilies:
        def __init__(self) -> None:
            self.block_size = _No()
            self.rotate = _No()
            self.rotate_noop = _No()
            self.rotate_lat = _No()

            self.fallback = _No()
            self.method = _No()

            self.pred_lat = _No()
            self.p_value = _No()

            self.invalid_seen = _No()
            self.invalid_dropped = _No()
            self.invalid_clipped = _No()
            self.invalid_predict_fail_open = _No()
            self.invalid_predict_fail_closed = _No()

            self.cp_ready = _No()
            self.prev_age = _No()
            self.cur_age = _No()

            self.cp_exact_abandoned = _No()
            self.cp_fallback_bound = _No()

            self.restore_failed = _No()
            self.misuse = _No()

            self.event_drop = _No()
            self.event_fail = _No()

            self.drift_detected = _No()
            self.drift_active = _No()

    def build_metrics(registry: Optional["CollectorRegistry"] = None) -> "_MetricsFamilies":  # type: ignore
        return _MetricsFamilies()

else:
    def _get_existing_collector(reg: "CollectorRegistry", name: str) -> Optional[Any]:
        m = getattr(reg, "_names_to_collectors", None)
        if isinstance(m, dict):
            return m.get(name)
        return None

    def _mk_counter(reg: "CollectorRegistry", name: str, doc: str, labelnames: Tuple[str, ...]) -> "Counter":
        try:
            return Counter(name, doc, labelnames=list(labelnames), registry=reg)
        except ValueError:
            ex = _get_existing_collector(reg, name)
            if ex is None or not isinstance(ex, Counter):
                raise
            ln = getattr(ex, "_labelnames", None)
            if ln is not None and tuple(ln) != tuple(labelnames):
                raise
            return ex

    def _mk_gauge(reg: "CollectorRegistry", name: str, doc: str, labelnames: Tuple[str, ...]) -> "Gauge":
        try:
            return Gauge(name, doc, labelnames=list(labelnames), registry=reg)
        except ValueError:
            ex = _get_existing_collector(reg, name)
            if ex is None or not isinstance(ex, Gauge):
                raise
            ln = getattr(ex, "_labelnames", None)
            if ln is not None and tuple(ln) != tuple(labelnames):
                raise
            return ex

    def _mk_hist(reg: "CollectorRegistry", name: str, doc: str, labelnames: Tuple[str, ...], buckets: Tuple[float, ...]) -> "Histogram":
        try:
            return Histogram(name, doc, labelnames=list(labelnames), buckets=buckets, registry=reg)
        except ValueError:
            ex = _get_existing_collector(reg, name)
            if ex is None or not isinstance(ex, Histogram):
                raise
            ln = getattr(ex, "_labelnames", None)
            if ln is not None and tuple(ln) != tuple(labelnames):
                raise
            return ex

    class _MetricsFamilies:
        def __init__(self, reg: "CollectorRegistry") -> None:
            self.block_size = _mk_gauge(
                reg,
                "tcd_calibration_block_size",
                "Number of samples in the previous (predictable) block used for calibration.",
                ("scope",),
            )
            self.rotate = _mk_counter(
                reg,
                "tcd_calibration_block_rotate_total",
                "Number of times predictable calibration rotated its block.",
                ("scope", "mode"),  # count/time/forced
            )
            self.rotate_noop = _mk_counter(
                reg,
                "tcd_calibration_block_rotate_noop_total",
                "Rotate requests that were no-ops (e.g., empty cur block).",
                ("scope", "mode"),  # forced/time
            )
            self.rotate_lat = _mk_hist(
                reg,
                "tcd_calibration_rotate_latency_seconds",
                "Latency of rotation rebuild/commit.",
                ("scope",),
                buckets=(0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0),
            )

            self.fallback = _mk_counter(
                reg,
                "tcd_conformal_fallback_total",
                "Times conformal fallback was used instead of primary calibrator.",
                ("scope", "reason"),  # insufficient/forced_drift/drift_detected
            )
            self.method = _mk_counter(
                reg,
                "tcd_calibration_method_total",
                "Times a calibration method was used.",
                ("scope", "method"),  # cp/conformal/invalid
            )

            self.pred_lat = _mk_hist(
                reg,
                "tcd_calibration_predict_latency_seconds",
                "Latency of predict/feed_and_predict",
                ("scope",),
                buckets=(0.00025, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02),
            )
            self.p_value = _mk_hist(
                reg,
                "tcd_calibration_p_value",
                "Observed p-values (forensics; ensure scope label is bounded).",
                ("scope",),
                buckets=(1e-8, 1e-7, 1e-6, 1e-5, 1e-4, 1e-3, 1e-2, 0.05, 0.1, 0.2, 0.5, 1.0),
            )

            self.invalid_seen = _mk_counter(
                reg,
                "tcd_calibration_invalid_seen_total",
                "Invalid (NaN/Inf/out-of-range) scores observed.",
                ("scope",),
            )
            self.invalid_dropped = _mk_counter(
                reg,
                "tcd_calibration_invalid_dropped_total",
                "Invalid scores dropped from training (update).",
                ("scope",),
            )
            self.invalid_clipped = _mk_counter(
                reg,
                "tcd_calibration_invalid_clipped_total",
                "Invalid scores clipped into [0,1] for training (update).",
                ("scope",),
            )
            self.invalid_predict_fail_open = _mk_counter(
                reg,
                "tcd_calibration_invalid_predict_fail_open_total",
                "Invalid scores in predict handled by fail-open (return p=1).",
                ("scope",),
            )
            self.invalid_predict_fail_closed = _mk_counter(
                reg,
                "tcd_calibration_invalid_predict_fail_closed_total",
                "Invalid scores in predict handled by fail-closed (return p=floor).",
                ("scope",),
            )

            self.cp_ready = _mk_gauge(
                reg,
                "tcd_calibration_cp_ready",
                "Whether CP calibrator is ready (1) or not (0).",
                ("scope",),
            )
            self.prev_age = _mk_gauge(
                reg,
                "tcd_calibration_prev_age_seconds",
                "Age of prev block since last commit (monotonic seconds).",
                ("scope",),
            )
            self.cur_age = _mk_gauge(
                reg,
                "tcd_calibration_cur_age_seconds",
                "Age of current block since started (monotonic seconds).",
                ("scope",),
            )

            self.cp_exact_abandoned = _mk_counter(
                reg,
                "tcd_calibration_cp_exact_abandoned_total",
                "CP exact path abandoned (bounded reasons).",
                ("scope", "kind"),
            )
            self.cp_fallback_bound = _mk_counter(
                reg,
                "tcd_calibration_cp_fallback_bound_total",
                "CP fallback bound used.",
                ("scope", "kind"),  # hoeffding/kl
            )

            self.restore_failed = _mk_counter(
                reg,
                "tcd_calibration_restore_failed_total",
                "from_snapshot failures (bounded reasons).",
                ("scope", "kind"),
            )
            self.misuse = _mk_counter(
                reg,
                "tcd_calibration_misuse_total",
                "API misuse / privileged op denied.",
                ("scope", "kind"),
            )

            self.event_drop = _mk_counter(
                reg,
                "tcd_calibration_event_drop_total",
                "Events dropped due to bounded queue.",
                ("scope",),
            )
            self.event_fail = _mk_counter(
                reg,
                "tcd_calibration_event_fail_total",
                "Event sink failures.",
                ("scope",),
            )

            self.drift_detected = _mk_counter(
                reg,
                "tcd_calibration_drift_detected_total",
                "Drift detector triggered.",
                ("scope",),
            )
            self.drift_active = _mk_gauge(
                reg,
                "tcd_calibration_drift_active",
                "Whether drift-forced conformal is active (1) or not (0).",
                ("scope",),
            )

    def build_metrics(registry: Optional["CollectorRegistry"] = None) -> "_MetricsFamilies":
        reg = registry or REGISTRY
        return _MetricsFamilies(reg)


_DEFAULT_METRICS_LOCK = threading.Lock()
_DEFAULT_METRICS: Optional[_MetricsFamilies] = None


def _get_default_metrics() -> _MetricsFamilies:
    global _DEFAULT_METRICS
    with _DEFAULT_METRICS_LOCK:
        if _DEFAULT_METRICS is None:
            _DEFAULT_METRICS = build_metrics()
        return _DEFAULT_METRICS


# ---------------------------------------------------------------------------
# Low-cardinality reason governance for metrics (41-like strictness)
# ---------------------------------------------------------------------------

_CP_EXACT_ABANDON_KINDS = frozenset({
    "no_betainc",
    "n_too_large",
    "beta_overflow",
    "betainc_nan",
    "sanity_fail",
    "exception",
})

_RESTORE_FAIL_KINDS = frozenset({
    "exception",
    "bad_hmac",
    "bad_snapshot_digest",
    "version_mismatch",
    "cfg_error",
    "too_large",
    "sanity_fail",
})

_MISUSE_KINDS = frozenset({
    "predict_disallowed",
    "update_disallowed",
    "force_fallback_denied",
    "rotate_denied",
    "randomized_tie_missing_u",
    "unsafe_predict_update_sequence",
})


@dataclass(slots=True)
class _MetricScope:
    fam: _MetricsFamilies
    scope: str

    def set_prev_n(self, n: int) -> None:
        try:
            self.fam.block_size.labels(self.scope).set(float(max(0, int(n))))
        except Exception:
            pass

    def rotate(self, mode: str) -> None:
        m = mode if mode in _ROTATE_MODES else "forced"
        try:
            self.fam.rotate.labels(self.scope, m).inc()
        except Exception:
            pass

    def rotate_noop(self, mode: str) -> None:
        m = mode if mode in _ROTATE_MODES else "forced"
        try:
            self.fam.rotate_noop.labels(self.scope, m).inc()
        except Exception:
            pass

    def rotate_lat(self, seconds: float) -> None:
        try:
            self.fam.rotate_lat.labels(self.scope).observe(max(0.0, float(seconds)))
        except Exception:
            pass

    def fallback(self, reason: str) -> None:
        r = reason if reason in _FALLBACK_REASONS else "insufficient"
        try:
            self.fam.fallback.labels(self.scope, r).inc()
        except Exception:
            pass

    def method(self, method: str) -> None:
        m = method if method in _METHODS else "invalid"
        try:
            self.fam.method.labels(self.scope, m).inc()
        except Exception:
            pass

    def pred_lat(self, seconds: float) -> None:
        try:
            self.fam.pred_lat.labels(self.scope).observe(max(0.0, float(seconds)))
        except Exception:
            pass

    def p_value(self, p: float) -> None:
        try:
            self.fam.p_value.labels(self.scope).observe(_clip01(p))
        except Exception:
            pass

    def invalid_seen(self) -> None:
        try:
            self.fam.invalid_seen.labels(self.scope).inc()
        except Exception:
            pass

    def invalid_dropped(self) -> None:
        try:
            self.fam.invalid_dropped.labels(self.scope).inc()
        except Exception:
            pass

    def invalid_clipped(self) -> None:
        try:
            self.fam.invalid_clipped.labels(self.scope).inc()
        except Exception:
            pass

    def invalid_predict_fail_open(self) -> None:
        try:
            self.fam.invalid_predict_fail_open.labels(self.scope).inc()
        except Exception:
            pass

    def invalid_predict_fail_closed(self) -> None:
        try:
            self.fam.invalid_predict_fail_closed.labels(self.scope).inc()
        except Exception:
            pass

    def cp_ready(self, ready: bool) -> None:
        try:
            self.fam.cp_ready.labels(self.scope).set(1.0 if ready else 0.0)
        except Exception:
            pass

    def prev_age(self, seconds: float) -> None:
        try:
            self.fam.prev_age.labels(self.scope).set(max(0.0, float(seconds)))
        except Exception:
            pass

    def cur_age(self, seconds: float) -> None:
        try:
            self.fam.cur_age.labels(self.scope).set(max(0.0, float(seconds)))
        except Exception:
            pass

    def cp_exact_abandoned(self, kind: str) -> None:
        k = kind if kind in _CP_EXACT_ABANDON_KINDS else "exception"
        try:
            self.fam.cp_exact_abandoned.labels(self.scope, k).inc()
        except Exception:
            pass

    def cp_fallback_bound(self, kind: str) -> None:
        k = kind if kind in _ALLOWED_FALLBACK_BOUNDS else "hoeffding"
        try:
            self.fam.cp_fallback_bound.labels(self.scope, k).inc()
        except Exception:
            pass

    def restore_failed(self, kind: str) -> None:
        k = kind if kind in _RESTORE_FAIL_KINDS else "exception"
        try:
            self.fam.restore_failed.labels(self.scope, k).inc()
        except Exception:
            pass

    def misuse(self, kind: str) -> None:
        k = kind if kind in _MISUSE_KINDS else "unsafe_predict_update_sequence"
        try:
            self.fam.misuse.labels(self.scope, k).inc()
        except Exception:
            pass

    def event_drop(self) -> None:
        try:
            self.fam.event_drop.labels(self.scope).inc()
        except Exception:
            pass

    def event_fail(self) -> None:
        try:
            self.fam.event_fail.labels(self.scope).inc()
        except Exception:
            pass

    def drift_detected(self) -> None:
        try:
            self.fam.drift_detected.labels(self.scope).inc()
        except Exception:
            pass

    def drift_active(self, active: bool) -> None:
        try:
            self.fam.drift_active.labels(self.scope).set(1.0 if active else 0.0)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Score normalization & quantization (12.1, 2.2)
# ---------------------------------------------------------------------------

def _clip01(x: float) -> float:
    """Clamp to [0,1], treating NaN/Inf as 1.0 (maximally conservative)."""
    try:
        if not math.isfinite(x):
            return 1.0
    except Exception:
        return 1.0
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    return float(x)


def _quantize01(x: float, qeps: float) -> float:
    """
    Quantize to nearest multiple of qeps, then clamp to [0,1].
    """
    if qeps <= 0.0:
        return _clip01(x)
    y = round(float(x) / qeps) * qeps
    return _clip01(y)


def _is_invalid_score(x: Any) -> bool:
    try:
        f = float(x)
    except Exception:
        return True
    if not math.isfinite(f):
        return True
    return f < 0.0 or f > 1.0


# ---------------------------------------------------------------------------
# Tail counting + tie handling (2.1, 3.4)
# ---------------------------------------------------------------------------

def _tail_counts(
    xs_sorted: Sequence[float],
    s: float,
    *,
    tail: str,
) -> Tuple[int, int, int, int, int]:
    """
    Return (n, left, right, count_lt, count_eq) where:
      left = bisect_left(xs, s)
      right = bisect_right(xs, s)
      count_lt = left
      count_eq = right - left
    Count of greater is n - right.

    Used for both tail directions.
    """
    n = len(xs_sorted)
    # s is already normalized by caller
    left = bisect.bisect_left(xs_sorted, s)
    right = bisect.bisect_right(xs_sorted, s)
    count_lt = left
    count_eq = max(0, right - left)
    # count_gt = n - right
    return n, left, right, count_lt, count_eq


def _k_effective_conformal(
    xs_sorted: Sequence[float],
    s: float,
    *,
    tail: str,
    tie_mode: str,
    tie_u: Optional[float],
    ms: Optional[_MetricScope] = None,
) -> float:
    """
    Effective tail count used for conformal p-value.

    For upper tail:
      k_ge = #{x >= s}
      randomized: k_eff = #{x > s} + U * #{x == s}

    For lower tail:
      k_le = #{x <= s}
      randomized: k_eff = #{x < s} + U * #{x == s}
    """
    tail_s = tail if tail in _ALLOWED_TAILS else "upper"
    tm = tie_mode if tie_mode in _ALLOWED_TIE_MODES else "inclusive"

    n, left, right, count_lt, count_eq = _tail_counts(xs_sorted, s, tail=tail_s)
    count_gt = n - right

    if tm == "randomized":
        if tie_u is None or (not _is_finite(tie_u)) or tie_u < 0.0 or tie_u > 1.0:
            if ms is not None:
                ms.misuse("randomized_tie_missing_u")
            tm = "inclusive"
        else:
            U = float(tie_u)
            if tail_s == "upper":
                return float(count_gt) + U * float(count_eq)
            else:
                return float(count_lt) + U * float(count_eq)

    if tail_s == "upper":
        if tm == "strict":
            return float(count_gt)  # > s
        # inclusive
        return float(n - left)  # >= s
    else:
        if tm == "strict":
            return float(count_lt)  # < s
        # inclusive
        return float(right)  # <= s


def _k_integer_for_cp(
    xs_sorted: Sequence[float],
    s: float,
    *,
    tail: str,
    tie_mode: str,
) -> int:
    """
    Integer tail count for CP upper bound.

    Randomized tie-mode is NOT used for CP (needs integer k). If tie_mode is randomized,
    CP behaves as inclusive semantics.
    """
    tail_s = tail if tail in _ALLOWED_TAILS else "upper"
    tm = tie_mode if tie_mode in _ALLOWED_TIE_MODES else "inclusive"
    if tm == "randomized":
        tm = "inclusive"

    n, left, right, count_lt, _count_eq = _tail_counts(xs_sorted, s, tail=tail_s)
    if tail_s == "upper":
        return (n - right) if tm == "strict" else (n - left)
    else:
        return left if tm == "strict" else right


# ---------------------------------------------------------------------------
# CP bounds: exact + fallback (1.2, 3.1, 3.2, 3.3)
# ---------------------------------------------------------------------------

def _kl_bernoulli(p: float, q: float) -> float:
    # KL(p||q) for Bernoulli, with safe handling at boundaries
    p = min(1.0, max(0.0, float(p)))
    q = min(1.0, max(0.0, float(q)))
    if p == q:
        return 0.0
    if p == 0.0:
        return math.log(1.0 / (1.0 - q))
    if p == 1.0:
        return math.log(1.0 / q)
    # stable logs
    return p * math.log(p / q) + (1.0 - p) * math.log((1.0 - p) / (1.0 - q))


def _upper_bound_kl(phat: float, n: int, alpha: float) -> float:
    """
    Chernoff/KL-based upper confidence bound:
      find smallest q >= phat s.t. exp(-n * KL(phat||q)) <= alpha
      => KL(phat||q) >= log(1/alpha)/n
    """
    ph = min(1.0, max(0.0, float(phat)))
    if n <= 0:
        return 1.0
    a = max(_MIN_ALPHA_CP, min(_MAX_ALPHA_CP, float(alpha)))
    target = math.log(1.0 / a) / float(n)

    if ph >= 1.0:
        return 1.0
    if target <= 0.0:
        return ph

    lo, hi = ph, 1.0
    for _ in range(60):
        mid = 0.5 * (lo + hi)
        v = _kl_bernoulli(ph, mid)
        if not math.isfinite(v):
            hi = mid
            continue
        if v < target:
            lo = mid
        else:
            hi = mid
    return _clip01(0.5 * (lo + hi))


def _upper_bound_hoeffding(phat: float, n: int, alpha: float) -> float:
    a = max(_MIN_ALPHA_CP, min(_MAX_ALPHA_CP, float(alpha)))
    if n <= 0:
        return 1.0
    radius = math.sqrt(max(0.0, math.log(1.0 / a) / (2.0 * float(n))))
    return _clip01(float(phat) + radius)


def _binomial_cp_upper(
    k: int,
    n: int,
    alpha: float,
    *,
    exact_max_n: int,
    fallback_bound: str,
    on_exact_abandon: Optional[Callable[[str], None]] = None,
    on_fallback_bound: Optional[Callable[[str], None]] = None,
) -> float:
    """
    Clopper–Pearson upper bound for Bernoulli proportion.

    Fixes (1.2): NaN/instability in exact path MUST NOT return 0.5;
                it MUST fall back conservatively.

    Adds (3.1): sanity checks for exact path (monotonic & target residual).
    Adds (3.2): exact_max_n configurable.
    Adds (3.3): fallback bound selectable (hoeffding or kl).
    """
    n = int(max(0, n))
    if n <= 0:
        return 1.0
    k = int(max(0, min(n, k)))

    a = float(alpha)
    if (not math.isfinite(a)) or a <= 0.0:
        a = _MIN_ALPHA_CP
    a = max(_MIN_ALPHA_CP, min(_MAX_ALPHA_CP, a))

    if k >= n:
        return 1.0
    if k <= 0:
        return _clip01(1.0 - a ** (1.0 / n))

    phat = k / float(n)

    # exact path eligibility
    if n > int(exact_max_n):
        if on_exact_abandon:
            on_exact_abandon("n_too_large")
        # fall through to fallback bound

    elif hasattr(math, "betainc") and hasattr(math, "beta"):
        A = float(k + 1)
        B = float(n - k)
        target = 1.0 - a

        denom = 0.0
        try:
            denom = float(math.beta(A, B))
            if (not math.isfinite(denom)) or denom == 0.0:
                raise ValueError("beta overflow/underflow")
        except Exception:
            denom = 0.0

        if denom <= 0.0:
            if on_exact_abandon:
                on_exact_abandon("beta_overflow")
        else:
            def _reg_ibeta(x: float) -> float:
                v = float(math.betainc(A, B, 0.0, float(x)))
                if (not math.isfinite(v)) or v < 0.0:
                    return float("nan")
                return v / denom

            lo, hi = 0.0, 1.0
            exact_ok = True
            for _ in range(60):
                mid = 0.5 * (lo + hi)
                v = _reg_ibeta(mid)
                if not math.isfinite(v):
                    exact_ok = False
                    if on_exact_abandon:
                        on_exact_abandon("betainc_nan")
                    break
                if v < target:
                    lo = mid
                else:
                    hi = mid

            if exact_ok:
                cand = 0.5 * (lo + hi)
                if math.isfinite(cand):
                    # (3.1) sanity checks
                    # 1) upper bound should not be below MLE
                    if cand + 1e-15 < phat:
                        exact_ok = False
                        if on_exact_abandon:
                            on_exact_abandon("sanity_fail")
                    else:
                        # 2) residual check
                        v2 = _reg_ibeta(cand)
                        if (not math.isfinite(v2)) or abs(v2 - target) > _CP_EXACT_SANITY_EPS:
                            exact_ok = False
                            if on_exact_abandon:
                                on_exact_abandon("sanity_fail")

                else:
                    exact_ok = False
                    if on_exact_abandon:
                        on_exact_abandon("exception")

            if exact_ok:
                return _clip01(0.5 * (lo + hi))

    else:
        if on_exact_abandon:
            on_exact_abandon("no_betainc")

    # conservative fallback bound (3.3)
    fb = fallback_bound if fallback_bound in _ALLOWED_FALLBACK_BOUNDS else "hoeffding"
    if on_fallback_bound:
        on_fallback_bound(fb)

    if fb == "kl":
        return _upper_bound_kl(phat, n, a)
    return _upper_bound_hoeffding(phat, n, a)


# ---------------------------------------------------------------------------
# Digest helpers (5.1–5.5)
# ---------------------------------------------------------------------------

def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _sampling_indices(n: int, m: int) -> List[int]:
    """
    Deterministic sampling with endpoints + integer arithmetic (5.2):
      - if m >= n -> [0..n-1]
      - if m == 1 -> [n//2]
      - else:
          idx_i = round(i*(n-1)/(m-1)), includes 0 and n-1.
      - de-dup, then fill neighbors if needed.
    """
    n = int(max(0, n))
    m = int(max(0, m))
    if n == 0 or m == 0:
        return []
    if m >= n:
        return list(range(n))
    if m == 1:
        return [n // 2]

    den = (m - 1)
    idxs: List[int] = []
    seen = set()
    for i in range(m):
        # integer rounding: round(num/den) where num=i*(n-1)
        num = i * (n - 1)
        # idx = floor(num/den + 0.5) = floor((2*num + den)/(2*den))
        idx = (2 * num + den) // (2 * den)
        if idx < 0:
            idx = 0
        if idx > n - 1:
            idx = n - 1
        if idx not in seen:
            seen.add(idx)
            idxs.append(idx)

    # fill if needed
    if len(idxs) < m:
        # add neighbors around existing indices
        for base in list(idxs):
            if len(idxs) >= m:
                break
            for d in (-1, 1, -2, 2, -3, 3):
                j = base + d
                if 0 <= j < n and j not in seen:
                    seen.add(j)
                    idxs.append(j)
                    if len(idxs) >= m:
                        break

    idxs.sort()
    return idxs[:m]


def _digest_scores(
    xs_sorted: Sequence[float],
    *,
    max_items: int,
    salt: Optional[bytes],
    digest_qeps: float,
) -> str:
    """
    Stable digest of a sorted score list.

    Improvements:
      - caches should call this only on rotation (5.1)
      - sampling includes endpoints and is integer stable (5.2)
      - if digest_qeps>0: digest uses integer bins (5.3)
      - includes total length (5.1/5.4)
      - optional HMAC salt (5.5)
    """
    n = len(xs_sorted)
    mi = int(max(0, min(_MAX_PREV_DIGEST_ITEMS, max_items)))

    base_prefix = f"engine={_CALIB_ENGINE_VERSION}|n={n}|dq={digest_qeps}".encode("utf-8")

    if mi == 0:
        if salt:
            return hmac_sha256_hex(salt, base_prefix)
        return hashlib.sha256(base_prefix).hexdigest()

    idxs = _sampling_indices(n, mi)
    if salt:
        h = hmac.new(salt, digestmod=hashlib.sha256)
    else:
        h = hashlib.sha256()

    h.update(base_prefix)
    h.update(b"|")
    if digest_qeps > 0.0:
        q = float(digest_qeps)
        for i in idxs:
            v = float(xs_sorted[i])
            if v == 0.0:
                v = 0.0
            b = int(round(v / q))
            h.update(struct.pack("!Q", b & 0xFFFFFFFFFFFFFFFF))
    else:
        for i in idxs:
            v = float(xs_sorted[i])
            if v == 0.0:
                v = 0.0
            h.update(struct.pack("!d", v))
    return h.hexdigest()


def _json_safe_number(x: float) -> Optional[float]:
    """
    (1.4) Ensure stats output is strict-JSON-friendly (no NaN/Inf).
    Return None if not finite.
    """
    try:
        xf = float(x)
    except Exception:
        return None
    return xf if math.isfinite(xf) else None


# ---------------------------------------------------------------------------
# Calibrators (assume normalized inputs; no duplicate clip/quantize) (12.1, 8.3)
# ---------------------------------------------------------------------------

class EmpiricalTailCalibrator:
    """
    Empirical tail estimator with conservative upper confidence via Clopper–Pearson
    (exact when stable; otherwise conservative fallback bound).
    """

    def __init__(
        self,
        scores_sorted_immutable: Sequence[float],
        *,
        alpha: float,
        tail: str,
        tie_mode: str,
        exact_max_n: int,
        fallback_bound: str,
        p_value_floor: float,
        on_exact_abandon: Optional[Callable[[str], None]] = None,
        on_fallback_bound: Optional[Callable[[str], None]] = None,
    ):
        self._xs = scores_sorted_immutable  # assume immutable prev reference
        self._n = len(scores_sorted_immutable)
        self._tail = tail if tail in _ALLOWED_TAILS else "upper"
        self._tie_mode = tie_mode if tie_mode in _ALLOWED_TIE_MODES else "inclusive"

        acp = float(alpha)
        if not math.isfinite(acp):
            acp = 0.05
        self._alpha = max(_MIN_ALPHA_CP, min(_MAX_ALPHA_CP, acp))

        self._exact_max_n = int(max(0, exact_max_n))
        self._fallback_bound = fallback_bound if fallback_bound in _ALLOWED_FALLBACK_BOUNDS else "hoeffding"

        self._p_floor = max(0.0, float(p_value_floor)) if _is_finite(p_value_floor) else 0.0
        self._on_exact_abandon = on_exact_abandon
        self._on_fallback_bound = on_fallback_bound

    def n(self) -> int:
        return self._n

    def p_upper(self, s: float) -> float:
        if self._n <= 0:
            return 1.0
        ss = _clip01(float(s))
        k = _k_integer_for_cp(self._xs, ss, tail=self._tail, tie_mode=self._tie_mode)
        p = _binomial_cp_upper(
            k=k,
            n=self._n,
            alpha=self._alpha,
            exact_max_n=self._exact_max_n,
            fallback_bound=self._fallback_bound,
            on_exact_abandon=self._on_exact_abandon,
            on_fallback_bound=self._on_fallback_bound,
        )
        return max(self._p_floor, _clip01(p))


class ConformalUpperEnvelope:
    """
    Split-conformal one-sided p-value:

      upper tail: p(s) = (1 + #{x >= s}) / (n + 1)
      lower tail: p(s) = (1 + #{x <= s}) / (n + 1)

    tie_mode:
      - inclusive: >= or <=
      - strict: > or <
      - randomized: uses U in [0,1] to randomize ties (caller must supply tie_u)
    """

    def __init__(
        self,
        scores_sorted_immutable: Sequence[float],
        *,
        tail: str,
        tie_mode: str,
        p_value_floor: float,
        ms: Optional[_MetricScope] = None,
    ):
        self._xs = scores_sorted_immutable
        self._n = len(scores_sorted_immutable)
        self._tail = tail if tail in _ALLOWED_TAILS else "upper"
        self._tie_mode = tie_mode if tie_mode in _ALLOWED_TIE_MODES else "inclusive"
        self._p_floor = max(0.0, float(p_value_floor)) if _is_finite(p_value_floor) else 0.0
        self._ms = ms

    def n(self) -> int:
        return self._n

    def p_value(self, s: float, *, tie_u: Optional[float] = None) -> float:
        if self._n <= 0:
            return 1.0
        ss = _clip01(float(s))
        k_eff = _k_effective_conformal(
            self._xs,
            ss,
            tail=self._tail,
            tie_mode=self._tie_mode,
            tie_u=tie_u,
            ms=self._ms,
        )
        p = (1.0 + float(k_eff)) / (float(self._n) + 1.0)
        return max(self._p_floor, _clip01(p))


# ---------------------------------------------------------------------------
# Configuration: policy object for calibration (2.x,3.x,4.x,5.x,6.x,7.x,8.x,9.x,11.x,12.x)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CalibConfig:
    """
    Platform policy object (not a loose bag of params).
    Every safety-relevant knob is included in digest().

    Key additions vs earlier versions (per your checklist):
      - tail direction; tie mode; invalid policies; p floor;
      - CP exact bound threshold; fallback bound method;
      - strict atomic API usage policy;
      - scope label governance for metrics;
      - digest protocol: digest_quantize_eps, salt_id;
      - snapshot/restore governance: restore limits, snapshot signing required;
      - drift detection config and cooldown;
      - state digest policy: anchor_only vs full (cur digest included).
    """

    # --- statistical policy ---
    block_size: int = 512
    min_train: int = 64
    alpha_cp: float = 0.05
    mode: str = "auto"  # auto/cp_only/conformal_only
    tail: str = "upper"  # upper/lower
    tie_mode: str = "inclusive"  # inclusive/strict/randomized
    intent: str = "fp_control"  # doc-only, included in digest for clarity

    # CP numerical controls
    cp_exact_max_n: int = _DEFAULT_CP_EXACT_MAX_N
    cp_fallback_bound: str = "hoeffding"  # hoeffding/kl

    # p-value floor (protect downstream -log(p) etc.)
    p_value_floor: float = 0.0

    # --- runtime rotation policy ---
    time_rotate_s: Optional[float] = None

    # quantize for calibration values (0 disables)
    quantize_eps: float = 0.0

    # digest-only quantization epsilon (for cross-language stability) (5.3)
    digest_quantize_eps: float = 2.0 ** -20  # digest-only; does not affect calibration

    # digest sampling cap (5.1)
    max_prev_digest_items: int = _DEFAULT_MAX_PREV_DIGEST_ITEMS

    # state digest policy (5.4)
    state_digest_mode: str = "full"  # full includes cur_digest; anchor_only excludes

    # --- API correctness policy (4.1) ---
    require_atomic: bool = True
    atomic_violation_action: str = "raise"  # "raise" or "record"

    # --- invalid handling (2.2) ---
    invalid_predict_policy: str = "clip_to_edge"
    invalid_update_policy: str = "clip"

    # --- scope & metrics governance (6.1) ---
    scope: str = "default"
    metrics_scope_mode: str = "bucket"  # raw/bucket/allowlist/fixed
    metrics_scope_buckets: int = 64
    allowed_scopes: Optional[Tuple[str, ...]] = None  # allowlist for mode=allowlist

    # governance: restrict allowed modes for this scope
    permitted_modes: Optional[Tuple[str, ...]] = None

    # --- drift detection (7.2) ---
    drift_detection: bool = False
    drift_min_samples: int = 64
    drift_mean_abs_threshold: float = 0.15
    drift_cooldown_s: float = 60.0
    drift_force_duration_s: float = 30.0  # how long to force conformal once drift triggers

    # --- snapshot/restore governance (9.x) ---
    max_restore_scores: int = _DEFAULT_MAX_RESTORE_SCORES
    require_snapshot_hmac: bool = False

    # --- digest salt governance (5.5) ---
    digest_salt_id: str = "v0"  # does not reveal salt, but provides rotation identity

    def __post_init__(self) -> None:
        # scope sanitation (for policy/digest identity only, not metrics label)
        s = _sanitize_scope(self.scope)
        object.__setattr__(self, "scope", s)

        # block_size bounds
        bs = int(self.block_size)
        if bs < _MIN_BLOCK_SIZE:
            bs = _MIN_BLOCK_SIZE
        if bs > _MAX_BLOCK_SIZE:
            bs = _MAX_BLOCK_SIZE
        object.__setattr__(self, "block_size", bs)

        # min_train bounds
        mt = int(self.min_train)
        mt = max(mt, _MIN_MIN_TRAIN)
        frac_floor = int(math.ceil(float(bs) * _MIN_TRAIN_FRACTION))
        mt = max(mt, frac_floor)
        if mt > bs:
            mt = bs
        object.__setattr__(self, "min_train", mt)

        # alpha bounds
        acp = float(self.alpha_cp)
        if not math.isfinite(acp):
            acp = 0.05
        acp = max(_MIN_ALPHA_CP, min(_MAX_ALPHA_CP, acp))
        object.__setattr__(self, "alpha_cp", acp)

        # mode normalization + governance
        mode = str(self.mode).strip().lower()
        if mode not in _ALLOWED_MODES:
            mode = "auto"
        perm = self.permitted_modes
        if perm is not None:
            cleaned = tuple(m for m in (str(x).strip().lower() for x in perm) if m in _ALLOWED_MODES)
            if not cleaned:
                cleaned = tuple(sorted(_ALLOWED_MODES))
            object.__setattr__(self, "permitted_modes", cleaned)
            if mode not in cleaned:
                mode = "auto" if "auto" in cleaned else sorted(cleaned)[0]
        object.__setattr__(self, "mode", mode)

        # tail direction
        tail = str(self.tail).strip().lower()
        if tail not in _ALLOWED_TAILS:
            tail = "upper"
        object.__setattr__(self, "tail", tail)

        # tie mode
        tm = str(self.tie_mode).strip().lower()
        if tm not in _ALLOWED_TIE_MODES:
            tm = "inclusive"
        object.__setattr__(self, "tie_mode", tm)

        # cp exact max n
        cpn = int(self.cp_exact_max_n)
        if cpn < 0:
            cpn = 0
        object.__setattr__(self, "cp_exact_max_n", cpn)

        # fallback bound
        fb = str(self.cp_fallback_bound).strip().lower()
        if fb not in _ALLOWED_FALLBACK_BOUNDS:
            fb = "hoeffding"
        object.__setattr__(self, "cp_fallback_bound", fb)

        # p floor
        pf = float(self.p_value_floor)
        if not math.isfinite(pf) or pf < 0.0:
            pf = 0.0
        object.__setattr__(self, "p_value_floor", pf)

        # time_rotate_s
        trs = self.time_rotate_s
        if trs is not None:
            trs_f = float(trs) if _is_finite(trs) else 0.0
            if (not math.isfinite(trs_f)) or trs_f <= 0.0:
                trs_f = None
            object.__setattr__(self, "time_rotate_s", trs_f)

        # quantize_eps (calibration)
        qeps = float(self.quantize_eps or 0.0)
        if not math.isfinite(qeps) or qeps < 0.0:
            qeps = 0.0
        if qeps > 0.0:
            qeps = max(qeps, _MIN_QUANT_EPS)
        object.__setattr__(self, "quantize_eps", qeps)

        # digest_quantize_eps (digest-only)
        dq = float(self.digest_quantize_eps or 0.0)
        if not math.isfinite(dq) or dq < 0.0:
            dq = 0.0
        if dq > 0.0:
            dq = max(dq, _MIN_QUANT_EPS)
        object.__setattr__(self, "digest_quantize_eps", dq)

        # max_prev_digest_items
        mi = int(self.max_prev_digest_items)
        if mi < 0:
            mi = 0
        if mi > _MAX_PREV_DIGEST_ITEMS:
            mi = _MAX_PREV_DIGEST_ITEMS
        object.__setattr__(self, "max_prev_digest_items", mi)

        # state digest mode
        sdm = str(self.state_digest_mode).strip().lower()
        if sdm not in _ALLOWED_STATE_DIGEST:
            sdm = "full"
        object.__setattr__(self, "state_digest_mode", sdm)

        # atomic policy
        av = str(self.atomic_violation_action).strip().lower()
        if av not in ("raise", "record"):
            av = "raise"
        object.__setattr__(self, "atomic_violation_action", av)

        # invalid policies
        ip = str(self.invalid_predict_policy).strip().lower()
        if ip not in _ALLOWED_INVALID_PREDICT:
            ip = "clip_to_edge"
        object.__setattr__(self, "invalid_predict_policy", ip)

        iu = str(self.invalid_update_policy).strip().lower()
        if iu not in _ALLOWED_INVALID_UPDATE:
            iu = "clip"
        object.__setattr__(self, "invalid_update_policy", iu)

        # metrics scope governance
        msm = str(self.metrics_scope_mode).strip().lower()
        if msm not in _ALLOWED_SCOPE_LABEL_MODE:
            msm = "bucket"
        object.__setattr__(self, "metrics_scope_mode", msm)

        b = int(self.metrics_scope_buckets)
        if b < 1:
            b = 1
        if b > 4096:
            b = 4096
        object.__setattr__(self, "metrics_scope_buckets", b)

        if self.allowed_scopes is not None:
            cleaned_allow = tuple(sorted({_sanitize_scope(str(x)) for x in self.allowed_scopes if str(x).strip()}))
            object.__setattr__(self, "allowed_scopes", cleaned_allow if cleaned_allow else tuple())

        # drift detection bounds
        dms = int(self.drift_min_samples)
        if dms < 1:
            dms = 1
        object.__setattr__(self, "drift_min_samples", dms)

        dth = float(self.drift_mean_abs_threshold)
        if not math.isfinite(dth) or dth < 0.0:
            dth = 0.15
        object.__setattr__(self, "drift_mean_abs_threshold", dth)

        dcd = float(self.drift_cooldown_s)
        if not math.isfinite(dcd) or dcd < 0.0:
            dcd = 60.0
        object.__setattr__(self, "drift_cooldown_s", dcd)

        dfd = float(self.drift_force_duration_s)
        if not math.isfinite(dfd) or dfd < 0.0:
            dfd = 30.0
        object.__setattr__(self, "drift_force_duration_s", dfd)

        # restore limits
        mrs = int(self.max_restore_scores)
        if mrs < 0:
            mrs = 0
        if mrs > _MAX_RESTORE_SCORES_HARD:
            mrs = _MAX_RESTORE_SCORES_HARD
        object.__setattr__(self, "max_restore_scores", mrs)

        # salt id (bounded for logs/receipts)
        sid = str(self.digest_salt_id or "v0").strip()
        if len(sid) > 64:
            sid = sid[:64]
        object.__setattr__(self, "digest_salt_id", sid)

    def digest(self) -> str:
        """
        Stable hash describing the calibration policy.

        Includes governance knobs to ensure digest changes when policy changes. (38 analog)
        """
        payload: Dict[str, Any] = {
            "engine_version": _CALIB_ENGINE_VERSION,
            "block_size": self.block_size,
            "min_train": self.min_train,
            "alpha_cp": self.alpha_cp,
            "mode": self.mode,
            "tail": self.tail,
            "tie_mode": self.tie_mode,
            "intent": self.intent,

            "cp_exact_max_n": self.cp_exact_max_n,
            "cp_fallback_bound": self.cp_fallback_bound,
            "p_value_floor": self.p_value_floor,

            "time_rotate_s": self.time_rotate_s,
            "quantize_eps": self.quantize_eps,

            "digest_quantize_eps": self.digest_quantize_eps,
            "max_prev_digest_items": self.max_prev_digest_items,
            "state_digest_mode": self.state_digest_mode,

            "require_atomic": self.require_atomic,
            "atomic_violation_action": self.atomic_violation_action,

            "invalid_predict_policy": self.invalid_predict_policy,
            "invalid_update_policy": self.invalid_update_policy,

            "scope": self.scope,
            "metrics_scope_mode": self.metrics_scope_mode,
            "metrics_scope_buckets": self.metrics_scope_buckets,
            "allowed_scopes": list(self.allowed_scopes) if self.allowed_scopes is not None else None,

            "permitted_modes": list(self.permitted_modes) if self.permitted_modes is not None else None,

            "drift_detection": self.drift_detection,
            "drift_min_samples": self.drift_min_samples,
            "drift_mean_abs_threshold": self.drift_mean_abs_threshold,
            "drift_cooldown_s": self.drift_cooldown_s,
            "drift_force_duration_s": self.drift_force_duration_s,

            "max_restore_scores": self.max_restore_scores,
            "require_snapshot_hmac": self.require_snapshot_hmac,

            "digest_salt_id": self.digest_salt_id,
        }
        return canonical_kv_hash(payload, ctx=f"tcd:calib_cfg:{self.scope}", label="calib_cfg")


# ---------------------------------------------------------------------------
# Privileged capability token (7.1)
# ---------------------------------------------------------------------------

class PrivilegedToken:
    """
    Opaque capability token. Only callers holding the same object can perform privileged ops.
    """
    __slots__ = ("_nonce",)

    def __init__(self) -> None:
        self._nonce = object()


# ---------------------------------------------------------------------------
# Event dispatcher (11.2) - bounded non-blocking queue, sink called outside lock
# ---------------------------------------------------------------------------

class _EventDispatcher:
    def __init__(
        self,
        *,
        sink: Callable[[Dict[str, Any]], None],
        ms: _MetricScope,
        max_queue: int = 1024,
    ) -> None:
        self._sink = sink
        self._ms = ms
        self._q: Deque[Dict[str, Any]] = collections.deque(maxlen=max(1, int(max_queue)))
        self._lock = threading.Lock()
        self._ev = threading.Event()
        self._stop = False
        self._thr = threading.Thread(target=self._run, name="tcd-calib-event", daemon=True)
        self._thr.start()

    def emit(self, event: Dict[str, Any]) -> None:
        # never block caller; drop if full
        with self._lock:
            if self._stop:
                return
            if len(self._q) >= self._q.maxlen:  # type: ignore[arg-type]
                self._ms.event_drop()
                # deque(maxlen) will drop oldest on append; still count drop explicitly
            self._q.append(event)
            self._ev.set()

    def close(self) -> None:
        with self._lock:
            self._stop = True
            self._ev.set()

    def _run(self) -> None:
        while True:
            self._ev.wait(timeout=1.0)
            self._ev.clear()
            if self._stop:
                return
            batch: List[Dict[str, Any]] = []
            with self._lock:
                while self._q:
                    batch.append(self._q.popleft())
            for ev in batch:
                try:
                    self._sink(ev)
                except Exception:
                    self._ms.event_fail()
                    # swallow; never break the dispatcher


# ---------------------------------------------------------------------------
# PredictableCalibrator (prev-only, drift-aware, async rotation rebuild) (4.x,7.x,8.x)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class _RotationTask:
    reason: str
    scores: array  # 'd'
    score_sum: float
    started_mono: float
    started_wall: float


class PredictableCalibrator:
    """
    Rolling predictable calibrator with strict prev-only p-values.

    Public API:
      - feed_and_predict(score, tie_u=None): recommended atomic primitive
      - predict/update are optional advanced APIs; gated by cfg.require_atomic

    Privileged operations (capability-gated):
      - rotate_now(priv=token, force=False)
      - force_conformal(priv=token, duration_s=...)
    """

    def __init__(
        self,
        cfg: Optional[CalibConfig] = None,
        *,
        metrics: Optional[_MetricsFamilies] = None,

        # Optional digest salt for receipts (does not affect calibration values).
        digest_salt_hex: Optional[str] = None,

        # Separate key for snapshot signing (9.1). If set, snapshot_hmac is emitted.
        snapshot_hmac_key_hex: Optional[str] = None,

        # Optional event sink for privileged operations / forensics (11.2).
        event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
        event_queue_max: int = 1024,

        # Optional clocks (useful for testing)
        time_provider: Optional[Callable[[], float]] = None,      # wall clock
        monotonic_provider: Optional[Callable[[], float]] = None, # monotonic clock

        # Optional privileged capability token (7.1). If not provided, privileged ops are disabled by default.
        privileged_token: Optional[PrivilegedToken] = None,
        allow_privileged_ops: bool = False,

        # Optional background ticker for time_rotate (4.3)
        background_tick_s: Optional[float] = None,
    ):
        self.cfg = cfg or CalibConfig()

        # metrics scope label governance (6.1)
        self._metrics_scope = _metrics_scope_label(
            scope=self.cfg.scope,
            mode=self.cfg.metrics_scope_mode,
            buckets=self.cfg.metrics_scope_buckets,
            allowlist=self.cfg.allowed_scopes,
        )

        self._fam = metrics or _get_default_metrics()
        self._ms = _MetricScope(self._fam, self._metrics_scope)

        self._cfg_digest = self.cfg.digest()

        # digest salt (5.5): robust parsing (1.3)
        self._digest_salt: Optional[bytes] = None
        if digest_salt_hex:
            sb = _hex_bytes_limited(digest_salt_hex, max_hex_chars=512)
            if sb is None or len(sb) < 16:
                raise ValueError("digest_salt_hex must be valid hex and >= 16 bytes")
            self._digest_salt = sb

        # snapshot HMAC signing key (9.1)
        self._snapshot_hmac_key: Optional[bytes] = None
        if snapshot_hmac_key_hex:
            kb = _hex_bytes_limited(snapshot_hmac_key_hex, max_hex_chars=512)
            if kb is None or len(kb) < 16:
                raise ValueError("snapshot_hmac_key_hex must be valid hex and >= 16 bytes")
            self._snapshot_hmac_key = kb

        # clocks
        self._time = time_provider or time.time
        self._mono = monotonic_provider or time.monotonic

        # privileged capability
        self._allow_privileged = bool(allow_privileged_ops)
        self._priv_token = privileged_token if self._allow_privileged else None

        # state buffers: use array('d') to reduce memory (8.1)
        self._prev_sorted: array = array("d")
        self._prev_sum: float = 0.0
        self._prev_committed_mono: float = float(self._mono())
        self._prev_committed_wall: float = float(self._time())

        self._cur_scores: array = array("d")
        self._cur_sum: float = 0.0
        self._cur_started_mono: float = float(self._mono())
        self._cur_started_wall: float = float(self._time())

        # calibrators reference prev immutable sequence (we never mutate _prev_sorted in-place after commit)
        self._cal_cp: Optional[EmpiricalTailCalibrator] = None
        self._cal_conf: Optional[ConformalUpperEnvelope] = None

        # counters / metadata
        self._rotate_count = 0

        # invalid accounting (12.2): total + window
        self._invalid_total = 0
        self._invalid_window = [0] * 60
        self._invalid_window_minute = [-1] * 60  # minute id per bucket

        # fallback & drift forensics
        self._last_rotation_ts: float = 0.0
        self._last_rotation_reason: str = ""
        self._last_fallback_ts: float = 0.0
        self._last_fallback_reason: str = ""
        self._last_forced_fallback_ts: float = 0.0
        self._last_forced_fallback_reason: str = ""
        self._last_drift_ts_mono: float = 0.0
        self._force_conformal_until_mono: float = 0.0

        # digests caching (5.1)
        self._prev_digest_cache: str = ""
        self._anchor_digest_cache: str = ""

        # rotation worker (4.2): sorting/rebuild outside lock; single worker thread
        self._rot_lock = threading.Lock()
        self._rot_q: Deque[_RotationTask] = collections.deque()
        self._rot_ev = threading.Event()
        self._rot_stop = False
        self._rot_thr = threading.Thread(target=self._rotation_worker, name="tcd-calib-rot", daemon=True)
        self._rot_thr.start()

        # event dispatcher (11.2)
        self._evdisp: Optional[_EventDispatcher] = None
        if event_sink is not None:
            self._evdisp = _EventDispatcher(sink=event_sink, ms=self._ms, max_queue=event_queue_max)

        # lock for state
        self._lock = threading.RLock()

        # initialize calibrators & caches
        with self._lock:
            self._rebuild_prev_unlocked(commit_meta=False)

        # background tick thread (4.3)
        self._tick_stop = False
        self._tick_thr: Optional[threading.Thread] = None
        if background_tick_s is not None:
            dt = float(background_tick_s)
            if _is_finite(dt) and dt > 0.0:
                self._tick_thr = threading.Thread(target=self._tick_loop, args=(dt,), name="tcd-calib-tick", daemon=True)
                self._tick_thr.start()

    # ---------------- lifecycle ----------------

    def close(self) -> None:
        # stop ticker
        self._tick_stop = True
        # stop rotation worker
        with self._rot_lock:
            self._rot_stop = True
            self._rot_ev.set()
        # stop event dispatcher
        if self._evdisp is not None:
            self._evdisp.close()

    # ---------------- internal utilities ----------------

    def _emit_event(self, kind: str, fields: Dict[str, Any]) -> None:
        if self._evdisp is None:
            return
        # build event under lock-light: do NOT call state_digest inside lock (expensive)
        ev = {
            "ts": float(self._time()),
            "kind": str(kind),
            "scope": self.cfg.scope,
            "metrics_scope": self._metrics_scope,
            "cfg_digest": self._cfg_digest,
            "engine_version": _CALIB_ENGINE_VERSION,
            "digest_salt_id": self.cfg.digest_salt_id,
            **fields,
        }
        self._evdisp.emit(ev)

    def _invalid_bump_unlocked(self) -> None:
        self._invalid_total += 1
        self._ms.invalid_seen()

        # window buckets by minute
        now = float(self._time())
        minute_id = int(now // 60.0)
        idx = minute_id % 60
        if self._invalid_window_minute[idx] != minute_id:
            self._invalid_window_minute[idx] = minute_id
            self._invalid_window[idx] = 0
        self._invalid_window[idx] += 1

    def _invalid_rates_unlocked(self) -> Tuple[int, int]:
        """
        Return (invalid_1m, invalid_5m) counts.
        """
        now = float(self._time())
        cur_min = int(now // 60.0)
        c1 = 0
        c5 = 0
        for j in range(60):
            mid = self._invalid_window_minute[j]
            if mid < 0:
                continue
            age = cur_min - mid
            if 0 <= age < 1:
                c1 += self._invalid_window[j]
            if 0 <= age < 5:
                c5 += self._invalid_window[j]
        return c1, c5

    def _digest_qeps(self) -> float:
        # prefer calibration quantization when enabled, else digest-only epsilon (5.3)
        if self.cfg.quantize_eps > 0.0:
            return float(self.cfg.quantize_eps)
        dq = float(self.cfg.digest_quantize_eps)
        return dq if dq > 0.0 else 0.0

    def _refresh_prev_digest_cache_unlocked(self) -> None:
        dq = self._digest_qeps()
        self._prev_digest_cache = _digest_scores(
            self._prev_sorted,
            max_items=self.cfg.max_prev_digest_items,
            salt=self._digest_salt,
            digest_qeps=dq,
        )

        # anchor digest (5.4): cfg + prev_digest only
        payload = {
            "engine_version": _CALIB_ENGINE_VERSION,
            "cfg_digest": self._cfg_digest,
            "prev_digest": self._prev_digest_cache,
            "prev_n": len(self._prev_sorted),
            "mode": self.cfg.mode,
            "tail": self.cfg.tail,
            "tie_mode": self.cfg.tie_mode,
            "digest_salt_id": self.cfg.digest_salt_id,
            "digest_salt_present": bool(self._digest_salt is not None),
        }
        self._anchor_digest_cache = canonical_kv_hash(payload, ctx=f"tcd:calib_anchor:{self.cfg.scope}", label="calib_anchor")

    def _rebuild_prev_unlocked(self, *, commit_meta: bool) -> None:
        """
        Build calibrators from current prev buffer.
        Assumes _prev_sorted is already sorted and immutable until replaced.
        """
        # update metrics ages
        now_m = float(self._mono())
        self._ms.prev_age(now_m - self._prev_committed_mono)
        self._ms.cur_age(now_m - self._cur_started_mono)

        prev_n = len(self._prev_sorted)

        # callbacks for CP metrics
        def _on_exact_abandon(kind: str) -> None:
            self._ms.cp_exact_abandoned(kind)

        def _on_fallback_bound(kind: str) -> None:
            self._ms.cp_fallback_bound(kind)

        self._cal_conf = ConformalUpperEnvelope(
            self._prev_sorted,
            tail=self.cfg.tail,
            tie_mode=self.cfg.tie_mode,
            p_value_floor=self.cfg.p_value_floor,
            ms=self._ms,
        )
        self._cal_cp = (
            EmpiricalTailCalibrator(
                self._prev_sorted,
                alpha=self.cfg.alpha_cp,
                tail=self.cfg.tail,
                tie_mode=self.cfg.tie_mode,
                exact_max_n=self.cfg.cp_exact_max_n,
                fallback_bound=self.cfg.cp_fallback_bound,
                p_value_floor=self.cfg.p_value_floor,
                on_exact_abandon=_on_exact_abandon,
                on_fallback_bound=_on_fallback_bound,
            )
            if prev_n >= self.cfg.min_train and self.cfg.mode != "conformal_only"
            else None
        )

        self._ms.set_prev_n(prev_n)
        self._ms.cp_ready(bool(self._cal_cp is not None and self._cal_cp.n() >= self.cfg.min_train))

        # digest caches refresh (5.1)
        self._refresh_prev_digest_cache_unlocked()

        if commit_meta:
            self._prev_committed_mono = float(self._mono())
            self._prev_committed_wall = float(self._time())

    def _queue_rotation_unlocked(self, reason: str) -> None:
        """
        Detach current block and enqueue rotation task.
        Must be called under _lock.
        """
        if not self._cur_scores:
            # no-op rotate
            self._ms.rotate_noop(reason if reason in _ROTATE_MODES else "forced")
            return

        # detach cur quickly (avoid lock hold)
        scores = self._cur_scores
        score_sum = float(self._cur_sum)

        self._cur_scores = array("d")
        self._cur_sum = 0.0
        self._cur_started_mono = float(self._mono())
        self._cur_started_wall = float(self._time())

        task = _RotationTask(
            reason=reason if reason in _ROTATE_MODES else "forced",
            scores=scores,
            score_sum=score_sum,
            started_mono=float(self._mono()),
            started_wall=float(self._time()),
        )
        with self._rot_lock:
            self._rot_q.append(task)
            self._rot_ev.set()

    def _rotation_worker(self) -> None:
        """
        Background worker to sort and rebuild prev, minimizing lock contention (4.2).
        """
        while True:
            self._rot_ev.wait(timeout=1.0)
            self._rot_ev.clear()

            with self._rot_lock:
                if self._rot_stop:
                    return
                task = self._rot_q.popleft() if self._rot_q else None

            if task is None:
                continue

            t0 = time.perf_counter()
            try:
                # heavy work outside state lock
                # normalize/sort: cur scores should already be normalized, but ensure safety
                # (avoid silent corruption due to external mutation)
                lst = list(task.scores)
                # All should be finite and [0,1], but enforce
                if self.cfg.quantize_eps > 0.0:
                    q = float(self.cfg.quantize_eps)
                    lst = [_quantize01(_clip01(float(x)), q) for x in lst if math.isfinite(float(x))]
                else:
                    lst = [_clip01(float(x)) for x in lst if math.isfinite(float(x))]
                lst.sort()
                new_prev = array("d", lst)
                new_prev_sum = float(sum(new_prev))  # verify sum instead of trusting (9.4 style)

                # commit under lock
                with self._lock:
                    self._prev_sorted = new_prev
                    self._prev_sum = new_prev_sum
                    self._rotate_count += 1
                    now_wall = float(self._time())
                    self._last_rotation_ts = now_wall
                    self._last_rotation_reason = task.reason

                    self._rebuild_prev_unlocked(commit_meta=True)

                    self._ms.rotate(task.reason)
                    self._emit_event("rotate_commit", {"reason": task.reason, "prev_n": len(self._prev_sorted)})

            except Exception:
                # never crash worker
                pass
            finally:
                self._ms.rotate_lat(time.perf_counter() - t0)

    def _maybe_rotate_time_unlocked(self) -> None:
        trs = self.cfg.time_rotate_s
        if not trs:
            return
        if not self._cur_scores:
            return
        now_m = float(self._mono())
        if (now_m - self._cur_started_mono) >= float(trs):
            self._queue_rotation_unlocked("time")

    def _rotate_if_needed_unlocked(self) -> None:
        # count based
        if len(self._cur_scores) >= self.cfg.block_size:
            self._queue_rotation_unlocked("count")
            return
        # time based
        self._maybe_rotate_time_unlocked()

    def _cp_ready_unlocked(self) -> bool:
        return self._cal_cp is not None and self._cal_cp.n() >= self.cfg.min_train

    def _should_use_cp_unlocked(self) -> bool:
        if self.cfg.mode == "conformal_only":
            return False
        # cp_only and auto both require readiness; cp_only simply doesn't allow anything else if ready
        return self._cp_ready_unlocked()

    def _drift_check_unlocked(self) -> None:
        """
        Lightweight drift detection (7.2):
          - compares cur_mean vs prev_mean once cur has drift_min_samples;
          - if triggered, force conformal for drift_force_duration_s.
        """
        if not self.cfg.drift_detection:
            self._ms.drift_active(False)
            return

        cur_n = len(self._cur_scores)
        if cur_n < int(self.cfg.drift_min_samples):
            self._ms.drift_active(float(self._mono()) < self._force_conformal_until_mono)
            return

        prev_n = len(self._prev_sorted)
        if prev_n <= 0:
            self._ms.drift_active(float(self._mono()) < self._force_conformal_until_mono)
            return

        prev_mean = self._prev_sum / float(prev_n)
        cur_mean = self._cur_sum / float(cur_n)

        now_m = float(self._mono())
        if (now_m - float(self._last_drift_ts_mono)) < float(self.cfg.drift_cooldown_s):
            self._ms.drift_active(now_m < self._force_conformal_until_mono)
            return

        if abs(cur_mean - prev_mean) >= float(self.cfg.drift_mean_abs_threshold):
            self._last_drift_ts_mono = now_m
            self._force_conformal_until_mono = now_m + float(self.cfg.drift_force_duration_s)
            self._ms.drift_detected()
            self._ms.drift_active(True)
            self._emit_event("drift_detected", {"prev_mean": prev_mean, "cur_mean": cur_mean})
        else:
            self._ms.drift_active(now_m < self._force_conformal_until_mono)

    def _effective_force_conformal_unlocked(self) -> bool:
        now_m = float(self._mono())
        return now_m < float(self._force_conformal_until_mono)

    def _normalize_for_predict_unlocked(self, score: Any) -> Tuple[Optional[float], str]:
        """
        Return (normalized_score or None if immediate-return, method_tag).

        (2.2) invalid_predict_policy:
          - clip_to_edge: clip into [0,1] and proceed
          - fail_open: return None and method 'invalid' with p=1.0
          - fail_closed: return None and method 'invalid' with p=p_floor
        """
        invalid = _is_invalid_score(score)
        if invalid:
            self._invalid_bump_unlocked()
            pol = self.cfg.invalid_predict_policy
            if pol == "fail_open":
                self._ms.invalid_predict_fail_open()
                return None, "invalid_fail_open"
            if pol == "fail_closed":
                self._ms.invalid_predict_fail_closed()
                return None, "invalid_fail_closed"
            # clip_to_edge
            # still record that we clipped for predict? we only have clipped metric for update; keep minimal.
        s = _clip01(float(score))
        if self.cfg.quantize_eps > 0.0:
            s = _quantize01(s, float(self.cfg.quantize_eps))
        return s, "ok"

    def _normalize_for_update_unlocked(self, score: Any) -> Optional[float]:
        """
        Normalize and apply invalid_update_policy:
          - drop: invalid scores are NOT fed into training
          - clip: clip into [0,1] and feed
        """
        invalid = _is_invalid_score(score)
        if invalid:
            self._invalid_bump_unlocked()
            if self.cfg.invalid_update_policy == "drop":
                self._ms.invalid_dropped()
                return None
            # clip
            self._ms.invalid_clipped()

        s = _clip01(float(score))
        if self.cfg.quantize_eps > 0.0:
            s = _quantize01(s, float(self.cfg.quantize_eps))
        return s

    def _predict_unlocked(self, score: Any, *, tie_u: Optional[float], privileged_force: bool) -> float:
        """
        Core predict under lock. Uses ONLY prev calibrators.
        """
        # opportunistic time rotation
        self._maybe_rotate_time_unlocked()

        s_norm, tag = self._normalize_for_predict_unlocked(score)
        if s_norm is None:
            # invalid immediate policies
            self._ms.method("invalid")
            if tag == "invalid_fail_closed":
                return max(float(self.cfg.p_value_floor), 0.0)
            return 1.0

        # drift auto-force (7.2)
        drift_forced = self._effective_force_conformal_unlocked()

        # privileged force conformal (7.1)
        if privileged_force or drift_forced:
            now = float(self._time())
            if privileged_force:
                self._last_forced_fallback_ts = now
                self._last_forced_fallback_reason = "forced_drift"
                self._last_fallback_ts = now
                self._last_fallback_reason = "forced_drift"
                self._ms.fallback("forced_drift")
                self._emit_event("forced_fallback", {"reason": "forced_drift"})
            else:
                self._last_fallback_ts = now
                self._last_fallback_reason = "drift_detected"
                self._ms.fallback("drift_detected")

            self._ms.method("conformal")
            p = self._cal_conf.p_value(s_norm, tie_u=tie_u) if self._cal_conf else 1.0
            return max(float(self.cfg.p_value_floor), _clip01(p))

        if self.cfg.mode == "conformal_only":
            self._ms.method("conformal")
            p = self._cal_conf.p_value(s_norm, tie_u=tie_u) if self._cal_conf else 1.0
            return max(float(self.cfg.p_value_floor), _clip01(p))

        if self._should_use_cp_unlocked():
            self._ms.method("cp")
            p = self._cal_cp.p_upper(s_norm) if self._cal_cp else 1.0
            return max(float(self.cfg.p_value_floor), _clip01(p))

        # insufficient fallback (CP not ready)
        now = float(self._time())
        self._last_fallback_ts = now
        self._last_fallback_reason = "insufficient"
        self._ms.fallback("insufficient")
        self._ms.method("conformal")
        p = self._cal_conf.p_value(s_norm, tie_u=tie_u) if self._cal_conf else 1.0
        return max(float(self.cfg.p_value_floor), _clip01(p))

    def _update_unlocked(self, score: Any) -> None:
        """
        Feed a normalized score into cur block.
        """
        s = self._normalize_for_update_unlocked(score)
        if s is None:
            # dropped
            return
        self._cur_scores.append(float(s))
        self._cur_sum += float(s)

        # drift check after update (7.2)
        self._drift_check_unlocked()

        # rotation triggers
        self._rotate_if_needed_unlocked()

    # ---------------- background tick (4.3) ----------------

    def _tick_loop(self, dt: float) -> None:
        while not self._tick_stop:
            try:
                self.tick()
            except Exception:
                pass
            time.sleep(max(0.05, float(dt)))

    def tick(self) -> None:
        """
        Public tick() (4.3):
          - performs time-based rotation checks even if predict/update not called frequently.
        """
        with self._lock:
            self._maybe_rotate_time_unlocked()
            # refresh gauges
            now_m = float(self._mono())
            self._ms.prev_age(now_m - self._prev_committed_mono)
            self._ms.cur_age(now_m - self._cur_started_mono)
            self._ms.drift_active(now_m < self._force_conformal_until_mono)

    # ---------------- public API (4.1 enforcement) ----------------

    def feed_and_predict(self, score: Any, *, tie_u: Optional[float] = None, priv: Optional[PrivilegedToken] = None, force_fallback: bool = False) -> float:
        """
        Atomic primitive: predict using prev-only, then update cur.

        force_fallback is deprecated but kept for backward compatibility;
        it is capability-gated (7.1).
        """
        t0 = time.perf_counter()
        try:
            with self._lock:
                privileged_force = False
                if force_fallback:
                    privileged_force = self._check_privileged(priv, kind="force_fallback_denied")
                p = self._predict_unlocked(score, tie_u=tie_u, privileged_force=privileged_force)
                self._update_unlocked(score)
                self._ms.p_value(p)
                return p
        finally:
            self._ms.pred_lat(time.perf_counter() - t0)

    def predict(self, score: Any, *, tie_u: Optional[float] = None, priv: Optional[PrivilegedToken] = None, force_fallback: bool = False) -> float:
        """
        Advanced API. If cfg.require_atomic is True, this is disallowed by default (4.1).
        """
        if self.cfg.require_atomic:
            self._ms.misuse("predict_disallowed")
            if self.cfg.atomic_violation_action == "raise":
                raise RuntimeError("predict() is disabled when require_atomic=True; use feed_and_predict()")
            # record-only: still proceed, but unsafe in multi-thread
        t0 = time.perf_counter()
        try:
            with self._lock:
                privileged_force = False
                if force_fallback:
                    privileged_force = self._check_privileged(priv, kind="force_fallback_denied")
                p = self._predict_unlocked(score, tie_u=tie_u, privileged_force=privileged_force)
                self._ms.p_value(p)
                return p
        finally:
            self._ms.pred_lat(time.perf_counter() - t0)

    def update(self, score: Any) -> None:
        """
        Advanced API. If cfg.require_atomic is True, disallowed by default (4.1).
        """
        if self.cfg.require_atomic:
            self._ms.misuse("update_disallowed")
            if self.cfg.atomic_violation_action == "raise":
                raise RuntimeError("update() is disabled when require_atomic=True; use feed_and_predict()")
        with self._lock:
            self._update_unlocked(score)

    # ---------------- privileged ops (7.1/7.3) ----------------

    def _check_privileged(self, priv: Optional[PrivilegedToken], *, kind: str) -> bool:
        if not self._allow_privileged or self._priv_token is None:
            self._ms.misuse(kind if kind in _MISUSE_KINDS else "rotate_denied")
            return False
        if priv is None or priv is not self._priv_token:
            self._ms.misuse(kind if kind in _MISUSE_KINDS else "rotate_denied")
            return False
        return True

    def rotate_now(self, *, priv: Optional[PrivilegedToken] = None, force: bool = False) -> None:
        """
        Capability-gated rotation (7.1). If cur empty:
          - force=False: no-op with rotate_noop_total (7.3)
          - force=True: commit rebuild anyway (noise-controlled)
        """
        if not self._check_privileged(priv, kind="rotate_denied"):
            return

        with self._lock:
            if not self._cur_scores and not force:
                self._ms.rotate_noop("forced")
                self._emit_event("rotate_noop", {"reason": "forced"})
                return
            # enqueue a forced rotation; if cur empty and force=True, still rebuild metadata
            self._queue_rotation_unlocked("forced")
            self._emit_event("rotate_now", {"reason": "forced", "force": bool(force)})

    def force_conformal(self, *, priv: Optional[PrivilegedToken] = None, duration_s: float = 30.0, reason: str = "forced_drift") -> None:
        """
        Force conformal calibration for a duration (privileged).
        """
        if not self._check_privileged(priv, kind="force_fallback_denied"):
            return
        dur = float(duration_s)
        if not math.isfinite(dur) or dur <= 0.0:
            dur = 30.0
        with self._lock:
            now_m = float(self._mono())
            self._force_conformal_until_mono = max(self._force_conformal_until_mono, now_m + dur)
            self._last_forced_fallback_ts = float(self._time())
            self._last_forced_fallback_reason = str(reason)[:64]
            self._ms.drift_active(True)
            self._emit_event("force_conformal", {"duration_s": dur, "reason": str(reason)[:64]})

    def get_privileged_token(self) -> Optional[PrivilegedToken]:
        """
        Return the configured privileged token reference (control-plane should hold it).
        If privileged ops not enabled, returns None.
        """
        return self._priv_token if self._allow_privileged else None

    # ---------------- digests (5.4) ----------------

    @property
    def cfg_digest_hex(self) -> str:
        return self._cfg_digest

    def prev_digest_hex(self) -> str:
        with self._lock:
            return self._prev_digest_cache

    def anchor_digest(self) -> str:
        """
        Prev-only anchor digest: cfg + prev block only (5.4 "lightweight state").
        """
        with self._lock:
            return self._anchor_digest_cache

    def state_digest(self) -> str:
        """
        State digest:
          - anchor_only: returns anchor_digest
          - full: includes cur_digest (to distinguish different cur contents) (5.4 "strong state")
        """
        with self._lock:
            if self.cfg.state_digest_mode == "anchor_only":
                return self._anchor_digest_cache

            # cur_digest: sequence digest (cheap, incremental could be added; here we compute with sampling to bound cost)
            # We keep it bounded by max_restore_scores to avoid unbounded hashing.
            dq = self._digest_qeps()
            cur_digest = _digest_scores(
                self._cur_scores,
                max_items=min(self.cfg.max_prev_digest_items, max(256, int(self.cfg.block_size // 2))),
                salt=self._digest_salt,
                digest_qeps=dq,
            )

            payload: Dict[str, Any] = {
                "engine_version": _CALIB_ENGINE_VERSION,
                "cfg_digest": self._cfg_digest,
                "prev_digest": self._prev_digest_cache,
                "cur_digest": cur_digest,
                "prev_n": len(self._prev_sorted),
                "cur_n": len(self._cur_scores),
                "rotations": int(self._rotate_count),
                "mode": self.cfg.mode,
                "tail": self.cfg.tail,
                "tie_mode": self.cfg.tie_mode,
                "digest_salt_id": self.cfg.digest_salt_id,
                "digest_salt_present": bool(self._digest_salt is not None),
            }
            return canonical_kv_hash(payload, ctx=f"tcd:calib_state:{self.cfg.scope}", label="calib_state")

    # ---------------- observability (1.4,6.2,6.3,4.3,12.2) ----------------

    def block_sizes(self) -> Tuple[int, int]:
        with self._lock:
            return len(self._prev_sorted), len(self._cur_scores)

    def stats(self) -> Dict[str, object]:
        """
        Strict-JSON-friendly stats (1.4): NaN/Inf -> None.
        """
        with self._lock:
            prev_n = len(self._prev_sorted)
            cur_n = len(self._cur_scores)

            prev_mean = (self._prev_sum / float(prev_n)) if prev_n > 0 else float("nan")
            cur_mean = (self._cur_sum / float(cur_n)) if cur_n > 0 else float("nan")

            # quantiles from prev_sorted without copying (array supports indexing)
            def q(p: float) -> Optional[float]:
                if prev_n <= 0:
                    return None
                pp = 0.0 if p <= 0.0 else 1.0 if p >= 1.0 else float(p)
                idx = int(pp * (prev_n - 1))
                return float(self._prev_sorted[idx])

            now_m = float(self._mono())
            prev_age = now_m - self._prev_committed_mono
            cur_age = now_m - self._cur_started_mono

            inv1, inv5 = self._invalid_rates_unlocked()

            out: Dict[str, object] = {
                "scope": self.cfg.scope,
                "metrics_scope": self._metrics_scope,
                "engine_version": _CALIB_ENGINE_VERSION,

                "cfg_digest": self._cfg_digest,
                "anchor_digest": self._anchor_digest_cache,
                "state_digest": self.state_digest(),

                "prev_digest": self._prev_digest_cache,
                "prev_n": prev_n,
                "cur_n": cur_n,

                "prev_mean": _json_safe_number(prev_mean),
                "cur_mean": _json_safe_number(cur_mean),

                "prev_q50": _json_safe_number(q(0.5) if q(0.5) is not None else float("nan")),
                "prev_q90": _json_safe_number(q(0.9) if q(0.9) is not None else float("nan")),
                "prev_q99": _json_safe_number(q(0.99) if q(0.99) is not None else float("nan")),

                "mode": self.cfg.mode,
                "tail": self.cfg.tail,
                "tie_mode": self.cfg.tie_mode,
                "min_train": int(self.cfg.min_train),
                "alpha_cp": float(self.cfg.alpha_cp),
                "cp_ready": bool(self._cp_ready_unlocked()),

                "time_rotate_s": self.cfg.time_rotate_s,
                "quantize_eps": float(self.cfg.quantize_eps),
                "digest_quantize_eps": float(self.cfg.digest_quantize_eps),
                "max_prev_digest_items": int(self.cfg.max_prev_digest_items),
                "state_digest_mode": self.cfg.state_digest_mode,

                "prev_age_s": _json_safe_number(prev_age),
                "cur_age_s": _json_safe_number(cur_age),

                "invalid_total": int(self._invalid_total),
                "invalid_1m": int(inv1),
                "invalid_5m": int(inv5),

                "rotations": int(self._rotate_count),
                "last_rotation_ts": _json_safe_number(self._last_rotation_ts),
                "last_rotation_reason": self._last_rotation_reason,

                "last_fallback_ts": _json_safe_number(self._last_fallback_ts),
                "last_fallback_reason": self._last_fallback_reason,

                "last_forced_fallback_ts": _json_safe_number(self._last_forced_fallback_ts),
                "last_forced_fallback_reason": self._last_forced_fallback_reason,

                "drift_detection": bool(self.cfg.drift_detection),
                "drift_active": bool(now_m < self._force_conformal_until_mono),
            }
            return out

    # ---------------- snapshot/restore (9.x,1.5) ----------------

    def _snapshot_payload(self) -> Dict[str, Any]:
        """
        Snapshot payload (without hmac wrapper). Includes engine_version.
        """
        with self._lock:
            return {
                "engine_version": _CALIB_ENGINE_VERSION,
                "cfg": asdict(self.cfg),
                "cfg_digest": self._cfg_digest,

                "prev_scores_sorted": list(self._prev_sorted),
                "cur_scores": list(self._cur_scores),

                "rotate_count": int(self._rotate_count),
                "cur_started_wall": float(self._cur_started_wall),
                "invalid_total": int(self._invalid_total),

                "last_rotation_ts": float(self._last_rotation_ts),
                "last_rotation_reason": self._last_rotation_reason,

                "last_fallback_ts": float(self._last_fallback_ts),
                "last_fallback_reason": self._last_fallback_reason,

                "last_forced_fallback_ts": float(self._last_forced_fallback_ts),
                "last_forced_fallback_reason": self._last_forced_fallback_reason,

                "digest_salt_id": self.cfg.digest_salt_id,
            }

    def snapshot(self) -> Dict[str, object]:
        """
        Serializable state for AE/warm-start (trusted environment).
        Adds snapshot_digest and optional snapshot_hmac (9.1).
        """
        payload = self._snapshot_payload()
        snap_digest = canonical_kv_hash(payload, ctx=f"tcd:calib_snapshot:{self.cfg.scope}", label="calib_snapshot")
        out: Dict[str, object] = dict(payload)
        out["snapshot_digest"] = snap_digest

        if self._snapshot_hmac_key is not None:
            out["snapshot_hmac"] = hmac_sha256_hex(self._snapshot_hmac_key, snap_digest.encode("utf-8"))
        return out

    @classmethod
    def from_snapshot(cls, snap: Mapping[str, object]) -> "PredictableCalibrator":
        """
        Hardened restore: never throws (1.5).
        Enforces snapshot digest/hmac if configured; validates version; bounds resources; verifies invariants (9.4).
        """
        # Outer try/except to honor "never throws" (1.5)
        try:
            cfg_raw_any = snap.get("cfg", {})
            cfg_raw = cfg_raw_any if isinstance(cfg_raw_any, dict) else {}

            allowed_cfg_keys = {
                "block_size",
                "min_train",
                "alpha_cp",
                "mode",
                "tail",
                "tie_mode",
                "intent",
                "cp_exact_max_n",
                "cp_fallback_bound",
                "p_value_floor",
                "time_rotate_s",
                "quantize_eps",
                "digest_quantize_eps",
                "max_prev_digest_items",
                "state_digest_mode",
                "require_atomic",
                "atomic_violation_action",
                "invalid_predict_policy",
                "invalid_update_policy",
                "scope",
                "metrics_scope_mode",
                "metrics_scope_buckets",
                "allowed_scopes",
                "permitted_modes",
                "drift_detection",
                "drift_min_samples",
                "drift_mean_abs_threshold",
                "drift_cooldown_s",
                "drift_force_duration_s",
                "max_restore_scores",
                "require_snapshot_hmac",
                "digest_salt_id",
            }
            filtered = {k: v for k, v in cfg_raw.items() if k in allowed_cfg_keys}
            try:
                cfg = CalibConfig(**filtered)
            except Exception:
                cfg = CalibConfig()
        except Exception:
            cfg = CalibConfig()

        inst = cls(cfg)

        try:
            with inst._lock:
                # Version governance (9.2)
                snap_ver = snap.get("engine_version")
                if isinstance(snap_ver, str) and snap_ver != _CALIB_ENGINE_VERSION:
                    inst._ms.restore_failed("version_mismatch")
                    # start fresh
                    inst._prev_sorted = array("d")
                    inst._prev_sum = 0.0
                    inst._cur_scores = array("d")
                    inst._cur_sum = 0.0
                    inst._rotate_count = 0
                    inst._rebuild_prev_unlocked(commit_meta=True)
                    return inst

            # Snapshot digest verification (9.1)
            snap_digest = snap.get("snapshot_digest")
            if isinstance(snap_digest, str):
                # recompute digest from payload fields we expect
                # build minimal payload (ignore hmac fields)
                payload = {k: snap.get(k) for k in snap.keys() if k not in ("snapshot_hmac",)}
                recomputed = canonical_kv_hash(payload, ctx=f"tcd:calib_snapshot:{cfg.scope}", label="calib_snapshot")
                if recomputed != snap_digest:
                    inst._ms.restore_failed("bad_snapshot_digest")
                    with inst._lock:
                        inst._prev_sorted = array("d")
                        inst._prev_sum = 0.0
                        inst._cur_scores = array("d")
                        inst._cur_sum = 0.0
                        inst._rotate_count = 0
                        inst._rebuild_prev_unlocked(commit_meta=True)
                    return inst

            # HMAC verification if required by cfg
            if cfg.require_snapshot_hmac:
                h = snap.get("snapshot_hmac")
                if not (isinstance(h, str) and inst._snapshot_hmac_key is not None and isinstance(snap_digest, str)):
                    inst._ms.restore_failed("bad_hmac")
                    return inst
                calc = hmac_sha256_hex(inst._snapshot_hmac_key, snap_digest.encode("utf-8"))
                if not hmac.compare_digest(calc, h):
                    inst._ms.restore_failed("bad_hmac")
                    return inst

            # cfg digest check (existing behavior, but hardened)
            snap_cfg_digest = snap.get("cfg_digest")
            if not (isinstance(snap_cfg_digest, str) and snap_cfg_digest == cfg.digest()):
                inst._ms.restore_failed("cfg_error")
                return inst

            # restore buffers with bounds (9.3)
            max_len = int(min(cfg.max_restore_scores, max(1, cfg.block_size * 4), _MAX_RESTORE_SCORES_HARD))

            def _sanitize_scores(raw: Any, *, max_items: int) -> array:
                out = array("d")
                if not isinstance(raw, list):
                    return out
                # avoid expensive float conversions on huge/hostile objects
                for v in raw:
                    if len(out) >= max_items:
                        break
                    try:
                        f = float(v)
                    except Exception:
                        continue
                    if not math.isfinite(f):
                        continue
                    x = _clip01(f)
                    if cfg.quantize_eps > 0.0:
                        x = _quantize01(x, float(cfg.quantize_eps))
                    out.append(float(x))
                return out

            prev_raw = snap.get("prev_scores_sorted", snap.get("prev_scores", []))
            cur_raw = snap.get("cur_scores", [])

            prev_arr = _sanitize_scores(prev_raw, max_items=max_len)
            cur_arr = _sanitize_scores(cur_raw, max_items=max_len)

            # sort outside lock (9.3)
            prev_list = list(prev_arr)
            prev_list.sort()
            prev_arr = array("d", prev_list)

            # invariant checks (9.4)
            if any((x < 0.0 or x > 1.0 or not math.isfinite(x)) for x in prev_arr):
                inst._ms.restore_failed("sanity_fail")
                return inst
            if any((x < 0.0 or x > 1.0 or not math.isfinite(x)) for x in cur_arr):
                inst._ms.restore_failed("sanity_fail")
                return inst

            prev_sum = float(sum(prev_arr))
            cur_sum = float(sum(cur_arr))

            # commit restore
            with inst._lock:
                inst._prev_sorted = prev_arr
                inst._prev_sum = prev_sum
                inst._cur_scores = cur_arr
                inst._cur_sum = cur_sum

                try:
                    inst._rotate_count = int(snap.get("rotate_count", 0) or 0)
                except Exception:
                    inst._rotate_count = 0

                # started wall sanity
                now_wall = float(inst._time())
                try:
                    csw = float(snap.get("cur_started_wall", now_wall) or now_wall)
                except Exception:
                    csw = now_wall
                if csw > now_wall + 3600.0 or csw < now_wall - 365.0 * 24.0 * 3600.0:
                    csw = now_wall
                inst._cur_started_wall = csw
                inst._cur_started_mono = float(inst._mono())

                # metadata best-effort
                def _sf(name: str) -> float:
                    try:
                        v = float(snap.get(name, 0.0) or 0.0)
                        return v if math.isfinite(v) else 0.0
                    except Exception:
                        return 0.0

                inst._last_rotation_ts = _sf("last_rotation_ts")
                inst._last_rotation_reason = str(snap.get("last_rotation_reason", "") or "")[:64]
                inst._last_fallback_ts = _sf("last_fallback_ts")
                inst._last_fallback_reason = str(snap.get("last_fallback_reason", "") or "")[:64]
                inst._last_forced_fallback_ts = _sf("last_forced_fallback_ts")
                inst._last_forced_fallback_reason = str(snap.get("last_forced_fallback_reason", "") or "")[:64]

                inst._rebuild_prev_unlocked(commit_meta=True)

            return inst

        except Exception:
            inst._ms.restore_failed("exception")
            # return fresh instance (never throw)
            return cls(CalibConfig())

# ---------------------------------------------------------------------------
# Env factory (11.1): build config & calibrator with governance
# ---------------------------------------------------------------------------

def build_calib_config_from_env() -> CalibConfig:
    """
    Environment-driven config bundle (platform governance).

    Example vars:
      - TCD_CALIB_MODE (required unless explicitly allowed)
      - TCD_CALIB_ALLOW_CONFORMAL_ONLY, TCD_CALIB_ALLOW_CP_ONLY
      - TCD_CALIB_TAIL ("upper"/"lower")
      - TCD_CALIB_TIE_MODE ("inclusive"/"strict"/"randomized")
      - TCD_CALIB_BLOCK_SIZE, TCD_CALIB_TIME_ROTATE_S, TCD_CALIB_QUANTIZE_EPS
      - TCD_CALIB_METRICS_SCOPE_MODE ("bucket"/"allowlist"/"raw"/"fixed")
      - TCD_CALIB_METRICS_SCOPE_BUCKETS
      - TCD_CALIB_ALLOWED_SCOPES (comma list)
      - TCD_CALIB_REQUIRE_ATOMIC (default 1)
    """
    mode = _parse_str_env("TCD_CALIB_MODE", "").strip().lower()
    allow_implicit = _parse_bool_env("TCD_CALIB_ALLOW_IMPLICIT_DEFAULT", False)
    if not mode:
        if not allow_implicit:
            raise ValueError("TCD_CALIB_MODE is required unless TCD_CALIB_ALLOW_IMPLICIT_DEFAULT=1")
        mode = "auto"

    # governance: restrict weak modes
    allow_conformal_only = _parse_bool_env("TCD_CALIB_ALLOW_CONFORMAL_ONLY", False)
    allow_cp_only = _parse_bool_env("TCD_CALIB_ALLOW_CP_ONLY", True)

    if mode == "conformal_only" and not allow_conformal_only:
        raise ValueError("conformal_only not permitted; set TCD_CALIB_ALLOW_CONFORMAL_ONLY=1")
    if mode == "cp_only" and not allow_cp_only:
        raise ValueError("cp_only not permitted; set TCD_CALIB_ALLOW_CP_ONLY=1")

    scope = _parse_str_env("TCD_CALIB_SCOPE", "default")
    tail = _parse_str_env("TCD_CALIB_TAIL", "upper").strip().lower()
    tie_mode = _parse_str_env("TCD_CALIB_TIE_MODE", "inclusive").strip().lower()

    cfg = CalibConfig(
        scope=scope,
        mode=mode,
        tail=tail,
        tie_mode=tie_mode,

        block_size=_parse_int_env("TCD_CALIB_BLOCK_SIZE", 512),
        time_rotate_s=_parse_float_env("TCD_CALIB_TIME_ROTATE_S", 0.0) or None,
        min_train=_parse_int_env("TCD_CALIB_MIN_TRAIN", 64),
        alpha_cp=_parse_float_env("TCD_CALIB_ALPHA_CP", 0.05),

        cp_exact_max_n=_parse_int_env("TCD_CALIB_CP_EXACT_MAX_N", _DEFAULT_CP_EXACT_MAX_N),
        cp_fallback_bound=_parse_str_env("TCD_CALIB_CP_FALLBACK_BOUND", "hoeffding"),

        quantize_eps=_parse_float_env("TCD_CALIB_QUANTIZE_EPS", 0.0),
        digest_quantize_eps=_parse_float_env("TCD_CALIB_DIGEST_QUANT_EPS", 2.0 ** -20),

        max_prev_digest_items=_parse_int_env("TCD_CALIB_MAX_PREV_DIGEST_ITEMS", _DEFAULT_MAX_PREV_DIGEST_ITEMS),
        state_digest_mode=_parse_str_env("TCD_CALIB_STATE_DIGEST_MODE", "full"),

        require_atomic=_parse_bool_env("TCD_CALIB_REQUIRE_ATOMIC", True),
        atomic_violation_action=_parse_str_env("TCD_CALIB_ATOMIC_VIOLATION_ACTION", "raise"),

        invalid_predict_policy=_parse_str_env("TCD_CALIB_INVALID_PREDICT_POLICY", "clip_to_edge"),
        invalid_update_policy=_parse_str_env("TCD_CALIB_INVALID_UPDATE_POLICY", "clip"),
        p_value_floor=_parse_float_env("TCD_CALIB_P_VALUE_FLOOR", 0.0),

        metrics_scope_mode=_parse_str_env("TCD_CALIB_METRICS_SCOPE_MODE", "bucket"),
        metrics_scope_buckets=_parse_int_env("TCD_CALIB_METRICS_SCOPE_BUCKETS", 64),

        drift_detection=_parse_bool_env("TCD_CALIB_DRIFT_DETECTION", False),
        drift_min_samples=_parse_int_env("TCD_CALIB_DRIFT_MIN_SAMPLES", 64),
        drift_mean_abs_threshold=_parse_float_env("TCD_CALIB_DRIFT_MEAN_ABS_THRESHOLD", 0.15),
        drift_cooldown_s=_parse_float_env("TCD_CALIB_DRIFT_COOLDOWN_S", 60.0),
        drift_force_duration_s=_parse_float_env("TCD_CALIB_DRIFT_FORCE_DURATION_S", 30.0),

        max_restore_scores=_parse_int_env("TCD_CALIB_MAX_RESTORE_SCORES", _DEFAULT_MAX_RESTORE_SCORES),
        require_snapshot_hmac=_parse_bool_env("TCD_CALIB_REQUIRE_SNAPSHOT_HMAC", False),

        digest_salt_id=_parse_str_env("TCD_CALIB_DIGEST_SALT_ID", "v0"),
    )

    allow_scopes_env = _parse_str_env("TCD_CALIB_ALLOWED_SCOPES", "").strip()
    if allow_scopes_env:
        allow_scopes = tuple(sorted({_sanitize_scope(x.strip()) for x in allow_scopes_env.split(",") if x.strip()}))
        object.__setattr__(cfg, "allowed_scopes", allow_scopes)  # type: ignore[misc]

    return cfg


def build_calibrator_from_env(
    *,
    metrics: Optional[_MetricsFamilies] = None,
    event_sink: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> PredictableCalibrator:
    """
    Build calibrator from env. Secret salts/keys are separate env vars:
      - TCD_CALIB_DIGEST_SALT_HEX
      - TCD_CALIB_SNAPSHOT_HMAC_KEY_HEX
    """
    cfg = build_calib_config_from_env()
    digest_salt_hex = _parse_str_env("TCD_CALIB_DIGEST_SALT_HEX", "").strip() or None
    snap_hmac_hex = _parse_str_env("TCD_CALIB_SNAPSHOT_HMAC_KEY_HEX", "").strip() or None

    # privileged ops governance
    allow_priv = _parse_bool_env("TCD_CALIB_ALLOW_PRIVILEGED_OPS", False)
    token = PrivilegedToken() if allow_priv else None

    tick_s = _parse_float_env("TCD_CALIB_BACKGROUND_TICK_S", 0.0)
    bg_tick = tick_s if (math.isfinite(tick_s) and tick_s > 0.0) else None

    return PredictableCalibrator(
        cfg,
        metrics=metrics,
        digest_salt_hex=digest_salt_hex,
        snapshot_hmac_key_hex=snap_hmac_hex,
        event_sink=event_sink,
        privileged_token=token,
        allow_privileged_ops=allow_priv,
        background_tick_s=bg_tick,
    )