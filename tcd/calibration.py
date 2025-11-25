from __future__ import annotations
"""
Predictable calibration core: score -> conservative p-value.

This module is the statistical control layer for runtime safety:
    - It converts [0,1] scores into conservative p-values;
    - It enforces a strict "previous block only" regime (no look-ahead);
    - It exposes stable digests for configuration and state so that
      receipts, e-process engines, and attestation layers can reference
      a concrete calibration state.
"""

import bisect
import hashlib
import math
import re
import threading
import time
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple, Any, Mapping

try:
    from prometheus_client import Counter, Gauge, Histogram

    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False

from .kv import canonical_kv_hash


# ---------------------------------------------------------------------------
# Prometheus metrics (SRE / forensics)
# ---------------------------------------------------------------------------

if _HAS_PROM:
    _G_BLOCK_SIZE = Gauge(
        "tcd_calibration_block_size",
        "Number of samples in the previous (predictable) block used for calibration.",
        ["scope"],
    )
    _C_ROTATE = Counter(
        "tcd_calibration_block_rotate_total",
        "Number of times predictable calibration rotated its block.",
        ["scope", "mode"],  # mode in {"count","time","forced"}
    )
    _C_FALLBACK = Counter(
        "tcd_conformal_fallback_total",
        "Times conformal fallback was used instead of primary calibrator.",
        ["scope", "reason"],  # reason in {"insufficient","forced_drift"}
    )
    _H_PRED_LAT = Histogram(
        "tcd_calibration_predict_latency_seconds",
        "Latency of predict()",
        buckets=(0.00025, 0.0005, 0.001, 0.002, 0.005),
        labelnames=("scope",),
    )
    _C_INVALID = Counter(
        "tcd_calibration_invalid_total",
        "Invalid/NaN/out-of-range scores observed",
        ["scope"],
    )
else:  # pragma: no cover
    class _No:
        def labels(self, *_, **__):
            return self

        def set(self, *_):
            pass

        def inc(self, *_):
            pass

        def observe(self, *_):
            pass

    _G_BLOCK_SIZE = _No()
    _C_ROTATE = _No()
    _C_FALLBACK = _No()
    _H_PRED_LAT = _No()
    _C_INVALID = _No()


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
_MIN_TRAIN_FRACTION = 0.1  # min_train >= this * block_size (capped by block_size)

_MIN_ALPHA_CP = 1e-4
_MAX_ALPHA_CP = 0.25

# Recommended lower bound for quantization epsilon (approx 2^-40).
_MIN_QUANT_EPS = max(0.0, 2.0 ** -40)

# Limit for how many scores can contribute to prev_digest.
_DEFAULT_MAX_PREV_DIGEST_ITEMS = 1024
_MAX_PREV_DIGEST_ITEMS = 1_000_000

# Allowed calibration modes.
_ALLOWED_MODES = frozenset({"auto", "cp_only", "conformal_only"})


def _clip01(x: float) -> float:
    """Clamp to [0,1], treating NaN/Inf as 1.0 (maximally conservative)."""
    try:
        if not math.isfinite(x):  # NaN/Inf -> 1.0 (most conservative)
            return 1.0
    except Exception:
        return 1.0
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    return float(x)


def _sanitize_scope(scope: str) -> str:
    """
    Sanitize a scope string for use as a metrics label.

    The intent is:
      - avoid unbounded label cardinality;
      - avoid leaking raw tenant/user identifiers directly;
      - keep a short, opaque identifier.

    Recommended: upstream should map human-readable scopes to a small
    registry of stable IDs. This function only enforces a safe shape.
    """
    raw = (scope or "").strip()
    if not raw:
        raw = "default"

    cleaned = _SCOPE_RE.sub("_", raw)
    cleaned = cleaned[:_MAX_SCOPE_LEN]
    cleaned = cleaned.strip("_") or "default"

    # If the cleaned value is still very messy (e.g., too many non-alnum),
    # fall back to a short hash-based identifier.
    non_alnum = sum(ch for ch in (1 for c in cleaned if not c.isalnum()))
    if non_alnum > len(cleaned) // 2 or len(cleaned) >= _MAX_SCOPE_LEN:
        h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
        return f"sc_{h}"

    return cleaned


def _binomial_cp_upper(k: int, n: int, alpha: float) -> float:
    """
    Clopper–Pearson upper bound for a Bernoulli proportion p given
    k successes in n trials.

    Returns p_u in [0,1] s.t. P(K <= k | p_u) >= 1 - alpha.

    When the regularized incomplete beta function is unavailable, falls
    back to a Hoeffding-style bound which is conservative.
    """
    n = int(max(0, n))
    k = int(max(0, min(n, k)))
    a = float(max(1e-12, min(1.0, alpha)))

    if n == 0 or k == n:
        return 1.0
    if k == 0:
        # (1 - p)^n = alpha  =>  p = 1 - alpha^(1/n)  (conservative)
        return _clip01(1.0 - a ** (1.0 / n))

    if hasattr(math, "betainc") and hasattr(math, "beta"):
        # Solve I_p(k+1, n-k) = 1 - alpha
        A = k + 1.0
        B = float(n - k)
        target = 1.0 - a

        def _reg_ibeta(x: float) -> float:
            return math.betainc(A, B, 0.0, x) / math.beta(A, B)

        lo, hi = 0.0, 1.0
        for _ in range(60):
            mid = 0.5 * (lo + hi)
            v = _reg_ibeta(mid)
            if v < target:
                lo = mid
            else:
                hi = mid
        return _clip01(0.5 * (lo + hi))

    # Hoeffding (conservative)
    phat = k / max(1.0, n)
    radius = math.sqrt(max(0.0, math.log(1.0 / a) / (2.0 * max(1.0, n))))
    return _clip01(phat + radius)


def _compute_quantiles(sorted_xs: List[float], probs: Tuple[float, ...]) -> Dict[float, float]:
    """
    Simple quantile helper on a sorted list. Returns a mapping prob -> value.
    """
    out: Dict[float, float] = {}
    n = len(sorted_xs)
    if n == 0:
        for p in probs:
            out[p] = float("nan")
        return out
    for p in probs:
        p_clamped = 0.0 if p <= 0.0 else 1.0 if p >= 1.0 else float(p)
        idx = int(p_clamped * (n - 1))
        out[p] = float(sorted_xs[idx])
    return out


# ---------------------------------------------------------------------------
# Calibrators
# ---------------------------------------------------------------------------


class EmpiricalTailCalibrator:
    """
    Empirical tail estimator with conservative upper confidence via Clopper–Pearson
    (exact when available; otherwise Hoeffding).

    We store a sorted array of scores from a *previous* block.
    For a query s, let k = #{x_i >= s}, then p_upper = CP(k, n; alpha).

    This class is purely local: it does not manage rotation or state on its own.
    """

    def __init__(self, scores: List[float], alpha: float = 0.05, *, quantize_eps: float = 0.0):
        if quantize_eps and quantize_eps > 0.0:
            qeps = max(float(quantize_eps), _MIN_QUANT_EPS)
            xs = [float(max(0.0, min(1.0, round(v / qeps) * qeps))) for v in scores]
        else:
            qeps = 0.0
            xs = [float(max(0.0, min(1.0, v))) for v in scores]

        xs.sort()
        self._xs = xs
        self._n = len(xs)
        self._alpha = float(max(_MIN_ALPHA_CP, min(0.5, alpha)))  # alpha in [MIN_ALPHA_CP, 0.5]
        self._qeps = qeps

    def n(self) -> int:
        return self._n

    def p_upper(self, s: float) -> float:
        if self._n <= 0:
            return 1.0
        if self._qeps > 0.0:
            s = round(float(s) / self._qeps) * self._qeps
        s = _clip01(s)
        i = bisect.bisect_left(self._xs, s)  # first idx >= s
        k = self._n - i
        return _binomial_cp_upper(k=k, n=self._n, alpha=self._alpha)


class ConformalUpperEnvelope:
    """
    Split-conformal one-sided p-value:

        p(s) = (1 + #{x_i >= s}) / (n + 1)

    Valid under arbitrary drift/adaptivity with no parametric assumptions,
    as long as each block is evaluated against an earlier calibration set.
    """

    def __init__(self, calib_scores: List[float], *, quantize_eps: float = 0.0):
        if quantize_eps and quantize_eps > 0.0:
            qeps = max(float(quantize_eps), _MIN_QUANT_EPS)
            xs = [float(max(0.0, min(1.0, round(v / qeps) * qeps))) for v in calib_scores]
        else:
            qeps = 0.0
            xs = [float(max(0.0, min(1.0, v))) for v in calib_scores]

        xs.sort()
        self._xs = xs
        self._n = len(xs)
        self._qeps = qeps

    def n(self) -> int:
        return self._n

    def p_value(self, s: float) -> float:
        if self._n <= 0:
            return 1.0
        if self._qeps > 0.0:
            s = round(float(s) / self._qeps) * self._qeps
        s = _clip01(s)
        i = bisect.bisect_left(self._xs, s)
        k = self._n - i
        return _clip01((1.0 + k) / (self._n + 1.0))


# ---------------------------------------------------------------------------
# Configuration: policy object for calibration
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CalibConfig:
    """
    Configuration for PredictableCalibrator.

    This is a policy object, not just a bag of parameters.

    Fields are divided into:
      - safety-critical:
          * alpha_cp       : confidence level for CP upper bound;
          * min_train      : minimum previous-block size to enable CP;
          * mode           : "auto" | "cp_only" | "conformal_only";
      - statistical-robustness:
          * block_size     : samples per block before rotation;
          * quantize_eps   : epsilon for score quantization;
      - runtime/performance:
          * time_rotate_s  : optional time-based rotation period;
          * max_prev_digest_items: cap on prev_scores included in digests;
          * scope          : label for metrics/logs.

    In high-assurance deployments CalibConfig is expected to be derived from
    a global settings object / config bundle, rather than constructed ad-hoc.
    """

    block_size: int = 512
    min_train: int = 64
    alpha_cp: float = 0.05
    mode: str = "auto"  # {"auto","cp_only","conformal_only"}
    scope: str = "default"

    time_rotate_s: Optional[float] = None
    quantize_eps: float = 0.0

    # Maximum number of prev_scores items to include when computing prev_digest.
    max_prev_digest_items: int = _DEFAULT_MAX_PREV_DIGEST_ITEMS

    # Optional extra governance: restrict allowed modes for this scope.
    permitted_modes: Optional[Tuple[str, ...]] = None

    def __post_init__(self) -> None:
        # Because dataclass is frozen, mutate via object.__setattr__.
        # 1) scope sanitation
        sanitized_scope = _sanitize_scope(self.scope)
        object.__setattr__(self, "scope", sanitized_scope)

        # 2) block_size bounds
        bs = int(self.block_size)
        if bs < _MIN_BLOCK_SIZE:
            bs = _MIN_BLOCK_SIZE
        if bs > _MAX_BLOCK_SIZE:
            bs = _MAX_BLOCK_SIZE
        object.__setattr__(self, "block_size", bs)

        # 3) min_train: at least MIN_MIN_TRAIN and at least MIN_TRAIN_FRACTION * block_size,
        #    but never above block_size.
        mt = int(self.min_train)
        mt = max(mt, _MIN_MIN_TRAIN)
        frac_floor = int(math.ceil(self.block_size * _MIN_TRAIN_FRACTION))
        mt = max(mt, frac_floor)
        if mt > self.block_size:
            mt = self.block_size
        object.__setattr__(self, "min_train", mt)

        # 4) alpha_cp bounds
        acp = float(self.alpha_cp)
        if not math.isfinite(acp):
            acp = 0.05
        acp = max(_MIN_ALPHA_CP, min(0.5, acp))
        object.__setattr__(self, "alpha_cp", acp)

        # 5) quantize_eps: non-negative, optional lower bound when > 0
        qeps = float(self.quantize_eps or 0.0)
        if not math.isfinite(qeps) or qeps < 0.0:
            qeps = 0.0
        if qeps > 0.0:
            qeps = max(qeps, _MIN_QUANT_EPS)
        object.__setattr__(self, "quantize_eps", qeps)

        # 6) time_rotate_s: None or positive float
        trs = self.time_rotate_s
        if trs is not None:
            try:
                trs_f = float(trs)
            except Exception:
                trs_f = 0.0
            if trs_f <= 0.0:
                trs_f = None
            object.__setattr__(self, "time_rotate_s", trs_f)

        # 7) permitted_modes sanity
        perm = self.permitted_modes
        if perm is not None:
            cleaned = tuple(m for m in (str(x).strip().lower() for x in perm) if m in _ALLOWED_MODES)
            if not cleaned:
                cleaned = tuple(sorted(_ALLOWED_MODES))
            object.__setattr__(self, "permitted_modes", cleaned)

        # 8) mode normalization + enforcement
        mode = str(self.mode).strip().lower()
        if mode not in _ALLOWED_MODES:
            mode = "auto"
        if self.permitted_modes is not None and mode not in self.permitted_modes:
            # If the requested mode is disallowed by governance, fall back to a
            # deterministic allowed mode (prefer "auto" if present).
            if "auto" in self.permitted_modes:
                mode = "auto"
            else:
                mode = sorted(self.permitted_modes)[0]
        object.__setattr__(self, "mode", mode)

        # 9) max_prev_digest_items bounds
        max_items = int(self.max_prev_digest_items)
        if max_items < 0:
            max_items = 0
        if max_items > _MAX_PREV_DIGEST_ITEMS:
            max_items = _MAX_PREV_DIGEST_ITEMS
        object.__setattr__(self, "max_prev_digest_items", max_items)

    # ------------------------------------------------------------------ #
    # Stable configuration digest
    # ------------------------------------------------------------------ #

    def digest(self) -> str:
        """
        Stable hash describing the calibration policy for this scope.

        Intended usage:
          - embed into receipts / safety decisions / e-process envelopes;
          - treat any change in this digest as a change of statistical policy;
          - e-process engines should start a new wealth track when this changes.
        """
        payload: Dict[str, Any] = {
            "block_size": self.block_size,
            "min_train": self.min_train,
            "alpha_cp": self.alpha_cp,
            "mode": self.mode,
            "scope": self.scope,
            "time_rotate_s": self.time_rotate_s,
            "quantize_eps": self.quantize_eps,
            "max_prev_digest_items": self.max_prev_digest_items,
        }
        if self.permitted_modes is not None:
            payload["permitted_modes"] = list(self.permitted_modes)
        return canonical_kv_hash(
            payload,
            ctx=f"tcd:calib_cfg:{self.scope}",
            label="calib_cfg",
        )


# ---------------------------------------------------------------------------
# Predictable, prev-only calibrator
# ---------------------------------------------------------------------------


class PredictableCalibrator:
    """
    Rolling cross-fit predictable calibrator.

    Design contract:
      - For a score stream {s_t}, at time t, predict(s_t) uses ONLY scores
        from a previous block (prev_scores) and the fixed CalibConfig cfg;
      - No look-ahead: current or future scores are never used for p_t;
      - Under suitable assumptions, the resulting p_t sequence is intended
        to be super-uniform and thus safe for e-process control.

    Internal structure:
      - Maintains two buffers: prev_scores (for predictions), cur_scores (collecting).
      - For each query s_t, use only prev_scores to compute p(s_t).
      - Rotates either by count (block_size) or by time (time_rotate_s), whichever
        triggers first.

    Modes:
      - "auto": use CP upper bound if prev_n >= min_train; else conformal fallback.
      - "cp_only": prefer CP; if insufficient data, conformal fallback.
      - "conformal_only": always use conformal.

    Fallback reasons:
      - "insufficient": not enough previous data for CP;
      - "forced_drift": caller explicitly forces fallback (e.g., drift alarm).

    Privileged operations:
      - rotate_now() and predict(score, force_fallback=True) are intended
        for use by drift detectors or an admin control-plane. Callers should
        record and audit their usage via logs or metrics.
    """

    def __init__(self, cfg: CalibConfig = CalibConfig()):
        self.cfg = cfg
        self._scope = cfg.scope
        self._cfg_digest = cfg.digest()

        self._prev_scores: List[float] = []
        self._cur_scores: List[float] = []
        self._cal_cp: Optional[EmpiricalTailCalibrator] = None
        self._cal_conf: Optional[ConformalUpperEnvelope] = None

        self._rotate_count = 0
        self._cur_started_at = time.time()

        # For forensics / abuse detection.
        self._invalid_count = 0
        self._last_rotation_ts: float = 0.0
        self._last_rotation_reason: str = ""
        self._last_forced_fallback_ts: float = 0.0
        self._last_forced_fallback_reason: str = ""

        self._lock = threading.RLock()

        _G_BLOCK_SIZE.labels(self._scope).set(0)

    # ---------- internal helpers ----------

    def _rebuild_prev(self) -> None:
        prev = list(self._prev_scores)
        prev.sort()
        self._cal_conf = ConformalUpperEnvelope(prev, quantize_eps=self.cfg.quantize_eps)
        self._cal_cp = (
            EmpiricalTailCalibrator(prev, alpha=self.cfg.alpha_cp, quantize_eps=self.cfg.quantize_eps)
            if len(prev) >= self.cfg.min_train
            else None
        )
        _G_BLOCK_SIZE.labels(self._scope).set(len(prev))

    def _maybe_rotate_time(self) -> None:
        if self.cfg.time_rotate_s:
            now = time.time()
            if (now - self._cur_started_at) >= float(self.cfg.time_rotate_s):
                self._prev_scores = self._cur_scores
                self._cur_scores = []
                self._cur_started_at = now
                self._rebuild_prev()
                self._rotate_count += 1
                self._last_rotation_ts = now
                self._last_rotation_reason = "time"
                _C_ROTATE.labels(self._scope, "time").inc()

    def _rotate_if_needed_unlocked(self) -> None:
        # Count-based rotation
        if len(self._cur_scores) >= self.cfg.block_size:
            now = time.time()
            self._prev_scores = self._cur_scores
            self._cur_scores = []
            self._cur_started_at = now
            self._rebuild_prev()
            self._rotate_count += 1
            self._last_rotation_ts = now
            self._last_rotation_reason = "count"
            _C_ROTATE.labels(self._scope, "count").inc()

        # Time-based rotation
        self._maybe_rotate_time()

    def _use_cp(self) -> bool:
        if self.cfg.mode == "cp_only":
            return True
        if self.cfg.mode == "conformal_only":
            return False
        # auto
        return (self._cal_cp is not None) and (self._cal_cp.n() >= self.cfg.min_train)

    def _digest_prev_hex_unlocked(self, max_items: Optional[int] = None) -> str:
        """
        Stable digest of prev_scores for receipts / attestation.

        To avoid unbounded cost, only the first max_items values are included.
        The caller is expected to treat this as an opaque identifier.
        """
        if max_items is None:
            max_items = self.cfg.max_prev_digest_items
        if max_items < 0:
            max_items = 0
        if max_items > _MAX_PREV_DIGEST_ITEMS:
            max_items = _MAX_PREV_DIGEST_ITEMS

        m = hashlib.sha256()
        items = self._prev_scores[:max_items]
        for v in items:
            # deterministic packing using float.hex()
            m.update(float(v).hex().encode("ascii"))
            m.update(b";")
        m.update(str(len(self._prev_scores)).encode("ascii"))
        return m.hexdigest()

    # ---------- public API ----------

    def predict(self, score: float, *, force_fallback: bool = False) -> float:
        """
        Compute a conservative p-value for a single score.

        Contract:
          - Uses only prev_scores and cfg (no future/current data);
          - Honors cfg.mode and min_train;
          - When force_fallback=True, always uses conformal calibration.
        """
        t0 = time.perf_counter()
        try:
            with self._lock:
                # Cold start: ensure calibrators exist.
                if self._cal_conf is None and self._cal_cp is None:
                    self._rebuild_prev()

                # Sanitize score.
                if not math.isfinite(score) or score < 0.0 or score > 1.0:
                    _C_INVALID.labels(self._scope).inc()
                    self._invalid_count += 1
                s = _clip01(score)

                # Time-based rotation can be checked here to keep block boundaries fresh.
                self._maybe_rotate_time()

                # Decide calibrator.
                if force_fallback:
                    # Privileged: caller explicitly forces conformal path
                    # (e.g., under a drift alarm). Should be audited by scope.
                    now = time.time()
                    self._last_forced_fallback_ts = now
                    self._last_forced_fallback_reason = "forced_drift"
                    _C_FALLBACK.labels(self._scope, "forced_drift").inc()
                    return self._cal_conf.p_value(s) if self._cal_conf else 1.0

                if self.cfg.mode == "conformal_only":
                    return self._cal_conf.p_value(s) if self._cal_conf else 1.0

                if self._use_cp():
                    return self._cal_cp.p_upper(s)  # CP (or Hoeffding inside) with prev-only data

                # Fallback: insufficient data for CP.
                now = time.time()
                self._last_forced_fallback_ts = now
                self._last_forced_fallback_reason = "insufficient"
                _C_FALLBACK.labels(self._scope, "insufficient").inc()
                return self._cal_conf.p_value(s) if self._cal_conf else 1.0
        finally:
            _H_PRED_LAT.labels(self._scope).observe(max(0.0, time.perf_counter() - t0))

    def update(self, score: float) -> None:
        """
        Feed a new score into the current block.

        This does not influence p-values for the current score; those are
        always computed using prev_scores only.
        """
        with self._lock:
            s = _clip01(score)
            if self.cfg.quantize_eps and self.cfg.quantize_eps > 0.0:
                s = round(s / self.cfg.quantize_eps) * self.cfg.quantize_eps
            self._cur_scores.append(s)
            self._rotate_if_needed_unlocked()

    def feed_and_predict(self, score: float, *, force_fallback: bool = False) -> float:
        """
        Convenience method: predict p-value and then feed the score into the
        current block.

        This preserves the prev-only contract: prediction happens before update.
        """
        with self._lock:
            p = self.predict(score, force_fallback=force_fallback)
            self.update(score)
            return p

    # ---------- stats & maintenance ----------

    def block_sizes(self) -> Tuple[int, int]:
        """Return (prev_n, cur_n) under the internal lock."""
        with self._lock:
            return len(self._prev_scores), len(self._cur_scores)

    def rotate_now(self) -> None:
        """
        Force a rotation: move cur_scores into prev_scores and reset the current block.

        This is a privileged operation and should be invoked by a drift detector
        or admin control-plane, not arbitrary untrusted callers.
        """
        with self._lock:
            if self._cur_scores:
                self._prev_scores = self._cur_scores
                self._cur_scores = []
            now = time.time()
            self._cur_started_at = now
            self._rebuild_prev()
            self._rotate_count += 1
            self._last_rotation_ts = now
            self._last_rotation_reason = "forced"
            _C_ROTATE.labels(self._scope, "forced").inc()

    @property
    def cfg_digest_hex(self) -> str:
        """
        Digest of the CalibConfig in effect for this instance.

        Any change in this value should be treated as a change in
        statistical policy for downstream e-process engines.
        """
        return self._cfg_digest

    def state_digest(self) -> str:
        """
        Stable digest of the calibration state (config + prev_scores summary).

        Intended usage:
          - embed in safety receipts and e-process envelopes;
          - include in runtime attestation payloads.

        Downstream systems can use this to verify that a given decision
        was made under a specific calibration state.
        """
        with self._lock:
            payload: Dict[str, Any] = {
                "cfg_digest": self._cfg_digest,
                "prev_digest": self._digest_prev_hex_unlocked(),
                "prev_n": len(self._prev_scores),
                "cur_n": len(self._cur_scores),
                "rotations": self._rotate_count,
                "mode": self.cfg.mode,
            }
            return canonical_kv_hash(
                payload,
                ctx=f"tcd:calib_state:{self._scope}",
                label="calib_state",
            )

    def stats(self) -> Dict[str, object]:
        """
        Human-readable stats for observability and forensics.

        Returns a JSON-serializable dictionary with:
          - current block sizes;
          - mode / min_train / alpha_cp;
          - rotation counters and last rotation metadata;
          - invalid score count;
          - basic distribution probes for prev_scores;
          - config and state digests.
        """
        with self._lock:
            prev_n = len(self._prev_scores)
            cur_n = len(self._cur_scores)
            prev_mean = float(sum(self._prev_scores) / prev_n) if prev_n > 0 else float("nan")
            cur_mean = float(sum(self._cur_scores) / cur_n) if cur_n > 0 else float("nan")

            # Use the sorted xs from the conformal calibrator if available.
            xs_sorted: Optional[List[float]] = None
            if self._cal_conf is not None and getattr(self._cal_conf, "_xs", None) is not None:
                xs_sorted = list(self._cal_conf._xs)  # type: ignore[attr-defined]
            elif prev_n > 0:
                xs_sorted = sorted(self._prev_scores)

            quantiles: Dict[float, float] = {}
            if xs_sorted is not None:
                quantiles = _compute_quantiles(xs_sorted, (0.5, 0.9, 0.99))

            return {
                "scope": self._scope,
                "cfg_digest": self._cfg_digest,
                "state_digest": self.state_digest(),
                "prev_n": prev_n,
                "cur_n": cur_n,
                "prev_mean": prev_mean,
                "cur_mean": cur_mean,
                "prev_q50": quantiles.get(0.5, float("nan")),
                "prev_q90": quantiles.get(0.9, float("nan")),
                "prev_q99": quantiles.get(0.99, float("nan")),
                "mode": self.cfg.mode,
                "min_train": self.cfg.min_train,
                "alpha_cp": self.cfg.alpha_cp,
                "rotations": self._rotate_count,
                "cp_ready": bool(self._cal_cp is not None and self._cal_cp.n() >= self.cfg.min_train),
                "time_rotate_s": self.cfg.time_rotate_s,
                "quantize_eps": self.cfg.quantize_eps,
                "max_prev_digest_items": self.cfg.max_prev_digest_items,
                "invalid_count": self._invalid_count,
                "last_rotation_ts": self._last_rotation_ts,
                "last_rotation_reason": self._last_rotation_reason,
                "last_forced_fallback_ts": self._last_forced_fallback_ts,
                "last_forced_fallback_reason": self._last_forced_fallback_reason,
            }

    # ---------- snapshot & restore for AE / warm-start ----------

    def snapshot(self) -> Dict[str, object]:
        """
        Serializable state for artifact evaluation / warm-start.

        This method is intended for trusted environments (e.g. AE harness,
        controlled warm-start for a particular scope). For untrusted inputs,
        do not feed the resulting snapshot directly into from_snapshot().
        """
        with self._lock:
            return {
                "cfg": asdict(self.cfg),
                "cfg_digest": self._cfg_digest,
                "prev_scores": list(self._prev_scores),
                "cur_scores": list(self._cur_scores),
                "rotate_count": int(self._rotate_count),
                "cur_started_at": float(self._cur_started_at),
                "invalid_count": int(self._invalid_count),
                "last_rotation_ts": float(self._last_rotation_ts),
                "last_rotation_reason": self._last_rotation_reason,
                "last_forced_fallback_ts": float(self._last_forced_fallback_ts),
                "last_forced_fallback_reason": self._last_forced_fallback_reason,
            }

    @classmethod
    def from_snapshot(cls, snap: Mapping[str, object]) -> "PredictableCalibrator":
        """
        Reconstruct a PredictableCalibrator from a snapshot() payload.

        The caller is expected to treat the snapshot as trusted input
        (e.g. from a signed bundle or controlled AE harness). Untrusted,
        user-supplied data should not be used here without additional
        validation and policy checks at a higher layer.
        """
        cfg_raw = snap.get("cfg", {})  # type: ignore[arg-type]
        if not isinstance(cfg_raw, dict):
            cfg_raw = {}
        cfg = CalibConfig(**cfg_raw)

        # Optional consistency check: compare provided cfg_digest with fresh digest.
        snap_digest = snap.get("cfg_digest")
        cfg_digest_now = cfg.digest()
        cfg_digest_matches = isinstance(snap_digest, str) and (snap_digest == cfg_digest_now)

        self = cls(cfg)

        with self._lock:  # type: ignore[attr-defined]
            # If the digest mismatches, discard score buffers and start fresh.
            if not cfg_digest_matches:
                # Keep only config; scores will start empty.
                self._prev_scores = []
                self._cur_scores = []
                self._rotate_count = 0
                self._cur_started_at = time.time()
                self._invalid_count = 0
                self._last_rotation_ts = 0.0
                self._last_rotation_reason = ""
                self._last_forced_fallback_ts = 0.0
                self._last_forced_fallback_reason = ""
                self._rebuild_prev()
                return self

            # Otherwise, restore scores with bounds and sanitization.
            max_len = max(1, min(_MAX_BLOCK_SIZE, cfg.block_size * 4))

            def _sanitize_scores(raw: Any) -> List[float]:
                out: List[float] = []
                if not isinstance(raw, list):
                    return out
                for v in raw:
                    if len(out) >= max_len:
                        break
                    try:
                        f = float(v)
                    except Exception:
                        continue
                    if not math.isfinite(f):
                        continue
                    out.append(_clip01(f))
                return out

            self._prev_scores = _sanitize_scores(snap.get("prev_scores"))
            self._cur_scores = _sanitize_scores(snap.get("cur_scores"))
            self._rotate_count = int(snap.get("rotate_count", 0) or 0)

            # cur_started_at sanity: clamp to a reasonable window around "now".
            now = time.time()
            try:
                cs = float(snap.get("cur_started_at", now) or now)
            except Exception:
                cs = now
            # If excessively in the future or past, reset to now.
            if cs > now + 3600.0 or cs < now - 365.0 * 24.0 * 3600.0:
                cs = now
            self._cur_started_at = cs

            self._invalid_count = int(snap.get("invalid_count", 0) or 0)
            try:
                self._last_rotation_ts = float(snap.get("last_rotation_ts", 0.0) or 0.0)
            except Exception:
                self._last_rotation_ts = 0.0
            self._last_rotation_reason = str(snap.get("last_rotation_reason", "") or "")
            try:
                self._last_forced_fallback_ts = float(snap.get("last_forced_fallback_ts", 0.0) or 0.0)
            except Exception:
                self._last_forced_fallback_ts = 0.0
            self._last_forced_fallback_reason = str(snap.get("last_forced_fallback_reason", "") or "")

            self._rebuild_prev()

        return self

    def prev_digest_hex(self) -> str:
        """Public access to the prev_scores digest."""
        with self._lock:
            return self._digest_prev_hex_unlocked()