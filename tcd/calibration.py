# FILE: tcd/calibration.py
from __future__ import annotations
"""
Predictable Calibration for Runtime Safety (score -> conservative p-value).

Enhancements for pilot stability & MLSys reproducibility:
  - Thread-safety via RLock
  - Optional time-based rotation (time_rotate_s)
  - Snapshot/restore & stable digest for receipts/AE
  - Optional score quantization (quantize_eps) for cross-hardware stability
  - Extra Prometheus metrics (latency, invalids)
"""

from dataclasses import dataclass, asdict
from typing import List, Optional, Tuple, Dict
import bisect
import math
import threading
import time
import hashlib

try:
    from prometheus_client import Counter, Gauge, Histogram
    _HAS_PROM = True
except Exception:
    _HAS_PROM = False


# ---------- Prometheus metrics (SRE) ----------

if _HAS_PROM:
    _G_BLOCK_SIZE = Gauge(
        "tcd_calibration_block_size",
        "Number of samples in the previous (predictable) block used for calibration.",
        ["scope"],
    )
    _C_ROTATE = Counter(
        "tcd_calibration_block_rotate_total",
        "Number of times predictable calibration rotated its block.",
        ["scope", "mode"],   # mode in {"count","time","forced"}
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
else:
    class _No:
        def labels(self, *_, **__): return self
        def set(self, *_): pass
        def inc(self, *_): pass
        def observe(self, *_): pass
    _G_BLOCK_SIZE = _No(); _C_ROTATE = _No(); _C_FALLBACK = _No(); _H_PRED_LAT = _No(); _C_INVALID = _No()


# ---------- Utilities ----------

def _clip01(x: float) -> float:
    try:
        if not math.isfinite(x):  # NaN/Inf -> 1.0 (most conservative)
            return 1.0
    except Exception:
        return 1.0
    return 0.0 if x <= 0.0 else 1.0 if x >= 1.0 else float(x)


def _binomial_cp_upper(k: int, n: int, alpha: float) -> float:
    """
    Clopper–Pearson upper bound for Binomial proportion p given k successes of n trials.
    Returns p_u in [0,1] s.t. P(K <= k | p_u) = 1 - alpha.
    Uses math.betainc (Python 3.11+) else a conservative Hoeffding bound.
    """
    n = int(max(0, n))
    k = int(max(0, min(n, k)))
    a = float(max(1e-12, min(1.0, alpha)))

    if n == 0 or k == n:
        return 1.0
    if k == 0:
        # (1 - p)^n = alpha  =>  p = 1 - alpha^(1/n)  (conservative w.r.t exact CP)
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


# ---------- Calibrators ----------

class EmpiricalTailCalibrator:
    """
    Empirical tail estimator with conservative upper confidence via Clopper–Pearson
    (exact when available; otherwise Hoeffding). We store a sorted array of scores
    from a *previous* block. For a query s, let k = #{x_i >= s}, then p_upper = CP(k, n; alpha).
    """

    def __init__(self, scores: List[float], alpha: float = 0.05, *, quantize_eps: float = 0.0):
        if quantize_eps and quantize_eps > 0.0:
            xs = [float(max(0.0, min(1.0, round(v / quantize_eps) * quantize_eps))) for v in scores]
        else:
            xs = [float(max(0.0, min(1.0, v))) for v in scores]
        xs.sort()
        self._xs = xs
        self._n = len(xs)
        self._alpha = float(max(1e-12, min(0.5, alpha)))  # alpha in (0, 0.5]
        self._qeps = float(max(0.0, quantize_eps or 0.0))

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
    Valid under arbitrary drift/adaptivity, no distributional assumptions.
    """

    def __init__(self, calib_scores: List[float], *, quantize_eps: float = 0.0):
        if quantize_eps and quantize_eps > 0.0:
            xs = [float(max(0.0, min(1.0, round(v / quantize_eps) * quantize_eps))) for v in calib_scores]
        else:
            xs = [float(max(0.0, min(1.0, v))) for v in calib_scores]
        xs.sort()
        self._xs = xs
        self._n = len(xs)
        self._qeps = float(max(0.0, quantize_eps or 0.0))

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


@dataclass
class CalibConfig:
    block_size: int = 512            # samples per block (count-driven rotation)
    min_train: int = 64              # min previous-block size to enable CP
    alpha_cp: float = 0.05           # CP confidence level (upper bound 1-alpha)
    mode: str = "auto"               # {"auto","cp_only","conformal_only"}
    scope: str = "default"           # Prom label (e.g., "chat/en/model0")
    time_rotate_s: Optional[float] = None   # optional time-based rotation period
    quantize_eps: float = 0.0        # optional score quantization epsilon (e.g., 1e-6)


class PredictableCalibrator:
    """
    Rolling cross-fit predictable calibrator:
      - Maintains two buffers: prev_block (for predictions), cur_block (collecting).
      - For each query s_t: use ONLY prev_block to compute p(s_t).
      - Rotate either by count (block_size) or by time (time_rotate_s), whichever triggers first.

    Modes:
      - "auto": use CP upper bound if prev_n >= min_train; else conformal fallback.
      - "cp_only": prefer CP; if insufficient data, conformal fallback.
      - "conformal_only": always use conformal.

    Fallback reasons:
      - "insufficient": not enough previous data
      - "forced_drift": caller explicitly forces fallback (e.g., drift alarm)
    """

    def __init__(self, cfg: CalibConfig = CalibConfig()):
        self.cfg = cfg
        self._prev_scores: List[float] = []
        self._cur_scores: List[float] = []
        self._cal_cp: Optional[EmpiricalTailCalibrator] = None
        self._cal_conf: Optional[ConformalUpperEnvelope] = None
        self._rotate_count = 0
        self._cur_started_at = time.time()
        self._lock = threading.RLock()
        _G_BLOCK_SIZE.labels(cfg.scope).set(0)

    # ---------- internal ----------

    def _rebuild_prev(self) -> None:
        prev = list(self._prev_scores)
        prev.sort()
        self._cal_conf = ConformalUpperEnvelope(prev, quantize_eps=self.cfg.quantize_eps)
        self._cal_cp = EmpiricalTailCalibrator(prev, alpha=self.cfg.alpha_cp, quantize_eps=self.cfg.quantize_eps) \
                       if len(prev) >= self.cfg.min_train else None
        _G_BLOCK_SIZE.labels(self.cfg.scope).set(len(prev))

    def _maybe_rotate_time(self) -> None:
        if self.cfg.time_rotate_s and (time.time() - self._cur_started_at) >= float(self.cfg.time_rotate_s):
            self._prev_scores = self._cur_scores
            self._cur_scores = []
            self._cur_started_at = time.time()
            self._rebuild_prev()
            self._rotate_count += 1
            _C_ROTATE.labels(self.cfg.scope, "time").inc()

    def _rotate_if_needed_unlocked(self) -> None:
        # count-based rotation
        if len(self._cur_scores) >= self.cfg.block_size:
            self._prev_scores = self._cur_scores
            self._cur_scores = []
            self._cur_started_at = time.time()
            self._rebuild_prev()
            self._rotate_count += 1
            _C_ROTATE.labels(self.cfg.scope, "count").inc()
        # time-based rotation
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
        Stable digest of prev scores for receipts/AE. Avoids Prom cardinality blowup;
        caller can attach this string into receipts/logs.
        """
        m = hashlib.sha256()
        items = self._prev_scores if max_items is None else self._prev_scores[:max_items]
        for v in items:
            # deterministic packing (8-byte float)
            m.update(float(v).hex().encode("ascii"))
            m.update(b";")
        m.update(str(len(self._prev_scores)).encode("ascii"))
        return m.hexdigest()

    # ---------- public ----------

    def predict(self, score: float, *, force_fallback: bool = False) -> float:
        t0 = time.perf_counter()
        try:
            with self._lock:
                # cold start: ensure calibrators exist
                if self._cal_conf is None and self._cal_cp is None:
                    self._rebuild_prev()

                # sanitize
                if not math.isfinite(score) or score < 0.0 or score > 1.0:
                    _C_INVALID.labels(self.cfg.scope).inc()
                s = _clip01(score)

                # time rotation can be checked here to keep prev/cur boundaries fresh
                self._maybe_rotate_time()

                # decide calibrator
                if force_fallback:
                    _C_FALLBACK.labels(self.cfg.scope, "forced_drift").inc()
                    return self._cal_conf.p_value(s) if self._cal_conf else 1.0

                if self.cfg.mode == "conformal_only":
                    return self._cal_conf.p_value(s) if self._cal_conf else 1.0

                if self._use_cp():
                    return self._cal_cp.p_upper(s)  # CP (or Hoeffding inside) with prev-only data

                _C_FALLBACK.labels(self.cfg.scope, "insufficient").inc()
                return self._cal_conf.p_value(s) if self._cal_conf else 1.0
        finally:
            _H_PRED_LAT.labels(self.cfg.scope).observe(max(0.0, time.perf_counter() - t0))

    def update(self, score: float) -> None:
        with self._lock:
            s = _clip01(score)
            if self.cfg.quantize_eps and self.cfg.quantize_eps > 0.0:
                s = round(s / self.cfg.quantize_eps) * self.cfg.quantize_eps
            self._cur_scores.append(s)
            self._rotate_if_needed_unlocked()

    def feed_and_predict(self, score: float, *, force_fallback: bool = False) -> float:
        with self._lock:
            p = self.predict(score, force_fallback=force_fallback)
            self.update(score)
            return p

    # ---------- stats & maintenance ----------

    def block_sizes(self) -> Tuple[int, int]:
        with self._lock:
            return len(self._prev_scores), len(self._cur_scores)

    def rotate_now(self) -> None:
        with self._lock:
            # forced rotate (admin/drift hook)
            if self._cur_scores:
                self._prev_scores = self._cur_scores
                self._cur_scores = []
            self._cur_started_at = time.time()
            self._rebuild_prev()
            self._rotate_count += 1
            _C_ROTATE.labels(self.cfg.scope, "forced").inc()

    def stats(self) -> Dict[str, object]:
        with self._lock:
            prev_n = len(self._prev_scores)
            cur_n = len(self._cur_scores)
            return {
                "prev_n": prev_n,
                "cur_n": cur_n,
                "mode": self.cfg.mode,
                "min_train": self.cfg.min_train,
                "alpha_cp": self.cfg.alpha_cp,
                "rotations": self._rotate_count,
                "cp_ready": bool(self._cal_cp is not None and self._cal_cp.n() >= self.cfg.min_train),
                "time_rotate_s": self.cfg.time_rotate_s,
                "quantize_eps": self.cfg.quantize_eps,
                "prev_digest": self._digest_prev_hex_unlocked(max_items=1024),  # bounded work
            }

    # ---------- AE reproducibility ----------

    def snapshot(self) -> Dict[str, object]:
        """Serializable state for artifact evaluation / warm-start."""
        with self._lock:
            return {
                "cfg": asdict(self.cfg),
                "prev_scores": list(self._prev_scores),
                "cur_scores": list(self._cur_scores),
                "rotate_count": int(self._rotate_count),
                "cur_started_at": float(self._cur_started_at),
            }

    @classmethod
    def from_snapshot(cls, snap: Dict[str, object]) -> "PredictableCalibrator":
        cfg_dict = dict(snap.get("cfg", {}))  # type: ignore
        cfg = CalibConfig(**cfg_dict)
        self = cls(cfg)
        with self._lock:
            self._prev_scores = list(snap.get("prev_scores", []))  # type: ignore
            self._cur_scores = list(snap.get("cur_scores", []))    # type: ignore
            self._rotate_count = int(snap.get("rotate_count", 0))  # type: ignore
            self._cur_started_at = float(snap.get("cur_started_at", time.time()))  # type: ignore
            self._rebuild_prev()
        return self

    def prev_digest_hex(self) -> str:
        with self._lock:
            return self._digest_prev_hex_unlocked()