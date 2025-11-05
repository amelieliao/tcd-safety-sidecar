# FILE: tcd/detector.py
from __future__ import annotations

"""
Low-latency, pluggable safety detector with monotone calibration and conformal fallback.

Design goals (aligned with the rest of TCD):
- Pure-Python, dependency-light, deterministic, production-safe defaults
- Clear separation of concerns: feature extraction → model score → calibration → decision
- Monotone calibration (isotonic knots / PAV) with split-conformal fallback under drift
- Tight input guards (max bytes/tokens), time-budget watchdog, and structured evidence
- Optional Prometheus metrics (auto-disabled if prometheus_client not installed)
- Canonical JSON dumps (orjson when available) and Blake3-based evidence hashing

Environment knobs:
- TCD_DETECTOR_TIME_BUDGET_MS   (default: 3.0)
- TCD_DETECTOR_MAX_TOKENS       (default: 2048)
- TCD_DETECTOR_MAX_BYTES        (default: 100_000)
- TCD_DETECTOR_THRESH_LOW       (default: 0.20)  → decision "allow" if p ≥ 1 - THRESH_LOW
- TCD_DETECTOR_THRESH_HIGH      (default: 0.80)  → decision "block" if p ≤ (1 - THRESH_HIGH)
- TCD_DETECTOR_CALIB_MODE       (default: "isotonic"; options: "isotonic", "conformal", "identity")
- TCD_DETECTOR_CALIB_KNOTS      (JSON: [[score, p], ...] sorted by score) for isotonic mode
- TCD_DETECTOR_CONFORMAL_WINDOW (default: 1024)
- TCD_DETECTOR_CONFORMAL_ALPHA  (default: 0.05)
- TCD_DETECTOR_RANDOM_SEED      (optional int; per-process seed for deterministic heuristics)

Notes on decisions:
- We map raw model scores (higher = riskier) to p-values in [0,1] with a *monotone* calibrator.
- A small p means "unlikely under safe behavior" → stronger evidence of risk.
- Routing example:
    if p <= (1 - THRESH_HIGH):  "block"
    elif p <= (1 - THRESH_LOW): "cool"   (throttle, temperature/top-p or fallback decoder)
    else:                       "allow"
"""

import dataclasses
import json
import logging
import math
import os
import random
import re
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

from pydantic import BaseModel, Field, field_validator

# Optional fast JSON
try:  # pragma: no cover (perf sugar)
    import orjson as _orjson

    def _dumps(obj: Any) -> bytes:
        return _orjson.dumps(obj, option=_orjson.OPT_SORT_KEYS)
except Exception:  # pragma: no cover
    def _dumps(obj: Any) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

# Optional Prometheus
try:  # pragma: no cover
    from prometheus_client import REGISTRY, Counter, Gauge, Histogram

    _METRICS_ENABLED = True
except Exception:  # pragma: no cover
    REGISTRY = None  # type: ignore
    _METRICS_ENABLED = False

# Repo-local crypto (preferred)
try:
    from .crypto import Blake3Hash  # type: ignore
except Exception:  # pragma: no cover
    import hashlib

    class Blake3Hash:  # minimal shim (not Blake3, but preserves interface)
        def hex(self, data: bytes, ctx: str = "") -> str:
            h = hashlib.blake2s()
            if ctx:
                h.update(ctx.encode("utf-8"))
            h.update(data)
            return h.hexdigest()

logger = logging.getLogger("tcd.detector")

__all__ = [
    # Schemas / configs
    "DetectRequest",
    "DetectOut",
    "DetectorConfig",
    "CalibratorConfig",
    "IsotonicKnots",
    "ConformalBuffer",
    # Interfaces
    "ScoreModel",
    "Detector",
    "build_default_detector",
    "HeuristicKeywordModel",
]

# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

_TIME_BUDGET_MS = float(os.getenv("TCD_DETECTOR_TIME_BUDGET_MS", "3.0"))
_MAX_TOKENS = int(os.getenv("TCD_DETECTOR_MAX_TOKENS", "2048"))
_MAX_BYTES = int(os.getenv("TCD_DETECTOR_MAX_BYTES", "100000"))
_THRESH_LOW = float(os.getenv("TCD_DETECTOR_THRESH_LOW", "0.20"))
_THRESH_HIGH = float(os.getenv("TCD_DETECTOR_THRESH_HIGH", "0.80"))
_CALIB_MODE = os.getenv("TCD_DETECTOR_CALIB_MODE", "isotonic").strip().lower()
_CONFORMAL_WINDOW = int(os.getenv("TCD_DETECTOR_CONFORMAL_WINDOW", "1024"))
_CONFORMAL_ALPHA = float(os.getenv("TCD_DETECTOR_CONFORMAL_ALPHA", "0.05"))
_seed = os.getenv("TCD_DETECTOR_RANDOM_SEED")
if _seed is not None:
    try:
        random.seed(int(_seed))
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _soft_truncate_bytes(s: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    b = s.encode("utf-8", "ignore")
    if len(b) <= max_bytes:
        return s
    return b[:max_bytes].decode("utf-8", "ignore")


def _approx_tokens(s: str) -> int:
    # Lightweight approximation (bounded CPU). Not model-specific.
    # Counts chunks of wordish runs + punctuation.
    # Keeps latency predictable and correlates with tokenizer length.
    return max(1, len(re.findall(r"\w+|[^\s\w]", s)))


def _truncate_tokens(s: str, max_tokens: int) -> str:
    if max_tokens <= 0:
        return ""
    if _approx_tokens(s) <= max_tokens:
        return s
    # Greedy split by whitespace; rough cut until token count under budget.
    parts = s.split()
    out: List[str] = []
    t = 0
    for p in parts:
        c = max(1, _approx_tokens(p))
        if t + c > max_tokens:
            break
        out.append(p)
        t += c
    text = " ".join(out)
    # Safety: enforce bytes cap as well
    return _soft_truncate_bytes(text, _MAX_BYTES)


class _TimeBudget:
    __slots__ = ("deadline",)

    def __init__(self, ms: float):
        self.deadline = time.perf_counter() + max(0.0005, ms / 1000.0)

    def check(self) -> None:
        if time.perf_counter() > self.deadline:
            raise TimeoutError("detector time budget exceeded")

    def remaining_ms(self) -> float:
        return max(0.0, (self.deadline - time.perf_counter()) * 1000.0)


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _hash_canon(obj: Any, ctx: str) -> str:
    return Blake3Hash().hex(_dumps(obj), ctx=ctx)


# ---------------------------------------------------------------------------
# Models / Features
# ---------------------------------------------------------------------------

@dataclass
class Features:
    len_bytes: int
    len_tokens: int
    has_url: bool
    upper_ratio: float
    digit_ratio: float
    keywords_hit: int


class ScoreModel(Protocol):
    """Pluggable scoring model: higher score → higher risk."""

    name: str
    version: str

    def score(self, text: str, meta: Optional[Dict[str, Any]], *, budget: _TimeBudget) -> Tuple[float, Dict[str, Any]]:
        """
        Returns (raw_score, model_evidence).
        Should be deterministic given inputs and not exceed the time budget.
        raw_score should lie in [0,1] if possible; out-of-range will be clamped.
        """


class HeuristicKeywordModel:
    """
    Tiny, deterministic heuristic:
    - Normalizes score by simple features and keyword hits
    - CPU-bounded; no external deps; great as a bootstrap fallback
    """

    name = "heuristic-keywords"
    version = "0.2.1"

    _KW = tuple(
        kw.lower()
        for kw in (
            # Illustrative set; caller can override via meta["extra_keywords"]
            "weapon",
            "bomb",
            "suicide",
            "kill",
            "credit card",
            "ssn",
            "exploit",
            "harm",
            "hate",
            "nsfw",
            "jailbreak",
            "prompt injection",
        )
    )

    def score(self, text: str, meta: Optional[Dict[str, Any]], *, budget: _TimeBudget) -> Tuple[float, Dict[str, Any]]:
        budget.check()
        low = text.lower()
        hits = 0
        kws = list(self._KW)
        if meta and isinstance(meta.get("extra_keywords"), (list, tuple)):
            kws = kws + [str(x).lower() for x in meta["extra_keywords"]]
        for kw in kws:
            if kw and kw in low:
                hits += 1
        budget.check()

        # Lightweight features
        n_bytes = len(text.encode("utf-8", "ignore"))
        n_tokens = _approx_tokens(text)
        has_url = bool(re.search(r"https?://|www\.", text))
        upper_ratio = _clamp01(len(re.findall(r"[A-Z]", text)) / max(1, len(text)))
        digit_ratio = _clamp01(len(re.findall(r"\d", text)) / max(1, len(text)))

        feats = Features(
            len_bytes=n_bytes,
            len_tokens=n_tokens,
            has_url=has_url,
            upper_ratio=upper_ratio,
            digit_ratio=digit_ratio,
            keywords_hit=hits,
        )

        # Simple bounded scoring: keywords + structure penalties (urls/upper/digits)
        # Shape to [0,1] with a sigmoid-ish curve for smoothness.
        base = hits + (0.6 if has_url else 0.0) + 0.4 * upper_ratio + 0.3 * digit_ratio
        base = base / (3.0 + 0.25 * math.log1p(n_tokens))  # normalize by length a bit
        raw = 1.0 / (1.0 + math.exp(-3.0 * (base - 0.5)))  # smooth
        raw = _clamp01(raw)

        evidence = {
            "features": dataclasses.asdict(feats),
            "hits": hits,
            "kw_sample": kws[:8],  # expose a bounded sample only
        }
        return raw, evidence


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------

@dataclass
class IsotonicKnots:
    """Pre-fit monotone mapping; pairs of (score, p). Score ↑ → p ↓ typically."""
    pairs: List[Tuple[float, float]]  # must be sorted by score asc

    def __post_init__(self):
        if not self.pairs:
            raise ValueError("IsotonicKnots requires at least one pair")
        self.pairs.sort(key=lambda x: float(x[0]))

    def map(self, s: float) -> float:
        s = float(s)
        xs = [x for x, _ in self.pairs]
        ys = [y for _, y in self.pairs]
        if s <= xs[0]:
            return _clamp01(ys[0])
        if s >= xs[-1]:
            return _clamp01(ys[-1])
        # Linear interpolate
        lo = 0
        hi = len(xs) - 1
        while hi - lo > 1:
            mid = (lo + hi) // 2
            if xs[mid] <= s:
                lo = mid
            else:
                hi = mid
        x0, y0 = xs[lo], ys[lo]
        x1, y1 = xs[hi], ys[hi]
        t = 0.0 if x1 == x0 else (s - x0) / (x1 - x0)
        return _clamp01(y0 + t * (y1 - y0))


class ConformalBuffer:
    """
    Split-conformal fallback for risk scores.
    Keep last N nonconformity scores S (e.g., model raw scores on "safe" reference)
    and convert a new score s to a p-value using rank-based method.

    p(s) = (|{i : S_i >= s}| + 1) / (N + 1)

    This is valid (super-uniform) under exchangeability and copes with slow drift.
    """

    def __init__(self, capacity: int = 1024):
        self._cap = max(32, int(capacity))
        self._buf: List[float] = []
        self._lock = threading.RLock()

    def update(self, ref_score: float) -> None:
        with self._lock:
            if len(self._buf) < self._cap:
                self._buf.append(float(ref_score))
            else:
                # Reservoir sampling to keep distributional stability
                j = random.randint(0, len(self._buf))
                if j < self._cap:
                    self._buf[j] = float(ref_score)

    def p_value(self, s: float) -> float:
        with self._lock:
            n = len(self._buf)
            if n == 0:
                # no calibration data; return conservative p from raw
                return 1.0 - _clamp01(float(s))
            ge = 1 + sum(1 for x in self._buf if x >= s)
            return _clamp01(ge / (n + 1))


@dataclass
class CalibratorConfig:
    mode: str = _CALIB_MODE              # "isotonic" | "conformal" | "identity"
    isotonic_knots: Optional[IsotonicKnots] = None
    conformal_window: int = _CONFORMAL_WINDOW
    alpha: float = _CONFORMAL_ALPHA      # informational; not directly used to compute p here
    version: str = "1.1.0"


class _Calibrator:
    def __init__(self, cfg: CalibratorConfig):
        self._cfg = cfg
        self._iso = cfg.isotonic_knots
        self._conf = ConformalBuffer(cfg.conformal_window) if cfg.mode == "conformal" else None

    @property
    def mode(self) -> str:
        return self._cfg.mode

    @property
    def version(self) -> str:
        return self._cfg.version

    def p_value(self, raw_score: float) -> float:
        s = _clamp01(float(raw_score))
        if self._cfg.mode == "identity":
            return 1.0 - s
        if self._cfg.mode == "isotonic":
            if not self._iso:
                # identity fallback if knots missing
                return 1.0 - s
            return _clamp01(float(self._iso.map(s)))
        if self._cfg.mode == "conformal":
            assert self._conf is not None
            return self._conf.p_value(s)
        # default conservative
        return 1.0 - s

    def update_reference(self, ref_score: float) -> None:
        """Optionally feed known-safe reference scores when using conformal mode."""
        if self._conf is not None:
            self._conf.update(_clamp01(float(ref_score)))


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

_MAX_TEXT_BYTES = _MAX_BYTES
_MAX_META_KEYS = 64

class DetectRequest(BaseModel):
    """
    Work unit for the detector. Text is truncated (bytes/tokens) before scoring.
    """
    tenant: str = Field(default="*", max_length=64)
    user: str = Field(default="*", max_length=128)
    session: str = Field(default="*", max_length=128)
    model_id: str = Field(default="*", max_length=128)
    lang: str = Field(default="*", max_length=16)
    kind: str = Field(default="completion", pattern="^(prompt|completion)$")
    text: str = Field(..., min_length=0, max_length=_MAX_TEXT_BYTES)
    meta: Optional[Dict[str, Any]] = Field(default=None)

    @field_validator("meta")
    @classmethod
    def _meta_ok(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if v is None:
            return None
        if len(v) > _MAX_META_KEYS:
            raise ValueError("meta too large")
        return v


class DetectOut(BaseModel):
    ok: bool
    decision: str  # "allow" | "cool" | "block"
    score_raw: float
    p_value: float
    latency_ms: float
    budget_left_ms: float
    thresholds: Dict[str, float]
    calibrator: Dict[str, Any]
    model: Dict[str, str]
    # Bounded evidence (safe to embed into receipts)
    evidence_hash: str
    evidence: Dict[str, Any]


@dataclass
class DetectorConfig:
    # Routing thresholds (interpreted in p-space)
    t_low: float = _THRESH_LOW
    t_high: float = _THRESH_HIGH
    # Processing limits
    time_budget_ms: float = _TIME_BUDGET_MS
    max_tokens: int = _MAX_TOKENS
    max_bytes: int = _MAX_BYTES
    # Calibrator config
    calibrator: CalibratorConfig = dataclasses.field(default_factory=CalibratorConfig)
    # Misc
    name: str = "tcd-detector"
    version: str = "0.3.0"


# ---------------------------------------------------------------------------
# Metrics (optional)
# ---------------------------------------------------------------------------

if _METRICS_ENABLED:  # pragma: no cover
    _DET_LAT = Histogram(
        "tcd_detector_latency_seconds", "Detector end-to-end latency", buckets=(0.001, 0.003, 0.005, 0.010, 0.020)
    )
    _DET_BYTES = Histogram("tcd_detector_text_bytes", "Detector input size (bytes)")
    _DET_TOK = Histogram("tcd_detector_text_tokens", "Detector input size (approx tokens)")
    _DET_DECISIONS = Counter("tcd_detector_decision_total", "Detector decisions", ["decision"])
    _DET_TIMEOUT = Counter("tcd_detector_timeout_total", "Detector timeouts")
else:  # pragma: no cover
    _DET_LAT = _DET_BYTES = _DET_TOK = _DET_DECISIONS = _DET_TIMEOUT = None  # type: ignore


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class Detector:
    """
    End-to-end safety detector:
        DetectRequest → (truncate) → model.score → p-value → decision + evidence
    """

    def __init__(self, model: ScoreModel, cfg: DetectorConfig):
        self._model = model
        self._cfg = cfg
        self._cal = _Calibrator(cfg.calibrator)

    @property
    def config(self) -> DetectorConfig:
        return self._cfg

    def _decide(self, p: float) -> str:
        # Map p to routing bands based on thresholds in probability space.
        # Example: t_low=0.20, t_high=0.80 → cool band = (1 - 0.80, 1 - 0.20]
        hi_edge = 1.0 - _clamp01(self._cfg.t_high)
        lo_edge = 1.0 - _clamp01(self._cfg.t_low)
        if p <= hi_edge:
            return "block"
        if p <= lo_edge:
            return "cool"
        return "allow"

    def detect(self, req: DetectRequest) -> DetectOut:
        t0 = time.perf_counter()
        budget = _TimeBudget(self._cfg.time_budget_ms)

        # Guard + truncate
        text0 = _soft_truncate_bytes(req.text or "", self._cfg.max_bytes)
        text = _truncate_tokens(text0, self._cfg.max_tokens)
        n_bytes = len(text.encode("utf-8", "ignore"))
        n_tokens = _approx_tokens(text)

        if _METRICS_ENABLED:  # pragma: no cover
            _DET_BYTES.observe(n_bytes)
            _DET_TOK.observe(n_tokens)

        # Score
        try:
            raw, model_evidence = self._model.score(text, req.meta, budget=budget)
        except TimeoutError:
            if _METRICS_ENABLED:  # pragma: no cover
                _DET_TIMEOUT.inc()
            raise
        except Exception as e:
            logger.exception("model.score failed: %s", e)
            # Conservative output: treat as risky
            raw = 1.0
            model_evidence = {"error": "model.score failed"}

        raw = _clamp01(float(raw))
        budget.check()

        # Calibrate
        p = self._cal.p_value(raw)
        p = _clamp01(float(p))
        budget.check()

        # Decision
        decision = self._decide(p)

        # Evidence (bounded, no raw text)
        ev: Dict[str, Any] = {
            "tenant": req.tenant,
            "user": req.user,
            "session": req.session,
            "model_id": req.model_id,
            "kind": req.kind,
            "len_bytes": n_bytes,
            "len_tokens": n_tokens,
            "score_raw": raw,
            "p_value": p,
            "calibrator": {
                "mode": self._cal.mode,
                "version": self._cal.version,
                "isotonic_knots_hash": (
                    _hash_canon(self._cfg.calibrator.isotonic_knots.pairs, ctx="tcd:iso_knots")
                    if (self._cfg.calibrator.isotonic_knots and self._cfg.calibrator.mode == "isotonic")
                    else None
                ),
                "conformal_window": self._cfg.calibrator.conformal_window if self._cal.mode == "conformal" else None,
            },
            "model_evidence": model_evidence,
        }
        ev_hash = _hash_canon(ev, ctx="tcd:detector:evidence")

        dt = (time.perf_counter() - t0)
        if _METRICS_ENABLED:  # pragma: no cover
            _DET_LAT.observe(dt)
            _DET_DECISIONS.labels(decision=decision).inc()

        out = DetectOut(
            ok=True,
            decision=decision,
            score_raw=raw,
            p_value=p,
            latency_ms=dt * 1000.0,
            budget_left_ms=budget.remaining_ms(),
            thresholds={"t_low": self._cfg.t_low, "t_high": self._cfg.t_high},
            calibrator={"mode": self._cal.mode, "version": self._cal.version},
            model={"name": getattr(self._model, "name", "?"), "version": getattr(self._model, "version", "?")},
            evidence_hash=ev_hash,
            evidence=ev,
        )
        return out

    # Optional helper for conformal reference updates
    def update_reference(self, ref_score: float) -> None:
        self._cal.update_reference(ref_score)


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def _load_isotonic_knots_from_env() -> Optional[IsotonicKnots]:
    raw = os.getenv("TCD_DETECTOR_CALIB_KNOTS")
    if not raw:
        return None
    try:
        pairs = json.loads(raw)
        pairs = [(float(x), float(y)) for x, y in pairs]
        return IsotonicKnots(pairs=pairs)
    except Exception as e:  # pragma: no cover
        logger.warning("failed to parse TCD_DETECTOR_CALIB_KNOTS: %s", e)
        return None


def build_default_detector() -> Detector:
    cal_cfg = CalibratorConfig(
        mode=_CALIB_MODE,
        isotonic_knots=_load_isotonic_knots_from_env(),
        conformal_window=_CONFORMAL_WINDOW,
        alpha=_CONFORMAL_ALPHA,
        version="1.1.0",
    )
    det_cfg = DetectorConfig(
        t_low=_THRESH_LOW,
        t_high=_THRESH_HIGH,
        time_budget_ms=_TIME_BUDGET_MS,
        max_tokens=_MAX_TOKENS,
        max_bytes=_MAX_BYTES,
        calibrator=cal_cfg,
        name="tcd-detector",
        version="0.3.0",
    )
    model = HeuristicKeywordModel()
    return Detector(model=model, cfg=det_cfg)

# --- Temporary shim for HTTP service ---
class TCDConfig:
    def __init__(self):
        pass

class TraceCollapseDetector:
    def __init__(self, config=None):
        self.config = config

    def diagnose(self, trace_vec, entropy, spectrum, step_id=None):
        # Minimal stub result
        return {"verdict": False, "score": 0.42, "step": 0, "components": {}}

    def snapshot_state(self):
        return {"status": "ok"}

    def load_state(self, state):
        pass