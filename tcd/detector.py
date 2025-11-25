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
- Content-agnostic evidence: no raw text in detector outputs, bounded metadata

Environment knobs:
- TCD_DETECTOR_TIME_BUDGET_MS        (default: 3.0, clamped into [0.5, 50.0])
- TCD_DETECTOR_MAX_TOKENS            (default: 2048, clamped into [64, 8192])
- TCD_DETECTOR_MAX_BYTES             (default: 100_000, clamped into [1024, 2_000_000])
- TCD_DETECTOR_THRESH_LOW            (default: 0.20)
- TCD_DETECTOR_THRESH_HIGH           (default: 0.80)
- TCD_DETECTOR_CALIB_MODE            (default: "isotonic"; options: "isotonic", "conformal", "identity")
- TCD_DETECTOR_CALIB_KNOTS           (JSON: [[score, p], ...] sorted by score) for isotonic mode
- TCD_DETECTOR_CONFORMAL_WINDOW      (default: 1024, clamped into [32, 16384])
- TCD_DETECTOR_CONFORMAL_ALPHA       (default: 0.05, clamped into [0,1])
- TCD_DETECTOR_CONFORMAL_BOOTSTRAP   (default: "identity"; options: "identity", "mid")
- TCD_DETECTOR_RANDOM_SEED           (optional int; per-process seed for deterministic heuristics)

Evidence hardening knobs:
- TCD_DETECTOR_SANITIZE_EVIDENCE     (default: "1")
- TCD_DETECTOR_STRIP_PII             (default: "1")
- TCD_DETECTOR_HASH_PII_TAGS         (default: "1")
- TCD_DETECTOR_PII_MODE              (default: "light"; options: "light", "strict")
- TCD_DETECTOR_MAX_EVIDENCE_KEYS     (default: "64")
- TCD_DETECTOR_MAX_EVIDENCE_STRING   (default: "512")

Notes on decisions:
- We map raw model scores (higher = riskier) to p-values in [0,1] with a monotone calibrator.
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
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple, Mapping, Set

from pydantic import BaseModel, Field, field_validator

from .utils import SanitizeConfig, sanitize_metadata_for_receipt  # type: ignore
from .kv import canonical_kv_hash  # type: ignore

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
# Core helpers for settings
# ---------------------------------------------------------------------------


def _clamp01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


def _bounded_int(env_name: str, default: int, min_v: int, max_v: int) -> int:
    try:
        v = int(os.getenv(env_name, str(default)))
    except Exception:
        return default
    return max(min_v, min(max_v, v))


def _validate_thresholds(low: float, high: float) -> Tuple[float, float]:
    low = _clamp01(low)
    high = _clamp01(high)
    if not (0.0 < low <= high <= 1.0):
        logger.warning(
            "Invalid detector thresholds (low=%s, high=%s); falling back to defaults 0.20/0.80",
            low,
            high,
        )
        low, high = 0.20, 0.80
    # Optionally ensure the cool band has a minimum width.
    if (high - low) < 0.1:
        logger.warning(
            "Detector cool band too narrow (low=%s, high=%s); widening to maintain 0.1 span",
            low,
            high,
        )
        mid = (low + high) / 2.0
        low = max(0.0, mid - 0.05)
        high = min(1.0, mid + 0.05)
    return low, high


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

# Raw env values
_RAW_THRESH_LOW = float(os.getenv("TCD_DETECTOR_THRESH_LOW", "0.20"))
_RAW_THRESH_HIGH = float(os.getenv("TCD_DETECTOR_THRESH_HIGH", "0.80"))

_THRESH_LOW, _THRESH_HIGH = _validate_thresholds(_RAW_THRESH_LOW, _RAW_THRESH_HIGH)

# Time budget in ms; bounded to avoid accidental DoS-level settings.
try:
    _TIME_BUDGET_MS = float(os.getenv("TCD_DETECTOR_TIME_BUDGET_MS", "3.0"))
except Exception:
    _TIME_BUDGET_MS = 3.0
_TIME_BUDGET_MS = max(0.5, min(_TIME_BUDGET_MS, 50.0))

# Input size bounds
_MAX_TOKENS = _bounded_int("TCD_DETECTOR_MAX_TOKENS", 2048, 64, 8192)
_MAX_BYTES = _bounded_int("TCD_DETECTOR_MAX_BYTES", 100000, 1024, 2_000_000)

# Calibration mode/config
_CALIB_MODE = os.getenv("TCD_DETECTOR_CALIB_MODE", "isotonic").strip().lower()
_CONFORMAL_WINDOW = _bounded_int("TCD_DETECTOR_CONFORMAL_WINDOW", 1024, 32, 16384)

try:
    _CONFORMAL_ALPHA_RAW = float(os.getenv("TCD_DETECTOR_CONFORMAL_ALPHA", "0.05"))
except Exception:
    _CONFORMAL_ALPHA_RAW = 0.05
_CONFORMAL_ALPHA = _clamp01(_CONFORMAL_ALPHA_RAW)

_CONFORMAL_BOOTSTRAP_MODE = os.getenv("TCD_DETECTOR_CONFORMAL_BOOTSTRAP", "identity").strip().lower()

_seed = os.getenv("TCD_DETECTOR_RANDOM_SEED")
if _seed is not None:
    try:
        random.seed(int(_seed))
    except Exception:
        pass

# Evidence hardening settings
_DETECTOR_SANITIZE_EVIDENCE = os.getenv("TCD_DETECTOR_SANITIZE_EVIDENCE", "1") == "1"
_DETECTOR_STRIP_PII = os.getenv("TCD_DETECTOR_STRIP_PII", "1") == "1"
_DETECTOR_HASH_PII_TAGS = os.getenv("TCD_DETECTOR_HASH_PII_TAGS", "1") == "1"
_DETECTOR_PII_MODE = os.getenv("TCD_DETECTOR_PII_MODE", "light").strip().lower()
_MAX_EVIDENCE_KEYS = int(os.getenv("TCD_DETECTOR_MAX_EVIDENCE_KEYS", "64"))
_MAX_EVIDENCE_STRING = int(os.getenv("TCD_DETECTOR_MAX_EVIDENCE_STRING", "512"))

# Keys that must not appear in detector evidence (to avoid content leakage)
_FORBIDDEN_EVIDENCE_KEYS: Set[str] = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "messages",
    "content",
    "body",
    "raw",
}

# Tag vocab for trust/route/override/PQ-related fields (aligned with logging/ledger)
_ALLOWED_TRUST_ZONES: Set[str] = {
    "internet",
    "internal",
    "partner",
    "admin",
    "ops",
}

_ALLOWED_ROUTE_PROFILES: Set[str] = {
    "inference",
    "admin",
    "control",
    "metrics",
    "health",
}

_ALLOWED_OVERRIDE_LEVELS: Set[str] = {
    "none",
    "break_glass",
    "maintenance",
}

_ALLOWED_PQ_SCHEMES: Set[str] = {
    "",
    "dilithium2",
    "dilithium3",
    "falcon",
    "sphincs+",
}

# Allowed request kinds
_ALLOWED_KINDS: Set[str] = {"prompt", "completion", "system", "tool"}


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


def _hash_canon(obj: Any, ctx: str) -> str:
    return Blake3Hash().hex(_dumps(obj), ctx=ctx)


def _looks_like_pii(value: str) -> bool:
    """
    Lightweight PII heuristic: only used on tag-like fields such as tenant/user/session.
    """
    v = value.strip()
    if not v:
        return False
    if "@" in v:
        return True
    if " " in v or "\u3000" in v:
        return True
    if len(v) > 96:
        return False
    return False


def _hash_if_pii_tag(key: str, value: Any) -> Any:
    """
    If key is a tag field and value looks like PII (or PII strict mode is active),
    replace it with a stable hash.
    """
    if not _DETECTOR_HASH_PII_TAGS:
        return value
    if not isinstance(value, str):
        return value
    kl = key.lower()
    if kl not in ("tenant", "user", "session", "override_actor"):
        return value
    if _DETECTOR_PII_MODE == "strict" or _looks_like_pii(value):
        try:
            digest = Blake3Hash().hex(value.encode("utf-8"), ctx="tcd:detector:pii")[:16]
            return f"{kl}-h-{digest}"
        except Exception:
            return f"{kl}-h-anon"
    return value


def _normalize_evidence_shape(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Apply structural constraints to evidence:
      - Hash tag-like PII (tenant/user/session/override_actor).
      - Enforce vocab for trust_zone / route_profile / override_level / pq_scheme.
      - Clamp numeric fields like score_raw / p_value / e_value / a_alloc.
      - Coerce override_applied / pq_required / pq_ok to bool.
      - Truncate overly long strings at top level.
      - Limit top-level key count.
    """
    out = dict(evidence)

    # Tag PII hashing
    for fld in ("tenant", "user", "session", "override_actor"):
        if fld in out:
            out[fld] = _hash_if_pii_tag(fld, out[fld])

    # Vocab constraints for routing / PQ tags
    tz = out.get("trust_zone")
    if isinstance(tz, str) and tz not in _ALLOWED_TRUST_ZONES:
        out.pop("trust_zone", None)

    rp = out.get("route_profile")
    if isinstance(rp, str) and rp not in _ALLOWED_ROUTE_PROFILES:
        out.pop("route_profile", None)

    ovl = out.get("override_level")
    if isinstance(ovl, str) and ovl not in _ALLOWED_OVERRIDE_LEVELS:
        out.pop("override_level", None)

    pqs = out.get("pq_scheme")
    if isinstance(pqs, str) and pqs not in _ALLOWED_PQ_SCHEMES:
        out.pop("pq_scheme", None)

    # Numeric clamps for score-like fields
    for fld in ("score_raw", "p_value", "e_value", "a_alloc", "score"):
        if fld not in out:
            continue
        try:
            v_f = float(out[fld])
        except Exception:
            out.pop(fld, None)
            continue
        if not math.isfinite(v_f):
            out.pop(fld, None)
            continue
        if fld == "p_value":
            out[fld] = _clamp01(v_f)
        elif fld == "a_alloc":
            out[fld] = max(0.0, min(1.0, v_f))
        elif fld in ("score_raw", "score", "e_value"):
            if fld == "e_value" and v_f < 0.0:
                out.pop(fld, None)
            else:
                out[fld] = _clamp01(v_f)

    # Boolean normalization for override / PQ flags
    for fld in ("override_applied", "pq_required", "pq_ok"):
        if fld in out:
            out[fld] = bool(out[fld])

    # Top-level string truncation
    for k, v in list(out.items()):
        if isinstance(v, str) and len(v) > _MAX_EVIDENCE_STRING:
            out[k] = v[:_MAX_EVIDENCE_STRING]

    # Top-level key count guard (deterministic subset)
    if len(out) > _MAX_EVIDENCE_KEYS:
        trimmed: Dict[str, Any] = {}
        for k in sorted(out.keys())[:_MAX_EVIDENCE_KEYS]:
            trimmed[k] = out[k]
        out = trimmed

    return out


def _sanitize_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run evidence through a metadata sanitizer and structural normalizer.

    This ensures:
      - Forbidden keys such as "prompt" or "completion" do not appear.
      - NaN/inf and oversized values are pruned.
      - PII can be stripped and/or hashed for tag fields.
      - Trust / PQ / override tags respect the global vocab.
    """
    ev = dict(evidence)

    # Remove obviously forbidden keys upfront
    for k in list(ev.keys()):
        if str(k).lower() in _FORBIDDEN_EVIDENCE_KEYS:
            ev.pop(k, None)

    if not _DETECTOR_SANITIZE_EVIDENCE:
        return _normalize_evidence_shape(ev)

    try:
        cfg = SanitizeConfig(
            sanitize_nan=True,
            prune_large=True,
            strip_pii=_DETECTOR_STRIP_PII,
            forbid_keys=tuple(_FORBIDDEN_EVIDENCE_KEYS),
        )
        sanitized = sanitize_metadata_for_receipt(ev, config=cfg)
        if isinstance(sanitized, Mapping):
            ev = dict(sanitized)
    except Exception:
        # In case of sanitizer failure, fall back to the original evidence.
        pass

    return _normalize_evidence_shape(ev)


def _normalize_model_evidence(model_evidence: Any) -> Dict[str, Any]:
    """
    Normalize model_evidence into a bounded, content-agnostic mapping:
      - Non-mapping evidence is wrapped with a type tag.
      - Key count is bounded.
      - Forbidden keys are removed.
    """
    if not isinstance(model_evidence, Mapping):
        return {"_model_evidence_type": str(type(model_evidence).__name__)}
    ev = dict(model_evidence)
    if len(ev) > 32:
        trimmed: Dict[str, Any] = {}
        for k in sorted(ev.keys())[:32]:
            trimmed[k] = ev[k]
        ev = trimmed
    for k in list(ev.keys()):
        if str(k).lower() in _FORBIDDEN_EVIDENCE_KEYS:
            ev.pop(k, None)
    return ev


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

        Requirements:
          - Deterministic given inputs.
          - Must respect the provided time budget.
          - raw_score should lie in [0,1] if possible; out-of-range values will be clamped.
          - model_evidence must remain content-agnostic; any raw text should be omitted
            or heavily truncated upstream, and will be sanitized again before storage.
        """


class HeuristicKeywordModel:
    """
    Tiny, deterministic heuristic:
    - Normalizes score by simple features and keyword hits.
    - CPU-bounded; no external dependencies; usable as a bootstrap fallback.
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
                # Cold start; configurable bootstrap behavior.
                if _CONFORMAL_BOOTSTRAP_MODE == "mid":
                    return 0.5
                # Default: identity-style mapping in p-space.
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
                # Identity fallback if knots missing.
                return 1.0 - s
            return _clamp01(float(self._iso.map(s)))
        if self._cfg.mode == "conformal":
            assert self._conf is not None
            return self._conf.p_value(s)
        # Default conservative
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
_MAX_ISO_KNOTS = 512


class DetectRequest(BaseModel):
    """
    Work unit for the detector. Text is truncated (bytes/tokens) before scoring.

    Text content itself never leaves the detector; only bounded features and
    content-agnostic evidence are exported.
    """
    tenant: str = Field(default="*", max_length=64)
    user: str = Field(default="*", max_length=128)
    session: str = Field(default="*", max_length=128)
    model_id: str = Field(default="*", max_length=128)
    lang: str = Field(default="*", max_length=16)
    kind: str = Field(default="completion", max_length=16)
    text: str = Field(..., min_length=0, max_length=_MAX_TEXT_BYTES)
    meta: Optional[Dict[str, Any]] = Field(default=None)

    @field_validator("kind")
    @classmethod
    def _kind_ok(cls, v: str) -> str:
        v_norm = (v or "completion").strip().lower()
        if v_norm not in _ALLOWED_KINDS:
            return "completion"
        return v_norm

    @field_validator("meta")
    @classmethod
    def _meta_ok(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if v is None:
            return None
        if len(v) > _MAX_META_KEYS:
            raise ValueError("meta too large")
        # Prevent content keys from being smuggled through meta.
        for k in v.keys():
            if str(k).lower() in _FORBIDDEN_EVIDENCE_KEYS:
                raise ValueError(f"meta contains forbidden key: {k!r}")
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

    This component is strictly content-agnostic at its boundary:
      - The text itself never appears in DetectOut.
      - Evidence is sanitized to remove forbidden keys and PII-like tags.
      - All numeric fields are clamped to safe ranges.
    """

    def __init__(self, model: ScoreModel, cfg: DetectorConfig):
        self._model = model
        self._cfg = cfg
        self._cal = _Calibrator(cfg.calibrator)

        # Log configuration and a stable configuration hash for later audits.
        cfg_payload = {
            "t_low": self._cfg.t_low,
            "t_high": self._cfg.t_high,
            "mode": self._cfg.calibrator.mode,
            "cal_version": self._cfg.calibrator.version,
            "conformal_window": self._cfg.calibrator.conformal_window,
        }
        cfg_hash = canonical_kv_hash(
            cfg_payload,
            ctx="tcd:detector",
            label="detector_cfg",
        )
        logger.info(
            "Detector initialized: t_low=%s, t_high=%s, mode=%s, cal_version=%s, cfg_hash=%s",
            self._cfg.t_low,
            self._cfg.t_high,
            self._cal.mode,
            self._cal.version,
            cfg_hash,
        )

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
            model_evidence = _normalize_model_evidence(model_evidence)
        except TimeoutError:
            if _METRICS_ENABLED:  # pragma: no cover
                _DET_TIMEOUT.inc()
            logger.warning(
                "Detector time budget exceeded for tenant=%s, model_id=%s",
                req.tenant,
                req.model_id,
            )
            # Surface timeout to caller; calling layer decides routing (typically block).
            raise
        except Exception as e:
            logger.exception("model.score failed: %s", e)
            # Conservative output: treat as risky and annotate error.
            raw = 1.0
            model_evidence = _normalize_model_evidence(
                {"error": "model.score failed", "exc_type": type(e).__name__}
            )

        raw = _clamp01(float(raw))
        budget.check()

        # Calibrate
        p = self._cal.p_value(raw)
        p = _clamp01(float(p))
        budget.check()

        # Decision
        decision = self._decide(p)

        # Evidence (bounded, no raw text). Only tags and structured metrics.
        base_ev: Dict[str, Any] = {
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

        evidence = _sanitize_evidence(base_ev)
        ev_hash = _hash_canon(evidence, ctx="tcd:detector:evidence")

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
            evidence=evidence,
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
        if not isinstance(pairs, list):
            raise ValueError("knots must be a list")
        if len(pairs) > _MAX_ISO_KNOTS:
            raise ValueError(f"too many isotonic knots: {len(pairs)}")
        processed: List[Tuple[float, float]] = []
        for item in pairs:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                raise ValueError("each knot must be a [score, p] pair")
            x, y = item
            xf = float(x)
            yf = float(y)
            if not (math.isfinite(xf) and math.isfinite(yf)):
                raise ValueError("non-finite knot")
            processed.append((xf, yf))
        iso = IsotonicKnots(pairs=processed)
        ys = [p[1] for p in iso.pairs]
        for i in range(1, len(ys)):
            if ys[i] > ys[i - 1] + 1e-6:
                logger.warning("isotonic knots not monotone in p; continuing with provided order")
                break
        return iso
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
    """
    TEMPORARY NON-PRODUCTION SHIM.

    This exists only to keep compatibility with older HTTP code paths.
    It must not be used for safety decisions or receipts in production.
    """

    def __init__(self, config=None):
        self.config = config

    def diagnose(self, trace_vec, entropy, spectrum, step_id=None):
        # Minimal stub result
        return {"verdict": False, "score": 0.42, "step": 0, "components": {}}

    def snapshot_state(self):
        return {"status": "ok"}

    def load_state(self, state):
        pass