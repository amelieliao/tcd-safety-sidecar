# FILE: tcd/detector.py
from __future__ import annotations

"""
Low-latency, pluggable safety detector with monotone calibration and conformal fallback.

This module is designed for production routing and receipts. Key guarantees:

L6/L7 hardening guarantees
- Deterministic behavior for a fixed (config_digest, calibrator_state_digest, request)
- End-to-end time budget enforced across: truncate, model.score, calibration, evidence sanitize, hash
- Never throws from Detector.detect(); fail-closed on error/timeout (decision="block")
- Evidence is content-agnostic: never includes raw text; forbidden keys stripped at any depth
- Evidence sanitization is bounded (max nodes/depth/keys/items) and DoS-resistant (scan caps)
- No module-level mutable policy (no cross-instance or cross-thread policy bleed)
- Stable digests:
    - config_hash: static config only
    - policy_digest: static semantics (incl. iso knots hash, evidence policy, forbiddens)
    - state_digest: dynamic calibrator state (conformal window summary), changes as state updates
    - evidence_hash: keyed HMAC when configured; domain-separated by (engine_version, config_hash)
    - decision_id: derived from (engine_version, config_hash, state_digest, evidence_hash, decision, error_code)

Environment knobs (safe-parsed, bounded)
- TCD_DETECTOR_TIME_BUDGET_MS            default: 3.0  clamp [0.5, 50.0]
- TCD_DETECTOR_MAX_TOKENS                default: 2048 clamp [64, 8192]
- TCD_DETECTOR_MAX_BYTES                 default: 100_000 clamp [1024, 2_000_000]

Routing thresholds (risk-space, where risk = 1 - p_value; higher = riskier)
- TCD_DETECTOR_THRESH_LOW                default: 0.20 clamp [0,1]
- TCD_DETECTOR_THRESH_HIGH               default: 0.80 clamp [0,1]
Decision:
    if risk >= thresh_high => block
    elif risk >= thresh_low => throttle
    else => allow

Legacy compatibility:
    decision_legacy uses "cool" instead of "throttle".

Calibration config
- TCD_DETECTOR_CALIB_MODE                default: "isotonic" ("isotonic"|"conformal"|"identity")
- TCD_DETECTOR_CALIB_KNOTS               JSON [[score,p], ...] for isotonic mode (bounded)
- TCD_DETECTOR_CONFORMAL_WINDOW          default: 1024 clamp [32,16384]
- TCD_DETECTOR_CONFORMAL_ALPHA           default: 0.05 clamp [0,1] informational
- TCD_DETECTOR_CONFORMAL_BOOTSTRAP       default: "identity" ("identity"|"mid")

Conformal update guard knobs (poisoning resistance)
- TCD_DETECTOR_CONFORMAL_REF_MAX         default: 0.50 clamp [0,1] (winsorize cap)
- TCD_DETECTOR_CONFORMAL_MIN_P_UPDATE    default: 0.80 clamp [0,1] (minimum p to accept auto-updates)
- TCD_DETECTOR_CONFORMAL_ALLOWED_SOURCES default: "golden_safe,canary" (comma separated)

Evidence / PII / hashing knobs
- TCD_DETECTOR_SANITIZE_EVIDENCE         default: "1"
- TCD_DETECTOR_STRIP_PII                 default: "1"
- TCD_DETECTOR_HASH_PII_TAGS             default: "1"
- TCD_DETECTOR_PII_MODE                  default: "light" ("light"|"strict")
- TCD_DETECTOR_ALLOW_RAW_TENANT          default: "0" (dev-only; production should stay 0)
- TCD_DETECTOR_MAX_EVIDENCE_KEYS         default: 64 clamp [16,256]
- TCD_DETECTOR_MAX_EVIDENCE_STRING       default: 512 clamp [128,2048]

PII hashing keys (optional but recommended)
- TCD_DETECTOR_PII_HMAC_KEY_HEX          optional hex key for HMAC-SHA256
- TCD_DETECTOR_PII_HMAC_KEY_ID           optional key id (e.g., "k2026q1") recorded in receipts

Evidence hashing keys (optional; helps unlinkability across envs/tenants)
- TCD_DETECTOR_EVIDENCE_HMAC_KEY_HEX     optional hex key for HMAC-SHA256
- TCD_DETECTOR_EVIDENCE_HMAC_KEY_ID      optional key id recorded in receipts

Notes
- We map raw scores (higher = riskier) to p-values in [0,1] with a monotone calibrator.
- Small p => "unlikely under safe behavior" => more risky.
- Routing is performed in calibrated risk space: risk = 1 - p_value.
"""

import dataclasses
import json
import logging
import math
import os
import re
import threading
import time
from collections import deque
from bisect import bisect_left, insort
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Protocol, Set, Tuple, Literal

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
    # Legacy shims
    "TCDConfig",
    "TraceCollapseDetector",
]

# ---------------------------------------------------------------------------
# Optional dependencies (pydantic, repo sanitizer, repo canonical hash)
# ---------------------------------------------------------------------------

_PYDANTIC_OK = True
try:  # pragma: no cover
    from pydantic import BaseModel, Field, field_validator
except Exception:  # pragma: no cover
    _PYDANTIC_OK = False
    BaseModel = object  # type: ignore
    Field = lambda *args, **kwargs: None  # type: ignore

    def field_validator(*args, **kwargs):  # type: ignore
        def _wrap(fn):
            return fn
        return _wrap

# Prefer repo canonical hash. If missing, we fall back to strict internal canonical JSON hashing.
try:
    from .kv import canonical_kv_hash  # type: ignore
except Exception:  # pragma: no cover
    canonical_kv_hash = None  # type: ignore[assignment]

# Optional receipt sanitizer (defense-in-depth; we still sanitize ourselves)
try:
    from .utils import SanitizeConfig, sanitize_metadata_for_receipt  # type: ignore
except Exception:  # pragma: no cover
    SanitizeConfig = None  # type: ignore
    sanitize_metadata_for_receipt = None  # type: ignore

# Optional Prometheus (keep labels low-cardinality)
try:  # pragma: no cover
    from prometheus_client import Counter, Histogram
    _METRICS_ENABLED = True
except Exception:  # pragma: no cover
    Counter = Histogram = None  # type: ignore
    _METRICS_ENABLED = False

# ---------------------------------------------------------------------------
# Engine versioning
# ---------------------------------------------------------------------------

_DETECTOR_ENGINE_VERSION = "detector_v3"
_SUPPORTED_ENGINE_VERSIONS: Set[str] = {_DETECTOR_ENGINE_VERSION}

# ---------------------------------------------------------------------------
# Safe env parsing
# ---------------------------------------------------------------------------

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    s = str(v).strip().lower()
    if s in ("1", "true", "t", "yes", "y", "on"):
        return True
    if s in ("0", "false", "f", "no", "n", "off"):
        return False
    return default


def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        # treat bool as invalid to avoid YAML/JSON footguns (true -> 1)
        if isinstance(raw, bool):  # pragma: no cover
            return default
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
        # treat bool as invalid (float(True) == 1.0)
        if isinstance(raw, bool):  # pragma: no cover
            return default
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


def _clamp01(x: float) -> float:
    if not math.isfinite(x):
        return 0.0
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else x


# ---------------------------------------------------------------------------
# Global defaults (read-once, never mutated at runtime)
# ---------------------------------------------------------------------------

_THRESH_LOW_DEFAULT = _env_float("TCD_DETECTOR_THRESH_LOW", 0.20, min_v=0.0, max_v=1.0)
_THRESH_HIGH_DEFAULT = _env_float("TCD_DETECTOR_THRESH_HIGH", 0.80, min_v=0.0, max_v=1.0)

_TIME_BUDGET_MS_DEFAULT = _env_float("TCD_DETECTOR_TIME_BUDGET_MS", 3.0, min_v=0.5, max_v=50.0)
_MAX_TOKENS_DEFAULT = _env_int("TCD_DETECTOR_MAX_TOKENS", 2048, min_v=64, max_v=8192)
_MAX_BYTES_DEFAULT = _env_int("TCD_DETECTOR_MAX_BYTES", 100_000, min_v=1024, max_v=2_000_000)

_CALIB_MODE_DEFAULT = str(os.getenv("TCD_DETECTOR_CALIB_MODE", "isotonic")).strip().lower()
if _CALIB_MODE_DEFAULT not in ("isotonic", "conformal", "identity"):
    _CALIB_MODE_DEFAULT = "isotonic"

_CONFORMAL_WINDOW_DEFAULT = _env_int("TCD_DETECTOR_CONFORMAL_WINDOW", 1024, min_v=32, max_v=16384)
_CONFORMAL_ALPHA_DEFAULT = _env_float("TCD_DETECTOR_CONFORMAL_ALPHA", 0.05, min_v=0.0, max_v=1.0)
_CONFORMAL_BOOTSTRAP_DEFAULT = str(os.getenv("TCD_DETECTOR_CONFORMAL_BOOTSTRAP", "identity")).strip().lower()
if _CONFORMAL_BOOTSTRAP_DEFAULT not in ("identity", "mid"):
    _CONFORMAL_BOOTSTRAP_DEFAULT = "identity"

# Conformal poisoning guards
_CONFORMAL_REF_MAX_DEFAULT = _env_float("TCD_DETECTOR_CONFORMAL_REF_MAX", 0.50, min_v=0.0, max_v=1.0)
_CONFORMAL_MIN_P_UPDATE_DEFAULT = _env_float("TCD_DETECTOR_CONFORMAL_MIN_P_UPDATE", 0.80, min_v=0.0, max_v=1.0)
_ALLOWED_SOURCES_DEFAULT = str(os.getenv("TCD_DETECTOR_CONFORMAL_ALLOWED_SOURCES", "golden_safe,canary"))
_ALLOWED_SOURCES_SET_DEFAULT: Set[str] = {s.strip() for s in _ALLOWED_SOURCES_DEFAULT.split(",") if s.strip()}
if not _ALLOWED_SOURCES_SET_DEFAULT:
    _ALLOWED_SOURCES_SET_DEFAULT = {"golden_safe"}

# Evidence policy defaults
_SANITIZE_EVIDENCE_DEFAULT = _env_bool("TCD_DETECTOR_SANITIZE_EVIDENCE", True)
_STRIP_PII_DEFAULT = _env_bool("TCD_DETECTOR_STRIP_PII", True)
_HASH_PII_TAGS_DEFAULT = _env_bool("TCD_DETECTOR_HASH_PII_TAGS", True)
_PII_MODE_DEFAULT = str(os.getenv("TCD_DETECTOR_PII_MODE", "light")).strip().lower()
if _PII_MODE_DEFAULT not in ("light", "strict"):
    _PII_MODE_DEFAULT = "light"

_ALLOW_RAW_TENANT_DEFAULT = _env_bool("TCD_DETECTOR_ALLOW_RAW_TENANT", False)

_MAX_EVIDENCE_KEYS_DEFAULT = _env_int("TCD_DETECTOR_MAX_EVIDENCE_KEYS", 64, min_v=16, max_v=256)
_MAX_EVIDENCE_STRING_DEFAULT = _env_int("TCD_DETECTOR_MAX_EVIDENCE_STRING", 512, min_v=128, max_v=2048)

# PII hash key + id
_PII_HMAC_KEY_HEX = os.getenv("TCD_DETECTOR_PII_HMAC_KEY_HEX")
_PII_HMAC_KEY_ID = (os.getenv("TCD_DETECTOR_PII_HMAC_KEY_ID") or "").strip()[:32]
# Evidence hash key + id
_EVIDENCE_HMAC_KEY_HEX = os.getenv("TCD_DETECTOR_EVIDENCE_HMAC_KEY_HEX")
_EVIDENCE_HMAC_KEY_ID = (os.getenv("TCD_DETECTOR_EVIDENCE_HMAC_KEY_ID") or "").strip()[:32]


def _parse_hex_key(hex_str: Optional[str], *, min_bytes: int = 16) -> Optional[bytes]:
    if not hex_str:
        return None
    hx = hex_str.strip()
    # Require even length, and at least min_bytes*2 hex chars.
    if len(hx) < min_bytes * 2 or (len(hx) % 2 != 0):
        return None
    try:
        b = bytes.fromhex(hx)
    except Exception:
        return None
    return b if len(b) >= min_bytes else None


_PII_HMAC_KEY = _parse_hex_key(_PII_HMAC_KEY_HEX, min_bytes=16)
_EVIDENCE_HMAC_KEY = _parse_hex_key(_EVIDENCE_HMAC_KEY_HEX, min_bytes=16)


# ---------------------------------------------------------------------------
# Threshold validation (risk-space)
# ---------------------------------------------------------------------------

def _validate_risk_thresholds(low: float, high: float) -> Tuple[float, float]:
    """
    Risk thresholds are in [0,1], and represent calibrated risk = 1 - p_value.
    We DO NOT auto-widen or swap semantics; we only clamp and enforce low <= high
    by clamping low downwards (conservative w.r.t. throttling band).
    """
    low_c = _clamp01(float(low))
    high_c = _clamp01(float(high))
    if low_c > high_c:
        logger.warning("Detector thresholds invalid (low=%s > high=%s); clamping low=high", low_c, high_c)
        low_c = high_c
    return low_c, high_c


# ---------------------------------------------------------------------------
# Time budget helper
# ---------------------------------------------------------------------------

class _TimeBudget:
    __slots__ = ("deadline",)

    def __init__(self, ms: float):
        self.deadline = time.perf_counter() + max(0.0005, float(ms) / 1000.0)

    def check(self, *, where: str = "") -> None:
        if time.perf_counter() > self.deadline:
            raise TimeoutError(f"detector time budget exceeded{': ' + where if where else ''}")

    def remaining_ms(self) -> float:
        return max(0.0, (self.deadline - time.perf_counter()) * 1000.0)


# ---------------------------------------------------------------------------
# Canonical hashing
# ---------------------------------------------------------------------------

def _canon_for_hash(obj: Any) -> Any:
    """
    Canonicalize to a JSON-serializable structure for hashing (not for output).
    Rules:
      - dict keys become strings
      - floats become scaled integers to avoid repr drift (1e6 precision)
      - NaN/Inf -> None
      - unknown objects -> type tag (never repr)
    """
    if obj is None or isinstance(obj, (bool, int, str)):
        return obj
    if isinstance(obj, float):
        if not math.isfinite(obj):
            return None
        return int(round(obj * 1_000_000))
    if isinstance(obj, Mapping):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            out[str(k)] = _canon_for_hash(v)
        return out
    if isinstance(obj, (list, tuple)):
        return [_canon_for_hash(x) for x in obj]
    if isinstance(obj, (set, frozenset)):
        arr = [_canon_for_hash(x) for x in obj]
        # stable ordering by JSON string of the canonicalized element
        arr.sort(key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
        return arr
    return f"<{type(obj).__name__}>"


def _canonical_hash(payload: Dict[str, Any], *, ctx: str, label: str) -> str:
    """
    Repo canonical hash is preferred. Fallback is internal canonical JSON + SHA256.
    """
    if canonical_kv_hash is not None:
        return str(canonical_kv_hash(payload, ctx=ctx, label=label))
    # Internal stable fallback (no repr()):
    raw = json.dumps(
        _canon_for_hash(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8", errors="replace")
    import hashlib
    return hashlib.sha256((ctx + "|" + label + "|").encode("utf-8") + raw).hexdigest()


def _hmac_sha256(data: bytes, key: bytes) -> bytes:
    import hmac
    import hashlib
    return hmac.new(key, data, hashlib.sha256).digest()


def _hash_bytes(data: bytes, *, domain: str, out_bytes: int = 32, key: Optional[bytes] = None) -> str:
    """
    Domain-separated digest:
      - if key is provided: HMAC-SHA256
      - else: SHA256

    Returns hex; out_bytes may be 16 or 32.
    """
    if out_bytes not in (16, 32):
        out_bytes = 32
    prefix = f"TCD|{_DETECTOR_ENGINE_VERSION}|{domain}|".encode("utf-8")
    blob = prefix + data
    import hashlib
    if key:
        d = _hmac_sha256(blob, key)
    else:
        d = hashlib.sha256(blob).digest()
    return d[:out_bytes].hex()


# ---------------------------------------------------------------------------
# Evidence policy + forbidden-key governance
# ---------------------------------------------------------------------------

# Exact forbidden keys (case-insensitive)
_FORBIDDEN_EVIDENCE_KEYS: Set[str] = {
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

# Substring/pattern forbids. Applied after key normalization.
# Keep this list short and stable (low false positives).
_FORBIDDEN_KEY_SUBSTRINGS: Tuple[str, ...] = (
    # content carriers
    "prompt",
    "message",
    "content",
    "body",
    "raw",
    "header",
    "cookie",
    # secrets
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "authorization",
    "bearer",
    "jwt",
    "privatekey",
    "sshkey",
)

_ALLOWED_TRUST_ZONES: Set[str] = {"internet", "internal", "partner", "admin", "ops"}
_ALLOWED_ROUTE_PROFILES: Set[str] = {"inference", "admin", "control", "metrics", "health"}
_ALLOWED_OVERRIDE_LEVELS: Set[str] = {"none", "break_glass", "maintenance"}
_ALLOWED_PQ_SCHEMES: Set[str] = {"", "dilithium2", "dilithium3", "falcon", "sphincs+", "sphincsplus"}
_ALLOWED_KINDS: Set[str] = {"prompt", "completion", "system", "tool"}

_CTRL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")

def _safe_text(x: Any, *, max_len: int) -> str:
    s = "" if x is None else str(x)
    s = _CTRL_RE.sub("", s).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    if len(s) > max_len:
        s = s[:max_len]
    return s


def _safe_key_str(k: Any, *, max_len: int = 64) -> str:
    """
    Key sanitizer that avoids calling repr() and reduces side-effects.
    For non-primitive keys, use type tag.
    """
    if k is None:
        return ""
    if isinstance(k, (str, int, bool)):
        return _safe_text(k, max_len=max_len)
    if isinstance(k, float):
        if not math.isfinite(k):
            return ""
        return _safe_text(f"{k:.6f}", max_len=max_len)
    # Avoid __str__ surprises for arbitrary objects; use type name only.
    return f"<{type(k).__name__}>"[:max_len]


def _normalize_key_for_match(k: str) -> str:
    # lower, strip control, remove non-alnum to collapse "api_key" -> "apikey"
    s = _safe_text(k, max_len=128).lower()
    s = _NON_ALNUM_RE.sub("", s)
    return s


def _is_forbidden_key(k: str) -> bool:
    """
    True if key is forbidden by exact match or substring match (after normalization).
    """
    if not k:
        return True
    kl = k.lower()
    if kl in _FORBIDDEN_EVIDENCE_KEYS:
        return True
    norm = _normalize_key_for_match(k)
    for sub in _FORBIDDEN_KEY_SUBSTRINGS:
        if sub in norm:
            return True
    return False


@dataclass(frozen=True, slots=True)
class EvidencePolicy:
    sanitize_evidence: bool
    strip_pii: bool
    hash_pii_tags: bool
    pii_mode: Literal["light", "strict"]
    allow_raw_tenant: bool

    max_evidence_keys: int
    max_evidence_string: int

    # recursive bounds
    max_depth: int = 4
    max_keys_per_dict: int = 64
    max_list_items: int = 64
    max_total_nodes: int = 512
    max_scan_per_dict: int = 256  # scan cap to avoid DoS when input has huge mappings/sets

    # hashing keys (optional)
    pii_hmac_key: Optional[bytes] = None
    pii_hmac_key_id: str = ""
    evidence_hmac_key: Optional[bytes] = None
    evidence_hmac_key_id: str = ""

    def normalized(self) -> "EvidencePolicy":
        mk = max(16, min(256, int(self.max_evidence_keys)))
        ms = max(128, min(2048, int(self.max_evidence_string)))
        md = max(1, min(8, int(self.max_depth)))
        mkk = max(8, min(256, int(self.max_keys_per_dict)))
        mli = max(8, min(256, int(self.max_list_items)))
        mtn = max(64, min(4096, int(self.max_total_nodes)))
        mscan = max(mkk, min(2048, int(self.max_scan_per_dict)))
        return EvidencePolicy(
            sanitize_evidence=bool(self.sanitize_evidence),
            strip_pii=bool(self.strip_pii),
            hash_pii_tags=bool(self.hash_pii_tags),
            pii_mode="strict" if self.pii_mode == "strict" else "light",
            allow_raw_tenant=bool(self.allow_raw_tenant),
            max_evidence_keys=mk,
            max_evidence_string=ms,
            max_depth=md,
            max_keys_per_dict=mkk,
            max_list_items=mli,
            max_total_nodes=mtn,
            max_scan_per_dict=mscan,
            pii_hmac_key=self.pii_hmac_key,
            pii_hmac_key_id=_safe_text(self.pii_hmac_key_id, max_len=32),
            evidence_hmac_key=self.evidence_hmac_key,
            evidence_hmac_key_id=_safe_text(self.evidence_hmac_key_id, max_len=32),
        )


# ---------------------------------------------------------------------------
# Tokenization / truncation (budget-aware)
# ---------------------------------------------------------------------------

_TOK_RE = re.compile(r"\w+|[^\s\w]", re.UNICODE)

_HARD_MAX_TEXT_CHARS = 2_000_000  # independent of env, to prevent runaway memory

def _count_tokens_budgeted(s: str, *, stop_at: int, budget: _TimeBudget, where: str) -> int:
    n = 0
    # Check budget periodically; avoid per-iteration overhead.
    for i, _m in enumerate(_TOK_RE.finditer(s)):
        n += 1
        if n >= stop_at:
            break
        if (i & 0xFF) == 0xFF:
            budget.check(where=where)
    return n


def _truncate_to_tokens_budgeted(s: str, *, max_tokens: int, budget: _TimeBudget) -> Tuple[str, int, bool]:
    """
    Truncate string to at most max_tokens using token regex boundaries.
    Returns (text, token_est, truncated)
    """
    if max_tokens <= 0:
        return "", 0, True
    if not s:
        return "", 0, False

    n = 0
    last_end = 0
    for i, m in enumerate(_TOK_RE.finditer(s)):
        n += 1
        last_end = m.end()
        if n >= max_tokens:
            break
        if (i & 0xFF) == 0xFF:
            budget.check(where="truncate:tokens")

    if n < max_tokens:
        return s, n, False
    return s[:last_end], n, True


def _truncate_text_budgeted(
    text_in: str,
    *,
    max_bytes: int,
    max_tokens: int,
    budget: _TimeBudget,
) -> Tuple[str, int, int, Dict[str, bool]]:
    """
    Budget-aware text truncation:
      1) hard char cap (prevents giant inputs even before encode)
      2) derived byte cap from token cap to bound regex/scan CPU
      3) encode+slice to byte cap (no full encode of unbounded text)
      4) token boundary truncation

    Returns: (text, n_bytes, n_tokens_est, flags)
    """
    budget.check(where="truncate:start")
    flags: Dict[str, bool] = {"truncated_chars": False, "truncated_bytes": False, "truncated_tokens": False}

    s = text_in or ""
    if len(s) > _HARD_MAX_TEXT_CHARS:
        s = s[:_HARD_MAX_TEXT_CHARS]
        flags["truncated_chars"] = True
    budget.check(where="truncate:char_cap")

    # Derived byte cap: upper envelope to stop DoS with huge max_bytes but small max_tokens.
    derived_bytes = max(1024, min(int(max_bytes), int(max_tokens) * 8))
    cap_bytes = min(int(max_bytes), derived_bytes)

    # Pre-trim by chars to keep encode bounded. Worst-case UTF-8 is 4 bytes/char.
    # Using 2x cap_bytes is conservative and keeps encode work bounded while retaining enough chars.
    pre_chars = min(len(s), cap_bytes * 2)
    if pre_chars < len(s):
        s = s[:pre_chars]
        flags["truncated_chars"] = True
    budget.check(where="truncate:pre_chars")

    # Encode (bounded) then slice.
    b = s.encode("utf-8", "ignore")
    budget.check(where="truncate:encode")
    if len(b) > cap_bytes:
        b = b[:cap_bytes]
        s = b.decode("utf-8", "ignore")
        flags["truncated_bytes"] = True

    budget.check(where="truncate:bytes")

    # Token truncation
    s2, tok_est, tok_trunc = _truncate_to_tokens_budgeted(s, max_tokens=int(max_tokens), budget=budget)
    if tok_trunc:
        flags["truncated_tokens"] = True
    s = s2

    n_bytes = len(s.encode("utf-8", "ignore"))
    n_tokens = max(0, int(tok_est))
    budget.check(where="truncate:done")
    return s, n_bytes, n_tokens, flags


# ---------------------------------------------------------------------------
# Evidence sanitization (budget-aware, bounded, DoS-resistant)
# ---------------------------------------------------------------------------

def _sanitize_str_value(s: str, policy: EvidencePolicy) -> str:
    return _safe_text(s, max_len=policy.max_evidence_string)


def _deep_sanitize(
    value: Any,
    *,
    policy: EvidencePolicy,
    budget: _TimeBudget,
    depth: int,
    nodes: List[int],
) -> Any:
    """
    Recursive sanitizer:
      - bounded depth and total nodes
      - dict: scan cap + deterministic subset + forbidden-key stripping (any depth)
      - list/tuple: prefix only (no full copy), bounded items
      - set/frozenset: bounded scan + stable sort of sanitized items
      - unknown types: type tag only (never repr)
    """
    nodes[0] += 1
    if nodes[0] > policy.max_total_nodes:
        return "<budget>"
    if depth > policy.max_depth:
        return "<depth>"

    # periodic budget check (cheap)
    if (nodes[0] & 0x3F) == 0x3F:
        budget.check(where="sanitize")

    if value is None or isinstance(value, (bool, int)):
        return value

    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return float(value)

    if isinstance(value, str):
        return _sanitize_str_value(value, policy)

    if isinstance(value, Mapping):
        # Scan at most max_scan_per_dict items to avoid DoS on huge dicts.
        selected: Dict[str, Tuple[str, int, Any]] = {}
        scanned = 0
        for idx, (rk, rv) in enumerate(value.items()):
            scanned += 1
            if scanned > policy.max_scan_per_dict:
                break

            sk = _safe_key_str(rk, max_len=64)
            if not sk or _is_forbidden_key(sk):
                continue

            # Tie breaker: stable string for raw key + insertion index to make deterministic
            tie = _safe_key_str(rk, max_len=64) + f"#{idx:06d}"
            sv = _deep_sanitize(rv, policy=policy, budget=budget, depth=depth + 1, nodes=nodes)

            # Resolve collisions deterministically: keep lexicographically smallest tie
            prev = selected.get(sk)
            if prev is None or tie < prev[0]:
                selected[sk] = (tie, idx, sv)

            if len(selected) >= policy.max_keys_per_dict and scanned >= policy.max_keys_per_dict:
                # we already have enough keys and have scanned at least max_keys_per_dict,
                # allow early exit for predictable CPU.
                pass

        # Deterministic ordering: by sanitized key
        out: Dict[str, Any] = {}
        for k in sorted(selected.keys())[: policy.max_keys_per_dict]:
            out[k] = selected[k][2]
        return out

    if isinstance(value, (list, tuple)):
        out_list: List[Any] = []
        # Avoid list(value) (could copy huge); slice for list/tuple is OK (bounded).
        seq = value[: policy.max_list_items]  # type: ignore[index]
        for item in seq:
            out_list.append(_deep_sanitize(item, policy=policy, budget=budget, depth=depth + 1, nodes=nodes))
        return out_list

    if isinstance(value, (set, frozenset)):
        # bounded scan + stable sort
        items: List[str] = []
        scanned = 0
        for x in value:
            scanned += 1
            if scanned > policy.max_scan_per_dict:
                break
            items.append(_safe_text(x, max_len=64))
            if (scanned & 0x3F) == 0x3F:
                budget.check(where="sanitize:set")
        items.sort()
        return items[: policy.max_list_items]

    # bytes: tag only (avoid content)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return f"<{type(value).__name__}:{len(value)}B>"

    return f"<{type(value).__name__}>"


def _apply_repo_sanitizer(ev: Dict[str, Any], policy: EvidencePolicy) -> Dict[str, Any]:
    """
    Optional sanitizer from repo (defense-in-depth). Never trusted alone.
    """
    if not policy.sanitize_evidence:
        return ev
    if sanitize_metadata_for_receipt is None or SanitizeConfig is None:
        return ev
    try:
        cfg = SanitizeConfig(
            sanitize_nan=True,
            prune_large=True,
            strip_pii=policy.strip_pii,
            forbid_keys=tuple(_FORBIDDEN_EVIDENCE_KEYS),
        )
        sanitized = sanitize_metadata_for_receipt(ev, config=cfg)
        if isinstance(sanitized, Mapping):
            return dict(sanitized)
        return ev
    except Exception:
        return ev


def _sanitize_evidence(evidence: Dict[str, Any], *, policy: EvidencePolicy, budget: _TimeBudget) -> Dict[str, Any]:
    """
    Sanitizes evidence with a *pure* policy (no module globals, no mutation).
    """
    # Pass 1: deep sanitize
    nodes = [0]
    ev1_any = _deep_sanitize(evidence, policy=policy, budget=budget, depth=0, nodes=nodes)
    ev1 = dict(ev1_any) if isinstance(ev1_any, Mapping) else {"_evidence_type": f"<{type(ev1_any).__name__}>"}

    # Pass 2: optional repo sanitizer
    budget.check(where="evidence:repo_sanitizer")
    ev2 = _apply_repo_sanitizer(ev1, policy)

    # Pass 3: deep sanitize again to enforce bounds post-sanitizer
    nodes2 = [0]
    ev3_any = _deep_sanitize(ev2, policy=policy, budget=budget, depth=0, nodes=nodes2)
    ev3 = dict(ev3_any) if isinstance(ev3_any, Mapping) else {"_evidence_type": f"<{type(ev3_any).__name__}>"}

    # Pass 4: enforce vocab + field-specific normalization
    out: Dict[str, Any] = dict(ev3)

    # Strip any forbidden keys that slipped in
    for k in list(out.keys()):
        if _is_forbidden_key(str(k)):
            out.pop(k, None)

    # PII/tag handling (tenant/user/session/override_actor)
    def _pii_hash_note() -> Dict[str, Any]:
        return {
            "pii_hmac": bool(policy.pii_hmac_key is not None),
            "pii_hmac_key_id": policy.pii_hmac_key_id or None,
        }

    out.setdefault("_pii", _pii_hash_note())

    for fld in ("tenant", "user", "session", "override_actor"):
        if fld not in out:
            continue
        v = out.get(fld)
        if not isinstance(v, str):
            out.pop(fld, None)
            continue
        vv = v.strip()
        if not vv:
            out[fld] = "*"
            continue

        if policy.strip_pii and fld in ("user", "session", "override_actor"):
            out.pop(fld, None)
            continue

        if fld == "tenant" and policy.allow_raw_tenant:
            out[fld] = _safe_text(vv, max_len=64)
            continue

        if policy.hash_pii_tags:
            if vv in ("*", "unknown", "anon"):
                out[fld] = vv
            else:
                # HMAC if key exists, else SHA256; keep compact 128-bit
                domain = f"pii:{fld}"
                if policy.pii_hmac_key is not None:
                    digest = _hash_bytes(vv.encode("utf-8", "replace"), domain=domain, out_bytes=16, key=policy.pii_hmac_key)
                else:
                    digest = _hash_bytes(vv.encode("utf-8", "replace"), domain=domain, out_bytes=16, key=None)
                out[fld] = f"{fld}-h-{digest}"
        else:
            out[fld] = _safe_text(vv, max_len=64)

    # Vocab constraints
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
    if isinstance(pqs, str):
        # normalize "sphincsplus" variant
        if pqs == "sphincsplus":
            pqs = "sphincs+"
            out["pq_scheme"] = pqs
        if pqs not in _ALLOWED_PQ_SCHEMES:
            out.pop("pq_scheme", None)

    # Clamp known numeric fields
    for fld in ("score_raw", "p_value", "risk", "e_value", "a_alloc", "score"):
        if fld not in out:
            continue
        try:
            vf = float(out[fld])  # type: ignore[arg-type]
        except Exception:
            out.pop(fld, None)
            continue
        if not math.isfinite(vf):
            out.pop(fld, None)
            continue
        if fld == "p_value":
            out[fld] = _clamp01(vf)
        elif fld == "a_alloc":
            out[fld] = max(0.0, min(1.0, vf))
        elif fld == "e_value":
            if vf < 0.0:
                out.pop(fld, None)
            else:
                out[fld] = max(0.0, vf)
        else:
            out[fld] = _clamp01(vf)

    # Boolean normalization
    for fld in ("override_applied", "pq_required", "pq_ok"):
        if fld in out:
            out[fld] = bool(out[fld])

    # Top-level string truncation and key cap
    for k, v in list(out.items()):
        if isinstance(v, str) and len(v) > policy.max_evidence_string:
            out[k] = v[: policy.max_evidence_string]

    if len(out) > policy.max_evidence_keys:
        trimmed: Dict[str, Any] = {}
        for k in sorted(out.keys())[: policy.max_evidence_keys]:
            trimmed[k] = out[k]
        out = trimmed

    return out

def _sanitize_meta_for_model(meta: Any, *, budget: _TimeBudget) -> Optional[Dict[str, Any]]:
    """
    Defensive meta sanitizer before handing to model.score.
    Keeps a deterministic subset (bounded scan), forbids content keys, bounds values.

    Important: do not materialize or sort *all* keys of an attacker-controlled dict.
    """
    if meta is None:
        return None
    if not isinstance(meta, dict):
        return None

    # Bounded scan to avoid DoS on huge meta dicts; sort only scanned subset for determinism.
    scanned: List[Tuple[str, int, Any]] = []
    for idx, k in enumerate(meta.keys()):
        if idx >= 256:
            break
        if (idx & 0x3F) == 0x3F:
            budget.check(where="meta:scan_keys")
        ks = _safe_key_str(k, max_len=64)
        if not ks or _is_forbidden_key(ks):
            continue
        scanned.append((ks, idx, k))

    scanned.sort(key=lambda t: (t[0], t[1]))
    selected = scanned[:64]

    out: Dict[str, Any] = {}
    for i, (ks, _idx, k) in enumerate(selected):
        if (i & 0x1F) == 0x1F:
            budget.check(where="meta:sanitize")
        v = meta.get(k)
        if isinstance(v, str):
            out[ks] = _safe_text(v, max_len=256)
        elif isinstance(v, (int, bool)) or v is None:
            out[ks] = v
        elif isinstance(v, float):
            out[ks] = float(v) if math.isfinite(v) else None
        elif isinstance(v, (list, tuple)) and ks == "extra_keywords":
            # Only allow bounded, sanitized keywords.
            arr: List[str] = []
            seq = v[:64]  # type: ignore[index]
            for j, item in enumerate(seq):
                if (j & 0x1F) == 0x1F:
                    budget.check(where="meta:extra_keywords")
                s = _safe_text(item, max_len=64).lower()
                if s:
                    arr.append(s)
            out[ks] = arr
        else:
            out[ks] = f"<{type(v).__name__}>"
    return out


def _meta_summary(meta: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Content-agnostic meta summary for receipts (keeps schema stable).
    """
    if not meta:
        return {}
    out: Dict[str, Any] = {}
    ek = meta.get("extra_keywords")
    if isinstance(ek, list):
        out["extra_keywords_count"] = min(64, len(ek))
    return out


def _normalize_model_evidence(model_evidence: Any, *, policy: EvidencePolicy, budget: _TimeBudget) -> Dict[str, Any]:
    """
    Normalize model_evidence into a bounded, content-agnostic mapping.
    """
    if not isinstance(model_evidence, Mapping):
        return {"_model_evidence_type": f"<{type(model_evidence).__name__}>"}

    # Tight bounds (model evidence should be small)
    tight_policy = EvidencePolicy(
        sanitize_evidence=False,
        strip_pii=policy.strip_pii,
        hash_pii_tags=policy.hash_pii_tags,
        pii_mode=policy.pii_mode,
        allow_raw_tenant=policy.allow_raw_tenant,
        max_evidence_keys=min(32, policy.max_evidence_keys),
        max_evidence_string=min(256, policy.max_evidence_string),
        max_depth=min(3, policy.max_depth),
        max_keys_per_dict=min(32, policy.max_keys_per_dict),
        max_list_items=min(32, policy.max_list_items),
        max_total_nodes=min(256, policy.max_total_nodes),
        max_scan_per_dict=min(128, policy.max_scan_per_dict),
        pii_hmac_key=policy.pii_hmac_key,
        pii_hmac_key_id=policy.pii_hmac_key_id,
        evidence_hmac_key=policy.evidence_hmac_key,
        evidence_hmac_key_id=policy.evidence_hmac_key_id,
    ).normalized()

    nodes = [0]
    ev_any = _deep_sanitize(model_evidence, policy=tight_policy, budget=budget, depth=0, nodes=nodes)
    ev = dict(ev_any) if isinstance(ev_any, Mapping) else {"_model_evidence_type": "<nonmapping>"}

    for k in list(ev.keys()):
        if _is_forbidden_key(str(k)):
            ev.pop(k, None)
    return ev


# ---------------------------------------------------------------------------
# Models / Features
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class Features:
    len_bytes: int
    len_tokens: int
    has_url: bool
    upper_ratio: float
    digit_ratio: float
    keywords_hit: int


class ScoreModel(Protocol):
    """Pluggable scoring model: higher score â higher risk."""
    name: str
    version: str

    def score(self, text: str, meta: Optional[Dict[str, Any]], *, budget: _TimeBudget) -> Tuple[float, Dict[str, Any]]:
        ...


class HeuristicKeywordModel:
    """
    Deterministic heuristic baseline model (CPU-bounded, budget-aware).
    """
    name = "heuristic-keywords"
    version = "0.4.0"

    _KW = tuple(
        kw.lower()
        for kw in (
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
        budget.check(where="model:enter")

        s = text or ""
        low = s.lower()

        # Build a token set for faster membership checks on single-word keywords.
        # Bound work: stop after 10k tokens.
        toks: Set[str] = set()
        if s:
            for i, m in enumerate(_TOK_RE.finditer(low)):
                toks.add(m.group(0))
                if i >= 10_000:
                    break
                if (i & 0xFF) == 0xFF:
                    budget.check(where="model:tokenize")
        budget.check(where="model:tokenize_done")

        hits = 0
        kws: List[str] = list(self._KW)

        # Meta-provided extra keywords are bounded by meta sanitizer upstream.
        if meta and isinstance(meta.get("extra_keywords"), list):
            kws = kws + [str(x).lower() for x in meta["extra_keywords"][:64]]

        # Keyword hit count: token membership for single tokens; substring match for phrases.
        for i, kw in enumerate(kws[:128]):
            if not kw:
                continue
            if " " in kw:
                if kw in low:
                    hits += 1
            else:
                if kw in toks:
                    hits += 1
            if (i & 0x1F) == 0x1F:
                budget.check(where="model:keywords")

        # Lightweight structural features with O(n) scans (budget-aware).
        n_chars = len(s)
        n_bytes = len(s.encode("utf-8", "ignore"))
        # Approx token count (bounded)
        n_tokens = min(10_000, _count_tokens_budgeted(s, stop_at=10_000, budget=budget, where="model:count_tokens"))

        has_url = ("http://" in low) or ("https://" in low) or ("www." in low)

        upper = 0
        digit = 0
        # Bound loop by char cap already applied upstream; still budget-check.
        for j, ch in enumerate(s):
            o = ord(ch)
            if 65 <= o <= 90:
                upper += 1
            # digits
            if 48 <= o <= 57:
                digit += 1
            if (j & 0x3FF) == 0x3FF:
                budget.check(where="model:char_scan")

        upper_ratio = _clamp01(upper / max(1, n_chars))
        digit_ratio = _clamp01(digit / max(1, n_chars))

        feats = Features(
            len_bytes=int(n_bytes),
            len_tokens=int(n_tokens),
            has_url=bool(has_url),
            upper_ratio=float(upper_ratio),
            digit_ratio=float(digit_ratio),
            keywords_hit=int(hits),
        )

        # Bounded scoring
        base = hits + (0.6 if has_url else 0.0) + 0.4 * upper_ratio + 0.3 * digit_ratio
        base = base / (3.0 + 0.25 * math.log1p(max(1, n_tokens)))
        raw = 1.0 / (1.0 + math.exp(-3.0 * (base - 0.5)))
        raw = _clamp01(float(raw))

        evidence = {
            "features": dataclasses.asdict(feats),
            "hits": int(hits),
            # DO NOT expose caller-provided keywords; keep only a stable sample of built-in vocab.
            "kw_sample": list(self._KW[:8]),
        }
        budget.check(where="model:exit")
        return raw, evidence


# ---------------------------------------------------------------------------
# Calibration
# ---------------------------------------------------------------------------

def _pav_non_decreasing(values: List[float]) -> List[float]:
    """
    Pool Adjacent Violators (PAV) for non-decreasing sequence.
    """
    n = len(values)
    if n <= 1:
        return values[:]
    # blocks: (start, end, avg)
    blocks: List[Tuple[int, int, float]] = []
    for i, v in enumerate(values):
        blocks.append((i, i, float(v)))
        while len(blocks) >= 2 and blocks[-2][2] > blocks[-1][2]:
            s1, e1, a1 = blocks[-2]
            s2, e2, a2 = blocks[-1]
            w1 = e1 - s1 + 1
            w2 = e2 - s2 + 1
            avg = (a1 * w1 + a2 * w2) / (w1 + w2)
            blocks.pop()
            blocks.pop()
            blocks.append((s1, e2, avg))
    out = [0.0] * n
    for s, e, a in blocks:
        for i in range(s, e + 1):
            out[i] = a
    return out


@dataclass(frozen=True, slots=True)
class IsotonicKnots:
    """
    Monotone mapping (score -> p). We enforce monotone non-increasing p with PAV.
    """
    pairs: Tuple[Tuple[float, float], ...]

    xs: Tuple[float, ...] = field(init=False, repr=False)
    ys: Tuple[float, ...] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.pairs:
            raise ValueError("IsotonicKnots requires at least one pair")

        pairs = sorted([(float(x), float(y)) for x, y in self.pairs], key=lambda t: t[0])

        # clamp and dedupe by x (average y)
        grouped: List[Tuple[float, List[float]]] = []
        for x, y in pairs:
            if not (math.isfinite(x) and math.isfinite(y)):
                continue
            x = _clamp01(x)
            y = _clamp01(y)
            if grouped and abs(grouped[-1][0] - x) <= 1e-12:
                grouped[-1][1].append(y)
            else:
                grouped.append((x, [y]))

        if not grouped:
            raise ValueError("IsotonicKnots has no finite pairs after filtering")

        xs = [g[0] for g in grouped]
        ys = [sum(g[1]) / max(1, len(g[1])) for g in grouped]

        # enforce non-increasing y via PAV on -y
        ys_neg = [-v for v in ys]
        ys_neg_hat = _pav_non_decreasing(ys_neg)
        ys_hat = [-v for v in ys_neg_hat]
        ys_hat = [_clamp01(v) for v in ys_hat]

        object.__setattr__(self, "xs", tuple(xs))
        object.__setattr__(self, "ys", tuple(ys_hat))

    def map(self, s: float) -> float:
        s = _clamp01(float(s))
        xs = self.xs
        ys = self.ys
        if len(xs) == 1:
            return float(ys[0])
        if s <= xs[0]:
            return float(ys[0])
        if s >= xs[-1]:
            return float(ys[-1])
        i = bisect_left(xs, s)
        if i <= 0:
            return float(ys[0])
        if i >= len(xs):
            return float(ys[-1])
        x0, y0 = xs[i - 1], ys[i - 1]
        x1, y1 = xs[i], ys[i]
        if x1 <= x0:
            return float(y0)
        t = (s - x0) / (x1 - x0)
        return _clamp01(float(y0 + t * (y1 - y0)))


def _qscore_to_u16(s: float) -> int:
    # quantize score in [0,1] to 0..65535
    s01 = _clamp01(float(s))
    return int(round(s01 * 65535.0))


def _u16_to_score(q: int) -> float:
    return float(max(0, min(65535, int(q))) / 65535.0)


class ConformalBuffer:
    """
    Sliding-window split-conformal p-value mapping with *quantized* scores.

    We store quantized uint16 scores to:
      - eliminate float equality/removal issues
      - preserve determinism
      - keep state digest stable

    p(s) = (count{Si >= s} + 1) / (N + 1)
    """

    def __init__(self, capacity: int = 1024):
        cap = int(capacity)
        cap = max(32, min(16384, cap))
        self._cap = cap
        self._q: deque[int] = deque()  # O(1) popleft; protected by lock
        self._sorted: List[int] = []
        self._lock = threading.RLock()

    @property
    def capacity(self) -> int:
        return self._cap

    def __len__(self) -> int:
        with self._lock:
            return len(self._sorted)

    def update(self, ref_score: float) -> None:
        q = _qscore_to_u16(ref_score)
        with self._lock:
            if len(self._q) >= self._cap:
                old = self._q.popleft()
                j = bisect_left(self._sorted, old)
                if 0 <= j < len(self._sorted) and self._sorted[j] == old:
                    self._sorted.pop(j)
                else:
                    # This should not happen with quantized ints; keep fail-safe.
                    if self._sorted:
                        self._sorted.pop(0)
            self._q.append(q)
            insort(self._sorted, q)

    def p_value(self, s: float) -> float:
        q = _qscore_to_u16(s)
        with self._lock:
            n = len(self._sorted)
            if n == 0:
                return 0.5 if _CONFORMAL_BOOTSTRAP_DEFAULT == "mid" else (1.0 - _clamp01(float(s)))
            idx = bisect_left(self._sorted, q)
            ge = n - idx
            return _clamp01((ge + 1.0) / (n + 1.0))

    def summary(self) -> Dict[str, Any]:
        """
        Non-sensitive distribution summary for drift awareness.
        """
        with self._lock:
            n = len(self._sorted)
            if n == 0:
                return {"n": 0, "cap": self._cap, "min": None, "q10": None, "q50": None, "q90": None, "max": None}
            def at(p: float) -> float:
                # p in [0,1]
                i = int(round(p * (n - 1)))
                i = max(0, min(n - 1, i))
                return _u16_to_score(self._sorted[i])

            return {
                "n": n,
                "cap": self._cap,
                "min": _u16_to_score(self._sorted[0]),
                "q10": at(0.10),
                "q50": at(0.50),
                "q90": at(0.90),
                "max": _u16_to_score(self._sorted[-1]),
            }

    def state_digest(self) -> str:
        """
        Stable digest of dynamic state (summary only; no raw samples).
        """
        return _canonical_hash(
            {"summary": self.summary()},
            ctx="tcd:detector",
            label="conformal_state",
        )

@dataclass(frozen=True, slots=True)
class CalibratorConfig:
    mode: Literal["isotonic", "conformal", "identity"] = "isotonic"
    isotonic_knots: Optional[IsotonicKnots] = None
    conformal_window: int = 1024
    alpha: float = 0.05  # informational
    version: str = "3.0.0"


class _Calibrator:
    def __init__(self, cfg: CalibratorConfig):
        mode = cfg.mode if cfg.mode in ("isotonic", "conformal", "identity") else "isotonic"
        window = max(32, min(16384, int(cfg.conformal_window)))
        self._cfg = CalibratorConfig(
            mode=mode,
            isotonic_knots=cfg.isotonic_knots,
            conformal_window=window,
            alpha=_clamp01(float(cfg.alpha)) if math.isfinite(float(cfg.alpha)) else 0.05,
            version=cfg.version or "3.0.0",
        )
        self._iso = self._cfg.isotonic_knots
        self._conf = ConformalBuffer(window) if self._cfg.mode == "conformal" else None

    @property
    def mode(self) -> str:
        return self._cfg.mode

    @property
    def version(self) -> str:
        return self._cfg.version

    def p_value(self, raw_score: float) -> float:
        s = _clamp01(float(raw_score))
        if self._cfg.mode == "identity":
            return _clamp01(1.0 - s)
        if self._cfg.mode == "isotonic":
            if self._iso is None:
                return _clamp01(1.0 - s)
            return _clamp01(float(self._iso.map(s)))
        if self._cfg.mode == "conformal":
            assert self._conf is not None
            return self._conf.p_value(s)
        return _clamp01(1.0 - s)

    def update_reference(self, ref_score: float) -> None:
        if self._conf is not None:
            self._conf.update(ref_score)

    def static_snapshot(self) -> Dict[str, Any]:
        """
        Static snapshot (for config_hash/policy_digest) - MUST NOT include dynamic state.
        """
        iso_hash = None
        if self._iso is not None:
            iso_hash = _canonical_hash(
                {"pairs": list(self._iso.pairs)},
                ctx="tcd:detector",
                label="iso_knots",
            )
        return {
            "mode": self._cfg.mode,
            "version": self._cfg.version,
            "alpha": float(self._cfg.alpha),
            "isotonic_knots_hash": iso_hash,
            "conformal_window": int(self._cfg.conformal_window) if self._cfg.mode == "conformal" else None,
        }

    def state_snapshot(self) -> Dict[str, Any]:
        """
        Dynamic snapshot (for state_digest / receipts).
        """
        if self._conf is None:
            return {"mode": self._cfg.mode, "state_digest": _canonical_hash(self.static_snapshot(), ctx="tcd:detector", label="cal_state_static")}
        return {
            "mode": self._cfg.mode,
            "conformal": self._conf.summary(),
            "state_digest": self._conf.state_digest(),
        }

    def state_digest(self) -> str:
        return str(self.state_snapshot().get("state_digest"))


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

_MAX_META_KEYS = 64
_MAX_ISO_KNOTS = 512

DetectorDecision = Literal["allow", "throttle", "block"]
DetectorActionHint = Literal["ALLOW", "THROTTLE", "BLOCK"]
DetectorErrorCode = Literal[
    "OK",
    "TIME_BUDGET_EXCEEDED",
    "MODEL_ERROR",
    "CALIBRATOR_ERROR",
    "SANITIZER_ERROR",
    "INTERNAL_ERROR",
]


if _PYDANTIC_OK:

    class DetectRequest(BaseModel):
        tenant: str = Field(default="*", max_length=64)
        user: str = Field(default="*", max_length=128)
        session: str = Field(default="*", max_length=128)
        model_id: str = Field(default="*", max_length=128)
        lang: str = Field(default="*", max_length=16)
        kind: str = Field(default="completion", max_length=16)
        # Hard cap in chars; bytes are enforced by DetectorConfig.max_bytes during detect().
        text: str = Field(..., min_length=0, max_length=_HARD_MAX_TEXT_CHARS)
        meta: Optional[Dict[str, Any]] = Field(default=None)

        @field_validator("kind")
        @classmethod
        def _kind_ok(cls, v: str) -> str:
            v_norm = (v or "completion").strip().lower()
            return v_norm if v_norm in _ALLOWED_KINDS else "completion"

        @field_validator("meta")
        @classmethod
        def _meta_ok(cls, v: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
            if v is None:
                return None
            if not isinstance(v, dict):
                raise ValueError("meta must be an object")
            if len(v) > _MAX_META_KEYS:
                raise ValueError("meta too large")
            for k in v.keys():
                if _is_forbidden_key(str(k)):
                    raise ValueError(f"meta contains forbidden key: {k!r}")
            return v


    class DetectOut(BaseModel):
        ok: bool
        decision: DetectorDecision
        action_hint: DetectorActionHint
        decision_legacy: Optional[str] = None
        reason_code: str
        error_code: DetectorErrorCode = "OK"

        score_raw: float
        p_value: float
        risk: float

        latency_ms: float
        budget_left_ms: float

        thresholds: Dict[str, float]  # risk thresholds
        calibrator: Dict[str, Any]    # static
        calibrator_state: Dict[str, Any]  # dynamic (bounded)
        model: Dict[str, str]

        engine_version: str
        config_hash: str
        policy_digest: str
        state_digest: str
        decision_id: str

        evidence_hash: str
        evidence: Dict[str, Any]

else:
    @dataclass(frozen=True, slots=True)
    class DetectRequest:
        tenant: str = "*"
        user: str = "*"
        session: str = "*"
        model_id: str = "*"
        lang: str = "*"
        kind: str = "completion"
        text: str = ""
        meta: Optional[Dict[str, Any]] = None

    @dataclass(frozen=True, slots=True)
    class DetectOut:
        ok: bool
        decision: str
        action_hint: str
        decision_legacy: Optional[str]
        reason_code: str
        error_code: str
        score_raw: float
        p_value: float
        risk: float
        latency_ms: float
        budget_left_ms: float
        thresholds: Dict[str, float]
        calibrator: Dict[str, Any]
        calibrator_state: Dict[str, Any]
        model: Dict[str, str]
        engine_version: str
        config_hash: str
        policy_digest: str
        state_digest: str
        decision_id: str
        evidence_hash: str
        evidence: Dict[str, Any]


# ---------------------------------------------------------------------------
# DetectorConfig
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class DetectorConfig:
    # Routing thresholds in risk-space
    t_low: float = _THRESH_LOW_DEFAULT
    t_high: float = _THRESH_HIGH_DEFAULT

    # Processing limits
    time_budget_ms: float = _TIME_BUDGET_MS_DEFAULT
    max_tokens: int = _MAX_TOKENS_DEFAULT
    max_bytes: int = _MAX_BYTES_DEFAULT

    # Calibration
    calibrator: CalibratorConfig = dataclasses.field(
        default_factory=lambda: CalibratorConfig(
            mode=_CALIB_MODE_DEFAULT,
            isotonic_knots=None,
            conformal_window=_CONFORMAL_WINDOW_DEFAULT,
            alpha=_CONFORMAL_ALPHA_DEFAULT,
            version="3.0.0",
        )
    )

    # Conformal update guards
    conformal_ref_max: float = _CONFORMAL_REF_MAX_DEFAULT
    conformal_min_p_update: float = _CONFORMAL_MIN_P_UPDATE_DEFAULT
    conformal_allowed_sources: Tuple[str, ...] = tuple(sorted(_ALLOWED_SOURCES_SET_DEFAULT))

    # Evidence policy
    evidence_policy: EvidencePolicy = dataclasses.field(
        default_factory=lambda: EvidencePolicy(
            sanitize_evidence=_SANITIZE_EVIDENCE_DEFAULT,
            strip_pii=_STRIP_PII_DEFAULT,
            hash_pii_tags=_HASH_PII_TAGS_DEFAULT,
            pii_mode=_PII_MODE_DEFAULT if _PII_MODE_DEFAULT in ("light", "strict") else "light",
            allow_raw_tenant=_ALLOW_RAW_TENANT_DEFAULT,
            max_evidence_keys=_MAX_EVIDENCE_KEYS_DEFAULT,
            max_evidence_string=_MAX_EVIDENCE_STRING_DEFAULT,
            pii_hmac_key=_PII_HMAC_KEY,
            pii_hmac_key_id=_PII_HMAC_KEY_ID,
            evidence_hmac_key=_EVIDENCE_HMAC_KEY,
            evidence_hmac_key_id=_EVIDENCE_HMAC_KEY_ID,
        )
    )

    # Governance
    engine_version: str = _DETECTOR_ENGINE_VERSION
    name: str = "tcd-detector"
    version: str = "0.5.0"

    def normalized(self) -> "DetectorConfig":
        low, high = _validate_risk_thresholds(self.t_low, self.t_high)

        tb = float(self.time_budget_ms)
        if not math.isfinite(tb):
            tb = 3.0
        tb = max(0.5, min(50.0, tb))

        mt = int(self.max_tokens)
        mt = max(64, min(8192, mt))

        mb = int(self.max_bytes)
        mb = max(1024, min(2_000_000, mb))

        ev = str(self.engine_version or _DETECTOR_ENGINE_VERSION).strip()
        if ev not in _SUPPORTED_ENGINE_VERSIONS:
            ev = _DETECTOR_ENGINE_VERSION

        cal = self.calibrator
        mode = cal.mode if cal.mode in ("isotonic", "conformal", "identity") else _CALIB_MODE_DEFAULT
        cw = max(32, min(16384, int(cal.conformal_window)))
        alpha = float(cal.alpha)
        alpha = _clamp01(alpha) if math.isfinite(alpha) else _CONFORMAL_ALPHA_DEFAULT

        cal_norm = CalibratorConfig(
            mode=mode,
            isotonic_knots=cal.isotonic_knots,
            conformal_window=cw,
            alpha=alpha,
            version=cal.version or "3.0.0",
        )

        # Conformal guards
        ref_max = _clamp01(float(self.conformal_ref_max)) if math.isfinite(float(self.conformal_ref_max)) else _CONFORMAL_REF_MAX_DEFAULT
        min_p = _clamp01(float(self.conformal_min_p_update)) if math.isfinite(float(self.conformal_min_p_update)) else _CONFORMAL_MIN_P_UPDATE_DEFAULT
        sources = tuple(sorted({s for s in self.conformal_allowed_sources if s})) or tuple(sorted(_ALLOWED_SOURCES_SET_DEFAULT))

        return DetectorConfig(
            t_low=low,
            t_high=high,
            time_budget_ms=tb,
            max_tokens=mt,
            max_bytes=mb,
            calibrator=cal_norm,
            conformal_ref_max=ref_max,
            conformal_min_p_update=min_p,
            conformal_allowed_sources=sources,
            evidence_policy=self.evidence_policy.normalized(),
            engine_version=ev,
            name=self.name or "tcd-detector",
            version=self.version or "0.5.0",
        )


# ---------------------------------------------------------------------------
# Metrics (optional)
# ---------------------------------------------------------------------------

if _METRICS_ENABLED:  # pragma: no cover
    _DET_LAT = Histogram(
        "tcd_detector_latency_seconds",
        "Detector end-to-end latency",
        buckets=(0.001, 0.003, 0.005, 0.010, 0.020, 0.050),
    )
    _DET_STAGE_LAT = Histogram(
        "tcd_detector_stage_latency_seconds",
        "Detector stage latency",
        ["stage"],
        buckets=(0.0002, 0.0005, 0.001, 0.002, 0.005, 0.010, 0.020),
    )
    _DET_DECISIONS = Counter("tcd_detector_decision_total", "Detector decisions", ["decision"])
    _DET_ERRORS = Counter("tcd_detector_error_total", "Detector errors", ["code"])
    _DET_STAGE_TIMEOUT = Counter("tcd_detector_stage_timeout_total", "Detector stage timeouts", ["stage"])
    _DET_STAGE_ERROR = Counter("tcd_detector_stage_error_total", "Detector stage errors", ["stage", "code"])
    _DET_CONFORMAL_REF_UPDATE = Counter("tcd_detector_conformal_ref_update_total", "Conformal reference updates", ["result", "reason"])
else:  # pragma: no cover
    _DET_LAT = _DET_STAGE_LAT = _DET_DECISIONS = _DET_ERRORS = _DET_STAGE_TIMEOUT = _DET_STAGE_ERROR = _DET_CONFORMAL_REF_UPDATE = None  # type: ignore


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class Detector:
    """
    End-to-end safety detector:
      DetectRequest -> truncate -> model.score -> p_value -> decision -> evidence

    Detector.detect() never throws; it fails closed (decision="block") on error/timeout.

    NOTE on decisions:
      - decision is canonical ("allow"|"throttle"|"block").
      - decision_legacy is provided for older integrations ("cool" instead of "throttle").
      - action_hint is uppercase ("ALLOW"|"THROTTLE"|"BLOCK").
    """

    def __init__(self, model: ScoreModel, cfg: DetectorConfig):
        self._model = model
        self._cfg = cfg.normalized()
        self._cal = _Calibrator(self._cfg.calibrator)

        # Static digests
        static_payload = {
            "engine_version": self._cfg.engine_version,
            "name": self._cfg.name,
            "version": self._cfg.version,
            "thresholds_risk": {"risk_low": float(self._cfg.t_low), "risk_high": float(self._cfg.t_high)},
            "limits": {"time_budget_ms": float(self._cfg.time_budget_ms), "max_tokens": int(self._cfg.max_tokens), "max_bytes": int(self._cfg.max_bytes)},
            "calibrator": self._cal.static_snapshot(),
            "conformal_guards": {
                "ref_max": float(self._cfg.conformal_ref_max),
                "min_p_update": float(self._cfg.conformal_min_p_update),
                "allowed_sources": list(self._cfg.conformal_allowed_sources),
            },
            "evidence_policy": {
                "sanitize_evidence": bool(self._cfg.evidence_policy.sanitize_evidence),
                "strip_pii": bool(self._cfg.evidence_policy.strip_pii),
                "hash_pii_tags": bool(self._cfg.evidence_policy.hash_pii_tags),
                "pii_mode": self._cfg.evidence_policy.pii_mode,
                "allow_raw_tenant": bool(self._cfg.evidence_policy.allow_raw_tenant),
                "max_evidence_keys": int(self._cfg.evidence_policy.max_evidence_keys),
                "max_evidence_string": int(self._cfg.evidence_policy.max_evidence_string),
                "pii_hmac": bool(self._cfg.evidence_policy.pii_hmac_key is not None),
                "pii_hmac_key_id": self._cfg.evidence_policy.pii_hmac_key_id or None,
                "evidence_hmac": bool(self._cfg.evidence_policy.evidence_hmac_key is not None),
                "evidence_hmac_key_id": self._cfg.evidence_policy.evidence_hmac_key_id or None,
                "forbidden_key_substrings": list(_FORBIDDEN_KEY_SUBSTRINGS),
            },
            "model": {"name": getattr(self._model, "name", "?"), "version": getattr(self._model, "version", "?")},
        }

        self._config_hash = _canonical_hash(static_payload, ctx="tcd:detector", label="detector_cfg")
        self._policy_digest = _canonical_hash(static_payload, ctx="tcd:detector", label="detector_policy")

        logger.info(
            "Detector initialized: engine=%s mode=%s cfg_hash=%s policy_digest=%s model=%s@%s",
            self._cfg.engine_version,
            self._cal.mode,
            self._config_hash[:16],
            self._policy_digest[:16],
            getattr(self._model, "name", "?"),
            getattr(self._model, "version", "?"),
        )

    @property
    def config(self) -> DetectorConfig:
        return self._cfg

    @property
    def config_hash(self) -> str:
        return self._config_hash

    @property
    def policy_digest(self) -> str:
        return self._policy_digest

    def _route(self, *, risk: float) -> Tuple[DetectorDecision, DetectorActionHint, str]:
        """
        Route in calibrated risk space.
        Returns (decision, action_hint, reason_code).
        """
        r = _clamp01(float(risk))
        if r >= float(self._cfg.t_high):
            return "block", "BLOCK", "RISK_HIGH"
        if r >= float(self._cfg.t_low):
            return "throttle", "THROTTLE", "RISK_MED"
        return "allow", "ALLOW", "RISK_LOW"

    def detect(self, req: DetectRequest) -> DetectOut:
        """
        Never-throw. Fail-closed on internal failure.
        """
        t0 = time.perf_counter()
        budget = _TimeBudget(self._cfg.time_budget_ms)

        stage_t0 = time.perf_counter()
        stage = "init"

        ok = True
        error_code: DetectorErrorCode = "OK"

        # Safe request field extraction (never trust req type)
        try:
            tenant = _safe_text(getattr(req, "tenant", "*"), max_len=64) or "*"
            user = _safe_text(getattr(req, "user", "*"), max_len=128) or "*"
            session = _safe_text(getattr(req, "session", "*"), max_len=128) or "*"
            model_id = _safe_text(getattr(req, "model_id", "*"), max_len=128) or "*"
            kind_raw = _safe_text(getattr(req, "kind", "completion"), max_len=16).lower() or "completion"
            kind = kind_raw if kind_raw in _ALLOWED_KINDS else "completion"
            text_in = getattr(req, "text", "") or ""
            meta_in = getattr(req, "meta", None)
        except Exception:
            tenant, user, session, model_id, kind, text_in, meta_in = "*", "*", "*", "*", "completion", "", None

        # Ensure hard char cap regardless of schema
        if isinstance(text_in, str) and len(text_in) > _HARD_MAX_TEXT_CHARS:
            text_in = text_in[:_HARD_MAX_TEXT_CHARS]
        elif not isinstance(text_in, str):
            text_in = _safe_text(text_in, max_len=0)  # non-string => empty

        # Stage: truncate
        stage = "truncate"
        try:
            budget.check(where="detect:truncate")
            text, n_bytes, n_tokens, trunc_flags = _truncate_text_budgeted(
                str(text_in),
                max_bytes=int(self._cfg.max_bytes),
                max_tokens=int(self._cfg.max_tokens),
                budget=budget,
            )
        except TimeoutError:
            ok = False
            error_code = "TIME_BUDGET_EXCEEDED"
            text, n_bytes, n_tokens, trunc_flags = "", 0, 0, {"truncated_chars": True, "truncated_bytes": True, "truncated_tokens": True}
            if _METRICS_ENABLED:  # pragma: no cover
                try:
                    _DET_STAGE_TIMEOUT.labels(stage=stage).inc()
                except Exception:
                    pass
        except Exception:
            ok = False
            error_code = "INTERNAL_ERROR"
            text, n_bytes, n_tokens, trunc_flags = "", 0, 0, {"truncated_chars": True, "truncated_bytes": True, "truncated_tokens": True}
            if _METRICS_ENABLED:  # pragma: no cover
                try:
                    _DET_STAGE_ERROR.labels(stage=stage, code=error_code).inc()
                except Exception:
                    pass
        finally:
            if _METRICS_ENABLED:  # pragma: no cover
                try:
                    _DET_STAGE_LAT.labels(stage=stage).observe(max(0.0, time.perf_counter() - stage_t0))
                except Exception:
                    pass
            stage_t0 = time.perf_counter()

        # Stage: meta sanitize
        stage = "meta"
        try:
            meta = _sanitize_meta_for_model(meta_in, budget=budget)
        except Exception:
            meta = None
        finally:
            if _METRICS_ENABLED:  # pragma: no cover
                try:
                    _DET_STAGE_LAT.labels(stage=stage).observe(max(0.0, time.perf_counter() - stage_t0))
                except Exception:
                    pass
            stage_t0 = time.perf_counter()

        # Stage: score
        stage = "score"
        raw = 1.0  # fail-closed default
        model_evidence: Dict[str, Any] = {"_model_evidence_type": "<none>"}

        if ok:
            try:
                budget.check(where="detect:before_score")
                raw, me = self._model.score(text, meta, budget=budget)
                model_evidence = _normalize_model_evidence(me, policy=self._cfg.evidence_policy, budget=budget)
                budget.check(where="detect:after_score")
            except TimeoutError:
                ok = False
                error_code = "TIME_BUDGET_EXCEEDED"
                raw = 1.0
                model_evidence = {"error": "timeout", "where": "model.score"}
                if _METRICS_ENABLED:  # pragma: no cover
                    try:
                        _DET_STAGE_TIMEOUT.labels(stage=stage).inc()
                    except Exception:
                        pass
            except Exception as e:
                ok = False
                error_code = "MODEL_ERROR"
                raw = 1.0
                model_evidence = {"error": "model_error", "exc_type": type(e).__name__}
                if _METRICS_ENABLED:  # pragma: no cover
                    try:
                        _DET_STAGE_ERROR.labels(stage=stage, code=error_code).inc()
                    except Exception:
                        pass
        if _METRICS_ENABLED:  # pragma: no cover
            try:
                _DET_STAGE_LAT.labels(stage=stage).observe(max(0.0, time.perf_counter() - stage_t0))
            except Exception:
                pass
        stage_t0 = time.perf_counter()

        # Clamp raw conservatively
        try:
            raw_f = float(raw)
            if not math.isfinite(raw_f):
                raw_f = 1.0
            raw = _clamp01(raw_f)
        except Exception:
            raw = 1.0

        # Stage: calibrate
        stage = "calibrate"
        p = 0.0  # fail-closed default (risk=1)
        if ok:
            try:
                budget.check(where="detect:before_calib")
                p = _clamp01(float(self._cal.p_value(raw)))
                budget.check(where="detect:after_calib")
            except TimeoutError:
                ok = False
                error_code = "TIME_BUDGET_EXCEEDED"
                p = 0.0
                if _METRICS_ENABLED:  # pragma: no cover
                    try:
                        _DET_STAGE_TIMEOUT.labels(stage=stage).inc()
                    except Exception:
                        pass
            except Exception:
                ok = False
                error_code = "CALIBRATOR_ERROR"
                p = 0.0
                if _METRICS_ENABLED:  # pragma: no cover
                    try:
                        _DET_STAGE_ERROR.labels(stage=stage, code=error_code).inc()
                    except Exception:
                        pass
        if _METRICS_ENABLED:  # pragma: no cover
            try:
                _DET_STAGE_LAT.labels(stage=stage).observe(max(0.0, time.perf_counter() - stage_t0))
            except Exception:
                pass
        stage_t0 = time.perf_counter()

        risk = _clamp01(1.0 - p)

        # Stage: route
        stage = "route"
        decision, action_hint, reason_code = self._route(risk=risk) if ok else ("block", "BLOCK", "FAIL_CLOSED")
        if _METRICS_ENABLED:  # pragma: no cover
            try:
                _DET_STAGE_LAT.labels(stage=stage).observe(max(0.0, time.perf_counter() - stage_t0))
            except Exception:
                pass
        stage_t0 = time.perf_counter()

        # Stage: evidence
        stage = "evidence"
        policy = self._cfg.evidence_policy
        evidence: Dict[str, Any] = {}
        evidence_hash = ""
        state = self._cal.state_snapshot()
        state_digest = str(state.get("state_digest") or "")
        try:
            budget.check(where="detect:before_evidence")

            # Stable evidence core (schema-first)
            base_ev: Dict[str, Any] = {
                "tenant": tenant,
                "user": user,
                "session": session,
                "model_id": model_id,
                "kind": kind,
                "len_bytes": int(n_bytes),
                "len_tokens": int(n_tokens),
                "truncated_chars": bool(trunc_flags.get("truncated_chars", False)),
                "truncated_bytes": bool(trunc_flags.get("truncated_bytes", False)),
                "truncated_tokens": bool(trunc_flags.get("truncated_tokens", False)),
                "score_raw": float(raw),
                "p_value": float(p),
                "risk": float(risk),
                "decision": decision,
                "decision_legacy": ("cool" if decision == "throttle" else decision),
                "action_hint": action_hint,
                "reason_code": reason_code,
                "error_code": error_code,
                "engine_version": self._cfg.engine_version,
                "config_hash": self._config_hash,
                "policy_digest": self._policy_digest,
                "state_digest": state_digest,
                "calibrator": self._cal.static_snapshot(),
                "calibrator_state": state,
                "model": {"name": getattr(self._model, "name", "?"), "version": getattr(self._model, "version", "?")},
                "meta_summary": _meta_summary(meta),
            }

            # Model evidence: include only a bounded sanitized mapping + its hash
            base_ev["model_evidence"] = model_evidence
            budget.check(where="evidence:model_evidence_hash")
            me_hash = _hash_bytes(
                json.dumps(_canon_for_hash(model_evidence), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
                domain=f"model_evidence|{self._config_hash[:16]}",
                out_bytes=16,
                key=policy.evidence_hmac_key,
            )
            budget.check(where="evidence:model_evidence_hash_done")
            base_ev["model_evidence_hash"] = me_hash

            evidence = _sanitize_evidence(base_ev, policy=policy, budget=budget)

            # Evidence hash domain-separated by config_hash; keyed if configured
            budget.check(where="evidence:evidence_hash")
            evidence_hash = _hash_bytes(
                json.dumps(_canon_for_hash(evidence), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
                domain=f"evidence|{self._config_hash[:16]}",
                out_bytes=32,
                key=policy.evidence_hmac_key,
            )
            budget.check(where="evidence:evidence_hash_done")
            budget.check(where="detect:after_evidence")
        except TimeoutError:
            ok = False
            error_code = "TIME_BUDGET_EXCEEDED"
            decision, action_hint, reason_code = "block", "BLOCK", "FAIL_CLOSED_TIMEOUT"
            evidence = {"error": "timeout", "stage": "evidence"}
            evidence_hash = _hash_bytes(b"timeout", domain=f"evidence_timeout|{self._config_hash[:16]}", key=policy.evidence_hmac_key)
            if _METRICS_ENABLED:  # pragma: no cover
                try:
                    _DET_STAGE_TIMEOUT.labels(stage=stage).inc()
                except Exception:
                    pass
        except Exception:
            ok = False
            error_code = "SANITIZER_ERROR"
            decision, action_hint, reason_code = "block", "BLOCK", "FAIL_CLOSED_SANITIZER"
            evidence = {"error": "sanitizer_error"}
            evidence_hash = _hash_bytes(b"sanitizer_error", domain=f"evidence_error|{self._config_hash[:16]}", key=policy.evidence_hmac_key)
            if _METRICS_ENABLED:  # pragma: no cover
                try:
                    _DET_STAGE_ERROR.labels(stage=stage, code=error_code).inc()
                except Exception:
                    pass
        finally:
            if _METRICS_ENABLED:  # pragma: no cover
                try:
                    _DET_STAGE_LAT.labels(stage=stage).observe(max(0.0, time.perf_counter() - stage_t0))
                except Exception:
                    pass

        # decision_id (stable for fixed state+evidence)
        decision_id = _canonical_hash(
            {
                "engine_version": self._cfg.engine_version,
                "config_hash": self._config_hash,
                "state_digest": state_digest,
                "evidence_hash": evidence_hash,
                "decision": decision,
                "error_code": error_code,
            },
            ctx="tcd:detector",
            label="decision_id",
        )

        dt = max(0.0, time.perf_counter() - t0)

        if _METRICS_ENABLED:  # pragma: no cover
            try:
                _DET_LAT.observe(dt)
                _DET_DECISIONS.labels(decision=decision).inc()
                if error_code != "OK":
                    _DET_ERRORS.labels(code=error_code).inc()
            except Exception:
                pass

        return DetectOut(
            ok=bool(ok),
            decision=decision,
            decision_legacy=("cool" if decision == "throttle" else decision),
            action_hint=action_hint,
            reason_code=reason_code,
            error_code=error_code,
            score_raw=float(raw),
            p_value=float(p),
            risk=float(risk),
            latency_ms=float(dt * 1000.0),
            budget_left_ms=float(budget.remaining_ms()),
            thresholds={"risk_low": float(self._cfg.t_low), "risk_high": float(self._cfg.t_high)},
            calibrator=self._cal.static_snapshot(),
            calibrator_state=state,
            model={"name": getattr(self._model, "name", "?"), "version": getattr(self._model, "version", "?")},
            engine_version=self._cfg.engine_version,
            config_hash=self._config_hash,
            policy_digest=self._policy_digest,
            state_digest=state_digest,
            decision_id=decision_id,
            evidence_hash=evidence_hash,
            evidence=evidence,
        )

    def update_reference(
        self,
        ref_score: float,
        *,
        source: str = "unknown",
        decision: Optional[str] = None,
        p_value: Optional[float] = None,
        allow_override: bool = False,
    ) -> bool:
        """
        Conformal reference update (poisoning-resistant). Returns True if accepted.

        Guards:
          - only applies in conformal mode
          - source must be allowlisted unless allow_override=True
          - if decision/p_value provided, requires decision=="allow" and p_value>=min_p_update
          - winsorize ref_score to <= conformal_ref_max

        This method never throws.
        """

        def _inc(result: str, reason: str) -> None:
            if not _METRICS_ENABLED:  # pragma: no cover
                return
            try:  # pragma: no cover
                if _DET_CONFORMAL_REF_UPDATE is not None:
                    _DET_CONFORMAL_REF_UPDATE.labels(result=result, reason=reason).inc()
            except Exception:
                return

        try:
            if self._cal.mode != "conformal":
                _inc("rejected", "MODE")
                return False

            src = _safe_text(source, max_len=32).lower() or "unknown"
            allowed = set(self._cfg.conformal_allowed_sources)

            if not allow_override and src not in allowed:
                _inc("rejected", "SRC")
                return False

            if decision is not None and str(decision).lower() != "allow":
                _inc("rejected", "DECISION")
                return False

            if p_value is not None:
                try:
                    pv = float(p_value)
                except Exception:
                    _inc("rejected", "P_PARSE")
                    return False
                if (not math.isfinite(pv)) or pv < float(self._cfg.conformal_min_p_update):
                    _inc("rejected", "P_LOW")
                    return False

            s = _clamp01(float(ref_score))
            # winsorize to reduce poisoning impact
            s = min(s, float(self._cfg.conformal_ref_max))
            self._cal.update_reference(s)
            _inc("accepted", "OK")
            return True
        except Exception:
            _inc("error", "EXC")
            return False