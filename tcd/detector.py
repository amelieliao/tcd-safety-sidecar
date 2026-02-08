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
