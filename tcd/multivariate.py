# FILE: tcd/multivariate.py
from __future__ import annotations

"""
Multivariate Security / Risk Detector (Strong L7 / L7+ hardened)

This revision is a "precision hardening" pass based strictly on the current
tcd/multivariate.py implementation + your upgrade checklist.

Key L7/L7+ closures implemented (non-exhaustive but comprehensive):
  - Deterministic config self-proof: detect() now runs on an immutable PolicyBundle
    (cfg + fp + derived caches). Eliminates cfg/fp vs runtime-caches inconsistency.
  - Allowlist safety correctness: "secret detection" no longer accidentally purges
    hash/digest values (e.g., long base64url digests). Hash-like validation is
    separated from secret-token detection.
  - Snapshot correctness: _jsonable() no longer sanitizes keys and then .get()'s
    them (which loses values). It iterates items and handles key-collisions.
  - Snapshot DoS resistance: strict scan limits; no full-key collection/sort of huge maps.
  - Profile authority: cfg.profile is authoritative; inp.crypto_profile is observational only.
    Unknown profile now defaults conservatively to PROD (not DEV), and is surfaced as a warning.
  - Fail-open policy hardening: error behavior is profile-aware and includes an error budget
    (burst of internal errors temporarily forces fail-closed/degrade depending on profile).
  - Output closure: strict JSON (allow_nan=False), UTF-8 strict, and size-bounded with
    deterministic shrink order.
  - State isolation (optional): wealth/recent stats can be keyed per tenant/user/session
    with bounded LRU + idle GC to prevent cross-tenant interference and memory growth.
  - Optional keyed HMAC redaction: allows correlation without leaking raw identifiers.

Design principles:
  - Treat all inputs as untrusted.
  - Never call __str__/__repr__ on unknown objects when snapshotting.
  - Keep CPU/memory bounded under adversarial inputs.
"""

import hashlib
import hmac
import json
import math
import re
import threading
import time
import unicodedata
from collections import OrderedDict, deque
from dataclasses import dataclass, field, fields as dataclass_fields
from typing import Any, Deque, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

# -----------------------------
# Unicode / sanitization helpers
# -----------------------------

# Full ASCII control range incl TAB/LF/CR plus DEL
_ASCII_CTRL_FULL_RE = re.compile(r"[\x00-\x1F\x7F]")

# Strong secret-token detectors (do NOT include generic high-entropy rules here)
_JWT_RE = re.compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", re.IGNORECASE)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b", re.IGNORECASE)
_OPENAI_SK_RE = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_AWS_AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GOOGLE_AIZA_RE = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]{8,})"
)

# High-entropy detector (ONLY for conservative snapshot redaction, not for allowlists)
_ENTROPY_B64URL_RE = re.compile(r"\b[A-Za-z0-9_-]{60,}\b")

# Tag-like identifiers
_TAGLIKE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")

# Hash-like formats (used for allowlists and integrity fields)
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,256}$")
_ALGO_PREFIX_RE = re.compile(r"^(?P<algo>[a-zA-Z0-9][a-zA-Z0-9_-]{1,15}):(?P<body>.+)$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]{20,512}$")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=]{20,768}$")

# Forbidden key tokens for snapshots (structure-leak and accidental payload capture)
_FORBIDDEN_KEY_TOKENS = {
    "authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "pwd",
    "secret",
    "token",
    "apikey",
    "api-key",
    "api_key",
    "x-api-key",
    "x_api_key",
    "bearer",
    "private",
    "privatekey",
    "ssh",
    "jwt",
    "prompt",
    "messages",
    "content",
    "body",
    "headers",
    "header",
    "query",
    "params",
    "multipart",
    "form",
    "sessioncookie",
}


def _has_unsafe_unicode(s: str) -> bool:
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False


def _strip_unsafe_text(s: str, *, max_len: int) -> str:
    """
    Remove:
      - ASCII controls: 0x00–0x1F, 0x7F
      - C1 controls:    0x80–0x9F
      - Unicode: Cc/Cf/Cs/Zl/Zp + U+2028/U+2029
    Clamp length early.
    """
    if not s:
        return ""
    if len(s) > max_len:
        s = s[:max_len]

    if s.isascii():
        if _ASCII_CTRL_FULL_RE.search(s):
            s = _ASCII_CTRL_FULL_RE.sub("", s)
        return s

    if not _ASCII_CTRL_FULL_RE.search(s) and not _has_unsafe_unicode(s):
        # still remove C1 if present
        if any(0x80 <= ord(ch) <= 0x9F for ch in s):
            pass
        else:
            return s

    out: List[str] = []
    for ch in s:
        o = ord(ch)
        if ch in ("\u2028", "\u2029"):
            continue
        if o < 0x20 or o == 0x7F:
            continue
        if 0x80 <= o <= 0x9F:
            continue
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            continue
        out.append(ch)
    return "".join(out)


def _looks_like_secret_token(s: str) -> bool:
    """
    Strong token/secret patterns only (JWT/Bearer/private key/cloud keys/kv-secret).
    This MUST NOT include generic high-entropy patterns, otherwise it breaks allowlists.
    """
    if not s:
        return False
    if _JWT_RE.search(s):
        return True
    if _PRIVKEY_RE.search(s):
        return True
    if _BEARER_RE.search(s):
        return True
    if _OPENAI_SK_RE.search(s):
        return True
    if _AWS_AKIA_RE.search(s):
        return True
    if _GOOGLE_AIZA_RE.search(s):
        return True
    if _KV_SECRET_RE.search(s):
        return True
    return False


def _looks_like_high_entropy(s: str) -> bool:
    """
    Conservative redaction helper for snapshots.
    DO NOT use for allowlists / integrity hashes filtering.
    """
    if not s:
        return False
    return _ENTROPY_B64URL_RE.search(s) is not None


def _finite_float(x: Any) -> Optional[float]:
    if isinstance(x, bool):
        return None
    try:
        v = float(x)
    except Exception:
        return None
    if not math.isfinite(v):
        return None
    return v


_INT_STR_RE = re.compile(r"^[+-]?\d+$")


def _finite_int_strict(x: Any) -> Optional[int]:
    if isinstance(x, bool):
        return None
    if isinstance(x, int):
        return x
    if isinstance(x, str):
        s = x.strip()
        if not s or len(s) > 64:
            return None
        if not _INT_STR_RE.fullmatch(s):
            return None
        try:
            return int(s)
        except Exception:
            return None
    return None


def _clamp_float(v: float, lo: float, hi: float) -> float:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _clamp_int(v: int, lo: int, hi: int) -> int:
    if v < lo:
        return lo
    if v > hi:
        return hi
    return v


def _parse_bool(x: Any, default: bool = False) -> bool:
    if isinstance(x, bool):
        return x
    if isinstance(x, int) and not isinstance(x, bool):
        return bool(x)
    if isinstance(x, str):
        s = x.strip().lower()
        if s in {"1", "true", "t", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "f", "no", "n", "off"}:
            return False
    return default


def _safe_str(
    v: Any,
    *,
    max_len: int,
    allow_empty: bool = False,
    redaction: str = "token",  # "none" | "token" | "token_or_entropy"
) -> Optional[str]:
    """
    Sanitize a string. Optionally redacts secrets.
    Returns "<redacted>" sentinel only if redaction != "none" and pattern matched.
    """
    if not isinstance(v, str):
        return None
    s = _strip_unsafe_text(v, max_len=max_len).strip()
    if not s and not allow_empty:
        return None
    if redaction != "none":
        if _looks_like_secret_token(s):
            return "<redacted>"
        if redaction == "token_or_entropy" and _looks_like_high_entropy(s):
            return "<redacted>"
    if len(s) > max_len:
        s = s[:max_len]
    return s


def _safe_id(v: Any, *, max_len: int = 128) -> Optional[str]:
    s = _safe_str(v, max_len=max_len, redaction="token")
    if not s or s == "<redacted>":
        return None
    if not _TAGLIKE_ID_RE.fullmatch(s):
        return None
    return s


def _tokenize_key(k: str) -> List[str]:
    s = _strip_unsafe_text(k, max_len=128).lower()
    # treat separators uniformly
    s = re.sub(r"[^a-z0-9]+", " ", s).strip()
    if not s:
        return []
    parts = [p for p in s.split(" ") if p]
    # also add fused token to catch e.g. "setcookie"
    fused = "".join(parts)
    if fused and fused not in parts:
        parts.append(fused)
    return parts


def _is_forbidden_snapshot_key(k: str) -> bool:
    toks = _tokenize_key(k)
    if not toks:
        return True
    return any(t in _FORBIDDEN_KEY_TOKENS for t in toks)


def _normalize_hashlike(v: Any, *, max_len: int = 512) -> Tuple[Optional[str], str]:
    """
    Normalize a hash/digest-like identifier used for integrity allowlists.

    Returns (normalized_value, status):
      - status: "ok" | "missing" | "secret_like" | "invalid_format"
    """
    if not isinstance(v, str):
        return None, "missing"
    raw = _strip_unsafe_text(v, max_len=max_len).strip()
    if not raw:
        return None, "missing"
    # If it clearly looks like a secret token, treat as invalid (do not redact to "<redacted>")
    if _looks_like_secret_token(raw):
        return None, "secret_like"

    # algo:body form
    m = _ALGO_PREFIX_RE.match(raw)
    if m:
        algo = m.group("algo").lower()
        body = m.group("body").strip()
        if not body:
            return None, "invalid_format"
        # hex body canonicalized lower
        if _HEX_RE.fullmatch(body):
            return f"{algo}:{body.lower()}", "ok"
        # base64url / base64 bodies are case-sensitive; keep as-is
        if _B64URL_RE.fullmatch(body) or _B64_RE.fullmatch(body):
            return f"{algo}:{body}", "ok"
        return None, "invalid_format"

    # plain hex canonicalized lower
    if _HEX_RE.fullmatch(raw):
        return raw.lower(), "ok"
    # base64url/base64 case-sensitive; keep
    if _B64URL_RE.fullmatch(raw) or _B64_RE.fullmatch(raw):
        return raw, "ok"

    return None, "invalid_format"


def _digest_bytes(data: bytes) -> str:
    try:
        from blake3 import blake3  # type: ignore

        return blake3(data).hexdigest()
    except Exception:
        return hashlib.sha256(data).hexdigest()


def _digest_iter(values: Iterable[str]) -> str:
    """
    Stable digest for an iterable of strings. Order-sensitive by default;
    callers should provide canonical ordering if needed.
    """
    h = hashlib.sha256()
    for s in values:
        h.update(s.encode("utf-8", errors="ignore"))
        h.update(b"\n")
    return h.hexdigest()


# -----------------------------
# Snapshot conversion (JSON-safe, bounded, deterministic)
# -----------------------------


class _SnapshotBudget:
    __slots__ = ("max_nodes", "max_str", "nodes_used", "str_used")

    def __init__(self, *, max_nodes: int, max_str: int):
        self.max_nodes = max_nodes
        self.max_str = max_str
        self.nodes_used = 0
        self.str_used = 0

    def take_node(self) -> bool:
        self.nodes_used += 1
        return self.nodes_used <= self.max_nodes

    def take_str(self, n: int) -> bool:
        self.str_used += n
        return self.str_used <= self.max_str


def _jsonable(
    obj: Any,
    *,
    budget: _SnapshotBudget,
    depth: int,
    max_depth: int,
    max_items: int,
    max_scan: int,
    max_str_len: int,
    redaction: str,  # "none" | "token" | "token_or_entropy"
) -> Any:
    """
    Convert to JSON-safe structure with strict bounds.
    Avoids calling __str__/__repr__ on unknown objects.

    Important closures:
      - For dict, iterate items directly (no sanitize-then-get bug).
      - Scan is bounded (max_scan), and output is bounded (max_items).
      - Forbidden keys are dropped.
      - Key collisions after sanitization are detected.
    """
    if not budget.take_node():
        return "<truncated>"

    if obj is None:
        return None
    if isinstance(obj, bool):
        return bool(obj)
    if isinstance(obj, int) and not isinstance(obj, bool):
        if obj.bit_length() > 256:
            return "<int:oversize>"
        return int(obj)
    if isinstance(obj, float):
        if not math.isfinite(obj):
            return None
        return float(obj)
    if isinstance(obj, str):
        s = _strip_unsafe_text(obj, max_len=max_str_len).strip()
        if redaction != "none":
            if _looks_like_secret_token(s) or (redaction == "token_or_entropy" and _looks_like_high_entropy(s)):
                s = "<redacted>"
        if len(s) > max_str_len:
            s = s[:max_str_len]
        if not budget.take_str(len(s)):
            return "<truncated>"
        return s

    if depth >= max_depth:
        return "<truncated>"

    # Dict only (avoid arbitrary Mapping side-effects)
    if isinstance(obj, dict):
        items: List[Tuple[str, Any]] = []
        seen: set[str] = set()
        scanned = 0
        truncated = False
        collisions = False
        forbidden_dropped = False

        for raw_k, raw_v in obj.items():
            scanned += 1
            if scanned > max_scan:
                truncated = True
                break

            if not isinstance(raw_k, str):
                continue
            ks = _strip_unsafe_text(raw_k, max_len=64).strip()
            if not ks:
                continue
            if _is_forbidden_snapshot_key(ks):
                forbidden_dropped = True
                continue

            # normalize key for storage
            ks_norm = re.sub(r"\s+", " ", ks)
            if ks_norm in seen:
                collisions = True
                continue
            seen.add(ks_norm)

            items.append(
                (
                    ks_norm,
                    _jsonable(
                        raw_v,
                        budget=budget,
                        depth=depth + 1,
                        max_depth=max_depth,
                        max_items=max_items,
                        max_scan=max_scan,
                        max_str_len=max_str_len,
                        redaction=redaction,
                    ),
                )
            )
            if len(items) >= max_items:
                truncated = True
                break

        # Deterministic ordering (only sort bounded items)
        items.sort(key=lambda kv: kv[0])
        out: Dict[str, Any] = {k: v for k, v in items}
        if truncated:
            out["_tcd_truncated"] = True
        if collisions:
            out["_tcd_key_collision"] = True
        if forbidden_dropped:
            out["_tcd_forbidden_keys_dropped"] = True
        return out

    # Safe sequences only
    if isinstance(obj, (list, tuple, deque, set, frozenset)):
        out_list: List[Any] = []
        scanned = 0
        for it in obj:
            scanned += 1
            if scanned > max_scan:
                out_list.append("<truncated>")
                break
            if len(out_list) >= max_items:
                out_list.append("<truncated>")
                break
            out_list.append(
                _jsonable(
                    it,
                    budget=budget,
                    depth=depth + 1,
                    max_depth=max_depth,
                    max_items=max_items,
                    max_scan=max_scan,
                    max_str_len=max_str_len,
                    redaction=redaction,
                )
            )
        # Deterministic order for sets (bounded list only)
        if isinstance(obj, (set, frozenset)):
            try:
                out_list = sorted(
                    out_list,
                    key=lambda x: json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False),
                )
            except Exception:
                pass
        return out_list

    # Fallback: disclose type only
    return f"<type:{type(obj).__name__}>"


# -----------------------------
# Config
# -----------------------------


def _canonical_profile(p: Any, *, fallback: str = "PROD") -> Tuple[str, bool]:
    """
    Returns (profile, unknown_flag). Unknown defaults conservatively to fallback (PROD).
    """
    s = _safe_str(p, max_len=32, redaction="token") or ""
    up = s.upper().strip()
    if up in {"HIGH_SECURITY", "HIGHSEC", "HIGH_SEC", "HISEC"}:
        return "HIGH_SEC", False
    if up in {"PROD", "PRODUCTION"}:
        return "PROD", False
    if up in {"DEV", "DEVELOPMENT"}:
        return "DEV", False
    fb, _ = _canonical_profile(fallback, fallback="PROD")
    return fb, True


def _coerce_str_list(v: Any, *, max_items: int, max_len: int) -> List[str]:
    out: List[str] = []
    if isinstance(v, str):
        # split on comma/whitespace
        parts = re.split(r"[,\s]+", v.strip())
        v = [p for p in parts if p]
    if isinstance(v, (list, tuple, set, frozenset, deque)):
        for item in v:
            if len(out) >= max_items:
                break
            s = _safe_str(item, max_len=max_len, redaction="token")
            if not s or s == "<redacted>":
                continue
            out.append(s)
    # dedupe + stable
    return sorted(set(out))[:max_items]


def _sanitize_weights(values: Any, *, max_items: int, max_scan: int) -> Dict[str, float]:
    if not isinstance(values, dict):
        return {}
    out: Dict[str, float] = {}
    scanned = 0
    for k, v in values.items():
        scanned += 1
        if scanned > max_scan:
            break
        if len(out) >= max_items:
            break
        if not isinstance(k, str):
            continue
        name = _strip_unsafe_text(k, max_len=64).strip()
        if not name or _looks_like_secret_token(name):
            continue
        w = _finite_float(v)
        if w is None:
            continue
        out[name] = _clamp_float(float(w), 0.0, 10.0)
    return dict(out)


def _sanitize_hash_list(values: Any, *, max_items: int, max_scan: int) -> Tuple[List[str], bool]:
    """
    Sanitizes allowlist entries using hash-like normalization only.
    Returns (list, truncated_flag).
    """
    out: List[str] = []
    seen: set[str] = set()
    truncated = False

    # Coerce strings into lines
    if isinstance(values, str):
        values = [ln for ln in values.splitlines() if ln.strip()]

    if not isinstance(values, (list, tuple, set, frozenset, deque)):
        return [], False

    scanned = 0
    for v in values:
        scanned += 1
        if scanned > max_scan:
            truncated = True
            break
        if len(seen) >= max_items:
            truncated = True
            break
        norm, status = _normalize_hashlike(v)
        if status != "ok" or not norm:
            continue
        if norm in seen:
            continue
        seen.add(norm)

    # Stable ordering for determinism (bounded by max_items)
    out = sorted(seen)
    return out, truncated


@dataclass
class MultiVarConfig:
    """
    Strong-L7 configuration for multivariate detector.

    Notes:
      - cfg.profile is authoritative for policy decisions.
      - allowlists are validated as hash-like; secret-token redaction is separate.
      - fingerprint() uses a canonical "fingerprint payload" that replaces large
        allowlists with their digests to keep CPU/memory bounded.
    """

    schema_version: int = 2

    enabled: bool = False
    window: int = 10
    profile: str = "DEV"  # "DEV" | "PROD" | "HIGH_SEC"
    unknown_profile_fallback: str = "PROD"  # conservative fallback

    # Thresholds
    threshold_global: float = 0.8
    threshold_apt: float = 0.7
    threshold_insider: float = 0.7
    threshold_supply_chain: float = 0.7
    threshold_pq_fail: float = 1.0

    # Weights
    weights: Dict[str, float] = field(
        default_factory=lambda: {
            "tokens_delta": 0.05,
            "rate_limit_fill": 0.10,
            "rate_limit_recent": 0.10,
            "gpu_hot_low_throughput": 0.15,
            "gpu_util_norm": 0.05,
            "gpu_mem_ratio": 0.05,
            "gpu_temp_norm": 0.05,
            "crypto_fallback": 0.15,
            "model_hash_mismatch": 0.20,
            "binary_hash_mismatch": 0.20,
            "recent_denials_ratio": 0.10,
            "ip_diversity": 0.10,
        }
    )
    max_weights_items: int = 128
    max_weights_scan: int = 2048

    # Linear score shaping
    linear_mode: str = "exp"  # "exp" | "clamp"
    linear_scale: float = 1.0  # used when linear_mode="exp"

    # PQ / crypto
    require_pq_in_high_profile: bool = False
    allowed_sign_algos_high: List[str] = field(default_factory=list)
    max_allowed_algos: int = 256
    flag_non_pq_in_prod: bool = True

    # Supply-chain / integrity
    enforce_model_hash_allowlist: bool = False
    enforce_binary_hash_allowlist: bool = False
    block_on_model_mismatch: bool = False
    missing_integrity_hash_score: float = 0.8

    allowed_model_hashes: List[str] = field(default_factory=list)
    allowed_tokenizer_hashes: List[str] = field(default_factory=list)
    allowed_binary_hashes: List[str] = field(default_factory=list)

    # Allowlist hardening
    max_allowlist_items: int = 200_000
    max_allowlist_scan: int = 1_000_000
    allowlist_empty_behavior: str = "warn_only"  # "fail_closed" | "fail_open" | "warn_only"

    # Wealth-like state
    wealth_init: float = 0.0
    wealth_upper_bound: float = 10.0
    wealth_lower_bound: float = -10.0
    wealth_step_positive: float = 0.1
    wealth_step_negative: float = 0.05

    # State isolation & bounds
    state_key_mode: str = "global"  # "global" | "tenant" | "tenant_user" | "session" | "tenant_user_session"
    state_max_entries: int = 50_000
    state_idle_ttl_seconds: float = 3600.0
    state_gc_interval_seconds: float = 30.0

    # Output policy
    include_feature_snapshot: bool = True
    include_features: bool = True
    include_internal_state: bool = True
    include_score_components: bool = True
    include_thresholds: bool = True
    include_decision_trace: bool = False
    emit_explain: bool = False  # feature contributions (DEV/PROD only)

    max_rules_triggered: int = 64
    output_max_bytes: int = 16_384

    # Snapshot budgets
    snapshot_max_depth: int = 4
    snapshot_max_items: int = 128
    snapshot_max_nodes: int = 1024
    snapshot_max_scan: int = 4096
    snapshot_max_str_len: int = 256
    snapshot_max_total_str: int = 32_768
    snapshot_redaction: str = "token_or_entropy"  # safer for unknown extras

    # Identifier redaction / hashing
    redact_identifiers_in_high_profile: bool = True
    emit_hmac_identifiers: bool = False
    hmac_identifier_hex_len: int = 16  # bytes*2 in hex output (e.g. 16 => 8 bytes)

    # Error handling
    # Legacy single knob (DEV default); profile-aware knobs are below.
    fail_open_on_error: bool = True
    fail_open_on_error_prod: Optional[bool] = None
    fail_open_on_error_high_sec: Optional[bool] = None

    # Error budget: burst of internal errors forces stricter posture temporarily.
    error_budget_window_seconds: float = 60.0
    error_budget_max_errors: int = 20
    error_budget_cooldown_seconds: float = 60.0

    # ---- normalization ----

    def normalized_copy(self) -> "MultiVarConfig":
        c = MultiVarConfig()

        c.schema_version = int(_finite_int_strict(self.schema_version) or 2)
        c.enabled = _parse_bool(self.enabled, default=False)

        c.window = _clamp_int(int(_finite_int_strict(self.window) or 10), 1, 4096)
        prof, unknown = _canonical_profile(self.profile, fallback=self.unknown_profile_fallback or "PROD")
        c.profile = prof
        c.unknown_profile_fallback = _safe_str(self.unknown_profile_fallback, max_len=16, redaction="token") or "PROD"

        # thresholds
        c.threshold_global = _clamp_float(float(_finite_float(self.threshold_global) or 0.8), 0.0, 1.0)
        c.threshold_apt = _clamp_float(float(_finite_float(self.threshold_apt) or 0.7), 0.0, 1.0)
        c.threshold_insider = _clamp_float(float(_finite_float(self.threshold_insider) or 0.7), 0.0, 1.0)
        c.threshold_supply_chain = _clamp_float(float(_finite_float(self.threshold_supply_chain) or 0.7), 0.0, 1.0)
        c.threshold_pq_fail = _clamp_float(float(_finite_float(self.threshold_pq_fail) or 1.0), 0.0, 1.0)

        # weights
        c.max_weights_items = _clamp_int(int(_finite_int_strict(self.max_weights_items) or 128), 1, 4096)
        c.max_weights_scan = _clamp_int(int(_finite_int_strict(self.max_weights_scan) or 2048), c.max_weights_items, 1_000_000)
        w = _sanitize_weights(self.weights, max_items=c.max_weights_items, max_scan=c.max_weights_scan)
        c.weights = w if w else _sanitize_weights(MultiVarConfig().weights, max_items=c.max_weights_items, max_scan=c.max_weights_scan)

        # linear shaping
        lm = _safe_str(self.linear_mode, max_len=16, redaction="token") or "exp"
        c.linear_mode = "exp" if lm.lower() not in {"exp", "clamp"} else lm.lower()
        c.linear_scale = _clamp_float(float(_finite_float(self.linear_scale) or 1.0), 0.01, 100.0)

        # crypto knobs
        c.require_pq_in_high_profile = _parse_bool(self.require_pq_in_high_profile, default=False)
        c.flag_non_pq_in_prod = _parse_bool(self.flag_non_pq_in_prod, default=True)
        c.max_allowed_algos = _clamp_int(int(_finite_int_strict(self.max_allowed_algos) or 256), 0, 4096)
        c.allowed_sign_algos_high = _coerce_str_list(self.allowed_sign_algos_high, max_items=c.max_allowed_algos, max_len=64)

        # integrity knobs
        c.enforce_model_hash_allowlist = _parse_bool(self.enforce_model_hash_allowlist, default=False)
        c.enforce_binary_hash_allowlist = _parse_bool(self.enforce_binary_hash_allowlist, default=False)
        c.block_on_model_mismatch = _parse_bool(self.block_on_model_mismatch, default=False)
        c.missing_integrity_hash_score = _clamp_float(float(_finite_float(self.missing_integrity_hash_score) or 0.8), 0.0, 1.0)

        c.max_allowlist_items = _clamp_int(int(_finite_int_strict(self.max_allowlist_items) or 200_000), 0, 500_000)
        c.max_allowlist_scan = _clamp_int(int(_finite_int_strict(self.max_allowlist_scan) or 1_000_000), 0, 5_000_000)

        # allowlist behavior
        beh = (_safe_str(self.allowlist_empty_behavior, max_len=16, redaction="token") or "warn_only").lower()
        if beh not in {"fail_closed", "fail_open", "warn_only"}:
            beh = "warn_only"
        c.allowlist_empty_behavior = beh

        # sanitize allowlists (hash-like only)
        c.allowed_model_hashes, _ = _sanitize_hash_list(self.allowed_model_hashes, max_items=c.max_allowlist_items, max_scan=c.max_allowlist_scan)
        c.allowed_tokenizer_hashes, _ = _sanitize_hash_list(self.allowed_tokenizer_hashes, max_items=c.max_allowlist_items, max_scan=c.max_allowlist_scan)
        c.allowed_binary_hashes, _ = _sanitize_hash_list(self.allowed_binary_hashes, max_items=c.max_allowlist_items, max_scan=c.max_allowlist_scan)

        # wealth
        c.wealth_init = float(_finite_float(self.wealth_init) or 0.0)
        c.wealth_upper_bound = float(_finite_float(self.wealth_upper_bound) or 10.0)
        c.wealth_lower_bound = float(_finite_float(self.wealth_lower_bound) or -10.0)
        if c.wealth_lower_bound > c.wealth_upper_bound:
            c.wealth_lower_bound, c.wealth_upper_bound = c.wealth_upper_bound, c.wealth_lower_bound
        c.wealth_step_positive = _clamp_float(float(_finite_float(self.wealth_step_positive) or 0.1), 0.0, 10.0)
        c.wealth_step_negative = _clamp_float(float(_finite_float(self.wealth_step_negative) or 0.05), 0.0, 10.0)

        # state isolation & bounds
        skm = (_safe_str(self.state_key_mode, max_len=32, redaction="token") or "global").lower()
        if skm not in {"global", "tenant", "tenant_user", "session", "tenant_user_session"}:
            skm = "global"
        c.state_key_mode = skm
        c.state_max_entries = _clamp_int(int(_finite_int_strict(self.state_max_entries) or 50_000), 1, 5_000_000)
        c.state_idle_ttl_seconds = _clamp_float(float(_finite_float(self.state_idle_ttl_seconds) or 3600.0), 10.0, 7 * 24 * 3600.0)
        c.state_gc_interval_seconds = _clamp_float(float(_finite_float(self.state_gc_interval_seconds) or 30.0), 1.0, 3600.0)

        # output policy
        c.include_feature_snapshot = _parse_bool(self.include_feature_snapshot, default=True)
        c.include_features = _parse_bool(self.include_features, default=True)
        c.include_internal_state = _parse_bool(self.include_internal_state, default=True)
        c.include_score_components = _parse_bool(self.include_score_components, default=True)
        c.include_thresholds = _parse_bool(self.include_thresholds, default=True)
        c.include_decision_trace = _parse_bool(self.include_decision_trace, default=False)
        c.emit_explain = _parse_bool(self.emit_explain, default=False)

        c.max_rules_triggered = _clamp_int(int(_finite_int_strict(self.max_rules_triggered) or 64), 0, 1024)
        c.output_max_bytes = _clamp_int(int(_finite_int_strict(self.output_max_bytes) or 16_384), 1024, 1_000_000)

        # snapshots
        c.snapshot_max_depth = _clamp_int(int(_finite_int_strict(self.snapshot_max_depth) or 4), 1, 16)
        c.snapshot_max_items = _clamp_int(int(_finite_int_strict(self.snapshot_max_items) or 128), 1, 4096)
        c.snapshot_max_nodes = _clamp_int(int(_finite_int_strict(self.snapshot_max_nodes) or 1024), 64, 1_000_000)
        c.snapshot_max_scan = _clamp_int(int(_finite_int_strict(self.snapshot_max_scan) or 4096), c.snapshot_max_items, 1_000_000)
        c.snapshot_max_str_len = _clamp_int(int(_finite_int_strict(self.snapshot_max_str_len) or 256), 16, 32_768)
        c.snapshot_max_total_str = _clamp_int(int(_finite_int_strict(self.snapshot_max_total_str) or 32_768), 256, 10_000_000)

        red = (_safe_str(self.snapshot_redaction, max_len=32, redaction="token") or "token_or_entropy").lower()
        if red not in {"none", "token", "token_or_entropy"}:
            red = "token_or_entropy"
        c.snapshot_redaction = red

        # ids redaction + hmac
        c.redact_identifiers_in_high_profile = _parse_bool(self.redact_identifiers_in_high_profile, default=True)
        c.emit_hmac_identifiers = _parse_bool(self.emit_hmac_identifiers, default=False)
        c.hmac_identifier_hex_len = _clamp_int(int(_finite_int_strict(self.hmac_identifier_hex_len) or 16), 8, 64)

        # error handling
        c.fail_open_on_error = _parse_bool(self.fail_open_on_error, default=True)
        # profile-aware overrides default to safe behavior if not explicitly provided
        c.fail_open_on_error_prod = self.fail_open_on_error_prod if isinstance(self.fail_open_on_error_prod, bool) else None
        c.fail_open_on_error_high_sec = self.fail_open_on_error_high_sec if isinstance(self.fail_open_on_error_high_sec, bool) else None

        c.error_budget_window_seconds = _clamp_float(float(_finite_float(self.error_budget_window_seconds) or 60.0), 1.0, 3600.0)
        c.error_budget_max_errors = _clamp_int(int(_finite_int_strict(self.error_budget_max_errors) or 20), 1, 10_000)
        c.error_budget_cooldown_seconds = _clamp_float(float(_finite_float(self.error_budget_cooldown_seconds) or 60.0), 1.0, 3600.0)

        # If profile was unknown, stay conservative and let internal_state surface this.
        # (We do not store unknown flag in config to keep serialization clean.)
        _ = unknown  # for clarity

        return c

    def to_dict(self) -> Dict[str, Any]:
        """
        Full dict suitable for persistence (may contain allowlists).
        """
        c = self.normalized_copy()
        return {
            "schema_version": c.schema_version,
            "enabled": c.enabled,
            "window": c.window,
            "profile": c.profile,
            "unknown_profile_fallback": c.unknown_profile_fallback,
            "threshold_global": c.threshold_global,
            "threshold_apt": c.threshold_apt,
            "threshold_insider": c.threshold_insider,
            "threshold_supply_chain": c.threshold_supply_chain,
            "threshold_pq_fail": c.threshold_pq_fail,
            "weights": dict(sorted(c.weights.items(), key=lambda kv: kv[0])),
            "max_weights_items": c.max_weights_items,
            "max_weights_scan": c.max_weights_scan,
            "linear_mode": c.linear_mode,
            "linear_scale": c.linear_scale,
            "require_pq_in_high_profile": c.require_pq_in_high_profile,
            "allowed_sign_algos_high": list(c.allowed_sign_algos_high),
            "max_allowed_algos": c.max_allowed_algos,
            "flag_non_pq_in_prod": c.flag_non_pq_in_prod,
            "enforce_model_hash_allowlist": c.enforce_model_hash_allowlist,
            "enforce_binary_hash_allowlist": c.enforce_binary_hash_allowlist,
            "block_on_model_mismatch": c.block_on_model_mismatch,
            "missing_integrity_hash_score": c.missing_integrity_hash_score,
            "allowed_model_hashes": list(c.allowed_model_hashes),
            "allowed_tokenizer_hashes": list(c.allowed_tokenizer_hashes),
            "allowed_binary_hashes": list(c.allowed_binary_hashes),
            "max_allowlist_items": c.max_allowlist_items,
            "max_allowlist_scan": c.max_allowlist_scan,
            "allowlist_empty_behavior": c.allowlist_empty_behavior,
            "wealth_init": c.wealth_init,
            "wealth_upper_bound": c.wealth_upper_bound,
            "wealth_lower_bound": c.wealth_lower_bound,
            "wealth_step_positive": c.wealth_step_positive,
            "wealth_step_negative": c.wealth_step_negative,
            "state_key_mode": c.state_key_mode,
            "state_max_entries": c.state_max_entries,
            "state_idle_ttl_seconds": c.state_idle_ttl_seconds,
            "state_gc_interval_seconds": c.state_gc_interval_seconds,
            "include_feature_snapshot": c.include_feature_snapshot,
            "include_features": c.include_features,
            "include_internal_state": c.include_internal_state,
            "include_score_components": c.include_score_components,
            "include_thresholds": c.include_thresholds,
            "include_decision_trace": c.include_decision_trace,
            "emit_explain": c.emit_explain,
            "max_rules_triggered": c.max_rules_triggered,
            "output_max_bytes": c.output_max_bytes,
            "snapshot_max_depth": c.snapshot_max_depth,
            "snapshot_max_items": c.snapshot_max_items,
            "snapshot_max_nodes": c.snapshot_max_nodes,
            "snapshot_max_scan": c.snapshot_max_scan,
            "snapshot_max_str_len": c.snapshot_max_str_len,
            "snapshot_max_total_str": c.snapshot_max_total_str,
            "snapshot_redaction": c.snapshot_redaction,
            "redact_identifiers_in_high_profile": c.redact_identifiers_in_high_profile,
            "emit_hmac_identifiers": c.emit_hmac_identifiers,
            "hmac_identifier_hex_len": c.hmac_identifier_hex_len,
            "fail_open_on_error": c.fail_open_on_error,
            "fail_open_on_error_prod": c.fail_open_on_error_prod,
            "fail_open_on_error_high_sec": c.fail_open_on_error_high_sec,
            "error_budget_window_seconds": c.error_budget_window_seconds,
            "error_budget_max_errors": c.error_budget_max_errors,
            "error_budget_cooldown_seconds": c.error_budget_cooldown_seconds,
        }

    def to_fingerprint_payload(self) -> Dict[str, Any]:
        """
        Canonical fingerprint payload: replaces large allowlists with digests + counts.
        Keeps fingerprint stable and bounded.
        """
        c = self.normalized_copy()

        # stable digests (lists are already sorted in normalized_copy)
        model_d = _digest_iter(c.allowed_model_hashes)
        tok_d = _digest_iter(c.allowed_tokenizer_hashes)
        bin_d = _digest_iter(c.allowed_binary_hashes)

        weights_d = _digest_iter([f"{k}={c.weights[k]:.12g}" for k in sorted(c.weights.keys())])

        return {
            "schema_version": c.schema_version,
            "enabled": c.enabled,
            "window": c.window,
            "profile": c.profile,
            "unknown_profile_fallback": c.unknown_profile_fallback,
            "thresholds": {
                "global": c.threshold_global,
                "apt": c.threshold_apt,
                "insider": c.threshold_insider,
                "supply_chain": c.threshold_supply_chain,
                "pq_fail": c.threshold_pq_fail,
            },
            "weights_digest": weights_d,
            "weights_count": len(c.weights),
            "linear_mode": c.linear_mode,
            "linear_scale": c.linear_scale,
            "crypto": {
                "require_pq_in_high_profile": c.require_pq_in_high_profile,
                "allowed_sign_algos_high": list(c.allowed_sign_algos_high),
                "flag_non_pq_in_prod": c.flag_non_pq_in_prod,
            },
            "integrity": {
                "enforce_model": c.enforce_model_hash_allowlist,
                "enforce_binary": c.enforce_binary_hash_allowlist,
                "block_on_model_mismatch": c.block_on_model_mismatch,
                "missing_integrity_hash_score": c.missing_integrity_hash_score,
                "allowlist_empty_behavior": c.allowlist_empty_behavior,
                "model_allowlist_digest": model_d,
                "model_allowlist_count": len(c.allowed_model_hashes),
                "tokenizer_allowlist_digest": tok_d,
                "tokenizer_allowlist_count": len(c.allowed_tokenizer_hashes),
                "binary_allowlist_digest": bin_d,
                "binary_allowlist_count": len(c.allowed_binary_hashes),
            },
            "wealth": {
                "init": c.wealth_init,
                "upper": c.wealth_upper_bound,
                "lower": c.wealth_lower_bound,
                "step_pos": c.wealth_step_positive,
                "step_neg": c.wealth_step_negative,
            },
            "state": {
                "key_mode": c.state_key_mode,
                "max_entries": c.state_max_entries,
                "idle_ttl": c.state_idle_ttl_seconds,
            },
            "output": {
                "include_feature_snapshot": c.include_feature_snapshot,
                "include_features": c.include_features,
                "include_internal_state": c.include_internal_state,
                "include_score_components": c.include_score_components,
                "include_thresholds": c.include_thresholds,
                "include_decision_trace": c.include_decision_trace,
                "emit_explain": c.emit_explain,
                "max_rules_triggered": c.max_rules_triggered,
                "output_max_bytes": c.output_max_bytes,
                "snapshot": {
                    "max_depth": c.snapshot_max_depth,
                    "max_items": c.snapshot_max_items,
                    "max_nodes": c.snapshot_max_nodes,
                    "max_scan": c.snapshot_max_scan,
                    "max_str_len": c.snapshot_max_str_len,
                    "max_total_str": c.snapshot_max_total_str,
                    "redaction": c.snapshot_redaction,
                },
                "id_policy": {
                    "redact_identifiers_in_high_profile": c.redact_identifiers_in_high_profile,
                    "emit_hmac_identifiers": c.emit_hmac_identifiers,
                    "hmac_identifier_hex_len": c.hmac_identifier_hex_len,
                },
            },
            "errors": {
                "fail_open_on_error": c.fail_open_on_error,
                "fail_open_on_error_prod": c.fail_open_on_error_prod,
                "fail_open_on_error_high_sec": c.fail_open_on_error_high_sec,
                "budget_window_s": c.error_budget_window_seconds,
                "budget_max_errors": c.error_budget_max_errors,
                "budget_cooldown_s": c.error_budget_cooldown_seconds,
            },
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "MultiVarConfig":
        base = cls()
        if not isinstance(data, Mapping):
            return base
        allowed = {f.name for f in dataclass_fields(cls)}
        for k, v in data.items():
            if isinstance(k, str) and k in allowed:
                try:
                    setattr(base, k, v)
                except Exception:
                    pass
        return base.normalized_copy()

    def fingerprint(self) -> str:
        payload = json.dumps(
            self.to_fingerprint_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", errors="strict")
        return _digest_bytes(payload)


# -----------------------------
# Input container
# -----------------------------


@dataclass
class MultiVarInput:
    """
    All fields are optional.
    """

    timestamp: float = field(default_factory=time.time)
    request_id: Optional[str] = None

    http_method: Optional[str] = None
    path: Optional[str] = None
    norm_path: Optional[str] = None
    client_ip: Optional[str] = None
    tenant: Optional[str] = None
    user: Optional[str] = None
    session: Optional[str] = None

    tokens_delta: Optional[float] = None
    rate_limit_remaining_before: Optional[float] = None
    rate_limit_capacity: Optional[float] = None
    rate_limit_recently_limited: bool = False

    origin: Optional[str] = None
    origin_ok: Optional[bool] = None
    threat_level: Optional[int] = None

    gpu_util: Optional[float] = None
    gpu_mem_used_mib: Optional[float] = None
    gpu_mem_total_mib: Optional[float] = None
    gpu_temp_c: Optional[float] = None
    gpu_power_w: Optional[float] = None
    gpu_health_level: Optional[str] = None

    # Observational only; policy uses cfg.profile
    crypto_profile: Optional[str] = None
    hash_algo: Optional[str] = None
    mac_algo: Optional[str] = None
    sign_algo: Optional[str] = None
    key_id: Optional[str] = None
    key_status: Optional[str] = None
    crypto_fallback_used: bool = False

    model_hash: Optional[str] = None
    tokenizer_hash: Optional[str] = None
    binary_hash: Optional[str] = None

    sampler_cfg: Optional[Dict[str, Any]] = None
    latency_ms: Optional[float] = None
    throughput_tok_s: Optional[float] = None
    context_len: Optional[int] = None
    rng_seed: Optional[int] = None

    historical: Dict[str, Any] = field(default_factory=dict)
    extra: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> "MultiVarInput":
        if not isinstance(data, Mapping):
            return cls()
        init_kwargs: Dict[str, Any] = {}
        field_names = {f.name for f in dataclass_fields(cls)}
        for k, v in data.items():
            if isinstance(k, str) and k in field_names:
                init_kwargs[k] = v
        try:
            return cls(**init_kwargs)
        except Exception:
            return cls()

    @classmethod
    def from_legacy(cls, data: Any) -> "MultiVarInput":
        if isinstance(data, MultiVarInput):
            return data
        if isinstance(data, Mapping):
            return cls.from_mapping(data)
        return cls()

    def to_features(self) -> Dict[str, float]:
        """
        Raw feature extraction with finite checks and conservative caps.
        """
        features: Dict[str, float] = {}

        td = _finite_float(self.tokens_delta)
        if td is not None:
            features["tokens_delta"] = min(max(0.0, td), 1_000_000.0)

        rem = _finite_float(self.rate_limit_remaining_before)
        cap = _finite_float(self.rate_limit_capacity)
        if rem is not None and cap is not None and cap > 0:
            fill = 1.0 - (rem / cap)
            features["rate_limit_fill"] = _clamp_float(fill, 0.0, 1.0)

        if bool(self.rate_limit_recently_limited):
            features["rate_limit_recent"] = 1.0

        tl = _finite_float(self.threat_level)
        if tl is not None:
            features["threat_level_norm"] = _clamp_float(tl / 5.0, 0.0, 1.0)

        gu = _finite_float(self.gpu_util)
        if gu is not None:
            features["gpu_util_norm"] = _clamp_float(gu / 100.0, 0.0, 1.0)

        used = _finite_float(self.gpu_mem_used_mib)
        total = _finite_float(self.gpu_mem_total_mib)
        if used is not None and total is not None and total > 0:
            features["gpu_mem_ratio"] = _clamp_float(used / total, 0.0, 1.0)

        gt = _finite_float(self.gpu_temp_c)
        if gt is not None:
            features["gpu_temp_norm"] = _clamp_float(gt / 100.0, 0.0, 1.0)

        if bool(self.crypto_fallback_used):
            features["crypto_fallback"] = 1.0

        lm = _finite_float(self.latency_ms)
        if lm is not None:
            features["latency_norm"] = _clamp_float(lm / 2000.0, 0.0, 1.0)

        thr = _finite_float(self.throughput_tok_s)
        if thr is not None and thr >= 0:
            features["throughput_tok_s"] = min(thr, 1_000_000.0)

        hist = self.historical
        if isinstance(hist, Mapping):
            v = _finite_float(hist.get("recent_denials_ratio"))
            if v is not None:
                features["recent_denials_ratio"] = _clamp_float(v, 0.0, 1.0)

            v = _finite_float(hist.get("recent_rate_limited_count"))
            if v is not None:
                features["recent_rate_limited_count"] = min(max(0.0, v), 1_000_000.0)

            v = _finite_float(hist.get("recent_ip_count_for_user"))
            if v is not None:
                features["ip_diversity"] = _clamp_float(v / 10.0, 0.0, 1.0)

        # Composite: GPU hot with low throughput (util_norm semantics)
        util_norm = features.get("gpu_util_norm", 0.0)
        temp_norm = features.get("gpu_temp_norm", 0.0)
        thr_val = _finite_float(self.throughput_tok_s) or 0.0
        if util_norm > 0.5 and temp_norm > 0.7 and thr_val < 1.0:
            features["gpu_hot_low_throughput"] = 1.0

        return features


# -----------------------------
# Detector (PolicyBundle, bounded state, strict output)
# -----------------------------


@dataclass(frozen=True)
class _PolicyBundle:
    cfg: MultiVarConfig
    fp: str
    weights: Tuple[Tuple[str, float], ...]  # immutable and deterministic
    model_allow: frozenset[str]
    tokenizer_allow: frozenset[str]
    binary_allow: frozenset[str]
    allowed_sign_high: frozenset[str]
    warnings: Tuple[str, ...]


@dataclass
class _EntityState:
    wealth: float
    recent_scores: Deque[float]
    last_seen_mono: float


class MultiVarDetector:
    """
    Strong L7/L7+ multivariate detector with deterministic policy bundling,
    bounded snapshots, and bounded state.
    """

    def __init__(
        self,
        config: Optional[MultiVarConfig] = None,
        *,
        redaction_hmac_key: Optional[bytes] = None,
        redaction_hmac_key_id: Optional[str] = None,
    ):
        self._bundle_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._err_lock = threading.Lock()

        self._redaction_key = redaction_hmac_key
        self._redaction_key_id = _safe_str(redaction_hmac_key_id, max_len=32, redaction="token") if isinstance(redaction_hmac_key_id, str) else None

        cfg = (config or MultiVarConfig()).normalized_copy()
        self._bundle: _PolicyBundle = self._build_bundle(cfg)

        # bounded per-entity state
        self._state: "OrderedDict[str, _EntityState]" = OrderedDict()
        self._last_state_gc = 0.0

        # error budget state
        self._err_times: Deque[float] = deque()
        self._err_block_until: float = 0.0

    # ---- policy bundle ----

    def _build_bundle(self, cfg: MultiVarConfig) -> _PolicyBundle:
        cfg2 = cfg.normalized_copy()
        fp = cfg2.fingerprint()

        # deterministic weights ordering
        w_items = tuple(sorted(((k, float(v)) for k, v in cfg2.weights.items()), key=lambda kv: kv[0]))

        # allowlists as frozenset for O(1) membership; already normalized in cfg2
        model_allow = frozenset(cfg2.allowed_model_hashes)
        tokenizer_allow = frozenset(cfg2.allowed_tokenizer_hashes)
        binary_allow = frozenset(cfg2.allowed_binary_hashes)

        # allowed algos for high profile (case-insensitive match)
        allowed_sign_high = frozenset({a.lower() for a in (cfg2.allowed_sign_algos_high or [])})

        # policy warnings (low cardinality)
        warnings: List[str] = []
        # unknown profile detection: recompute from original to signal
        _, unknown = _canonical_profile(cfg.profile, fallback=cfg2.unknown_profile_fallback)
        if unknown:
            warnings.append("unknown_profile_fallback")
        # allowlist empty warnings
        if cfg2.enforce_model_hash_allowlist and not model_allow:
            warnings.append("model_allowlist_empty")
        if cfg2.enforce_binary_hash_allowlist and not binary_allow:
            warnings.append("binary_allowlist_empty")

        return _PolicyBundle(
            cfg=cfg2,
            fp=fp,
            weights=w_items,
            model_allow=model_allow,
            tokenizer_allow=tokenizer_allow,
            binary_allow=binary_allow,
            allowed_sign_high=allowed_sign_high,
            warnings=tuple(sorted(set(warnings))),
        )

    @property
    def config(self) -> MultiVarConfig:
        with self._bundle_lock:
            return self._bundle.cfg.normalized_copy()

    def set_config(self, config: MultiVarConfig) -> None:
        cfg = (config or MultiVarConfig()).normalized_copy()
        bundle = self._build_bundle(cfg)
        with self._bundle_lock:
            self._bundle = bundle
        # wealth/state will adapt lazily on access (window changes handled per entity)

    def set_redaction_key(self, key: Optional[bytes], *, key_id: Optional[str] = None) -> None:
        self._redaction_key = key
        self._redaction_key_id = _safe_str(key_id, max_len=32, redaction="token") if isinstance(key_id, str) else None

    # ---- state helpers ----

    def _state_gc(self, bundle: _PolicyBundle, now_mono: float) -> None:
        cfg = bundle.cfg
        if (now_mono - self._last_state_gc) < cfg.state_gc_interval_seconds:
            return
        self._last_state_gc = now_mono
        cutoff = now_mono - cfg.state_idle_ttl_seconds

        # evict idle entries
        for k, st in list(self._state.items()):
            if st.last_seen_mono < cutoff:
                self._state.pop(k, None)

        # enforce hard cap (LRU)
        while len(self._state) > cfg.state_max_entries:
            self._state.popitem(last=False)

    def _hmac_id(self, label: str, value: str, *, hex_len: int) -> Optional[str]:
        if not value:
            return None
        if not self._redaction_key:
            return None
        msg = f"TCD|multivar|{label}|v1|{value}".encode("utf-8", errors="ignore")
        dig = hmac.new(self._redaction_key, msg, digestmod=hashlib.sha256).digest()
        # hex_len is number of hex chars
        out = dig.hex()[: _clamp_int(hex_len, 8, 128)]
        return out

    def _state_key(self, bundle: _PolicyBundle, inp: MultiVarInput) -> str:
        cfg = bundle.cfg
        profile = cfg.profile

        # sanitize components (token-only; do not entropy-redact)
        tenant = _safe_str(inp.tenant, max_len=128, redaction="token")
        user = _safe_str(inp.user, max_len=128, redaction="token")
        session = _safe_str(inp.session, max_len=128, redaction="token")

        # HIGH_SEC: avoid raw identifiers unless HMAC is enabled
        if profile == "HIGH_SEC" and cfg.redact_identifiers_in_high_profile:
            if cfg.emit_hmac_identifiers and self._redaction_key:
                tenant = self._hmac_id("tenant", tenant or "", hex_len=cfg.hmac_identifier_hex_len)
                user = self._hmac_id("user", user or "", hex_len=cfg.hmac_identifier_hex_len)
                session = self._hmac_id("session", session or "", hex_len=cfg.hmac_identifier_hex_len)
            else:
                tenant = None
                user = None
                session = None

        mode = cfg.state_key_mode
        if mode == "global":
            return "global"
        if mode == "tenant":
            return f"t:{tenant or 'anon'}"
        if mode == "tenant_user":
            return f"t:{tenant or 'anon'}|u:{user or 'anon'}"
        if mode == "session":
            return f"s:{session or 'anon'}"
        if mode == "tenant_user_session":
            return f"t:{tenant or 'anon'}|u:{user or 'anon'}|s:{session or 'anon'}"
        return "global"

    def _get_entity_state(self, bundle: _PolicyBundle, key: str, now_mono: float) -> _EntityState:
        cfg = bundle.cfg
        with self._state_lock:
            self._state_gc(bundle, now_mono)
            st = self._state.get(key)
            if st is None:
                st = _EntityState(
                    wealth=float(cfg.wealth_init),
                    recent_scores=deque(maxlen=cfg.window),
                    last_seen_mono=now_mono,
                )
                self._state[key] = st
            else:
                st.last_seen_mono = now_mono
                # adjust window if needed
                if st.recent_scores.maxlen != cfg.window:
                    st.recent_scores = deque(list(st.recent_scores)[-cfg.window :], maxlen=cfg.window)
                # LRU bump
                self._state.move_to_end(key, last=True)

            # enforce cap (LRU)
            while len(self._state) > cfg.state_max_entries:
                self._state.popitem(last=False)

            return st

    # ---- error budget ----

    def _error_budget_allows_fail_open(self, bundle: _PolicyBundle, now_mono: float) -> bool:
        cfg = bundle.cfg
        with self._err_lock:
            if now_mono < self._err_block_until:
                return False
        # profile-aware default
        if cfg.profile == "HIGH_SEC":
            fo = cfg.fail_open_on_error_high_sec if isinstance(cfg.fail_open_on_error_high_sec, bool) else False
            return bool(fo)
        if cfg.profile == "PROD":
            fo = cfg.fail_open_on_error_prod if isinstance(cfg.fail_open_on_error_prod, bool) else False
            return bool(fo)
        return bool(cfg.fail_open_on_error)

    def _record_error_and_maybe_trip_budget(self, bundle: _PolicyBundle, now_mono: float) -> None:
        cfg = bundle.cfg
        with self._err_lock:
            self._err_times.append(now_mono)
            # drop old
            cutoff = now_mono - cfg.error_budget_window_seconds
            while self._err_times and self._err_times[0] < cutoff:
                self._err_times.popleft()
            if len(self._err_times) >= cfg.error_budget_max_errors:
                self._err_block_until = now_mono + cfg.error_budget_cooldown_seconds

    # ---- rules & scoring ----

    def _effective_profile(self, cfg: MultiVarConfig) -> str:
        # cfg already normalized; still keep for clarity
        return cfg.profile

    def _safe_rule_list(self, cfg: MultiVarConfig, rules: List[str]) -> List[str]:
        maxn = int(cfg.max_rules_triggered or 0)
        if maxn <= 0:
            return []
        out: List[str] = []
        for r in rules:
            if len(out) >= maxn:
                break
            if not isinstance(r, str):
                continue
            rr = _strip_unsafe_text(r, max_len=64).strip()
            if not rr or _looks_like_secret_token(rr):
                continue
            out.append(rr)
        return sorted(set(out))[:maxn]

    def _rule_eval(self, bundle: _PolicyBundle, inp: MultiVarInput, features: Dict[str, float]) -> Dict[str, Any]:
        cfg = bundle.cfg
        profile = self._effective_profile(cfg)
        high_profile = profile == "HIGH_SEC"

        rules: List[str] = []
        apt_score = 0.0
        insider_score = 0.0
        supply_score = 0.0
        pq_risk = "ok"

        # --- Integrity / allowlists ---
        model_norm, model_status = _normalize_hashlike(inp.model_hash)
        tok_norm, tok_status = _normalize_hashlike(inp.tokenizer_hash)
        bin_norm, bin_status = _normalize_hashlike(inp.binary_hash)

        # Helper for allowlist empty behavior
        def _allowlist_empty_action(which: str) -> None:
            beh = cfg.allowlist_empty_behavior
            rules.append(f"{which}_allowlist_empty")
            if beh == "fail_closed":
                nonlocal supply_score
                supply_score = max(supply_score, 1.0)
            elif beh == "fail_open":
                pass
            else:
                # warn_only
                pass

        # Model allowlist enforcement
        if cfg.enforce_model_hash_allowlist:
            if not bundle.model_allow:
                _allowlist_empty_action("model")
            else:
                if model_status == "missing":
                    supply_score = max(supply_score, cfg.missing_integrity_hash_score)
                    rules.append("model_hash_missing")
                elif model_status == "secret_like":
                    supply_score = max(supply_score, 1.0)
                    rules.append("model_hash_secret_like")
                elif model_status == "invalid_format":
                    supply_score = max(supply_score, cfg.missing_integrity_hash_score)
                    rules.append("model_hash_invalid_format")
                elif model_norm and model_norm not in bundle.model_allow:
                    supply_score = max(supply_score, 1.0)
                    rules.append("model_hash_not_allowed")
                    features["model_hash_mismatch"] = 1.0

            # Tokenizer allowlist is optional but if configured, enforce against non-empty set.
            if bundle.tokenizer_allow:
                if tok_status == "ok" and tok_norm and tok_norm not in bundle.tokenizer_allow:
                    supply_score = max(supply_score, 0.8)
                    rules.append("tokenizer_hash_not_allowed")
            else:
                # if tokenizer hash allowlist list is empty but tokenizer hash is present,
                # we do NOT penalize (avoid misconfig-driven false positives).
                pass

        # Binary allowlist enforcement
        if cfg.enforce_binary_hash_allowlist:
            if not bundle.binary_allow:
                _allowlist_empty_action("binary")
            else:
                if bin_status == "missing":
                    supply_score = max(supply_score, cfg.missing_integrity_hash_score)
                    rules.append("binary_hash_missing")
                elif bin_status == "secret_like":
                    supply_score = max(supply_score, 1.0)
                    rules.append("binary_hash_secret_like")
                elif bin_status == "invalid_format":
                    supply_score = max(supply_score, cfg.missing_integrity_hash_score)
                    rules.append("binary_hash_invalid_format")
                elif bin_norm and bin_norm not in bundle.binary_allow:
                    supply_score = max(supply_score, 1.0)
                    rules.append("binary_hash_not_allowed")
                    features["binary_hash_mismatch"] = 1.0

        # --- Crypto / PQ policy (cfg.profile authoritative) ---
        sign_algo = _safe_str(inp.sign_algo, max_len=64, redaction="token")
        key_status = _safe_str(inp.key_status, max_len=32, redaction="token")

        if high_profile and cfg.require_pq_in_high_profile:
            if not bundle.allowed_sign_high:
                pq_risk = "warn"
                rules.append("pq_policy_misconfigured")
            else:
                if not sign_algo or sign_algo == "<redacted>":
                    pq_risk = "fail"
                    rules.append("sign_algo_missing_in_high_profile")
                elif sign_algo.lower() not in bundle.allowed_sign_high:
                    pq_risk = "fail"
                    rules.append("sign_algo_not_in_high_profile")

        if key_status and key_status != "<redacted>":
            if key_status.lower() in {"revoked", "expired", "compromised"}:
                pq_risk = "fail"
                rules.append("crypto_policy_violation")

        if bool(inp.crypto_fallback_used):
            rules.append("crypto_fallback_used")
            apt_score = max(apt_score, 0.6)

        if cfg.flag_non_pq_in_prod and profile in {"PROD", "HIGH_SEC"}:
            if sign_algo and sign_algo != "<redacted>":
                # still a heuristic; callers should supply a stable label if possible
                if "pq" not in sign_algo.lower():
                    if pq_risk != "fail":
                        pq_risk = "warn"
                    rules.append("crypto_policy_warning")

        # --- Behavior / edge signals ---
        if inp.origin_ok is False:
            apt_score = max(apt_score, 0.5)
            rules.append("origin_not_ok")

        hist = inp.historical if isinstance(inp.historical, Mapping) else {}
        rl_count = _finite_float(hist.get("recent_rate_limited_count")) or 0.0
        denials_ratio = _finite_float(hist.get("recent_denials_ratio")) or 0.0
        ip_count = _finite_float(hist.get("recent_ip_count_for_user")) or 0.0

        if rl_count > 0:
            apt_score = max(apt_score, _clamp_float(0.1 * rl_count, 0.0, 1.0))
            rules.append("rate_limit_pattern")
        if denials_ratio > 0.3:
            apt_score = max(apt_score, _clamp_float(denials_ratio, 0.0, 1.0))
            rules.append("denial_pattern")
        if ip_count > 3:
            insider_score = max(insider_score, _clamp_float((ip_count - 3.0) / 5.0, 0.0, 1.0))
            rules.append("ip_diversity_pattern")

        tl = _finite_float(inp.threat_level)
        if tl is not None and tl > 0:
            apt_score = max(apt_score, _clamp_float(tl / 5.0, 0.0, 1.0))

        return {
            "apt_score": _clamp_float(apt_score, 0.0, 1.0),
            "insider_score": _clamp_float(insider_score, 0.0, 1.0),
            "supply_chain_score": _clamp_float(supply_score, 0.0, 1.0),
            "pq_risk_level": pq_risk,
            "rules_triggered": self._safe_rule_list(cfg, rules),
            "features": dict(features),
        }

    def _linear_score(self, bundle: _PolicyBundle, features: Mapping[str, float]) -> Tuple[float, float, Dict[str, float]]:
        """
        Returns (linear_score, raw_sum, contributions).
        """
        cfg = bundle.cfg
        raw = 0.0
        contribs: Dict[str, float] = {}

        for name, w in bundle.weights:
            ww = _finite_float(w) or 0.0
            if ww <= 0:
                continue
            vv = _finite_float(features.get(name, 0.0)) or 0.0
            if vv < 0:
                vv = 0.0
            raw += ww * vv
            # contributions kept for explain mode (bounded by weights size)
            contribs[name] = ww * vv

        raw = max(0.0, raw)

        if cfg.linear_mode == "exp":
            # stable saturation
            s = 1.0 - math.exp(-raw / cfg.linear_scale)
            return _clamp_float(s, 0.0, 1.0), raw, contribs

        # clamp mode
        return _clamp_float(raw, 0.0, 1.0), raw, contribs

    def _combine_scores(self, bundle: _PolicyBundle, rule_out: Mapping[str, Any]) -> Dict[str, Any]:
        cfg = bundle.cfg
        features = rule_out.get("features") if isinstance(rule_out.get("features"), Mapping) else {}

        apt_score = float(rule_out.get("apt_score") or 0.0)
        insider_score = float(rule_out.get("insider_score") or 0.0)
        supply_score = float(rule_out.get("supply_chain_score") or 0.0)
        pq_risk = str(rule_out.get("pq_risk_level") or "ok")
        rules = list(rule_out.get("rules_triggered") or [])

        linear, raw_sum, contribs = self._linear_score(bundle, features)

        combined = max(linear, apt_score, insider_score, supply_score)
        trace: List[str] = []

        if pq_risk == "fail":
            combined = max(combined, cfg.threshold_pq_fail)
            trace.append("pq_fail=>floor")
        elif pq_risk == "warn":
            combined = _clamp_float(combined + 0.1, 0.0, 1.0)
            trace.append("pq_warn=>bump")

        risk_score = _clamp_float(combined, 0.0, 1.0)

        action = "allow"
        verdict = True

        # Hard fail paths (crypto policy)
        if pq_risk == "fail":
            action = "block"
            verdict = False
            trace.append("pq_fail=>block")
        elif cfg.block_on_model_mismatch and supply_score >= cfg.threshold_supply_chain:
            action = "block"
            verdict = False
            trace.append("supply_chain>=threshold=>block")
        elif risk_score >= cfg.threshold_global:
            action = "block"
            verdict = False
            trace.append("risk>=global=>block")
        elif risk_score >= 0.5:
            action = "degrade"
            trace.append("risk>=0.5=>degrade")
        elif rules:
            action = "alert"
            trace.append("rules_nonempty=>alert")

        return {
            "verdict": verdict,
            "action": action,
            "risk_score": risk_score,
            "apt_score": _clamp_float(apt_score, 0.0, 1.0),
            "insider_score": _clamp_float(insider_score, 0.0, 1.0),
            "supply_chain_score": _clamp_float(supply_score, 0.0, 1.0),
            "pq_risk_level": pq_risk,
            "rules_triggered": rules,
            "features": dict(features),
            "linear_score": linear,
            "linear_score_raw": raw_sum,
            "contributions": contribs,
            "decision_trace": trace,
        }

    def _update_wealth_and_recent(
        self,
        bundle: _PolicyBundle,
        st: _EntityState,
        score: float,
        rules_triggered: Sequence[str],
        now_mono: float,
    ) -> Tuple[Dict[str, float], Dict[str, float]]:
        cfg = bundle.cfg
        rs = _clamp_float(float(_finite_float(score) or 0.0), 0.0, 1.0)

        # update under state lock to keep per-entity coherent
        with self._state_lock:
            before = float(st.wealth)
            delta = 0.0
            if rs > 0.5:
                delta += cfg.wealth_step_positive * (rs - 0.5) * 2.0
            else:
                delta -= cfg.wealth_step_negative * (0.5 - rs) * 2.0

            if any(
                r in {"model_hash_not_allowed", "binary_hash_not_allowed", "sign_algo_not_in_high_profile", "crypto_policy_violation"}
                for r in rules_triggered
            ):
                delta += 0.2

            st.wealth = _clamp_float(before + delta, cfg.wealth_lower_bound, cfg.wealth_upper_bound)
            st.last_seen_mono = now_mono
            st.recent_scores.append(rs)
            arr = list(st.recent_scores)

        # compute stats outside lock
        arr_sorted = sorted(arr)
        avg = sum(arr) / max(1, len(arr))
        p95 = arr_sorted[int(0.95 * (len(arr_sorted) - 1))] if len(arr_sorted) > 1 else (arr_sorted[0] if arr_sorted else 0.0)

        wealth_info = {
            "wealth_before": before,
            "wealth_after": float(st.wealth),
            "wealth_upper": cfg.wealth_upper_bound,
            "wealth_lower": cfg.wealth_lower_bound,
        }
        recent_info = {"recent_avg": _clamp_float(avg, 0.0, 1.0), "recent_p95": _clamp_float(p95, 0.0, 1.0)}
        return wealth_info, recent_info

    def _build_feature_snapshot(self, bundle: _PolicyBundle, inp: MultiVarInput) -> Dict[str, Any]:
        cfg = bundle.cfg
        profile = cfg.profile
        redact_ids = cfg.redact_identifiers_in_high_profile and profile == "HIGH_SEC"

        tenant = _safe_str(inp.tenant, max_len=128, redaction="token")
        user = _safe_str(inp.user, max_len=128, redaction="token")
        session = _safe_str(inp.session, max_len=128, redaction="token")

        # Optional HMAC identifiers (for correlation without raw IDs)
        tenant_h = user_h = session_h = None
        if cfg.emit_hmac_identifiers and self._redaction_key:
            tenant_h = self._hmac_id("tenant", tenant or "", hex_len=cfg.hmac_identifier_hex_len)
            user_h = self._hmac_id("user", user or "", hex_len=cfg.hmac_identifier_hex_len)
            session_h = self._hmac_id("session", session or "", hex_len=cfg.hmac_identifier_hex_len)

        if redact_ids:
            tenant = None
            user = None
            session = None

        snap: Dict[str, Any] = {
            "tenant": tenant,
            "user": user,
            "session": session,
            "tenant_h": tenant_h if redact_ids else None,
            "user_h": user_h if redact_ids else None,
            "session_h": session_h if redact_ids else None,
            "client_ip": None,  # never expose raw IP
            "path": _safe_str(inp.path, max_len=256, redaction="token_or_entropy"),
            "norm_path": _safe_str(inp.norm_path, max_len=256, redaction="token_or_entropy"),
            "http_method": _safe_str(inp.http_method, max_len=16, redaction="token"),
            "crypto_profile_observed": _safe_str(inp.crypto_profile, max_len=32, redaction="token"),
            "sign_algo": _safe_str(inp.sign_algo, max_len=64, redaction="token"),
            "key_status": _safe_str(inp.key_status, max_len=32, redaction="token"),
            # integrity fields: keep as normalized hash-like when possible, do not "<redacted>" them
            "model_hash": _normalize_hashlike(inp.model_hash)[0],
            "tokenizer_hash": _normalize_hashlike(inp.tokenizer_hash)[0],
            "binary_hash": _normalize_hashlike(inp.binary_hash)[0],
            "gpu_health_level": _safe_str(inp.gpu_health_level, max_len=32, redaction="token"),
        }

        budget = _SnapshotBudget(max_nodes=cfg.snapshot_max_nodes, max_str=cfg.snapshot_max_total_str)
        snap["historical"] = (
            _jsonable(
                inp.historical if isinstance(inp.historical, dict) else {},
                budget=budget,
                depth=0,
                max_depth=cfg.snapshot_max_depth,
                max_items=cfg.snapshot_max_items,
                max_scan=cfg.snapshot_max_scan,
                max_str_len=cfg.snapshot_max_str_len,
                redaction=cfg.snapshot_redaction,
            )
            if isinstance(inp.historical, dict)
            else {}
        )
        snap["extra"] = (
            _jsonable(
                inp.extra if isinstance(inp.extra, dict) else {},
                budget=budget,
                depth=0,
                max_depth=cfg.snapshot_max_depth,
                max_items=cfg.snapshot_max_items,
                max_scan=cfg.snapshot_max_scan,
                max_str_len=cfg.snapshot_max_str_len,
                redaction=cfg.snapshot_redaction,
            )
            if isinstance(inp.extra, dict)
            else {}
        )

        # key id disclosure is optional and safe-ish (low-cardinality) but keep out by default
        if cfg.emit_hmac_identifiers and self._redaction_key_id:
            snap["hmac_key_id"] = self._redaction_key_id

        return snap

    def _enforce_output_budget(self, bundle: _PolicyBundle, out: Dict[str, Any]) -> Dict[str, Any]:
        """
        Strict JSON closure + byte-budget shrink.
        Deterministic shrink order: drop optional, keep required.
        """
        cfg = bundle.cfg
        max_bytes = cfg.output_max_bytes

        def _try_dump(o: Dict[str, Any]) -> Optional[bytes]:
            try:
                s = json.dumps(o, ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False)
                b = s.encode("utf-8", errors="strict")
                return b
            except Exception:
                return None

        b0 = _try_dump(out)
        if b0 is not None and len(b0) <= max_bytes:
            return out

        # shrink deterministically
        shrunk = dict(out)
        shrunk["_tcd_shrunk"] = True

        drop_order = [
            "feature_snapshot",
            "features",
            "internal_state",
            "score_components",
            "thresholds",
            "decision_trace",
            "explain",
        ]
        for k in drop_order:
            if k in shrunk:
                shrunk.pop(k, None)
                b1 = _try_dump(shrunk)
                if b1 is not None and len(b1) <= max_bytes:
                    return shrunk

        # last resort minimal
        minimal = {
            "schema": out.get("schema", "tcd.multivar.v2"),
            "schema_version": out.get("schema_version", 2),
            "verdict": bool(out.get("verdict", True)),
            "action": str(out.get("action", "allow")),
            "risk_score": float(out.get("risk_score", 0.0)),
            "rules_triggered": list(out.get("rules_triggered", [])[:16]),
            "config_fingerprint": out.get("config_fingerprint"),
            "profile": out.get("profile"),
            "timestamp": out.get("timestamp", time.time()),
            "_tcd_shrunk": True,
        }
        return minimal

    # ---- public API ----

    def detect(self, data: Any) -> Dict[str, Any]:
        # Snapshot bundle atomically (no cfg/fp vs caches inconsistency)
        with self._bundle_lock:
            bundle = self._bundle
        cfg = bundle.cfg

        # Disabled: stable allow
        if not cfg.enabled:
            ts = time.time()
            out = {
                "schema": "tcd.multivar.v2",
                "schema_version": cfg.schema_version,
                "verdict": True,
                "action": "allow",
                "score": 0.0,
                "risk_score": 0.0,
                "apt_score": 0.0,
                "insider_score": 0.0,
                "supply_chain_score": 0.0,
                "pq_risk_level": "ok",
                "rules_triggered": [],
                "config_fingerprint": bundle.fp,
                "profile": cfg.profile,
                "timestamp": ts,
                "request_id": None,
            }
            if cfg.include_internal_state:
                out["internal_state"] = {
                    "warnings": list(bundle.warnings),
                    "state_key_mode": cfg.state_key_mode,
                }
            return self._enforce_output_budget(bundle, out)

        now_mono = time.monotonic()
        try:
            inp = MultiVarInput.from_legacy(data)

            # minimal ids
            rid = _safe_id(inp.request_id, max_len=128)
            ts = _finite_float(inp.timestamp)
            if ts is None:
                ts = time.time()

            # per-entity state
            skey = self._state_key(bundle, inp)
            st = self._get_entity_state(bundle, skey, now_mono)

            features = inp.to_features()
            rule_out = self._rule_eval(bundle, inp, features)
            combined = self._combine_scores(bundle, rule_out)

            wealth_info, recent_info = self._update_wealth_and_recent(
                bundle, st, combined["risk_score"], combined["rules_triggered"], now_mono
            )

            out: Dict[str, Any] = {
                "schema": "tcd.multivar.v2",
                "schema_version": cfg.schema_version,
                "verdict": bool(combined["verdict"]),
                "action": str(combined["action"]),
                "score": float(combined["risk_score"]),  # legacy alias
                "risk_score": float(combined["risk_score"]),
                "apt_score": float(combined["apt_score"]),
                "insider_score": float(combined["insider_score"]),
                "supply_chain_score": float(combined["supply_chain_score"]),
                "pq_risk_level": str(combined["pq_risk_level"]),
                "rules_triggered": self._safe_rule_list(cfg, list(combined["rules_triggered"])),
                "config_fingerprint": bundle.fp,
                "profile": cfg.profile,
                "timestamp": float(ts),
                "request_id": rid,
                "wealth_before": float(wealth_info["wealth_before"]),
                "wealth_after": float(wealth_info["wealth_after"]),
                "wealth_thresholds": {"upper": float(wealth_info["wealth_upper"]), "lower": float(wealth_info["wealth_lower"])},
            }

            if cfg.include_thresholds:
                out["thresholds"] = {
                    "global": cfg.threshold_global,
                    "apt": cfg.threshold_apt,
                    "insider": cfg.threshold_insider,
                    "supply_chain": cfg.threshold_supply_chain,
                    "pq_fail": cfg.threshold_pq_fail,
                }

            if cfg.include_score_components:
                out["score_components"] = {
                    "linear_score": float(combined["linear_score"]),
                    "linear_score_raw": float(combined["linear_score_raw"]),
                    "apt_score": float(combined["apt_score"]),
                    "insider_score": float(combined["insider_score"]),
                    "supply_chain_score": float(combined["supply_chain_score"]),
                    "pq_risk_level": str(combined["pq_risk_level"]),
                }

            if cfg.include_decision_trace:
                out["decision_trace"] = list(combined.get("decision_trace") or [])[:64]

            if cfg.include_features:
                safe_feat: Dict[str, float] = {}
                for k, v in (combined.get("features") or {}).items():
                    if not isinstance(k, str):
                        continue
                    kk = _strip_unsafe_text(k, max_len=64).strip()
                    if not kk or _looks_like_secret_token(kk):
                        continue
                    fv = _finite_float(v)
                    if fv is None or fv < 0:
                        fv = 0.0
                    safe_feat[kk] = float(fv)
                out["features"] = safe_feat

            if cfg.emit_explain and cfg.profile != "HIGH_SEC":
                # explain can leak feature structure; block by default in HIGH_SEC
                explain = dict(sorted((combined.get("contributions") or {}).items(), key=lambda kv: kv[0]))
                out["explain"] = {"contributions": explain}

            if cfg.include_feature_snapshot:
                out["feature_snapshot"] = self._build_feature_snapshot(bundle, inp)

            if cfg.include_internal_state:
                out["internal_state"] = {
                    "warnings": list(bundle.warnings),
                    "state_key_mode": cfg.state_key_mode,
                    "state_key": None if (cfg.profile == "HIGH_SEC" and cfg.redact_identifiers_in_high_profile) else skey,
                    "recent_risk_avg": float(recent_info["recent_avg"]),
                    "recent_risk_p95": float(recent_info["recent_p95"]),
                    "window": int(cfg.window),
                }

            return self._enforce_output_budget(bundle, out)

        except Exception as e:
            # error budget update
            self._record_error_and_maybe_trip_budget(bundle, now_mono)

            fail_open = self._error_budget_allows_fail_open(bundle, now_mono)
            # In PROD, prefer degrade over allow when failing open (safer posture)
            if cfg.profile == "PROD" and fail_open:
                verdict = True
                action = "degrade"
                score = 0.5
            else:
                verdict = bool(fail_open)
                action = "allow" if verdict else "block"
                score = 0.0 if verdict else 1.0

            err_type = _strip_unsafe_text(type(e).__name__, max_len=64).strip() or "Exception"

            out: Dict[str, Any] = {
                "schema": "tcd.multivar.v2",
                "schema_version": cfg.schema_version,
                "verdict": verdict,
                "action": action,
                "score": score,
                "risk_score": score,
                "apt_score": 0.0,
                "insider_score": 0.0,
                "supply_chain_score": 0.0,
                "pq_risk_level": "error",
                "rules_triggered": ["detector_error"],
                "config_fingerprint": bundle.fp,
                "profile": cfg.profile,
                "timestamp": time.time(),
                "request_id": None,
            }

            if cfg.include_internal_state:
                out["internal_state"] = {
                    "warnings": list(bundle.warnings),
                    "error_type": err_type,
                    "fail_open_effective": bool(fail_open),
                }

            return self._enforce_output_budget(bundle, out)

    def detect_many(self, items: Iterable[Any]) -> List[Dict[str, Any]]:
        """
        Batch convenience API (no additional guarantees beyond per-call detect()).
        """
        return [self.detect(x) for x in items]