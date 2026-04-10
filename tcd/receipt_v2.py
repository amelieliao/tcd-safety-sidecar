from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import threading
import time
import unicodedata
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Literal

try:  # optional, explicit use only when selected by config
    from .crypto import Blake3Hash
except ImportError:  # pragma: no cover
    Blake3Hash = None  # type: ignore[assignment]


__all__ = [
    "AlwaysValidConfig",
    "EProcessState",
    "AlwaysValidRiskController",
]

# ---------------------------------------------------------------------------
# Constants / schemas / enums
# ---------------------------------------------------------------------------

Profile = Literal["DEV", "PROD", "FINREG", "LOCKDOWN"]
OnConfigError = Literal["fallback", "fail_closed", "raise"]
DecisionSource = Literal["controller", "strict", "strict_if_available_else_controller"]
ScoreToPMode = Literal["one_minus_score", "sigmoid_tail", "exp_tail"]
NewStreamPolicy = Literal["deny_new_when_full", "evict_lru"]
OnStateExhaustion = Literal["allow", "deny"]
StreamHashAlgorithm = Literal["hmac_sha256", "blake2b", "blake3"]

_CONTROLLER_NAME = "tcd.risk_av"
_CONTROLLER_VERSION = "1.0.0"
_SCHEMA = "tcd.eprocess.v2"

_ASCII_CTRL_RE = __import__("re").compile(r"[\x00-\x1F\x7F]")
_SAFE_LABEL_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9_.:\-]{0,63}$")
_SAFE_ID_RE = __import__("re").compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-@#]{0,255}$")
_HEX_RE = __import__("re").compile(r"^[0-9a-fA-F]{16,4096}$")

# Conservative secret detection for caller-provided metadata/context
_JWT_RE = __import__("re").compile(r"\b[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_PRIVKEY_RE = __import__("re").compile(r"-----BEGIN (?:RSA |EC |OPENSSH |)?PRIVATE KEY-----", __import__("re").IGNORECASE)
_BEARER_RE = __import__("re").compile(r"\bBearer\s+[A-Za-z0-9._\-~=+/]+\b", __import__("re").IGNORECASE)
_BASIC_RE = __import__("re").compile(r"\bBasic\s+[A-Za-z0-9+/=]{16,}\b", __import__("re").IGNORECASE)
_KV_SECRET_RE = __import__("re").compile(
    r"(?i)\b(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[:=]\s*([^\s,;]{8,})"
)

_FORBIDDEN_META_KEY_TOKENS = {
    "prompt",
    "completion",
    "messages",
    "message",
    "content",
    "body",
    "payload",
    "request",
    "response",
    "headers",
    "header",
    "cookie",
    "cookies",
    "authorization",
    "auth",
    "token",
    "secret",
    "password",
    "apikey",
    "api_key",
    "private",
    "privatekey",
}

_DEFAULT_SEVERITY_WEIGHTS = MappingProxyType(
    {
        "low": 1.0,
        "medium": 2.0,
        "high": 3.0,
        "critical": 4.0,
    }
)

_DEFAULT_P_TO_E_KAPPAS = (0.2, 0.5, 0.8)


# ---------------------------------------------------------------------------
# Low-level hardening helpers
# ---------------------------------------------------------------------------

def _has_unsafe_unicode(s: str) -> bool:
    for ch in s:
        if ch in ("\u2028", "\u2029"):
            return True
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Cs", "Zl", "Zp"):
            return True
    return False


def _strip_unsafe_text(s: Any, *, max_len: int) -> str:
    if not isinstance(s, str):
        return ""
    if len(s) > max_len:
        s = s[:max_len]

    if s.isascii():
        if _ASCII_CTRL_RE.search(s):
            s = _ASCII_CTRL_RE.sub("", s)
        return s.strip()

    if not _ASCII_CTRL_RE.search(s) and not _has_unsafe_unicode(s):
        if any(0x80 <= ord(ch) <= 0x9F for ch in s):
            pass
        else:
            return s.strip()

    out: list[str] = []
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
    return "".join(out).strip()


def _safe_label(v: Any, *, default: str) -> str:
    s = _strip_unsafe_text(v, max_len=64).lower()
    if not s or not _SAFE_LABEL_RE.fullmatch(s):
        return default
    return s


def _safe_id(v: Any, *, default: Optional[str], max_len: int = 256) -> Optional[str]:
    s = _strip_unsafe_text(v, max_len=max_len)
    if not s:
        return default
    if not _SAFE_ID_RE.fullmatch(s):
        return default
    return s


def _looks_like_secret(s: str) -> bool:
    if not s:
        return False
    if _JWT_RE.search(s):
        return True
    if _PRIVKEY_RE.search(s):
        return True
    if _BEARER_RE.search(s):
        return True
    if _BASIC_RE.search(s):
        return True
    if _KV_SECRET_RE.search(s):
        return True
    return False


def _coerce_float(v: Any) -> Optional[float]:
    if type(v) is bool:
        return None
    if isinstance(v, (int, float)):
        try:
            x = float(v)
        except Exception:
            return None
        return x if math.isfinite(x) else None
    if type(v) is str:
        s = v.strip()
        if not s or len(s) > 64:
            return None
        try:
            x = float(s)
        except Exception:
            return None
        return x if math.isfinite(x) else None
    return None


def _coerce_int(v: Any) -> Optional[int]:
    if type(v) is int:
        return int(v)
    if type(v) is str:
        s = v.strip()
        if not s or len(s) > 64:
            return None
        if s.startswith(("+", "-")):
            sign = s[0]
            digits = s[1:]
        else:
            sign = ""
            digits = s
        if not digits.isdigit():
            return None
        try:
            return int(sign + digits, 10)
        except Exception:
            return None
    return None


def _clamp_float(v: Any, *, default: float, lo: float, hi: float) -> float:
    x = _coerce_float(v)
    if x is None:
        return float(default)
    if x < lo:
        return float(lo)
    if x > hi:
        return float(hi)
    return float(x)


def _clamp_int(v: Any, *, default: int, lo: int, hi: int) -> int:
    x = _coerce_int(v)
    if x is None:
        return int(default)
    if x < lo:
        return int(lo)
    if x > hi:
        return int(hi)
    return int(x)


def _safe_exp(x: float) -> float:
    try:
        if x > 700.0:
            return float("inf")
        if x < -700.0:
            return 0.0
        return math.exp(x)
    except Exception:
        return float("nan")


def _canon_json(obj: Any) -> str:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _parse_key_material(v: Any) -> Optional[bytes]:
    """
    Supports:
      - bytes
      - "hex:<...>"
      - "b64:<...>"
      - plain hex
      - plain base64url
    """
    if type(v) is bytes:
        if 1 <= len(v) <= 4096:
            return bytes(v)
        return None

    if type(v) is not str:
        return None

    s = _strip_unsafe_text(v, max_len=4096)
    if not s:
        return None

    if s.lower().startswith("hex:"):
        hx = s[4:].strip()
        if not _HEX_RE.fullmatch(hx) or len(hx) % 2 != 0:
            return None
        try:
            return bytes.fromhex(hx)
        except Exception:
            return None

    if s.lower().startswith("b64:"):
        raw = s[4:].strip()
        try:
            pad = "=" * ((4 - (len(raw) % 4)) % 4)
            out = base64.urlsafe_b64decode((raw + pad).encode("utf-8", errors="strict"))
            return out if out else None
        except Exception:
            return None

    if _HEX_RE.fullmatch(s) and len(s) % 2 == 0:
        try:
            return bytes.fromhex(s)
        except Exception:
            return None

    try:
        pad = "=" * ((4 - (len(s) % 4)) % 4)
        out = base64.urlsafe_b64decode((s + pad).encode("utf-8", errors="strict"))
        return out if out else None
    except Exception:
        return None


def _logsumexp(values: Sequence[float]) -> float:
    if not values:
        return float("-inf")
    m = max(values)
    if not math.isfinite(m):
        return m
    acc = 0.0
    for v in values:
        acc += math.exp(v - m)
    if acc <= 0.0 or not math.isfinite(acc):
        return m
    return m + math.log(acc)


def _key_tokenize(k: str) -> Tuple[str, ...]:
    s = _strip_unsafe_text(k, max_len=128)
    if not s:
        return tuple()
    # split camel-ish and punctuation-ish without importing regex extras
    out: list[str] = []
    cur: list[str] = []
    prev_is_alnum = False
    for ch in s:
        if ch.isalnum():
            if prev_is_alnum:
                cur.append(ch.lower())
            else:
                if cur:
                    out.append("".join(cur))
                cur = [ch.lower()]
                prev_is_alnum = True
        else:
            if cur:
                out.append("".join(cur))
                cur = []
            prev_is_alnum = False
    if cur:
        out.append("".join(cur))
    fused = "".join(out)
    if fused and fused not in out:
        out.append(fused)
    return tuple(x for x in out if x)


class _JsonBudget:
    __slots__ = ("max_nodes", "max_items", "max_depth", "max_str_total", "nodes", "str_used")

    def __init__(self, *, max_nodes: int, max_items: int, max_depth: int, max_str_total: int):
        self.max_nodes = max_nodes
        self.max_items = max_items
        self.max_depth = max_depth
        self.max_str_total = max_str_total
        self.nodes = 0
        self.str_used = 0

    def take_node(self) -> bool:
        self.nodes += 1
        return self.nodes <= self.max_nodes

    def take_str(self, n: int) -> bool:
        self.str_used += n
        return self.str_used <= self.max_str_total


def _json_sanitize(
    obj: Any,
    *,
    budget: _JsonBudget,
    depth: int,
    redact_secrets: bool,
) -> Any:
    """
    JSON-safe sanitizer that does not call str()/repr() on unknown objects.
    Only exact builtins are traversed.
    """
    if not budget.take_node():
        return "[truncated]"

    t = type(obj)

    if obj is None:
        return None
    if t is bool:
        return bool(obj)
    if t is int:
        if obj.bit_length() > 256:
            return "[int:oversize]"
        return int(obj)
    if t is float:
        return float(obj) if math.isfinite(obj) else None
    if t is str:
        s = _strip_unsafe_text(obj, max_len=512)
        if redact_secrets and _looks_like_secret(s):
            s = "[redacted]"
        if len(s) > 512:
            s = s[:512] + "...[truncated]"
        if not budget.take_str(len(s)):
            return "[truncated]"
        return s
    if t in (bytes, bytearray):
        return f"[bytes:{len(obj)}]"

    if depth >= budget.max_depth:
        return "[truncated-depth]"

    if t is dict:
        out: Dict[str, Any] = {}
        n = 0
        for k, v in obj.items():
            if n >= budget.max_items:
                out["_tcd_truncated"] = True
                break
            if type(k) is not str:
                continue
            kk = _safe_id(k, default=None, max_len=128)
            if kk is None:
                continue
            toks = _key_tokenize(kk)
            if any(tok in _FORBIDDEN_META_KEY_TOKENS for tok in toks):
                continue
            out[kk] = _json_sanitize(
                v,
                budget=budget,
                depth=depth + 1,
                redact_secrets=redact_secrets,
            )
            n += 1
        return out

    if t in (list, tuple):
        out_list = []
        for i, item in enumerate(obj):
            if i >= budget.max_items:
                out_list.append("[truncated]")
                break
            out_list.append(
                _json_sanitize(
                    item,
                    budget=budget,
                    depth=depth + 1,
                    redact_secrets=redact_secrets,
                )
            )
        return out_list

    return f"[type:{t.__name__}]"


# ---------------------------------------------------------------------------
# Config / state / bundle
# ---------------------------------------------------------------------------

@dataclass
class AlwaysValidConfig:
    """
    Research-grade content-agnostic, stream-centric statistical controller.

    This is no longer a bare-bones e-process skeleton. It now supports:
      - immutable compiled policy bundle with config fingerprint
      - strict vs controller evidence tracks
      - valid p->e power-mixture calibrators for direct p-values
      - heuristic score->p calibration for score-only inputs
      - alpha-wealth control with optional controller freeze
      - hysteretic triggering
      - bounded, privacy-aware stream state store
      - dual clocks for auditability
      - JSON-safe bounded outputs
    """

    schema_version: int = 2
    enabled: bool = True
    profile: Profile = "PROD"
    label: str = "default"
    policyset_ref: Optional[str] = None
    on_config_error: OnConfigError = "fail_closed"

    # Decision semantics
    decision_source: DecisionSource = "controller"
    block_on_trigger: bool = False

    # Trigger thresholds / hysteresis
    threshold_log_e: float = 4.0
    threshold_clear_log_e: float = 3.0
    max_log_e: float = 32.0
    min_log_e: float = -32.0
    max_step_abs_log_e: float = 16.0

    # Alpha-wealth / controller budgeting
    alpha_base: float = 0.05
    alpha_wealth_init: float = 1.0
    alpha_wealth_cap: float = 1.0
    alpha_spend_per_decision: float = 0.0
    alpha_reward_per_safe_decision: float = 0.0
    freeze_on_exhaust: bool = False

    # Weighting
    max_weight: float = 10.0
    severity_weights: Dict[str, float] = field(default_factory=lambda: dict(_DEFAULT_SEVERITY_WEIGHTS))

    # P-value handling
    min_p_value: float = 1e-12
    max_p_value: float = 1.0

    # Direct p -> e calibrator
    p_to_e_kappas: Tuple[float, ...] = _DEFAULT_P_TO_E_KAPPAS
    p_to_e_weights: Optional[Tuple[float, ...]] = None

    # Score -> pseudo-p mapping
    score_to_p_mode: ScoreToPMode = "one_minus_score"
    score_reference: float = 0.5
    score_scale: float = 10.0
    heuristic_p_weight: float = 0.5

    # Stream store governance
    max_streams: int = 100_000
    idle_ttl_s: float = 24.0 * 3600.0
    stream_cleanup_budget: int = 8
    new_stream_policy: NewStreamPolicy = "deny_new_when_full"
    on_state_exhaustion: OnStateExhaustion = "deny"
    evict_only_inactive_streams: bool = True

    # Stream hashing / pseudonymization
    stream_hash_algorithm: StreamHashAlgorithm = "hmac_sha256"
    stream_hash_key: Optional[Any] = None
    stream_hash_key_id: Optional[str] = None
    auto_ephemeral_hash_key_if_missing: bool = True
    min_stream_hash_key_bytes: int = 16

    # Time
    monotonic_fn: Optional[Callable[[], Any]] = None
    wall_time_fn: Optional[Callable[[], Any]] = None

    # Diagnostics / history / output budgets
    history_window: int = 64
    retain_history: bool = True
    include_history_in_snapshot: bool = False
    ewma_alpha: float = 0.1

    meta_max_nodes: int = 256
    meta_max_items: int = 64
    meta_max_depth: int = 4
    meta_max_str_total: int = 8192

    def normalized_copy(self) -> "AlwaysValidConfig":
        c = AlwaysValidConfig()

        c.schema_version = _clamp_int(self.schema_version, default=2, lo=1, hi=1_000_000)
        prof = _safe_label(self.profile, default="prod").upper()
        if prof not in {"DEV", "PROD", "FINREG", "LOCKDOWN"}:
            prof = "PROD"
        c.profile = prof  # type: ignore[assignment]

        c.enabled = bool(self.enabled)
        c.label = _safe_label(self.label, default="default")
        c.policyset_ref = _safe_id(self.policyset_ref, default=None, max_len=128)
        c.on_config_error = self.on_config_error if self.on_config_error in {"fallback", "fail_closed", "raise"} else "fail_closed"

        c.decision_source = (
            self.decision_source
            if self.decision_source in {"controller", "strict", "strict_if_available_else_controller"}
            else "controller"
        )
        c.block_on_trigger = bool(self.block_on_trigger)

        c.threshold_log_e = _clamp_float(self.threshold_log_e, default=4.0, lo=0.0, hi=1_000_000.0)
        c.threshold_clear_log_e = _clamp_float(self.threshold_clear_log_e, default=3.0, lo=-1_000_000.0, hi=c.threshold_log_e)
        if c.threshold_clear_log_e > c.threshold_log_e:
            c.threshold_clear_log_e = c.threshold_log_e

        c.max_log_e = _clamp_float(self.max_log_e, default=32.0, lo=0.0, hi=1_000_000.0)
        c.min_log_e = _clamp_float(self.min_log_e, default=-32.0, lo=-1_000_000.0, hi=0.0)
        if c.min_log_e > c.max_log_e:
            c.min_log_e, c.max_log_e = c.max_log_e, c.min_log_e
        c.max_step_abs_log_e = _clamp_float(self.max_step_abs_log_e, default=16.0, lo=0.0, hi=1_000_000.0)

        c.alpha_base = _clamp_float(self.alpha_base, default=0.05, lo=1e-12, hi=1.0)
        c.alpha_wealth_init = _clamp_float(self.alpha_wealth_init, default=1.0, lo=0.0, hi=1_000_000.0)
        c.alpha_wealth_cap = _clamp_float(self.alpha_wealth_cap, default=max(1.0, c.alpha_wealth_init), lo=0.0, hi=1_000_000.0)
        if c.alpha_wealth_cap < c.alpha_wealth_init:
            c.alpha_wealth_cap = c.alpha_wealth_init
        c.alpha_spend_per_decision = _clamp_float(self.alpha_spend_per_decision, default=0.0, lo=0.0, hi=1_000_000.0)
        c.alpha_reward_per_safe_decision = _clamp_float(self.alpha_reward_per_safe_decision, default=0.0, lo=0.0, hi=1_000_000.0)
        c.freeze_on_exhaust = bool(self.freeze_on_exhaust)

        c.max_weight = _clamp_float(self.max_weight, default=10.0, lo=0.0, hi=1_000_000.0)

        sev: Dict[str, float] = {}
        if isinstance(self.severity_weights, Mapping):
            for k, v in self.severity_weights.items():
                kk = _safe_label(k, default="")
                if not kk:
                    continue
                vv = _clamp_float(v, default=1.0, lo=0.0, hi=max(1.0, c.max_weight))
                sev[kk] = vv
        if not sev:
            sev = dict(_DEFAULT_SEVERITY_WEIGHTS)
        c.severity_weights = sev

        c.min_p_value = _clamp_float(self.min_p_value, default=1e-12, lo=1e-300, hi=1.0)
        c.max_p_value = _clamp_float(self.max_p_value, default=1.0, lo=c.min_p_value, hi=1.0)
        if c.max_p_value < c.min_p_value:
            c.max_p_value = c.min_p_value

        kappas: list[float] = []
        if isinstance(self.p_to_e_kappas, tuple):
            seq = self.p_to_e_kappas
        elif isinstance(self.p_to_e_kappas, list):
            seq = tuple(self.p_to_e_kappas)
        else:
            seq = _DEFAULT_P_TO_E_KAPPAS
        for x in seq:
            xv = _coerce_float(x)
            if xv is None:
                continue
            if 0.0 < xv < 1.0:
                kappas.append(float(xv))
        if not kappas:
            kappas = list(_DEFAULT_P_TO_E_KAPPAS)
        c.p_to_e_kappas = tuple(kappas)

        if isinstance(self.p_to_e_weights, tuple):
            wseq = self.p_to_e_weights
        elif isinstance(self.p_to_e_weights, list):
            wseq = tuple(self.p_to_e_weights)
        else:
            wseq = None
        if wseq is not None and len(wseq) == len(c.p_to_e_kappas):
            ws: list[float] = []
            for x in wseq:
                xv = _coerce_float(x)
                if xv is None or xv < 0.0:
                    ws.append(0.0)
                else:
                    ws.append(float(xv))
            tot = sum(ws)
            if tot > 0.0 and math.isfinite(tot):
                c.p_to_e_weights = tuple(x / tot for x in ws)
            else:
                c.p_to_e_weights = None
        else:
            c.p_to_e_weights = None

        c.score_to_p_mode = (
            self.score_to_p_mode
            if self.score_to_p_mode in {"one_minus_score", "sigmoid_tail", "exp_tail"}
            else "one_minus_score"
        )
        c.score_reference = _clamp_float(self.score_reference, default=0.5, lo=-1_000_000.0, hi=1_000_000.0)
        c.score_scale = _clamp_float(self.score_scale, default=10.0, lo=1e-6, hi=1_000_000.0)
        c.heuristic_p_weight = _clamp_float(self.heuristic_p_weight, default=0.5, lo=0.0, hi=1.0)

        c.max_streams = _clamp_int(self.max_streams, default=100_000, lo=1, hi=10_000_000)
        c.idle_ttl_s = _clamp_float(self.idle_ttl_s, default=24.0 * 3600.0, lo=0.0, hi=1_000_000_000.0)
        c.stream_cleanup_budget = _clamp_int(self.stream_cleanup_budget, default=8, lo=0, hi=10_000)
        c.new_stream_policy = self.new_stream_policy if self.new_stream_policy in {"deny_new_when_full", "evict_lru"} else "deny_new_when_full"
        c.on_state_exhaustion = self.on_state_exhaustion if self.on_state_exhaustion in {"allow", "deny"} else "deny"
        c.evict_only_inactive_streams = bool(self.evict_only_inactive_streams)

        c.stream_hash_algorithm = (
            self.stream_hash_algorithm
            if self.stream_hash_algorithm in {"hmac_sha256", "blake2b", "blake3"}
            else "hmac_sha256"
        )
        c.stream_hash_key = self.stream_hash_key
        c.stream_hash_key_id = _safe_id(self.stream_hash_key_id, default=None, max_len=64)
        c.auto_ephemeral_hash_key_if_missing = bool(self.auto_ephemeral_hash_key_if_missing)
        c.min_stream_hash_key_bytes = _clamp_int(self.min_stream_hash_key_bytes, default=16, lo=1, hi=4096)

        c.monotonic_fn = self.monotonic_fn if callable(self.monotonic_fn) else None
        c.wall_time_fn = self.wall_time_fn if callable(self.wall_time_fn) else None

        c.history_window = _clamp_int(self.history_window, default=64, lo=0, hi=4096)
        c.retain_history = bool(self.retain_history)
        c.include_history_in_snapshot = bool(self.include_history_in_snapshot)
        c.ewma_alpha = _clamp_float(self.ewma_alpha, default=0.1, lo=0.0, hi=1.0)

        c.meta_max_nodes = _clamp_int(self.meta_max_nodes, default=256, lo=16, hi=1_000_000)
        c.meta_max_items = _clamp_int(self.meta_max_items, default=64, lo=1, hi=4096)
        c.meta_max_depth = _clamp_int(self.meta_max_depth, default=4, lo=1, hi=32)
        c.meta_max_str_total = _clamp_int(self.meta_max_str_total, default=8192, lo=256, hi=10_000_000)

        # profile-aware tightening
        if c.profile in {"FINREG", "LOCKDOWN"}:
            if c.on_config_error == "fallback":
                c.on_config_error = "fail_closed"
            if c.stream_hash_algorithm == "hmac_sha256" and c.auto_ephemeral_hash_key_if_missing is False and c.stream_hash_key is None:
                # compile stage will produce a hard error; this just keeps semantics explicit
                pass
            c.include_history_in_snapshot = False
            c.meta_max_items = min(c.meta_max_items, 32)
            c.meta_max_nodes = min(c.meta_max_nodes, 256)
            c.max_streams = min(c.max_streams, 1_000_000)

        return c

    def fingerprint(self) -> str:
        c = self.normalized_copy()
        payload = {
            "schema_version": c.schema_version,
            "enabled": c.enabled,
            "profile": c.profile,
            "label": c.label,
            "policyset_ref": c.policyset_ref,
            "on_config_error": c.on_config_error,
            "decision_source": c.decision_source,
            "block_on_trigger": c.block_on_trigger,
            "threshold_log_e": c.threshold_log_e,
            "threshold_clear_log_e": c.threshold_clear_log_e,
            "max_log_e": c.max_log_e,
            "min_log_e": c.min_log_e,
            "max_step_abs_log_e": c.max_step_abs_log_e,
            "alpha_base": c.alpha_base,
            "alpha_wealth_init": c.alpha_wealth_init,
            "alpha_wealth_cap": c.alpha_wealth_cap,
            "alpha_spend_per_decision": c.alpha_spend_per_decision,
            "alpha_reward_per_safe_decision": c.alpha_reward_per_safe_decision,
            "freeze_on_exhaust": c.freeze_on_exhaust,
            "max_weight": c.max_weight,
            "severity_weights": dict(sorted(c.severity_weights.items())),
            "min_p_value": c.min_p_value,
            "max_p_value": c.max_p_value,
            "p_to_e_kappas": list(c.p_to_e_kappas),
            "p_to_e_weights": list(c.p_to_e_weights) if c.p_to_e_weights else None,
            "score_to_p_mode": c.score_to_p_mode,
            "score_reference": c.score_reference,
            "score_scale": c.score_scale,
            "heuristic_p_weight": c.heuristic_p_weight,
            "max_streams": c.max_streams,
            "idle_ttl_s": c.idle_ttl_s,
            "stream_cleanup_budget": c.stream_cleanup_budget,
            "new_stream_policy": c.new_stream_policy,
            "on_state_exhaustion": c.on_state_exhaustion,
            "evict_only_inactive_streams": c.evict_only_inactive_streams,
            "stream_hash_algorithm": c.stream_hash_algorithm,
            "stream_hash_key_id": c.stream_hash_key_id,
            "auto_ephemeral_hash_key_if_missing": c.auto_ephemeral_hash_key_if_missing,
            "min_stream_hash_key_bytes": c.min_stream_hash_key_bytes,
            "history_window": c.history_window,
            "retain_history": c.retain_history,
            "include_history_in_snapshot": c.include_history_in_snapshot,
            "ewma_alpha": c.ewma_alpha,
            "meta_max_nodes": c.meta_max_nodes,
            "meta_max_items": c.meta_max_items,
            "meta_max_depth": c.meta_max_depth,
            "meta_max_str_total": c.meta_max_str_total,
        }
        raw = _canon_json(payload).encode("utf-8", errors="strict")
        d = hashlib.sha256(raw).hexdigest()
        return f"cfg1:{d}"


@dataclass(slots=True)
class EProcessState:
    """
    Per-stream internal state.

    Public callers should not mutate instances returned from internal store;
    snapshots exposed by the controller are always rebuilt into plain dicts.
    """

    strict_log_e: float = 0.0
    controller_log_e: float = 0.0
    alpha_wealth: float = 1.0

    decisions: int = 0
    triggers: int = 0
    active: bool = False
    frozen: bool = False
    last_trigger_step: Optional[int] = None
    exhausted_step: Optional[int] = None

    last_update_mono_ns: int = 0
    last_update_unix_ns: int = 0

    last_p_value: float = 1.0
    last_p_source: str = "neutral"
    last_score: Optional[float] = None

    ewma_score: Optional[float] = None
    ewma_neglogp: float = 0.0

    min_p_value: float = 1.0
    min_p_value_step: Optional[int] = None
    max_score: Optional[float] = None
    max_score_step: Optional[int] = None

    direct_p_steps: int = 0
    heuristic_p_steps: int = 0
    neutral_steps: int = 0

    small_p_count_05: int = 0
    small_p_count_01: int = 0
    small_p_count_001: int = 0

    fisher_stat: float = 0.0
    fisher_df: int = 0

    history_p: deque[float] = field(default_factory=deque)
    history_score: deque[float] = field(default_factory=deque)
    history_log_e: deque[float] = field(default_factory=deque)


@dataclass(frozen=True, slots=True)
class _CompiledBundle:
    version: int
    updated_at_unix_ns: int
    cfg_fp: str
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    enabled: bool
    profile: Profile
    label: str
    policyset_ref: Optional[str]
    on_config_error: OnConfigError

    decision_source: DecisionSource
    block_on_trigger: bool

    threshold_log_e: float
    threshold_clear_log_e: float
    max_log_e: float
    min_log_e: float
    max_step_abs_log_e: float

    alpha_base: float
    alpha_wealth_init: float
    alpha_wealth_cap: float
    alpha_spend_per_decision: float
    alpha_reward_per_safe_decision: float
    freeze_on_exhaust: bool

    max_weight: float
    severity_weights: Mapping[str, float]

    min_p_value: float
    max_p_value: float
    p_to_e_kappas: Tuple[float, ...]
    p_to_e_weights: Tuple[float, ...]
    score_to_p_mode: ScoreToPMode
    score_reference: float
    score_scale: float
    heuristic_p_weight: float

    max_streams: int
    idle_ttl_ns: int
    stream_cleanup_budget: int
    new_stream_policy: NewStreamPolicy
    on_state_exhaustion: OnStateExhaustion
    evict_only_inactive_streams: bool

    stream_hash_algorithm: StreamHashAlgorithm
    stream_hash_key: Optional[bytes]
    stream_hash_key_id: Optional[str]
    stream_hash_mode: str

    history_window: int
    retain_history: bool
    include_history_in_snapshot: bool
    ewma_alpha: float

    meta_max_nodes: int
    meta_max_items: int
    meta_max_depth: int
    meta_max_str_total: int

    monotonic_fn: Callable[[], Any]
    wall_time_fn: Callable[[], Any]


# ---------------------------------------------------------------------------
# Controller
# ---------------------------------------------------------------------------

class AlwaysValidRiskController:
    """
    Research-grade anytime-valid / e-process statistical platform.

    Key properties:
      - immutable compiled config bundle + atomic config swap
      - strict direct-p evidence process and richer controller process
      - bounded, privacy-aware stream state store
      - dual clocks for replay / audit friendliness
      - JSON-safe bounded outputs, no raw object leakage
      - content-agnostic: never inspects request payloads
    """

    def __init__(self, config: Optional[AlwaysValidConfig] = None, **overrides: Any) -> None:
        base = config or AlwaysValidConfig()
        for key, value in overrides.items():
            if hasattr(base, key):
                try:
                    setattr(base, key, value)
                except Exception:
                    pass

        self._lock = threading.RLock()
        self._bundle_lock = threading.RLock()
        self._instance_id = os.urandom(8).hex()
        self._decision_seq = 0

        bundle = self._compile_bundle(base, previous=None)
        if bundle.errors and bundle.on_config_error == "raise":
            raise ValueError("invalid AlwaysValidConfig: " + "; ".join(bundle.errors[:3]))
        self._bundle: _CompiledBundle = bundle

        self._streams: Dict[str, EProcessState] = {}
        self._lru: "OrderedDict[str, None]" = OrderedDict()

        # health counters
        self._state_capacity_denies = 0
        self._config_error_denies = 0
        self._compaction_count = 0
        self._evicted_streams = 0
        self._idle_evicted_streams = 0
        self._allowed_steps = 0
        self._blocked_steps = 0

    # ------------------------------------------------------------------
    # Public config API
    # ------------------------------------------------------------------

    @property
    def config(self) -> AlwaysValidConfig:
        with self._bundle_lock:
            # return normalized external-facing copy
            return AlwaysValidConfig().normalized_copy() if False else self._config_from_bundle(self._bundle)

    @property
    def cfg_fp(self) -> str:
        return self._bundle.cfg_fp

    @property
    def bundle_version(self) -> int:
        return self._bundle.version

    def set_config(self, config: AlwaysValidConfig) -> None:
        with self._bundle_lock:
            old = self._bundle
            new = self._compile_bundle(config, previous=old)
            if new.errors and new.on_config_error == "raise":
                raise ValueError("invalid AlwaysValidConfig: " + "; ".join(new.errors[:3]))
            self._bundle = new

        # If stream hash identity changed, we cannot safely preserve state.
        hash_identity_old = (old.stream_hash_algorithm, old.stream_hash_key, old.stream_hash_key_id, old.stream_hash_mode)
        hash_identity_new = (new.stream_hash_algorithm, new.stream_hash_key, new.stream_hash_key_id, new.stream_hash_mode)

        with self._lock:
            if hash_identity_old != hash_identity_new:
                self._streams.clear()
                self._lru.clear()
                return

            if old.history_window != new.history_window:
                for st in self._streams.values():
                    st.history_p = deque(list(st.history_p)[-new.history_window:], maxlen=new.history_window)
                    st.history_score = deque(list(st.history_score)[-new.history_window:], maxlen=new.history_window)
                    st.history_log_e = deque(list(st.history_log_e)[-new.history_window:], maxlen=new.history_window)

            self._compact_locked(now_mono_ns=self._mono_ns(new), budget=max(16, new.stream_cleanup_budget * 4))

    def diagnostics(self) -> Dict[str, Any]:
        b = self._bundle
        return {
            "schema": _SCHEMA,
            "controller": _CONTROLLER_NAME,
            "version": _CONTROLLER_VERSION,
            "instance_id": self._instance_id,
            "cfg_fp": b.cfg_fp,
            "bundle_version": b.version,
            "updated_at_unix_ns": b.updated_at_unix_ns,
            "profile": b.profile,
            "label": b.label,
            "policyset_ref": b.policyset_ref,
            "enabled": b.enabled,
            "on_config_error": b.on_config_error,
            "error_count": len(b.errors),
            "warning_count": len(b.warnings),
            "errors": list(b.errors[:50]),
            "warnings": list(b.warnings[:50]),
            "stream_hash_algorithm": b.stream_hash_algorithm,
            "stream_hash_key_id": b.stream_hash_key_id,
            "stream_hash_mode": b.stream_hash_mode,
            "state_scope": "local_best_effort",
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def step(
        self,
        request: Any = None,
        *,
        stream_id: Optional[str] = None,
        p_value: Optional[float] = None,
        score: Optional[float] = None,
        weight: float = 1.0,
        severity: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
        **ctx: Any,
    ) -> Dict[str, Any]:
        b = self._bundle
        now_mono_ns = self._mono_ns(b)
        now_unix_ns = self._wall_ns(b)

        sid = self._sanitize_stream_id(stream_id)
        stream_hash = self._canonical_stream_hash(b, sid)

        meta_s = self._sanitize_meta_dict(b, meta or {})
        ctx_s = self._sanitize_meta_dict(b, ctx or {})

        # Disabled mode
        if not b.enabled:
            return self._build_step_result(
                bundle=b,
                sid=sid,
                stream_hash=stream_hash,
                state=None,
                allowed=True,
                reason="disabled",
                p_value_out=self._normalize_p_like(b, p_value, score)[0],
                p_source="disabled",
                score_out=self._normalize_score(score),
                effective_weight=0.0,
                selected_source=b.decision_source,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
                meta_s=meta_s,
                ctx_s=ctx_s,
                has_request=request is not None,
            )

        # Config error behavior
        if b.errors:
            if b.on_config_error == "raise":
                raise RuntimeError("AlwaysValidRiskController bundle has compile errors")
            if b.on_config_error == "fail_closed":
                with self._lock:
                    self._config_error_denies += 1
                    self._blocked_steps += 1
                    self._decision_seq += 1
                    seq = self._decision_seq
                return self._build_step_result(
                    bundle=b,
                    sid=sid,
                    stream_hash=stream_hash,
                    state=None,
                    allowed=False,
                    reason="config_error",
                    p_value_out=self._normalize_p_like(b, p_value, score)[0],
                    p_source="config_error",
                    score_out=self._normalize_score(score),
                    effective_weight=0.0,
                    selected_source=b.decision_source,
                    now_mono_ns=now_mono_ns,
                    now_unix_ns=now_unix_ns,
                    meta_s=meta_s,
                    ctx_s=ctx_s,
                    has_request=request is not None,
                    decision_seq=seq,
                )

        p_like, p_source, score_out = self._normalize_p_like(b, p_value, score)
        eff_weight = self._effective_weight(b, weight, severity)

        with self._lock:
            self._compact_locked(now_mono_ns, budget=b.stream_cleanup_budget)

            st = self._streams.get(stream_hash)
            if st is None:
                admitted = self._admit_stream_locked(b, now_mono_ns)
                if not admitted:
                    allowed = (b.on_state_exhaustion == "allow")
                    if allowed:
                        self._allowed_steps += 1
                    else:
                        self._blocked_steps += 1
                        self._state_capacity_denies += 1
                    self._decision_seq += 1
                    seq = self._decision_seq
                    return self._build_step_result(
                        bundle=b,
                        sid=sid,
                        stream_hash=stream_hash,
                        state=None,
                        allowed=allowed,
                        reason="state_capacity_exhausted",
                        p_value_out=p_like,
                        p_source=p_source,
                        score_out=score_out,
                        effective_weight=eff_weight,
                        selected_source=b.decision_source,
                        now_mono_ns=now_mono_ns,
                        now_unix_ns=now_unix_ns,
                        meta_s=meta_s,
                        ctx_s=ctx_s,
                        has_request=request is not None,
                        decision_seq=seq,
                    )

                st = self._make_initial_state(b, now_mono_ns, now_unix_ns)
                self._streams[stream_hash] = st
                self._lru[stream_hash] = None

            # update / touch LRU
            self._lru.pop(stream_hash, None)
            self._lru[stream_hash] = None

            self._update_state(
                bundle=b,
                state=st,
                p_like=p_like,
                p_source=p_source,
                score=score_out,
                effective_weight=eff_weight,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
            )

            selected_log_e, selected_source = self._selected_log_e(b, st)
            prev_active = st.active
            if not prev_active:
                active = bool(selected_log_e >= b.threshold_log_e)
                newly_triggered = active
            else:
                active = bool(selected_log_e >= b.threshold_clear_log_e)
                newly_triggered = False

            st.active = active
            if newly_triggered:
                st.triggers += 1
                st.last_trigger_step = st.decisions

            # alpha reward only for controller-safe non-active steps
            if (not active) and (not st.frozen) and b.alpha_reward_per_safe_decision > 0.0:
                st.alpha_wealth = min(
                    b.alpha_wealth_cap,
                    st.alpha_wealth + b.alpha_reward_per_safe_decision,
                )

            if active and b.block_on_trigger:
                allowed = False
                reason = "e-process-trigger"
                self._blocked_steps += 1
            elif active:
                allowed = True
                reason = "e-process-trigger-advisory"
                self._allowed_steps += 1
            else:
                allowed = True
                reason = "always-valid"
                self._allowed_steps += 1

            self._decision_seq += 1
            seq = self._decision_seq

        return self._build_step_result(
            bundle=b,
            sid=sid,
            stream_hash=stream_hash,
            state=st,
            allowed=allowed,
            reason=reason,
            p_value_out=p_like,
            p_source=p_source,
            score_out=score_out,
            effective_weight=eff_weight,
            selected_source=selected_source,
            now_mono_ns=now_mono_ns,
            now_unix_ns=now_unix_ns,
            meta_s=meta_s,
            ctx_s=ctx_s,
            has_request=request is not None,
            decision_seq=seq,
        )

    def step_many(self, items: Sequence[Mapping[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, Mapping):
                out.append(self.step())
                continue
            request = item.get("request")
            kwargs: Dict[str, Any] = {}
            for k, v in item.items():
                if k == "request":
                    continue
                kwargs[k] = v
            out.append(self.step(request=request, **kwargs))
        return out

    def snapshot(self, stream_id: Optional[str] = None) -> Dict[str, Any]:
        b = self._bundle
        sid = self._sanitize_stream_id(stream_id)
        stream_hash = self._canonical_stream_hash(b, sid)
        now_mono_ns = self._mono_ns(b)
        now_unix_ns = self._wall_ns(b)

        with self._lock:
            st = self._streams.get(stream_hash)

        return self._build_snapshot_result(
            bundle=b,
            sid=sid,
            stream_hash=stream_hash,
            state=st,
            now_mono_ns=now_mono_ns,
            now_unix_ns=now_unix_ns,
        )

    def reset_stream(self, stream_id: str) -> bool:
        b = self._bundle
        sid = self._sanitize_stream_id(stream_id)
        h = self._canonical_stream_hash(b, sid)
        with self._lock:
            existed = h in self._streams
            self._streams.pop(h, None)
            self._lru.pop(h, None)
            return existed

    def clear(self) -> None:
        with self._lock:
            self._streams.clear()
            self._lru.clear()

    def all_stream_ids(self) -> Dict[str, int]:
        with self._lock:
            return {sh: int(st.decisions) for sh, st in self._streams.items()}

    def streams_overview(
        self,
        *,
        limit: int = 100,
        sort_by: str = "controller_log_e",
    ) -> Dict[str, Any]:
        b = self._bundle
        lim = _clamp_int(limit, default=100, lo=1, hi=10_000)
        now_mono_ns = self._mono_ns(b)
        now_unix_ns = self._wall_ns(b)

        with self._lock:
            rows = []
            for stream_hash, st in self._streams.items():
                sel_log_e, sel_source = self._selected_log_e(b, st)
                rows.append(
                    {
                        "stream_hash": stream_hash,
                        "selected_source": sel_source,
                        "selected_log_e": float(sel_log_e),
                        "selected_e_value": _safe_exp(sel_log_e),
                        "strict_log_e": float(st.strict_log_e),
                        "controller_log_e": float(st.controller_log_e),
                        "active": bool(st.active),
                        "frozen": bool(st.frozen),
                        "alpha_wealth": float(st.alpha_wealth),
                        "decisions": int(st.decisions),
                        "triggers": int(st.triggers),
                        "last_trigger_step": st.last_trigger_step,
                        "direct_p_steps": int(st.direct_p_steps),
                        "heuristic_p_steps": int(st.heuristic_p_steps),
                        "last_update_mono_ns": int(st.last_update_mono_ns),
                        "last_update_unix_ns": int(st.last_update_unix_ns),
                    }
                )

        key_name = sort_by if sort_by in {"selected_log_e", "strict_log_e", "controller_log_e", "decisions", "triggers"} else "controller_log_e"
        rows.sort(key=lambda r: (r.get(key_name, 0.0), r["decisions"]), reverse=True)
        rows = rows[:lim]

        return {
            "schema": _SCHEMA,
            "controller": {
                "name": _CONTROLLER_NAME,
                "version": _CONTROLLER_VERSION,
                "instance_id": self._instance_id,
                "cfg_fp": b.cfg_fp,
                "bundle_version": b.version,
                "profile": b.profile,
                "label": b.label,
                "policyset_ref": b.policyset_ref,
                "ts_monotonic_ns": now_mono_ns,
                "ts_unix_ns": now_unix_ns,
                "enabled": b.enabled,
            },
            "streams": rows,
        }

    def controller_health(self) -> Dict[str, Any]:
        b = self._bundle
        now_mono_ns = self._mono_ns(b)
        now_unix_ns = self._wall_ns(b)
        with self._lock:
            active_count = 0
            frozen_count = 0
            for st in self._streams.values():
                if st.active:
                    active_count += 1
                if st.frozen:
                    frozen_count += 1
            stream_count = len(self._streams)

        return {
            "schema": _SCHEMA,
            "controller": {
                "name": _CONTROLLER_NAME,
                "version": _CONTROLLER_VERSION,
                "instance_id": self._instance_id,
                "cfg_fp": b.cfg_fp,
                "bundle_version": b.version,
                "ts_monotonic_ns": now_mono_ns,
                "ts_unix_ns": now_unix_ns,
                "profile": b.profile,
                "label": b.label,
                "policyset_ref": b.policyset_ref,
                "enabled": b.enabled,
                "state_scope": "local_best_effort",
            },
            "health": {
                "stream_count": stream_count,
                "active_stream_count": active_count,
                "frozen_stream_count": frozen_count,
                "config_error_count": len(b.errors),
                "config_warning_count": len(b.warnings),
                "state_capacity_denies": int(self._state_capacity_denies),
                "config_error_denies": int(self._config_error_denies),
                "compaction_count": int(self._compaction_count),
                "evicted_streams": int(self._evicted_streams),
                "idle_evicted_streams": int(self._idle_evicted_streams),
                "allowed_steps": int(self._allowed_steps),
                "blocked_steps": int(self._blocked_steps),
            },
            "errors": list(b.errors[:50]),
            "warnings": list(b.warnings[:50]),
        }

    # ------------------------------------------------------------------
    # Internal: bundle compilation / decompilation
    # ------------------------------------------------------------------

    def _config_from_bundle(self, b: _CompiledBundle) -> AlwaysValidConfig:
        cfg = AlwaysValidConfig()
        cfg.enabled = b.enabled
        cfg.profile = b.profile
        cfg.label = b.label
        cfg.policyset_ref = b.policyset_ref
        cfg.on_config_error = b.on_config_error
        cfg.decision_source = b.decision_source
        cfg.block_on_trigger = b.block_on_trigger
        cfg.threshold_log_e = b.threshold_log_e
        cfg.threshold_clear_log_e = b.threshold_clear_log_e
        cfg.max_log_e = b.max_log_e
        cfg.min_log_e = b.min_log_e
        cfg.max_step_abs_log_e = b.max_step_abs_log_e
        cfg.alpha_base = b.alpha_base
        cfg.alpha_wealth_init = b.alpha_wealth_init
        cfg.alpha_wealth_cap = b.alpha_wealth_cap
        cfg.alpha_spend_per_decision = b.alpha_spend_per_decision
        cfg.alpha_reward_per_safe_decision = b.alpha_reward_per_safe_decision
        cfg.freeze_on_exhaust = b.freeze_on_exhaust
        cfg.max_weight = b.max_weight
        cfg.severity_weights = dict(b.severity_weights)
        cfg.min_p_value = b.min_p_value
        cfg.max_p_value = b.max_p_value
        cfg.p_to_e_kappas = b.p_to_e_kappas
        cfg.p_to_e_weights = b.p_to_e_weights
        cfg.score_to_p_mode = b.score_to_p_mode
        cfg.score_reference = b.score_reference
        cfg.score_scale = b.score_scale
        cfg.heuristic_p_weight = b.heuristic_p_weight
        cfg.max_streams = b.max_streams
        cfg.idle_ttl_s = b.idle_ttl_ns / 1_000_000_000.0
        cfg.stream_cleanup_budget = b.stream_cleanup_budget
        cfg.new_stream_policy = b.new_stream_policy
        cfg.on_state_exhaustion = b.on_state_exhaustion
        cfg.evict_only_inactive_streams = b.evict_only_inactive_streams
        cfg.stream_hash_algorithm = b.stream_hash_algorithm
        cfg.stream_hash_key = b.stream_hash_key
        cfg.stream_hash_key_id = b.stream_hash_key_id
        cfg.auto_ephemeral_hash_key_if_missing = (b.stream_hash_mode == "ephemeral")
        cfg.history_window = b.history_window
        cfg.retain_history = b.retain_history
        cfg.include_history_in_snapshot = b.include_history_in_snapshot
        cfg.ewma_alpha = b.ewma_alpha
        cfg.meta_max_nodes = b.meta_max_nodes
        cfg.meta_max_items = b.meta_max_items
        cfg.meta_max_depth = b.meta_max_depth
        cfg.meta_max_str_total = b.meta_max_str_total
        return cfg

    def _compile_bundle(self, cfg: AlwaysValidConfig, previous: Optional[_CompiledBundle]) -> _CompiledBundle:
        c = cfg.normalized_copy()
        errors: List[str] = []
        warnings: List[str] = []

        # compile mixture weights
        kappas = tuple(float(x) for x in c.p_to_e_kappas if 0.0 < float(x) < 1.0)
        if not kappas:
            errors.append("no valid p_to_e_kappas after normalization")
            kappas = _DEFAULT_P_TO_E_KAPPAS

        if c.p_to_e_weights and len(c.p_to_e_weights) == len(kappas):
            weights = tuple(float(x) for x in c.p_to_e_weights)
            if any((not math.isfinite(w) or w < 0.0) for w in weights):
                warnings.append("invalid p_to_e_weights; using equal weights")
                weights = tuple(1.0 / len(kappas) for _ in kappas)
        else:
            weights = tuple(1.0 / len(kappas) for _ in kappas)

        tot = sum(weights)
        if tot <= 0.0 or not math.isfinite(tot):
            errors.append("p_to_e_weights sum invalid; using equal weights")
            weights = tuple(1.0 / len(kappas) for _ in kappas)
        else:
            weights = tuple(w / tot for w in weights)

        # stream hash key handling
        key_bytes = _parse_key_material(c.stream_hash_key)
        key_mode = "configured" if key_bytes is not None else "none"
        if key_bytes is not None and len(key_bytes) < c.min_stream_hash_key_bytes:
            errors.append("stream_hash_key shorter than min_stream_hash_key_bytes")
            key_bytes = None
            key_mode = "none"

        if key_bytes is None and c.auto_ephemeral_hash_key_if_missing and c.stream_hash_algorithm == "hmac_sha256":
            if previous is not None and previous.stream_hash_mode == "ephemeral" and previous.stream_hash_key is not None:
                key_bytes = previous.stream_hash_key
            else:
                key_bytes = os.urandom(max(16, c.min_stream_hash_key_bytes))
            key_mode = "ephemeral"

        if c.stream_hash_algorithm == "hmac_sha256" and key_bytes is None:
            errors.append("stream_hash_algorithm='hmac_sha256' requires a key (configured or ephemeral)")
        if c.stream_hash_algorithm == "blake3" and Blake3Hash is None:
            errors.append("stream_hash_algorithm='blake3' requested but Blake3Hash unavailable")

        sev = MappingProxyType(dict(sorted(c.severity_weights.items())))
        updated_at_unix_ns = self._call_time_ns(c.wall_time_fn or time.time_ns, fallback=time.time_ns)

        fp_payload = {
            "schema_version": c.schema_version,
            "enabled": c.enabled,
            "profile": c.profile,
            "label": c.label,
            "policyset_ref": c.policyset_ref,
            "on_config_error": c.on_config_error,
            "decision_source": c.decision_source,
            "block_on_trigger": c.block_on_trigger,
            "threshold_log_e": c.threshold_log_e,
            "threshold_clear_log_e": c.threshold_clear_log_e,
            "max_log_e": c.max_log_e,
            "min_log_e": c.min_log_e,
            "max_step_abs_log_e": c.max_step_abs_log_e,
            "alpha_base": c.alpha_base,
            "alpha_wealth_init": c.alpha_wealth_init,
            "alpha_wealth_cap": c.alpha_wealth_cap,
            "alpha_spend_per_decision": c.alpha_spend_per_decision,
            "alpha_reward_per_safe_decision": c.alpha_reward_per_safe_decision,
            "freeze_on_exhaust": c.freeze_on_exhaust,
            "max_weight": c.max_weight,
            "severity_weights": dict(sev),
            "min_p_value": c.min_p_value,
            "max_p_value": c.max_p_value,
            "p_to_e_kappas": list(kappas),
            "p_to_e_weights": list(weights),
            "score_to_p_mode": c.score_to_p_mode,
            "score_reference": c.score_reference,
            "score_scale": c.score_scale,
            "heuristic_p_weight": c.heuristic_p_weight,
            "max_streams": c.max_streams,
            "idle_ttl_s": c.idle_ttl_s,
            "stream_cleanup_budget": c.stream_cleanup_budget,
            "new_stream_policy": c.new_stream_policy,
            "on_state_exhaustion": c.on_state_exhaustion,
            "evict_only_inactive_streams": c.evict_only_inactive_streams,
            "stream_hash_algorithm": c.stream_hash_algorithm,
            "stream_hash_key_id": c.stream_hash_key_id,
            "stream_hash_key_mode": key_mode,
            "history_window": c.history_window,
            "retain_history": c.retain_history,
            "include_history_in_snapshot": c.include_history_in_snapshot,
            "ewma_alpha": c.ewma_alpha,
            "meta_max_nodes": c.meta_max_nodes,
            "meta_max_items": c.meta_max_items,
            "meta_max_depth": c.meta_max_depth,
            "meta_max_str_total": c.meta_max_str_total,
        }
        cfg_fp_raw = hashlib.sha256(_canon_json(fp_payload).encode("utf-8", errors="strict")).hexdigest()
        cfg_fp = f"cfg1:{cfg_fp_raw}"

        version = 1 if previous is None else previous.version + 1

        return _CompiledBundle(
            version=version,
            updated_at_unix_ns=updated_at_unix_ns,
            cfg_fp=cfg_fp,
            errors=tuple(errors),
            warnings=tuple(warnings),
            enabled=bool(c.enabled),
            profile=c.profile,
            label=c.label,
            policyset_ref=c.policyset_ref,
            on_config_error=c.on_config_error,
            decision_source=c.decision_source,
            block_on_trigger=bool(c.block_on_trigger),
            threshold_log_e=float(c.threshold_log_e),
            threshold_clear_log_e=float(c.threshold_clear_log_e),
            max_log_e=float(c.max_log_e),
            min_log_e=float(c.min_log_e),
            max_step_abs_log_e=float(c.max_step_abs_log_e),
            alpha_base=float(c.alpha_base),
            alpha_wealth_init=float(c.alpha_wealth_init),
            alpha_wealth_cap=float(c.alpha_wealth_cap),
            alpha_spend_per_decision=float(c.alpha_spend_per_decision),
            alpha_reward_per_safe_decision=float(c.alpha_reward_per_safe_decision),
            freeze_on_exhaust=bool(c.freeze_on_exhaust),
            max_weight=float(c.max_weight),
            severity_weights=sev,
            min_p_value=float(c.min_p_value),
            max_p_value=float(c.max_p_value),
            p_to_e_kappas=kappas,
            p_to_e_weights=weights,
            score_to_p_mode=c.score_to_p_mode,
            score_reference=float(c.score_reference),
            score_scale=float(c.score_scale),
            heuristic_p_weight=float(c.heuristic_p_weight),
            max_streams=int(c.max_streams),
            idle_ttl_ns=int(round(c.idle_ttl_s * 1_000_000_000.0)),
            stream_cleanup_budget=int(c.stream_cleanup_budget),
            new_stream_policy=c.new_stream_policy,
            on_state_exhaustion=c.on_state_exhaustion,
            evict_only_inactive_streams=bool(c.evict_only_inactive_streams),
            stream_hash_algorithm=c.stream_hash_algorithm,
            stream_hash_key=key_bytes,
            stream_hash_key_id=c.stream_hash_key_id,
            stream_hash_mode=key_mode,
            history_window=int(c.history_window),
            retain_history=bool(c.retain_history),
            include_history_in_snapshot=bool(c.include_history_in_snapshot),
            ewma_alpha=float(c.ewma_alpha),
            meta_max_nodes=int(c.meta_max_nodes),
            meta_max_items=int(c.meta_max_items),
            meta_max_depth=int(c.meta_max_depth),
            meta_max_str_total=int(c.meta_max_str_total),
            monotonic_fn=c.monotonic_fn or time.monotonic_ns,
            wall_time_fn=c.wall_time_fn or time.time_ns,
        )

    # ------------------------------------------------------------------
    # Internal: time / stream hashing / store management
    # ------------------------------------------------------------------

    def _call_time_ns(self, fn: Callable[[], Any], *, fallback: Callable[[], int]) -> int:
        try:
            v = fn()
        except Exception:
            return int(fallback())
        if type(v) is int:
            return int(v)
        if isinstance(v, (float, int)) and math.isfinite(float(v)):
            return int(float(v) * 1_000_000_000.0)
        return int(fallback())

    def _mono_ns(self, bundle: _CompiledBundle) -> int:
        return self._call_time_ns(bundle.monotonic_fn, fallback=time.monotonic_ns)

    def _wall_ns(self, bundle: _CompiledBundle) -> int:
        return self._call_time_ns(bundle.wall_time_fn, fallback=time.time_ns)

    def _sanitize_stream_id(self, stream_id: Optional[str]) -> str:
        sid = _safe_id(stream_id, default=None, max_len=256)
        return sid if sid is not None else "default"

    def _canonical_stream_hash(self, bundle: _CompiledBundle, stream_id: str) -> str:
        sid = _strip_unsafe_text(stream_id, max_len=4096)
        data = sid.encode("utf-8", errors="surrogatepass")

        if bundle.stream_hash_algorithm == "hmac_sha256":
            key = bundle.stream_hash_key or b""
            dig = hmac.new(
                key,
                b"tcd:eprocess:stream:v1\x00" + data,
                digestmod=hashlib.sha256,
            ).hexdigest()[:48]
            return f"{bundle.stream_hash_key_id or 'sh1'}:{dig}"

        if bundle.stream_hash_algorithm == "blake3" and Blake3Hash is not None:
            dig = Blake3Hash().hex(
                b"tcd:eprocess:stream:v1\x00" + data,
                ctx="tcd:eprocess:stream",
            )[:48]
            return f"{bundle.stream_hash_key_id or 'sh1'}:{dig}"

        dig = hashlib.blake2b(
            (b"tcd:eprocess:stream:v1\x00" + data),
            digest_size=24,
            key=bundle.stream_hash_key or b"",
        ).hexdigest()[:48]
        return f"{bundle.stream_hash_key_id or 'sh1'}:{dig}"

    def _make_initial_state(self, bundle: _CompiledBundle, now_mono_ns: int, now_unix_ns: int) -> EProcessState:
        maxlen = bundle.history_window if (bundle.retain_history and bundle.history_window > 0) else 0
        return EProcessState(
            strict_log_e=0.0,
            controller_log_e=0.0,
            alpha_wealth=bundle.alpha_wealth_init,
            last_update_mono_ns=now_mono_ns,
            last_update_unix_ns=now_unix_ns,
            history_p=deque(maxlen=maxlen or None),
            history_score=deque(maxlen=maxlen or None),
            history_log_e=deque(maxlen=maxlen or None),
        )

    def _compact_locked(self, now_mono_ns: int, budget: int) -> None:
        if budget <= 0 or not self._streams:
            return
        ttl_ns = self._bundle.idle_ttl_ns
        if ttl_ns <= 0:
            return

        removed = 0
        while budget > 0 and self._lru:
            sh = next(iter(self._lru.keys()))
            st = self._streams.get(sh)
            if st is None:
                self._lru.pop(sh, None)
                budget -= 1
                continue
            if (now_mono_ns - st.last_update_mono_ns) <= ttl_ns:
                break
            self._streams.pop(sh, None)
            self._lru.pop(sh, None)
            removed += 1
            budget -= 1

        if removed > 0:
            self._idle_evicted_streams += removed
            self._evicted_streams += removed
            self._compaction_count += 1

    def _admit_stream_locked(self, bundle: _CompiledBundle, now_mono_ns: int) -> bool:
        self._compact_locked(now_mono_ns, budget=max(1, bundle.stream_cleanup_budget))

        if len(self._streams) < bundle.max_streams:
            return True

        if bundle.new_stream_policy != "evict_lru":
            return False

        # Optional safety: only evict inactive streams
        victim: Optional[str] = None
        for sh in self._lru.keys():
            st = self._streams.get(sh)
            if st is None:
                victim = sh
                break
            if bundle.evict_only_inactive_streams and st.active:
                continue
            victim = sh
            break

        if victim is None:
            return False

        self._streams.pop(victim, None)
        self._lru.pop(victim, None)
        self._evicted_streams += 1
        return len(self._streams) < bundle.max_streams

    # ------------------------------------------------------------------
    # Internal: statistics / update math
    # ------------------------------------------------------------------

    def _normalize_score(self, score: Optional[float]) -> Optional[float]:
        s = _coerce_float(score)
        return float(s) if s is not None else None

    def _normalize_p_like(
        self,
        bundle: _CompiledBundle,
        p_value: Optional[float],
        score: Optional[float],
    ) -> Tuple[float, str, Optional[float]]:
        p = _coerce_float(p_value)
        if p is not None:
            p = min(bundle.max_p_value, max(bundle.min_p_value, p))
            return float(p), "direct", self._normalize_score(score)

        s = self._normalize_score(score)
        if s is None:
            return 1.0, "neutral", None

        if bundle.score_to_p_mode == "one_minus_score":
            # assume higher score => more suspicious, typically in [0,1]
            x = 1.0 - s
        elif bundle.score_to_p_mode == "sigmoid_tail":
            # p = 1 / (1 + exp(scale*(score-ref)))
            z = bundle.score_scale * (s - bundle.score_reference)
            if z >= 0:
                ez = math.exp(-z)
                x = ez / (1.0 + ez)
            else:
                ez = math.exp(z)
                x = 1.0 / (1.0 + ez)
        else:  # exp_tail
            z = max(0.0, s - bundle.score_reference)
            x = math.exp(-bundle.score_scale * z)

        x = min(bundle.max_p_value, max(bundle.min_p_value, x))
        return float(x), "score_heuristic", s

    def _effective_weight(
        self,
        bundle: _CompiledBundle,
        base_weight: float,
        severity: Optional[str],
    ) -> float:
        w = _coerce_float(base_weight)
        if w is None:
            w = 1.0
        sev_mult = 1.0
        if type(severity) is str:
            sev = _safe_label(severity, default="")
            sev_mult = float(bundle.severity_weights.get(sev, 1.0))
        eff = w * sev_mult
        if not math.isfinite(eff):
            eff = 1.0
        if eff < 0.0:
            eff = 0.0
        if eff > bundle.max_weight:
            eff = bundle.max_weight
        return float(eff)

    def _e_log_increment(self, bundle: _CompiledBundle, p_like: float) -> float:
        p = min(bundle.max_p_value, max(bundle.min_p_value, p_like))
        lp = math.log(p)
        terms: List[float] = []
        for kappa, w in zip(bundle.p_to_e_kappas, bundle.p_to_e_weights):
            # e(p)=kappa * p^(kappa-1), mixed with convex weights
            term = math.log(w) + math.log(kappa) + (kappa - 1.0) * lp
            terms.append(term)
        inc = _logsumexp(terms)
        if not math.isfinite(inc):
            return 0.0
        if inc > bundle.max_step_abs_log_e:
            return bundle.max_step_abs_log_e
        if inc < -bundle.max_step_abs_log_e:
            return -bundle.max_step_abs_log_e
        return float(inc)

    def _selected_log_e(self, bundle: _CompiledBundle, st: EProcessState) -> Tuple[float, str]:
        if bundle.decision_source == "strict":
            return float(st.strict_log_e), "strict"
        if bundle.decision_source == "strict_if_available_else_controller":
            if st.direct_p_steps > 0:
                return float(st.strict_log_e), "strict"
            return float(st.controller_log_e), "controller"
        return float(st.controller_log_e), "controller"

    def _update_state(
        self,
        *,
        bundle: _CompiledBundle,
        state: EProcessState,
        p_like: float,
        p_source: str,
        score: Optional[float],
        effective_weight: float,
        now_mono_ns: int,
        now_unix_ns: int,
    ) -> None:
        state.decisions += 1
        state.last_update_mono_ns = now_mono_ns
        state.last_update_unix_ns = now_unix_ns
        state.last_p_value = float(p_like)
        state.last_p_source = p_source
        state.last_score = score

        # source counters
        if p_source == "direct":
            state.direct_p_steps += 1
        elif p_source == "score_heuristic":
            state.heuristic_p_steps += 1
        else:
            state.neutral_steps += 1

        # descriptive stats
        if p_source in {"direct", "score_heuristic"}:
            nl = -math.log(max(bundle.min_p_value, p_like))
            a = bundle.ewma_alpha
            state.ewma_neglogp = nl if state.decisions == 1 else ((a * nl) + ((1.0 - a) * state.ewma_neglogp))

        if score is not None:
            a = bundle.ewma_alpha
            state.ewma_score = score if state.ewma_score is None else ((a * score) + ((1.0 - a) * state.ewma_score))
            if state.max_score is None or score > state.max_score:
                state.max_score = score
                state.max_score_step = state.decisions

        if p_source in {"direct", "score_heuristic"}:
            if p_like < state.min_p_value:
                state.min_p_value = p_like
                state.min_p_value_step = state.decisions
            if p_like <= 0.05:
                state.small_p_count_05 += 1
            if p_like <= 0.01:
                state.small_p_count_01 += 1
            if p_like <= 0.001:
                state.small_p_count_001 += 1

        # Fisher-style diagnostic from direct p-values only
        if p_source == "direct":
            try:
                state.fisher_stat += -2.0 * math.log(max(bundle.min_p_value, p_like))
                state.fisher_df += 2
            except Exception:
                pass

        # History
        if bundle.retain_history and bundle.history_window > 0:
            if p_source in {"direct", "score_heuristic"}:
                state.history_p.append(float(p_like))
            if score is not None:
                state.history_score.append(float(score))

        # strict process: only direct p-values contribute, no heuristic weighting
        if p_source == "direct":
            strict_inc = self._e_log_increment(bundle, p_like)
            state.strict_log_e = min(bundle.max_log_e, max(bundle.min_log_e, state.strict_log_e + strict_inc))
        else:
            strict_inc = 0.0

        # controller process
        if not (bundle.freeze_on_exhaust and state.frozen):
            if bundle.alpha_spend_per_decision > 0.0:
                spend = bundle.alpha_spend_per_decision * max(1.0, effective_weight)
                state.alpha_wealth = max(0.0, state.alpha_wealth - spend)

            controller_inc = self._e_log_increment(bundle, p_like)
            if p_source == "score_heuristic":
                controller_inc *= bundle.heuristic_p_weight
            controller_inc *= effective_weight

            if not math.isfinite(controller_inc):
                controller_inc = 0.0

            state.controller_log_e = min(
                bundle.max_log_e,
                max(bundle.min_log_e, state.controller_log_e + controller_inc),
            )

            if bundle.freeze_on_exhaust and state.alpha_wealth <= 0.0:
                state.alpha_wealth = 0.0
                state.frozen = True
                if state.exhausted_step is None:
                    state.exhausted_step = state.decisions

        if bundle.retain_history and bundle.history_window > 0:
            state.history_log_e.append(float(state.controller_log_e))

    # ------------------------------------------------------------------
    # Internal: result building
    # ------------------------------------------------------------------

    def _sanitize_meta_dict(self, bundle: _CompiledBundle, obj: Mapping[str, Any]) -> Dict[str, Any]:
        budget = _JsonBudget(
            max_nodes=bundle.meta_max_nodes,
            max_items=bundle.meta_max_items,
            max_depth=bundle.meta_max_depth,
            max_str_total=bundle.meta_max_str_total,
        )
        safe = _json_sanitize(obj, budget=budget, depth=0, redact_secrets=True)
        return safe if isinstance(safe, dict) else {}

    def _build_process_block(
        self,
        bundle: _CompiledBundle,
        st: Optional[EProcessState],
    ) -> Dict[str, Any]:
        if st is None:
            selected_log_e = 0.0
            selected_source = bundle.decision_source
            trigger = False
            return {
                "strict_e_value": 1.0,
                "controller_e_value": 1.0,
                "selected_source": selected_source,
                "selected_log_e": 0.0,
                "selected_e_value": 1.0,
                "alpha_base": bundle.alpha_base,
                "alpha_wealth": bundle.alpha_wealth_init,
                "alpha_wealth_init": bundle.alpha_wealth_init,
                "alpha_wealth_cap": bundle.alpha_wealth_cap,
                "alpha_spend_per_decision": bundle.alpha_spend_per_decision,
                "alpha_reward_per_safe_decision": bundle.alpha_reward_per_safe_decision,
                "threshold_log_e": bundle.threshold_log_e,
                "threshold_clear_log_e": bundle.threshold_clear_log_e,
                "threshold_e_value": _safe_exp(bundle.threshold_log_e),
                "trigger": trigger,
                "decisions": 0,
                "triggers": 0,
                "last_trigger_step": None,
                "strict_log_e": 0.0,
                "controller_log_e": 0.0,
                "frozen": False,
                "active": False,
                "selected_reason": "none",
            }

        selected_log_e, selected_source = self._selected_log_e(bundle, st)
        trigger = bool(st.active)
        return {
            "strict_e_value": _safe_exp(st.strict_log_e),
            "controller_e_value": _safe_exp(st.controller_log_e),
            "selected_source": selected_source,
            "selected_log_e": float(selected_log_e),
            "selected_e_value": _safe_exp(selected_log_e),
            "alpha_base": bundle.alpha_base,
            "alpha_wealth": float(st.alpha_wealth),
            "alpha_wealth_init": bundle.alpha_wealth_init,
            "alpha_wealth_cap": bundle.alpha_wealth_cap,
            "alpha_spend_per_decision": bundle.alpha_spend_per_decision,
            "alpha_reward_per_safe_decision": bundle.alpha_reward_per_safe_decision,
            "threshold_log_e": bundle.threshold_log_e,
            "threshold_clear_log_e": bundle.threshold_clear_log_e,
            "threshold_e_value": _safe_exp(bundle.threshold_log_e),
            "trigger": trigger,
            "decisions": int(st.decisions),
            "triggers": int(st.triggers),
            "last_trigger_step": st.last_trigger_step,
            "strict_log_e": float(st.strict_log_e),
            "controller_log_e": float(st.controller_log_e),
            "frozen": bool(st.frozen),
            "active": bool(st.active),
            "exhausted_step": st.exhausted_step,
        }

    def _build_stats_block(self, bundle: _CompiledBundle, st: Optional[EProcessState]) -> Dict[str, Any]:
        if st is None:
            return {
                "direct_p_steps": 0,
                "heuristic_p_steps": 0,
                "neutral_steps": 0,
                "min_p_value": 1.0,
                "min_p_value_step": None,
                "max_score": None,
                "max_score_step": None,
                "ewma_score": None,
                "ewma_neglogp": 0.0,
                "fisher_stat": 0.0,
                "fisher_df": 0,
                "small_p_count_05": 0,
                "small_p_count_01": 0,
                "small_p_count_001": 0,
            }

        out = {
            "direct_p_steps": int(st.direct_p_steps),
            "heuristic_p_steps": int(st.heuristic_p_steps),
            "neutral_steps": int(st.neutral_steps),
            "min_p_value": float(st.min_p_value),
            "min_p_value_step": st.min_p_value_step,
            "max_score": float(st.max_score) if st.max_score is not None else None,
            "max_score_step": st.max_score_step,
            "ewma_score": float(st.ewma_score) if st.ewma_score is not None else None,
            "ewma_neglogp": float(st.ewma_neglogp),
            "fisher_stat": float(st.fisher_stat),
            "fisher_df": int(st.fisher_df),
            "small_p_count_05": int(st.small_p_count_05),
            "small_p_count_01": int(st.small_p_count_01),
            "small_p_count_001": int(st.small_p_count_001),
            "last_p_value": float(st.last_p_value),
            "last_p_source": st.last_p_source,
            "last_score": float(st.last_score) if st.last_score is not None else None,
            "last_update_mono_ns": int(st.last_update_mono_ns),
            "last_update_unix_ns": int(st.last_update_unix_ns),
        }

        if bundle.include_history_in_snapshot and bundle.retain_history and bundle.history_window > 0:
            out["history"] = {
                "p_values": list(st.history_p),
                "scores": list(st.history_score),
                "controller_log_e": list(st.history_log_e),
            }
        return out

    def _build_validity_block(
        self,
        bundle: _CompiledBundle,
        st: Optional[EProcessState],
        *,
        p_source: str,
        selected_source: str,
    ) -> Dict[str, Any]:
        return {
            "strict_process_valid_if_direct_p_values_are_valid": True,
            "controller_process_is_statistical_controller_not_pure_e_process": True,
            "decision_source": bundle.decision_source,
            "selected_source": selected_source,
            "p_source_this_step": p_source,
            "has_direct_p_history": bool(st.direct_p_steps > 0) if st is not None else False,
            "has_heuristic_history": bool(st.heuristic_p_steps > 0) if st is not None else False,
        }

    def _build_step_result(
        self,
        *,
        bundle: _CompiledBundle,
        sid: str,
        stream_hash: str,
        state: Optional[EProcessState],
        allowed: bool,
        reason: str,
        p_value_out: float,
        p_source: str,
        score_out: Optional[float],
        effective_weight: float,
        selected_source: str,
        now_mono_ns: int,
        now_unix_ns: int,
        meta_s: Dict[str, Any],
        ctx_s: Dict[str, Any],
        has_request: bool,
        decision_seq: int = 0,
    ) -> Dict[str, Any]:
        process = self._build_process_block(bundle, state)
        stats = self._build_stats_block(bundle, state)
        validity = self._build_validity_block(bundle, state or self._make_initial_state(bundle, now_mono_ns, now_unix_ns), p_source=p_source, selected_source=selected_source)

        security = {
            "av_label": bundle.label,
            "policyset_ref": bundle.policyset_ref,
            "cfg_fp": bundle.cfg_fp,
            "bundle_version": bundle.version,
            "trigger": bool(process["trigger"]),
            "trigger_reason": reason,
            "block_on_trigger": bool(bundle.block_on_trigger),
            "stream_hash": stream_hash,
            "selected_source": selected_source,
            "state_scope": "local_best_effort",
        }

        return {
            "allowed": bool(allowed),
            "reason": reason,
            "stream_id": sid,
            "stream_hash": stream_hash,
            "decision_seq": int(decision_seq),
            "bundle_version": int(bundle.version),
            "config_fingerprint": bundle.cfg_fp,
            "p_value": float(p_value_out),
            "p_source": p_source,
            "score": float(score_out) if score_out is not None else None,
            "effective_weight": float(effective_weight),
            "meta": meta_s,
            "ctx": ctx_s,
            "has_request": bool(has_request),
            "e_state": {
                "schema": _SCHEMA,
                "controller": {
                    "name": _CONTROLLER_NAME,
                    "version": _CONTROLLER_VERSION,
                    "instance_id": self._instance_id,
                    "profile": bundle.profile,
                    "label": bundle.label,
                    "policyset_ref": bundle.policyset_ref,
                    "cfg_fp": bundle.cfg_fp,
                    "bundle_version": int(bundle.version),
                    "ts_monotonic_ns": int(now_mono_ns),
                    "ts_unix_ns": int(now_unix_ns),
                    "enabled": bool(bundle.enabled),
                    "state_scope": "local_best_effort",
                },
                "stream": {
                    "id": sid,
                    "hash": stream_hash,
                },
                "process": process,
                "stats": stats,
                "validity": validity,
            },
            "security": security,
        }

    def _build_snapshot_result(
        self,
        *,
        bundle: _CompiledBundle,
        sid: str,
        stream_hash: str,
        state: Optional[EProcessState],
        now_mono_ns: int,
        now_unix_ns: int,
    ) -> Dict[str, Any]:
        process = self._build_process_block(bundle, state)
        stats = self._build_stats_block(bundle, state)
        validity = self._build_validity_block(
            bundle,
            state or self._make_initial_state(bundle, now_mono_ns, now_unix_ns),
            p_source="snapshot",
            selected_source=process["selected_source"],
        )
        return {
            "schema": _SCHEMA,
            "controller": {
                "name": _CONTROLLER_NAME,
                "version": _CONTROLLER_VERSION,
                "instance_id": self._instance_id,
                "profile": bundle.profile,
                "label": bundle.label,
                "policyset_ref": bundle.policyset_ref,
                "cfg_fp": bundle.cfg_fp,
                "bundle_version": int(bundle.version),
                "ts_monotonic_ns": int(now_mono_ns),
                "ts_unix_ns": int(now_unix_ns),
                "enabled": bool(bundle.enabled),
                "state_scope": "local_best_effort",
            },
            "stream": {
                "id": sid,
                "hash": stream_hash,
            },
            "process": process,
            "stats": stats,
            "validity": validity,
        }