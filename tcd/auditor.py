from __future__ import annotations

"""
Chain auditor for verifiable receipts (platform-hardened, L6-L7).

This module:
- Runs integrity checks over recent receipts from a ReceiptStore.
- Exports low-cardinality Prometheus metrics (multi-instance safe via labels).
- Provides one-shot audit() and a periodic ChainAuditor loop.

P0/L6 enforced by default knobs:
- Deterministic policy digest (domain sep, strict JSON, normalized allowlists).
- Transactional-ish audit: never raise on routine data/store errors; returns report with error_kind.
- Robust parsing guards (per-body bytes cap, JSON bracket depth guard, int digit cap, hex length cap).
- Chain-semantic window selection (backtrack from best tip), not topo+suffix heuristics.
- Explicit anomaly accounting: parse errors, invalid heads, oversize bodies, duplicates, forks, cycles, ambiguity.
- Verify isolation with timeout + busy distinction; process mode is spawn-safe (top-level worker).
- Prometheus hygiene: labels for all metrics (name/version/store), info gauge label leak prevented (remove old labels).
- No import-time metric registration side effects (lazy default metrics builder).

L7 knobs/hooks included:
- Verify executor subsystem abstraction (thread/process, stuck detection, temp-file IPC).
- Optional event_sink hook for emitting structured audit events (e.g., to tcd/audit ledger).
- Optional policy signature fields + verify hook placeholder.
"""

import dataclasses
import hashlib
import json
import logging
import math
import os
import random
import re
import tempfile
import threading
import time
from dataclasses import field
from typing import Any, Callable, Dict, Iterable, List, NamedTuple, Optional, Tuple

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge, Histogram

__all__ = [
    "ReceiptRow",
    "ReceiptStore",
    "ChainAuditConfig",
    "ChainAuditReport",
    "build_metrics",
    "audit",
    "ChainAuditor",
]

logger = logging.getLogger(__name__)

# Best-effort verify implementation fingerprint.
try:
    from .verify import VERIFY_IMPL_DIGEST as _VERIFY_IMPL_DIGEST  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    _VERIFY_IMPL_DIGEST = "unknown"

# ---------------------------------------------------------------------------
# Safety/determinism utilities
# ---------------------------------------------------------------------------

_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_ALG_HEX_RE = re.compile(r"^([a-zA-Z0-9_.-]{1,32}):([0-9a-fA-FxX]+)$")


def _now_ns() -> int:
    return time.time_ns()


def _safe_text(x: Any, *, max_len: int = 256) -> str:
    try:
        s = str(x)
    except Exception:
        s = "<unprintable>"
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = _CTRL_CHARS_RE.sub("", s).strip()
    # Make UTF-8 safe deterministically (avoid surrogate DoS in logs).
    s = s.encode("utf-8", errors="replace").decode("utf-8", errors="strict")
    if max_len <= 0:
        return ""
    if len(s) <= max_len:
        return s
    return s[: max(0, max_len - 3)] + "..."


def _utf8_len_lossy(s: str) -> int:
    # Lossy length used for budgets; does not raise on surrogates.
    return len(s.encode("utf-8", errors="replace"))


def _canonical_json(obj: Any) -> str:
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _is_finite(x: float) -> bool:
    return math.isfinite(x)


def _canon_hex_no_prefix_limited(s: Optional[str], *, max_hex_chars: int) -> Optional[str]:
    """
    Canonicalize hex-ish string to lowercase hex WITHOUT 0x prefix.
    Enforces max_hex_chars to avoid bytes.fromhex DoS.
    """
    if s is None or not isinstance(s, str):
        return None
    ss = s.strip()
    if ss.startswith(("0x", "0X")):
        ss = ss[2:]
    ss = ss.strip()
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
    # bytes.fromhex alloc is bounded by max_hex_chars.
    try:
        bytes.fromhex(ss)
    except Exception:
        return None
    return ss.lower()


def _canon_hex_0x_limited(s: Optional[str], *, max_hex_chars: int) -> Optional[str]:
    hx = _canon_hex_no_prefix_limited(s, max_hex_chars=max_hex_chars)
    return ("0x" + hx) if hx is not None else None


def _bracket_depth_guard(s: str, *, max_depth: int, max_scan_chars: int) -> bool:
    """
    JSON-ish bracket depth guard with a small string-state machine.
    Counts { [ as +1, } ] as -1 only when not inside a JSON string.
    """
    if max_depth <= 0:
        return True
    depth = 0
    in_str = False
    esc = False
    # Bound scan to avoid O(n) on huge input.
    n = min(len(s), max(0, int(max_scan_chars)))
    for i in range(n):
        ch = s[i]
        if in_str:
            if esc:
                esc = False
            else:
                if ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch == "{" or ch == "[":
            depth += 1
            if depth > max_depth:
                return False
        elif ch == "}" or ch == "]":
            if depth > 0:
                depth -= 1
    return True


def _make_parse_int_limiter(max_digits: int) -> Callable[[str], int]:
    md = max(1, int(max_digits))

    def _parse_int(s: str) -> int:
        # JSON parser gives us digit string with optional leading '-'.
        ss = s[1:] if s.startswith("-") else s
        if len(ss) > md:
            raise ValueError("int too large")
        return int(s)

    return _parse_int


def _normalize_salt_hex(s: Optional[str], *, max_hex_chars: int) -> Optional[str]:
    if s is None or s == "":
        return None
    out = _canon_hex_0x_limited(s, max_hex_chars=max_hex_chars)
    return out


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


class ReceiptRow(NamedTuple):
    head_hex: str
    body_json: str


class ReceiptStore:
    def tail(self, n: int) -> List[ReceiptRow]: ...
    def stats(self) -> Dict[str, Any]: ...


# ---------------------------------------------------------------------------
# Error kinds (low-cardinality)
# ---------------------------------------------------------------------------

ERR_NONE = "NONE"
ERR_CONFIG = "CONFIG_INVALID"
ERR_STORE_TAIL = "STORE_TAIL_FAIL"
ERR_STORE_STATS = "STORE_STATS_FAIL"
ERR_ROW_SHAPE = "ROW_SHAPE"
ERR_INTERNAL = "INTERNAL"

VERIFY_ERR_NONE = "NONE"
VERIFY_ERR_IMPORT = "IMPORT"
VERIFY_ERR_BUSY = "BUSY"
VERIFY_ERR_TIMEOUT = "TIMEOUT"
VERIFY_ERR_EXCEPTION = "EXCEPTION"
VERIFY_ERR_SPAWN_FAIL = "PROCESS_SPAWN_FAIL"
VERIFY_ERR_KILL_FAIL = "PROCESS_KILL_FAIL"
VERIFY_ERR_INPUT = "BAD_INPUT"

# Failure reasons (bounded enum)
R_PARSE_ERROR = "PARSE_ERROR"
R_INVALID_HEAD = "INVALID_HEAD"
R_OVERSIZE_BODY = "OVERSIZE_BODY"
R_DUPLICATE_HEAD = "DUPLICATE_HEAD"
R_FORK_DETECTED = "FORK_DETECTED"
R_CYCLE_DETECTED = "CYCLE_DETECTED"
R_AMBIGUOUS_PREV = "AMBIGUOUS_PREV"
R_MISSING_PREV = "MISSING_PREV"
R_TS_VIOLATION = "TS_VIOLATION"
R_SCHEMA_HEAD_MISMATCH = "SCHEMA_HEAD_MISMATCH"
R_AUTH_POLICY_VIOLATION = "AUTH_POLICY_VIOLATION"
R_CFG_DIGEST_VIOLATION = "CFG_DIGEST_VIOLATION"
R_CALIB_DIGEST_VIOLATION = "CALIB_DIGEST_VIOLATION"
R_VERIFY_TIMEOUT = "VERIFY_TIMEOUT"
R_VERIFY_BUSY = "VERIFY_BUSY"
R_VERIFY_EXCEPTION = "VERIFY_EXCEPTION"
R_VERIFY_FALSE = "VERIFY_FALSE"
R_INSUFFICIENT_BUDGET = "INSUFFICIENT_BUDGET"
R_INSUFFICIENT_CHAIN = "INSUFFICIENT_CHAIN"
R_ROLLBACK_SUSPECTED = "ROLLBACK_SUSPECTED"
R_ROW_SHAPE = "ROW_SHAPE"
R_STORE_TAIL_FAIL = "STORE_TAIL_FAIL"


# ---------------------------------------------------------------------------
# Config + Report (policy object)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True, slots=True)
class ChainAuditConfig:
    # Policy identity (low-cardinality labels)
    name: str = "default"
    version: str = "v1"
    store_id: Optional[str] = None  # for metrics labels; fallback uses store class name

    # Window sizing (hard caps to avoid misconfig DoS)
    window: int = 256
    window_cap: int = 4096  # absolute upper bound regardless of config
    max_window_bytes: Optional[int] = 512 * 1024  # selected window bytes cap (verify input cap)

    # Fetch-side memory cap (even before selection); protects against weird store.tail behavior.
    max_fetched_bytes: Optional[int] = 2 * 1024 * 1024  # 2 MiB default

    # Store order semantics (needed for ts_check_mode="store_order")
    # - "newest_first": tail() returns newest->oldest
    # - "oldest_first": tail() returns oldest->newest
    # - "unknown": no ordering guarantee
    store_order: str = "unknown"

    # Periodic auditor behavior
    interval_s: float = 15.0
    min_sleep_s: float = 0.05
    fail_retry_s: float = 1.0
    continue_on_fail: bool = True
    max_bad_bodies: int = 8

    # Verify settings
    label_salt_hex: Optional[str] = None
    verify_timeout_s: Optional[float] = 1.0
    verify_timeout_mode: str = "thread"  # "thread" or "process"
    verify_stuck_reset_s: Optional[float] = 300.0  # if in-flight age exceeds, mark stuck
    verify_fallback_to_process_on_stuck: bool = True
    # Process verify controls (spawn-safe + cost control)
    process_start_method: str = "spawn"  # "spawn" recommended; "fork" is unsafe with threads
    process_ipc_mode: str = "tempfile"  # "tempfile" (L7-ish) or "pickle" (not recommended)
    process_mode_max_window_bytes: int = 256 * 1024
    process_mode_max_records: int = 512
    # Optional process resource limits (best-effort, POSIX only)
    process_rlimit_cpu_s: Optional[int] = None
    process_rlimit_as_bytes: Optional[int] = None

    # Parsing/DoS budgets
    max_body_bytes_per_row: int = 256 * 1024  # soft cap; above -> parse skipped
    max_body_bytes_hard: int = 512 * 1024  # hard cap; above -> dropped
    max_json_depth: int = 128
    max_json_depth_scan_chars: int = 200_000
    max_int_digits: int = 2048
    max_hex_chars: int = 256  # for head/prev/salt
    sanitize_invalid_utf8: bool = False  # if True, replace surrogates for parsing/verify; default strict-fail

    # Chain semantics selection
    ordering_mode: str = "chain_backtrack"  # reserved; only chain_backtrack implemented
    max_tip_candidates: int = 32
    min_chain_len: int = 1  # if longest chain < min, fail (or degraded)
    treat_gaps_as_fail: bool = True  # kept for compatibility; chain selection should yield 0 gaps
    treat_parse_errors_as_fail: bool = True
    fail_on_duplicate_heads: bool = True
    fail_on_cycles: bool = True
    fail_on_forks: bool = False  # forks may happen in windows; choose your policy
    fail_on_ambiguous_prev: bool = True

    # ts checks
    expect_monotonic_ts_ns: bool = False
    ts_check_mode: str = "chain_order"  # "chain_order", "store_order", "none"
    max_future_skew_s: float = 300.0

    # Schema enforcement
    strict_body_schema: bool = False
    enforce_body_head_match: bool = False

    enforce_auth_policy_digest: bool = False
    expected_auth_policy_digests: Optional[List[str]] = None

    enforce_cfg_digest: bool = False
    expected_cfg_digests: Optional[List[str]] = None

    enforce_calib_digest: bool = False
    expected_calib_digests: Optional[List[str]] = None

    # Digest token format (strict; avoids "string bypass")
    # "any": accepts hex / 0xhex / alg:hex (canonicalized)
    # "0xhex": requires hex digests and canonicalizes to 0x...
    # "hex": requires bare hex
    # "alg:hex": requires alg:hex
    digest_format: str = "any"

    # Labels format passed into verify_chain for heads
    verify_head_format: str = "hex"  # "hex" or "0xhex"

    # Logging safety: rate-limit stack traces
    log_stacktrace_rate_s: float = 60.0

    # L7 hook: emit structured audit events (do NOT include full bodies)
    event_sink: Optional[Callable[[Dict[str, Any]], None]] = None

    # L7 hook: policy signature metadata (verify via policy_sig_verify_func if provided)
    policy_sig_alg: Optional[str] = None
    policy_sig_key_id: Optional[str] = None
    policy_sig_b64: Optional[str] = None
    policy_sig_verify_func: Optional[Callable[[bytes, bytes, Optional[str], Optional[str]], bool]] = None

    def validate(self) -> None:
        # Window semantics
        if int(self.window) < 0:
            raise ValueError("window must be >= 0")
        if int(self.window_cap) <= 0:
            raise ValueError("window_cap must be > 0")
        if int(self.window) > int(self.window_cap):
            raise ValueError("window exceeds window_cap")

        # Numeric sanity (finite)
        for nm, v in (
            ("interval_s", float(self.interval_s)),
            ("min_sleep_s", float(self.min_sleep_s)),
            ("fail_retry_s", float(self.fail_retry_s)),
            ("max_future_skew_s", float(self.max_future_skew_s)),
            ("log_stacktrace_rate_s", float(self.log_stacktrace_rate_s)),
        ):
            if not _is_finite(v):
                raise ValueError(f"{nm} must be finite")
        if float(self.min_sleep_s) <= 0:
            raise ValueError("min_sleep_s must be > 0")
        if float(self.interval_s) < 0 or float(self.fail_retry_s) < 0:
            raise ValueError("interval_s/fail_retry_s must be >= 0")

        if int(self.max_bad_bodies) < 0:
            raise ValueError("max_bad_bodies must be >= 0")

        # Budgets
        if self.max_window_bytes is not None and int(self.max_window_bytes) <= 0:
            raise ValueError("max_window_bytes must be > 0 or None")
        if self.max_fetched_bytes is not None and int(self.max_fetched_bytes) <= 0:
            raise ValueError("max_fetched_bytes must be > 0 or None")
        if int(self.max_body_bytes_per_row) <= 0 or int(self.max_body_bytes_hard) <= 0:
            raise ValueError("max_body_bytes_per_row/max_body_bytes_hard must be > 0")
        if int(self.max_body_bytes_per_row) > int(self.max_body_bytes_hard):
            raise ValueError("max_body_bytes_per_row must be <= max_body_bytes_hard")
        if int(self.max_hex_chars) <= 0:
            raise ValueError("max_hex_chars must be > 0")
        if int(self.max_json_depth) <= 0:
            raise ValueError("max_json_depth must be > 0")
        if int(self.max_json_depth_scan_chars) <= 0:
            raise ValueError("max_json_depth_scan_chars must be > 0")
        if int(self.max_int_digits) <= 0:
            raise ValueError("max_int_digits must be > 0")

        # Salt validity (do not silently drop)
        if self.label_salt_hex is not None and self.label_salt_hex != "":
            if _normalize_salt_hex(self.label_salt_hex, max_hex_chars=int(self.max_hex_chars)) is None:
                raise ValueError("label_salt_hex provided but invalid")

        # Verify timeout validity (finite)
        if self.verify_timeout_s is not None:
            vt = float(self.verify_timeout_s)
            if not _is_finite(vt) or vt < 0:
                raise ValueError("verify_timeout_s must be finite and >= 0")

        m = (self.verify_timeout_mode or "thread").lower().strip()
        if m not in ("thread", "process"):
            raise ValueError("verify_timeout_mode must be 'thread' or 'process'")

        if self.verify_stuck_reset_s is not None:
            ss = float(self.verify_stuck_reset_s)
            if not _is_finite(ss) or ss <= 0:
                raise ValueError("verify_stuck_reset_s must be finite and > 0")

        # Store order semantics
        so = (self.store_order or "unknown").lower().strip()
        if so not in ("unknown", "newest_first", "oldest_first"):
            raise ValueError("store_order must be one of: unknown, newest_first, oldest_first")

        tsm = (self.ts_check_mode or "chain_order").lower().strip()
        if tsm not in ("chain_order", "store_order", "none"):
            raise ValueError("ts_check_mode must be one of: chain_order, store_order, none")
        if tsm == "store_order" and so == "unknown":
            raise ValueError("ts_check_mode=store_order requires store_order != unknown")

        # Schema allowlist enforcement must not be silently disabled
        if self.enforce_auth_policy_digest and not (self.expected_auth_policy_digests and len(self.expected_auth_policy_digests) > 0):
            raise ValueError("enforce_auth_policy_digest=True requires non-empty expected_auth_policy_digests")
        if self.enforce_cfg_digest and not (self.expected_cfg_digests and len(self.expected_cfg_digests) > 0):
            raise ValueError("enforce_cfg_digest=True requires non-empty expected_cfg_digests")
        if self.enforce_calib_digest and not (self.expected_calib_digests and len(self.expected_calib_digests) > 0):
            raise ValueError("enforce_calib_digest=True requires non-empty expected_calib_digests")

        df = (self.digest_format or "any").lower().strip()
        if df not in ("any", "0xhex", "hex", "alg:hex"):
            raise ValueError("digest_format must be one of: any, 0xhex, hex, alg:hex")

        vhf = (self.verify_head_format or "hex").lower().strip()
        if vhf not in ("hex", "0xhex"):
            raise ValueError("verify_head_format must be 'hex' or '0xhex'")

        if int(self.min_chain_len) < 1:
            raise ValueError("min_chain_len must be >= 1")

        # Tip candidate bound
        if int(self.max_tip_candidates) <= 0:
            raise ValueError("max_tip_candidates must be > 0")

        # Process mode bounds
        if int(self.process_mode_max_window_bytes) <= 0 or int(self.process_mode_max_records) <= 0:
            raise ValueError("process_mode_max_window_bytes/process_mode_max_records must be > 0")
        pm = (self.process_ipc_mode or "tempfile").lower().strip()
        if pm not in ("tempfile", "pickle"):
            raise ValueError("process_ipc_mode must be tempfile or pickle")

    def policy_digest(self) -> str:
        """
        Stable policy digest (domain separated SHA-256, strict JSON).
        """
        def _norm_list(xs: Optional[List[str]]) -> Optional[List[str]]:
            if xs is None:
                return None
            out: List[str] = []
            for v in xs:
                out.append(_safe_text(v, max_len=256).strip())
            return sorted(set(out))

        payload: Dict[str, Any] = {
            "name": str(self.name),
            "version": str(self.version),
            "store_id": self.store_id,
            "window": int(self.window),
            "window_cap": int(self.window_cap),
            "max_window_bytes": int(self.max_window_bytes) if self.max_window_bytes is not None else None,
            "max_fetched_bytes": int(self.max_fetched_bytes) if self.max_fetched_bytes is not None else None,
            "store_order": (self.store_order or "unknown").lower().strip(),
            "interval_s": float(self.interval_s),
            "min_sleep_s": float(self.min_sleep_s),
            "fail_retry_s": float(self.fail_retry_s),
            "continue_on_fail": bool(self.continue_on_fail),
            "max_bad_bodies": int(self.max_bad_bodies),
            "label_salt_hex": _normalize_salt_hex(self.label_salt_hex, max_hex_chars=int(self.max_hex_chars)),
            "verify_timeout_s": float(self.verify_timeout_s) if self.verify_timeout_s is not None else None,
            "verify_timeout_mode": (self.verify_timeout_mode or "thread").lower().strip(),
            "verify_stuck_reset_s": float(self.verify_stuck_reset_s) if self.verify_stuck_reset_s is not None else None,
            "verify_fallback_to_process_on_stuck": bool(self.verify_fallback_to_process_on_stuck),
            "process_start_method": (self.process_start_method or "spawn").lower().strip(),
            "process_ipc_mode": (self.process_ipc_mode or "tempfile").lower().strip(),
            "process_mode_max_window_bytes": int(self.process_mode_max_window_bytes),
            "process_mode_max_records": int(self.process_mode_max_records),
            "process_rlimit_cpu_s": int(self.process_rlimit_cpu_s) if self.process_rlimit_cpu_s is not None else None,
            "process_rlimit_as_bytes": int(self.process_rlimit_as_bytes) if self.process_rlimit_as_bytes is not None else None,
            "max_body_bytes_per_row": int(self.max_body_bytes_per_row),
            "max_body_bytes_hard": int(self.max_body_bytes_hard),
            "max_json_depth": int(self.max_json_depth),
            "max_json_depth_scan_chars": int(self.max_json_depth_scan_chars),
            "max_int_digits": int(self.max_int_digits),
            "max_hex_chars": int(self.max_hex_chars),
            "sanitize_invalid_utf8": bool(self.sanitize_invalid_utf8),
            "ordering_mode": (self.ordering_mode or "chain_backtrack").lower().strip(),
            "max_tip_candidates": int(self.max_tip_candidates),
            "min_chain_len": int(self.min_chain_len),
            "treat_gaps_as_fail": bool(self.treat_gaps_as_fail),
            "treat_parse_errors_as_fail": bool(self.treat_parse_errors_as_fail),
            "fail_on_duplicate_heads": bool(self.fail_on_duplicate_heads),
            "fail_on_cycles": bool(self.fail_on_cycles),
            "fail_on_forks": bool(self.fail_on_forks),
            "fail_on_ambiguous_prev": bool(self.fail_on_ambiguous_prev),
            "expect_monotonic_ts_ns": bool(self.expect_monotonic_ts_ns),
            "ts_check_mode": (self.ts_check_mode or "chain_order").lower().strip(),
            "max_future_skew_s": float(self.max_future_skew_s),
            "strict_body_schema": bool(self.strict_body_schema),
            "enforce_body_head_match": bool(self.enforce_body_head_match),
            "enforce_auth_policy_digest": bool(self.enforce_auth_policy_digest),
            "expected_auth_policy_digests": _norm_list(self.expected_auth_policy_digests),
            "enforce_cfg_digest": bool(self.enforce_cfg_digest),
            "expected_cfg_digests": _norm_list(self.expected_cfg_digests),
            "enforce_calib_digest": bool(self.enforce_calib_digest),
            "expected_calib_digests": _norm_list(self.expected_calib_digests),
            "digest_format": (self.digest_format or "any").lower().strip(),
            "verify_head_format": (self.verify_head_format or "hex").lower().strip(),
            # policy signature metadata included (but not raw verify func)
            "policy_sig_alg": self.policy_sig_alg,
            "policy_sig_key_id": self.policy_sig_key_id,
            "policy_sig_present": bool(self.policy_sig_b64),
        }

        b = _canonical_json(payload).encode("utf-8")
        h = hashlib.sha256()
        h.update(b"tcd:chain_audit_policy")
        h.update(b"\x00")
        h.update(b)
        return "0x" + h.hexdigest()


@dataclasses.dataclass(slots=True)
class ChainAuditReport:
    # Existing fields (compat)
    ok: bool
    checked: int
    gaps: int
    parse_errors: int
    latency_s: float

    ts_violations: int = 0
    head_mismatch: int = 0
    audit_policy_digest: str = ""
    verify_impl_digest: str = ""

    auth_policy_violations: int = 0
    cfg_digest_violations: int = 0
    calib_digest_violations: int = 0

    # New platform fields (defaults keep backward compatibility)
    error_kind: str = ERR_NONE
    error_msg: str = ""
    failure_reasons: List[str] = field(default_factory=list)

    # Window accounting
    fetched: int = 0
    fetched_bytes: int = 0
    selected_bytes: int = 0
    dropped_oversize: int = 0
    dropped_fetch_budget: int = 0
    dropped_invalid_head: int = 0
    dropped_parse_skipped: int = 0  # bodies above per-row soft cap
    chain_len: int = 0
    chain_tip_head: str = ""  # truncated/canon
    chain_tip_ts_ns: Optional[int] = None
    ts_min_ns: Optional[int] = None
    ts_max_ns: Optional[int] = None

    # Structural anomalies (counts)
    invalid_heads: int = 0
    oversize_bodies: int = 0
    duplicate_head_groups: int = 0
    duplicate_head_total: int = 0
    forks: int = 0
    cycles: int = 0
    ambiguous_prev: int = 0
    missing_prev: int = 0

    # Verify details
    local_ok: bool = False
    verify_ok: bool = False
    verify_error_kind: str = VERIFY_ERR_NONE
    verify_timed_out: bool = False
    verify_busy: bool = False
    verify_latency_s: float = 0.0
    verify_mode_used: str = ""

    # Latency breakdown
    store_tail_latency_s: float = 0.0
    parse_latency_s: float = 0.0
    ordering_latency_s: float = 0.0

    # Diagnostic samples (strictly truncated)
    sample_bad_head: str = ""
    sample_gap: str = ""
    sample_parse_error_head: str = ""
    sample_duplicate_head: str = ""
    sample_cycle_head: str = ""
    sample_rollback: str = ""


# ---------------------------------------------------------------------------
# Prometheus metrics (multi-instance safe via labels)
# ---------------------------------------------------------------------------

# Small helper to reuse already-registered collectors safely (no import side effect).
def _get_existing_collector(reg: CollectorRegistry, name: str) -> Optional[Any]:
    m = getattr(reg, "_names_to_collectors", None)
    if isinstance(m, dict):
        return m.get(name)
    return None


def _mk_gauge(reg: CollectorRegistry, name: str, doc: str, labelnames: List[str]) -> Gauge:
    try:
        return Gauge(name, doc, labelnames=labelnames, registry=reg)
    except ValueError:
        ex = _get_existing_collector(reg, name)
        if ex is None or not isinstance(ex, Gauge):
            raise
        # Best-effort labelnames compatibility check.
        ln = getattr(ex, "_labelnames", None)
        if ln is not None and tuple(ln) != tuple(labelnames):
            raise
        return ex


def _mk_counter(reg: CollectorRegistry, name: str, doc: str, labelnames: List[str]) -> Counter:
    try:
        return Counter(name, doc, labelnames=labelnames, registry=reg)
    except ValueError:
        ex = _get_existing_collector(reg, name)
        if ex is None or not isinstance(ex, Counter):
            raise
        ln = getattr(ex, "_labelnames", None)
        if ln is not None and tuple(ln) != tuple(labelnames):
            raise
        return ex


def _mk_hist(reg: CollectorRegistry, name: str, doc: str, labelnames: List[str], buckets: Tuple[float, ...]) -> Histogram:
    try:
        return Histogram(name, doc, labelnames=labelnames, buckets=buckets, registry=reg)
    except ValueError:
        ex = _get_existing_collector(reg, name)
        if ex is None or not isinstance(ex, Histogram):
            raise
        ln = getattr(ex, "_labelnames", None)
        if ln is not None and tuple(ln) != tuple(labelnames):
            raise
        return ex


@dataclasses.dataclass(slots=True)
class _MetricsFamilies:
    # Base labels always (multi-instance safe)
    labelnames: Tuple[str, str, str]  # name, version, store

    chain_ok: Gauge
    chain_fail: Counter
    chain_gap_total: Counter
    chain_gap_window: Gauge

    # Latencies
    audit_latency: Histogram
    store_tail_latency: Histogram
    parse_latency: Histogram
    ordering_latency: Histogram
    verify_latency: Histogram

    # Sizes / budgets
    rcpt_size: Histogram
    fetched_count: Gauge
    fetched_bytes: Gauge
    selected_count: Gauge
    selected_bytes: Gauge

    # Store stats
    store_count: Gauge
    store_size: Gauge
    store_last_ts: Gauge
    store_tail_fail: Counter
    store_stats_fail: Counter

    # Parsing/structure counters
    parse_error_total: Counter
    invalid_head_total: Counter
    oversize_body_total: Counter
    duplicate_head_total: Counter
    fork_total: Counter
    cycle_total: Counter
    ambiguous_prev_total: Counter
    missing_prev_total: Counter
    rollback_suspected_total: Counter
    insufficient_budget_total: Counter
    insufficient_chain_total: Counter

    # ts/schema counters
    ts_violation_total: Counter
    head_mismatch_total: Counter
    auth_policy_violation_total: Counter
    cfg_digest_violation_total: Counter
    calib_digest_violation_total: Counter

    # Verify execution
    verify_timeout_total: Counter
    verify_busy_total: Counter
    verify_exception_total: Counter
    verify_spawn_fail_total: Counter
    verify_kill_total: Counter
    verify_inflight: Gauge
    verify_inflight_age_s: Gauge
    verify_stuck_total: Counter
    verify_mode_info: Gauge  # label includes mode

    # Error kind counters
    audit_error_total: Counter  # label includes kind
    verify_error_total: Counter  # label includes kind

    # Policy info (prevent label leak by removing old values)
    policy_info: Gauge  # labels include policy_digest, verify_digest


class _MetricsScope:
    """
    Pre-labeled metric handles for (name, version, store).
    """
    def __init__(self, fam: _MetricsFamilies, *, name: str, version: str, store: str):
        self._fam = fam
        self._lv = (name, version, store)

        self.chain_ok = fam.chain_ok.labels(*self._lv)
        self.chain_fail = fam.chain_fail.labels(*self._lv)
        self.chain_gap_total = fam.chain_gap_total.labels(*self._lv)
        self.chain_gap_window = fam.chain_gap_window.labels(*self._lv)

        self.audit_latency = fam.audit_latency.labels(*self._lv)
        self.store_tail_latency = fam.store_tail_latency.labels(*self._lv)
        self.parse_latency = fam.parse_latency.labels(*self._lv)
        self.ordering_latency = fam.ordering_latency.labels(*self._lv)
        self.verify_latency = fam.verify_latency.labels(*self._lv)

        self.rcpt_size = fam.rcpt_size.labels(*self._lv)
        self.fetched_count = fam.fetched_count.labels(*self._lv)
        self.fetched_bytes = fam.fetched_bytes.labels(*self._lv)
        self.selected_count = fam.selected_count.labels(*self._lv)
        self.selected_bytes = fam.selected_bytes.labels(*self._lv)

        self.store_count = fam.store_count.labels(*self._lv)
        self.store_size = fam.store_size.labels(*self._lv)
        self.store_last_ts = fam.store_last_ts.labels(*self._lv)
        self.store_tail_fail = fam.store_tail_fail.labels(*self._lv)
        self.store_stats_fail = fam.store_stats_fail.labels(*self._lv)

        self.parse_error_total = fam.parse_error_total.labels(*self._lv)
        self.invalid_head_total = fam.invalid_head_total.labels(*self._lv)
        self.oversize_body_total = fam.oversize_body_total.labels(*self._lv)
        self.duplicate_head_total = fam.duplicate_head_total.labels(*self._lv)
        self.fork_total = fam.fork_total.labels(*self._lv)
        self.cycle_total = fam.cycle_total.labels(*self._lv)
        self.ambiguous_prev_total = fam.ambiguous_prev_total.labels(*self._lv)
        self.missing_prev_total = fam.missing_prev_total.labels(*self._lv)
        self.rollback_suspected_total = fam.rollback_suspected_total.labels(*self._lv)
        self.insufficient_budget_total = fam.insufficient_budget_total.labels(*self._lv)
        self.insufficient_chain_total = fam.insufficient_chain_total.labels(*self._lv)

        self.ts_violation_total = fam.ts_violation_total.labels(*self._lv)
        self.head_mismatch_total = fam.head_mismatch_total.labels(*self._lv)
        self.auth_policy_violation_total = fam.auth_policy_violation_total.labels(*self._lv)
        self.cfg_digest_violation_total = fam.cfg_digest_violation_total.labels(*self._lv)
        self.calib_digest_violation_total = fam.calib_digest_violation_total.labels(*self._lv)

        self.verify_timeout_total = fam.verify_timeout_total.labels(*self._lv)
        self.verify_busy_total = fam.verify_busy_total.labels(*self._lv)
        self.verify_exception_total = fam.verify_exception_total.labels(*self._lv)
        self.verify_spawn_fail_total = fam.verify_spawn_fail_total.labels(*self._lv)
        self.verify_kill_total = fam.verify_kill_total.labels(*self._lv)
        self.verify_inflight = fam.verify_inflight.labels(*self._lv)
        self.verify_inflight_age_s = fam.verify_inflight_age_s.labels(*self._lv)
        self.verify_stuck_total = fam.verify_stuck_total.labels(*self._lv)

        # verify_mode_info has an extra label "mode"
        self._verify_mode_info = fam.verify_mode_info

        # error kind counters have extra label "kind"
        self._audit_error_total = fam.audit_error_total
        self._verify_error_total = fam.verify_error_total

        # policy info includes digests
        self._policy_info = fam.policy_info

    def inc_audit_error(self, kind: str) -> None:
        try:
            self._audit_error_total.labels(*self._lv, kind=_safe_text(kind, max_len=32)).inc()
        except Exception:
            pass

    def inc_verify_error(self, kind: str) -> None:
        try:
            self._verify_error_total.labels(*self._lv, kind=_safe_text(kind, max_len=32)).inc()
        except Exception:
            pass

    def set_verify_mode(self, mode: str) -> None:
        # gauge with label mode; set 1.0 for current mode, leave others untouched (low cardinality)
        try:
            self._verify_mode_info.labels(*self._lv, mode=_safe_text(mode, max_len=16)).set(1.0)
        except Exception:
            pass

    def set_policy_info(self, policy_digest: str, verify_digest: str) -> None:
        # Remove previous labelset to prevent leak.
        _policy_info_set(self._policy_info, self._lv, policy_digest, verify_digest)


_POLICY_INFO_LOCK = threading.Lock()
_POLICY_INFO_LAST: Dict[Tuple[str, str, str], Tuple[str, str]] = {}


def _policy_info_set(g: Gauge, lv: Tuple[str, str, str], policy_digest: str, verify_digest: str) -> None:
    pd = _safe_text(policy_digest, max_len=80)
    vd = _safe_text(verify_digest, max_len=80)
    with _POLICY_INFO_LOCK:
        old = _POLICY_INFO_LAST.get(lv)
        if old is not None and old != (pd, vd):
            try:
                g.remove(lv[0], lv[1], lv[2], old[0], old[1])
            except Exception:
                pass
        _POLICY_INFO_LAST[lv] = (pd, vd)
    try:
        g.labels(lv[0], lv[1], lv[2], pd, vd).set(1.0)
    except Exception:
        pass


def build_metrics(registry: Optional[CollectorRegistry] = None) -> _MetricsFamilies:
    """
    Build (or reuse) metrics families in a registry. Safe to call multiple times.
    All metrics are labeled by (name, version, store), making multiple auditors safe.
    """
    reg = registry or REGISTRY
    base = ["name", "version", "store"]

    fam = _MetricsFamilies(
        labelnames=("name", "version", "store"),
        chain_ok=_mk_gauge(reg, "tcd_chain_verify_ok", "Recent chain verified OK", base),
        chain_fail=_mk_counter(reg, "tcd_chain_verify_fail_total", "Verification rounds that ended not-ok", base),
        chain_gap_total=_mk_counter(reg, "tcd_chain_gap_total", "Total prev gaps observed", base),
        chain_gap_window=_mk_gauge(reg, "tcd_chain_gap_window", "Prev gaps in last selected chain", base),
        audit_latency=_mk_hist(
            reg,
            "tcd_chain_audit_latency_seconds",
            "End-to-end audit latency (seconds)",
            base,
            buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20, 0.50, 1.0, 2.0, 5.0),
        ),
        store_tail_latency=_mk_hist(
            reg,
            "tcd_chain_store_tail_latency_seconds",
            "store.tail latency (seconds)",
            base,
            buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20, 0.50, 1.0, 2.0),
        ),
        parse_latency=_mk_hist(
            reg,
            "tcd_chain_parse_latency_seconds",
            "Parse/scan latency (seconds)",
            base,
            buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20, 0.50, 1.0),
        ),
        ordering_latency=_mk_hist(
            reg,
            "tcd_chain_ordering_latency_seconds",
            "Ordering/selection latency (seconds)",
            base,
            buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20, 0.50, 1.0),
        ),
        verify_latency=_mk_hist(
            reg,
            "tcd_chain_verify_latency_seconds",
            "verify_chain latency (seconds)",
            base,
            buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20, 0.50, 1.0, 2.0, 5.0),
        ),
        rcpt_size=_mk_hist(
            reg,
            "tcd_receipt_size_bytes",
            "Receipt body size (bytes)",
            base,
            buckets=(128, 256, 512, 1024, 2048, 4096, 8192, 16384, 65536, 262144, 524288),
        ),
        fetched_count=_mk_gauge(reg, "tcd_chain_fetched_count", "Rows fetched from store.tail", base),
        fetched_bytes=_mk_gauge(reg, "tcd_chain_fetched_bytes", "Total bytes of fetched bodies", base),
        selected_count=_mk_gauge(reg, "tcd_chain_selected_count", "Rows selected for verification", base),
        selected_bytes=_mk_gauge(reg, "tcd_chain_selected_bytes", "Total bytes of selected bodies", base),
        store_count=_mk_gauge(reg, "tcd_store_count", "Total receipts (store-reported)", base),
        store_size=_mk_gauge(reg, "tcd_store_size_bytes", "Approx store size (bytes)", base),
        store_last_ts=_mk_gauge(reg, "tcd_store_last_ts_seconds", "Timestamp of last receipt (epoch seconds)", base),
        store_tail_fail=_mk_counter(reg, "tcd_chain_store_tail_fail_total", "store.tail failures", base),
        store_stats_fail=_mk_counter(reg, "tcd_chain_store_stats_fail_total", "store.stats failures", base),
        parse_error_total=_mk_counter(reg, "tcd_chain_parse_error_total", "Body JSON parse/structure errors", base),
        invalid_head_total=_mk_counter(reg, "tcd_chain_invalid_head_total", "Invalid head_hex observed", base),
        oversize_body_total=_mk_counter(reg, "tcd_chain_body_oversize_total", "Bodies dropped due to oversize", base),
        duplicate_head_total=_mk_counter(reg, "tcd_chain_duplicate_head_total", "Duplicate head occurrences", base),
        fork_total=_mk_counter(reg, "tcd_chain_fork_total", "Forks observed (prev referenced by >1 child)", base),
        cycle_total=_mk_counter(reg, "tcd_chain_cycle_total", "Cycles detected in window graph", base),
        ambiguous_prev_total=_mk_counter(reg, "tcd_chain_ambiguous_prev_total", "Ambiguous prev (prev maps to multiple heads)", base),
        missing_prev_total=_mk_counter(reg, "tcd_chain_missing_prev_total", "Missing prev (prev not found in window)", base),
        rollback_suspected_total=_mk_counter(reg, "tcd_chain_rollback_suspected_total", "Rollback suspected across windows", base),
        insufficient_budget_total=_mk_counter(reg, "tcd_chain_insufficient_budget_total", "Budget insufficient for min_chain_len", base),
        insufficient_chain_total=_mk_counter(reg, "tcd_chain_insufficient_chain_total", "Longest chain shorter than min_chain_len", base),
        ts_violation_total=_mk_counter(reg, "tcd_chain_ts_violation_total", "ts_ns violations (monotonic/range)", base),
        head_mismatch_total=_mk_counter(reg, "tcd_chain_head_mismatch_total", '"head" mismatches in body (strict)', base),
        auth_policy_violation_total=_mk_counter(reg, "tcd_chain_auth_policy_violation_total", "auth_policy_digest violations", base),
        cfg_digest_violation_total=_mk_counter(reg, "tcd_chain_cfg_digest_violation_total", "cfg_digest violations", base),
        calib_digest_violation_total=_mk_counter(reg, "tcd_chain_calib_digest_violation_total", "calib_state_digest violations", base),
        verify_timeout_total=_mk_counter(reg, "tcd_chain_verify_timeout_total", "verify timed out", base),
        verify_busy_total=_mk_counter(reg, "tcd_chain_verify_busy_total", "verify busy (already in-flight)", base),
        verify_exception_total=_mk_counter(reg, "tcd_chain_verify_exception_total", "verify raised exception", base),
        verify_spawn_fail_total=_mk_counter(reg, "tcd_chain_verify_process_spawn_fail_total", "verify process spawn failures", base),
        verify_kill_total=_mk_counter(reg, "tcd_chain_verify_process_kill_total", "verify process kill attempts", base),
        verify_inflight=_mk_gauge(reg, "tcd_chain_verify_inflight", "verify in-flight (0/1)", base),
        verify_inflight_age_s=_mk_gauge(reg, "tcd_chain_verify_inflight_age_seconds", "verify in-flight age (seconds)", base),
        verify_stuck_total=_mk_counter(reg, "tcd_chain_verify_stuck_total", "verify stuck detected", base),
        verify_mode_info=_mk_gauge(
            reg,
            "tcd_chain_verify_mode_info",
            "Verify mode info gauge (value=1)",
            base + ["mode"],
        ),
        audit_error_total=_mk_counter(
            reg,
            "tcd_chain_audit_error_total",
            "Audit errors by kind",
            base + ["kind"],
        ),
        verify_error_total=_mk_counter(
            reg,
            "tcd_chain_verify_error_total",
            "Verify errors by kind",
            base + ["kind"],
        ),
        policy_info=_mk_gauge(
            reg,
            "tcd_chain_audit_policy_info",
            "Chain auditor policy info (value=1)",
            base + ["policy_digest", "verify_digest"],
        ),
    )
    return fam


_DEFAULT_METRICS_LOCK = threading.Lock()
_DEFAULT_METRICS: Optional[_MetricsFamilies] = None


def _get_default_metrics() -> _MetricsFamilies:
    global _DEFAULT_METRICS
    with _DEFAULT_METRICS_LOCK:
        if _DEFAULT_METRICS is None:
            _DEFAULT_METRICS = build_metrics()
        return _DEFAULT_METRICS


# ---------------------------------------------------------------------------
# Log rate limiter
# ---------------------------------------------------------------------------


class _LogRateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._last: Dict[str, float] = {}

    def allow(self, key: str, interval_s: float) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last.get(key, 0.0)
            if now - last >= max(0.0, float(interval_s)):
                self._last[key] = now
                return True
            return False


_LOG_RL = _LogRateLimiter()


# ---------------------------------------------------------------------------
# Digest normalization for allowlists (strict)
# ---------------------------------------------------------------------------


def _normalize_digest_token_strict(s: Any, *, fmt: str, max_hex_chars: int) -> Optional[str]:
    """
    Strict digest normalization (no "plain string bypass"):
      - any: accepts hex/0xhex or alg:hex, returns canonical:
          * hex -> "0x" + hex
          * alg:hex -> "<alg>:0x<hex>"
      - 0xhex: returns "0x<hex>"
      - hex: returns "<hex>"
      - alg:hex: returns "<alg>:0x<hex>"
    Returns None if not parseable under the selected format.
    """
    if not isinstance(s, str):
        return None
    ss = s.strip()
    if ss == "":
        return None
    f = (fmt or "any").lower().strip()

    if f in ("any", "alg:hex"):
        m = _ALG_HEX_RE.match(ss)
        if m:
            alg = m.group(1).lower()
            hx = m.group(2)
            hx2 = _canon_hex_no_prefix_limited(hx, max_hex_chars=max_hex_chars)
            if hx2 is None:
                return None
            return f"{alg}:0x{hx2}"
        if f == "alg:hex":
            return None  # must be alg:hex

    if f in ("any", "0xhex"):
        hx0 = _canon_hex_no_prefix_limited(ss, max_hex_chars=max_hex_chars)
        if hx0 is not None:
            return "0x" + hx0
        return None

    if f == "hex":
        hx1 = _canon_hex_no_prefix_limited(ss, max_hex_chars=max_hex_chars)
        return hx1

    return None


# ---------------------------------------------------------------------------
# Receipt normalization / parsing with guards
# ---------------------------------------------------------------------------


def _coerce_field_strict(x: Any) -> Optional[str]:
    # Avoid calling str() on arbitrary objects (DoS / side effects).
    if isinstance(x, str):
        return x
    if isinstance(x, (bytes, bytearray, memoryview)):
        return bytes(x).decode("utf-8", errors="replace")
    return None


def _normalize_rows_strict(rows: Iterable[Any], *, hard_cap: int) -> List[ReceiptRow]:
    out: List[ReceiptRow] = []
    for r in rows:
        if len(out) >= hard_cap:
            break
        if isinstance(r, ReceiptRow):
            h = _coerce_field_strict(r.head_hex)
            b = _coerce_field_strict(r.body_json)
            if h is None or b is None:
                raise TypeError("ReceiptRow fields must be str/bytes")
            out.append(ReceiptRow(h, b))
            continue
        if isinstance(r, tuple) and len(r) == 2:
            h = _coerce_field_strict(r[0])
            b = _coerce_field_strict(r[1])
            if h is None or b is None:
                raise TypeError("tuple(head, body) fields must be str/bytes")
            out.append(ReceiptRow(h, b))
            continue
        if isinstance(r, dict):
            if "head_hex" not in r or "body_json" not in r:
                raise TypeError("dict row missing head_hex/body_json")
            h = _coerce_field_strict(r["head_hex"])
            b = _coerce_field_strict(r["body_json"])
            if h is None or b is None:
                raise TypeError("dict row head_hex/body_json must be str/bytes")
            out.append(ReceiptRow(h, b))
            continue
        # Object attributes
        h = _coerce_field_strict(getattr(r, "head_hex", None))
        b = _coerce_field_strict(getattr(r, "body_json", None))
        if h is None or b is None:
            raise TypeError("Unsupported row type from ReceiptStore.tail()")
        out.append(ReceiptRow(h, b))
    return out


@dataclasses.dataclass(slots=True)
class _Rec:
    idx: int
    head_raw: str
    head_canon: Optional[str]  # lowercase hex no prefix
    head_verify: Optional[str]  # per cfg.verify_head_format
    body_raw: str
    body_bytes: int
    oversize: bool
    utf8_valid: bool

    # meta extracted from JSON body (guarded)
    parse_error: bool
    obj: Optional[Dict[str, Any]]
    prev_canon: Optional[str]
    ts_ns: Optional[int]


def _safe_parse_body_meta(
    body: str,
    *,
    max_body_bytes_per_row: int,
    max_json_depth: int,
    max_json_depth_scan_chars: int,
    max_int_digits: int,
    sanitize_invalid_utf8: bool,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str], Optional[int], bool]:
    """
    Returns (parse_error, obj, prev_str, ts_ns, utf8_valid).
    - parse_error True covers JSON parse failure OR top-level not dict OR soft-cap skip.
    - utf8_valid is strict-utf8 encodability of Python str.
    """
    # UTF-8 validity check (surrogate DoS).
    utf8_valid = True
    try:
        body.encode("utf-8", errors="strict")
    except Exception:
        utf8_valid = False
        if sanitize_invalid_utf8:
            body = body.encode("utf-8", errors="replace").decode("utf-8", errors="strict")
        else:
            return True, None, None, None, False

    bsz = _utf8_len_lossy(body)
    if bsz > int(max_body_bytes_per_row):
        # soft cap: do not parse; caller counts as parse_skipped
        return True, None, None, None, utf8_valid

    if not _bracket_depth_guard(body, max_depth=int(max_json_depth), max_scan_chars=int(max_json_depth_scan_chars)):
        return True, None, None, None, utf8_valid

    try:
        obj = json.loads(body, parse_int=_make_parse_int_limiter(int(max_int_digits)))
    except Exception:
        return True, None, None, None, utf8_valid

    if not isinstance(obj, dict):
        return True, None, None, None, utf8_valid

    pv = obj.get("prev")
    prev_str = pv if isinstance(pv, str) else None
    tv = obj.get("ts_ns")
    ts_ns = int(tv) if isinstance(tv, int) else None
    return False, obj, prev_str, ts_ns, utf8_valid


def _store_label(store: ReceiptStore, cfg: ChainAuditConfig) -> str:
    if cfg.store_id:
        return _safe_text(cfg.store_id, max_len=64)
    # fallback: store class name
    return _safe_text(store.__class__.__name__, max_len=64)


# ---------------------------------------------------------------------------
# Chain reconstruction (chain semantics, not topo heuristics)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(slots=True)
class _ChainBuildStats:
    invalid_heads: int = 0
    oversize_bodies: int = 0
    parse_errors: int = 0
    parse_skipped: int = 0
    duplicate_head_groups: int = 0
    duplicate_head_total: int = 0
    forks: int = 0
    cycles: int = 0
    ambiguous_prev: int = 0
    missing_prev: int = 0

    sample_bad_head: str = ""
    sample_parse_error_head: str = ""
    sample_duplicate_head: str = ""
    sample_cycle_head: str = ""

    # derived
    ts_min_ns: Optional[int] = None
    ts_max_ns: Optional[int] = None


def _compute_forks(recs: List[_Rec]) -> Tuple[int, Optional[str]]:
    # fork: a prev head referenced by >1 child within considered records
    prev_to_children: Dict[str, int] = {}
    sample: Optional[str] = None
    for r in recs:
        if r.head_canon is None:
            continue
        if r.prev_canon is None:
            continue
        prev_to_children[r.prev_canon] = prev_to_children.get(r.prev_canon, 0) + 1
    forks = 0
    for pv, c in prev_to_children.items():
        if c > 1:
            forks += 1
            if sample is None:
                sample = pv[:16]
    return forks, sample


def _detect_cycles_unique_heads(recs: List[_Rec]) -> Tuple[int, Optional[str]]:
    """
    Best-effort cycle detection on unique-head graph.
    Duplicate heads already flagged separately.
    """
    # Build mapping unique head -> unique prev (only when both are unique)
    head_to_prev: Dict[str, str] = {}
    head_counts: Dict[str, int] = {}
    for r in recs:
        if r.head_canon is None:
            continue
        head_counts[r.head_canon] = head_counts.get(r.head_canon, 0) + 1

    for r in recs:
        if r.head_canon is None or r.prev_canon is None:
            continue
        if head_counts.get(r.head_canon, 0) != 1:
            continue
        if head_counts.get(r.prev_canon, 0) != 1:
            continue
        head_to_prev[r.head_canon] = r.prev_canon

    # Floyd cycle detection on each node (bounded)
    seen_global: set[str] = set()
    cycles = 0
    sample: Optional[str] = None

    for start in list(head_to_prev.keys()):
        if start in seen_global:
            continue
        tort = start
        hare = start
        while True:
            tort = head_to_prev.get(tort, "")
            hare = head_to_prev.get(hare, "")
            hare = head_to_prev.get(hare, "") if hare else ""
            if not tort or not hare:
                break
            if tort == hare:
                cycles += 1
                if sample is None:
                    sample = tort[:16]
                break
        # mark path as seen (best-effort)
        cur = start
        for _ in range(1024):
            if cur in seen_global or cur == "":
                break
            seen_global.add(cur)
            cur = head_to_prev.get(cur, "")
    return cycles, sample


def _pick_best_tip_candidates(recs: List[_Rec], cfg: ChainAuditConfig) -> List[int]:
    """
    Choose candidate tips:
      - tips are heads not referenced as prev by any other record (within window),
      - fall back to all valid heads if none.
    Sort by ts desc, then idx desc (newer-ish), deterministic.
    """
    head_set = {r.head_canon for r in recs if r.head_canon is not None}
    referenced = set()
    for r in recs:
        if r.prev_canon is not None and r.prev_canon in head_set:
            referenced.add(r.prev_canon)

    tips = [r.idx for r in recs if r.head_canon is not None and r.head_canon not in referenced and not r.oversize]
    if not tips:
        tips = [r.idx for r in recs if r.head_canon is not None and not r.oversize]

    # sort by ts desc (None last), then idx desc
    def key(i: int) -> Tuple[int, int, int]:
        rr = recs[i]
        t = rr.ts_ns
        # want None last: (0 for has ts, 1 for none) in ascending would place has ts first,
        # but we want ts desc, so invert carefully.
        # We'll use tuple with has_ts flag first.
        has = 0 if t is not None else 1
        return (has, -(t or 0), -i)

    tips_sorted = sorted(tips, key=key)
    return tips_sorted[: max(1, int(cfg.max_tip_candidates))]


def _select_head_verify(head_canon: str, *, fmt: str) -> str:
    f = (fmt or "hex").lower().strip()
    if f == "0xhex":
        return "0x" + head_canon
    return head_canon


def _build_chain_best_effort(
    recs: List[_Rec],
    cfg: ChainAuditConfig,
) -> Tuple[List[int], _ChainBuildStats]:
    """
    Build the best chain (oldest->newest indices into recs) using prev backtracking.
    Stops chain on missing prev / ambiguous prev / cycle.
    """
    st = _ChainBuildStats()

    # Count duplicates and build head->indices map
    head_to_idxs: Dict[str, List[int]] = {}
    for r in recs:
        if r.head_canon is None:
            continue
        head_to_idxs.setdefault(r.head_canon, []).append(r.idx)

    for h, li in head_to_idxs.items():
        if len(li) > 1:
            st.duplicate_head_groups += 1
            st.duplicate_head_total += (len(li) - 1)
            if not st.sample_duplicate_head:
                st.sample_duplicate_head = h[:16]

    # forks/cycles (global best-effort)
    forks, _fork_sample = _compute_forks(recs)
    st.forks = forks
    cycles, cyc_sample = _detect_cycles_unique_heads(recs)
    st.cycles = cycles
    if cyc_sample and not st.sample_cycle_head:
        st.sample_cycle_head = cyc_sample

    tips = _pick_best_tip_candidates(recs, cfg)

    def backtrack_from(tip_i: int) -> Tuple[List[int], int, int, int]:
        """
        Returns:
          chain_indices (oldest->newest),
          missing_prev, ambiguous_prev, cycle_hit (0/1)
        """
        chain_rev: List[int] = []
        visited: set[str] = set()
        missing = 0
        amb = 0
        cyc = 0
        cur = tip_i
        for _ in range(int(cfg.window_cap) + 5):
            rr = recs[cur]
            if rr.head_canon is None:
                break
            if rr.head_canon in visited:
                cyc = 1
                break
            visited.add(rr.head_canon)
            chain_rev.append(cur)
            pv = rr.prev_canon
            if pv is None:
                break
            cand = head_to_idxs.get(pv)
            if not cand:
                missing = 1
                break
            if len(cand) != 1:
                amb = 1
                break
            cur = cand[0]
        chain = list(reversed(chain_rev))
        return chain, missing, amb, cyc

    best: List[int] = []
    best_meta: Tuple[int, int, int, int] = (0, 0, 0, 0)  # len, missing, amb, cyc
    best_tip_ts: int = -1
    best_tip_i: int = -1

    for tip_i in tips:
        chain, missing, amb, cyc = backtrack_from(tip_i)
        tip_ts = recs[tip_i].ts_ns or -1

        meta = (len(chain), missing, amb, cyc)

        # Prefer longer chain; then fewer anomalies; then higher tip_ts; then higher tip index.
        if len(chain) > len(best):
            best, best_meta, best_tip_ts, best_tip_i = chain, meta, tip_ts, tip_i
        elif len(chain) == len(best):
            # fewer anomalies (missing+amb+cyc)
            a1 = best_meta[1] + best_meta[2] + best_meta[3]
            a2 = meta[1] + meta[2] + meta[3]
            if a2 < a1:
                best, best_meta, best_tip_ts, best_tip_i = chain, meta, tip_ts, tip_i
            elif a2 == a1:
                if tip_ts > best_tip_ts:
                    best, best_meta, best_tip_ts, best_tip_i = chain, meta, tip_ts, tip_i
                elif tip_ts == best_tip_ts and tip_i > best_tip_i:
                    best, best_meta, best_tip_ts, best_tip_i = chain, meta, tip_ts, tip_i

    st.missing_prev = int(best_meta[1])
    st.ambiguous_prev = int(best_meta[2])
    # cycle_hit in best chain backtrack
    if best_meta[3] and not st.sample_cycle_head and best:
        st.sample_cycle_head = (recs[best[-1]].head_canon or "")[:16]

    # ts range in best chain
    ts_vals = [recs[i].ts_ns for i in best if recs[i].ts_ns is not None]
    if ts_vals:
        st.ts_min_ns = min(ts_vals)
        st.ts_max_ns = max(ts_vals)

    return best, st


def _select_chain_suffix_by_budget(
    chain: List[int],
    recs: List[_Rec],
    *,
    max_bytes: Optional[int],
) -> Tuple[List[int], int]:
    if not chain:
        return [], 0
    if max_bytes is None or int(max_bytes) <= 0:
        total = sum(recs[i].body_bytes for i in chain)
        return chain, int(total)

    b = int(max_bytes)
    total = 0
    keep_rev: List[int] = []
    for i in reversed(chain):
        sz = int(recs[i].body_bytes)
        if keep_rev and (total + sz) > b:
            break
        total += sz
        keep_rev.append(i)
    keep = list(reversed(keep_rev))
    if not keep:
        # keep none (budget too small); return last element only to keep deterministic diagnostics
        keep = [chain[-1]]
        total = int(recs[keep[0]].body_bytes)
    return keep, int(total)


# ---------------------------------------------------------------------------
# Verify execution subsystem (thread/process, spawn-safe)
# ---------------------------------------------------------------------------

# Top-level worker for spawn (picklable).
def _verify_proc_worker(conn, payload_path: str, rlimit_cpu_s: Optional[int], rlimit_as_bytes: Optional[int]) -> None:  # pragma: no cover
    # Apply best-effort resource limits (POSIX only).
    try:
        if rlimit_cpu_s is not None or rlimit_as_bytes is not None:
            import resource  # type: ignore
            if rlimit_cpu_s is not None:
                lim = int(rlimit_cpu_s)
                resource.setrlimit(resource.RLIMIT_CPU, (lim, lim))
            if rlimit_as_bytes is not None:
                lim2 = int(rlimit_as_bytes)
                resource.setrlimit(resource.RLIMIT_AS, (lim2, lim2))
    except Exception:
        pass

    ok = False
    try:
        with open(payload_path, "rb") as fh:
            payload = json.loads(fh.read().decode("utf-8"))
        heads = payload.get("heads")
        bodies = payload.get("bodies")
        salt = payload.get("salt")
        if not isinstance(heads, list) or not isinstance(bodies, list):
            ok = False
        else:
            # Import verify inside worker.
            from .verify import verify_chain  # type: ignore
            ok = bool(verify_chain(heads, bodies, label_salt_hex=salt))
    except Exception:
        ok = False
    try:
        conn.send(bool(ok))
    except Exception:
        pass
    try:
        conn.close()
    except Exception:
        pass


@dataclasses.dataclass(slots=True)
class _VerifyResult:
    ok: bool
    error_kind: str
    timed_out: bool
    busy: bool
    latency_s: float
    mode_used: str


class _VerifyExecutor:
    """
    Per-(name,version,store) verify executor:
    - capacity=1 (no queue leak)
    - exposes inflight + age
    - thread mode: daemon thread; cannot kill; uses inflight age + stuck detection + fallback
    - process mode: spawn-safe worker with tempfile IPC and hard terminate on timeout
    """
    def __init__(self) -> None:
        self._sem = threading.BoundedSemaphore(1)
        self._lock = threading.Lock()
        self._inflight: bool = False
        self._started_at: float = 0.0
        self._mode: str = ""

    def inflight_age_s(self) -> float:
        with self._lock:
            if not self._inflight:
                return 0.0
            return max(0.0, time.monotonic() - self._started_at)

    def inflight(self) -> bool:
        with self._lock:
            return bool(self._inflight)

    def _set_inflight(self, on: bool, mode: str) -> None:
        with self._lock:
            self._inflight = on
            self._mode = mode
            self._started_at = time.monotonic() if on else 0.0

    def run(
        self,
        heads: List[str],
        bodies: List[str],
        salt: Optional[str],
        cfg: ChainAuditConfig,
        ms: _MetricsScope,
    ) -> _VerifyResult:
        mode = (cfg.verify_timeout_mode or "thread").lower().strip()
        timeout_s = cfg.verify_timeout_s
        if timeout_s is not None and float(timeout_s) == 0:
            timeout_s = None

        # publish mode info
        ms.set_verify_mode(mode)

        # update inflight gauges
        ms.verify_inflight.set(1.0 if self.inflight() else 0.0)
        ms.verify_inflight_age_s.set(float(self.inflight_age_s()))

        # busy detection + stuck handling
        if not self._sem.acquire(blocking=False):
            age = self.inflight_age_s()
            ms.verify_inflight.set(1.0)
            ms.verify_inflight_age_s.set(float(age))
            ms.verify_busy_total.inc()
            ms.inc_verify_error(VERIFY_ERR_BUSY)

            # stuck detection
            if cfg.verify_stuck_reset_s is not None and age > float(cfg.verify_stuck_reset_s):
                ms.verify_stuck_total.inc()
                if cfg.verify_fallback_to_process_on_stuck:
                    # Try process fallback even though a thread verify may be stuck.
                    return self._run_process(heads, bodies, salt, cfg, ms, bypass_sem=True, stuck_fallback=True)
            return _VerifyResult(
                ok=False,
                error_kind=VERIFY_ERR_BUSY,
                timed_out=False,
                busy=True,
                latency_s=0.0,
                mode_used=mode,
            )

        # acquired slot
        self._set_inflight(True, mode)
        ms.verify_inflight.set(1.0)
        ms.verify_inflight_age_s.set(0.0)

        try:
            if mode == "process":
                return self._run_process(heads, bodies, salt, cfg, ms, bypass_sem=False, stuck_fallback=False)
            return self._run_thread(heads, bodies, salt, cfg, ms, timeout_s)
        finally:
            # slot release is handled in worker completion for thread-timeout case,
            # so we must not release here unconditionally.
            pass

    def _run_thread(
        self,
        heads: List[str],
        bodies: List[str],
        salt: Optional[str],
        cfg: ChainAuditConfig,
        ms: _MetricsScope,
        timeout_s: Optional[float],
    ) -> _VerifyResult:
        t0 = time.perf_counter()

        # Inline if no timeout requested (still bounded by semaphore).
        if timeout_s is None or float(timeout_s) <= 0:
            try:
                from .verify import verify_chain  # type: ignore
            except Exception:
                ms.verify_exception_total.inc()
                ms.inc_verify_error(VERIFY_ERR_IMPORT)
                self._set_inflight(False, "")
                try:
                    self._sem.release()
                except Exception:
                    pass
                ms.verify_inflight.set(0.0)
                ms.verify_inflight_age_s.set(0.0)
                return _VerifyResult(False, VERIFY_ERR_IMPORT, False, False, 0.0, "thread")

            try:
                ok = bool(verify_chain(heads, bodies, label_salt_hex=salt))
                lat = time.perf_counter() - t0
                ms.verify_latency.observe(lat)
                self._set_inflight(False, "")
                try:
                    self._sem.release()
                except Exception:
                    pass
                ms.verify_inflight.set(0.0)
                ms.verify_inflight_age_s.set(0.0)
                return _VerifyResult(ok, VERIFY_ERR_NONE if ok else VERIFY_ERR_NONE, False, False, float(lat), "thread")
            except Exception:
                ms.verify_exception_total.inc()
                ms.inc_verify_error(VERIFY_ERR_EXCEPTION)
                lat = time.perf_counter() - t0
                ms.verify_latency.observe(lat)
                self._set_inflight(False, "")
                try:
                    self._sem.release()
                except Exception:
                    pass
                ms.verify_inflight.set(0.0)
                ms.verify_inflight_age_s.set(0.0)
                return _VerifyResult(False, VERIFY_ERR_EXCEPTION, False, False, float(lat), "thread")

        done = threading.Event()
        ok_box: Dict[str, Any] = {"ok": False, "err": VERIFY_ERR_NONE}

        def _worker() -> None:
            try:
                from .verify import verify_chain  # type: ignore
                ok_box["ok"] = bool(verify_chain(heads, bodies, label_salt_hex=salt))
            except ImportError:
                ok_box["ok"] = False
                ok_box["err"] = VERIFY_ERR_IMPORT
            except Exception:
                ok_box["ok"] = False
                ok_box["err"] = VERIFY_ERR_EXCEPTION
            finally:
                done.set()
                # release slot only when worker finishes
                self._set_inflight(False, "")
                try:
                    self._sem.release()
                except Exception:
                    pass
                ms.verify_inflight.set(0.0)
                ms.verify_inflight_age_s.set(0.0)

        th = threading.Thread(target=_worker, name="tcd-chain-verify", daemon=True)
        th.start()

        if done.wait(timeout=float(timeout_s)):
            lat = time.perf_counter() - t0
            ms.verify_latency.observe(lat)
            err = str(ok_box.get("err") or VERIFY_ERR_NONE)
            if err == VERIFY_ERR_IMPORT:
                ms.verify_exception_total.inc()
                ms.inc_verify_error(VERIFY_ERR_IMPORT)
            elif err == VERIFY_ERR_EXCEPTION:
                ms.verify_exception_total.inc()
                ms.inc_verify_error(VERIFY_ERR_EXCEPTION)
            ok = bool(ok_box.get("ok"))
            return _VerifyResult(ok, err if not ok else VERIFY_ERR_NONE, False, False, float(lat), "thread")

        # timeout (thread continues; semaphore stays held until worker completes)
        ms.verify_timeout_total.inc()
        ms.inc_verify_error(VERIFY_ERR_TIMEOUT)
        lat = time.perf_counter() - t0
        ms.verify_latency.observe(lat)
        # keep inflight gauges updated
        ms.verify_inflight.set(1.0)
        ms.verify_inflight_age_s.set(float(self.inflight_age_s()))
        return _VerifyResult(False, VERIFY_ERR_TIMEOUT, True, False, float(lat), "thread")

    def _run_process(
        self,
        heads: List[str],
        bodies: List[str],
        salt: Optional[str],
        cfg: ChainAuditConfig,
        ms: _MetricsScope,
        *,
        bypass_sem: bool,
        stuck_fallback: bool,
    ) -> _VerifyResult:
        t0 = time.perf_counter()

        # Cost control
        if len(heads) > int(cfg.process_mode_max_records):
            ms.verify_exception_total.inc()
            ms.inc_verify_error(VERIFY_ERR_INPUT)
            if not bypass_sem:
                self._set_inflight(False, "")
                try:
                    self._sem.release()
                except Exception:
                    pass
                ms.verify_inflight.set(0.0)
                ms.verify_inflight_age_s.set(0.0)
            return _VerifyResult(False, VERIFY_ERR_INPUT, False, False, 0.0, "process")

        total_bytes = sum(_utf8_len_lossy(b) for b in bodies)
        if total_bytes > int(cfg.process_mode_max_window_bytes):
            ms.verify_exception_total.inc()
            ms.inc_verify_error(VERIFY_ERR_INPUT)
            if not bypass_sem:
                self._set_inflight(False, "")
                try:
                    self._sem.release()
                except Exception:
                    pass
                ms.verify_inflight.set(0.0)
                ms.verify_inflight_age_s.set(0.0)
            return _VerifyResult(False, VERIFY_ERR_INPUT, False, False, 0.0, "process")

        timeout_s = cfg.verify_timeout_s
        if timeout_s is not None and float(timeout_s) == 0:
            timeout_s = None

        # Mark inflight for process mode too (unless bypassing due to stuck thread)
        if not bypass_sem:
            self._set_inflight(True, "process")
            ms.verify_inflight.set(1.0)
            ms.verify_inflight_age_s.set(0.0)

        try:
            import multiprocessing as mp
        except Exception:
            ms.verify_spawn_fail_total.inc()
            ms.inc_verify_error(VERIFY_ERR_SPAWN_FAIL)
            if not bypass_sem:
                self._set_inflight(False, "")
                try:
                    self._sem.release()
                except Exception:
                    pass
                ms.verify_inflight.set(0.0)
                ms.verify_inflight_age_s.set(0.0)
            lat = time.perf_counter() - t0
            ms.verify_latency.observe(lat)
            return _VerifyResult(False, VERIFY_ERR_SPAWN_FAIL, False, False, float(lat), "process")

        method = (cfg.process_start_method or "spawn").lower().strip()
        try:
            ctx = mp.get_context(method)
        except Exception:
            ctx = mp.get_context("spawn")

        # IPC via tempfile (avoids pickling huge payload)
        payload_path = ""
        tmp = None
        try:
            tmp = tempfile.NamedTemporaryFile("wb", delete=False, prefix="tcd_verify_", suffix=".json")
            payload_path = tmp.name
            payload = {"heads": heads, "bodies": bodies, "salt": salt}
            tmp.write(_canonical_json(payload).encode("utf-8"))
            tmp.flush()
            tmp.close()
            tmp = None
        except Exception:
            try:
                if tmp is not None:
                    tmp.close()
            except Exception:
                pass
            if payload_path:
                try:
                    os.remove(payload_path)
                except Exception:
                    pass
            ms.verify_spawn_fail_total.inc()
            ms.inc_verify_error(VERIFY_ERR_SPAWN_FAIL)
            if not bypass_sem:
                self._set_inflight(False, "")
                try:
                    self._sem.release()
                except Exception:
                    pass
                ms.verify_inflight.set(0.0)
                ms.verify_inflight_age_s.set(0.0)
            lat = time.perf_counter() - t0
            ms.verify_latency.observe(lat)
            return _VerifyResult(False, VERIFY_ERR_SPAWN_FAIL, False, False, float(lat), "process")

        parent_conn, child_conn = ctx.Pipe(duplex=False)
        p = None
        try:
            p = ctx.Process(
                target=_verify_proc_worker,
                args=(child_conn, payload_path, cfg.process_rlimit_cpu_s, cfg.process_rlimit_as_bytes),
            )
            p.daemon = True
            p.start()
            try:
                child_conn.close()
            except Exception:
                pass
        except Exception:
            ms.verify_spawn_fail_total.inc()
            ms.inc_verify_error(VERIFY_ERR_SPAWN_FAIL)
            try:
                parent_conn.close()
            except Exception:
                pass
            try:
                child_conn.close()
            except Exception:
                pass
            try:
                if p is not None and p.is_alive():
                    p.terminate()
            except Exception:
                pass
            try:
                if payload_path:
                    os.remove(payload_path)
            except Exception:
                pass
            if not bypass_sem:
                self._set_inflight(False, "")
                try:
                    self._sem.release()
                except Exception:
                    pass
                ms.verify_inflight.set(0.0)
                ms.verify_inflight_age_s.set(0.0)
            lat = time.perf_counter() - t0
            ms.verify_latency.observe(lat)
            return _VerifyResult(False, VERIFY_ERR_SPAWN_FAIL, False, False, float(lat), "process")

        ok = False
        timed_out = False
        try:
            if timeout_s is None:
                ok = bool(parent_conn.recv())
            else:
                if parent_conn.poll(timeout=float(timeout_s)):
                    ok = bool(parent_conn.recv())
                else:
                    timed_out = True
        except Exception:
            ok = False

        if timed_out:
            ms.verify_timeout_total.inc()
            ms.inc_verify_error(VERIFY_ERR_TIMEOUT)
            # terminate/kill
            try:
                ms.verify_kill_total.inc()
                if p is not None:
                    p.terminate()
            except Exception:
                ms.inc_verify_error(VERIFY_ERR_KILL_FAIL)
            # best-effort join + kill
            try:
                if p is not None:
                    p.join(timeout=0.5)
            except Exception:
                pass
            try:
                if p is not None and p.is_alive() and hasattr(p, "kill"):
                    ms.verify_kill_total.inc()
                    p.kill()  # type: ignore[attr-defined]
            except Exception:
                pass
            try:
                if p is not None:
                    p.join(timeout=0.5)
            except Exception:
                pass

        # cleanup
        try:
            parent_conn.close()
        except Exception:
            pass
        try:
            if payload_path:
                os.remove(payload_path)
        except Exception:
            pass

        lat = time.perf_counter() - t0
        ms.verify_latency.observe(lat)

        if not bypass_sem:
            self._set_inflight(False, "")
            try:
                self._sem.release()
            except Exception:
                pass
            ms.verify_inflight.set(0.0)
            ms.verify_inflight_age_s.set(0.0)

        if timed_out:
            return _VerifyResult(False, VERIFY_ERR_TIMEOUT, True, False, float(lat), "process")
        return _VerifyResult(bool(ok), VERIFY_ERR_NONE if ok else VERIFY_ERR_NONE, False, False, float(lat), "process")


_VERIFY_EXEC_LOCK = threading.Lock()
_VERIFY_EXECUTORS: Dict[Tuple[str, str, str], _VerifyExecutor] = {}


def _get_verify_executor(key: Tuple[str, str, str]) -> _VerifyExecutor:
    with _VERIFY_EXEC_LOCK:
        ex = _VERIFY_EXECUTORS.get(key)
        if ex is None:
            ex = _VerifyExecutor()
            _VERIFY_EXECUTORS[key] = ex
        return ex


# ---------------------------------------------------------------------------
# Event sink helper (L7 hook)
# ---------------------------------------------------------------------------


def _emit_event(cfg: ChainAuditConfig, event: Dict[str, Any]) -> None:
    if cfg.event_sink is None:
        return
    try:
        cfg.event_sink(event)
    except Exception:
        # never let event sink break audit
        pass


# ---------------------------------------------------------------------------
# Main audit() implementation (never raises for routine failures)
# ---------------------------------------------------------------------------


def audit(
    store: ReceiptStore,
    cfg: ChainAuditConfig,
    *,
    metrics: Optional[_MetricsFamilies] = None,
) -> ChainAuditReport:
    t0_all = time.perf_counter()
    fam = metrics or _get_default_metrics()

    name = _safe_text(cfg.name, max_len=64)
    version = _safe_text(cfg.version, max_len=32)
    store_lbl = _store_label(store, cfg)
    ms = _MetricsScope(fam, name=name, version=version, store=store_lbl)

    # Default report skeleton
    rep = ChainAuditReport(
        ok=False,
        checked=0,
        gaps=0,
        parse_errors=0,
        latency_s=0.0,
        audit_policy_digest="",
        verify_impl_digest=_safe_text(_VERIFY_IMPL_DIGEST, max_len=64),
    )

    # Validate config (must not raise to caller)
    try:
        cfg.validate()
    except Exception as e:
        rep.error_kind = ERR_CONFIG
        rep.error_msg = _safe_text(e, max_len=200)
        rep.failure_reasons = [ERR_CONFIG]
        rep.audit_policy_digest = "unknown"
        ms.chain_ok.set(0.0)
        ms.chain_fail.inc()
        ms.inc_audit_error(ERR_CONFIG)
        rep.latency_s = float(time.perf_counter() - t0_all)
        ms.audit_latency.observe(rep.latency_s)
        return rep

    policy_digest = cfg.policy_digest()
    rep.audit_policy_digest = policy_digest
    ms.set_policy_info(policy_digest, rep.verify_impl_digest)

    # window==0 must not call tail(0) (some stores interpret as unbounded)
    if int(cfg.window) == 0:
        rep.ok = True
        rep.local_ok = True
        rep.verify_ok = True
        rep.checked = 0
        rep.latency_s = float(time.perf_counter() - t0_all)
        ms.chain_ok.set(1.0)
        ms.chain_gap_window.set(0.0)
        ms.fetched_count.set(0.0)
        ms.fetched_bytes.set(0.0)
        ms.selected_count.set(0.0)
        ms.selected_bytes.set(0.0)
        ms.audit_latency.observe(rep.latency_s)
        return rep

    # Fetch tail rows
    t0_tail = time.perf_counter()
    rows_raw: Any = None
    try:
        n = int(cfg.window)
        # Prefer optional iterator method if store provides it (L7-ish compatibility)
        if hasattr(store, "tail_iter"):
            it = getattr(store, "tail_iter")
            rows_raw = list(it(n))
        else:
            rows_raw = store.tail(n)
    except Exception as e:
        rep.error_kind = ERR_STORE_TAIL
        rep.error_msg = _safe_text(e, max_len=200)
        rep.failure_reasons = [R_STORE_TAIL_FAIL]
        ms.store_tail_fail.inc()
        ms.inc_audit_error(ERR_STORE_TAIL)
        # rate-limited stack trace
        if _LOG_RL.allow("store_tail", cfg.log_stacktrace_rate_s):
            logger.exception("store.tail failed: %s", _safe_text(e, max_len=200))
        else:
            logger.warning("store.tail failed: %s", _safe_text(e, max_len=200))
        rep.latency_s = float(time.perf_counter() - t0_all)
        ms.chain_ok.set(0.0)
        ms.chain_fail.inc()
        ms.audit_latency.observe(rep.latency_s)
        return rep
    finally:
        tail_lat = time.perf_counter() - t0_tail
        rep.store_tail_latency_s = float(tail_lat)
        ms.store_tail_latency.observe(tail_lat)

    # Normalize rows (strict shape). Must not throw out of audit().
    try:
        hard_cap = min(int(cfg.window), int(cfg.window_cap))
        rows = _normalize_rows_strict(rows_raw, hard_cap=hard_cap)
    except Exception as e:
        rep.error_kind = ERR_ROW_SHAPE
        rep.error_msg = _safe_text(e, max_len=200)
        rep.failure_reasons = [R_ROW_SHAPE]
        ms.inc_audit_error(ERR_ROW_SHAPE)
        ms.chain_ok.set(0.0)
        ms.chain_fail.inc()
        if _LOG_RL.allow("row_shape", cfg.log_stacktrace_rate_s):
            logger.exception("row normalization failed: %s", _safe_text(e, max_len=200))
        else:
            logger.warning("row normalization failed: %s", _safe_text(e, max_len=200))
        rep.latency_s = float(time.perf_counter() - t0_all)
        ms.audit_latency.observe(rep.latency_s)
        return rep

    if not rows:
        # Empty store => ok
        rep.ok = True
        rep.local_ok = True
        rep.verify_ok = True
        rep.checked = 0
        rep.fetched = 0
        rep.fetched_bytes = 0
        rep.selected_bytes = 0
        ms.chain_ok.set(1.0)
        ms.chain_gap_window.set(0.0)
        ms.fetched_count.set(0.0)
        ms.fetched_bytes.set(0.0)
        ms.selected_count.set(0.0)
        ms.selected_bytes.set(0.0)

        # stats best-effort
        try:
            st = store.stats()
        except Exception as e:
            ms.store_stats_fail.inc()
            ms.inc_audit_error(ERR_STORE_STATS)
            if _LOG_RL.allow("store_stats", cfg.log_stacktrace_rate_s):
                logger.exception("store.stats failed: %s", _safe_text(e, max_len=200))
            else:
                logger.warning("store.stats failed: %s", _safe_text(e, max_len=200))
            st = {}
        ms.store_count.set(float(st.get("count", 0.0) or 0.0))
        ms.store_size.set(float(st.get("size_bytes", 0.0) or 0.0))
        ms.store_last_ts.set(float(st.get("last_ts", 0.0) or 0.0))

        rep.latency_s = float(time.perf_counter() - t0_all)
        ms.audit_latency.observe(rep.latency_s)
        return rep

    # Parse/scan (guarded), build rec list with budgets
    t0_parse = time.perf_counter()

    recs: List[_Rec] = []
    fetched_bytes = 0
    dropped_fetch_budget = 0
    oversize_drop = 0
    invalid_head_drop = 0
    parse_skipped = 0
    parse_errors = 0
    invalid_heads = 0
    oversize_bodies = 0

    parse_int = _make_parse_int_limiter(int(cfg.max_int_digits))

    # First pass: compute sizes + enforce fetched-bytes cap by keeping a suffix-ish of rows
    # We do not trust store order; we still cap memory by dropping largest bodies if needed.
    # Strategy: keep all until cap exceeded, then drop oldest remaining rows (by input order) deterministically.
    max_fetched = int(cfg.max_fetched_bytes) if cfg.max_fetched_bytes is not None else None

    tmp_rows: List[Tuple[int, ReceiptRow, int]] = []
    for i, r in enumerate(rows):
        b = r.body_json
        bsz = _utf8_len_lossy(b)
        ms.rcpt_size.observe(bsz)
        tmp_rows.append((i, r, bsz))

    # Deterministic downselect for fetched bytes cap
    kept = tmp_rows
    total_fetch = sum(x[2] for x in kept)
    if max_fetched is not None and total_fetch > max_fetched:
        # Keep smaller bodies first (more chance to keep more chain links),
        # tie-break by input order descending (newer-ish if store is newest-first).
        kept_sorted = sorted(kept, key=lambda x: (x[2], -x[0]))
        acc = 0
        chosen: List[Tuple[int, ReceiptRow, int]] = []
        for it in kept_sorted:
            if acc + it[2] > max_fetched and chosen:
                continue
            if acc + it[2] <= max_fetched or not chosen:
                chosen.append(it)
                acc += it[2]
        # restore deterministic order by original index
        chosen.sort(key=lambda x: x[0])
        dropped_fetch_budget = max(0, len(kept) - len(chosen))
        kept = chosen

    rep.fetched = len(rows)
    rep.fetched_bytes = int(total_fetch)
    rep.dropped_fetch_budget = int(dropped_fetch_budget)
    ms.fetched_count.set(float(len(rows)))
    ms.fetched_bytes.set(float(total_fetch))
    if dropped_fetch_budget:
        ms.insufficient_budget_total.inc(0)  # no-op but keeps metric initialized

    # Second pass: create _Rec with strict caps
    for j, (orig_i, rr, bsz) in enumerate(kept):
        head_raw = rr.head_hex
        body_raw = rr.body_json

        head_c = _canon_hex_no_prefix_limited(head_raw, max_hex_chars=int(cfg.max_hex_chars))
        if head_c is None:
            invalid_head_drop += 1
            invalid_heads += 1
            if not rep.sample_bad_head:
                rep.sample_bad_head = _safe_text(head_raw, max_len=64)
            continue

        # hard body cap
        if bsz > int(cfg.max_body_bytes_hard):
            oversize_drop += 1
            oversize_bodies += 1
            continue

        # guarded parse meta (soft cap inside)
        pe, obj, prev_s, ts_ns, utf8_ok = _safe_parse_body_meta(
            body_raw,
            max_body_bytes_per_row=int(cfg.max_body_bytes_per_row),
            max_json_depth=int(cfg.max_json_depth),
            max_json_depth_scan_chars=int(cfg.max_json_depth_scan_chars),
            max_int_digits=int(cfg.max_int_digits),
            sanitize_invalid_utf8=bool(cfg.sanitize_invalid_utf8),
        )
        if pe:
            # distinguish parse-skipped vs true parse error
            if bsz > int(cfg.max_body_bytes_per_row) or not _bracket_depth_guard(body_raw, max_depth=int(cfg.max_json_depth), max_scan_chars=int(cfg.max_json_depth_scan_chars)):
                parse_skipped += 1
            else:
                parse_errors += 1
                if not rep.sample_parse_error_head:
                    rep.sample_parse_error_head = head_c[:16]
            ms.parse_error_total.inc(1)

        prev_c = None
        if prev_s is not None:
            prev_c = _canon_hex_no_prefix_limited(prev_s, max_hex_chars=int(cfg.max_hex_chars))

        head_verify = _select_head_verify(head_c, fmt=cfg.verify_head_format)

        recs.append(
            _Rec(
                idx=len(recs),
                head_raw=head_raw,
                head_canon=head_c,
                head_verify=head_verify,
                body_raw=body_raw,
                body_bytes=int(bsz),
                oversize=False,
                utf8_valid=bool(utf8_ok),
                parse_error=bool(pe),
                obj=obj,
                prev_canon=prev_c,
                ts_ns=ts_ns,
            )
        )
        fetched_bytes += int(bsz)

    rep.dropped_oversize = int(oversize_drop)
    rep.dropped_invalid_head = int(invalid_head_drop)
    rep.dropped_parse_skipped = int(parse_skipped)
    rep.parse_errors = int(parse_errors)
    rep.invalid_heads = int(invalid_heads)
    rep.oversize_bodies = int(oversize_bodies)

    if invalid_heads:
        ms.invalid_head_total.inc(int(invalid_heads))
    if oversize_bodies:
        ms.oversize_body_total.inc(int(oversize_bodies))

    rep.parse_latency_s = float(time.perf_counter() - t0_parse)
    ms.parse_latency.observe(rep.parse_latency_s)

    # If nothing remains, decide outcome under policy
    if not recs:
        rep.checked = 0
        rep.chain_len = 0
        rep.selected_bytes = 0
        rep.local_ok = False
        rep.verify_ok = False
        rep.verify_error_kind = VERIFY_ERR_INPUT
        rep.failure_reasons = []
        if invalid_heads:
            rep.failure_reasons.append(R_INVALID_HEAD)
        if oversize_bodies:
            rep.failure_reasons.append(R_OVERSIZE_BODY)
        if parse_errors or parse_skipped:
            rep.failure_reasons.append(R_PARSE_ERROR)
        rep.ok = False
        ms.chain_ok.set(0.0)
        ms.chain_fail.inc()
        rep.latency_s = float(time.perf_counter() - t0_all)
        ms.audit_latency.observe(rep.latency_s)
        return rep

    # Ordering/selection: build best chain by prev backtracking
    t0_order = time.perf_counter()
    chain, st = _build_chain_best_effort(recs, cfg)
    rep.chain_len = int(len(chain))
    rep.forks = int(st.forks)
    rep.cycles = int(st.cycles)
    rep.ambiguous_prev = int(st.ambiguous_prev)
    rep.missing_prev = int(st.missing_prev)
    rep.duplicate_head_groups = int(st.duplicate_head_groups)
    rep.duplicate_head_total = int(st.duplicate_head_total)
    rep.ts_min_ns = st.ts_min_ns
    rep.ts_max_ns = st.ts_max_ns

    if st.duplicate_head_total:
        ms.duplicate_head_total.inc(int(st.duplicate_head_total))
    if st.forks:
        ms.fork_total.inc(int(st.forks))
    if st.cycles:
        ms.cycle_total.inc(int(st.cycles))
    if st.ambiguous_prev:
        ms.ambiguous_prev_total.inc(int(st.ambiguous_prev))
    if st.missing_prev:
        ms.missing_prev_total.inc(int(st.missing_prev))

    # Determine tip info
    if chain:
        tip = recs[chain[-1]]
        rep.chain_tip_head = (tip.head_canon or "")[:32]
        rep.chain_tip_ts_ns = tip.ts_ns

    rep.sample_duplicate_head = _safe_text(st.sample_duplicate_head, max_len=32)
    rep.sample_cycle_head = _safe_text(st.sample_cycle_head, max_len=32)

    # Select suffix under byte budget
    sel, sel_bytes = _select_chain_suffix_by_budget(chain, recs, max_bytes=cfg.max_window_bytes)
    rep.checked = int(len(sel))
    rep.selected_bytes = int(sel_bytes)
    ms.selected_count.set(float(len(sel)))
    ms.selected_bytes.set(float(sel_bytes))
    ms.chain_gap_window.set(0.0)  # chain selection is contiguous by construction

    rep.ordering_latency_s = float(time.perf_counter() - t0_order)
    ms.ordering_latency.observe(rep.ordering_latency_s)

    # Enforce min_chain_len
    if int(cfg.min_chain_len) > 1 and len(chain) < int(cfg.min_chain_len):
        ms.insufficient_chain_total.inc()
        rep.failure_reasons.append(R_INSUFFICIENT_CHAIN)
        _emit_event(
            cfg,
            {
                "kind": "insufficient_chain",
                "policy_digest": policy_digest,
                "store": store_lbl,
                "chain_len": len(chain),
                "min_chain_len": int(cfg.min_chain_len),
                "tip_head": rep.chain_tip_head,
            },
        )

    # Budget insufficiency for selected min length
    if int(cfg.min_chain_len) > 1 and len(sel) < int(cfg.min_chain_len):
        ms.insufficient_budget_total.inc()
        rep.failure_reasons.append(R_INSUFFICIENT_BUDGET)
        _emit_event(
            cfg,
            {
                "kind": "insufficient_budget",
                "policy_digest": policy_digest,
                "store": store_lbl,
                "selected_len": len(sel),
                "min_chain_len": int(cfg.min_chain_len),
                "max_window_bytes": int(cfg.max_window_bytes or 0),
                "selected_bytes": int(sel_bytes),
            },
        )

    # Local checks: parse errors, duplicates/cycles/forks policy, ts, schema
    local_ok = True

    # parse errors anywhere in considered set count toward policy
    if (parse_errors + parse_skipped) > 0:
        rep.failure_reasons.append(R_PARSE_ERROR)
        if cfg.treat_parse_errors_as_fail:
            local_ok = False

    if invalid_heads > 0:
        rep.failure_reasons.append(R_INVALID_HEAD)
        local_ok = False

    if oversize_bodies > 0:
        rep.failure_reasons.append(R_OVERSIZE_BODY)
        local_ok = False

    if st.duplicate_head_total > 0:
        rep.failure_reasons.append(R_DUPLICATE_HEAD)
        if cfg.fail_on_duplicate_heads:
            local_ok = False

    if st.cycles > 0:
        rep.failure_reasons.append(R_CYCLE_DETECTED)
        if cfg.fail_on_cycles:
            local_ok = False

    if st.forks > 0:
        rep.failure_reasons.append(R_FORK_DETECTED)
        if cfg.fail_on_forks:
            local_ok = False

    if st.ambiguous_prev > 0:
        rep.failure_reasons.append(R_AMBIGUOUS_PREV)
        if cfg.fail_on_ambiguous_prev:
            local_ok = False

    if st.missing_prev > 0:
        rep.failure_reasons.append(R_MISSING_PREV)
        # missing prev inside window may be normal if window truncated; treat as gap if requested
        if cfg.treat_gaps_as_fail:
            local_ok = False

    # ts checks
    ts_viol = 0
    if cfg.expect_monotonic_ts_ns and (cfg.ts_check_mode or "chain_order").lower().strip() != "none":
        now_ns = _now_ns()
        max_future = int(float(cfg.max_future_skew_s) * 1e9)

        def check_seq(ts_list: List[Optional[int]], *, nondecreasing: bool) -> int:
            last: Optional[int] = None
            v = 0
            for t in ts_list:
                if t is None:
                    continue
                if t < 0:
                    v += 1
                    continue
                if t > now_ns + max_future:
                    v += 1
                if last is not None:
                    if nondecreasing and t < last:
                        v += 1
                    if (not nondecreasing) and t > last:
                        v += 1
                last = t
            return v

        mode_ts = (cfg.ts_check_mode or "chain_order").lower().strip()
        if mode_ts == "chain_order":
            ts_list = [recs[i].ts_ns for i in sel]
            ts_viol = check_seq(ts_list, nondecreasing=True)
        elif mode_ts == "store_order":
            so = (cfg.store_order or "unknown").lower().strip()
            nondec = True if so == "oldest_first" else False
            ts_list = [r.ts_ns for r in recs]  # recs follow kept order
            ts_viol = check_seq(ts_list, nondecreasing=nondec)

        if ts_viol:
            rep.ts_violations = int(ts_viol)
            ms.ts_violation_total.inc(int(ts_viol))
            rep.failure_reasons.append(R_TS_VIOLATION)
            local_ok = False

    # Schema checks (only on selected records; strict enforcement per your rules)
    head_mismatch = 0
    auth_v = 0
    cfg_v = 0
    calib_v = 0

    # Normalize allowlists (strict)
    fmt = (cfg.digest_format or "any").lower().strip()
    maxh = int(cfg.max_hex_chars)

    auth_allow = set()
    if cfg.enforce_auth_policy_digest and cfg.expected_auth_policy_digests:
        for x in cfg.expected_auth_policy_digests:
            nx = _normalize_digest_token_strict(x, fmt=fmt, max_hex_chars=maxh)
            if nx is None:
                # config should have caught, but stay safe
                local_ok = False
            else:
                auth_allow.add(nx)

    cfg_allow = set()
    if cfg.enforce_cfg_digest and cfg.expected_cfg_digests:
        for x in cfg.expected_cfg_digests:
            nx = _normalize_digest_token_strict(x, fmt=fmt, max_hex_chars=maxh)
            if nx is None:
                local_ok = False
            else:
                cfg_allow.add(nx)

    calib_allow = set()
    if cfg.enforce_calib_digest and cfg.expected_calib_digests:
        for x in cfg.expected_calib_digests:
            nx = _normalize_digest_token_strict(x, fmt=fmt, max_hex_chars=maxh)
            if nx is None:
                local_ok = False
            else:
                calib_allow.add(nx)

    for i in sel:
        rr = recs[i]
        obj = rr.obj

        # strict body schema (optional)
        if cfg.strict_body_schema:
            if obj is None:
                local_ok = False
                continue
            v = obj.get("v")
            if not isinstance(v, int):
                local_ok = False

            pv = obj.get("prev")
            if not isinstance(pv, str) or _canon_hex_no_prefix_limited(pv, max_hex_chars=maxh) is None:
                local_ok = False

            tv = obj.get("ts_ns")
            if not isinstance(tv, int):
                local_ok = False

        # enforce_body_head_match strict semantics (missing/non-string/uncanon => mismatch)
        if cfg.enforce_body_head_match:
            if obj is None:
                head_mismatch += 1
            else:
                hf = obj.get("head")
                if not isinstance(hf, str):
                    head_mismatch += 1
                else:
                    hc = _canon_hex_no_prefix_limited(hf, max_hex_chars=maxh)
                    if hc is None or rr.head_canon is None or hc != rr.head_canon:
                        head_mismatch += 1

        if cfg.enforce_auth_policy_digest and auth_allow:
            if obj is None:
                auth_v += 1
            else:
                v = _normalize_digest_token_strict(obj.get("auth_policy_digest"), fmt=fmt, max_hex_chars=maxh)
                if v is None or v not in auth_allow:
                    auth_v += 1

        if cfg.enforce_cfg_digest and cfg_allow:
            if obj is None:
                cfg_v += 1
            else:
                v = _normalize_digest_token_strict(obj.get("cfg_digest"), fmt=fmt, max_hex_chars=maxh)
                if v is None or v not in cfg_allow:
                    cfg_v += 1

        if cfg.enforce_calib_digest and calib_allow:
            if obj is None:
                calib_v += 1
            else:
                v = _normalize_digest_token_strict(obj.get("calib_state_digest"), fmt=fmt, max_hex_chars=maxh)
                if v is None or v not in calib_allow:
                    calib_v += 1

    if head_mismatch:
        rep.head_mismatch = int(head_mismatch)
        ms.head_mismatch_total.inc(int(head_mismatch))
        rep.failure_reasons.append(R_SCHEMA_HEAD_MISMATCH)
        local_ok = False

    if auth_v:
        rep.auth_policy_violations = int(auth_v)
        ms.auth_policy_violation_total.inc(int(auth_v))
        rep.failure_reasons.append(R_AUTH_POLICY_VIOLATION)
        local_ok = False

    if cfg_v:
        rep.cfg_digest_violations = int(cfg_v)
        ms.cfg_digest_violation_total.inc(int(cfg_v))
        rep.failure_reasons.append(R_CFG_DIGEST_VIOLATION)
        local_ok = False

    if calib_v:
        rep.calib_digest_violations = int(calib_v)
        ms.calib_digest_violation_total.inc(int(calib_v))
        rep.failure_reasons.append(R_CALIB_DIGEST_VIOLATION)
        local_ok = False

    rep.local_ok = bool(local_ok)

    # Verify step (only if we have at least 1 selected record)
    verify_ok = False
    verify_err = VERIFY_ERR_NONE
    verify_busy = False
    verify_to = False
    verify_lat = 0.0
    mode_used = (cfg.verify_timeout_mode or "thread").lower().strip()

    salt = _normalize_salt_hex(cfg.label_salt_hex, max_hex_chars=int(cfg.max_hex_chars))

    heads_sel = []
    bodies_sel = []
    for i in sel:
        rr = recs[i]
        if rr.head_verify is None:
            continue
        # If invalid utf8 and sanitize_invalid_utf8 is False => it was already parse_error; still avoid verify blowups
        if (not rr.utf8_valid) and (not cfg.sanitize_invalid_utf8):
            continue
        heads_sel.append(rr.head_verify)
        bodies_sel.append(rr.body_raw)

    # If selection got emptied by strict filters, treat as verify input error.
    if not heads_sel:
        verify_ok = False
        verify_err = VERIFY_ERR_INPUT
        ms.verify_exception_total.inc()
        ms.inc_verify_error(VERIFY_ERR_INPUT)
        rep.failure_reasons.append(R_VERIFY_EXCEPTION)
    else:
        # Verify signature hook for policy blob (optional, best-effort)
        if cfg.policy_sig_verify_func is not None and cfg.policy_sig_b64:
            try:
                import base64
                sig = base64.b64decode(cfg.policy_sig_b64.encode("ascii"), validate=True)
                ok_sig = bool(cfg.policy_sig_verify_func(policy_digest.encode("utf-8"), sig, cfg.policy_sig_alg, cfg.policy_sig_key_id))
                if not ok_sig:
                    local_ok = False
                    rep.failure_reasons.append("POLICY_SIGNATURE_INVALID")
            except Exception:
                local_ok = False
                rep.failure_reasons.append("POLICY_SIGNATURE_INVALID")

        # Execute verify via per-instance executor
        key = (name, version, store_lbl)
        ex = _get_verify_executor(key)
        vr = ex.run(heads_sel, bodies_sel, salt, cfg, ms)
        verify_ok = bool(vr.ok)
        verify_err = str(vr.error_kind or VERIFY_ERR_NONE)
        verify_busy = bool(vr.busy)
        verify_to = bool(vr.timed_out)
        verify_lat = float(vr.latency_s)
        mode_used = str(vr.mode_used or mode_used)

        rep.verify_ok = verify_ok
        rep.verify_error_kind = verify_err
        rep.verify_busy = verify_busy
        rep.verify_timed_out = verify_to
        rep.verify_latency_s = verify_lat
        rep.verify_mode_used = mode_used

        if verify_busy:
            rep.failure_reasons.append(R_VERIFY_BUSY)
        if verify_to:
            rep.failure_reasons.append(R_VERIFY_TIMEOUT)
        if verify_err in (VERIFY_ERR_EXCEPTION, VERIFY_ERR_IMPORT, VERIFY_ERR_SPAWN_FAIL, VERIFY_ERR_KILL_FAIL, VERIFY_ERR_INPUT):
            rep.failure_reasons.append(R_VERIFY_EXCEPTION)
        if (not verify_ok) and (not verify_busy) and (not verify_to) and verify_err == VERIFY_ERR_NONE:
            rep.failure_reasons.append(R_VERIFY_FALSE)

    # Final decision: combine local + verify.
    ok_final = bool(local_ok) and bool(verify_ok) and (len(chain) >= int(cfg.min_chain_len)) and (len(sel) >= 1)
    if int(cfg.min_chain_len) > 1 and len(chain) < int(cfg.min_chain_len):
        ok_final = False
    if int(cfg.min_chain_len) > 1 and len(sel) < int(cfg.min_chain_len):
        ok_final = False

    rep.ok = bool(ok_final)

    # gaps metric: chain semantics selection yields 0 gaps inside selected chain; missing_prev/ambiguous tracked separately
    rep.gaps = 0

    # Store stats best-effort (observability, not correctness)
    try:
        st = store.stats()
    except Exception as e:
        ms.store_stats_fail.inc()
        ms.inc_audit_error(ERR_STORE_STATS)
        if _LOG_RL.allow("store_stats", cfg.log_stacktrace_rate_s):
            logger.exception("store.stats failed: %s", _safe_text(e, max_len=200))
        else:
            logger.warning("store.stats failed: %s", _safe_text(e, max_len=200))
        st = {}

    ms.store_count.set(float(st.get("count", 0.0) or 0.0))
    ms.store_size.set(float(st.get("size_bytes", 0.0) or 0.0))
    ms.store_last_ts.set(float(st.get("last_ts", 0.0) or 0.0))

    # Metrics finalization
    ms.chain_ok.set(1.0 if rep.ok else 0.0)
    if not rep.ok:
        ms.chain_fail.inc()
    if st.missing_prev and cfg.treat_gaps_as_fail:
        # This is the closest "gap" semantics under chain mode
        ms.chain_gap_total.inc(1.0)

    rep.latency_s = float(time.perf_counter() - t0_all)
    ms.audit_latency.observe(rep.latency_s)

    # Emit structured events for high-risk findings (L7 hook)
    if rep.cycles or rep.duplicate_head_total or rep.ambiguous_prev or rep.missing_prev:
        _emit_event(
            cfg,
            {
                "kind": "chain_anomaly",
                "policy_digest": policy_digest,
                "store": store_lbl,
                "duplicate_head_total": rep.duplicate_head_total,
                "cycles": rep.cycles,
                "ambiguous_prev": rep.ambiguous_prev,
                "missing_prev": rep.missing_prev,
                "tip_head": rep.chain_tip_head,
            },
        )

    return rep


# ---------------------------------------------------------------------------
# Periodic ChainAuditor (lifecycle fixed + cross-window continuity checks)
# ---------------------------------------------------------------------------


class ChainAuditor:
    """
    Periodic chain auditor loop.

    - Robust against exceptions: never silently dies.
    - stop(join timeout) does NOT drop thread reference if still alive.
    - Maintains cross-window continuity heuristics (rollback suspicion).
    """

    def __init__(
        self,
        store: ReceiptStore,
        cfg: ChainAuditConfig = ChainAuditConfig(),
        *,
        metrics: Optional[_MetricsFamilies] = None,
    ):
        self._store = store
        self._cfg = cfg
        self._metrics = metrics
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.RLock()

        # Cross-window continuity memory
        self._last_tip_head: Optional[str] = None
        self._last_tip_ts_ns: Optional[int] = None
        self._last_ok: Optional[bool] = None

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run_loop,
                name="tcd-chain-auditor",
                daemon=True,
            )
            logger.info(
                "ChainAuditor starting name=%s version=%s store=%s",
                _safe_text(self._cfg.name, max_len=64),
                _safe_text(self._cfg.version, max_len=32),
                _store_label(self._store, self._cfg),
            )
            self._thread.start()

    def stop(self, *, join: bool = True, timeout: Optional[float] = 5.0) -> None:
        with self._lock:
            t = self._thread
            if t is None:
                return
            self._stop.set()

        if join and t is not None:
            # Validate timeout (finite)
            to = 5.0 if timeout is None else float(timeout)
            if not _is_finite(to) or to < 0:
                to = 0.0
            t.join(timeout=to)

        # Do NOT lose thread handle if still alive (lifecycle correctness)
        with self._lock:
            if self._thread is not None and (not self._thread.is_alive()):
                self._thread = None

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                rep = audit(self._store, self._cfg, metrics=self._metrics)
            except Exception as e:
                # Should be very rare because audit() is defensive, but never die.
                if _LOG_RL.allow("loop_audit_raise", self._cfg.log_stacktrace_rate_s):
                    logger.exception("audit() raised in ChainAuditor loop: %s", _safe_text(e, max_len=200))
                else:
                    logger.warning("audit() raised in ChainAuditor loop: %s", _safe_text(e, max_len=200))
                rep = ChainAuditReport(
                    ok=False,
                    checked=0,
                    gaps=0,
                    parse_errors=0,
                    latency_s=0.0,
                    error_kind=ERR_INTERNAL,
                    error_msg=_safe_text(e, max_len=200),
                    audit_policy_digest="unknown",
                    verify_impl_digest=_safe_text(_VERIFY_IMPL_DIGEST, max_len=64),
                    failure_reasons=[ERR_INTERNAL],
                )

            # Cross-window rollback suspicion (heuristic, low false positive threshold)
            # If last tip existed and now:
            #  - current tip missing, or
            #  - current tip ts < last tip ts (beyond skew), and last tip not observed in current chain -> suspicious
            try:
                # Build a metrics scope to bump rollback counter if needed (same labels as audit uses)
                fam = self._metrics or _get_default_metrics()
                ms = _MetricsScope(
                    fam,
                    name=_safe_text(self._cfg.name, max_len=64),
                    version=_safe_text(self._cfg.version, max_len=32),
                    store=_store_label(self._store, self._cfg),
                )

                if self._last_tip_head is not None:
                    cur_tip = rep.chain_tip_head or None
                    cur_ts = rep.chain_tip_ts_ns
                    last_ts = self._last_tip_ts_ns

                    # if store became empty unexpectedly
                    if cur_tip is None and rep.fetched == 0:
                        ms.rollback_suspected_total.inc()
                        rep.sample_rollback = "tip_disappeared"
                        if R_ROLLBACK_SUSPECTED not in rep.failure_reasons:
                            rep.failure_reasons.append(R_ROLLBACK_SUSPECTED)

                    # ts rollback
                    if cur_tip is not None and last_ts is not None and cur_ts is not None:
                        skew_ns = int(float(self._cfg.max_future_skew_s) * 1e9)
                        if cur_ts + skew_ns < last_ts:
                            ms.rollback_suspected_total.inc()
                            rep.sample_rollback = f"ts_decreased:{last_ts}->{cur_ts}"
                            if R_ROLLBACK_SUSPECTED not in rep.failure_reasons:
                                rep.failure_reasons.append(R_ROLLBACK_SUSPECTED)
                            # treat as not-ok in strict sense
                            rep.ok = False
                            ms.chain_ok.set(0.0)
                            ms.chain_fail.inc()
            except Exception:
                pass

            # Update cross-window memory after checks
            self._last_tip_head = rep.chain_tip_head or self._last_tip_head
            self._last_tip_ts_ns = rep.chain_tip_ts_ns if rep.chain_tip_ts_ns is not None else self._last_tip_ts_ns
            self._last_ok = bool(rep.ok)

            # Sleep/backoff strategy
            if (not rep.ok) and (not self._cfg.continue_on_fail):
                base = max(float(self._cfg.min_sleep_s), float(self._cfg.fail_retry_s))
            else:
                base = max(float(self._cfg.min_sleep_s), float(self._cfg.interval_s))

            if rep.parse_errors > int(self._cfg.max_bad_bodies):
                base = max(base, 2.0 * float(self._cfg.interval_s))

            # Jitter (finite)
            if not _is_finite(base) or base < 0:
                base = float(self._cfg.min_sleep_s)
            jitter = base * (0.95 + 0.10 * random.random())
            self._stop.wait(timeout=jitter)