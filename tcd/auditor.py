from __future__ import annotations

"""
Chain auditor for verifiable receipts.

This module runs integrity checks over recent receipts, exports Prometheus
metrics, and provides both a one-shot `audit()` function and a periodic
`ChainAuditor` loop.

Responsibilities:
  - inspect a sliding window from a ReceiptStore via tail(window);
  - run local structural checks (prev-pointer, optional ts_ns monotonicity);
  - call verify_chain() for cryptographic chain validation;
  - bound resource use (window size, total bytes, verify timeout);
  - expose compact, low-cardinality metrics for alerting and forensics;
  - attach an audit policy digest and verify implementation digest so that
    higher layers (e-process / PQ / zk) can treat this auditor as a
    well-defined strategy object rather than ad-hoc logic.
"""

import dataclasses
import hashlib
import json
import logging
import random
import threading
import time
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, TimeoutError

from prometheus_client import (
    REGISTRY,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
)

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

# Best-effort verify implementation fingerprint. If not provided by .verify,
# we fall back to a stable "unknown" string.
try:
    from .verify import VERIFY_IMPL_DIGEST as _VERIFY_IMPL_DIGEST  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - defensive; .verify usually exports this
    _VERIFY_IMPL_DIGEST = "unknown"


class ReceiptRow(NamedTuple):
    """
    Minimal storage-facing row representation used by the auditor.

    Fields:
      - head_hex : hex-encoded head hash (current receipt id)
      - body_json: JSON-encoded receipt body (string)
    """

    head_hex: str
    body_json: str


class ReceiptStore:
    """
    Abstract interface for a receipt store.

    Implementations are expected to provide:
      - tail(n): return up to n most recent receipts (any order);
      - stats(): return basic store statistics.

    The auditor deliberately does not assume any particular storage
    backend (filesystem, SQL, object store, etc.).
    """

    def tail(self, n: int) -> List[ReceiptRow]: ...
    def stats(self) -> Dict[str, Any]: ...


@dataclasses.dataclass
class ChainAuditConfig:
    """
    Configuration for a single audit run and for ChainAuditor.

    High-level policy fields:
      - name                     : logical name for this audit policy
      - version                  : human-readable policy version tag

    Core behavior fields:
      - window                   : number of recent receipts to inspect
      - interval_s               : baseline sleep between periodic runs
      - label_salt_hex           : optional hex salt for verification
      - continue_on_fail         : if False, sleep using fail_retry_s after
                                   a failed round (loop still continues)
      - max_bad_bodies           : if too many JSON parse failures are seen
                                   in one window, consider the store noisy
                                   and increase sleep duration
      - min_sleep_s              : minimum sleep floor
      - fail_retry_s             : base sleep used when a round fails and
                                   continue_on_fail is False
      - verify_timeout_s         : optional timeout for verify step (seconds);
                                   0/None means no timeout
      - max_window_bytes         : optional cap on total bytes from bodies
                                   considered in one round

    High-assurance options:
      - treat_parse_errors_as_fail:
                                   if True, any parse errors in the selected
                                   window will cause ok=False
      - expect_monotonic_ts_ns   : if True, ts_ns values are expected to be
                                   non-decreasing; violations are counted and
                                   can force ok=False

    Optional schema enforcement (all off by default for compatibility):
      - enforce_body_head_match  : if True, and a body contains a "head"
                                   field that does not match head_hex, it
                                   is counted as a mismatch and can force
                                   ok=False
      - enforce_auth_policy_digest:
                                   if True, bodies are expected to contain
                                   an "auth_policy_digest" string that is a
                                   member of expected_auth_policy_digests;
                                   missing or unexpected values are counted
                                   as violations and can force ok=False
      - expected_auth_policy_digests:
                                   allowlist for auth_policy_digest values
      - enforce_cfg_digest       : same as above, for "cfg_digest"
      - expected_cfg_digests     : allowlist for cfg_digest values
      - enforce_calib_digest     : same as above, for "calib_state_digest"
      - expected_calib_digests   : allowlist for calib_state_digest values
    """

    # Policy identity
    name: str = "default"
    version: str = "v1"

    # How many recent receipts to inspect
    window: int = 256
    # Periodic auditor sleep baseline
    interval_s: float = 15.0
    # Optional label salt (hex or 0x-prefixed hex) for verification
    label_salt_hex: Optional[str] = None
    # Keep looping after a failed round
    continue_on_fail: bool = True
    # If too many bad JSON bodies appear, back off more
    max_bad_bodies: int = 8
    # Minimum sleep floor
    min_sleep_s: float = 0.05
    # Sleep base used when a round fails
    fail_retry_s: float = 1.0
    # Optional timeout for verify step (seconds); 0/None means no timeout
    verify_timeout_s: Optional[float] = 1.0
    # Optional cap on total bytes from bodies considered in one round
    max_window_bytes: Optional[int] = 512 * 1024  # 512 KiB

    # High-assurance options
    treat_parse_errors_as_fail: bool = True
    expect_monotonic_ts_ns: bool = False

    # Optional schema enforcement
    enforce_body_head_match: bool = False

    enforce_auth_policy_digest: bool = False
    expected_auth_policy_digests: Optional[List[str]] = None

    enforce_cfg_digest: bool = False
    expected_cfg_digests: Optional[List[str]] = None

    enforce_calib_digest: bool = False
    expected_calib_digests: Optional[List[str]] = None


@dataclasses.dataclass
class ChainAuditReport:
    """
    Result of a single audit run.

    Fields:
      - ok                  : True if the chain is considered healthy for
                              this window (under current policy)
      - checked             : number of receipts actually checked (after any
                              truncation based on byte budget)
      - gaps                : number of prev-pointer gaps detected via local
                              check
      - parse_errors        : number of receipts whose JSON bodies failed to
                              parse during local prev-pointer checks
      - latency_s           : end-to-end audit latency (seconds)
      - ts_violations       : count of ts_ns monotonicity violations in this
                              window (if enabled)
      - head_mismatch       : count of bodies whose "head" field (if present)
                              does not match head_hex
      - audit_policy_digest : digest of the ChainAuditConfig used for this
                              run (policy fingerprint)
      - verify_impl_digest  : digest/identifier of the verify implementation
                              used (if exported by .verify; otherwise "unknown")
      - auth_policy_violations:
                              violations of auth_policy_digest rules
      - cfg_digest_violations:
                              violations of cfg_digest rules
      - calib_digest_violations:
                              violations of calib_state_digest rules
    """

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


class _Metrics(NamedTuple):
    """
    Metric handles used by the auditor.

    All metrics are low-cardinality and suitable for alerting:
      - chain_ok                         : gauge, 1.0 when last run succeeded
      - chain_fail                       : counter of failed verification rounds
      - chain_gap_total                  : total gaps ever observed
      - chain_gap_window                 : gaps in the most recent window
      - chain_latency                    : latency histogram for verify rounds
      - rcpt_size                        : histogram of individual receipt sizes
      - store_count                      : reported total count from store.stats()
      - store_size                       : reported size_bytes from store.stats()
      - store_last_ts                    : reported last_ts from store.stats()
      - chain_verify_timeout             : total verify timeouts
      - chain_parse_error_total          : total parse failures over all runs
      - chain_window_checked             : receipts checked in last window
      - chain_window_bytes               : total bytes across bodies in last window
      - chain_ts_violation_total         : ts_ns monotonicity violations
      - chain_head_mismatch_total        : "head" field mismatches
      - chain_auth_policy_violation_total:
                                           auth_policy_digest violations
      - chain_cfg_digest_violation_total : cfg_digest violations
      - chain_calib_digest_violation_total:
                                           calib_state_digest violations
      - chain_audit_policy_info          : info gauge with labels
                                           (name, version, policy_digest,
                                            verify_digest)
    """

    chain_ok: Gauge
    chain_fail: Counter
    chain_gap_total: Counter
    chain_gap_window: Gauge
    chain_latency: Histogram
    rcpt_size: Histogram
    store_count: Gauge
    store_size: Gauge
    store_last_ts: Gauge
    chain_verify_timeout: Counter
    chain_parse_error_total: Counter
    chain_window_checked: Gauge
    chain_window_bytes: Gauge
    chain_ts_violation_total: Counter
    chain_head_mismatch_total: Counter
    chain_auth_policy_violation_total: Counter
    chain_cfg_digest_violation_total: Counter
    chain_calib_digest_violation_total: Counter
    chain_audit_policy_info: Gauge


def build_metrics(registry: Optional[CollectorRegistry] = None) -> _Metrics:
    reg = registry or REGISTRY
    return _Metrics(
        chain_ok=Gauge(
            "tcd_chain_verify_ok",
            "Recent chain verified OK",
            registry=reg,
        ),
        chain_fail=Counter(
            "tcd_chain_verify_fail_total",
            "Recent chain verification failures",
            registry=reg,
        ),
        chain_gap_total=Counter(
            "tcd_chain_gap_total",
            "Prev-pointer gaps detected",
            registry=reg,
        ),
        chain_gap_window=Gauge(
            "tcd_chain_gap_window",
            "Prev-pointer gaps in last window",
            registry=reg,
        ),
        chain_latency=Histogram(
            "tcd_chain_verify_latency_seconds",
            "Chain verification latency (seconds)",
            buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20),
            registry=reg,
        ),
        rcpt_size=Histogram(
            "tcd_receipt_size_bytes",
            "Receipt body size (bytes)",
            registry=reg,
        ),
        store_count=Gauge(
            "tcd_store_count",
            "Total receipts (store-reported)",
            registry=reg,
        ),
        store_size=Gauge(
            "tcd_store_size_bytes",
            "Approx store size (bytes)",
            registry=reg,
        ),
        store_last_ts=Gauge(
            "tcd_store_last_ts_seconds",
            "Timestamp of last receipt (epoch seconds)",
            registry=reg,
        ),
        chain_verify_timeout=Counter(
            "tcd_chain_verify_timeout_total",
            "Verify step timed out",
            registry=reg,
        ),
        chain_parse_error_total=Counter(
            "tcd_chain_parse_error_total",
            "Receipt JSON parse errors",
            registry=reg,
        ),
        chain_window_checked=Gauge(
            "tcd_chain_window_checked",
            "Receipts checked in last verification window",
            registry=reg,
        ),
        chain_window_bytes=Gauge(
            "tcd_chain_window_bytes",
            "Total bytes of receipt bodies in last verification window",
            registry=reg,
        ),
        chain_ts_violation_total=Counter(
            "tcd_chain_ts_violation_total",
            "ts_ns monotonicity violations across windows",
            registry=reg,
        ),
        chain_head_mismatch_total=Counter(
            "tcd_chain_head_mismatch_total",
            '"head" field mismatches across windows',
            registry=reg,
        ),
        chain_auth_policy_violation_total=Counter(
            "tcd_chain_auth_policy_violation_total",
            "auth_policy_digest violations across windows",
            registry=reg,
        ),
        chain_cfg_digest_violation_total=Counter(
            "tcd_chain_cfg_digest_violation_total",
            "cfg_digest violations across windows",
            registry=reg,
        ),
        chain_calib_digest_violation_total=Counter(
            "tcd_chain_calib_digest_violation_total",
            "calib_state_digest violations across windows",
            registry=reg,
        ),
        chain_audit_policy_info=Gauge(
            "tcd_chain_audit_policy_info",
            "Chain auditor policy info (value is always 1.0)",
            ["name", "version", "policy_digest", "verify_digest"],
            registry=reg,
        ),
    )


_METRICS = build_metrics()
# Tiny pool; verification is expected to be cheap but we still bound concurrency.
_EXECUTOR = ThreadPoolExecutor(max_workers=1)


def _compute_audit_policy_digest(cfg: ChainAuditConfig) -> str:
    """
    Compute a stable digest for the given ChainAuditConfig.

    This is used to identify the audit policy in metrics, reports,
    and higher-layer attestations. The exact field set is the full
    dataclass asdict(), serialized via sorted-key JSON and hashed
    with a domain-separated SHA-256.
    """
    try:
        payload = dataclasses.asdict(cfg)
    except TypeError:
        return "unknown"
    payload_bytes = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    h = hashlib.sha256()
    h.update(b"tcd:chain_audit_policy")
    h.update(payload_bytes)
    return "0x" + h.hexdigest()


def _normalize_rows(rows: Iterable[Any]) -> List[ReceiptRow]:
    """
    Convert various row shapes into a homogeneous List[ReceiptRow].

    Supported inputs:
      - ReceiptRow
      - tuple(head, body)
      - dict with keys "head_hex" and "body_json"
      - object with attributes head_hex / body_json

    Any unknown shape raises TypeError; the store adapter should be fixed
    rather than silently skipping unrecognized rows.
    """
    out: List[ReceiptRow] = []
    for r in rows:
        if isinstance(r, ReceiptRow):
            out.append(r)
            continue
        if isinstance(r, tuple) and len(r) == 2:
            out.append(ReceiptRow(str(r[0]), str(r[1])))
            continue
        if isinstance(r, dict):
            out.append(ReceiptRow(str(r["head_hex"]), str(r["body_json"])))
            continue
        head = getattr(r, "head_hex", None)
        body = getattr(r, "body_json", None)
        if head is None or body is None:
            raise TypeError("Unsupported row type from ReceiptStore.tail()")
        out.append(ReceiptRow(str(head), str(body)))
    return out


def _hex_ok(s: Optional[str]) -> Optional[str]:
    """
    Normalize an optional hex string.

    Accepts:
      - None / ""  -> None
      - "0x..."    -> "0x..." (normalized)
      - "abc123"   -> "0xabc123"
    Returns None if the string cannot be parsed as hex.
    """
    if s is None or s == "":
        return None
    if s.startswith("0x") or s.startswith("0X"):
        s = s[2:]
    try:
        bytes.fromhex(s)
        return "0x" + s
    except Exception:
        return None


def _extract_ts_ns_safe(body: str) -> Optional[int]:
    """
    Safely extract ts_ns from a receipt body JSON, if present and integer.

    Returns:
      - int(ts_ns) on success;
      - None on any parse error or missing / invalid ts_ns.
    """
    try:
        obj = json.loads(body)
        v = obj.get("ts_ns")
        return int(v) if isinstance(v, int) else None
    except Exception:
        return None


def _prev_gap_count_ordered(
    heads: List[str],
    bodies: List[str],
) -> Tuple[int, int]:
    """
    Count prev-pointer gaps in a given order.

    Assumes ascending order such that body[i]["prev"] should equal heads[i-1].

    Returns:
      (gaps, parse_bad) where:
        - gaps      : number of prev mismatches
        - parse_bad : number of bodies that failed JSON parsing
    """
    gaps = 0
    bad = 0
    for i in range(len(bodies)):
        try:
            obj = json.loads(bodies[i])
        except Exception:
            bad += 1
            continue
        if i == 0:
            continue
        prev_in_body = obj.get("prev")
        if prev_in_body is not None and prev_in_body != heads[i - 1]:
            gaps += 1
    return gaps, bad


def _choose_order(
    heads: List[str],
    bodies: List[str],
) -> Tuple[List[str], List[str]]:
    """
    Pick an order that best matches prev pointers.

    Strategy:
      - if ts_ns is present for a majority of bodies, sort by ts_ns ascending;
      - otherwise, compare forward vs reversed order by number of prev gaps
        and parse errors; choose the one with fewer gaps (ties broken by fewer
        parse errors, then by keeping forward order).
    """
    if not bodies:
        return heads, bodies

    # Try ts_ns if present in a majority.
    ts_list = [_extract_ts_ns_safe(b) for b in bodies]
    present = sum(1 for t in ts_list if t is not None)
    if present >= max(3, len(bodies) // 2):
        order = sorted(
            range(len(bodies)),
            key=lambda i: (ts_list[i] if ts_list[i] is not None else 0),
        )
        return [heads[i] for i in order], [bodies[i] for i in order]

    # Otherwise, compare forward vs reversed match counts.
    f_gaps, f_bad = _prev_gap_count_ordered(heads, bodies)
    r_heads = list(reversed(heads))
    r_bodies = list(reversed(bodies))
    r_gaps, r_bad = _prev_gap_count_ordered(r_heads, r_bodies)

    # Prefer fewer gaps; tie-breaker uses fewer parse errors; final fallback keeps forward.
    if r_gaps < f_gaps or (r_gaps == f_gaps and r_bad <= f_bad):
        return r_heads, r_bodies
    return heads, bodies


def _count_ts_monotonic_violations(bodies: List[str]) -> int:
    """
    Count ts_ns monotonicity violations in the provided bodies.

    A violation is any case where ts_ns decreases compared to the last
    observed ts_ns (None values are skipped).

    Returns:
      - number of violations (0 if ts_ns is absent or always non-decreasing).
    """
    last: Optional[int] = None
    violations = 0
    for b in bodies:
        t = _extract_ts_ns_safe(b)
        if t is None:
            continue
        if last is not None and t < last:
            violations += 1
        last = t
    return violations


def _parse_bodies_for_schema(
    bodies: List[str],
) -> List[Optional[Dict[str, Any]]]:
    """
    Parse bodies into JSON objects for schema-level checks.

    Returns a list of Optional[dict]. Entries are None when parsing fails
    or the top-level is not a dict. Parse failures are already counted by
    _prev_gap_count_ordered and should not be double-counted here.
    """
    out: List[Optional[Dict[str, Any]]] = []
    for b in bodies:
        try:
            obj = json.loads(b)
            if isinstance(obj, dict):
                out.append(obj)
            else:
                out.append(None)
        except Exception:
            out.append(None)
    return out


def _analyze_schema_fields(
    heads: List[str],
    objs: List[Optional[Dict[str, Any]]],
    cfg: ChainAuditConfig,
) -> Tuple[int, int, int, int]:
    """
    Analyze schema-level fields inside receipt bodies.

    Returns:
      (head_mismatch, auth_policy_violations, cfg_digest_violations,
       calib_digest_violations)

    Semantics:
      - head mismatch:
          if enforce_body_head_match is True and a body has a "head"
          string that differs from the corresponding head_hex, it is
          counted as a mismatch.

      - auth/cfg/calib violations:
          if the corresponding enforce_* flag is True and an allowlist
          is provided, then:
            * missing or non-string values are violations;
            * values not in the allowlist are violations.
          If the allowlist is empty/None, the field is not enforced.
    """
    head_mismatch = 0
    auth_policy_violations = 0
    cfg_digest_violations = 0
    calib_digest_violations = 0

    # Precompute allowlists as sets for faster membership checks.
    auth_allow = (
        set(cfg.expected_auth_policy_digests or [])
        if cfg.enforce_auth_policy_digest
        else set()
    )
    cfg_allow = (
        set(cfg.expected_cfg_digests or [])
        if cfg.enforce_cfg_digest
        else set()
    )
    calib_allow = (
        set(cfg.expected_calib_digests or [])
        if cfg.enforce_calib_digest
        else set()
    )

    for h, obj in zip(heads, objs):
        if obj is None:
            # Parse errors were already counted elsewhere; treat as
            # neutral here for schema checks.
            continue

        # head vs head_hex
        if cfg.enforce_body_head_match:
            head_field = obj.get("head")
            if isinstance(head_field, str) and head_field != h:
                head_mismatch += 1

        # auth_policy_digest
        if cfg.enforce_auth_policy_digest and auth_allow:
            v = obj.get("auth_policy_digest")
            if not isinstance(v, str) or v not in auth_allow:
                auth_policy_violations += 1

        # cfg_digest
        if cfg.enforce_cfg_digest and cfg_allow:
            v = obj.get("cfg_digest")
            if not isinstance(v, str) or v not in cfg_allow:
                cfg_digest_violations += 1

        # calib_state_digest
        if cfg.enforce_calib_digest and calib_allow:
            v = obj.get("calib_state_digest")
            if not isinstance(v, str) or v not in calib_allow:
                calib_digest_violations += 1

    return (
        head_mismatch,
        auth_policy_violations,
        cfg_digest_violations,
        calib_digest_violations,
    )


def _verify_chain_call(
    heads: List[str],
    bodies: List[str],
    label_salt_hex: Optional[str],
) -> bool:
    """
    Thin wrapper around verify_chain, used to isolate thread pool execution.
    """
    from .verify import verify_chain

    return bool(
        verify_chain(
            heads,
            bodies,
            label_salt_hex=label_salt_hex,
        )
    )


def audit(
    store: ReceiptStore,
    cfg: ChainAuditConfig,
    *,
    metrics: _Metrics = _METRICS,
) -> ChainAuditReport:
    """
    Run a single audit round over the given store.

    Steps:
      1. Fetch up to cfg.window rows via store.tail().
      2. Normalize row types to ReceiptRow.
      3. Enforce a soft byte budget across bodies (cfg.max_window_bytes).
      4. Choose the most plausible chronological order.
      5. Count prev-pointer gaps and parse errors.
      6. Optionally enforce ts_ns monotonicity.
      7. Optionally enforce schema-level rules (head, policy digests).
      8. Call verify_chain (possibly with timeout) over the final window.
      9. Export metrics and return a ChainAuditReport.

    The function is designed to be side-effect free with respect to the
    underlying store; it only reads tail() and stats().
    """
    t0 = time.perf_counter()
    policy_digest = _compute_audit_policy_digest(cfg)

    # Record the current policy into an info-style gauge. Cardinality stays
    # small because (name, version, policy_digest, verify_digest) change at
    # deployment / configuration boundaries, not per request.
    metrics.chain_audit_policy_info.labels(
        name=cfg.name,
        version=cfg.version,
        policy_digest=policy_digest,
        verify_digest=_VERIFY_IMPL_DIGEST,
    ).set(1.0)

    try:
        rows_raw = store.tail(int(cfg.window))
    except Exception as e:
        logger.exception("store.tail failed: %s", e)
        dur = time.perf_counter() - t0
        metrics.chain_ok.set(0.0)
        metrics.chain_latency.observe(dur)
        # Store stats may still be useful, but we skip here to avoid
        # compounding failures. Higher layers can inspect logs/metrics.
        return ChainAuditReport(
            ok=False,
            checked=0,
            gaps=0,
            parse_errors=0,
            latency_s=dur,
            audit_policy_digest=policy_digest,
            verify_impl_digest=_VERIFY_IMPL_DIGEST,
        )

    rows = _normalize_rows(rows_raw)
    if not rows:
        # Empty store is considered "OK" for chain integrity purposes.
        dur = time.perf_counter() - t0
        metrics.chain_ok.set(1.0)
        metrics.chain_gap_window.set(0)
        metrics.chain_window_checked.set(0)
        metrics.chain_window_bytes.set(0.0)
        try:
            st = store.stats()
        except Exception as e:
            logger.warning("store.stats failed on empty store: %s", e)
            st = {}
        metrics.store_count.set(float(st.get("count", 0.0) or 0.0))
        metrics.store_size.set(float(st.get("size_bytes", 0.0) or 0.0))
        metrics.store_last_ts.set(float(st.get("last_ts", 0.0) or 0.0))
        metrics.chain_latency.observe(dur)
        return ChainAuditReport(
            ok=True,
            checked=0,
            gaps=0,
            parse_errors=0,
            latency_s=dur,
            audit_policy_digest=policy_digest,
            verify_impl_digest=_VERIFY_IMPL_DIGEST,
        )

    heads = [r.head_hex for r in rows]
    bodies = [r.body_json for r in rows]

    # Observe sizes and enforce a soft budget on total bytes. We use an
    # initial pass over the raw bodies; verify_chain can handle prefixes
    # safely, so we may truncate the window when the budget is exceeded.
    budget = (
        cfg.max_window_bytes
        if (cfg.max_window_bytes is not None and cfg.max_window_bytes > 0)
        else None
    )
    consumed = 0
    for i, b in enumerate(bodies):
        try:
            size = len(b.encode("utf-8"))
        except Exception:
            size = len(b)
        metrics.rcpt_size.observe(size)

        if budget is not None:
            consumed += size
            if consumed > budget:
                # Truncate on size budget; we keep at least one element.
                cut = max(1, int(len(bodies) * 0.7))
                heads = heads[:cut]
                bodies = bodies[:cut]
                break

    # Recompute total bytes for the possibly truncated list and expose as gauge.
    total_bytes = 0
    for b in bodies:
        try:
            total_bytes += len(b.encode("utf-8"))
        except Exception:
            total_bytes += len(b)
    metrics.chain_window_bytes.set(float(total_bytes))

    # Choose the most plausible chronological order.
    heads, bodies = _choose_order(heads, bodies)
    f_gaps, f_bad = _prev_gap_count_ordered(heads, bodies)
    parse_bad = f_bad
    if parse_bad:
        metrics.chain_parse_error_total.inc(parse_bad)

    # Optional ts_ns monotonicity check.
    ts_violations = 0
    if cfg.expect_monotonic_ts_ns:
        ts_violations = _count_ts_monotonic_violations(bodies)
        if ts_violations:
            metrics.chain_ts_violation_total.inc(ts_violations)

    # Schema-level checks (head field, policy digests).
    objs = _parse_bodies_for_schema(bodies)
    (
        head_mismatch,
        auth_policy_violations,
        cfg_digest_violations,
        calib_digest_violations,
    ) = _analyze_schema_fields(heads, objs, cfg)

    if head_mismatch:
        metrics.chain_head_mismatch_total.inc(head_mismatch)
    if auth_policy_violations:
        metrics.chain_auth_policy_violation_total.inc(auth_policy_violations)
    if cfg_digest_violations:
        metrics.chain_cfg_digest_violation_total.inc(cfg_digest_violations)
    if calib_digest_violations:
        metrics.chain_calib_digest_violation_total.inc(calib_digest_violations)

    # Normalize label salt (accept "0x" or bare hex).
    salt = _hex_ok(cfg.label_salt_hex)

    # Verify with an optional timeout.
    ok = False
    try:
        if cfg.verify_timeout_s and cfg.verify_timeout_s > 0:
            fut = _EXECUTOR.submit(
                _verify_chain_call,
                heads,
                bodies,
                salt,
            )
            ok = bool(fut.result(timeout=float(cfg.verify_timeout_s)))
        else:
            ok = _verify_chain_call(heads, bodies, salt)
    except TimeoutError:
        metrics.chain_verify_timeout.inc()
        ok = False
        logger.warning(
            "chain verify timeout after %.3fs",
            float(cfg.verify_timeout_s or 0.0),
        )
    except Exception as e:
        logger.exception("verify_chain raised: %s", e)
        ok = False

    # High-assurance options: treat parse errors, ts_ns violations, and
    # schema-level mismatches as hard failures where configured.
    if cfg.treat_parse_errors_as_fail and parse_bad > 0:
        ok = False
    if cfg.expect_monotonic_ts_ns and ts_violations > 0:
        ok = False
    if cfg.enforce_body_head_match and head_mismatch > 0:
        ok = False
    if cfg.enforce_auth_policy_digest and auth_policy_violations > 0:
        ok = False
    if cfg.enforce_cfg_digest and cfg_digest_violations > 0:
        ok = False
    if cfg.enforce_calib_digest and calib_digest_violations > 0:
        ok = False

    dur = time.perf_counter() - t0

    # Store-level stats (do not affect ok, but improve observability).
    try:
        st = store.stats()
    except Exception as e:
        logger.warning("store.stats failed: %s", e)
        st = {}

    metrics.store_count.set(float(st.get("count", 0.0) or 0.0))
    metrics.store_size.set(float(st.get("size_bytes", 0.0) or 0.0))
    metrics.store_last_ts.set(float(st.get("last_ts", 0.0) or 0.0))

    metrics.chain_latency.observe(dur)
    metrics.chain_ok.set(1.0 if ok else 0.0)
    metrics.chain_gap_window.set(int(f_gaps))
    metrics.chain_window_checked.set(float(len(bodies)))
    if f_gaps > 0:
        metrics.chain_gap_total.inc(int(f_gaps))
    if not ok:
        metrics.chain_fail.inc()

    return ChainAuditReport(
        ok=ok,
        checked=len(bodies),
        gaps=int(f_gaps),
        parse_errors=int(parse_bad),
        latency_s=dur,
        ts_violations=int(ts_violations),
        head_mismatch=int(head_mismatch),
        audit_policy_digest=policy_digest,
        verify_impl_digest=_VERIFY_IMPL_DIGEST,
        auth_policy_violations=int(auth_policy_violations),
        cfg_digest_violations=int(cfg_digest_violations),
        calib_digest_violations=int(calib_digest_violations),
    )


class ChainAuditor:
    """
    Periodic chain auditor.

    This is a small background loop that repeatedly calls audit() over the
    given store, with jittered sleeps between rounds. It is intended to run
    in-process alongside the main service stack and export metrics into
    the same Prometheus registry.

    Threading model:
      - a single daemon thread runs _run_loop();
      - _run_loop uses a shared ThreadPoolExecutor for verify_chain;
      - stop() is idempotent and can optionally join the thread.
    """

    def __init__(
        self,
        store: ReceiptStore,
        cfg: ChainAuditConfig = ChainAuditConfig(),
        *,
        metrics: _Metrics = _METRICS,
    ):
        self._store = store
        self._cfg = cfg
        self._metrics = metrics
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.RLock()

    def start(self) -> None:
        """
        Start the periodic auditor loop if it is not already running.
        """
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
                "ChainAuditor starting with policy name=%s version=%s",
                self._cfg.name,
                self._cfg.version,
            )
            self._thread.start()

    def stop(
        self,
        *,
        join: bool = True,
        timeout: Optional[float] = 5.0,
    ) -> None:
        """
        Signal the auditor loop to stop.

        If join=True, this call will wait (up to `timeout` seconds) for the
        background thread to exit.
        """
        with self._lock:
            t = self._thread
            if t is None:
                return
            self._stop.set()
        if join and t is not None:
            t.join(timeout=timeout)
        with self._lock:
            self._thread = None

    def _run_loop(self) -> None:
        """
        Main loop: run audit() with jittered sleep between rounds.

        Sleep strategy:
          - if the last report is ok or continue_on_fail=True:
              base = max(min_sleep_s, interval_s)
          - else (failed and continue_on_fail=False):
              base = max(min_sleep_s, fail_retry_s)
          - if parse_errors exceed max_bad_bodies:
              base = max(base, 2 * interval_s)
          - final sleep = base * (0.95 + 0.10 * random.random())
        """
        while not self._stop.is_set():
            rep = audit(self._store, self._cfg, metrics=self._metrics)

            if not rep.ok and not self._cfg.continue_on_fail:
                base = max(self._cfg.min_sleep_s, float(self._cfg.fail_retry_s))
            else:
                base = max(self._cfg.min_sleep_s, float(self._cfg.interval_s))

            if rep.parse_errors > self._cfg.max_bad_bodies:
                base = max(base, 2.0 * self._cfg.interval_s)

            jitter = base * (0.95 + 0.10 * random.random())
            self._stop.wait(timeout=jitter)