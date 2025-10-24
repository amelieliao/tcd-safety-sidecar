# FILE: tcd/auditor.py
from __future__ import annotations

"""Chain auditor for verifiable receipts.

Runs integrity checks over recent receipts, exports Prometheus metrics,
and provides both a one-shot `audit()` function and a periodic `ChainAuditor`.
"""

import dataclasses
import json
import logging
import random
import threading
import time
from typing import Any, Dict, Iterable, List, NamedTuple, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, TimeoutError

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


class ReceiptRow(NamedTuple):
    head_hex: str
    body_json: str


class ReceiptStore:
    def tail(self, n: int) -> List[ReceiptRow]: ...
    def stats(self) -> Dict[str, Any]: ...


@dataclasses.dataclass
class ChainAuditConfig:
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


@dataclasses.dataclass
class ChainAuditReport:
    ok: bool
    checked: int
    gaps: int
    parse_errors: int
    latency_s: float


class _Metrics(NamedTuple):
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


def build_metrics(registry: Optional[CollectorRegistry] = None) -> _Metrics:
    reg = registry or REGISTRY
    return _Metrics(
        chain_ok=Gauge("tcd_chain_verify_ok", "Recent chain verified OK", registry=reg),
        chain_fail=Counter("tcd_chain_verify_fail_total", "Recent chain verification failures", registry=reg),
        chain_gap_total=Counter("tcd_chain_gap_total", "Prev-pointer gaps detected", registry=reg),
        chain_gap_window=Gauge("tcd_chain_gap_window", "Prev-pointer gaps in last window", registry=reg),
        chain_latency=Histogram(
            "tcd_chain_verify_latency_seconds",
            "Chain verification latency (seconds)",
            buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.10, 0.20),
            registry=reg,
        ),
        rcpt_size=Histogram("tcd_receipt_size_bytes", "Receipt body size (bytes)", registry=reg),
        store_count=Gauge("tcd_store_count", "Total receipts (store-reported)", registry=reg),
        store_size=Gauge("tcd_store_size_bytes", "Approx store size (bytes)", registry=reg),
        store_last_ts=Gauge("tcd_store_last_ts_seconds", "Timestamp of last receipt (epoch seconds)", registry=reg),
        chain_verify_timeout=Counter("tcd_chain_verify_timeout_total", "Verify step timed out", registry=reg),
        chain_parse_error_total=Counter("tcd_chain_parse_error_total", "Receipt JSON parse errors", registry=reg),
    )


_METRICS = build_metrics()
_EXECUTOR = ThreadPoolExecutor(max_workers=1)  # tiny pool; verification is cheap


def _normalize_rows(rows: Iterable[Any]) -> List[ReceiptRow]:
    out: List[ReceiptRow] = []
    for r in rows:
        if isinstance(r, ReceiptRow):
            out.append(r); continue
        if isinstance(r, tuple) and len(r) == 2:
            out.append(ReceiptRow(str(r[0]), str(r[1]))); continue
        if isinstance(r, dict):
            out.append(ReceiptRow(str(r["head_hex"]), str(r["body_json"]))); continue
        head = getattr(r, "head_hex", None)
        body = getattr(r, "body_json", None)
        if head is None or body is None:
            raise TypeError("Unsupported row type from ReceiptStore.tail()")
        out.append(ReceiptRow(str(head), str(body)))
    return out


def _hex_ok(s: Optional[str]) -> Optional[str]:
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
    try:
        obj = json.loads(body)
        v = obj.get("ts_ns")
        return int(v) if isinstance(v, int) else None
    except Exception:
        return None


def _prev_gap_count_ordered(heads: List[str], bodies: List[str]) -> Tuple[int, int]:
    """Assumes ascending order: body[i]['prev'] should equal heads[i-1]."""
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


def _choose_order(heads: List[str], bodies: List[str]) -> Tuple[List[str], List[str]]:
    """Pick an order that best matches prev pointers. Prefer ts_ns ascending when available."""
    # Try ts_ns if present in a majority
    ts_list = [_extract_ts_ns_safe(b) for b in bodies]
    present = sum(1 for t in ts_list if t is not None)
    if present >= max(3, len(bodies) // 2):
        order = sorted(range(len(bodies)), key=lambda i: (ts_list[i] if ts_list[i] is not None else 0))
        return [heads[i] for i in order], [bodies[i] for i in order]
    # Otherwise, compare forward vs. reversed match counts
    f_gaps, f_bad = _prev_gap_count_ordered(heads, bodies)
    r_heads = list(reversed(heads))
    r_bodies = list(reversed(bodies))
    r_gaps, r_bad = _prev_gap_count_ordered(r_heads, r_bodies)
    # Prefer fewer gaps; tie-breaker uses fewer parse errors; final fallback keeps forward
    if r_gaps < f_gaps or (r_gaps == f_gaps and r_bad <= f_bad):
        return r_heads, r_bodies
    return heads, bodies


def _verify_chain_call(heads: List[str], bodies: List[str], label_salt_hex: Optional[str]) -> bool:
    from .verify import verify_chain
    return bool(verify_chain(heads, bodies, label_salt_hex=label_salt_hex))


def audit(store: ReceiptStore, cfg: ChainAuditConfig, *, metrics: _Metrics = _METRICS) -> ChainAuditReport:
    t0 = time.perf_counter()
    try:
        rows_raw = store.tail(int(cfg.window))
    except Exception as e:
        logger.exception("store.tail failed: %s", e)
        dur = time.perf_counter() - t0
        metrics.chain_ok.set(0.0)
        metrics.chain_latency.observe(dur)
        return ChainAuditReport(ok=False, checked=0, gaps=0, parse_errors=0, latency_s=dur)

    rows = _normalize_rows(rows_raw)
    if not rows:
        dur = time.perf_counter() - t0
        metrics.chain_ok.set(1.0)
        metrics.chain_gap_window.set(0)
        try:
            st = store.stats()
        except Exception as e:
            logger.warning("store.stats failed on empty store: %s", e)
            st = {}
        metrics.store_count.set(float(st.get("count", 0.0) or 0.0))
        metrics.store_size.set(float(st.get("size_bytes", 0.0) or 0.0))
        metrics.store_last_ts.set(float(st.get("last_ts", 0.0) or 0.0))
        metrics.chain_latency.observe(dur)
        return ChainAuditReport(ok=True, checked=0, gaps=0, parse_errors=0, latency_s=dur)

    heads = [r.head_hex for r in rows]
    bodies = [r.body_json for r in rows]

    # Observe sizes, but keep a running budget to avoid pathological payloads
    budget = cfg.max_window_bytes if (cfg.max_window_bytes and cfg.max_window_bytes > 0) else None
    consumed = 0
    parse_bad = 0
    for b in bodies:
        try:
            size = len(b.encode("utf-8"))
        except Exception:
            size = len(b)
        metrics.rcpt_size.observe(size)
        if budget is not None:
            consumed += size
            if consumed > budget:
                # Truncate on size budget; safe because verify_chain can handle prefixes
                cut = max(1, int(len(bodies) * 0.7))
                heads = heads[:cut]
                bodies = bodies[:cut]
                break

    # Choose the most plausible chronological order
    heads, bodies = _choose_order(heads, bodies)
    f_gaps, f_bad = _prev_gap_count_ordered(heads, bodies)
    parse_bad += f_bad
    if parse_bad:
        metrics.chain_parse_error_total.inc(parse_bad)

    # Normalize salt (accept "0x" or bare hex)
    salt = _hex_ok(cfg.label_salt_hex)

    # Verify with an optional timeout
    ok = False
    try:
        if cfg.verify_timeout_s and cfg.verify_timeout_s > 0:
            fut = _EXECUTOR.submit(_verify_chain_call, heads, bodies, salt)
            ok = bool(fut.result(timeout=float(cfg.verify_timeout_s)))
        else:
            ok = _verify_chain_call(heads, bodies, salt)
    except TimeoutError:
        metrics.chain_verify_timeout.inc()
        ok = False
        logger.warning("chain verify timeout after %.3fs", float(cfg.verify_timeout_s or 0.0))
    except Exception as e:
        logger.exception("verify_chain raised: %s", e)
        ok = False

    dur = time.perf_counter() - t0

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
    if f_gaps > 0:
        metrics.chain_gap_total.inc(int(f_gaps))
    if not ok:
        metrics.chain_fail.inc()

    return ChainAuditReport(ok=ok, checked=len(bodies), gaps=int(f_gaps), parse_errors=int(parse_bad), latency_s=dur)


class ChainAuditor:
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
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run_loop, name="tcd-chain-auditor", daemon=True)
            self._thread.start()

    def stop(self, *, join: bool = True, timeout: Optional[float] = 5.0) -> None:
        with self._lock:
            t = self._thread
            if t is None:
                return
            self._stop.set()
        if join:
            t.join(timeout=timeout)
        with self._lock:
            self._thread = None

    def _run_loop(self) -> None:
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