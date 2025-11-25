from __future__ import annotations

"""
Receipt stores — pluggable persistence for verifiable receipts with chain integrity checks.

Goals
  - Persist attested receipts (head/body/signature/public key) with minimal overhead.
  - Provide chain continuity checks (prev pointer linearity) and basic audit stats.
  - Offer multiple backends with the same API: in-memory, JSONL (append-only), SQLite.
  - Be SRE-friendly: safe appends (fsync), rotation hooks, Prom/OTel metric surfaces.

Security / compliance
  - This module acts as an append-only, verifiable ledger for higher-level security
    decisions (routing, safety, patch management, audit events, etc.).
  - The issuer (attestor / security router / control plane) is responsible for:
      * enforcing that receipt_body contains only redacted / hashed metadata,
      * embedding anytime-valid e-process state (e_value, alpha_wealth, trigger, ...),
      * choosing signature scheme(s), including classical / PQ / hybrid variants.
  - The store itself is signature-scheme agnostic: it keeps head/body/sig/vk and
    provides chain verification and aggregate SRE stats without touching raw content.
  - No raw prompts/outputs should be present in `receipt_body_json` (by design of issuer);
    operators are responsible for keeping that contract.
"""

import dataclasses
import io
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Protocol

from .verify import verify_chain

try:
    # Optional native Prometheus metrics (kept very lightweight).
    from prometheus_client import REGISTRY, Counter, Histogram, Gauge  # type: ignore
    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False


# =============================================================================
# Metrics (optional, no-op if prometheus_client is unavailable)
# =============================================================================

if _HAS_PROM:
    _RCPT_APPEND = Counter(
        "tcd_receipts_append_total",
        "Receipt append operations",
        ["backend"],
        registry=REGISTRY,
    )
    _RCPT_BYTES = Counter(
        "tcd_receipts_body_bytes_total",
        "Total appended receipt body bytes",
        ["backend"],
        registry=REGISTRY,
    )
    _RCPT_COUNT = Gauge(
        "tcd_receipts_count",
        "Approx number of receipts in store",
        ["backend"],
        registry=REGISTRY,
    )
    _RCPT_APPEND_LAT = Histogram(
        "tcd_receipts_append_latency_seconds",
        "Append latency",
        ["backend"],
        registry=REGISTRY,
        buckets=(0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1),
    )
    _RCPT_VERIFY_LAT = Histogram(
        "tcd_receipts_verify_latency_seconds",
        "Verification latency over a window",
        ["backend"],
        registry=REGISTRY,
        buckets=(0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1),
    )
    _RCPT_VERIFY_FAIL = Counter(
        "tcd_receipts_verify_fail_total",
        "Chain verification failures",
        ["backend"],
        registry=REGISTRY,
    )
else:
    class _Nop:
        def labels(self, *_, **__): return self
        def inc(self, *_ , **__): pass
        def set(self, *_ , **__): pass
        def observe(self, *_ , **__): pass
    _RCPT_APPEND = _Nop()
    _RCPT_BYTES = _Nop()
    _RCPT_COUNT = _Nop()
    _RCPT_APPEND_LAT = _Nop()
    _RCPT_VERIFY_LAT = _Nop()
    _RCPT_VERIFY_FAIL = _Nop()


# =============================================================================
# Data model + interface
# =============================================================================

@dataclasses.dataclass(frozen=True)
class ReceiptRow:
    """
    A single persisted receipt entry.

    id:
        Monotonically increasing integer (per backend instance).
    head_hex:
        The computed receipt head (domain-separated BLAKE3 or equivalent).
    body_json:
        Canonical JSON string (the "receipt_body" from the issuer). It should only
        contain redacted / hashed metadata and e-process state; no raw prompts or
        model outputs should appear here.
    sig_hex:
        Opaque signature material. Higher-level components may choose any signature
        scheme (classical, PQ, or hybrid); the store does not interpret this field.
    verify_key_hex:
        Opaque verification key material (if applicable). Scheme and key identifiers
        should be present inside the receipt body for audits.
    ts:
        Storage timestamp (seconds since epoch, float).
    """
    id: int
    head_hex: str
    body_json: str
    sig_hex: str
    verify_key_hex: str
    ts: float


class ReceiptStore(Protocol):
    """Minimal contract every store backend must satisfy (thread-safe)."""

    def append(self, head_hex: str, body_json: str, sig_hex: str = "", verify_key_hex: str = "") -> int:
        """Append a receipt, returns assigned id."""
        ...

    def get(self, rid: int) -> Optional[ReceiptRow]:
        """Fetch a receipt by id (None if not found)."""
        ...

    def tail(self, n: int) -> List[ReceiptRow]:
        """Return the last n receipts (ascending by id)."""
        ...

    def last_head(self) -> Optional[str]:
        """Return the last (most recent) head or None."""
        ...

    def count(self) -> int:
        """Number of receipts stored."""
        ...

    def verify_chain_window(self, window: int, *, label_salt_hex: Optional[str] = None) -> bool:
        """
        Verify linear chain for the last `window` receipts.
        Uses verify_chain(heads, bodies) to assert prev pointers and head/body binding.
        """
        ...

    def stats(self) -> Dict[str, float]:
        """Basic SRE stats: count, size_bytes (if applicable), last_ts, append_qps_ema."""
        ...


@dataclasses.dataclass(frozen=True)
class ReceiptSummary:
    """
    Aggregate view over a sliding window of receipts.

    This does not inspect raw prompts/outputs – it only looks at the
    canonical receipt_body JSON, which is expected to contain:
      - a coarse 'kind' (e.g. "safety_decision", "patch_runtime", "audit");
      - a 'risk_label' or 'risk_level' (e.g. "low", "high", "apt_suspect");
      - an e-process snapshot under 'e' or 'e_obj' with a boolean 'trigger' flag.

    Higher-level components (security router / attestor / control plane) are
    responsible for defining these fields and their semantics.
    """

    total: int
    triggered_e: int
    by_kind: Dict[str, int]
    by_risk: Dict[str, int]


# =============================================================================
# Helpers
# =============================================================================

def _qps_ema(prev: float, last_ts: float, now: float, alpha: float = 0.1) -> float:
    """
    Exponentially-weighted estimate of instantaneous QPS using time delta.
    """
    if last_ts <= 0.0 or now <= last_ts:
        return (1.0 - alpha) * prev + alpha * 1.0
    inst = 1.0 / max(1e-6, (now - last_ts))
    return (1.0 - alpha) * prev + alpha * inst


def _tail_lines(path: Path, n: int, *, block_size: int = 64 * 1024) -> List[str]:
    """
    Read last n non-empty lines from a text file efficiently without loading the whole file.
    Returns lines in file order (oldest .. newest).
    """
    if n <= 0 or not path.exists():
        return []
    out: List[str] = []
    with path.open("rb") as f:
        f.seek(0, os.SEEK_END)
        end = f.tell()
        buf = b""
        pos = end
        while pos > 0 and len(out) < n:
            step = max(0, pos - block_size)
            size = pos - step
            f.seek(step)
            chunk = f.read(size)
            pos = step
            buf = chunk + buf
            *lines, buf = buf.split(b"\n")
            for line in reversed(lines):
                s = line.decode("utf-8", errors="ignore").strip()
                if s:
                    out.append(s)
                if len(out) >= n:
                    break
        if len(out) < n and buf:
            s = buf.decode("utf-8", errors="ignore").strip()
            if s:
                out.append(s)
    out.reverse()
    return out[-n:]


# =============================================================================
# In-memory backend
# =============================================================================

class InMemoryReceiptStore(ReceiptStore):
    """Process-local in-memory store (good for tests or single-worker dev)."""

    def __init__(self):
        self._rows: List[ReceiptRow] = []
        self._id = 0
        self._lk = threading.RLock()
        self._append_ema = 0.0
        self._last_ts = 0.0

    def append(self, head_hex: str, body_json: str, sig_hex: str = "", verify_key_hex: str = "") -> int:
        t0 = time.perf_counter()
        ts = time.time()
        with self._lk:
            self._id += 1
            rid = self._id
            row = ReceiptRow(rid, head_hex, body_json, sig_hex or "", verify_key_hex or "", ts)
            self._rows.append(row)
            self._append_ema = _qps_ema(self._append_ema, self._last_ts, ts)
            self._last_ts = ts
            _RCPT_COUNT.labels("memory").set(len(self._rows))
        _RCPT_APPEND.labels("memory").inc()
        _RCPT_BYTES.labels("memory").inc(len(body_json.encode("utf-8")))
        _RCPT_APPEND_LAT.labels("memory").observe(max(0.0, time.perf_counter() - t0))
        return rid

    def get(self, rid: int) -> Optional[ReceiptRow]:
        with self._lk:
            idx = rid - 1
            if 0 <= idx < len(self._rows):
                return self._rows[idx]
            return None

    def tail(self, n: int) -> List[ReceiptRow]:
        with self._lk:
            return list(self._rows[-max(0, int(n)):])

    def last_head(self) -> Optional[str]:
        with self._lk:
            return self._rows[-1].head_hex if self._rows else None

    def count(self) -> int:
        with self._lk:
            return len(self._rows)

    def verify_chain_window(self, window: int, *, label_salt_hex: Optional[str] = None) -> bool:
        t0 = time.perf_counter()
        with self._lk:
            rows = self._rows[-max(0, int(window)):]
            if not rows:
                _RCPT_VERIFY_LAT.labels("memory").observe(max(0.0, time.perf_counter() - t0))
                return True
            heads = [r.head_hex for r in rows]
            bodies = [r.body_json for r in rows]
        ok = bool(verify_chain(heads, bodies, label_salt_hex=label_salt_hex))
        if not ok:
            _RCPT_VERIFY_FAIL.labels("memory").inc()
        _RCPT_VERIFY_LAT.labels("memory").observe(max(0.0, time.perf_counter() - t0))
        return ok

    def stats(self) -> Dict[str, float]:
        with self._lk:
            last_ts = self._rows[-1].ts if self._rows else 0.0
            return {
                "count": float(len(self._rows)),
                "size_bytes": 0.0,
                "last_ts": float(last_ts),
                "append_qps_ema": float(self._append_ema),
            }


# =============================================================================
# JSONL backend (append-only)
# =============================================================================

class JsonlReceiptStore(ReceiptStore):
    """
    Append-only JSONL store with optional fsync for durability.

    File format: one object per line
      {"id": int, "ts": float, "receipt": "<head_hex>", "receipt_body": "<canonical JSON>",
       "receipt_sig": "<sig hex or empty>", "verify_key": "<vk hex or empty>"}

    Rotation: instantiate a new store with a new path; the old file remains as archive.
    """

    def __init__(
        self,
        path: str,
        *,
        create_dirs: bool = True,
        fsync_writes: bool = True,
        fsync_dir: bool = False,
    ):
        self._path = Path(path)
        if create_dirs:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lk = threading.RLock()
        self._fsync = bool(fsync_writes)
        self._fsync_dir = bool(fsync_dir)
        self._next_id = 1
        self._last_head: Optional[str] = None
        self._append_ema = 0.0
        self._last_ts = 0.0

        # Initialize next_id/last_head from the last good line (robust against partial last line).
        if self._path.exists():
            try:
                tail = _tail_lines(self._path, 1)
                if tail:
                    obj = json.loads(tail[0])
                    self._next_id = int(obj.get("id", 0)) + 1
                    self._last_head = str(obj.get("receipt") or "") or None
            except Exception:
                # File present but unreadable; fall back to append from id=1
                self._next_id = 1
                self._last_head = None

    def _atomic_append(self, text_line: str) -> None:
        # A single-file append with flush+fsync. Directory fsync is optional (off by default).
        with self._path.open("a", encoding="utf-8") as fw:
            fw.write(text_line)
            fw.flush()
            if self._fsync:
                os.fsync(fw.fileno())
        if self._fsync_dir:
            try:
                dir_fd = os.open(str(self._path.parent), os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except Exception:
                # Directory fsync may not be supported on all platforms; ignore.
                pass

    def append(self, head_hex: str, body_json: str, sig_hex: str = "", verify_key_hex: str = "") -> int:
        t0 = time.perf_counter()
        ts = time.time()
        with self._lk:
            rid = self._next_id
            self._next_id += 1

            obj = {
                "id": rid,
                "ts": ts,
                "receipt": head_hex,
                "receipt_body": body_json,
                "receipt_sig": sig_hex or "",
                "verify_key": verify_key_hex or "",
            }
            data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + "\n"
            self._atomic_append(data)

            self._last_head = head_hex
            self._append_ema = _qps_ema(self._append_ema, self._last_ts, ts)
            self._last_ts = ts

        _RCPT_APPEND.labels("jsonl").inc()
        _RCPT_BYTES.labels("jsonl").inc(len(body_json.encode("utf-8")))
        _RCPT_COUNT.labels("jsonl").set(float(self.count()))  # approximate, O(n) but infrequent
        _RCPT_APPEND_LAT.labels("jsonl").observe(max(0.0, time.perf_counter() - t0))
        return rid

    def _iter_tail(self, n: int) -> List[ReceiptRow]:
        lines = _tail_lines(self._path, n)
        out: List[ReceiptRow] = []
        for s in lines:
            try:
                obj = json.loads(s)
            except Exception:
                continue
            out.append(
                ReceiptRow(
                    id=int(obj["id"]),
                    head_hex=str(obj["receipt"]),
                    body_json=str(obj["receipt_body"]),
                    sig_hex=str(obj.get("receipt_sig", "")),
                    verify_key_hex=str(obj.get("verify_key", "")),
                    ts=float(obj["ts"]),
                )
            )
        return out

    def get(self, rid: int) -> Optional[ReceiptRow]:
        if rid <= 0:
            return None
        # O(n) scan; acceptable for operator/debug usage.
        try:
            with self._path.open("r", encoding="utf-8") as fr:
                for line in fr:
                    if not line.strip():
                        continue
                    obj = json.loads(line)
                    if int(obj.get("id", -1)) == rid:
                        return ReceiptRow(
                            id=int(obj["id"]),
                            head_hex=str(obj["receipt"]),
                            body_json=str(obj["receipt_body"]),
                            sig_hex=str(obj.get("receipt_sig", "")),
                            verify_key_hex=str(obj.get("verify_key", "")),
                            ts=float(obj["ts"]),
                        )
        except Exception:
            return None
        return None

    def tail(self, n: int) -> List[ReceiptRow]:
        with self._lk:
            return self._iter_tail(max(0, int(n)))

    def last_head(self) -> Optional[str]:
        with self._lk:
            return self._last_head

    def count(self) -> int:
        # Count lines; for very large files this is O(n). For production at scale, prefer SQLite.
        try:
            c = 0
            with self._path.open("r", encoding="utf-8") as fr:
                for _ in fr:
                    c += 1
            return c
        except Exception:
            return 0

    def verify_chain_window(self, window: int, *, label_salt_hex: Optional[str] = None) -> bool:
        t0 = time.perf_counter()
        rows = self.tail(window)
        if not rows:
            _RCPT_VERIFY_LAT.labels("jsonl").observe(max(0.0, time.perf_counter() - t0))
            return True
        heads = [r.head_hex for r in rows]
        bodies = [r.body_json for r in rows]
        ok = bool(verify_chain(heads, bodies, label_salt_hex=label_salt_hex))
        if not ok:
            _RCPT_VERIFY_FAIL.labels("jsonl").inc()
        _RCPT_VERIFY_LAT.labels("jsonl").observe(max(0.0, time.perf_counter() - t0))
        return ok

    def stats(self) -> Dict[str, float]:
        size = 0.0
        last_ts = 0.0
        try:
            st = self._path.stat()
            size = float(st.st_size)
        except Exception:
            pass
        tail1 = self.tail(1)
        if tail1:
            last_ts = float(tail1[-1].ts)
        return {
            "count": float(self.count()),
            "size_bytes": size,
            "last_ts": last_ts,
            "append_qps_ema": float(self._append_ema),
        }


# =============================================================================
# SQLite backend (optional; stdlib only)
# =============================================================================

_SQL_SCHEMA = """
CREATE TABLE IF NOT EXISTS receipts (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    ts   REAL NOT NULL,
    head TEXT NOT NULL,
    body TEXT NOT NULL,
    sig  TEXT,
    vk   TEXT
);
CREATE INDEX IF NOT EXISTS idx_receipts_ts ON receipts(ts);
"""

class SqliteReceiptStore(ReceiptStore):
    """
    SQLite-backed store with indexes. Suitable for multi-process access on the same host
    (subject to SQLite locking semantics). Uses WAL and synchronous=NORMAL by default.
    """

    def __init__(self, path: str):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lk = threading.RLock()
        self._conn = sqlite3.connect(
            str(self._path),
            timeout=30.0,
            isolation_level=None,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False,
        )
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute("PRAGMA synchronous=NORMAL;")
            self._conn.execute("PRAGMA busy_timeout=30000;")
            self._conn.executescript(_SQL_SCHEMA)

    def append(self, head_hex: str, body_json: str, sig_hex: str = "", verify_key_hex: str = "") -> int:
        t0 = time.perf_counter()
        ts = time.time()
        with self._lk, self._conn:  # implicit transaction
            cur = self._conn.execute(
                "INSERT INTO receipts (ts, head, body, sig, vk) VALUES (?, ?, ?, ?, ?)",
                (ts, head_hex, body_json, sig_hex or "", verify_key_hex or ""),
            )
            rid = int(cur.lastrowid)
        _RCPT_APPEND.labels("sqlite").inc()
        _RCPT_BYTES.labels("sqlite").inc(len(body_json.encode("utf-8")))
        _RCPT_COUNT.labels("sqlite").set(float(self.count()))
        _RCPT_APPEND_LAT.labels("sqlite").observe(max(0.0, time.perf_counter() - t0))
        return rid

    def get(self, rid: int) -> Optional[ReceiptRow]:
        with self._lk:
            cur = self._conn.execute("SELECT id, ts, head, body, sig, vk FROM receipts WHERE id=?", (int(rid),))
            row = cur.fetchone()
        if not row:
            return None
        rid, ts, head, body, sig, vk = row
        return ReceiptRow(int(rid), str(head), str(body), str(sig or ""), str(vk or ""), float(ts))

    def tail(self, n: int) -> List[ReceiptRow]:
        with self._lk:
            rows = self._conn.execute(
                "SELECT id, ts, head, body, sig, vk FROM receipts ORDER BY id DESC LIMIT ?",
                (int(max(0, n)),),
            ).fetchall()
        out: List[ReceiptRow] = []
        for rid, ts, head, body, sig, vk in reversed(rows):
            out.append(ReceiptRow(int(rid), str(head), str(body), str(sig or ""), str(vk or ""), float(ts)))
        return out

    def last_head(self) -> Optional[str]:
        with self._lk:
            row = self._conn.execute("SELECT head FROM receipts ORDER BY id DESC LIMIT 1").fetchone()
        return str(row[0]) if row else None

    def count(self) -> int:
        with self._lk:
            (c,) = self._conn.execute("SELECT COUNT(*) FROM receipts").fetchone()
        return int(c)

    def verify_chain_window(self, window: int, *, label_salt_hex: Optional[str] = None) -> bool:
        t0 = time.perf_counter()
        rows = self.tail(window)
        if not rows:
            _RCPT_VERIFY_LAT.labels("sqlite").observe(max(0.0, time.perf_counter() - t0))
            return True
        heads = [r.head_hex for r in rows]
        bodies = [r.body_json for r in rows]
        ok = bool(verify_chain(heads, bodies, label_salt_hex=label_salt_hex))
        if not ok:
            _RCPT_VERIFY_FAIL.labels("sqlite").inc()
        _RCPT_VERIFY_LAT.labels("sqlite").observe(max(0.0, time.perf_counter() - t0))
        return ok

    def stats(self) -> Dict[str, float]:
        last_ts = 0.0
        tail1 = self.tail(1)
        if tail1:
            last_ts = float(tail1[-1].ts)
        size_bytes = 0.0
        try:
            size_bytes = float(self._path.stat().st_size)
        except Exception:
            pass
        return {
            "count": float(self.count()),
            "size_bytes": size_bytes,
            "last_ts": last_ts,
        }


# =============================================================================
# Factory & helpers
# =============================================================================

def build_store_from_env() -> ReceiptStore:
    """
    Construct a store backend using environment knobs:

      TCD_RECEIPT_STORE = "jsonl" | "sqlite" | "memory"   (default: "jsonl")
      TCD_RECEIPT_PATH  = path to file (jsonl or sqlite). default: "./data/receipts.jsonl"
      TCD_RECEIPT_FSYNC = "1" | "0" for JSONL fsync writes (default: "1")
      TCD_RECEIPT_FSYNC_DIR = "1" | "0" fsync the directory entry (default: "0")

    For SQLite, path should end with ".db" (by convention).
    """
    backend = (os.environ.get("TCD_RECEIPT_STORE") or "jsonl").strip().lower()
    path = os.environ.get("TCD_RECEIPT_PATH") or "./data/receipts.jsonl"

    if backend == "memory":
        return InMemoryReceiptStore()

    if backend == "sqlite":
        p = Path(path)
        if p.suffix.lower() != ".db":
            path = str(p.with_suffix(".db"))
        return SqliteReceiptStore(path=path)

    # default: jsonl
    fsync = os.environ.get("TCD_RECEIPT_FSYNC", "1").strip() == "1"
    fsync_dir = os.environ.get("TCD_RECEIPT_FSYNC_DIR", "0").strip() == "1"
    return JsonlReceiptStore(path=path, fsync_writes=fsync, fsync_dir=fsync_dir)


def verify_recent_chain(store: ReceiptStore, window: int, *, label_salt_hex: Optional[str] = None) -> bool:
    """
    Convenience wrapper for periodic SRE audits. Intended to be called by a background job
    (e.g., cron, a scheduled worker, or an admin health endpoint). Returns True if the chain
    is valid over the given window.
    """
    try:
        return store.verify_chain_window(window, label_salt_hex=label_salt_hex)
    except Exception:
        return False


def summarize_recent_receipts(store: ReceiptStore, window: int) -> ReceiptSummary:
    """
    Aggregate metadata over the last `window` receipts.

    This helper is intended for security / compliance monitoring:
      - anomaly / abuse signals should drive the e-process trigger bit;
      - classifications (e.g. APT-like, insider-like, supply-chain-like) should be
        encoded as coarse labels in the receipt body (risk_label, kind, ...).

    The function is deliberately conservative:
      - it never returns raw bodies;
      - it only extracts a small set of agreed-upon fields.

    Expected body layout (conventions, not hard requirements):
      {
        "kind": "security_router" | "patch_runtime" | "audit" | ...,
        "risk_label": "low" | "high" | "apt_suspect" | ...,
        "e": {
          "e_value": ...,
          "alpha_wealth": ...,
          "trigger": true/false,
          ...
        },
        ...
      }
    """
    rows = store.tail(max(0, int(window)))
    total = len(rows)
    triggered_e = 0
    by_kind: Dict[str, int] = {}
    by_risk: Dict[str, int] = {}

    for r in rows:
        try:
            body = json.loads(r.body_json)
        except Exception:
            # Malformed bodies are skipped but still contribute to total.
            continue

        # kind: high-level category of the receipt
        kind_val = body.get("kind") or "unknown"
        kind = str(kind_val)
        by_kind[kind] = by_kind.get(kind, 0) + 1

        # risk: either risk_label or risk_level (for backward compatibility)
        risk_val = body.get("risk_label") or body.get("risk_level") or "unknown"
        risk = str(risk_val)
        by_risk[risk] = by_risk.get(risk, 0) + 1

        # e-process trigger: look under 'e' or 'e_obj' for a 'trigger' flag
        e_obj = body.get("e") or body.get("e_obj") or {}
        if isinstance(e_obj, dict) and bool(e_obj.get("trigger")):
            triggered_e += 1

    return ReceiptSummary(
        total=total,
        triggered_e=triggered_e,
        by_kind=by_kind,
        by_risk=by_risk,
    )