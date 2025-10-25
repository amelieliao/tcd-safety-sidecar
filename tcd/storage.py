# FILE: tcd/storage.py
from __future__ import annotations

import json
import math
import random
import sqlite3
import threading
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Union

# ------------------------------
# Common types & helpers
# ------------------------------

Subject = Tuple[str, str, str]  # (tenant, user, session)


def _finite_float(x: Union[float, int, None], default: float = 0.0) -> float:
    """Coerce to a finite float; return default for NaN/Inf/None."""
    try:
        v = float(x) if x is not None else float(default)
    except Exception:
        return float(default)
    if math.isfinite(v):
        return v
    return float(default)


# ------------------------------
# Data models
# ------------------------------

@dataclass(frozen=True, slots=True)
class InvestingStep:
    """
    Canonical investing step applied on a subject's alpha-wealth ledger.

    Semantics:
      wealth_next = max(0, wealth_cur - alpha_alloc + (earn if reject else 0) + reward)

    Notes
      - 'reject' models the detector firing; 'earn' is only credited on reject=True.
      - 'idem_key' enables idempotent replay protection across retries.
      - 'ts' allows callers to supply an external event timestamp.
    """
    alpha_alloc: float
    reject: bool
    earn: float = 0.0
    reward: float = 0.0
    policy_ref: str = "default"
    idem_key: Optional[str] = None
    ts: Optional[float] = None


@dataclass(slots=True)
class InvestingResult:
    applied: bool            # False => idempotent replay (no state mutation)
    wealth_before: float
    wealth_after: float
    alpha_alloc: float
    policy_ref: str
    idem_key: Optional[str]


@dataclass(frozen=True, slots=True)
class ReceiptRecord:
    """
    Persisted receipt line item.
    'body_json' must be the canonical JSON string used to compute the head.
    """
    head: str
    body_json: str
    sig_hex: str = ""
    verify_key_hex: str = ""
    prev: Optional[str] = None
    ts: Optional[float] = None
    chain_id: str = "default"  # optional namespace for multi-tenant separation


# ------------------------------
# Abstract interfaces
# ------------------------------

class AlphaWealthLedger(ABC):
    """Persistent ledger with idempotent investing updates."""

    @abstractmethod
    def get(self, subject: Subject, *, policy_ref: str = "default", default_alpha0: float = 0.05) -> float:
        """Return current wealth for subject (creating with alpha0 if missing)."""

    @abstractmethod
    def apply(self, subject: Subject, step: InvestingStep, *, default_alpha0: float = 0.05) -> InvestingResult:
        """Apply an investing step with idempotency and transactional safety."""


class ReceiptStore(ABC):
    """Persistent receipt store supporting append, lookup and linear chain traversal."""

    @abstractmethod
    def append(self, rec: ReceiptRecord) -> bool:
        """Insert a receipt (idempotent by head). Return True if newly inserted, False if existed."""

    @abstractmethod
    def get(self, head: str) -> Optional[ReceiptRecord]:
        """Fetch a receipt by head."""

    @abstractmethod
    def latest(self, *, chain_id: Optional[str] = None) -> Optional[ReceiptRecord]:
        """Get most recent receipt (per chain_id if provided)."""

    @abstractmethod
    def walk_back(self, head: Optional[str], *, limit: int = 100, chain_id: Optional[str] = None) -> List[ReceiptRecord]:
        """Starting at 'head' (or latest), follow prev pointers backwards up to 'limit'."""

    @abstractmethod
    def check_integrity(self, head: Optional[str], *, limit: int = 100, chain_id: Optional[str] = None) -> Dict[str, Union[bool, int, str]]:
        """Verify 'prev' linkage for the last 'limit' receipts. Returns {'ok', 'checked', 'bad_head'?}."""


# ------------------------------
# In-memory implementations
# ------------------------------

class InMemoryAlphaWealthLedger(AlphaWealthLedger):
    """
    Thread-safe in-memory ledger with idempotency window (TTL + LRU).
    Intended for tests and local dev; production should use SQLite or Redis.
    """

    def __init__(self, *, idem_ttl_s: float = 900.0, idem_max: int = 200_000):
        self._wealth: Dict[Tuple[Subject, str], float] = {}
        self._idem: OrderedDict[str, Tuple[float, InvestingResult]] = OrderedDict()
        self._idem_ttl = float(idem_ttl_s)
        self._idem_max = int(idem_max)
        self._g = threading.RLock()

    def _prune_idem(self, now: float) -> None:
        # Drop expired items
        keys = list(self._idem.keys())
        for k in keys:
            ts, _ = self._idem.get(k, (0.0, None))
            if now - ts > self._idem_ttl:
                self._idem.pop(k, None)
        # Enforce LRU bound
        while len(self._idem) > self._idem_max:
            self._idem.popitem(last=False)

    def get(self, subject: Subject, *, policy_ref: str = "default", default_alpha0: float = 0.05) -> float:
        with self._g:
            key = (subject, policy_ref)
            if key not in self._wealth:
                self._wealth[key] = float(_finite_float(default_alpha0, default_alpha0))
            return float(self._wealth[key])

    def apply(self, subject: Subject, step: InvestingStep, *, default_alpha0: float = 0.05) -> InvestingResult:
        now = time.time()
        with self._g:
            # Idempotency replay?
            if step.idem_key:
                self._prune_idem(now)
                cached = self._idem.get(step.idem_key)
                if cached is not None:
                    ts, res = cached
                    # Touch LRU
                    self._idem.pop(step.idem_key, None)
                    self._idem[step.idem_key] = (ts, res)
                    return InvestingResult(
                        applied=False,
                        wealth_before=res.wealth_before,
                        wealth_after=res.wealth_after,
                        alpha_alloc=res.alpha_alloc,
                        policy_ref=res.policy_ref,
                        idem_key=step.idem_key,
                    )

            key = (subject, step.policy_ref)
            wealth_before = float(self._wealth.get(key, _finite_float(default_alpha0, default_alpha0)))

            a = max(0.0, _finite_float(step.alpha_alloc))
            earn = _finite_float(step.earn if step.reject else 0.0)
            reward = _finite_float(step.reward)
            wealth_after = max(0.0, wealth_before - a + earn + reward)

            self._wealth[key] = wealth_after
            res = InvestingResult(
                applied=True,
                wealth_before=wealth_before,
                wealth_after=wealth_after,
                alpha_alloc=a,
                policy_ref=step.policy_ref,
                idem_key=step.idem_key,
            )
            if step.idem_key:
                self._idem[step.idem_key] = (now, res)
            return res


class InMemoryReceiptStore(ReceiptStore):
    def __init__(self):
        self._by_head: Dict[str, ReceiptRecord] = {}
        self._by_chain: Dict[str, List[str]] = {}
        self._g = threading.RLock()

    def append(self, rec: ReceiptRecord) -> bool:
        with self._g:
            if rec.head in self._by_head:
                return False
            # Insert
            self._by_head[rec.head] = rec
            chain = rec.chain_id or "default"
            self._by_chain.setdefault(chain, [])
            self._by_chain[chain].append(rec.head)
            return True

    def get(self, head: str) -> Optional[ReceiptRecord]:
        with self._g:
            return self._by_head.get(head)

    def latest(self, *, chain_id: Optional[str] = None) -> Optional[ReceiptRecord]:
        chain = (chain_id or "default")
        with self._g:
            arr = self._by_chain.get(chain, [])
            if not arr:
                return None
            return self._by_head.get(arr[-1])

    def walk_back(self, head: Optional[str], *, limit: int = 100, chain_id: Optional[str] = None) -> List[ReceiptRecord]:
        out: List[ReceiptRecord] = []
        with self._g:
            start = head
            if start is None:
                last = self.latest(chain_id=chain_id)
                start = last.head if last else None
            cur = start
            while cur and len(out) < int(limit):
                rec = self._by_head.get(cur)
                if not rec:
                    break
                out.append(rec)
                cur = rec.prev
        return out

    def check_integrity(self, head: Optional[str], *, limit: int = 100, chain_id: Optional[str] = None) -> Dict[str, Union[bool, int, str]]:
        seq = self.walk_back(head, limit=limit, chain_id=chain_id)
        if not seq:
            return {"ok": True, "checked": 0}
        # Validate forward 'prev' pointers
        checked = 0
        for i in range(1, len(seq)):
            # seq is [newest,...,oldest]; for linear chain: seq[i-1].prev == seq[i].head
            if seq[i - 1].prev != seq[i].head:
                return {"ok": False, "checked": checked, "bad_head": seq[i - 1].head}
            checked += 1
        return {"ok": True, "checked": checked}


# ------------------------------
# SQLite implementations
# ------------------------------

_SQL_SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS wealth (
  tenant TEXT NOT NULL,
  user   TEXT NOT NULL,
  session TEXT NOT NULL,
  policy_ref TEXT NOT NULL,
  wealth REAL NOT NULL,
  updated_at REAL NOT NULL,
  PRIMARY KEY (tenant, user, session, policy_ref)
);

CREATE TABLE IF NOT EXISTS wealth_idem (
  idem_key TEXT PRIMARY KEY,
  tenant TEXT NOT NULL,
  user   TEXT NOT NULL,
  session TEXT NOT NULL,
  policy_ref TEXT NOT NULL,
  wealth_before REAL NOT NULL,
  wealth_after REAL NOT NULL,
  alpha_alloc REAL NOT NULL,
  applied_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS receipts (
  head TEXT PRIMARY KEY,
  body_json TEXT NOT NULL,
  sig_hex TEXT DEFAULT '',
  verify_key_hex TEXT DEFAULT '',
  prev TEXT,
  ts REAL,
  chain_id TEXT DEFAULT 'default'
);

CREATE INDEX IF NOT EXISTS idx_receipts_chain_ts ON receipts(chain_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_receipts_prev ON receipts(prev);
"""


class _SQLite:
    """Small wrapper around sqlite3 to centralize connection & transactions."""

    def __init__(self, path: str):
        self._path = path
        self._g = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        # be resilient under load
        try:
            self._conn.execute("PRAGMA busy_timeout=30000;")
        except Exception:
            pass
        with self._conn:
            self._conn.executescript(_SQL_SCHEMA)

    def tx(self):
        """Context manager for IMMEDIATE transactions."""
        outer = self

        class _Tx:
            def __enter__(self):
                outer._g.acquire()
                outer._conn.execute("BEGIN IMMEDIATE;")
                return outer._conn

            def __exit__(self, exc_type, exc, tb):
                try:
                    if exc_type is None:
                        outer._conn.execute("COMMIT;")
                    else:
                        outer._conn.execute("ROLLBACK;")
                finally:
                    outer._g.release()

        return _Tx()

    def close(self) -> None:
        with self._g:
            try:
                self._conn.close()
            except Exception:
                pass


class SQLiteAlphaWealthLedger(AlphaWealthLedger):
    def __init__(self, path: str = "tcd.db", *, idem_retention_s: float = 24 * 3600, purge_prob: float = 0.01):
        self._db = _SQLite(path)
        self._idem_retention_s = float(idem_retention_s)
        self._purge_prob = max(0.0, min(1.0, float(purge_prob)))

    def _maybe_purge_idem(self, now: float) -> None:
        if self._idem_retention_s <= 0:
            return
        if random.random() > self._purge_prob:
            return
        cutoff = now - self._idem_retention_s
        with self._db.tx() as conn:
            try:
                conn.execute("DELETE FROM wealth_idem WHERE applied_at < ?", (cutoff,))
            except Exception:
                # Best-effort purge; ignore errors
                pass

    def get(self, subject: Subject, *, policy_ref: str = "default", default_alpha0: float = 0.05) -> float:
        t, u, s = subject
        now = time.time()
        with self._db.tx() as conn:
            row = conn.execute(
                "SELECT wealth FROM wealth WHERE tenant=? AND user=? AND session=? AND policy_ref=?",
                (t, u, s, policy_ref),
            ).fetchone()
            if row:
                return float(row["wealth"])
            conn.execute(
                "INSERT INTO wealth(tenant,user,session,policy_ref,wealth,updated_at) VALUES(?,?,?,?,?,?)",
                (t, u, s, policy_ref, float(_finite_float(default_alpha0, default_alpha0)), now),
            )
            return float(_finite_float(default_alpha0, default_alpha0))

    def apply(self, subject: Subject, step: InvestingStep, *, default_alpha0: float = 0.05) -> InvestingResult:
        t, u, s = subject
        now = float(step.ts if step.ts is not None else time.time())
        with self._db.tx() as conn:
            # Idempotent replay?
            if step.idem_key:
                row = conn.execute(
                    "SELECT wealth_before, wealth_after, alpha_alloc, policy_ref FROM wealth_idem WHERE idem_key=?",
                    (step.idem_key,),
                ).fetchone()
                if row:
                    # opportunistic purge (out of txn to avoid holding lock longer)
                    pass_result = InvestingResult(
                        applied=False,
                        wealth_before=float(row["wealth_before"]),
                        wealth_after=float(row["wealth_after"]),
                        alpha_alloc=float(row["alpha_alloc"]),
                        policy_ref=str(row["policy_ref"]),
                        idem_key=step.idem_key,
                    )
                    # Purge outside the tx lock to minimize contention
                    # (we still hold tx lock here; schedule purge after commit)
                    # Defer purge by returning and letting caller trigger.
                    # To keep simple, we do a second best-effort purge after tx.
                    res = pass_result
                    # end of tx
                    # (commit happens in __exit__)
                    # fall-through to return outside 'with'
                else:
                    res = None
            else:
                res = None

            if res is not None:
                # commit then maybe purge
                pass
            else:
                row = conn.execute(
                    "SELECT wealth FROM wealth WHERE tenant=? AND user=? AND session=? AND policy_ref=?",
                    (t, u, s, step.policy_ref),
                ).fetchone()
                wealth_before = float(row["wealth"]) if row else float(_finite_float(default_alpha0, default_alpha0))

                a = max(0.0, _finite_float(step.alpha_alloc))
                earn = _finite_float(step.earn if step.reject else 0.0)
                reward = _finite_float(step.reward)
                wealth_after = max(0.0, wealth_before - a + earn + reward)

                if row:
                    conn.execute(
                        "UPDATE wealth SET wealth=?, updated_at=? WHERE tenant=? AND user=? AND session=? AND policy_ref=?",
                        (wealth_after, now, t, u, s, step.policy_ref),
                    )
                else:
                    conn.execute(
                        "INSERT INTO wealth(tenant,user,session,policy_ref,wealth,updated_at) VALUES(?,?,?,?,?,?)",
                        (t, u, s, step.policy_ref, wealth_after, now),
                    )

                if step.idem_key:
                    conn.execute(
                        "INSERT OR IGNORE INTO wealth_idem(idem_key, tenant, user, session, policy_ref, wealth_before, wealth_after, alpha_alloc, applied_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?)",
                        (step.idem_key, t, u, s, step.policy_ref, wealth_before, wealth_after, a, now),
                    )

                res = InvestingResult(
                    applied=True,
                    wealth_before=wealth_before,
                    wealth_after=wealth_after,
                    alpha_alloc=a,
                    policy_ref=step.policy_ref,
                    idem_key=step.idem_key,
                )

        # post-commit: opportunistic idempotency purge
        self._maybe_purge_idem(now)
        return res  # type: ignore[return-value]


class SQLiteReceiptStore(ReceiptStore):
    def __init__(self, path: str = "tcd.db"):
        self._db = _SQLite(path)

    def append(self, rec: ReceiptRecord) -> bool:
        ts = rec.ts if rec.ts is not None else _extract_ts(rec.body_json) or time.time()
        with self._db.tx() as conn:
            try:
                conn.execute(
                    "INSERT INTO receipts(head, body_json, sig_hex, verify_key_hex, prev, ts, chain_id) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (rec.head, rec.body_json, rec.sig_hex or "", rec.verify_key_hex or "", rec.prev, ts, rec.chain_id or "default"),
                )
                return True
            except sqlite3.IntegrityError:
                # PK conflict -> already exists (idempotent)
                return False

    def get(self, head: str) -> Optional[ReceiptRecord]:
        with self._db.tx() as conn:
            row = conn.execute(
                "SELECT head, body_json, sig_hex, verify_key_hex, prev, ts, chain_id FROM receipts WHERE head=?",
                (head,),
            ).fetchone()
        if not row:
            return None
        return ReceiptRecord(
            head=row["head"],
            body_json=row["body_json"],
            sig_hex=row["sig_hex"] or "",
            verify_key_hex=row["verify_key_hex"] or "",
            prev=row["prev"],
            ts=float(row["ts"]) if row["ts"] is not None else None,
            chain_id=row["chain_id"] or "default",
        )

    def latest(self, *, chain_id: Optional[str] = None) -> Optional[ReceiptRecord]:
        chain = chain_id or "default"
        with self._db.tx() as conn:
            # Order by ts (NULLS LAST) then rowid as tie-breaker for recency
            row = conn.execute(
                "SELECT head, body_json, sig_hex, verify_key_hex, prev, ts, chain_id "
                "FROM receipts WHERE chain_id=? "
                "ORDER BY (ts IS NULL), ts DESC, rowid DESC LIMIT 1",
                (chain,),
            ).fetchone()
        if not row:
            return None
        return ReceiptRecord(
            head=row["head"],
            body_json=row["body_json"],
            sig_hex=row["sig_hex"] or "",
            verify_key_hex=row["verify_key_hex"] or "",
            prev=row["prev"],
            ts=float(row["ts"]) if row["ts"] is not None else None,
            chain_id=row["chain_id"] or "default",
        )

    def walk_back(self, head: Optional[str], *, limit: int = 100, chain_id: Optional[str] = None) -> List[ReceiptRecord]:
        out: List[ReceiptRecord] = []
        cur_head = head
        if cur_head is None:
            latest = self.latest(chain_id=chain_id)
            cur_head = latest.head if latest else None
        with self._db.tx() as conn:
            while cur_head and len(out) < int(limit):
                row = conn.execute(
                    "SELECT head, body_json, sig_hex, verify_key_hex, prev, ts, chain_id "
                    "FROM receipts WHERE head=?",
                    (cur_head,),
                ).fetchone()
                if not row:
                    break
                rec = ReceiptRecord(
                    head=row["head"],
                    body_json=row["body_json"],
                    sig_hex=row["sig_hex"] or "",
                    verify_key_hex=row["verify_key_hex"] or "",
                    prev=row["prev"],
                    ts=float(row["ts"]) if row["ts"] is not None else None,
                    chain_id=row["chain_id"] or "default",
                )
                out.append(rec)
                cur_head = rec.prev
        return out

    def check_integrity(self, head: Optional[str], *, limit: int = 100, chain_id: Optional[str] = None) -> Dict[str, Union[bool, int, str]]:
        seq = self.walk_back(head, limit=limit, chain_id=chain_id)
        if not seq:
            return {"ok": True, "checked": 0}
        # Validate forward 'prev' pointers. seq = [newest,...,oldest]
        checked = 0
        for i in range(1, len(seq)):
            # Correct relation: newest.prev == older.head
            if seq[i - 1].prev != seq[i].head:
                return {"ok": False, "checked": checked, "bad_head": seq[i - 1].head}
            checked += 1
        return {"ok": True, "checked": checked}


# ------------------------------
# Helpers & factories
# ------------------------------

def _extract_ts(body_json: str) -> Optional[float]:
    try:
        obj = json.loads(body_json)
        ts = obj.get("ts") or obj.get("meta", {}).get("ts")
        return float(ts) if ts is not None else None
    except Exception:
        return None


def make_ledger(dsn: Optional[str]) -> AlphaWealthLedger:
    """
    Factory:
      - None or "mem://"                          -> InMemoryAlphaWealthLedger
      - "sqlite:///path/to/tcd.db"                -> SQLiteAlphaWealthLedger
      - "sqlite:///:memory:" or "sqlite:///:mem:" -> SQLiteAlphaWealthLedger (in-memory)
      - "redis://..."                             -> NotImplementedError (reserved)
    """
    if not dsn or dsn.strip().lower().startswith("mem://"):
        return InMemoryAlphaWealthLedger()
    dsn_l = dsn.strip().lower()
    if dsn_l.startswith("sqlite:///"):
        path = dsn[len("sqlite:///") :]
        return SQLiteAlphaWealthLedger(path=path)
    if dsn_l.startswith("sqlite:///:memory:") or dsn_l.startswith("sqlite:///:mem:"):
        return SQLiteAlphaWealthLedger(path=":memory:")
    if dsn_l.startswith("redis://") or dsn_l.startswith("rediss://"):
        raise NotImplementedError("Redis ledger backend is not implemented in this release.")
    raise ValueError(f"Unsupported ledger dsn: {dsn}")


def make_receipt_store(dsn: Optional[str]) -> ReceiptStore:
    """
    Factory mirrors make_ledger(). It is common to co-locate both in the same SQLite file.
    """
    if not dsn or dsn.strip().lower().startswith("mem://"):
        return InMemoryReceiptStore()
    dsn_l = dsn.strip().lower()
    if dsn_l.startswith("sqlite:///"):
        path = dsn[len("sqlite:///") :]
        return SQLiteReceiptStore(path=path)
    if dsn_l.startswith("sqlite:///:memory:") or dsn_l.startswith("sqlite:///:mem:"):
        return SQLiteReceiptStore(path=":memory:")
    if dsn_l.startswith("redis://") or dsn_l.startswith("rediss://"):
        raise NotImplementedError("Redis receipt backend is not implemented in this release.")
    raise ValueError(f"Unsupported receipt store dsn: {dsn}")


# ------------------------------
# Minimal self-check (optional)
# ------------------------------

if __name__ == "__main__":
    # Quick smoke test for local runs: python -m tcd.storage
    ledger = make_ledger("sqlite:///tcd.db")
    store = make_receipt_store("sqlite:///tcd.db")

    subj: Subject = ("t", "u", "s")
    before = ledger.get(subj, policy_ref="p0", default_alpha0=0.1)
    r1 = ledger.apply(subj, InvestingStep(alpha_alloc=0.02, reject=True, earn=0.01, policy_ref="p0", idem_key="k1"))
    r2 = ledger.apply(subj, InvestingStep(alpha_alloc=0.02, reject=True, earn=0.01, policy_ref="p0", idem_key="k1"))  # replay
    print("wealth_before=", before, "res1=", r1, "res2(replay)=", r2)

    # Append a tiny chain of receipts
    body0 = json.dumps({"ts": time.time(), "witness_commit": "abc", "meta": {"i": 0}}, separators=(",", ":"), ensure_ascii=False)
    body1 = json.dumps({"ts": time.time(), "witness_commit": "def", "meta": {"i": 1}}, separators=(",", ":"), ensure_ascii=False)
    head0 = "h0"
    head1 = "h1"
    store.append(ReceiptRecord(head=head0, body_json=body0, prev=None))
    store.append(ReceiptRecord(head=head1, body_json=body1, prev=head0))
    print("latest=", store.latest())
    print("walk_back=", [r.head for r in store.walk_back(None, limit=10)])
    print("integrity=", store.check_integrity(None, limit=10))