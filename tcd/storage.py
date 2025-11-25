# FILE: tcd/storage.py
"""
Persistent storage backends for TCD:

  - AlphaWealthLedger:
      Backing store for e-process / alpha-investing.
      For each (subject, policy_ref), maintains a single non-negative wealth
      scalar and supports idempotent investing updates keyed by idem_key.

  - ReceiptStore:
      Append-only receipt store with prev-linked chains.
      Stores only canonical, content-agnostic receipt bodies (JSON) and
      associated metadata (heads, signatures, supply-chain fingerprints),
      suitable as a tamper-evident ground truth for audits.

Design constraints:

  - Content-agnostic:
      No prompts, completions or other raw content must be stored here.
      Receipt bodies are expected to contain IDs, hashes, policy references,
      security blocks and small numeric summaries only.

  - Idempotent and replay-safe:
      Both wealth updates and receipts can be safely retried without mutating
      state, as long as idem_key / head are reused.

  - Deterministic and auditable:
      For a fixed configuration and inputs, ledger and receipt state must be
      reproducible and suitable for later audit / verification.
"""
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

import logging

logger = logging.getLogger(__name__)

# ------------------------------
# Common types & helpers
# ------------------------------

#: Subject key used across the system: (tenant_id, user_id, session_id).
#:
#: All three components are expected to be opaque identifiers or hashes and
#: MUST NOT contain direct personal identifiers such as emails or full names.
Subject = Tuple[str, str, str]


def _finite_float(x: Union[float, int, None], default: float = 0.0) -> float:
    """
    Coerce x into a finite float, falling back to default on:
      - None,
      - NaN,
      - +/-Inf,
      - type conversion errors.

    This helper is used to keep ledger arithmetic robust under malformed or
    missing inputs.
    """
    try:
        v = float(x) if x is not None else float(default)
    except Exception:
        return float(default)
    if math.isfinite(v):
        return v
    return float(default)


def sanitize_subject(subject: Subject) -> Subject:
    """
    Best-effort sanity check for Subject.

    - Components MUST be opaque IDs or hashes, not emails or full names.
    - If a component clearly looks like PII (for example contains '@' or
      spaces), it is replaced with a generic placeholder and a generic
      warning is logged (without including the original value).

    This is a defensive guard; upstream is still responsible for proper
    anonymization / hashing.
    """
    t, u, s = subject

    def _clean(x: str, placeholder: str) -> str:
        if "@" in x or " " in x:
            logger.warning("Subject component looks like PII; upstream must hash/tokenize it")
            return placeholder
        return x or placeholder

    return (_clean(t, "tenant0"), _clean(u, "user0"), _clean(s, "sess0"))


# ------------------------------
# Data models
# ------------------------------

@dataclass(frozen=True, slots=True)
class InvestingStep:
    """
    Canonical investing step applied on a subject's alpha-wealth ledger.

    Wealth semantics:
      Given current wealth W and step parameters (alpha_alloc, reject, earn, reward):

        W_next = max(0, W - alpha_alloc + (earn if reject else 0) + reward)

      - alpha_alloc:
          Non-negative amount of wealth to allocate (spend) on this decision.
      - reject:
          True if the risk detector / AV controller triggered on this decision.
          Only when reject is True is 'earn' credited.
      - earn:
          Amount of wealth credited back when reject=True; often derived from
          e-process gains (e.g. from e-value based updates).
      - reward:
          Optional extra adjustment (for example manual credit or policy bonus).

    Idempotency and metadata:
      - policy_ref identifies the applicable investing policy.
      - idem_key allows idempotent replay across retries: when the same
        idem_key is seen again, the ledger returns the previous result
        without mutating underlying wealth.
      - ts allows callers to attach an external event timestamp; if omitted,
        wall-clock time is used.

    Security / routing context:
      These fields do not affect wealth arithmetic; they bind each investing
      step to its security and routing context so that later audits can
      reconstruct why the step was taken.

      - reason_code:
          Short code describing which subsystem caused this step:
            "detector", "av", "manual_adjust", "compensation", ...
      - threat_kind:
          Threat taxonomy aligned with upstream security context. Allowed
          values are typically: "apt", "insider", "supply_chain", or None.
      - trust_zone:
          Security zone where the decision is made. Example values:
            "internet", "internal", "partner", "admin".
      - route_profile:
          Route profile under which the decision is made:
            "inference", "admin", "control", ...
      - stream_id:
          Identifier tying this step to a stream / call chain (for example
          composed from subject, model, or route identifiers).
      - route_id:
          Deterministic route identifier from the routing layer.

      - override_applied / override_actor:
          Flag and opaque actor identifier for break-glass / internal override
          paths where standard policies were bypassed.
    """
    alpha_alloc: float
    reject: bool
    earn: float = 0.0
    reward: float = 0.0
    policy_ref: str = "default"
    idem_key: Optional[str] = None
    ts: Optional[float] = None

    # --- Security / compliance extensions ---
    reason_code: str = "normal"
    threat_kind: Optional[str] = None
    trust_zone: str = "internet"
    route_profile: str = "inference"
    stream_id: Optional[str] = None
    route_id: Optional[str] = None
    override_applied: bool = False
    override_actor: Optional[str] = None


@dataclass(slots=True)
class InvestingResult:
    """
    Result of applying an InvestingStep to the ledger.

      - applied:
          True if the step actually mutated state; False if it was treated
          as an idempotent replay (no mutation).
      - wealth_before / wealth_after:
          Wealth snapshot before and after the step (or the original snapshots
          in case of idempotent replay).
      - alpha_alloc:
          Effective non-negative allocation used for this step.
      - policy_ref / idem_key:
          Echo of the step metadata for audit / logging.
      - reason_code:
          Echo of the step's reason_code, carried through to make downstream
          logging and auditing easier.
    """
    applied: bool
    wealth_before: float
    wealth_after: float
    alpha_alloc: float
    policy_ref: str
    idem_key: Optional[str]
    reason_code: str = "normal"


@dataclass(frozen=True, slots=True)
class ReceiptRecord:
    """
    Persisted receipt line item.

    Fields:
      - head:
          Hex-encoded head of the receipt (for example hash(commitment)).
      - body_json:
          Canonical JSON string used to compute the head; this must be the
          exact bytes used when hashing. The body is expected to contain only
          structural metadata (IDs / hashes / numeric summaries / security
          blocks), not raw prompts or completions.
      - sig_hex / verify_key_hex:
          Optional signature and verification key used for authenticity checks.
      - prev:
          Head of the previous receipt in the chain (or None for chain root).
      - ts:
          Event timestamp associated with the receipt; if omitted, it may be
          inferred from the body JSON (field "ts" or "meta.ts") or fallback to
          insertion time.
      - chain_id:
          Optional namespace to separate independent chains (for example
          per-tenant or per deployment).

    PQ / supply-chain / compliance metadata:
      - sig_scheme:
          Signature scheme identifier (for example "dilithium3", "ed25519").
      - sig_class:
          Signature classification: "pq", "classical" or "hybrid".
      - signer_id:
          Identifier of the signing service, key management cluster or HSM.
      - key_id:
          Key identifier or version used to produce the signature.

      - build_id:
          Build or image identifier used by the serving environment.
      - image_digest:
          Container or artifact digest associated with the serving environment.
      - env_fingerprint:
          Fingerprint of the runtime environment (for example host, runtime).

      - compliance_tags_json:
          Canonical JSON-encoded list of compliance tags, such as:
            ["privacy_law_1","security_standard_x"].
          Tags are stored as a JSON string for indexing and scanning.
    """
    head: str
    body_json: str
    sig_hex: str = ""
    verify_key_hex: str = ""
    prev: Optional[str] = None
    ts: Optional[float] = None
    chain_id: str = "default"

    # PQ / signing posture
    sig_scheme: str = ""
    sig_class: str = ""
    signer_id: str = ""
    key_id: str = ""

    # Supply-chain binding
    build_id: str = ""
    image_digest: str = ""
    env_fingerprint: str = ""

    # Compliance tags as JSON string
    compliance_tags_json: str = ""


# ------------------------------
# Abstract interfaces
# ------------------------------

class AlphaWealthLedger(ABC):
    """
    Persistent ledger with idempotent investing updates.

    This is the backing store for the e-process controller. For each
    (subject, policy_ref) pair, it maintains a single non-negative wealth
    scalar and supports idempotent "investing" updates keyed by idem_key.
    """

    @abstractmethod
    def get(
        self,
        subject: Subject,
        *,
        policy_ref: str = "default",
        default_alpha0: float = 0.05,
    ) -> float:
        """
        Return current wealth for subject under a given policy_ref.

        If the (subject, policy_ref) pair is not present, initialize it to
        default_alpha0 (clamped via _finite_float) and return that value.
        """

    @abstractmethod
    def apply(
        self,
        subject: Subject,
        step: InvestingStep,
        *,
        default_alpha0: float = 0.05,
    ) -> InvestingResult:
        """
        Apply an investing step with idempotency and transactional safety.

        Idempotency:
          If step.idem_key is provided and a record exists for this key, the
          ledger MUST:
            - return the original InvestingResult for that key, with
              applied=False;
            - avoid mutating any wealth state.

          If no record exists for step.idem_key, the ledger MUST:
            - compute the new wealth using InvestingStep semantics;
            - persist the new wealth and idem entry atomically;
            - return an InvestingResult with applied=True.
        """


class ReceiptStore(ABC):
    """
    Persistent receipt store supporting append, lookup and linear chain traversal.

    This store serves as the tamper-evident ground truth for receipts and
    their prev-linked chains.
    """

    @abstractmethod
    def append(self, rec: ReceiptRecord) -> bool:
        """
        Insert a receipt (idempotent by 'head').

        Returns:
          True  if the record was newly inserted;
          False if a record with the same head already existed (no mutation).
        """

    @abstractmethod
    def get(self, head: str) -> Optional[ReceiptRecord]:
        """Fetch a receipt by head, or None if not found."""

    @abstractmethod
    def latest(self, *, chain_id: Optional[str] = None) -> Optional[ReceiptRecord]:
        """
        Get the most recent receipt for a given chain_id (or default chain).

        "Most recent" is defined as the receipt with the highest timestamp,
        breaking ties by row insertion order in persistent backends.
        """

    @abstractmethod
    def walk_back(
        self,
        head: Optional[str],
        *,
        limit: int = 100,
        chain_id: Optional[str] = None,
    ) -> List[ReceiptRecord]:
        """
        Starting at 'head' (or latest receipt for chain_id if head is None),
        follow 'prev' pointers backwards up to 'limit' records.

        Returns a list [newest, ..., oldest].
        """

    @abstractmethod
    def check_integrity(
        self,
        head: Optional[str],
        *,
        limit: int = 100,
        chain_id: Optional[str] = None,
    ) -> Dict[str, Union[bool, int, str]]:
        """
        Verify 'prev' linkage for the last 'limit' receipts.

        Returns:
          {"ok": True, "checked": N}
            if all prev pointers in the window are consistent; N is the number
            of links successfully checked (N <= limit-1).

          {"ok": False, "checked": N, "bad_head": <head>}
            if at position N a mismatch is detected between a record and its
            supposed previous head; 'bad_head' is the head of the newer record.
        """


# ------------------------------
# In-memory implementations
# ------------------------------

class InMemoryAlphaWealthLedger(AlphaWealthLedger):
    """
    Thread-safe in-memory ledger with an idempotency window.

    Features:
      - Wealth stored in-process as a plain dict keyed by (subject, policy_ref).
      - Idempotent steps remembered via LRU + TTL in _idem.
      - Intended for tests and local development; production deployments
        should use SQLiteAlphaWealthLedger or another persistent backend.

    No prompts or completions are stored here; only scalar wealth values and
    numeric investing results.
    """

    def __init__(self, *, idem_ttl_s: float = 900.0, idem_max: int = 200_000):
        self._wealth: Dict[Tuple[Subject, str], float] = {}
        # idem_key -> (ts, InvestingResult)
        self._idem: OrderedDict[str, Tuple[float, InvestingResult]] = OrderedDict()
        self._idem_ttl = float(idem_ttl_s)
        self._idem_max = int(idem_max)
        self._g = threading.RLock()

    def _prune_idem(self, now: float) -> None:
        """
        Remove expired idempotency entries and enforce LRU bound.
        """
        # Drop expired items
        for k, (ts, _) in list(self._idem.items()):
            if now - ts > self._idem_ttl:
                self._idem.pop(k, None)
        # Enforce LRU bound
        while len(self._idem) > self._idem_max:
            self._idem.popitem(last=False)

    def get(
        self,
        subject: Subject,
        *,
        policy_ref: str = "default",
        default_alpha0: float = 0.05,
    ) -> float:
        subj = sanitize_subject(subject)
        with self._g:
            key = (subj, policy_ref)
            if key not in self._wealth:
                self._wealth[key] = float(_finite_float(default_alpha0, default_alpha0))
            return float(self._wealth[key])

    def apply(
        self,
        subject: Subject,
        step: InvestingStep,
        *,
        default_alpha0: float = 0.05,
    ) -> InvestingResult:
        subj = sanitize_subject(subject)
        now = time.time()
        with self._g:
            # Idempotent replay?
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
                        reason_code=res.reason_code,
                    )

            key = (subj, step.policy_ref)
            wealth_before = float(
                self._wealth.get(key, _finite_float(default_alpha0, default_alpha0))
            )

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
                reason_code=step.reason_code,
            )
            if step.idem_key:
                self._idem[step.idem_key] = (now, res)
            return res


class InMemoryReceiptStore(ReceiptStore):
    """
    Simple in-memory receipt store.

    Characteristics:
      - Append-only per head; appending a duplicate head is treated as a
        no-op and returns False.
      - Per-chain latest() and walk_back() are implemented via in-memory
        lists of heads.
      - Intended for tests and local development; production should use
        SQLite or another durable store.
    """

    def __init__(self):
        self._by_head: Dict[str, ReceiptRecord] = {}
        self._by_chain: Dict[str, List[str]] = {}
        self._g = threading.RLock()

    def append(self, rec: ReceiptRecord) -> bool:
        with self._g:
            if rec.head in self._by_head:
                return False
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

    def walk_back(
        self,
        head: Optional[str],
        *,
        limit: int = 100,
        chain_id: Optional[str] = None,
    ) -> List[ReceiptRecord]:
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

    def check_integrity(
        self,
        head: Optional[str],
        *,
        limit: int = 100,
        chain_id: Optional[str] = None,
    ) -> Dict[str, Union[bool, int, str]]:
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
  applied_at REAL NOT NULL,

  -- Security / compliance context
  reason_code TEXT DEFAULT 'normal',
  threat_kind TEXT DEFAULT '',
  trust_zone  TEXT DEFAULT 'internet',
  route_profile TEXT DEFAULT 'inference',
  stream_id   TEXT DEFAULT '',
  route_id    TEXT DEFAULT '',
  override_applied INTEGER DEFAULT 0,
  override_actor   TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS receipts (
  head TEXT PRIMARY KEY,
  body_json TEXT NOT NULL,
  sig_hex TEXT DEFAULT '',
  verify_key_hex TEXT DEFAULT '',
  prev TEXT,
  ts REAL,
  chain_id TEXT DEFAULT 'default',

  -- PQ / signing posture
  sig_scheme TEXT DEFAULT '',
  sig_class  TEXT DEFAULT '',
  signer_id  TEXT DEFAULT '',
  key_id     TEXT DEFAULT '',

  -- Supply-chain binding
  build_id      TEXT DEFAULT '',
  image_digest  TEXT DEFAULT '',
  env_fingerprint TEXT DEFAULT '',

  -- Compliance tags as JSON string
  compliance_tags_json TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_receipts_chain_ts ON receipts(chain_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_receipts_prev ON receipts(prev);
CREATE INDEX IF NOT EXISTS idx_receipts_build ON receipts(build_id);
CREATE INDEX IF NOT EXISTS idx_receipts_image_digest ON receipts(image_digest);
CREATE INDEX IF NOT EXISTS idx_receipts_sig_class ON receipts(sig_class);
"""


class _SQLite:
    """
    Small wrapper around sqlite3 to centralize connection & transactions.

    Characteristics:
      - Single shared connection with check_same_thread=False for concurrent
        access across threads; guarded by a re-entrant lock.
      - IMMEDIATE transactions to avoid write skew.
      - WAL mode and busy_timeout to behave reasonably under moderate load.
    """

    def __init__(self, path: str):
        self._path = path
        self._g = threading.RLock()
        self._conn = sqlite3.connect(
            self._path,
            check_same_thread=False,
            isolation_level=None,
        )
        self._conn.row_factory = sqlite3.Row
        # Be resilient under load
        try:
            self._conn.execute("PRAGMA busy_timeout=30000;")
        except Exception:
            pass
        with self._conn:
            self._conn.executescript(_SQL_SCHEMA)

    def tx(self):
        """
        Context manager for IMMEDIATE transactions.

        Usage:
            with db.tx() as conn:
                conn.execute(...)
        """
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
        """Close the underlying SQLite connection."""
        with self._g:
            try:
                self._conn.close()
            except Exception:
                pass


class SQLiteAlphaWealthLedger(AlphaWealthLedger):
    """
    SQLite-backed implementation of AlphaWealthLedger.

    - Wealth is stored per (tenant, user, session, policy_ref).
    - Idempotent steps are stored in wealth_idem keyed by idem_key.
    - A probabilistic purge reclaims old wealth_idem rows based on
      idem_retention_s and purge_prob.
    """

    def __init__(
        self,
        path: str = "tcd.db",
        *,
        idem_retention_s: float = 24 * 3600,
        purge_prob: float = 0.01,
    ):
        self._db = _SQLite(path)
        self._idem_retention_s = float(idem_retention_s)
        self._purge_prob = max(0.0, min(1.0, float(purge_prob)))

    def _maybe_purge_idem(self, now: float) -> None:
        """
        Opportunistically purge old idempotency entries based on retention
        window and a random sampling probability.
        """
        if self._idem_retention_s <= 0:
            return
        if random.random() > self._purge_prob:
            return
        cutoff = now - self._idem_retention_s
        with self._db.tx() as conn:
            try:
                conn.execute(
                    "DELETE FROM wealth_idem WHERE applied_at < ?",
                    (cutoff,),
                )
            except Exception:
                # Best-effort purge; ignore errors
                pass

    def get(
        self,
        subject: Subject,
        *,
        policy_ref: str = "default",
        default_alpha0: float = 0.05,
    ) -> float:
        subj = sanitize_subject(subject)
        t, u, s = subj
        now = time.time()
        with self._db.tx() as conn:
            row = conn.execute(
                "SELECT wealth FROM wealth "
                "WHERE tenant=? AND user=? AND session=? AND policy_ref=?",
                (t, u, s, policy_ref),
            ).fetchone()
            if row:
                return float(row["wealth"])
            alpha0 = float(_finite_float(default_alpha0, default_alpha0))
            conn.execute(
                "INSERT INTO wealth(tenant,user,session,policy_ref,wealth,updated_at) "
                "VALUES(?,?,?,?,?,?)",
                (t, u, s, policy_ref, alpha0, now),
            )
            return alpha0

    def apply(
        self,
        subject: Subject,
        step: InvestingStep,
        *,
        default_alpha0: float = 0.05,
    ) -> InvestingResult:
        subj = sanitize_subject(subject)
        t, u, s = subj
        now = float(step.ts if step.ts is not None else time.time())

        with self._db.tx() as conn:
            # Idempotent replay?
            res: Optional[InvestingResult]
            if step.idem_key:
                row = conn.execute(
                    "SELECT wealth_before, wealth_after, alpha_alloc, policy_ref, reason_code "
                    "FROM wealth_idem WHERE idem_key=?",
                    (step.idem_key,),
                ).fetchone()
                if row:
                    res = InvestingResult(
                        applied=False,
                        wealth_before=float(row["wealth_before"]),
                        wealth_after=float(row["wealth_after"]),
                        alpha_alloc=float(row["alpha_alloc"]),
                        policy_ref=str(row["policy_ref"]),
                        idem_key=step.idem_key,
                        reason_code=str(row["reason_code"]) if row["reason_code"] is not None else "normal",
                    )
                else:
                    res = None
            else:
                res = None

            if res is None:
                row = conn.execute(
                    "SELECT wealth FROM wealth "
                    "WHERE tenant=? AND user=? AND session=? AND policy_ref=?",
                    (t, u, s, step.policy_ref),
                ).fetchone()
                wealth_before = float(row["wealth"]) if row else float(
                    _finite_float(default_alpha0, default_alpha0)
                )

                a = max(0.0, _finite_float(step.alpha_alloc))
                earn = _finite_float(step.earn if step.reject else 0.0)
                reward = _finite_float(step.reward)
                wealth_after = max(0.0, wealth_before - a + earn + reward)

                if row:
                    conn.execute(
                        "UPDATE wealth SET wealth=?, updated_at=? "
                        "WHERE tenant=? AND user=? AND session=? AND policy_ref=?",
                        (wealth_after, now, t, u, s, step.policy_ref),
                    )
                else:
                    conn.execute(
                        "INSERT INTO wealth(tenant,user,session,policy_ref,wealth,updated_at) "
                        "VALUES(?,?,?,?,?,?)",
                        (t, u, s, step.policy_ref, wealth_after, now),
                    )

                if step.idem_key:
                    conn.execute(
                        "INSERT OR IGNORE INTO wealth_idem("
                        "idem_key, tenant, user, session, policy_ref, "
                        "wealth_before, wealth_after, alpha_alloc, applied_at, "
                        "reason_code, threat_kind, trust_zone, route_profile, "
                        "stream_id, route_id, override_applied, override_actor"
                        ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            step.idem_key,
                            t,
                            u,
                            s,
                            step.policy_ref,
                            wealth_before,
                            wealth_after,
                            a,
                            now,
                            step.reason_code,
                            step.threat_kind or "",
                            step.trust_zone,
                            step.route_profile,
                            step.stream_id or "",
                            step.route_id or "",
                            1 if step.override_applied else 0,
                            step.override_actor or "",
                        ),
                    )

                res = InvestingResult(
                    applied=True,
                    wealth_before=wealth_before,
                    wealth_after=wealth_after,
                    alpha_alloc=a,
                    policy_ref=step.policy_ref,
                    idem_key=step.idem_key,
                    reason_code=step.reason_code,
                )

        # Post-commit: opportunistic idempotency purge
        self._maybe_purge_idem(now)
        return res


class SQLiteReceiptStore(ReceiptStore):
    """
    SQLite-backed implementation of ReceiptStore.

    The receipts table is append-only by primary key (head). Chains are
    traversed using prev pointers, and the latest receipt per chain_id is
    selected by timestamp with a rowid tie-breaker.
    """

    def __init__(self, path: str = "tcd.db"):
        self._db = _SQLite(path)

    def append(self, rec: ReceiptRecord) -> bool:
        """
        Insert a receipt, enforcing content-agnostic body_json and inferring
        ts from body_json if not explicitly set.

        The body_json is treated as canonical, so callers MUST ensure they
        pass the exact string representation used to compute the head.
        """
        _assert_content_agnostic_body(rec.body_json)
        ts = rec.ts if rec.ts is not None else _extract_ts(rec.body_json) or time.time()
        with self._db.tx() as conn:
            try:
                conn.execute(
                    "INSERT INTO receipts("
                    "head, body_json, sig_hex, verify_key_hex, prev, ts, chain_id, "
                    "sig_scheme, sig_class, signer_id, key_id, "
                    "build_id, image_digest, env_fingerprint, compliance_tags_json"
                    ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        rec.head,
                        rec.body_json,
                        rec.sig_hex or "",
                        rec.verify_key_hex or "",
                        rec.prev,
                        ts,
                        rec.chain_id or "default",
                        rec.sig_scheme or "",
                        rec.sig_class or "",
                        rec.signer_id or "",
                        rec.key_id or "",
                        rec.build_id or "",
                        rec.image_digest or "",
                        rec.env_fingerprint or "",
                        rec.compliance_tags_json or "",
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                # PK conflict -> already exists (idempotent)
                return False

    def _row_to_record(self, row: sqlite3.Row) -> ReceiptRecord:
        return ReceiptRecord(
            head=row["head"],
            body_json=row["body_json"],
            sig_hex=row["sig_hex"] or "",
            verify_key_hex=row["verify_key_hex"] or "",
            prev=row["prev"],
            ts=float(row["ts"]) if row["ts"] is not None else None,
            chain_id=row["chain_id"] or "default",
            sig_scheme=row["sig_scheme"] or "",
            sig_class=row["sig_class"] or "",
            signer_id=row["signer_id"] or "",
            key_id=row["key_id"] or "",
            build_id=row["build_id"] or "",
            image_digest=row["image_digest"] or "",
            env_fingerprint=row["env_fingerprint"] or "",
            compliance_tags_json=row["compliance_tags_json"] or "",
        )

    def get(self, head: str) -> Optional[ReceiptRecord]:
        with self._db.tx() as conn:
            row = conn.execute(
                "SELECT head, body_json, sig_hex, verify_key_hex, prev, ts, chain_id, "
                "sig_scheme, sig_class, signer_id, key_id, "
                "build_id, image_digest, env_fingerprint, compliance_tags_json "
                "FROM receipts WHERE head=?",
                (head,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_record(row)

    def latest(self, *, chain_id: Optional[str] = None) -> Optional[ReceiptRecord]:
        chain = chain_id or "default"
        with self._db.tx() as conn:
            # Order by ts (NULLS LAST) then rowid as tie-breaker for recency
            row = conn.execute(
                "SELECT head, body_json, sig_hex, verify_key_hex, prev, ts, chain_id, "
                "sig_scheme, sig_class, signer_id, key_id, "
                "build_id, image_digest, env_fingerprint, compliance_tags_json "
                "FROM receipts WHERE chain_id=? "
                "ORDER BY (ts IS NULL), ts DESC, rowid DESC LIMIT 1",
                (chain,),
            ).fetchone()
        if not row:
            return None
        return self._row_to_record(row)

    def walk_back(
        self,
        head: Optional[str],
        *,
        limit: int = 100,
        chain_id: Optional[str] = None,
    ) -> List[ReceiptRecord]:
        out: List[ReceiptRecord] = []
        cur_head = head
        if cur_head is None:
            latest = self.latest(chain_id=chain_id)
            cur_head = latest.head if latest else None
        with self._db.tx() as conn:
            while cur_head and len(out) < int(limit):
                row = conn.execute(
                    "SELECT head, body_json, sig_hex, verify_key_hex, prev, ts, chain_id, "
                    "sig_scheme, sig_class, signer_id, key_id, "
                    "build_id, image_digest, env_fingerprint, compliance_tags_json "
                    "FROM receipts WHERE head=?",
                    (cur_head,),
                ).fetchone()
                if not row:
                    break
                rec = self._row_to_record(row)
                out.append(rec)
                cur_head = rec.prev
        return out

    def check_integrity(
        self,
        head: Optional[str],
        *,
        limit: int = 100,
        chain_id: Optional[str] = None,
    ) -> Dict[str, Union[bool, int, str]]:
        """
        Validate prev linkage for up to 'limit' receipts starting from 'head'
        (or latest for chain_id if head is None).

        See ReceiptStore.check_integrity for return format.
        """
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
    """
    Extract an event timestamp from a canonical receipt body.

    Convention:
      - Prefer top-level field "ts" if present;
      - Otherwise, use "meta.ts" if present;
      - If neither is present or parsing fails, return None.
    """
    try:
        obj = json.loads(body_json)
        ts = obj.get("ts") or obj.get("meta", {}).get("ts")
        return float(ts) if ts is not None else None
    except Exception:
        return None


_FORBIDDEN_RECEIPT_KEYS = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "raw_prompt",
    "raw_completion",
}


def _assert_content_agnostic_body(body_json: str) -> None:
    """
    Best-effort guard to keep receipt bodies content-agnostic.

    This function parses the JSON and scans top-level keys for obviously
    unsafe fields such as "prompt" or "completion". It cannot prove the
    absence of raw content, but it helps catch accidental misuse.

    Raises:
      ValueError if body_json is not valid JSON or contains forbidden keys.
    """
    try:
        obj = json.loads(body_json)
    except Exception as exc:
        raise ValueError("Receipt body_json must be valid JSON") from exc

    if isinstance(obj, dict):
        lower_keys = {str(k).lower() for k in obj.keys()}
        if _FORBIDDEN_RECEIPT_KEYS & lower_keys:
            raise ValueError(
                "Receipt body_json contains forbidden keys; "
                "it MUST NOT include raw prompts or completions."
            )


def make_ledger(dsn: Optional[str]) -> AlphaWealthLedger:
    """
    Factory for AlphaWealthLedger backends.

    Accepted DSNs:
      - None or "mem://"
          -> InMemoryAlphaWealthLedger
      - "sqlite:///path/to/tcd.db"
          -> SQLiteAlphaWealthLedger(path="path/to/tcd.db")
      - "sqlite:///:memory:" or "sqlite:///:mem:"
          -> SQLiteAlphaWealthLedger(path=":memory:")
      - "redis://..." / "rediss://..."
          -> reserved for future backends (NotImplementedError)

    Note:
      In-memory and in-process SQLite configurations are suitable for tests
      and local development only. Persistent, externally-backed storage
      should be used for any audited deployment.
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
    Factory for ReceiptStore backends.

    Mirrors make_ledger() semantics; it is common to co-locate both ledger
    and receipt store in the same SQLite file.

    Note:
      In-memory and in-process SQLite configurations are suitable for tests
      and local development only. Persistent, externally-backed storage
      should be used for any audited deployment.
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

    subj: Subject = ("tenant@example", "user name", "sess0")
    subj = sanitize_subject(subj)

    before = ledger.get(subj, policy_ref="p0", default_alpha0=0.1)
    step = InvestingStep(
        alpha_alloc=0.02,
        reject=True,
        earn=0.01,
        policy_ref="p0",
        idem_key="k1",
        reason_code="detector",
        threat_kind="apt",
        trust_zone="internal",
        route_profile="inference",
        stream_id="stream-1",
        route_id="route-1",
        override_applied=False,
    )
    r1 = ledger.apply(subj, step)
    # Replay with same idem_key: should not mutate wealth
    r2 = ledger.apply(subj, step)
    print("wealth_before=", before, "res1=", r1, "res2(replay)=", r2)

    # Append a tiny chain of receipts
    body0 = json.dumps(
        {"ts": time.time(), "witness_commit": "abc", "meta": {"i": 0}},
        separators=(",", ":"),
        ensure_ascii=False,
    )
    body1 = json.dumps(
        {"ts": time.time(), "witness_commit": "def", "meta": {"i": 1}},
        separators=(",", ":"),
        ensure_ascii=False,
    )
    head0 = "h0"
    head1 = "h1"
    store.append(
        ReceiptRecord(
            head=head0,
            body_json=body0,
            prev=None,
            sig_scheme="scheme-x",
            sig_class="pq",
            signer_id="signer-1",
            key_id="key-1",
            build_id="build-1",
            image_digest="digest-1",
            env_fingerprint="env-1",
            compliance_tags_json=json.dumps(["privacy_law_1"]),
        )
    )
    store.append(
        ReceiptRecord(
            head=head1,
            body_json=body1,
            prev=head0,
            sig_scheme="scheme-x",
            sig_class="pq",
            signer_id="signer-1",
            key_id="key-1",
            build_id="build-1",
            image_digest="digest-1",
            env_fingerprint="env-1",
            compliance_tags_json=json.dumps(["privacy_law_1"]),
        )
    )
    print("latest=", store.latest())
    print("walk_back=", [r.head for r in store.walk_back(None, limit=10)])
    print("integrity=", store.check_integrity(None, limit=10))