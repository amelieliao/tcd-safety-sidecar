# FILE: tcd/ledger.py
from __future__ import annotations

"""
TCD Ledger — Wealth (alpha-investing) persistence + Receipt chain storage.

Goals:
  - Cross-instance consistency for alpha-investing wealth
  - Idempotent events to avoid double-spend under retries
  - Durable receipt chain with anti-fork constraints
  - Minimal deps; production-ready SQLite backend (WAL) + versioned schema
  - Auditor/AE-friendly helpers: recompute, export/import, pagination, pruning
  - Optional Prometheus metrics (safe no-op when prometheus_client absent)

Notes:
  - This module persists results emitted by controllers; it does NOT compute decisions.
  - Event idempotency is per event_id (your /diagnose should pass request_id/idempotency-key).
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List, Iterable, Any, Mapping, Set
import json
import os
import sqlite3
import threading
import time
import hmac
import hashlib
import math
from contextlib import contextmanager

# ---------- Optional metrics (no-op if prometheus_client missing) ----------

try:
    from prometheus_client import Counter, Histogram  # type: ignore

    _HAS_PROM = True
except Exception:  # pragma: no cover
    _HAS_PROM = False


class _NopMetric:
    def labels(self, *_, **__):
        return self

    def inc(self, *_, **__):
        pass

    def observe(self, *_, **__):
        pass

    def set(self, *_, **__):
        pass


if _HAS_PROM:
    _EVT_APPLIED = Counter(
        "tcd_ledger_event_applied_total", "Applied wealth update events"
    )
    _EVT_DUP = Counter(
        "tcd_ledger_event_duplicate_total", "Duplicate events (idempotent)"
    )
    _EVT_CROSS = Counter(
        "tcd_ledger_event_cross_subject_total",
        "event_id reused across different subject",
    )
    _EVT_FLOOR = Counter(
        "tcd_ledger_wealth_floor_hit_total",
        "Wealth updates clamped by hard floor",
    )
    _TX_LAT = Histogram(
        "tcd_ledger_tx_latency_seconds",
        "SQLite transaction latency (seconds)",
        buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.1, 0.2),
    )
    _RCPT_FAIL = Counter(
        "tcd_receipts_append_fail_total", "Receipt append failures (duplicates/forks)"
    )
    _RCPT_COUNT = Counter(
        "tcd_receipts_append_total", "Receipt append success"
    )
    _RCPT_SIZE = Histogram(
        "tcd_receipt_body_size_bytes", "Receipt body size (bytes)"
    )
    _RCPT_PRUNED = Counter(
        "tcd_receipts_pruned_total", "Receipts pruned by cutoff"
    )
else:  # pragma: no cover
    _EVT_APPLIED = _NopMetric()
    _EVT_DUP = _NopMetric()
    _EVT_CROSS = _NopMetric()
    _EVT_FLOOR = _NopMetric()
    _TX_LAT = _NopMetric()
    _RCPT_FAIL = _NopMetric()
    _RCPT_COUNT = _NopMetric()
    _RCPT_SIZE = _NopMetric()
    _RCPT_PRUNED = _NopMetric()

# ---------- Metadata / receipt guards (content-agnostic) ----------

# For metadata stored in wealth/events (do not persist raw content)
_FORBIDDEN_META_KEYS: Set[str] = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "messages",
    "content",
    "raw",
    "body",
}

# Optional hard whitelist mode (only allow a small safe set of keys in meta)
_LEDGER_META_WHITELIST_MODE = (
    os.environ.get("TCD_LEDGER_META_WHITELIST", "0") == "1"
)

# Ledger-level allowed meta keys (small, schema-like tag set)
_ALLOWED_LEDGER_META_KEYS: Set[str] = {
    "policy_ref",
    "chain_id",
    "pq_scheme",
    "pq_required",
    "pq_ok",
    "pq_chain_id",
    "override_applied",
    "override_actor",
    "override_level",
    "lockdown_level",
    "trust_zone",
    "route_profile",
    "tenant",
    "user",
    "session",
    "model_id",
    "e_value",
    "a_alloc",
    "score",
}

_LEDGER_SANITIZE_META = os.environ.get("TCD_LEDGER_SANITIZE_META", "1") == "1"
_LEDGER_STRIP_PII = os.environ.get("TCD_LEDGER_STRIP_PII", "0") == "1"

# Optional hash mode for tag-like PII (tenant/user/session/override_actor)
_LEDGER_HASH_PII_TAGS = os.environ.get("TCD_LEDGER_HASH_PII_TAGS", "1") == "1"

# Vocabulary constraints for trust_zone, route_profile, override_level, pq_scheme
_ALLOWED_TRUST_ZONES: Set[str] = {
    "internet",
    "internal",
    "partner",
    "admin",
    "ops",
}

_ALLOWED_ROUTE_PROFILES: Set[str] = {
    "inference",
    "admin",
    "control",
    "metrics",
    "health",
}

_ALLOWED_OVERRIDE_LEVELS: Set[str] = {
    "none",
    "break_glass",
    "maintenance",
}

_ALLOWED_PQ_SCHEMES: Set[str] = {
    "",
    "dilithium2",
    "dilithium3",
    "falcon",
    "sphincs+",
}

# Guard for receipt payload size (ledger-level)
_MAX_RECEIPT_BODY_BYTES = 16_384  # 16 KiB

# Guard for receipt identifiers / signatures
_MAX_RECEIPT_HEAD_LEN = 256
_MAX_RECEIPT_SIG_LEN = 4_096

# Optional guard for event identifiers
_MAX_EVENT_ID_LEN = 256

# Structured metadata sanitization (shared with logging/verify)
from .utils import (  # noqa: E402
    SanitizeConfig,
    sanitize_metadata_for_receipt,
    blake2s_hex,
)


def _looks_like_pii(value: str) -> bool:
    """
    Very lightweight PII heuristic:
    used only for tag-like fields (tenant/user/session/override_actor),
    to avoid logging direct emails or person names.
    """
    v = value.strip()
    if not v:
        return False
    if "@" in v:
        return True
    if " " in v or "\u3000" in v:
        return True
    # Very long token-like strings are treated as IDs/hashes, not PII
    if len(v) > 96:
        return False
    return False


def _hash_if_pii_tag(key: str, value: Any) -> Any:
    """
    If key is a tag field and value looks like PII, replace with Blake2s hash.
    """
    if not _LEDGER_HASH_PII_TAGS:
        return value
    if not isinstance(value, str):
        return value
    kl = key.lower()
    if kl not in ("tenant", "user", "session", "override_actor"):
        return value
    if not _looks_like_pii(value):
        return value
    try:
        digest = blake2s_hex(value, canonical=False)[:16]
        return f"{kl}-h-{digest}"
    except Exception:
        return f"{kl}-h-anon"


def _normalize_meta_shape(meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Second-stage normalization for ledger metadata:

      - Pseudonymize possible PII-like tags via hashing.
      - Enforce vocabulary constraints for trust_zone / route_profile /
        override_level / pq_scheme.
      - Clamp e-process-related numeric fields (e_value / a_alloc / score)
        into safe domains.
      - Normalize override_applied / pq_required / pq_ok as booleans.
    """
    out = dict(meta)

    # 1) PII-like tags: hash if needed
    for fld in ("tenant", "user", "session", "override_actor"):
        if fld in out:
            out[fld] = _hash_if_pii_tag(fld, out[fld])

    # 2) Vocabulary constraints
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
    if isinstance(pqs, str) and pqs not in _ALLOWED_PQ_SCHEMES:
        out.pop("pq_scheme", None)

    # 3) e-process-related numeric fields
    for fld in ("e_value", "a_alloc", "score"):
        if fld not in out:
            continue
        v = out.get(fld)
        try:
            v_f = float(v)
        except Exception:
            out.pop(fld, None)
            continue
        if not math.isfinite(v_f):
            out.pop(fld, None)
            continue
        if fld == "e_value":
            if v_f < 0.0:
                out.pop(fld, None)
            else:
                out[fld] = v_f
        elif fld == "a_alloc":
            # Alpha budget in [0, 1]
            out[fld] = max(0.0, min(1.0, v_f))
        elif fld == "score":
            # Clamp score into [0, 1]
            out[fld] = max(0.0, min(1.0, v_f))

    # 4) Bool-like fields
    for fld in ("override_applied", "pq_required", "pq_ok"):
        if fld in out:
            out[fld] = bool(out[fld])

    return out


def _sanitize_meta_for_storage(
    meta: Optional[Dict[str, object]],
) -> Dict[str, object]:
    """
    Sanitize metadata before persisting:

      - Drop forbidden keys (prompt/completion/etc.).
      - Optionally run structured sanitization (depth/size, NaN, PII stripping).
      - Normalize PQ / override / trust_zone / e-process shape.
      - Optionally enforce a tight whitelist of keys.
      - Ensure JSON-serializable shape.
    """
    if not meta:
        return {}

    # Drop forbidden keys at top level
    filtered: Dict[str, Any] = {}
    for k, v in meta.items():
        key = str(k)
        if key.lower() in _FORBIDDEN_META_KEYS:
            continue
        filtered[key] = v

    if not filtered:
        return {}

    # Structured sanitization via utils (mirrors logging/receipt behavior)
    if _LEDGER_SANITIZE_META:
        try:
            cfg = SanitizeConfig(
                sanitize_nan=True,
                prune_large=True,
                strip_pii=_LEDGER_STRIP_PII,
                forbid_keys=tuple(_FORBIDDEN_META_KEYS),
            )
            sanitized = sanitize_metadata_for_receipt(filtered, config=cfg)
            if isinstance(sanitized, Mapping):
                out: Dict[str, Any] = dict(sanitized)
            else:
                out = dict(filtered)
        except Exception:
            out = dict(filtered)
    else:
        out = dict(filtered)

    # Second-stage normalization for PQ / override / trust_zone / e-process
    out = _normalize_meta_shape(out)

    # Hard whitelist mode: only keep known ledger-safe keys
    if _LEDGER_META_WHITELIST_MODE:
        whitelisted: Dict[str, Any] = {}
        for k, v in out.items():
            if k.lower() in _ALLOWED_LEDGER_META_KEYS:
                whitelisted[k] = v
        return whitelisted

    return out


def _meta_to_json(meta: Dict[str, object]) -> str:
    """
    Serialize sanitized metadata to compact JSON.
    """
    return json.dumps(meta, separators=(",", ":"), ensure_ascii=False)


def _validate_event_id(event_id: str) -> str:
    """
    Basic validation for event_id to avoid pathological cases.
    """
    if not isinstance(event_id, str) or not event_id:
        raise LedgerError("event_id must be non-empty string")
    if len(event_id) > _MAX_EVENT_ID_LEN:
        raise LedgerError("event_id too long")
    return event_id


def _validate_receipt_record(rec: "ReceiptRecord") -> None:
    """
    Basic structural validation for ReceiptRecord before persistence.

    This does NOT perform cryptographic verification; it only checks basic
    shapes and size limits to defend the ledger from unbounded payloads.
    """
    if not isinstance(rec.head, str) or not rec.head:
        raise LedgerError("receipt head must be non-empty string")
    if len(rec.head) > _MAX_RECEIPT_HEAD_LEN:
        raise LedgerError("receipt head too long")

    if rec.prev is not None:
        if not isinstance(rec.prev, str):
            raise LedgerError("receipt prev must be None or string")
        if len(rec.prev) > _MAX_RECEIPT_HEAD_LEN:
            raise LedgerError("receipt prev too long")

    if rec.sig is not None:
        if not isinstance(rec.sig, str):
            raise LedgerError("receipt sig must be None or string")
        if len(rec.sig) > _MAX_RECEIPT_SIG_LEN:
            raise LedgerError("receipt sig too long")

    try:
        body_bytes = rec.body.encode("utf-8", errors="ignore")
    except Exception as e:
        raise LedgerError(f"receipt body not utf-8 encodable: {e}") from e
    if len(body_bytes) > _MAX_RECEIPT_BODY_BYTES:
        raise LedgerError("receipt body too large for ledger")


# ---------- Data Models ----------


@dataclass(frozen=True)
class SubjectKey:
    tenant: str
    user: str
    session: str

    def as_tuple(self) -> Tuple[str, str, str]:
        return (self.tenant, self.user, self.session)

    def as_str(self) -> str:
        # canonical stable key used in DB; avoid JSON for hot paths
        # NOTE: if your identifiers may contain "::<", enforce a sanitize rule before constructing SubjectKey.
        return f"{self.tenant}::{self.user}::{self.session}"


@dataclass
class WealthRecord:
    subject: SubjectKey
    wealth: float
    alpha0: float
    hard_floor: float
    policy_ref: str
    version: int
    updated_ts: float
    meta: Dict[str, object]


@dataclass
class EventApplyResult:
    applied: bool  # True if new event applied, False if duplicate (idempotent hit)
    wealth_after: float
    alpha_spent: float  # echo
    updated_ts: float


@dataclass
class ReceiptRecord:
    head: str
    body: str
    sig: Optional[str]
    prev: Optional[str]
    ts: float


# ---------- Exceptions ----------


class LedgerError(RuntimeError):
    pass


# ---------- Base Interface ----------


class Ledger:
    """
    Abstract ledger API (storage only).
    """

    # Wealth / Investing

    def ensure_subject(
        self,
        subject: SubjectKey,
        *,
        alpha0: float,
        hard_floor: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> WealthRecord:
        raise NotImplementedError

    def get_wealth(self, subject: SubjectKey) -> Optional[WealthRecord]:
        raise NotImplementedError

    def apply_event(
        self,
        subject: SubjectKey,
        *,
        event_id: str,
        alpha_spent: float,
        reward: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> EventApplyResult:
        raise NotImplementedError

    # Receipts

    def append_receipt(self, rec: ReceiptRecord) -> None:
        raise NotImplementedError

    def append_receipt_strict(self, rec: ReceiptRecord) -> None:
        """
        Atomic append with prev=head check in the same DB txn (anti-race).
        Implemented by SQLiteLedger; InMemoryLedger delegates to append_receipt.
        """
        self.append_receipt(rec)

    def chain_head(self) -> Optional[str]:
        raise NotImplementedError

    def load_chain(self, limit: int = 1000) -> List[ReceiptRecord]:
        raise NotImplementedError

    # AE / audit helpers (optional)

    def recompute_wealth(self, subject: SubjectKey) -> Dict[str, float]:
        """Replay events to recompute wealth for subject; returns {expected, recorded, delta}."""
        raise NotImplementedError

    def export_events(
        self,
        *,
        subject: Optional[SubjectKey] = None,
        ts_from: float = 0.0,
        ts_to: Optional[float] = None,
    ) -> Iterable[Dict[str, Any]]:
        """Yield events as dictionaries (JSONL-friendly)."""
        raise NotImplementedError

    def import_events(self, rows: Iterable[Dict[str, Any]]) -> int:
        """Import events (idempotent). Returns count attempted/inserted."""
        raise NotImplementedError

    def load_chain_page(
        self, page_size: int = 256, cursor_ts: Optional[float] = None
    ) -> Tuple[List[ReceiptRecord], Optional[float]]:
        """Page receipts by timestamp. Returns (records_sorted_asc, next_cursor_ts or None)."""
        raise NotImplementedError

    def prune_receipts_before(self, cutoff_ts: float) -> int:
        """Delete receipts with ts < cutoff. Returns deleted count (use with export first!)."""
        raise NotImplementedError


# ---------- In-Memory Implementation (tests / dev) ----------


class InMemoryLedger(Ledger):
    def __init__(self):
        self._w: Dict[str, WealthRecord] = {}
        # event_id -> subject_str (for idempotency & cross-subject guard)
        self._events: Dict[str, str] = {}
        self._receipts: List[ReceiptRecord] = []
        self._lock = threading.RLock()

    def ensure_subject(
        self,
        subject: SubjectKey,
        *,
        alpha0: float,
        hard_floor: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> WealthRecord:
        now = time.time()
        s = subject.as_str()

        if not (math.isfinite(alpha0) and math.isfinite(hard_floor)):
            raise LedgerError("non-finite alpha0/hard_floor")
        if alpha0 < 0.0 or hard_floor < 0.0:
            raise LedgerError("negative alpha0/hard_floor not allowed")

        alpha0_f = float(alpha0)
        hard_floor_f = float(hard_floor)

        meta_sanitized = _sanitize_meta_for_storage(meta)
        with self._lock:
            wr = self._w.get(s)
            if wr is None:
                wr = WealthRecord(
                    subject=subject,
                    wealth=alpha0_f,
                    alpha0=alpha0_f,
                    hard_floor=hard_floor_f,
                    policy_ref=str(policy_ref),
                    version=1,
                    updated_ts=now,
                    meta=dict(meta_sanitized),
                )
                self._w[s] = wr
            return wr

    def get_wealth(self, subject: SubjectKey) -> Optional[WealthRecord]:
        with self._lock:
            return self._w.get(subject.as_str())

    def apply_event(
        self,
        subject: SubjectKey,
        *,
        event_id: str,
        alpha_spent: float,
        reward: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> EventApplyResult:
        now = time.time()
        s = subject.as_str()
        _validate_event_id(event_id)

        with self._lock:
            # cross-subject reuse detection
            if event_id in self._events and self._events[event_id] != s:
                _EVT_CROSS.inc()
                raise LedgerError("event_id reused across different subject")

            # idempotent duplicate on same subject
            if event_id in self._events:
                wr = self._w.get(s)
                wealth_after = float(wr.wealth) if wr else 0.0
                _EVT_DUP.inc()
                return EventApplyResult(False, wealth_after, float(alpha_spent), now)

            wr = self._w.get(s)
            if wr is None:
                raise LedgerError(
                    "apply_event: subject not found; call ensure_subject first"
                )

            # sanitize numbers
            if not (math.isfinite(alpha_spent) and math.isfinite(reward)):
                raise LedgerError("non-finite alpha_spent/reward")
            alpha_spent = float(max(0.0, alpha_spent))
            reward = float(max(0.0, reward))

            if not (math.isfinite(wr.wealth) and math.isfinite(wr.hard_floor)):
                raise LedgerError("non-finite wealth state for subject")

            # wealth update (hard floor guard)
            tentative = float(wr.wealth) - alpha_spent + reward
            if tentative < float(wr.hard_floor):
                _EVT_FLOOR.inc()
            wealth_after = max(float(wr.hard_floor), tentative)

            wr.wealth = wealth_after
            wr.updated_ts = now
            wr.policy_ref = str(policy_ref)
            wr.version += 1

            if meta:
                meta_sanitized = _sanitize_meta_for_storage(meta)
                if meta_sanitized:
                    wr.meta.update(meta_sanitized)

            self._events[event_id] = s
            _EVT_APPLIED.inc()
            return EventApplyResult(True, wealth_after, float(alpha_spent), now)

    def append_receipt(self, rec: ReceiptRecord) -> None:
        _validate_receipt_record(rec)
        with self._lock:
            prev = self._receipts[-1].head if self._receipts else None
            if prev != rec.prev:
                _RCPT_FAIL.inc()
                raise LedgerError("append_receipt: chain prev pointer mismatch")
            self._receipts.append(rec)
            _RCPT_SIZE.observe(len(rec.body.encode("utf-8", errors="ignore")))
            _RCPT_COUNT.inc()

    def append_receipt_strict(self, rec: ReceiptRecord) -> None:
        # In-memory: same as append (no separate txn semantics needed)
        self.append_receipt(rec)

    def chain_head(self) -> Optional[str]:
        with self._lock:
            return self._receipts[-1].head if self._receipts else None

    def load_chain(self, limit: int = 1000) -> List[ReceiptRecord]:
        with self._lock:
            if limit > 0:
                return list(self._receipts[-limit:])
            return list(self._receipts)

    def recompute_wealth(self, subject: SubjectKey) -> Dict[str, float]:
        with self._lock:
            wr = self._w.get(subject.as_str())
            if not wr:
                raise LedgerError("subject not found")
            # In-memory ledger does not persist event rows; we treat recorded
            # wealth as the reference value and expose zero delta for tests.
            return {
                "expected": float(wr.wealth),
                "recorded": float(wr.wealth),
                "delta": 0.0,
            }

    def export_events(
        self,
        *,
        subject: Optional[SubjectKey] = None,
        ts_from: float = 0.0,
        ts_to: Optional[float] = None,
    ) -> Iterable[Dict[str, Any]]:
        # In-memory demo store has no persisted event rows; emit nothing
        return []

    def import_events(self, rows: Iterable[Dict[str, Any]]) -> int:
        # Not supported in in-memory demo
        return 0

    def load_chain_page(
        self, page_size: int = 256, cursor_ts: Optional[float] = None
    ) -> Tuple[List[ReceiptRecord], Optional[float]]:
        with self._lock:
            rows = self._receipts
            if cursor_ts is None:
                start = 0
            else:
                # find first ts > cursor_ts
                start = 0
                for i, r in enumerate(rows):
                    if r.ts > float(cursor_ts):
                        start = i
                        break
                else:
                    return ([], None)
            end = min(len(rows), start + max(1, int(page_size)))
            out = rows[start:end]
            next_cursor = out[-1].ts if out and end < len(rows) else None
            return (list(out), next_cursor)

    def prune_receipts_before(self, cutoff_ts: float) -> int:
        with self._lock:
            keep = [r for r in self._receipts if r.ts >= cutoff_ts]
            deleted = len(self._receipts) - len(keep)
            self._receipts = keep
            _RCPT_PRUNED.inc(deleted)
            return deleted


# ---------- SQLite Implementation (production) ----------

# Schema v1 (initial)
_SCHEMA_V1 = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS subjects (
  skey            TEXT PRIMARY KEY,              -- "tenant::user::session"
  tenant          TEXT NOT NULL,
  usr             TEXT NOT NULL,
  sess            TEXT NOT NULL,
  wealth          REAL NOT NULL,
  alpha0          REAL NOT NULL,
  hard_floor      REAL NOT NULL,
  policy_ref      TEXT NOT NULL,
  version         INTEGER NOT NULL,
  updated_ts      REAL NOT NULL,
  meta_json       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  event_id        TEXT PRIMARY KEY,
  skey            TEXT NOT NULL,
  alpha_spent     REAL NOT NULL,
  reward          REAL NOT NULL,
  policy_ref      TEXT NOT NULL,
  ts              REAL NOT NULL,
  meta_json       TEXT NOT NULL,
  FOREIGN KEY(skey) REFERENCES subjects(skey) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS receipts (
  head            TEXT PRIMARY KEY,
  body            TEXT NOT NULL,
  sig             TEXT,
  prev            TEXT,
  ts              REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_ts ON receipts(ts);
"""

# Schema v2 (add anti-fork + perf indexes + single genesis)
_SCHEMA_V2 = """
CREATE INDEX IF NOT EXISTS idx_events_skey_ts ON events(skey, ts);
CREATE UNIQUE INDEX IF NOT EXISTS ux_receipts_prev ON receipts(prev);

-- Allow only a single genesis (prev IS NULL) row in receipts
CREATE TRIGGER IF NOT EXISTS trg_receipts_single_genesis
BEFORE INSERT ON receipts
WHEN NEW.prev IS NULL
BEGIN
  SELECT CASE WHEN (SELECT COUNT(1) FROM receipts WHERE prev IS NULL) > 0
       THEN RAISE(ABORT, 'genesis already exists') END;
END;
"""


class SQLiteLedger(Ledger):
    """
    Durable single-file ledger. Thread-safe via per-thread connection and a coarse process lock
    around write transactions (sufficient for most FastAPI worker setups).

    All metadata persisted here is content-agnostic:
      - forbidden keys are stripped;
      - optional sanitization and whitelist mode mirror logging/receipt behavior;
      - PQ / override / trust_zone / e-process fields are normalized at the storage boundary.
    """

    def __init__(self, path: str = None):
        # default path: $TCD_LEDGER_DB or local file "tcd_ledger.db"
        self._path = path or os.environ.get("TCD_LEDGER_DB", "tcd_ledger.db")
        self._lock = threading.RLock()
        self._local = threading.local()
        # ensure DB exists & migrate
        self._migrate()

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        conn = sqlite3.connect(
            self._path,
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        # helpful (optional):
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute("PRAGMA mmap_size=134217728")  # 128MB
        self._local.conn = conn
        return conn

    def _migrate(self) -> None:
        conn = self._get_conn()
        with self._lock:
            ver = conn.execute("PRAGMA user_version").fetchone()[0]
            if ver == 0:
                conn.executescript(_SCHEMA_V1)
                conn.execute("PRAGMA user_version=1")
                ver = 1
            if ver < 2:
                conn.executescript(_SCHEMA_V2)
                conn.execute("PRAGMA user_version=2")

    # ----- helpers -----

    def _subject_row_to_wr(self, row) -> WealthRecord:
        # row order must match SELECT columns
        (
            skey,
            tenant,
            usr,
            sess,
            wealth,
            alpha0,
            hard_floor,
            policy_ref,
            version,
            updated_ts,
            meta_json,
        ) = row
        return WealthRecord(
            subject=SubjectKey(tenant=tenant, user=usr, session=sess),
            wealth=float(wealth),
            alpha0=float(alpha0),
            hard_floor=float(hard_floor),
            policy_ref=str(policy_ref),
            version=int(version),
            updated_ts=float(updated_ts),
            meta=json.loads(meta_json) if meta_json else {},
        )

    def _get_subject_row(self, conn: sqlite3.Connection, skey: str):
        cur = conn.execute(
            "SELECT skey, tenant, usr, sess, wealth, alpha0, hard_floor, policy_ref, version, updated_ts, meta_json "
            "FROM subjects WHERE skey=?",
            (skey,),
        )
        return cur.fetchone()

    @contextmanager
    def _txn(self):
        t0 = time.perf_counter()
        conn = self._get_conn()
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.execute("COMMIT")
            _TX_LAT.observe(time.perf_counter() - t0)
        except Exception:
            try:
                conn.execute("ROLLBACK")
            except Exception:
                pass
            _TX_LAT.observe(time.perf_counter() - t0)
            raise

    # ----- Ledger API -----

    def ensure_subject(
        self,
        subject: SubjectKey,
        *,
        alpha0: float,
        hard_floor: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> WealthRecord:
        now = time.time()
        conn = self._get_conn()
        skey = subject.as_str()

        if not (math.isfinite(alpha0) and math.isfinite(hard_floor)):
            raise LedgerError("non-finite alpha0/hard_floor")
        if alpha0 < 0.0 or hard_floor < 0.0:
            raise LedgerError("negative alpha0/hard_floor not allowed")

        alpha0_f = float(alpha0)
        hard_floor_f = float(hard_floor)

        meta_sanitized = _sanitize_meta_for_storage(meta)
        meta_json = _meta_to_json(meta_sanitized)
        with self._lock:
            row = self._get_subject_row(conn, skey)
            if row:
                return self._subject_row_to_wr(row)
            conn.execute(
                "INSERT OR IGNORE INTO subjects(skey, tenant, usr, sess, wealth, alpha0, hard_floor, policy_ref, version, updated_ts, meta_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    skey,
                    subject.tenant,
                    subject.user,
                    subject.session,
                    float(alpha0_f),
                    float(alpha0_f),
                    float(hard_floor_f),
                    str(policy_ref),
                    1,
                    now,
                    meta_json,
                ),
            )
            row = self._get_subject_row(conn, skey)
            return self._subject_row_to_wr(row)

    def get_wealth(self, subject: SubjectKey) -> Optional[WealthRecord]:
        conn = self._get_conn()
        row = self._get_subject_row(conn, subject.as_str())
        return self._subject_row_to_wr(row) if row else None

    def apply_event(
        self,
        subject: SubjectKey,
        *,
        event_id: str,
        alpha_spent: float,
        reward: float,
        policy_ref: str,
        meta: Optional[Dict[str, object]] = None,
    ) -> EventApplyResult:
        """
        Atomic transaction:
          - INSERT event (idempotent via PK)
          - If inserted, UPDATE wealth with floor guard
          - Cross-subject reuse of event_id is rejected
        """
        _validate_event_id(event_id)

        if not (math.isfinite(alpha_spent) and math.isfinite(reward)):
            raise LedgerError("non-finite alpha_spent/reward")
        alpha_spent = float(max(0.0, alpha_spent))
        reward = float(max(0.0, reward))

        now = time.time()
        skey = subject.as_str()
        meta_sanitized = _sanitize_meta_for_storage(meta)
        meta_json = _meta_to_json(meta_sanitized)

        with self._lock, self._txn() as conn:
            # ensure subject exists
            row = self._get_subject_row(conn, skey)
            if not row:
                raise LedgerError(
                    "apply_event: subject not found; call ensure_subject first"
                )

            # try insert event
            try:
                conn.execute(
                    "INSERT INTO events(event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json) "
                    "VALUES(?,?,?,?,?,?,?)",
                    (event_id, skey, alpha_spent, reward, str(policy_ref), now, meta_json),
                )
                inserted = True
            except sqlite3.IntegrityError:
                inserted = False

            # cross-subject guard on duplicate id
            if not inserted:
                row2 = conn.execute(
                    "SELECT skey FROM events WHERE event_id=?", (event_id,)
                ).fetchone()
                if row2 and row2[0] != skey:
                    _EVT_CROSS.inc()
                    raise LedgerError("event_id reused across different subject")
                # duplicate on same subject: no change
                wr = self._subject_row_to_wr(self._get_subject_row(conn, skey))
                _EVT_DUP.inc()
                return EventApplyResult(
                    False, float(wr.wealth), float(alpha_spent), now
                )

            # update wealth
            wr = self._subject_row_to_wr(self._get_subject_row(conn, skey))
            if not (math.isfinite(wr.wealth) and math.isfinite(wr.hard_floor)):
                raise LedgerError("non-finite wealth state for subject")

            tentative = wr.wealth - alpha_spent + reward
            if tentative < wr.hard_floor:
                _EVT_FLOOR.inc()
            wealth_after = max(wr.hard_floor, tentative)

            # merge subject meta with new sanitized meta
            merged_meta = dict(wr.meta)
            if meta_sanitized:
                merged_meta.update(meta_sanitized)

            conn.execute(
                "UPDATE subjects SET wealth=?, policy_ref=?, version=version+1, updated_ts=?, meta_json=? "
                "WHERE skey=?",
                (
                    float(wealth_after),
                    str(policy_ref),
                    now,
                    _meta_to_json(merged_meta),
                    skey,
                ),
            )
            _EVT_APPLIED.inc()
            return EventApplyResult(True, float(wealth_after), float(alpha_spent), now)

    def append_receipt(self, rec: ReceiptRecord) -> None:
        _validate_receipt_record(rec)
        conn = self._get_conn()
        with self._lock:
            try:
                conn.execute(
                    "INSERT INTO receipts(head, body, sig, prev, ts) VALUES(?,?,?,?,?)",
                    (
                        str(rec.head),
                        str(rec.body),
                        str(rec.sig or ""),
                        rec.prev,
                        float(rec.ts),
                    ),
                )
                _RCPT_SIZE.observe(
                    len(rec.body.encode("utf-8", errors="ignore"))
                )
                _RCPT_COUNT.inc()
            except sqlite3.IntegrityError as e:
                _RCPT_FAIL.inc()
                # duplicate head or prev -> raise to surface anomaly
                raise LedgerError(
                    f"append_receipt duplicate/fork: {str(e)[:120]}"
                ) from e

    def append_receipt_strict(self, rec: ReceiptRecord) -> None:
        """
        Atomic append with prev=head check to avoid race/fork.
        Also protected by UNIQUE(prev) + single-genesis trigger.
        """
        _validate_receipt_record(rec)
        conn = self._get_conn()
        with self._lock, self._txn() as txn:
            row = txn.execute(
                "SELECT head FROM receipts ORDER BY ts DESC LIMIT 1"
            ).fetchone()
            current = row[0] if row else None
            if current != rec.prev:
                _RCPT_FAIL.inc()
                raise LedgerError("prev mismatch (race or fork)")
            try:
                txn.execute(
                    "INSERT INTO receipts(head, body, sig, prev, ts) VALUES(?,?,?,?,?)",
                    (
                        str(rec.head),
                        str(rec.body),
                        str(rec.sig or ""),
                        rec.prev,
                        float(rec.ts),
                    ),
                )
                _RCPT_SIZE.observe(
                    len(rec.body.encode("utf-8", errors="ignore"))
                )
                _RCPT_COUNT.inc()
            except sqlite3.IntegrityError as e:
                _RCPT_FAIL.inc()
                raise LedgerError(
                    f"append_receipt_strict duplicate/fork: {str(e)[:120]}"
                ) from e

    def chain_head(self) -> Optional[str]:
        conn = self._get_conn()
        row = conn.execute(
            "SELECT head FROM receipts ORDER BY ts DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else None

    def load_chain(self, limit: int = 1000) -> List[ReceiptRecord]:
        conn = self._get_conn()
        cur = conn.execute(
            "SELECT head, body, sig, prev, ts FROM receipts ORDER BY ts ASC LIMIT ?",
            (int(max(1, limit)),),
        )
        out: List[ReceiptRecord] = []
        for head, body, sig, prev, ts in cur.fetchall():
            out.append(
                ReceiptRecord(
                    head=head,
                    body=body,
                    sig=sig,
                    prev=prev,
                    ts=float(ts),
                )
            )
        return out

    # ----- AE / audit helpers -----

    def recompute_wealth(self, subject: SubjectKey) -> Dict[str, float]:
        conn = self._get_conn()
        skey = subject.as_str()
        row = self._get_subject_row(conn, skey)
        if not row:
            raise LedgerError("subject not found")
        wr = self._subject_row_to_wr(row)
        wealth = wr.alpha0
        cur = conn.execute(
            "SELECT alpha_spent, reward FROM events WHERE skey=? ORDER BY ts ASC",
            (skey,),
        )
        for a, r in cur.fetchall():
            wealth = max(
                wr.hard_floor, wealth - float(a) + float(r)
            )
        return {
            "expected": float(wealth),
            "recorded": float(wr.wealth),
            "delta": float(wealth - wr.wealth),
        }

    def export_events(
        self,
        *,
        subject: Optional[SubjectKey] = None,
        ts_from: float = 0.0,
        ts_to: Optional[float] = None,
    ) -> Iterable[Dict[str, Any]]:
        conn = self._get_conn()
        if subject is None:
            q = (
                "SELECT event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json "
                "FROM events WHERE ts>=? {} ORDER BY ts ASC"
            )
            if ts_to is None:
                q = q.format("")
                cur = conn.execute(q, (float(ts_from),))
            else:
                q = q.format("AND ts<?")
                cur = conn.execute(q, (float(ts_from), float(ts_to)))
        else:
            skey = subject.as_str()
            if ts_to is None:
                cur = conn.execute(
                    "SELECT event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json "
                    "FROM events WHERE skey=? AND ts>=? ORDER BY ts ASC",
                    (skey, float(ts_from)),
                )
            else:
                cur = conn.execute(
                    "SELECT event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json "
                    "FROM events WHERE skey=? AND ts>=? AND ts<? ORDER BY ts ASC",
                    (skey, float(ts_from), float(ts_to)),
                )
        for event_id, skey, a, r, pref, ts, meta_json in cur.fetchall():
            yield {
                "event_id": event_id,
                "skey": skey,
                "alpha_spent": float(a),
                "reward": float(r),
                "policy_ref": pref,
                "ts": float(ts),
                "meta": json.loads(meta_json) if meta_json else {},
            }

    def import_events(self, rows: Iterable[Dict[str, Any]]) -> int:
        """
        Idempotent import. Expects rows in export format.
        - subject rows must exist or import fails for that row.
        - cross-subject reuse is rejected (same semantics as apply_event).
        """
        conn = self._get_conn()
        count = 0
        with self._lock:
            for row in rows:
                try:
                    event_id = _validate_event_id(str(row["event_id"]))
                    skey = str(row["skey"])
                    a_raw = float(row["alpha_spent"])
                    r_raw = float(row["reward"])
                    if not (math.isfinite(a_raw) and math.isfinite(r_raw)):
                        raise LedgerError("non-finite alpha_spent/reward in import")
                    a = max(0.0, float(a_raw))
                    r = max(0.0, float(r_raw))

                    pref = str(row.get("policy_ref", "import"))
                    ts_raw = float(row.get("ts", time.time()))
                    ts = ts_raw if math.isfinite(ts_raw) else time.time()

                    meta_sanitized = _sanitize_meta_for_storage(row.get("meta") or {})
                    meta_json = _meta_to_json(meta_sanitized)
                except Exception as e:
                    raise LedgerError(f"bad import row: {e}")

                # subject must exist
                if not self._get_subject_row(conn, skey):
                    raise LedgerError(f"import subject missing: {skey}")

                try:
                    with self._txn() as txn:
                        try:
                            txn.execute(
                                "INSERT INTO events(event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json) "
                                "VALUES(?,?,?,?,?,?,?)",
                                (event_id, skey, a, r, pref, ts, meta_json),
                            )
                        except sqlite3.IntegrityError:
                            # duplicate: verify same subject
                            row2 = txn.execute(
                                "SELECT skey FROM events WHERE event_id=?",
                                (event_id,),
                            ).fetchone()
                            if row2 and row2[0] != skey:
                                _EVT_CROSS.inc()
                                raise LedgerError(
                                    "event_id reused across different subject (import)"
                                )
                            # idempotent duplicate on same subject: skip
                            pass
                    count += 1
                except Exception:
                    # For audit/import tools we keep strict semantics and re-raise.
                    raise
        return count

    def load_chain_page(
        self, page_size: int = 256, cursor_ts: Optional[float] = None
    ) -> Tuple[List[ReceiptRecord], Optional[float]]:
        conn = self._get_conn()
        if cursor_ts is None:
            cur = conn.execute(
                "SELECT head, body, sig, prev, ts FROM receipts ORDER BY ts ASC LIMIT ?",
                (int(max(1, page_size)),),
            )
        else:
            cur = conn.execute(
                "SELECT head, body, sig, prev, ts FROM receipts WHERE ts>? ORDER BY ts ASC LIMIT ?",
                (float(cursor_ts), int(max(1, page_size))),
            )
        out: List[ReceiptRecord] = []
        rows = cur.fetchall()
        for head, body, sig, prev, ts in rows:
            out.append(
                ReceiptRecord(
                    head=head,
                    body=body,
                    sig=sig,
                    prev=prev,
                    ts=float(ts),
                )
            )
        next_cursor = out[-1].ts if out else None
        return (out, next_cursor)

    def prune_receipts_before(self, cutoff_ts: float) -> int:
        conn = self._get_conn()
        with self._lock, self._txn() as txn:
            cur = txn.execute(
                "SELECT COUNT(1) FROM receipts WHERE ts < ?",
                (float(cutoff_ts),),
            )
            n = int(cur.fetchone()[0])
            txn.execute(
                "DELETE FROM receipts WHERE ts < ?",
                (float(cutoff_ts),),
            )
        try:
            conn.execute("PRAGMA optimize")
        except Exception:
            pass
        _RCPT_PRUNED.inc(n)
        return n


# ---------- Helpers (optional) ----------


def stable_subject_hash(
    sk: SubjectKey, *, key: Optional[bytes] = None, out_hex: int = 16
) -> str:
    """
    Stable, optional-HMAC hash for using subject as metric label / privacy-preserving id.

    In production you SHOULD pass a secret key (for example from an environment
    variable) to avoid cross-system linkability.
    """
    s = sk.as_str().encode("utf-8")
    if key:
        h = hmac.new(key, s, hashlib.blake2s).hexdigest()
    else:
        h = hashlib.blake2s(s).hexdigest()
    return h[: max(8, int(out_hex))]