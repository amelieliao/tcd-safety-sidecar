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

Strong L7 → L7+ hardening upgrades (systematic):
  - Fix PII hashing logic (external: default hash-all for tag-like IDs; no more “almost always false”).
  - No silent numeric “clamp-to-0” in external: negative alpha_spent/reward rejected.
    Internal may clamp but MUST emit metrics.
  - Enforce alpha0 >= hard_floor invariant at subject creation.
  - Idempotency strengthened: event_id duplicates must match an event_fingerprint (params+meta digest),
    otherwise treated as an integrity error.
  - policy_ref validated (tag-like, bounded, no unsafe chars); immutable under external profile.
  - Subject meta merge is budgeted after merge (prevents subjects.meta_json unbounded growth).
  - Read-path sanitization: export/read never trusts DB content blindly (legacy rows re-sanitized).
  - Receipt chain upgraded:
      * Optional multi-chain via chain_id (default chain_id preserves legacy behavior).
      * DB constraints are chain-aware: UNIQUE(chain_id, prev), single genesis per chain,
        prev must exist in same chain, no self-loop, no empty prev, anti-tamper (immutable head/body/sig/ts/chain_id).
      * Strict append checks prev==leaf within same DB txn.
      * Leaf ambiguity (fork/multi-leaf) is detected and fail-closed under external profile.
      * Optional receipt head verification: head must equal computed blake2s(chain_id, prev, canonical_json(body), sig)
        under strict mode (external default).
  - Deterministic event replay ordering: ORDER BY ts, event_id (NOT rowid).
  - Avoid fetchall() on unbounded queries; stream rows.
  - Hard caps on paging/limits to reduce DoS blast radius.
  - Domain-separated hashing for PII digests / subject hashes / event fingerprints / receipt heads.

NOTE:
  - This module persists results emitted by controllers; it does NOT compute decisions.
  - Your /diagnose should pass a stable request_id / idempotency key as event_id.
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List, Iterable, Any, Mapping, Set, Literal, Iterator
import json
import os
import sqlite3
import threading
import time
import hmac
import hashlib
import math
import re
import unicodedata
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
    _EVT_APPLIED = Counter("tcd_ledger_event_applied_total", "Applied wealth update events")
    _EVT_DUP = Counter("tcd_ledger_event_duplicate_total", "Duplicate events (idempotent)")
    _EVT_CROSS = Counter("tcd_ledger_event_cross_subject_total", "event_id reused across different subject")
    _EVT_FLOOR = Counter("tcd_ledger_wealth_floor_hit_total", "Wealth updates clamped by hard floor")
    _EVT_CLAMP = Counter("tcd_ledger_event_value_clamped_total", "Event values clamped (internal only)", labelnames=("field",))
    _EVT_MISMATCH = Counter("tcd_ledger_event_idempotency_mismatch_total", "Idempotency mismatch (same event_id, different params)")
    _META_SHRUNK = Counter("tcd_ledger_subject_meta_shrunk_total", "Subject meta shrunk after merge")
    _TX_LAT = Histogram(
        "tcd_ledger_tx_latency_seconds",
        "SQLite transaction latency (seconds)",
        buckets=(0.001, 0.002, 0.005, 0.010, 0.020, 0.050, 0.1, 0.2),
    )
    _RCPT_FAIL = Counter("tcd_receipts_append_fail_total", "Receipt append failures (duplicates/forks/integrity)")
    _RCPT_COUNT = Counter("tcd_receipts_append_total", "Receipt append success")
    _RCPT_SIZE = Histogram("tcd_receipt_body_size_bytes", "Receipt body size (bytes)")
    _RCPT_PRUNED = Counter("tcd_receipts_pruned_total", "Receipts pruned by cutoff")
    _RCPT_HEAD_MISMATCH = Counter("tcd_receipt_head_mismatch_total", "Receipt head mismatch")
    _RCPT_INTEGRITY = Counter("tcd_receipt_chain_integrity_error_total", "Receipt chain integrity errors", labelnames=("reason",))
else:  # pragma: no cover
    _EVT_APPLIED = _NopMetric()
    _EVT_DUP = _NopMetric()
    _EVT_CROSS = _NopMetric()
    _EVT_FLOOR = _NopMetric()
    _EVT_CLAMP = _NopMetric()
    _EVT_MISMATCH = _NopMetric()
    _META_SHRUNK = _NopMetric()
    _TX_LAT = _NopMetric()
    _RCPT_FAIL = _NopMetric()
    _RCPT_COUNT = _NopMetric()
    _RCPT_SIZE = _NopMetric()
    _RCPT_PRUNED = _NopMetric()
    _RCPT_HEAD_MISMATCH = _NopMetric()
    _RCPT_INTEGRITY = _NopMetric()


# ---------- Structured sanitization helpers (shared with logging/verify) ----------

from .utils import (  # noqa: E402
    SanitizeConfig,
    sanitize_metadata_for_receipt,
    blake2s_hex,
)

# ---------------------------------------------------------------------------
# Config snapshot
# ---------------------------------------------------------------------------

Profile = Literal["internal", "external"]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    s = str(raw).strip().lower()
    if s in {"1", "true", "t", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "f", "no", "n", "off"}:
        return False
    return default


def _env_int(name: str, default: int, *, min_v: int, max_v: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
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


def _env_str(name: str, default: str) -> str:
    raw = os.getenv(name)
    if raw is None:
        return default
    return str(raw).strip()


def _parse_key_material(s: str) -> Optional[bytes]:
    """
    Parse secret key material from env:
      - hex (even length) OR
      - base64/url-safe base64 OR
      - raw utf-8 string (last resort)
    """
    if not s:
        return None
    ss = s.strip()
    if not ss:
        return None

    hexd = re.fullmatch(r"[0-9a-fA-F]+", ss)
    if hexd and len(ss) % 2 == 0:
        try:
            return bytes.fromhex(ss)
        except Exception:
            pass

    try:
        import base64

        padded = ss + "=" * ((4 - (len(ss) % 4)) % 4)
        b = base64.urlsafe_b64decode(padded.encode("ascii", errors="strict"))
        if b:
            return b
    except Exception:
        pass

    try:
        return ss.encode("utf-8", errors="strict")
    except Exception:
        return None


# Forbidden keys (content-bearing) — token-based strict scan
_DEFAULT_FORBIDDEN_META_KEYS: Set[str] = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "messages",
    "message",
    "content",
    "raw",
    "body",
    "payload",
    "request",
    "response",
    "headers",
    "header",
    "cookies",
    "cookie",
    "authorization",
    "auth",
    "bearer",
    "api_key",
    "apikey",
    "secret",
    "private_key",
}

# Ledger-level allowed meta keys (schema-like, small)
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

_ALLOWED_TRUST_ZONES: Set[str] = {"internet", "internal", "partner", "admin", "ops"}
_ALLOWED_ROUTE_PROFILES: Set[str] = {"inference", "admin", "control", "metrics", "health"}
_ALLOWED_OVERRIDE_LEVELS: Set[str] = {"none", "break_glass", "maintenance"}
_ALLOWED_PQ_SCHEMES: Set[str] = {"", "dilithium2", "dilithium3", "falcon", "sphincs+"}

# Patterns (tag-like)
_TAGLIKE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_TAGLIKE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_POLICY_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_PREHASH_RE = re.compile(r"^(?:[0-9a-fA-F]{16,128}|[A-Za-z0-9_-]{16,128})$")  # hex or base64url-ish
_HASHED_TAG_PREFIX_RE = re.compile(r"^(tenant|user|session|override_actor)-h-[0-9a-f]{16}$")

# Key tokenization (camelCase aware, sequence match)
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_ALPHA_DIGIT_BOUNDARY_RE = re.compile(r"(?<=[a-zA-Z])(?=\d)|(?<=\d)(?=[a-zA-Z])")
_TOKEN_SPLIT_RE = re.compile(r"[^a-z0-9]+")

# ASCII control including DEL
_ASCII_CTRL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")


def _key_tokens(s: str) -> Tuple[str, ...]:
    if not s:
        return ()
    t = _CAMEL_BOUNDARY_RE.sub("_", s)
    t = _ALPHA_DIGIT_BOUNDARY_RE.sub("_", t)
    t = t.strip().lower()
    toks = [x for x in _TOKEN_SPLIT_RE.split(t) if x]
    return tuple(toks)


@dataclass(frozen=True, slots=True)
class LedgerConfig:
    profile: Profile

    # meta governance
    sanitize_meta: bool
    strip_pii: bool
    meta_whitelist_mode: bool
    forbid_meta_keys: bool
    forbid_meta_keys_strict: bool
    forbidden_keys_exact_lower: Set[str]
    forbidden_key_token_seqs: Tuple[Tuple[str, ...], ...]

    # PII handling for tag-like meta fields
    hash_pii_tags: bool
    pii_hmac_key: Optional[bytes]
    pii_hmac_min_bytes: int
    external_hash_all_pii_tags: bool

    # subject governance
    strict_subject_tags: bool
    subject_part_max_bytes: int
    forbid_subject_delim: bool

    # policy_ref governance
    max_policy_ref_bytes: int
    strict_policy_ref_taglike: bool
    immutable_policy_ref_external: bool

    # event id/value governance
    max_event_id_len: int
    strict_event_id_taglike: bool
    reject_negative_event_values_external: bool

    # receipt governance
    default_chain_id: str
    max_chain_id_bytes: int
    strict_chain_id_taglike: bool

    max_receipt_body_bytes: int
    max_receipt_head_len: int
    max_receipt_sig_len: int
    strict_receipt_head_hex64: bool
    validate_receipt_json: bool
    receipt_json_taglike_strings_external: bool
    verify_receipt_head: bool
    fail_closed_on_receipt_integrity_external: bool

    # receipt chain governance
    require_strict_receipt_append: bool
    enforce_monotonic_receipt_ts: bool

    # receipt json budgets
    max_receipt_json_depth: int
    max_receipt_json_nodes: int
    max_receipt_json_string_bytes: int
    max_receipt_json_int_bits: int

    # meta size budgets
    max_meta_items: int
    max_meta_key_bytes: int
    max_meta_string_bytes: int
    max_meta_json_bytes: int

    # API caps
    max_page_size: int
    max_chain_load: int
    max_export_rows: int  # soft cap for external safety (0=unbounded internal)

    # sqlite behavior
    sqlite_timeout_s: float
    sqlite_synchronous: Literal["NORMAL", "FULL"]
    sqlite_journal_mode: Literal["WAL"]
    sqlite_wal_autocheckpoint: int
    sqlite_journal_size_limit: int

    # verbosity (avoid leaking identifiers into errors by default)
    verbose_errors: bool

    @staticmethod
    def from_env() -> "LedgerConfig":
        prof_raw = _env_str("TCD_LEDGER_PROFILE", "internal").lower()
        profile: Profile = "external" if prof_raw == "external" else "internal"

        if profile == "external":
            sanitize_meta_default = True
            strip_pii_default = True
            meta_whitelist_default = True
            strict_subject_tags_default = True
            strict_event_id_default = True
            strict_policy_ref_default = True
            immutable_policy_ref_default = True
            reject_negative_event_values_external_default = True

            strict_chain_id_default = True

            strict_receipt_head_hex_default = True
            validate_receipt_json_default = True
            receipt_json_taglike_strings_external_default = True
            verify_receipt_head_default = True
            fail_closed_receipts_default = True

            require_strict_receipt_append_default = True
            enforce_monotonic_ts_default = True

            max_meta_json_default = 2048
            max_meta_str_default = 128
            max_policy_ref_bytes_default = 128
            max_export_rows_default = 50_000

            sqlite_timeout_default = 30.0
            sqlite_synchronous_default: Literal["NORMAL", "FULL"] = "FULL"
        else:
            sanitize_meta_default = True
            strip_pii_default = False
            meta_whitelist_default = False
            strict_subject_tags_default = False
            strict_event_id_default = False
            strict_policy_ref_default = False
            immutable_policy_ref_default = False
            reject_negative_event_values_external_default = True  # still reject negatives if profile switches

            strict_chain_id_default = False

            strict_receipt_head_hex_default = False
            validate_receipt_json_default = False
            receipt_json_taglike_strings_external_default = False
            verify_receipt_head_default = False
            fail_closed_receipts_default = False

            require_strict_receipt_append_default = False
            enforce_monotonic_ts_default = True

            max_meta_json_default = 8192
            max_meta_str_default = 512
            max_policy_ref_bytes_default = 512
            max_export_rows_default = 0  # unbounded internal by default

            sqlite_timeout_default = 30.0
            sqlite_synchronous_default = "NORMAL"

        sanitize_meta = _env_bool("TCD_LEDGER_SANITIZE_META", sanitize_meta_default)
        strip_pii = _env_bool("TCD_LEDGER_STRIP_PII", strip_pii_default)
        meta_whitelist_mode = _env_bool("TCD_LEDGER_META_WHITELIST", meta_whitelist_default)

        forbid_meta_keys = _env_bool("TCD_LEDGER_FORBID_META_KEYS", True)
        forbid_meta_keys_strict = _env_bool("TCD_LEDGER_FORBID_META_KEYS_STRICT", True)

        hash_pii_tags = _env_bool("TCD_LEDGER_HASH_PII_TAGS", True)
        external_hash_all_pii_tags = _env_bool("TCD_LEDGER_EXTERNAL_HASH_ALL_PII_TAGS", True)
        pii_key_raw = _env_str("TCD_LEDGER_PII_HMAC_KEY", "")
        pii_hmac_key = _parse_key_material(pii_key_raw)
        pii_hmac_min_bytes = _env_int("TCD_LEDGER_PII_HMAC_MIN_BYTES", 16, min_v=8, max_v=4096)

        strict_subject_tags = _env_bool("TCD_LEDGER_STRICT_SUBJECT_TAGS", strict_subject_tags_default)
        subject_part_max_bytes = _env_int("TCD_LEDGER_SUBJECT_PART_MAX_BYTES", 128, min_v=16, max_v=4096)
        forbid_subject_delim = _env_bool("TCD_LEDGER_FORBID_SUBJECT_DELIM", True)

        max_policy_ref_bytes = _env_int(
            "TCD_LEDGER_MAX_POLICY_REF_BYTES", max_policy_ref_bytes_default, min_v=32, max_v=4096
        )
        strict_policy_ref_taglike = _env_bool("TCD_LEDGER_STRICT_POLICY_REF_TAGLIKE", strict_policy_ref_default)
        immutable_policy_ref_external = _env_bool(
            "TCD_LEDGER_IMMUTABLE_POLICY_REF_EXTERNAL", immutable_policy_ref_default
        )

        max_event_id_len = _env_int("TCD_LEDGER_MAX_EVENT_ID_LEN", 256, min_v=16, max_v=4096)
        strict_event_id_taglike = _env_bool("TCD_LEDGER_STRICT_EVENT_ID_TAGLIKE", strict_event_id_default)
        reject_negative_event_values_external = _env_bool(
            "TCD_LEDGER_REJECT_NEGATIVE_EVENT_VALUES_EXTERNAL", reject_negative_event_values_external_default
        )

        default_chain_id = _env_str("TCD_LEDGER_DEFAULT_CHAIN_ID", "")
        max_chain_id_bytes = _env_int("TCD_LEDGER_MAX_CHAIN_ID_BYTES", 128, min_v=16, max_v=4096)
        strict_chain_id_taglike = _env_bool("TCD_LEDGER_STRICT_CHAIN_ID_TAGLIKE", strict_chain_id_default)

        max_receipt_body_bytes = _env_int(
            "TCD_LEDGER_MAX_RECEIPT_BODY_BYTES", 16_384, min_v=1024, max_v=1_000_000
        )
        max_receipt_head_len = _env_int("TCD_LEDGER_MAX_RECEIPT_HEAD_LEN", 256, min_v=32, max_v=4096)
        max_receipt_sig_len = _env_int("TCD_LEDGER_MAX_RECEIPT_SIG_LEN", 4096, min_v=0, max_v=1_000_000)
        strict_receipt_head_hex64 = _env_bool(
            "TCD_LEDGER_STRICT_RECEIPT_HEAD_HEX64", strict_receipt_head_hex_default
        )
        validate_receipt_json = _env_bool("TCD_LEDGER_VALIDATE_RECEIPT_JSON", validate_receipt_json_default)
        receipt_json_taglike_strings_external = _env_bool(
            "TCD_LEDGER_RECEIPT_JSON_TAGLIKE_STRINGS_EXTERNAL", receipt_json_taglike_strings_external_default
        )
        verify_receipt_head = _env_bool("TCD_LEDGER_VERIFY_RECEIPT_HEAD", verify_receipt_head_default)
        fail_closed_on_receipt_integrity_external = _env_bool(
            "TCD_LEDGER_FAIL_CLOSED_RECEIPT_INTEGRITY_EXTERNAL", fail_closed_receipts_default
        )

        require_strict_receipt_append = _env_bool(
            "TCD_LEDGER_REQUIRE_STRICT_RECEIPT_APPEND", require_strict_receipt_append_default
        )
        enforce_monotonic_receipt_ts = _env_bool(
            "TCD_LEDGER_ENFORCE_MONOTONIC_RECEIPT_TS", enforce_monotonic_ts_default
        )

        max_receipt_json_depth = _env_int("TCD_LEDGER_MAX_RECEIPT_JSON_DEPTH", 8, min_v=4, max_v=64)
        max_receipt_json_nodes = _env_int("TCD_LEDGER_MAX_RECEIPT_JSON_NODES", 4096, min_v=256, max_v=1_000_000)
        max_receipt_json_string_bytes = _env_int(
            "TCD_LEDGER_MAX_RECEIPT_JSON_STRING_BYTES", 256 if profile == "external" else 1024, min_v=32, max_v=1_000_000
        )
        max_receipt_json_int_bits = _env_int("TCD_LEDGER_MAX_RECEIPT_JSON_INT_BITS", 256, min_v=64, max_v=4096)

        max_meta_items = _env_int("TCD_LEDGER_MAX_META_ITEMS", 64, min_v=8, max_v=4096)
        max_meta_key_bytes = _env_int("TCD_LEDGER_MAX_META_KEY_BYTES", 64, min_v=16, max_v=4096)
        max_meta_string_bytes = _env_int(
            "TCD_LEDGER_MAX_META_STRING_BYTES", max_meta_str_default, min_v=32, max_v=1_000_000
        )
        max_meta_json_bytes = _env_int(
            "TCD_LEDGER_MAX_META_JSON_BYTES", max_meta_json_default, min_v=256, max_v=5_000_000
        )

        max_page_size = _env_int("TCD_LEDGER_MAX_PAGE_SIZE", 2048, min_v=64, max_v=50_000)
        max_chain_load = _env_int("TCD_LEDGER_MAX_CHAIN_LOAD", 4096, min_v=256, max_v=200_000)
        max_export_rows = _env_int("TCD_LEDGER_MAX_EXPORT_ROWS", max_export_rows_default, min_v=0, max_v=5_000_000)

        sqlite_timeout_s = _env_float("TCD_LEDGER_SQLITE_TIMEOUT_S", sqlite_timeout_default, min_v=1.0, max_v=300.0)
        sqlite_synchronous = _env_str("TCD_LEDGER_SQLITE_SYNCHRONOUS", sqlite_synchronous_default).upper()
        if sqlite_synchronous not in {"NORMAL", "FULL"}:
            sqlite_synchronous = sqlite_synchronous_default

        sqlite_journal_mode: Literal["WAL"] = "WAL"
        sqlite_wal_autocheckpoint = _env_int("TCD_LEDGER_SQLITE_WAL_AUTOCHECKPOINT", 1000, min_v=1, max_v=1_000_000)
        sqlite_journal_size_limit = _env_int(
            "TCD_LEDGER_SQLITE_JOURNAL_SIZE_LIMIT", 64 * 1024 * 1024, min_v=1 * 1024 * 1024, max_v=4 * 1024 * 1024 * 1024
        )

        verbose_errors = _env_bool("TCD_LEDGER_VERBOSE_ERRORS", False)

        forbidden_exact = {k.strip().lower() for k in _DEFAULT_FORBIDDEN_META_KEYS if k}
        token_seqs: list[Tuple[str, ...]] = []
        for fk in _DEFAULT_FORBIDDEN_META_KEYS:
            toks = _key_tokens(fk)
            if toks:
                token_seqs.append(toks)
        token_seqs = list({ts: None for ts in token_seqs}.keys())

        return LedgerConfig(
            profile=profile,
            sanitize_meta=sanitize_meta,
            strip_pii=strip_pii,
            meta_whitelist_mode=meta_whitelist_mode,
            forbid_meta_keys=forbid_meta_keys,
            forbid_meta_keys_strict=forbid_meta_keys_strict,
            forbidden_keys_exact_lower=forbidden_exact,
            forbidden_key_token_seqs=tuple(token_seqs),
            hash_pii_tags=hash_pii_tags,
            pii_hmac_key=pii_hmac_key,
            pii_hmac_min_bytes=pii_hmac_min_bytes,
            external_hash_all_pii_tags=external_hash_all_pii_tags,
            strict_subject_tags=strict_subject_tags,
            subject_part_max_bytes=subject_part_max_bytes,
            forbid_subject_delim=forbid_subject_delim,
            max_policy_ref_bytes=max_policy_ref_bytes,
            strict_policy_ref_taglike=strict_policy_ref_taglike,
            immutable_policy_ref_external=immutable_policy_ref_external,
            max_event_id_len=max_event_id_len,
            strict_event_id_taglike=strict_event_id_taglike,
            reject_negative_event_values_external=reject_negative_event_values_external,
            default_chain_id=default_chain_id,
            max_chain_id_bytes=max_chain_id_bytes,
            strict_chain_id_taglike=strict_chain_id_taglike,
            max_receipt_body_bytes=max_receipt_body_bytes,
            max_receipt_head_len=max_receipt_head_len,
            max_receipt_sig_len=max_receipt_sig_len,
            strict_receipt_head_hex64=strict_receipt_head_hex64,
            validate_receipt_json=validate_receipt_json,
            receipt_json_taglike_strings_external=receipt_json_taglike_strings_external,
            verify_receipt_head=verify_receipt_head,
            fail_closed_on_receipt_integrity_external=fail_closed_on_receipt_integrity_external,
            require_strict_receipt_append=require_strict_receipt_append,
            enforce_monotonic_receipt_ts=enforce_monotonic_receipt_ts,
            max_receipt_json_depth=max_receipt_json_depth,
            max_receipt_json_nodes=max_receipt_json_nodes,
            max_receipt_json_string_bytes=max_receipt_json_string_bytes,
            max_receipt_json_int_bits=max_receipt_json_int_bits,
            max_meta_items=max_meta_items,
            max_meta_key_bytes=max_meta_key_bytes,
            max_meta_string_bytes=max_meta_string_bytes,
            max_meta_json_bytes=max_meta_json_bytes,
            max_page_size=max_page_size,
            max_chain_load=max_chain_load,
            max_export_rows=max_export_rows,
            sqlite_timeout_s=sqlite_timeout_s,
            sqlite_synchronous=sqlite_synchronous,  # type: ignore[arg-type]
            sqlite_journal_mode=sqlite_journal_mode,
            sqlite_wal_autocheckpoint=sqlite_wal_autocheckpoint,
            sqlite_journal_size_limit=sqlite_journal_size_limit,
            verbose_errors=verbose_errors,
        )


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class LedgerError(RuntimeError):
    """
    Ledger error.

    Keep messages low-information; never include raw identifiers/values.
    You may attach a low-cardinality .code for safe APIs/metrics.
    """

    def __init__(self, message: str = "ledger error", *, code: str = "LEDGER_ERROR"):
        super().__init__(message)
        self.code = code


# ---------------------------------------------------------------------------
# Unsafe char guards
# ---------------------------------------------------------------------------


def _has_surrogate(s: str) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in s)


def _encode_utf8_strict(s: str) -> bytes:
    if _has_surrogate(s):
        raise LedgerError("invalid unicode", code="INVALID_UNICODE")
    return s.encode("utf-8", errors="strict")


def _has_unicode_invisible_or_control(s: str) -> bool:
    # Reject Unicode categories Cc (control) and Cf (format/invisible)
    for ch in s:
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf"):
            return True
    return False


def _reject_unsafe_text(s: str, *, allow_whitespace: bool) -> None:
    if _ASCII_CTRL_RE.search(s):
        raise LedgerError("control chars not allowed", code="UNSAFE_CHARS")
    if _has_unicode_invisible_or_control(s):
        raise LedgerError("invisible/control unicode not allowed", code="UNSAFE_CHARS")
    if not allow_whitespace and any(ch.isspace() for ch in s):
        raise LedgerError("whitespace not allowed", code="UNSAFE_CHARS")


def _is_forbidden_key_name(key: str, cfg: LedgerConfig) -> bool:
    if not cfg.forbid_meta_keys:
        return False
    k = (key or "").strip()
    if not k:
        return False

    kl = k.lower()
    if kl in cfg.forbidden_keys_exact_lower:
        return True

    if not cfg.forbid_meta_keys_strict:
        return False

    toks = _key_tokens(k)
    if not toks:
        return False

    for seq in cfg.forbidden_key_token_seqs:
        if not seq:
            continue
        if len(seq) == 1:
            if seq[0] in toks:
                return True
            continue
        n = len(seq)
        for i in range(0, len(toks) - n + 1):
            if toks[i : i + n] == seq:
                return True
    return False


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _validate_subject_part(name: str, value: str, cfg: LedgerConfig) -> str:
    if not isinstance(value, str):
        raise LedgerError(f"{name} must be string", code="INVALID_SUBJECT")
    v = value.strip()
    if not v:
        raise LedgerError(f"{name} must be non-empty", code="INVALID_SUBJECT")
    if _has_surrogate(v):
        raise LedgerError(f"{name} invalid unicode", code="INVALID_SUBJECT")
    _reject_unsafe_text(v, allow_whitespace=False)

    vb = _encode_utf8_strict(v)
    if len(vb) > cfg.subject_part_max_bytes:
        raise LedgerError(f"{name} too long", code="INVALID_SUBJECT")

    if cfg.forbid_subject_delim and "::" in v:
        raise LedgerError(f"{name} contains forbidden delimiter", code="INVALID_SUBJECT")

    if cfg.strict_subject_tags and not _TAGLIKE_KEY_RE.fullmatch(v):
        raise LedgerError(f"{name} not tag-like", code="INVALID_SUBJECT")

    return v


def _validate_policy_ref(policy_ref: Any, cfg: LedgerConfig) -> str:
    if not isinstance(policy_ref, str):
        raise LedgerError("policy_ref must be string", code="INVALID_POLICY_REF")
    p = policy_ref.strip()
    if not p:
        raise LedgerError("policy_ref must be non-empty", code="INVALID_POLICY_REF")
    if _has_surrogate(p):
        raise LedgerError("policy_ref invalid unicode", code="INVALID_POLICY_REF")
    _reject_unsafe_text(p, allow_whitespace=False)
    pb = _encode_utf8_strict(p)
    if len(pb) > cfg.max_policy_ref_bytes:
        raise LedgerError("policy_ref too long", code="INVALID_POLICY_REF")
    if cfg.strict_policy_ref_taglike and not _POLICY_REF_RE.fullmatch(p):
        raise LedgerError("policy_ref not tag-like", code="INVALID_POLICY_REF")
    return p


def _validate_event_id(event_id: Any, cfg: LedgerConfig) -> str:
    if not isinstance(event_id, str):
        raise LedgerError("event_id must be string", code="INVALID_EVENT_ID")
    eid = event_id.strip()
    if not eid:
        raise LedgerError("event_id must be non-empty string", code="INVALID_EVENT_ID")
    if len(eid) > cfg.max_event_id_len:
        raise LedgerError("event_id too long", code="INVALID_EVENT_ID")
    if _has_surrogate(eid):
        raise LedgerError("event_id invalid unicode", code="INVALID_EVENT_ID")
    _reject_unsafe_text(eid, allow_whitespace=False)
    if cfg.strict_event_id_taglike and not _TAGLIKE_RE.fullmatch(eid):
        raise LedgerError("event_id not tag-like", code="INVALID_EVENT_ID")
    return eid


def _validate_chain_id(chain_id: Optional[str], cfg: LedgerConfig) -> str:
    cid = (chain_id if isinstance(chain_id, str) else "") or cfg.default_chain_id
    cid = cid.strip()
    if _has_surrogate(cid):
        raise LedgerError("chain_id invalid unicode", code="INVALID_CHAIN_ID")
    _reject_unsafe_text(cid, allow_whitespace=False)
    cb = _encode_utf8_strict(cid)
    if len(cb) > cfg.max_chain_id_bytes:
        raise LedgerError("chain_id too long", code="INVALID_CHAIN_ID")
    if cfg.strict_chain_id_taglike and cid and not _TAGLIKE_RE.fullmatch(cid):
        raise LedgerError("chain_id not tag-like", code="INVALID_CHAIN_ID")
    return cid


def _validate_subject_numbers(alpha0: float, hard_floor: float) -> Tuple[float, float]:
    if not (math.isfinite(alpha0) and math.isfinite(hard_floor)):
        raise LedgerError("non-finite alpha0/hard_floor", code="INVALID_SUBJECT")
    if alpha0 < 0.0 or hard_floor < 0.0:
        raise LedgerError("negative alpha0/hard_floor not allowed", code="INVALID_SUBJECT")
    if alpha0 < hard_floor:
        raise LedgerError("alpha0 must be >= hard_floor", code="INVALID_SUBJECT")
    return float(alpha0), float(hard_floor)


def _validate_event_values(alpha_spent: Any, reward: Any, cfg: LedgerConfig) -> Tuple[float, float, bool]:
    # accept int/float only here (callers should pre-parse for import)
    if not isinstance(alpha_spent, (int, float)) or isinstance(alpha_spent, bool):
        raise LedgerError("alpha_spent must be number", code="INVALID_EVENT_VALUE")
    if not isinstance(reward, (int, float)) or isinstance(reward, bool):
        raise LedgerError("reward must be number", code="INVALID_EVENT_VALUE")

    a = float(alpha_spent)
    r = float(reward)
    if not (math.isfinite(a) and math.isfinite(r)):
        raise LedgerError("non-finite alpha_spent/reward", code="INVALID_EVENT_VALUE")

    clamped = False
    if cfg.profile == "external" and cfg.reject_negative_event_values_external:
        if a < 0.0 or r < 0.0:
            raise LedgerError("negative alpha_spent/reward rejected", code="INVALID_EVENT_VALUE")
    else:
        if a < 0.0:
            a = 0.0
            clamped = True
            _EVT_CLAMP.labels(field="alpha_spent").inc()
        if r < 0.0:
            r = 0.0
            clamped = True
            _EVT_CLAMP.labels(field="reward").inc()

    # Keep semantics: alpha_spent/reward cannot be negative.
    if a < 0.0:
        a = 0.0
    if r < 0.0:
        r = 0.0

    return float(a), float(r), clamped


# ---------------------------------------------------------------------------
# PII pseudonymization for tag-like meta fields
# ---------------------------------------------------------------------------

_PII_TAG_KEYS: Tuple[str, ...] = ("tenant", "user", "session", "override_actor")
_PII_PLACEHOLDERS: Set[str] = {"", "*", "unknown", "unk", "anon", "anonymous", "na", "n/a", "none"}


def _is_prehashed_identifier(v: str) -> bool:
    vv = v.strip()
    if not vv:
        return False
    if _HASHED_TAG_PREFIX_RE.fullmatch(vv):
        return True
    # If looks like already-hashed token (hex/base64url-ish), treat as prehashed to avoid double-hash.
    if _PREHASH_RE.fullmatch(vv):
        # exclude very short trivially-guessable tokens
        if len(vv) >= 16:
            return True
    return False


def _pii_digest(value: str, *, cfg: LedgerConfig, domain: bytes) -> str:
    """
    Return a short stable digest for PII-like tag values, domain-separated.

    Prefer keyed HMAC-BLAKE2s if key is present and sufficiently long.
    If no key is configured:
      - internal profile: allow unkeyed blake2s (linkable) as fallback.
      - external profile: fail-closed (drop).
    """
    v = value.strip()
    b = _encode_utf8_strict(v)
    msg = domain + b"|"+ b

    if cfg.pii_hmac_key is not None and len(cfg.pii_hmac_key) >= cfg.pii_hmac_min_bytes:
        mac = hmac.new(cfg.pii_hmac_key, msg, hashlib.blake2s).hexdigest()
        return mac[:16]

    if cfg.profile == "external":
        raise LedgerError("pii hashing requires configured HMAC key in external profile", code="PII_KEY_MISSING")

    return hashlib.blake2s(msg).hexdigest()[:16]


def _hash_pii_tag_value(key: str, raw_value: str, cfg: LedgerConfig) -> Optional[str]:
    """
    External: default hash-all for PII tag keys unless placeholder or already prehashed.
    Internal: hash for high-card / PII-looking values; allow low-card placeholders and prehashed.
    """
    v = raw_value.strip()
    if v.lower() in _PII_PLACEHOLDERS:
        return v  # keep placeholder as-is

    if _is_prehashed_identifier(v):
        return v  # don't double hash

    if cfg.profile == "external" and cfg.external_hash_all_pii_tags:
        # Always hash in external unless placeholder/prehashed
        digest = _pii_digest(v, cfg=cfg, domain=b"TCD|ledger|pii|tag|v1|")
        return f"{key}-h-{digest}"

    # internal: heuristic: hash if looks like PII OR high-card (length)
    # NOTE: since meta is content-agnostic, we bias toward hashing rather than keeping.
    looks_like_email = "@" in v
    looks_like_name = (" " in v) or ("\u3000" in v)
    high_card = len(v) >= 24
    if looks_like_email or looks_like_name or high_card:
        try:
            digest = _pii_digest(v, cfg=cfg, domain=b"TCD|ledger|pii|tag|v1|")
            return f"{key}-h-{digest}"
        except Exception:
            return None

    # allow small low-card identifiers in internal if taglike
    return v


# ---------------------------------------------------------------------------
# Metadata sanitization (content-agnostic; strict JSON)
# ---------------------------------------------------------------------------


def _coerce_bool(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    if isinstance(v, int) and v in (0, 1):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in {"1", "true", "t", "yes", "y", "on"}:
            return True
        if s in {"0", "false", "f", "no", "n", "off"}:
            return False
    return None


def _coerce_float_finite(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        f = float(v)
        if math.isfinite(f):
            return f
        return None
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return None
        # block weird values early
        if len(s) > 64:
            return None
        try:
            f = float(s)
        except Exception:
            return None
        return f if math.isfinite(f) else None
    return None


def _guard_meta_key(k: str, cfg: LedgerConfig) -> str:
    if not isinstance(k, str):
        raise LedgerError("meta key must be str", code="INVALID_META")
    ks = k.strip()
    if not ks:
        raise LedgerError("empty meta key", code="INVALID_META")
    if _has_surrogate(ks):
        raise LedgerError("invalid meta key unicode", code="INVALID_META")
    _reject_unsafe_text(ks, allow_whitespace=False)
    kb = _encode_utf8_strict(ks)
    if len(kb) > cfg.max_meta_key_bytes:
        raise LedgerError("meta key too long", code="INVALID_META")
    if not _TAGLIKE_KEY_RE.fullmatch(ks):
        raise LedgerError("meta key not tag-like", code="INVALID_META")
    if _is_forbidden_key_name(ks, cfg):
        raise LedgerError("forbidden meta key", code="FORBIDDEN_META")
    return ks.lower()


def _guard_meta_string_generic(v: str, cfg: LedgerConfig) -> str:
    vs = v.strip()
    if _has_surrogate(vs):
        raise LedgerError("invalid meta string unicode", code="INVALID_META")
    _reject_unsafe_text(vs, allow_whitespace=False)
    vb = _encode_utf8_strict(vs)
    if len(vb) > cfg.max_meta_string_bytes:
        raise LedgerError("meta string too long", code="INVALID_META")
    # external: content-agnostic => tag-like only
    if cfg.profile == "external" and not _TAGLIKE_RE.fullmatch(vs):
        raise LedgerError("meta string not tag-like", code="INVALID_META")
    return vs


def _meta_to_json(meta: Dict[str, object], cfg: LedgerConfig) -> str:
    try:
        return json.dumps(meta, separators=(",", ":"), ensure_ascii=False, sort_keys=True, allow_nan=False)
    except Exception:
        return "{}" if cfg.profile == "external" else "{}"


def _enforce_meta_budget(meta: Dict[str, object], cfg: LedgerConfig) -> Dict[str, object]:
    """
    Enforce JSON byte budget deterministically.
    Strategy:
      - If within budget: keep.
      - If too big: keep a fixed stable subset first, then add remaining keys in sorted order
        until budget satisfied.
    """
    if not meta:
        return {}

    j = _meta_to_json(meta, cfg)
    if len(j.encode("utf-8", errors="strict")) <= cfg.max_meta_json_bytes:
        return meta

    # Stable keys to keep (low-card, audit-friendly)
    stable_keep = (
        "policy_ref",
        "chain_id",
        "route_profile",
        "trust_zone",
        "pq_scheme",
        "pq_required",
        "pq_ok",
        "pq_chain_id",
        "override_applied",
        "override_level",
        "lockdown_level",
        "model_id",
        "e_value",
        "a_alloc",
        "score",
    )

    out: Dict[str, object] = {}
    for k in stable_keep:
        if k in meta:
            out[k] = meta[k]

    # Fill more keys deterministically
    for k in sorted(meta.keys()):
        if k in out:
            continue
        out[k] = meta[k]
        j2 = _meta_to_json(out, cfg)
        if len(j2.encode("utf-8", errors="strict")) > cfg.max_meta_json_bytes:
            out.pop(k, None)
            break

    _META_SHRUNK.inc()
    return out


def _sanitize_meta_for_storage(meta: Optional[Mapping[str, object]], cfg: LedgerConfig) -> Dict[str, object]:
    """
    Content-agnostic meta sanitizer:
      - str keys only; key must be tag-like and not forbidden.
      - scalar-only values (None/bool/int/float/str), finite floats.
      - external: strings must be tag-like EXCEPT PII tag keys which are always hashed (then tag-like).
      - whitelist optional.
      - hard caps: items + key/value length + JSON size (enforced after merge too).
    """
    if not meta:
        return {}

    if not isinstance(meta, Mapping):
        raise LedgerError("meta must be a mapping", code="INVALID_META")

    out: Dict[str, object] = {}
    n = 0

    for k, v in meta.items():
        n += 1
        if n > cfg.max_meta_items:
            break
        if not isinstance(k, str):
            continue

        try:
            key = _guard_meta_key(k, cfg)
        except Exception:
            continue

        if cfg.meta_whitelist_mode and key not in _ALLOWED_LEDGER_META_KEYS:
            continue

        # PII tag keys: accept broader string then hash/drop
        if key in _PII_TAG_KEYS:
            if isinstance(v, str):
                # allow any non-whitespace string within size; hashing will produce tag-like result
                try:
                    raw = v.strip()
                    if _has_surrogate(raw):
                        continue
                    _reject_unsafe_text(raw, allow_whitespace=False)
                    if len(_encode_utf8_strict(raw)) > cfg.max_meta_string_bytes:
                        continue
                    hv = _hash_pii_tag_value(key, raw, cfg)
                    if hv is None:
                        continue
                    out[key] = hv
                except Exception:
                    continue
            continue

        # Known bool fields
        if key in ("override_applied", "pq_required", "pq_ok"):
            b = _coerce_bool(v)
            if b is None:
                continue
            out[key] = bool(b)
            continue

        # Known numeric fields
        if key in ("e_value", "a_alloc", "score"):
            f = _coerce_float_finite(v)
            if f is None:
                continue
            if key == "e_value":
                if f < 0.0:
                    continue
                out[key] = float(f)
            elif key == "a_alloc":
                out[key] = float(max(0.0, min(1.0, f)))
            else:
                out[key] = float(max(0.0, min(1.0, f)))
            continue

        # enums
        if key == "trust_zone":
            if isinstance(v, str) and v in _ALLOWED_TRUST_ZONES:
                out[key] = v
            continue
        if key == "route_profile":
            if isinstance(v, str) and v in _ALLOWED_ROUTE_PROFILES:
                out[key] = v
            continue
        if key == "override_level":
            if isinstance(v, str) and v in _ALLOWED_OVERRIDE_LEVELS:
                out[key] = v
            continue
        if key == "pq_scheme":
            if isinstance(v, str) and v in _ALLOWED_PQ_SCHEMES:
                out[key] = v
            continue

        # generic scalar handling
        if v is None:
            out[key] = None
            continue
        if isinstance(v, bool):
            out[key] = bool(v)
            continue
        if isinstance(v, int) and not isinstance(v, bool):
            if v.bit_length() > 256:
                continue
            out[key] = int(v)
            continue
        if isinstance(v, float):
            if not math.isfinite(v):
                continue
            out[key] = float(v)
            continue
        if isinstance(v, str):
            try:
                sv = _guard_meta_string_generic(v, cfg)
            except Exception:
                continue
            out[key] = sv
            continue

        continue

    if not out:
        return {}

    if cfg.sanitize_meta:
        try:
            scfg = SanitizeConfig(
                sanitize_nan=True,
                prune_large=True,
                strip_pii=cfg.strip_pii,
                forbid_keys=tuple(_DEFAULT_FORBIDDEN_META_KEYS),
            )
            sanitized = sanitize_metadata_for_receipt(out, config=scfg)
            if isinstance(sanitized, Mapping):
                out = dict(sanitized)  # type: ignore[assignment]
        except Exception:
            pass

    out = _enforce_meta_budget(out, cfg)
    return out


def _sanitize_meta_from_json(meta_json: Optional[str], cfg: LedgerConfig) -> Dict[str, object]:
    if not meta_json:
        return {}
    try:
        obj = json.loads(meta_json)
    except Exception:
        return {}
    if not isinstance(obj, dict):
        return {}
    try:
        return _sanitize_meta_for_storage(obj, cfg)
    except Exception:
        return {}


# ---------------------------------------------------------------------------
# JSON strict parsing for receipts (reject NaN/Inf and giant ints)
# ---------------------------------------------------------------------------


def _parse_float_strict(s: str) -> float:
    f = float(s)
    if not math.isfinite(f):
        raise ValueError("non-finite float")
    return f


def _parse_int_strict(s: str, cfg: LedgerConfig) -> int:
    i = int(s, 10)
    if i.bit_length() > cfg.max_receipt_json_int_bits:
        raise ValueError("int too large")
    return i


def _parse_json_strict(s: str, cfg: LedgerConfig) -> Any:
    def _reject_const(_x: str) -> Any:
        raise ValueError("non-finite JSON constant")

    return json.loads(
        s,
        parse_constant=_reject_const,
        parse_float=_parse_float_strict,
        parse_int=lambda x: _parse_int_strict(x, cfg),
    )


def _validate_receipt_json_tree(obj: Any, cfg: LedgerConfig, *, depth: int = 0, nodes: int = 0) -> int:
    nodes += 1
    if nodes > cfg.max_receipt_json_nodes:
        raise LedgerError("receipt json too large", code="RECEIPT_JSON_TOO_LARGE")
    if depth > cfg.max_receipt_json_depth:
        raise LedgerError("receipt json too deep", code="RECEIPT_JSON_TOO_DEEP")

    if isinstance(obj, dict):
        if len(obj) > 1024:
            raise LedgerError("receipt json too wide", code="RECEIPT_JSON_TOO_LARGE")
        for k, v in obj.items():
            if not isinstance(k, str):
                raise LedgerError("receipt json keys must be strings", code="RECEIPT_JSON_INVALID")
            if _is_forbidden_key_name(k, cfg):
                raise LedgerError("receipt contains forbidden key", code="RECEIPT_JSON_FORBIDDEN")
            if cfg.profile == "external":
                if not _TAGLIKE_KEY_RE.fullmatch(k):
                    raise LedgerError("receipt json key not tag-like", code="RECEIPT_JSON_INVALID")
            nodes = _validate_receipt_json_tree(v, cfg, depth=depth + 1, nodes=nodes)
        return nodes

    if isinstance(obj, list):
        if len(obj) > 2048:
            raise LedgerError("receipt json list too large", code="RECEIPT_JSON_TOO_LARGE")
        for it in obj:
            nodes = _validate_receipt_json_tree(it, cfg, depth=depth + 1, nodes=nodes)
        return nodes

    if obj is None or isinstance(obj, bool):
        return nodes

    if isinstance(obj, int) and not isinstance(obj, bool):
        if obj.bit_length() > cfg.max_receipt_json_int_bits:
            raise LedgerError("receipt json int too large", code="RECEIPT_JSON_INVALID")
        return nodes

    if isinstance(obj, float):
        if not math.isfinite(obj):
            raise LedgerError("receipt json float non-finite", code="RECEIPT_JSON_INVALID")
        return nodes

    if isinstance(obj, str):
        if _has_surrogate(obj):
            raise LedgerError("receipt json string invalid unicode", code="RECEIPT_JSON_INVALID")
        _reject_unsafe_text(obj, allow_whitespace=False)
        b = _encode_utf8_strict(obj)
        if len(b) > cfg.max_receipt_json_string_bytes:
            raise LedgerError("receipt json string too long", code="RECEIPT_JSON_INVALID")
        if cfg.profile == "external" and cfg.receipt_json_taglike_strings_external:
            if not _TAGLIKE_RE.fullmatch(obj):
                raise LedgerError("receipt json string not tag-like", code="RECEIPT_JSON_INVALID")
        return nodes

    raise LedgerError("receipt json invalid type", code="RECEIPT_JSON_INVALID")


# ---------------------------------------------------------------------------
# Receipt head computation (domain-separated)
# ---------------------------------------------------------------------------


def _canonicalize_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False, sort_keys=True, allow_nan=False)


def _compute_receipt_head(chain_id: str, prev: Optional[str], body_canon: str, sig: Optional[str]) -> str:
    # domain separation
    domain = b"TCD|ledger|receipt|v1|"
    cid_b = _encode_utf8_strict(chain_id)
    prev_b = _encode_utf8_strict(prev or "")
    body_b = _encode_utf8_strict(body_canon)
    sig_b = _encode_utf8_strict(sig or "")
    h = hashlib.blake2s(domain + cid_b + b"\0" + prev_b + b"\0" + body_b + b"\0" + sig_b)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubjectKey:
    tenant: str
    user: str
    session: str

    def as_tuple(self) -> Tuple[str, str, str]:
        return (self.tenant, self.user, self.session)

    def as_str(self) -> str:
        # canonical stable key used in DB; must remain injective
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
    applied: bool
    wealth_after: float
    alpha_spent: float
    updated_ts: float


@dataclass
class ReceiptRecord:
    head: str
    body: str
    sig: Optional[str]
    prev: Optional[str]
    ts: float
    chain_id: str = ""  # optional multi-chain support; default preserves legacy behavior


# ---------------------------------------------------------------------------
# Receipt structural validation + normalization
# ---------------------------------------------------------------------------


def _validate_receipt_record(rec: "ReceiptRecord", cfg: LedgerConfig) -> "ReceiptRecord":
    chain_id = _validate_chain_id(rec.chain_id, cfg)

    if not isinstance(rec.head, str) or not rec.head.strip():
        raise LedgerError("receipt head must be non-empty string", code="RECEIPT_INVALID")
    head = rec.head.strip()
    if len(head) > cfg.max_receipt_head_len:
        raise LedgerError("receipt head too long", code="RECEIPT_INVALID")
    if _has_surrogate(head):
        raise LedgerError("receipt head invalid unicode", code="RECEIPT_INVALID")
    _reject_unsafe_text(head, allow_whitespace=False)
    if cfg.strict_receipt_head_hex64:
        if not _HEX64_RE.fullmatch(head):
            raise LedgerError("receipt head must be 64-char lowercase hex in strict mode", code="RECEIPT_INVALID")
    else:
        if not _TAGLIKE_RE.fullmatch(head):
            raise LedgerError("receipt head not tag-like", code="RECEIPT_INVALID")

    prev = rec.prev
    if prev is not None:
        if not isinstance(prev, str):
            raise LedgerError("receipt prev must be None or string", code="RECEIPT_INVALID")
        prev = prev.strip()
        if prev == "":
            prev = None
        else:
            if len(prev) > cfg.max_receipt_head_len:
                raise LedgerError("receipt prev too long", code="RECEIPT_INVALID")
            if _has_surrogate(prev):
                raise LedgerError("receipt prev invalid unicode", code="RECEIPT_INVALID")
            _reject_unsafe_text(prev, allow_whitespace=False)
            if cfg.strict_receipt_head_hex64:
                if not _HEX64_RE.fullmatch(prev):
                    raise LedgerError("receipt prev must be 64-char lowercase hex in strict mode", code="RECEIPT_INVALID")
            else:
                if not _TAGLIKE_RE.fullmatch(prev):
                    raise LedgerError("receipt prev not tag-like", code="RECEIPT_INVALID")

    if prev is not None and prev == head:
        raise LedgerError("receipt head must not equal prev (self-loop)", code="RECEIPT_INVALID")

    sig = rec.sig
    if sig is not None:
        if not isinstance(sig, str):
            raise LedgerError("receipt sig must be None or string", code="RECEIPT_INVALID")
        sig = sig.strip()
        if sig == "":
            sig = None
        else:
            if len(sig) > cfg.max_receipt_sig_len:
                raise LedgerError("receipt sig too long", code="RECEIPT_INVALID")
            if _has_surrogate(sig):
                raise LedgerError("receipt sig invalid unicode", code="RECEIPT_INVALID")
            if _ASCII_CTRL_RE.search(sig) or _has_unicode_invisible_or_control(sig):
                raise LedgerError("receipt sig contains unsafe chars", code="RECEIPT_INVALID")

    if not isinstance(rec.body, str):
        raise LedgerError("receipt body must be string", code="RECEIPT_INVALID")
    body = rec.body
    if _has_surrogate(body):
        raise LedgerError("receipt body invalid unicode", code="RECEIPT_INVALID")

    # If validate_receipt_json OR verify_receipt_head, require strict JSON and canonicalize
    body_canon = body
    if cfg.validate_receipt_json or cfg.verify_receipt_head:
        try:
            obj = _parse_json_strict(body, cfg)
            _validate_receipt_json_tree(obj, cfg, depth=0, nodes=0)
            body_canon = _canonicalize_json(obj)
        except LedgerError:
            raise
        except Exception as e:
            raise LedgerError("receipt body must be strict JSON", code="RECEIPT_JSON_INVALID") from e

    body_bytes = body_canon.encode("utf-8", errors="strict")
    if len(body_bytes) > cfg.max_receipt_body_bytes:
        raise LedgerError("receipt body too large for ledger", code="RECEIPT_INVALID")

    # Optional receipt head verification (strict L7+ mode)
    if cfg.verify_receipt_head and cfg.strict_receipt_head_hex64:
        expected = _compute_receipt_head(chain_id, prev, body_canon, sig)
        if head != expected:
            _RCPT_HEAD_MISMATCH.inc()
            raise LedgerError("receipt head mismatch", code="RECEIPT_HEAD_MISMATCH")

    # ts sanity (note: NOT included in head computation; we may adjust for monotonicity)
    ts = float(rec.ts)
    if not math.isfinite(ts) or ts <= 0.0:
        ts = time.time()

    return ReceiptRecord(head=head, body=body_canon, sig=sig, prev=prev, ts=ts, chain_id=chain_id)


# ---------------------------------------------------------------------------
# Base Interface
# ---------------------------------------------------------------------------


class Ledger:
    """
    Abstract ledger API (storage only).

    Backward-compat notes:
      - ReceiptRecord now has optional chain_id; default chain_id preserves legacy single-chain behavior.
    """

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

    def append_receipt(self, rec: ReceiptRecord) -> None:
        raise NotImplementedError

    def append_receipt_strict(self, rec: ReceiptRecord) -> None:
        self.append_receipt(rec)

    def chain_head(self) -> Optional[str]:
        raise NotImplementedError

    def load_chain(self, limit: int = 1000) -> List[ReceiptRecord]:
        raise NotImplementedError

    def recompute_wealth(self, subject: SubjectKey) -> Dict[str, float]:
        raise NotImplementedError

    def export_events(
        self,
        *,
        subject: Optional[SubjectKey] = None,
        ts_from: float = 0.0,
        ts_to: Optional[float] = None,
    ) -> Iterable[Dict[str, Any]]:
        raise NotImplementedError

    def import_events(self, rows: Iterable[Dict[str, Any]]) -> int:
        raise NotImplementedError

    def load_chain_page(
        self, page_size: int = 256, cursor_ts: Optional[float] = None
    ) -> Tuple[List[ReceiptRecord], Optional[float]]:
        raise NotImplementedError

    def prune_receipts_before(self, cutoff_ts: float) -> int:
        raise NotImplementedError

    # --- safe wrappers (optional) ---

    def ensure_subject_safe(self, *args, **kwargs) -> Tuple[bool, Optional[WealthRecord], str]:
        try:
            return (True, self.ensure_subject(*args, **kwargs), "OK")
        except LedgerError as e:
            return (False, None, getattr(e, "code", "LEDGER_ERROR"))
        except Exception:
            return (False, None, "INTERNAL_ERROR")

    def apply_event_safe(self, *args, **kwargs) -> Tuple[bool, Optional[EventApplyResult], str]:
        try:
            return (True, self.apply_event(*args, **kwargs), "OK")
        except LedgerError as e:
            return (False, None, getattr(e, "code", "LEDGER_ERROR"))
        except Exception:
            return (False, None, "INTERNAL_ERROR")

    def append_receipt_safe(self, *args, **kwargs) -> Tuple[bool, str]:
        try:
            self.append_receipt(*args, **kwargs)
            return (True, "OK")
        except LedgerError as e:
            return (False, getattr(e, "code", "LEDGER_ERROR"))
        except Exception:
            return (False, "INTERNAL_ERROR")


# ---------------------------------------------------------------------------
# In-Memory Implementation (tests / dev)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _EventRow:
    event_id: str
    skey: str
    alpha_spent: float
    reward: float
    policy_ref: str
    ts: float
    meta_json: str
    fingerprint: str


def _fp_event(skey: str, alpha_spent: float, reward: float, policy_ref: str, meta_json: str) -> str:
    # domain-separated, stable representation (use 17g round-trip safe format)
    domain = b"TCD|ledger|event|fp|v1|"
    payload = (
        skey
        + "\n"
        + format(float(alpha_spent), ".17g")
        + "\n"
        + format(float(reward), ".17g")
        + "\n"
        + policy_ref
        + "\n"
        + meta_json
    )
    b = payload.encode("utf-8", errors="strict")
    return hashlib.blake2s(domain + b).hexdigest()


class InMemoryLedger(Ledger):
    def __init__(self, *, cfg: Optional[LedgerConfig] = None):
        self._cfg = cfg or LedgerConfig.from_env()
        self._w: Dict[str, WealthRecord] = {}
        self._events_by_id: Dict[str, _EventRow] = {}
        self._events_by_skey: Dict[str, List[_EventRow]] = {}
        self._receipts_by_chain: Dict[str, List[ReceiptRecord]] = {}
        self._receipt_heads_by_chain: Dict[str, Set[str]] = {}
        self._lock = threading.RLock()

    def _norm_subject(self, subject: SubjectKey) -> SubjectKey:
        t = _validate_subject_part("tenant", subject.tenant, self._cfg)
        u = _validate_subject_part("user", subject.user, self._cfg)
        s = _validate_subject_part("session", subject.session, self._cfg)
        return SubjectKey(tenant=t, user=u, session=s)

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
        subject = self._norm_subject(subject)
        skey = subject.as_str()

        alpha0_f, hard_floor_f = _validate_subject_numbers(float(alpha0), float(hard_floor))
        pref = _validate_policy_ref(policy_ref, self._cfg)
        meta_sanitized = _sanitize_meta_for_storage(meta or {}, self._cfg)

        with self._lock:
            wr = self._w.get(skey)
            if wr is None:
                wr = WealthRecord(
                    subject=subject,
                    wealth=alpha0_f,  # alpha0 >= hard_floor enforced
                    alpha0=alpha0_f,
                    hard_floor=hard_floor_f,
                    policy_ref=pref,
                    version=1,
                    updated_ts=now,
                    meta=dict(meta_sanitized),
                )
                self._w[skey] = wr
                self._events_by_skey.setdefault(skey, [])
                return wr

            if self._cfg.profile == "external":
                if float(wr.alpha0) != float(alpha0_f) or float(wr.hard_floor) != float(hard_floor_f):
                    raise LedgerError("ensure_subject parameter mismatch", code="SUBJECT_MISMATCH")
                if self._cfg.immutable_policy_ref_external and wr.policy_ref != pref:
                    raise LedgerError("policy_ref mismatch for subject", code="POLICY_MISMATCH")
            return wr

    def get_wealth(self, subject: SubjectKey) -> Optional[WealthRecord]:
        subject = self._norm_subject(subject)
        with self._lock:
            wr = self._w.get(subject.as_str())
            if not wr:
                return None
            # read-path sanitize (legacy safety)
            wr.meta = _enforce_meta_budget(_sanitize_meta_for_storage(wr.meta or {}, self._cfg), self._cfg)
            return wr

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
        subject = self._norm_subject(subject)
        skey = subject.as_str()

        eid = _validate_event_id(event_id, self._cfg)
        pref = _validate_policy_ref(policy_ref, self._cfg)
        a, r, _clamped = _validate_event_values(alpha_spent, reward, self._cfg)

        meta_sanitized = _sanitize_meta_for_storage(meta or {}, self._cfg)
        meta_json = _meta_to_json(meta_sanitized, self._cfg)
        fp = _fp_event(skey, a, r, pref, meta_json)

        with self._lock:
            wr = self._w.get(skey)
            if wr is None:
                raise LedgerError("subject not found", code="SUBJECT_MISSING")

            # enforce policy immutability for external
            if self._cfg.profile == "external" and self._cfg.immutable_policy_ref_external and wr.policy_ref != pref:
                raise LedgerError("policy_ref mismatch", code="POLICY_MISMATCH")

            # per-subject monotonic time
            now = time.time()
            ts = now if now > float(wr.updated_ts) else float(wr.updated_ts) + 1e-6

            # cross-subject reuse / idempotency
            ex = self._events_by_id.get(eid)
            if ex is not None:
                if ex.skey != skey:
                    _EVT_CROSS.inc()
                    raise LedgerError("event_id reused across different subject", code="EVENT_CROSS_SUBJECT")
                if ex.fingerprint != fp:
                    _EVT_MISMATCH.inc()
                    raise LedgerError("event_id params mismatch", code="EVENT_IDEMPOTENCY_MISMATCH")
                _EVT_DUP.inc()
                return EventApplyResult(False, float(wr.wealth), float(ex.alpha_spent), float(wr.updated_ts))

            tentative = float(wr.wealth) - a + r
            if tentative < float(wr.hard_floor):
                _EVT_FLOOR.inc()
            wealth_after = max(float(wr.hard_floor), tentative)

            wr.wealth = float(wealth_after)
            wr.updated_ts = float(ts)
            wr.version += 1
            # in L7+, subject policy_ref is stable under external; under internal we allow update
            if self._cfg.profile != "external":
                wr.policy_ref = pref

            merged = dict(wr.meta or {})
            if meta_sanitized:
                merged.update(meta_sanitized)
            wr.meta = _enforce_meta_budget(merged, self._cfg)

            er = _EventRow(
                event_id=eid,
                skey=skey,
                alpha_spent=float(a),
                reward=float(r),
                policy_ref=pref,
                ts=float(ts),
                meta_json=meta_json,
                fingerprint=fp,
            )
            self._events_by_id[eid] = er
            self._events_by_skey.setdefault(skey, []).append(er)
            _EVT_APPLIED.inc()
            return EventApplyResult(True, float(wealth_after), float(a), float(ts))

    def _chain_leaf(self, chain_id: str) -> Optional[str]:
        rows = self._receipts_by_chain.get(chain_id, [])
        if not rows:
            return None
        # strict in-memory is always linear, leaf is last
        return rows[-1].head

    def append_receipt(self, rec: ReceiptRecord) -> None:
        r = _validate_receipt_record(rec, self._cfg)
        chain_id = r.chain_id

        with self._lock:
            rows = self._receipts_by_chain.setdefault(chain_id, [])
            heads = self._receipt_heads_by_chain.setdefault(chain_id, set())

            current = rows[-1].head if rows else None
            if current != r.prev:
                _RCPT_FAIL.inc()
                raise LedgerError("receipt prev pointer mismatch", code="RECEIPT_PREV_MISMATCH")

            if r.head in heads:
                _RCPT_FAIL.inc()
                raise LedgerError("duplicate receipt head", code="RECEIPT_DUPLICATE")

            # monotonic ts
            if self._cfg.enforce_monotonic_receipt_ts and rows:
                last_ts = float(rows[-1].ts)
                if r.ts <= last_ts:
                    r = ReceiptRecord(head=r.head, body=r.body, sig=r.sig, prev=r.prev, ts=last_ts + 1e-6, chain_id=chain_id)

            rows.append(r)
            heads.add(r.head)

            _RCPT_SIZE.observe(len(r.body.encode("utf-8", errors="strict")))
            _RCPT_COUNT.inc()

    def append_receipt_strict(self, rec: ReceiptRecord) -> None:
        self.append_receipt(rec)

    def chain_head(self) -> Optional[str]:
        chain_id = self._cfg.default_chain_id
        with self._lock:
            return self._chain_leaf(chain_id)

    def load_chain(self, limit: int = 1000) -> List[ReceiptRecord]:
        chain_id = self._cfg.default_chain_id
        lim = int(limit)
        if lim <= 0:
            lim = self._cfg.max_chain_load
        lim = min(lim, self._cfg.max_chain_load)

        with self._lock:
            rows = self._receipts_by_chain.get(chain_id, [])
            return list(rows[-lim:]) if lim else list(rows)

    def recompute_wealth(self, subject: SubjectKey) -> Dict[str, float]:
        subject = self._norm_subject(subject)
        skey = subject.as_str()
        with self._lock:
            wr = self._w.get(skey)
            if not wr:
                raise LedgerError("subject not found", code="SUBJECT_MISSING")
            wealth = float(wr.alpha0)
            evs = sorted(self._events_by_skey.get(skey, []), key=lambda e: (e.ts, e.event_id))
            for e in evs:
                wealth = max(float(wr.hard_floor), wealth - float(e.alpha_spent) + float(e.reward))
            return {"expected": float(wealth), "recorded": float(wr.wealth), "delta": float(wealth - wr.wealth)}

    def export_events(
        self,
        *,
        subject: Optional[SubjectKey] = None,
        ts_from: float = 0.0,
        ts_to: Optional[float] = None,
    ) -> Iterable[Dict[str, Any]]:
        ts_from_f = float(ts_from) if math.isfinite(float(ts_from)) else 0.0
        ts_to_f = float(ts_to) if (ts_to is not None and math.isfinite(float(ts_to))) else None

        with self._lock:
            if subject is None:
                all_events = list(self._events_by_id.values())
            else:
                skey = self._norm_subject(subject).as_str()
                all_events = list(self._events_by_skey.get(skey, []))

        all_events.sort(key=lambda e: (e.ts, e.event_id))
        emitted = 0
        for e in all_events:
            if e.ts < ts_from_f:
                continue
            if ts_to_f is not None and e.ts >= ts_to_f:
                continue
            emitted += 1
            if self._cfg.profile == "external" and self._cfg.max_export_rows and emitted > self._cfg.max_export_rows:
                break
            meta = _sanitize_meta_from_json(e.meta_json, self._cfg)
            yield {
                "event_id": e.event_id,
                "skey": e.skey,
                "alpha_spent": float(e.alpha_spent),
                "reward": float(e.reward),
                "policy_ref": e.policy_ref,
                "ts": float(e.ts),
                "meta": meta,
                "fingerprint": e.fingerprint,
            }

    def import_events(self, rows: Iterable[Dict[str, Any]]) -> int:
        """
        Strict import (idempotent):
          - requires JSON-basic types only.
          - subject must exist.
          - event_id duplicates must match fingerprint, else reject.
          - DOES NOT mutate wealth (use recompute_wealth audit tool if needed).
        """
        count = 0
        with self._lock:
            for row in rows:
                if not isinstance(row, Mapping):
                    raise LedgerError("bad import row", code="IMPORT_INVALID")

                event_id = row.get("event_id")
                skey = row.get("skey")
                if not isinstance(event_id, str) or not isinstance(skey, str):
                    raise LedgerError("bad import row types", code="IMPORT_INVALID")
                eid = _validate_event_id(event_id, self._cfg)
                skey_s = skey.strip()
                _reject_unsafe_text(skey_s, allow_whitespace=False)
                if len(skey_s) > 1024:
                    raise LedgerError("bad skey", code="IMPORT_INVALID")
                if skey_s not in self._w:
                    raise LedgerError("import subject missing", code="IMPORT_SUBJECT_MISSING")

                a_raw = row.get("alpha_spent")
                r_raw = row.get("reward")
                if not isinstance(a_raw, (int, float)) or isinstance(a_raw, bool):
                    raise LedgerError("bad alpha_spent", code="IMPORT_INVALID")
                if not isinstance(r_raw, (int, float)) or isinstance(r_raw, bool):
                    raise LedgerError("bad reward", code="IMPORT_INVALID")
                a, r, _ = _validate_event_values(a_raw, r_raw, self._cfg)

                pref_raw = row.get("policy_ref", "import")
                pref = _validate_policy_ref(pref_raw, self._cfg)

                ts_raw = row.get("ts", time.time())
                if not isinstance(ts_raw, (int, float)) or isinstance(ts_raw, bool):
                    raise LedgerError("bad ts", code="IMPORT_INVALID")
                ts = float(ts_raw)
                if not math.isfinite(ts) or ts <= 0:
                    ts = time.time()

                meta_obj = row.get("meta") or {}
                if not isinstance(meta_obj, Mapping):
                    meta_obj = {}
                meta_s = _sanitize_meta_for_storage(meta_obj, self._cfg)
                meta_json = _meta_to_json(meta_s, self._cfg)

                fp = row.get("fingerprint")
                if isinstance(fp, str) and fp.strip():
                    fp_s = fp.strip()
                else:
                    fp_s = _fp_event(skey_s, a, r, pref, meta_json)

                ex = self._events_by_id.get(eid)
                if ex is not None:
                    if ex.skey != skey_s:
                        _EVT_CROSS.inc()
                        raise LedgerError("event_id cross-subject (import)", code="EVENT_CROSS_SUBJECT")
                    if ex.fingerprint != fp_s:
                        _EVT_MISMATCH.inc()
                        raise LedgerError("event_id mismatch (import)", code="EVENT_IDEMPOTENCY_MISMATCH")
                    count += 1
                    continue

                er = _EventRow(
                    event_id=eid,
                    skey=skey_s,
                    alpha_spent=float(a),
                    reward=float(r),
                    policy_ref=pref,
                    ts=float(ts),
                    meta_json=meta_json,
                    fingerprint=fp_s,
                )
                self._events_by_id[eid] = er
                self._events_by_skey.setdefault(skey_s, []).append(er)
                count += 1
        return count

    def load_chain_page(self, page_size: int = 256, cursor_ts: Optional[float] = None) -> Tuple[List[ReceiptRecord], Optional[float]]:
        chain_id = self._cfg.default_chain_id
        n = int(max(1, page_size))
        n = min(n, self._cfg.max_page_size)

        with self._lock:
            rows = self._receipts_by_chain.get(chain_id, [])
            if cursor_ts is None:
                out = rows[:n]
            else:
                c = float(cursor_ts)
                out = [r for r in rows if float(r.ts) > c][:n]
            next_cursor = out[-1].ts if out and (len(out) == n) else None
            return (list(out), next_cursor)

    def prune_receipts_before(self, cutoff_ts: float) -> int:
        chain_id = self._cfg.default_chain_id
        cutoff = float(cutoff_ts)
        if not math.isfinite(cutoff) or cutoff <= 0:
            return 0

        with self._lock:
            rows = self._receipts_by_chain.get(chain_id, [])
            keep = [r for r in rows if r.ts >= cutoff]
            deleted = len(rows) - len(keep)
            if keep and deleted > 0:
                first = keep[0]
                keep[0] = ReceiptRecord(head=first.head, body=first.body, sig=first.sig, prev=None, ts=first.ts, chain_id=chain_id)

            self._receipts_by_chain[chain_id] = keep
            self._receipt_heads_by_chain[chain_id] = {r.head for r in keep}

            _RCPT_PRUNED.inc(deleted)
            return deleted


# ---------------------------------------------------------------------------
# SQLite Implementation (production)
# ---------------------------------------------------------------------------

_SCHEMA_V1 = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS subjects (
  skey            TEXT PRIMARY KEY,
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

_SCHEMA_V2 = """
CREATE INDEX IF NOT EXISTS idx_events_skey_ts ON events(skey, ts);
CREATE UNIQUE INDEX IF NOT EXISTS ux_receipts_prev ON receipts(prev);

CREATE TRIGGER IF NOT EXISTS trg_receipts_single_genesis
BEFORE INSERT ON receipts
WHEN NEW.prev IS NULL
BEGIN
  SELECT CASE WHEN (SELECT COUNT(1) FROM receipts WHERE prev IS NULL) > 0
       THEN RAISE(ABORT, 'genesis already exists') END;
END;
"""

_SCHEMA_V3 = """
CREATE INDEX IF NOT EXISTS idx_events_skey_ts_rowid ON events(skey, ts, rowid);

CREATE TRIGGER IF NOT EXISTS trg_receipts_prev_not_empty
BEFORE INSERT ON receipts
WHEN NEW.prev = ''
BEGIN
  SELECT RAISE(ABORT, 'prev must be NULL or non-empty');
END;

CREATE TRIGGER IF NOT EXISTS trg_receipts_no_self_loop
BEFORE INSERT ON receipts
WHEN NEW.prev IS NOT NULL AND NEW.prev = NEW.head
BEGIN
  SELECT RAISE(ABORT, 'head must not equal prev');
END;

CREATE TRIGGER IF NOT EXISTS trg_receipts_prev_must_exist
BEFORE INSERT ON receipts
WHEN NEW.prev IS NOT NULL
BEGIN
  SELECT CASE WHEN (SELECT COUNT(1) FROM receipts WHERE head = NEW.prev) = 0
       THEN RAISE(ABORT, 'prev does not exist') END;
END;

CREATE TRIGGER IF NOT EXISTS trg_receipts_single_genesis_update
BEFORE UPDATE OF prev ON receipts
WHEN NEW.prev IS NULL AND OLD.prev IS NOT NULL
BEGIN
  SELECT CASE WHEN (SELECT COUNT(1) FROM receipts WHERE prev IS NULL) > 0
       THEN RAISE(ABORT, 'genesis already exists') END;
END;

CREATE INDEX IF NOT EXISTS idx_receipts_prev_head ON receipts(prev, head);
"""

# Schema v4: L7+ event fingerprint + chain-aware receipts + anti-tamper
_SCHEMA_V4 = """
-- events: idempotency fingerprint
ALTER TABLE events ADD COLUMN fingerprint TEXT NOT NULL DEFAULT '';

-- receipts: chain_id for multi-chain isolation (default preserves legacy chain)
ALTER TABLE receipts ADD COLUMN chain_id TEXT NOT NULL DEFAULT '';

-- receipts: replace UNIQUE(prev) with UNIQUE(chain_id, prev)
DROP INDEX IF EXISTS ux_receipts_prev;
CREATE UNIQUE INDEX IF NOT EXISTS ux_receipts_chain_prev ON receipts(chain_id, prev);

-- deterministic event ordering index (ts, event_id)
CREATE INDEX IF NOT EXISTS idx_events_skey_ts_eventid ON events(skey, ts, event_id);

-- drop legacy triggers (recreate as chain-aware)
DROP TRIGGER IF EXISTS trg_receipts_single_genesis;
DROP TRIGGER IF EXISTS trg_receipts_prev_not_empty;
DROP TRIGGER IF EXISTS trg_receipts_no_self_loop;
DROP TRIGGER IF EXISTS trg_receipts_prev_must_exist;
DROP TRIGGER IF EXISTS trg_receipts_single_genesis_update;

-- chain-aware genesis (single per chain_id)
CREATE TRIGGER IF NOT EXISTS trg_receipts_single_genesis_chain
BEFORE INSERT ON receipts
WHEN NEW.prev IS NULL
BEGIN
  SELECT CASE WHEN (SELECT COUNT(1) FROM receipts WHERE chain_id = NEW.chain_id AND prev IS NULL) > 0
       THEN RAISE(ABORT, 'genesis already exists for chain') END;
END;

-- prev cannot be empty string
CREATE TRIGGER IF NOT EXISTS trg_receipts_prev_not_empty_chain
BEFORE INSERT ON receipts
WHEN NEW.prev = ''
BEGIN
  SELECT RAISE(ABORT, 'prev must be NULL or non-empty');
END;

-- no self-loop
CREATE TRIGGER IF NOT EXISTS trg_receipts_no_self_loop_chain
BEFORE INSERT ON receipts
WHEN NEW.prev IS NOT NULL AND NEW.prev = NEW.head
BEGIN
  SELECT RAISE(ABORT, 'head must not equal prev');
END;

-- prev must exist in same chain
CREATE TRIGGER IF NOT EXISTS trg_receipts_prev_must_exist_chain
BEFORE INSERT ON receipts
WHEN NEW.prev IS NOT NULL
BEGIN
  SELECT CASE WHEN (SELECT COUNT(1) FROM receipts WHERE chain_id = NEW.chain_id AND head = NEW.prev) = 0
       THEN RAISE(ABORT, 'prev does not exist in chain') END;
END;

-- allow only update prev from NOT NULL -> NULL (checkpoint rewrite) and keep single genesis per chain
CREATE TRIGGER IF NOT EXISTS trg_receipts_prev_update_restricted_chain
BEFORE UPDATE OF prev ON receipts
WHEN NOT (NEW.prev IS NULL AND OLD.prev IS NOT NULL)
BEGIN
  SELECT RAISE(ABORT, 'prev is immutable (except checkpoint to NULL)');
END;

CREATE TRIGGER IF NOT EXISTS trg_receipts_single_genesis_update_chain
BEFORE UPDATE OF prev ON receipts
WHEN NEW.prev IS NULL AND OLD.prev IS NOT NULL
BEGIN
  SELECT CASE WHEN (SELECT COUNT(1) FROM receipts WHERE chain_id = NEW.chain_id AND prev IS NULL) > 0
       THEN RAISE(ABORT, 'genesis already exists for chain') END;
END;

-- anti-tamper: immutable fields
CREATE TRIGGER IF NOT EXISTS trg_receipts_head_immutable
BEFORE UPDATE OF head ON receipts
BEGIN
  SELECT RAISE(ABORT, 'head is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_receipts_body_immutable
BEFORE UPDATE OF body ON receipts
BEGIN
  SELECT RAISE(ABORT, 'body is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_receipts_sig_immutable
BEFORE UPDATE OF sig ON receipts
BEGIN
  SELECT RAISE(ABORT, 'sig is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_receipts_ts_immutable
BEFORE UPDATE OF ts ON receipts
BEGIN
  SELECT RAISE(ABORT, 'ts is immutable');
END;

CREATE TRIGGER IF NOT EXISTS trg_receipts_chainid_immutable
BEFORE UPDATE OF chain_id ON receipts
BEGIN
  SELECT RAISE(ABORT, 'chain_id is immutable');
END;

-- indexes for leaf queries per chain
CREATE INDEX IF NOT EXISTS idx_receipts_chain_prev_head ON receipts(chain_id, prev, head);
CREATE INDEX IF NOT EXISTS idx_receipts_chain_ts ON receipts(chain_id, ts);
"""


class SQLiteLedger(Ledger):
    """
    Durable single-file ledger.

    Thread safety:
      - per-thread sqlite connection + a coarse process lock around write txns.
    Cross-process:
      - SQLite serializes writers via WAL + BEGIN IMMEDIATE.

    Content-agnostic storage:
      - meta is sanitized at boundary (no content-bearing keys/values),
      - receipts are size-bounded and optionally JSON-validated + head-verifiable.
    """

    def __init__(self, path: str = None, *, cfg: Optional[LedgerConfig] = None):
        self._cfg = cfg or LedgerConfig.from_env()
        self._path = path or os.environ.get("TCD_LEDGER_DB", "tcd_ledger.db")
        self._lock = threading.RLock()
        self._local = threading.local()

        self._ensure_db_path_hygiene()
        self._migrate()

    # ----- path hygiene (L7) -----

    def _ensure_db_path_hygiene(self) -> None:
        p = str(self._path)
        if self._cfg.profile == "external":
            low = p.lower()
            if ":memory:" in low or low.startswith("file:"):
                raise LedgerError("unsafe sqlite path", code="DB_PATH_UNSAFE")

        # ensure directory exists
        d = os.path.dirname(os.path.abspath(p)) or "."
        try:
            os.makedirs(d, exist_ok=True)
        except Exception:
            pass

        # create file with 0600 if missing
        if not os.path.exists(p):
            try:
                fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            except FileExistsError:
                pass
            except Exception:
                pass

        # external: reject overly-permissive perms best-effort
        if self._cfg.profile == "external":
            try:
                st = os.stat(p)
                mode = st.st_mode & 0o777
                if (mode & 0o077) != 0:
                    raise LedgerError("sqlite db permissions too broad", code="DB_PERMS_UNSAFE")
            except LedgerError:
                raise
            except Exception:
                pass

    # ----- connection -----

    def _get_conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            return conn
        conn = sqlite3.connect(
            self._path,
            timeout=float(self._cfg.sqlite_timeout_s),
            isolation_level=None,
            check_same_thread=False,
        )
        conn.execute(f"PRAGMA busy_timeout={int(self._cfg.sqlite_timeout_s * 1000)}")
        conn.execute(f"PRAGMA journal_mode={self._cfg.sqlite_journal_mode}")
        conn.execute(f"PRAGMA synchronous={self._cfg.sqlite_synchronous}")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA temp_store=MEMORY")
        conn.execute(f"PRAGMA wal_autocheckpoint={int(self._cfg.sqlite_wal_autocheckpoint)}")
        conn.execute(f"PRAGMA journal_size_limit={int(self._cfg.sqlite_journal_size_limit)}")
        try:
            conn.execute("PRAGMA mmap_size=134217728")  # 128MB
        except Exception:
            pass
        self._local.conn = conn
        return conn

    def close(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    # ----- migrate -----

    def _migrate(self) -> None:
        conn = self._get_conn()
        with self._lock:
            ver = int(conn.execute("PRAGMA user_version").fetchone()[0] or 0)
            if ver == 0:
                conn.executescript(_SCHEMA_V1)
                conn.execute("PRAGMA user_version=1")
                ver = 1
            if ver < 2:
                conn.executescript(_SCHEMA_V2)
                conn.execute("PRAGMA user_version=2")
                ver = 2
            if ver < 3:
                # hygiene: normalize legacy empty prev/sig to NULL (best-effort before triggers)
                try:
                    conn.execute("UPDATE receipts SET prev=NULL WHERE prev=''")
                except Exception:
                    pass
                try:
                    conn.execute("UPDATE receipts SET sig=NULL WHERE sig=''")
                except Exception:
                    pass
                conn.executescript(_SCHEMA_V3)
                conn.execute("PRAGMA user_version=3")
                ver = 3
            if ver < 4:
                # hygiene: normalize legacy empty prev/sig to NULL
                try:
                    conn.execute("UPDATE receipts SET prev=NULL WHERE prev=''")
                except Exception:
                    pass
                try:
                    conn.execute("UPDATE receipts SET sig=NULL WHERE sig=''")
                except Exception:
                    pass
                conn.executescript(_SCHEMA_V4)
                conn.execute("PRAGMA user_version=4")
                ver = 4

            # startup self-check in external profile (quick)
            if self._cfg.profile == "external":
                try:
                    fk = conn.execute("PRAGMA foreign_key_check").fetchall()
                    if fk:
                        raise LedgerError("foreign key check failed", code="DB_INTEGRITY")
                    qc = conn.execute("PRAGMA quick_check").fetchone()
                    if not qc or str(qc[0]).lower() != "ok":
                        raise LedgerError("db quick_check failed", code="DB_INTEGRITY")
                except LedgerError:
                    raise
                except Exception:
                    # conservative: do not block if pragma unavailable
                    pass

    # ----- helpers -----

    def _norm_subject(self, subject: SubjectKey) -> SubjectKey:
        t = _validate_subject_part("tenant", subject.tenant, self._cfg)
        u = _validate_subject_part("user", subject.user, self._cfg)
        s = _validate_subject_part("session", subject.session, self._cfg)
        return SubjectKey(tenant=t, user=u, session=s)

    def _subject_row_to_wr(self, row) -> WealthRecord:
        (
            _skey,
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
        meta = _sanitize_meta_from_json(meta_json, self._cfg)
        return WealthRecord(
            subject=SubjectKey(tenant=str(tenant), user=str(usr), session=str(sess)),
            wealth=float(wealth),
            alpha0=float(alpha0),
            hard_floor=float(hard_floor),
            policy_ref=str(policy_ref),
            version=int(version),
            updated_ts=float(updated_ts),
            meta=meta,
        )

    def _get_subject_row(self, conn: sqlite3.Connection, skey: str):
        cur = conn.execute(
            "SELECT skey, tenant, usr, sess, wealth, alpha0, hard_floor, policy_ref, version, updated_ts, meta_json "
            "FROM subjects WHERE skey=?",
            (skey,),
        )
        return cur.fetchone()

    def _chain_leaf_candidates(self, conn: sqlite3.Connection, chain_id: str) -> List[str]:
        cur = conn.execute(
            "SELECT r.head FROM receipts r "
            "WHERE r.chain_id=? AND NOT EXISTS (SELECT 1 FROM receipts c WHERE c.chain_id=r.chain_id AND c.prev=r.head) "
            "ORDER BY r.ts DESC, r.rowid DESC LIMIT 2",
            (chain_id,),
        )
        return [str(x[0]) for x in cur.fetchall()]

    def _chain_leaf_head(self, conn: sqlite3.Connection, chain_id: str) -> Optional[str]:
        leaves = self._chain_leaf_candidates(conn, chain_id)
        if not leaves:
            return None
        if len(leaves) > 1:
            _RCPT_INTEGRITY.labels(reason="multiple_leaf").inc()
            if self._cfg.profile == "external" and self._cfg.fail_closed_on_receipt_integrity_external:
                raise LedgerError("receipt chain fork detected", code="RECEIPT_CHAIN_FORK")
            # internal: best-effort choose newest leaf
        return leaves[0]

    def _chain_genesis_count(self, conn: sqlite3.Connection, chain_id: str) -> int:
        row = conn.execute(
            "SELECT COUNT(1) FROM receipts WHERE chain_id=? AND prev IS NULL",
            (chain_id,),
        ).fetchone()
        return int(row[0] or 0)

    @contextmanager
    def _txn(self) -> Iterator[sqlite3.Connection]:
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
        subject = self._norm_subject(subject)
        skey = subject.as_str()

        alpha0_f, hard_floor_f = _validate_subject_numbers(float(alpha0), float(hard_floor))
        pref = _validate_policy_ref(policy_ref, self._cfg)

        meta_sanitized = _sanitize_meta_for_storage(meta or {}, self._cfg)
        meta_json = _meta_to_json(meta_sanitized, self._cfg)

        with self._lock, self._txn() as txn:
            row = self._get_subject_row(txn, skey)
            if row:
                wr = self._subject_row_to_wr(row)
                if self._cfg.profile == "external":
                    if float(wr.alpha0) != float(alpha0_f) or float(wr.hard_floor) != float(hard_floor_f):
                        raise LedgerError("ensure_subject parameter mismatch", code="SUBJECT_MISMATCH")
                    if self._cfg.immutable_policy_ref_external and wr.policy_ref != pref:
                        raise LedgerError("policy_ref mismatch for subject", code="POLICY_MISMATCH")
                return wr

            txn.execute(
                "INSERT INTO subjects(skey, tenant, usr, sess, wealth, alpha0, hard_floor, policy_ref, version, updated_ts, meta_json) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    skey,
                    subject.tenant,
                    subject.user,
                    subject.session,
                    float(alpha0_f),
                    float(alpha0_f),
                    float(hard_floor_f),
                    pref,
                    1,
                    float(now),
                    meta_json,
                ),
            )
            row2 = self._get_subject_row(txn, skey)
            return self._subject_row_to_wr(row2)

    def get_wealth(self, subject: SubjectKey) -> Optional[WealthRecord]:
        subject = self._norm_subject(subject)
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
        subject = self._norm_subject(subject)
        skey = subject.as_str()

        eid = _validate_event_id(event_id, self._cfg)
        pref = _validate_policy_ref(policy_ref, self._cfg)
        a, r, _clamped = _validate_event_values(alpha_spent, reward, self._cfg)

        meta_sanitized = _sanitize_meta_for_storage(meta or {}, self._cfg)
        meta_json = _meta_to_json(meta_sanitized, self._cfg)
        fp_req = _fp_event(skey, a, r, pref, meta_json)

        now = time.time()

        with self._lock, self._txn() as conn:
            row = self._get_subject_row(conn, skey)
            if not row:
                raise LedgerError("subject not found", code="SUBJECT_MISSING")
            wr = self._subject_row_to_wr(row)

            # external: policy_ref immutable
            if self._cfg.profile == "external" and self._cfg.immutable_policy_ref_external and wr.policy_ref != pref:
                raise LedgerError("policy_ref mismatch", code="POLICY_MISMATCH")

            # per-subject monotonic timestamp
            ts = float(now) if float(now) > float(wr.updated_ts) else float(wr.updated_ts) + 1e-6

            # try insert event with fingerprint
            inserted = False
            try:
                conn.execute(
                    "INSERT INTO events(event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json, fingerprint) "
                    "VALUES(?,?,?,?,?,?,?,?)",
                    (eid, skey, float(a), float(r), pref, float(ts), meta_json, fp_req),
                )
                inserted = True
            except sqlite3.IntegrityError:
                inserted = False

            if not inserted:
                # duplicate event_id: verify subject + fingerprint matches
                rowe = conn.execute(
                    "SELECT skey, alpha_spent, reward, policy_ref, ts, meta_json, fingerprint FROM events WHERE event_id=?",
                    (eid,),
                ).fetchone()
                if not rowe:
                    raise LedgerError("event lookup failed", code="DB_INTEGRITY")

                skey_db, a_db, r_db, pref_db, ts_db, meta_json_db, fp_db = rowe
                if str(skey_db) != skey:
                    _EVT_CROSS.inc()
                    raise LedgerError("event_id reused across different subject", code="EVENT_CROSS_SUBJECT")

                meta_db_s = _sanitize_meta_from_json(str(meta_json_db or ""), self._cfg)
                meta_json_db_canon = _meta_to_json(meta_db_s, self._cfg)
                fp_stored = str(fp_db or "").strip() or _fp_event(
                    skey, float(a_db), float(r_db), str(pref_db), meta_json_db_canon
                )
                # opportunistic backfill
                if not str(fp_db or "").strip():
                    try:
                        conn.execute("UPDATE events SET fingerprint=? WHERE event_id=?", (fp_stored, eid))
                    except Exception:
                        pass

                if fp_stored != fp_req:
                    _EVT_MISMATCH.inc()
                    raise LedgerError("event_id params mismatch", code="EVENT_IDEMPOTENCY_MISMATCH")

                _EVT_DUP.inc()
                # return recorded values (not request now)
                wr2 = self._subject_row_to_wr(self._get_subject_row(conn, skey))
                return EventApplyResult(False, float(wr2.wealth), float(a_db), float(wr2.updated_ts))

            # update wealth with floor guard
            if not (math.isfinite(wr.wealth) and math.isfinite(wr.hard_floor)):
                raise LedgerError("non-finite wealth state", code="DB_INTEGRITY")

            tentative = float(wr.wealth) - float(a) + float(r)
            if tentative < float(wr.hard_floor):
                _EVT_FLOOR.inc()
            wealth_after = max(float(wr.hard_floor), tentative)

            merged_meta = dict(wr.meta or {})
            if meta_sanitized:
                merged_meta.update(meta_sanitized)
            merged_meta = _enforce_meta_budget(merged_meta, self._cfg)
            merged_meta_json = _meta_to_json(merged_meta, self._cfg)

            # under external, keep stored policy_ref stable; under internal allow update
            new_policy_ref = wr.policy_ref if (self._cfg.profile == "external") else pref

            conn.execute(
                "UPDATE subjects SET wealth=?, policy_ref=?, version=version+1, updated_ts=?, meta_json=? WHERE skey=?",
                (float(wealth_after), new_policy_ref, float(ts), merged_meta_json, skey),
            )
            _EVT_APPLIED.inc()
            return EventApplyResult(True, float(wealth_after), float(a), float(ts))

    # ----- receipts -----

    def append_receipt(self, rec: ReceiptRecord) -> None:
        # external: strict by default
        if self._cfg.require_strict_receipt_append:
            self.append_receipt_strict(rec)
            return

        r = _validate_receipt_record(rec, self._cfg)
        conn = self._get_conn()

        with self._lock:
            # best-effort monotonic ts per chain (non-strict path)
            if self._cfg.enforce_monotonic_receipt_ts:
                row = conn.execute(
                    "SELECT ts FROM receipts WHERE chain_id=? ORDER BY rowid DESC LIMIT 1",
                    (r.chain_id,),
                ).fetchone()
                if row:
                    last_ts = float(row[0])
                    if r.ts <= last_ts:
                        r = ReceiptRecord(
                            head=r.head, body=r.body, sig=r.sig, prev=r.prev, ts=last_ts + 1e-6, chain_id=r.chain_id
                        )

            try:
                conn.execute(
                    "INSERT INTO receipts(head, body, sig, prev, ts, chain_id) VALUES(?,?,?,?,?,?)",
                    (r.head, r.body, r.sig, r.prev, float(r.ts), r.chain_id),
                )
                _RCPT_SIZE.observe(len(r.body.encode("utf-8", errors="strict")))
                _RCPT_COUNT.inc()
            except sqlite3.IntegrityError as e:
                _RCPT_FAIL.inc()
                raise LedgerError("append_receipt integrity error", code="RECEIPT_INTEGRITY") from e

    def append_receipt_strict(self, rec: ReceiptRecord) -> None:
        r = _validate_receipt_record(rec, self._cfg)
        chain_id = r.chain_id

        with self._lock, self._txn() as txn:
            # fail-closed on multi-leaf for external (fork)
            leaf = self._chain_leaf_head(txn, chain_id)
            genesis_count = self._chain_genesis_count(txn, chain_id)
            if genesis_count > 1:
                _RCPT_INTEGRITY.labels(reason="multiple_genesis").inc()
                raise LedgerError("receipt chain invalid", code="RECEIPT_CHAIN_INVALID")

            # prev must match current leaf (or both None if empty chain)
            if leaf is None:
                if r.prev is not None:
                    _RCPT_FAIL.inc()
                    raise LedgerError("prev mismatch (empty chain)", code="RECEIPT_PREV_MISMATCH")
            else:
                if leaf != r.prev:
                    _RCPT_FAIL.inc()
                    raise LedgerError("prev mismatch (race/fork)", code="RECEIPT_PREV_MISMATCH")

            # monotonic ts inside txn per chain
            if self._cfg.enforce_monotonic_receipt_ts:
                row = txn.execute(
                    "SELECT ts FROM receipts WHERE chain_id=? ORDER BY rowid DESC LIMIT 1",
                    (chain_id,),
                ).fetchone()
                if row:
                    last_ts = float(row[0])
                    if r.ts <= last_ts:
                        r = ReceiptRecord(
                            head=r.head, body=r.body, sig=r.sig, prev=r.prev, ts=last_ts + 1e-6, chain_id=chain_id
                        )

            try:
                txn.execute(
                    "INSERT INTO receipts(head, body, sig, prev, ts, chain_id) VALUES(?,?,?,?,?,?)",
                    (r.head, r.body, r.sig, r.prev, float(r.ts), chain_id),
                )
                _RCPT_SIZE.observe(len(r.body.encode("utf-8", errors="strict")))
                _RCPT_COUNT.inc()
            except sqlite3.IntegrityError as e:
                _RCPT_FAIL.inc()
                raise LedgerError("append_receipt_strict integrity error", code="RECEIPT_INTEGRITY") from e

    def chain_head(self) -> Optional[str]:
        conn = self._get_conn()
        chain_id = self._cfg.default_chain_id
        return self._chain_leaf_head(conn, chain_id)

    def load_chain(self, limit: int = 1000) -> List[ReceiptRecord]:
        """
        Load up to `limit` receipts from the tail of the chain, in chain order (genesis→head).
        Uses prev pointers rather than timestamps. Hard-capped for safety.
        """
        conn = self._get_conn()
        chain_id = self._cfg.default_chain_id

        lim = int(limit)
        if lim <= 0:
            lim = self._cfg.max_chain_load
        lim = min(lim, self._cfg.max_chain_load)

        head = self._chain_leaf_head(conn, chain_id)
        if not head:
            return []

        out_rev: List[ReceiptRecord] = []
        cur_head: Optional[str] = head
        steps = 0
        while cur_head:
            row = conn.execute(
                "SELECT head, body, sig, prev, ts, chain_id FROM receipts WHERE chain_id=? AND head=?",
                (chain_id, cur_head),
            ).fetchone()
            if not row:
                break
            h, body, sig, prev, ts, cid = row
            sig2 = sig if (isinstance(sig, str) and sig.strip()) else None
            out_rev.append(
                ReceiptRecord(head=str(h), body=str(body), sig=sig2, prev=(str(prev) if prev is not None else None), ts=float(ts), chain_id=str(cid))
            )
            steps += 1
            if lim and steps >= lim:
                break
            cur_head = (str(prev) if prev is not None else None)

        return list(reversed(out_rev))

    # ----- AE / audit helpers -----

    def recompute_wealth(self, subject: SubjectKey) -> Dict[str, float]:
        subject = self._norm_subject(subject)
        conn = self._get_conn()
        skey = subject.as_str()
        row = self._get_subject_row(conn, skey)
        if not row:
            raise LedgerError("subject not found", code="SUBJECT_MISSING")
        wr = self._subject_row_to_wr(row)

        wealth = float(wr.alpha0)
        cur = conn.execute(
            "SELECT alpha_spent, reward, ts, event_id FROM events WHERE skey=? ORDER BY ts ASC, event_id ASC",
            (skey,),
        )
        for a, r, _ts, _eid in cur:
            wealth = max(float(wr.hard_floor), wealth - float(a) + float(r))

        return {"expected": float(wealth), "recorded": float(wr.wealth), "delta": float(wealth - wr.wealth)}

    def export_events(
        self,
        *,
        subject: Optional[SubjectKey] = None,
        ts_from: float = 0.0,
        ts_to: Optional[float] = None,
    ) -> Iterable[Dict[str, Any]]:
        conn = self._get_conn()
        ts_from_f = float(ts_from) if math.isfinite(float(ts_from)) else 0.0
        ts_to_f = float(ts_to) if (ts_to is not None and math.isfinite(float(ts_to))) else None

        if subject is None:
            if ts_to_f is None:
                cur = conn.execute(
                    "SELECT event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json, fingerprint "
                    "FROM events WHERE ts>=? ORDER BY ts ASC, event_id ASC",
                    (ts_from_f,),
                )
            else:
                cur = conn.execute(
                    "SELECT event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json, fingerprint "
                    "FROM events WHERE ts>=? AND ts<? ORDER BY ts ASC, event_id ASC",
                    (ts_from_f, ts_to_f),
                )
        else:
            skey = self._norm_subject(subject).as_str()
            if ts_to_f is None:
                cur = conn.execute(
                    "SELECT event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json, fingerprint "
                    "FROM events WHERE skey=? AND ts>=? ORDER BY ts ASC, event_id ASC",
                    (skey, ts_from_f),
                )
            else:
                cur = conn.execute(
                    "SELECT event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json, fingerprint "
                    "FROM events WHERE skey=? AND ts>=? AND ts<? ORDER BY ts ASC, event_id ASC",
                    (skey, ts_from_f, ts_to_f),
                )

        emitted = 0
        for event_id, skey, a, r, pref, ts, meta_json, fp in cur:
            emitted += 1
            if self._cfg.profile == "external" and self._cfg.max_export_rows and emitted > self._cfg.max_export_rows:
                break

            meta = _sanitize_meta_from_json(meta_json, self._cfg)
            meta_json_c = _meta_to_json(meta, self._cfg)
            fp2 = str(fp or "").strip() or _fp_event(str(skey), float(a), float(r), str(pref), meta_json_c)

            yield {
                "event_id": str(event_id),
                "skey": str(skey),
                "alpha_spent": float(a),
                "reward": float(r),
                "policy_ref": str(pref),
                "ts": float(ts),
                "meta": meta,
                "fingerprint": fp2,
            }

    def import_events(self, rows: Iterable[Dict[str, Any]]) -> int:
        """
        Strict, streaming idempotent import.
        - Only JSON-basic types accepted.
        - subject rows must exist.
        - cross-subject reuse rejected.
        - event_id duplicates must match fingerprint, otherwise reject.
        - Does NOT update subjects wealth automatically (use recompute_wealth for audit).
        """
        conn = self._get_conn()
        count = 0
        with self._lock:
            for row in rows:
                if not isinstance(row, Mapping):
                    raise LedgerError("bad import row", code="IMPORT_INVALID")

                event_id = row.get("event_id")
                skey = row.get("skey")
                if not isinstance(event_id, str) or not isinstance(skey, str):
                    raise LedgerError("bad import row types", code="IMPORT_INVALID")
                eid = _validate_event_id(event_id, self._cfg)

                skey_s = skey.strip()
                _reject_unsafe_text(skey_s, allow_whitespace=False)
                if len(skey_s) > 1024:
                    raise LedgerError("bad skey", code="IMPORT_INVALID")

                if not self._get_subject_row(conn, skey_s):
                    raise LedgerError("import subject missing", code="IMPORT_SUBJECT_MISSING")

                a_raw = row.get("alpha_spent")
                r_raw = row.get("reward")
                if not isinstance(a_raw, (int, float)) or isinstance(a_raw, bool):
                    raise LedgerError("bad alpha_spent", code="IMPORT_INVALID")
                if not isinstance(r_raw, (int, float)) or isinstance(r_raw, bool):
                    raise LedgerError("bad reward", code="IMPORT_INVALID")
                a, r, _ = _validate_event_values(a_raw, r_raw, self._cfg)

                pref_raw = row.get("policy_ref", "import")
                pref = _validate_policy_ref(pref_raw, self._cfg)

                ts_raw = row.get("ts", time.time())
                if not isinstance(ts_raw, (int, float)) or isinstance(ts_raw, bool):
                    raise LedgerError("bad ts", code="IMPORT_INVALID")
                ts = float(ts_raw)
                if not math.isfinite(ts) or ts <= 0:
                    ts = time.time()

                meta_obj = row.get("meta") or {}
                if not isinstance(meta_obj, Mapping):
                    meta_obj = {}
                meta_s = _sanitize_meta_for_storage(meta_obj, self._cfg)
                meta_json = _meta_to_json(meta_s, self._cfg)

                fp = row.get("fingerprint")
                fp_s = fp.strip() if isinstance(fp, str) and fp.strip() else _fp_event(skey_s, a, r, pref, meta_json)

                with self._txn() as txn:
                    try:
                        txn.execute(
                            "INSERT INTO events(event_id, skey, alpha_spent, reward, policy_ref, ts, meta_json, fingerprint) "
                            "VALUES(?,?,?,?,?,?,?,?)",
                            (eid, skey_s, float(a), float(r), pref, float(ts), meta_json, fp_s),
                        )
                        count += 1
                    except sqlite3.IntegrityError:
                        row2 = txn.execute(
                            "SELECT skey, alpha_spent, reward, policy_ref, meta_json, fingerprint FROM events WHERE event_id=?",
                            (eid,),
                        ).fetchone()
                        if not row2:
                            raise LedgerError("event lookup failed", code="DB_INTEGRITY")

                        skey_db, a_db, r_db, pref_db, meta_db, fp_db = row2
                        if str(skey_db) != skey_s:
                            _EVT_CROSS.inc()
                            raise LedgerError("event_id reused across different subject (import)", code="EVENT_CROSS_SUBJECT")

                        meta_db_s = _sanitize_meta_from_json(meta_db, self._cfg)
                        meta_db_json = _meta_to_json(meta_db_s, self._cfg)
                        fp_stored = str(fp_db or "").strip() or _fp_event(skey_s, float(a_db), float(r_db), str(pref_db), meta_db_json)
                        if fp_stored != fp_s:
                            _EVT_MISMATCH.inc()
                            raise LedgerError("event_id mismatch (import)", code="EVENT_IDEMPOTENCY_MISMATCH")

                        # ok: idempotent duplicate
                        count += 1
        return count

    def load_chain_page(self, page_size: int = 256, cursor_ts: Optional[float] = None) -> Tuple[List[ReceiptRecord], Optional[float]]:
        """
        Page receipts by ts for the DEFAULT chain only.
        Enforce hard cap on page size.
        """
        conn = self._get_conn()
        chain_id = self._cfg.default_chain_id
        n = int(max(1, page_size))
        n = min(n, self._cfg.max_page_size)

        if cursor_ts is None:
            cur = conn.execute(
                "SELECT head, body, sig, prev, ts, chain_id FROM receipts WHERE chain_id=? ORDER BY ts ASC, rowid ASC LIMIT ?",
                (chain_id, n),
            )
        else:
            cur = conn.execute(
                "SELECT head, body, sig, prev, ts, chain_id FROM receipts WHERE chain_id=? AND ts>? ORDER BY ts ASC, rowid ASC LIMIT ?",
                (chain_id, float(cursor_ts), n),
            )

        out: List[ReceiptRecord] = []
        for head, body, sig, prev, ts, cid in cur:
            sig2 = sig if (isinstance(sig, str) and sig.strip()) else None
            out.append(
                ReceiptRecord(
                    head=str(head),
                    body=str(body),
                    sig=sig2,
                    prev=(str(prev) if prev is not None else None),
                    ts=float(ts),
                    chain_id=str(cid),
                )
            )
        next_cursor = out[-1].ts if out else None
        return (out, next_cursor)

    def prune_receipts_before(self, cutoff_ts: float) -> int:
        """
        Chain-safe pruning for DEFAULT chain only:
          - delete receipts with ts < cutoff (within chain)
          - if anything remains and anything was deleted, rewrite earliest kept receipt prev=NULL
            (checkpoint genesis) so remaining chain is self-contained.

        WARNING:
          - For best safety in external environments, prefer "keep last N" pruning by chain length
            (not exposed in base interface).
        """
        cutoff = float(cutoff_ts)
        if not math.isfinite(cutoff) or cutoff <= 0:
            return 0

        conn = self._get_conn()
        chain_id = self._cfg.default_chain_id

        with self._lock, self._txn() as txn:
            keep_row = txn.execute(
                "SELECT head FROM receipts WHERE chain_id=? AND ts >= ? ORDER BY ts ASC, rowid ASC LIMIT 1",
                (chain_id, cutoff),
            ).fetchone()
            keep_head = keep_row[0] if keep_row else None

            cur = txn.execute(
                "SELECT COUNT(1) FROM receipts WHERE chain_id=? AND ts < ?",
                (chain_id, cutoff),
            )
            to_delete = int(cur.fetchone()[0] or 0)
            if to_delete <= 0:
                return 0

            txn.execute(
                "DELETE FROM receipts WHERE chain_id=? AND ts < ?",
                (chain_id, cutoff),
            )

            if keep_head is not None:
                # checkpoint genesis
                txn.execute(
                    "UPDATE receipts SET prev=NULL WHERE chain_id=? AND head=?",
                    (chain_id, keep_head),
                )

        try:
            conn.execute("PRAGMA optimize")
        except Exception:
            pass

        _RCPT_PRUNED.inc(to_delete)
        return to_delete


# ---------------------------------------------------------------------------
# Helpers (optional)
# ---------------------------------------------------------------------------


def stable_subject_hash(sk: SubjectKey, *, key: Optional[bytes] = None, out_hex: int = 16) -> str:
    """
    Stable, optional-HMAC hash for subject identifiers (privacy-preserving).

    Uses canonical JSON for injective encoding (does NOT depend on 'tenant::user::session').
    Domain-separated to prevent cross-purpose linkage.
    """
    if not isinstance(out_hex, int) or out_hex <= 0:
        out_hex = 16
    out_hex = min(out_hex, 64)

    obj = {"tenant": sk.tenant, "user": sk.user, "session": sk.session}
    payload = _canonicalize_json(obj)
    b = _encode_utf8_strict(payload)

    domain = b"TCD|ledger|subject|v1|"
    msg = domain + b

    if key:
        if not isinstance(key, (bytes, bytearray)):
            raise LedgerError("stable_subject_hash key must be bytes", code="INVALID_KEY")
        kb = bytes(key)
        if len(kb) < 16:
            raise LedgerError("stable_subject_hash key too short", code="INVALID_KEY")
        h = hmac.new(kb, msg, hashlib.blake2s).hexdigest()
    else:
        h = hashlib.blake2s(msg).hexdigest()

    return h[:out_hex]