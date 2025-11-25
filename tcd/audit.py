from __future__ import annotations

"""
Append-only audit ledger for verifiable local logging.

This module provides a small, high-assurance append-only ledger used to
record audit events in a hash-chained log stored on disk.

Design goals:
  - append-only semantics with per-record head hash and prev pointer;
  - deterministic hashing with explicit domain separation;
  - optional keyed hashing (MAC-style) for stronger tamper-resistance;
  - optional signing hook to integrate with HSM / external signers;
  - fsync-on-write (configurable) and directory fsync on rotation;
  - rotation by size with a simple, indexable segment description;
  - lightweight, thread-safe, and dependency-free beyond stdlib.

The ledger is not a full receipt store (see tcd.auditor) but acts as a
local trust anchor that other components (auth, calibration, chain
auditor, e-process, PQ attestations) can reference via digests.
"""

import dataclasses
import json
import os
import threading
import time
from base64 import b64encode
from hashlib import blake2s, sha256
from typing import Any, Callable, Dict, Optional, TextIO


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _canonical_kv_hash(
    obj: Dict[str, Any],
    *,
    ctx: str = "tcd:audit_cfg",
) -> str:
    """
    Simple canonical hash for configuration objects.

    - sort keys for determinism;
    - encode as UTF-8 JSON;
    - hash with blake2s and an explicit context prefix.

    This is used to derive ledger_policy_digest which can be embedded
    into other receipts / attestations.
    """
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    h = blake2s()
    h.update(ctx.encode("utf-8"))
    h.update(data.encode("utf-8"))
    return h.hexdigest()


def _fsync_dir_for_path(path: str) -> None:
    """
    Best-effort directory fsync for crash consistency.

    On filesystems that support it, this ensures that rename/creation of
    the file is durable once this call returns.
    """
    try:
        dirname = os.path.dirname(path) or "."
        fd = os.open(dirname, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception:
        # Directory fsync failures are non-fatal here; they should be
        # surfaced via higher-level observability if needed.
        pass


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class AuditLedgerConfig:
    """
    Configuration for AuditLedger.

    Core fields:
      - path             : path to the current, active audit log file
      - rotate_mb        : size threshold (in MiB) for log rotation
      - hash_ctx         : domain-separation context for the hash function
      - digest_size      : digest size in bytes for blake2s (default 32 -> 64 hex chars)
      - sync_on_write    : if True, fsync after each append()
      - hash_alg         : "blake2s" (default); reserved for future extension

    Policy / origin fields:
      - node_id          : logical node identifier (router/instance id)
      - proc_id          : build / process identifier (e.g. git commit, image digest)

    Policy digest wiring:
      - include_policy_block      : if True, append() will embed a policy block
      - default_auth_policy       : default auth policy digest (Authenticator)
      - default_calib_policy      : default calibrator policy digest
      - default_chain_audit_policy: default chain-auditor policy digest
      - default_cfg_digest        : default high-level config digest

    Integrity hardening:
      - mac_key_hex       : optional hex-encoded key for keyed blake2s
      - enable_hash_self_test
                          : if True, run a simple blake2s self-test on init

    Index / metadata:
      - enable_index      : if True, maintain a small index JSON describing
                            rotated segments and a root digest
      - index_path        : optional override for index file path; if None,
                            defaults to "<path>.index.json"

    Record validation:
      - record_validator  : optional callback(record) -> None; may raise to
                            reject records before they are serialized.
    """

    # Core
    path: str = "./audit/audit.log"
    rotate_mb: int = 50
    hash_ctx: str = "tcd:audit_ledger"
    digest_size: int = 32
    sync_on_write: bool = True
    hash_alg: str = "blake2s"

    # Origin / process
    node_id: Optional[str] = None
    proc_id: Optional[str] = None

    # Policy embedding
    include_policy_block: bool = False
    default_auth_policy: Optional[str] = None
    default_calib_policy: Optional[str] = None
    default_chain_audit_policy: Optional[str] = None
    default_cfg_digest: Optional[str] = None

    # Integrity hardening
    mac_key_hex: Optional[str] = None
    enable_hash_self_test: bool = False

    # Indexing / segments
    enable_index: bool = True
    index_path: Optional[str] = None

    # Validation hooks (not part of digest)
    record_validator: Optional[Callable[[Dict[str, Any]], None]] = None
    # Signing hook: sign_func(body_bytes) -> signature_bytes
    sign_func: Optional[Callable[[bytes], bytes]] = None
    sig_alg: Optional[str] = None
    sig_key_id: Optional[str] = None

    # ------------------------------------------------------------------ #
    # Digest helpers                                                     #
    # ------------------------------------------------------------------ #

    def policy_digest(self) -> str:
        """
        Compute a stable digest of the ledger policy configuration.

        This excludes callbacks and runtime-only fields but includes
        everything that affects how records are produced. It is suitable
        for embedding into other receipts / attestations as
        ledger_policy_digest.
        """
        material: Dict[str, Any] = {
            "path": self.path,
            "rotate_mb": int(self.rotate_mb),
            "hash_ctx": self.hash_ctx,
            "digest_size": int(self.digest_size),
            "sync_on_write": bool(self.sync_on_write),
            "hash_alg": self.hash_alg,
            "node_id": self.node_id,
            "proc_id": self.proc_id,
            "include_policy_block": bool(self.include_policy_block),
            "default_auth_policy": self.default_auth_policy,
            "default_calib_policy": self.default_calib_policy,
            "default_chain_audit_policy": self.default_chain_audit_policy,
            "default_cfg_digest": self.default_cfg_digest,
            "mac_key_hex": self.mac_key_hex,
            "enable_hash_self_test": bool(self.enable_hash_self_test),
            "enable_index": bool(self.enable_index),
            "index_path": self.index_path,
            "sig_alg": self.sig_alg,
            "sig_key_id": self.sig_key_id,
        }
        return _canonical_kv_hash(material, ctx="tcd:audit_policy")

    def effective_index_path(self) -> str:
        if self.index_path:
            return self.index_path
        return self.path + ".index.json"


# ---------------------------------------------------------------------------
# Audit ledger
# ---------------------------------------------------------------------------


class AuditLedger:
    """
    Append-only, hash-chained audit ledger.

    File format (one JSON object per line, UTF-8 text):

        {
          "head": "<hex-hash>",
          "body": "{...json string...}"
        }

    where "body" is a compact JSON encoding of the inner record:

        {
          "v": 1,
          "ts_ns": <int unix nanoseconds>,
          "seq": <int, strictly increasing>,
          "prev": "<previous head hex>",
          "origin": {
            "node_id": "<node identifier>",
            "proc_id": "<build/process id>"
          },
          "policy": {
            "ledger_policy": "<ledger_policy_digest>",
            "auth_policy": "<auth policy digest>",
            "calib_policy": "<calibrator policy digest>",
            "chain_audit_policy": "<chain-audit policy digest>",
            "cfg_digest": "<global cfg digest>"
          },
          "payload": {...},       # user-provided record
          "sig": {
            "alg": "<sig algorithm>",
            "key_id": "<signing key id>",
            "val": "<base64 signature>"
          }
        }

    Fields in "policy" and "sig" are optional and controlled by
    AuditLedgerConfig.

    Hash:
      - default is blake2s with configurable digest_size and explicit
        domain separation via hash_ctx;
      - if mac_key_hex is set, a keyed blake2s (MAC-style) is used;
      - head = HEX( H( ctx_bytes || body_bytes ) ).

    Thread safety:
      - append() and head() are safe for concurrent use by multiple threads.

    Crash safety:
      - writes are line-buffered and flushed;
      - if sync_on_write is True, fsync(fd) is called after each append;
      - rotation renames the active file and then fsyncs the directory
        best-effort.

    Index:
      - when enable_index is True, a small JSON index file describes the
        rotated segments and includes a root digest that can be mirrored
        or anchored externally.
    """

    # ------------------------------------------------------------------ #
    # Construction                                                       #
    # ------------------------------------------------------------------ #

    def __init__(
        self,
        path: str = "./audit/audit.log",
        rotate_mb: int = 50,
        *,
        cfg: Optional[AuditLedgerConfig] = None,
    ):
        """
        Construct an AuditLedger.

        Backward compatibility:
          - if cfg is None, `path` and `rotate_mb` are used to build a
            default AuditLedgerConfig;
          - if cfg is provided, its fields take precedence, and `path` /
            `rotate_mb` arguments are ignored.
        """
        if cfg is None:
            cfg = AuditLedgerConfig(path=path, rotate_mb=rotate_mb)
        self._cfg = cfg

        self.path: str = cfg.path
        self.rotate_bytes: int = int(cfg.rotate_mb * 1024 * 1024)

        # Hash context and parameters.
        self._hash_ctx_bytes: bytes = cfg.hash_ctx.encode("utf-8")
        self._digest_size: int = int(cfg.digest_size)
        self._hash_alg: str = cfg.hash_alg.lower().strip() or "blake2s"

        # Optional MAC key bytes.
        self._mac_key: Optional[bytes] = None
        if cfg.mac_key_hex:
            self._mac_key = bytes.fromhex(cfg.mac_key_hex.strip())

        # Optional hash self-test (simple sanity check).
        if cfg.enable_hash_self_test:
            self._hash_self_test()

        # Threading and file handle.
        self._lock = threading.RLock()
        self._fh: Optional[TextIO] = None

        # Genesis head: all zeros, sized to digest_size * 2 hex chars.
        self._prev: str = "0" * (self._digest_size * 2)

        # Sequence counter; -1 means "no records yet".
        self._seq: int = -1

        # Per-segment metadata for index.
        self._segment_start_seq: Optional[int] = None
        self._segment_start_ts_ns: Optional[int] = None
        self._segment_last_seq: Optional[int] = None
        self._segment_last_ts_ns: Optional[int] = None

        # Ensure directory exists and open the log, recovering last head
        # and last seq if present.
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self._open_and_recover()

    # ------------------------------------------------------------------ #
    # Internal helpers                                                   #
    # ------------------------------------------------------------------ #

    def _hash_self_test(self) -> None:
        """
        Simple self-test for blake2s to catch obvious tampering.

        Uses a fixed test vector (not meant as a full KAT suite).
        """
        # blake2s(b"test") with digest_size=32, no key, no salt/personal.
        h = blake2s()
        h.update(b"test")
        expected = "455e518824bc0601f9fb858ff5e3c5e362a09e17f4c1f3f0fcedd8e9f5c6e341"
        if h.hexdigest() != expected:
            raise RuntimeError("AuditLedger hash self-test failed")

    def _open_and_recover(self) -> None:
        """
        Open the current log file in append mode and recover last head/seq.

        Recovery:
          - seeks near the end;
          - scans backwards over the last chunk of lines;
          - picks the first line that decodes as JSON with a "head" field;
          - attempts to parse inner body JSON and recover "seq" if present;
          - leaves self._prev and self._seq unchanged if nothing valid is found.
        """
        exists = os.path.exists(self.path)
        # Text mode, line-buffered.
        self._fh = open(self.path, "a+", buffering=1, encoding="utf-8")
        if not exists:
            return

        try:
            self._fh.seek(0, os.SEEK_END)
            if self._fh.tell() <= 0:
                return

            size = os.path.getsize(self.path)
            if size <= 0:
                return

            tail_bytes = min(8192, size)
            with open(self.path, "rb") as rf:
                rf.seek(-tail_bytes, os.SEEK_END)
                tail = rf.read().splitlines()

            for line in reversed(tail):
                if not line:
                    continue
                try:
                    outer = json.loads(line.decode("utf-8"))
                    head = outer.get("head")
                    body_str = outer.get("body")
                    if not isinstance(head, str) or not head:
                        continue
                    # Accept this head.
                    self._prev = head
                    # Try to recover seq.
                    if isinstance(body_str, str) and body_str:
                        try:
                            inner = json.loads(body_str)
                            seq_val = inner.get("seq")
                            if isinstance(seq_val, int):
                                self._seq = seq_val
                        except Exception:
                            pass
                    break
                except Exception:
                    continue
        except Exception:
            # Recovery failure should not prevent further appends.
            pass

    def _hash_body(self, body: str) -> str:
        """
        Compute the head hash for a given body string.

        - The default algorithm is blake2s.
        - If mac_key is set, blake2s is used in keyed mode (MAC-style).
        - The hash includes an explicit context prefix for domain separation.
        """
        data = body.encode("utf-8")

        if self._hash_alg == "blake2s":
            if self._mac_key is not None:
                h = blake2s(digest_size=self._digest_size, key=self._mac_key)
            else:
                h = blake2s(digest_size=self._digest_size)
        else:
            # Reserved for future hash algorithms; for now, fall back to
            # blake2s with the configured digest size.
            if self._mac_key is not None:
                h = blake2s(digest_size=self._digest_size, key=self._mac_key)
            else:
                h = blake2s(digest_size=self._digest_size)

        h.update(self._hash_ctx_bytes)
        h.update(data)
        return h.hexdigest()

    def _load_index(self) -> Dict[str, Any]:
        """
        Load or initialize the index structure.

        Structure:

            {
              "v": 1,
              "segments": [
                {
                  "file": "<rotated file name>",
                  "start_seq": <int>,
                  "end_seq": <int>,
                  "last_head": "<hex>",
                  "ts_from_ns": <int>,
                  "ts_to_ns": <int>
                },
                ...
              ],
              "root_digest": "<sha256-of-segments-json>"
            }
        """
        path = self._cfg.effective_index_path()
        if not os.path.exists(path):
            return {"v": 1, "segments": [], "root_digest": ""}

        try:
            with open(path, "r", encoding="utf-8") as fh:
                obj = json.load(fh)
            if not isinstance(obj, dict):
                return {"v": 1, "segments": [], "root_digest": ""}
            if "segments" not in obj or not isinstance(obj["segments"], list):
                obj["segments"] = []
            if "root_digest" not in obj or not isinstance(obj["root_digest"], str):
                obj["root_digest"] = ""
            return obj
        except Exception:
            return {"v": 1, "segments": [], "root_digest": ""}

    def _update_index(
        self,
        rotated_file: str,
        start_seq: int,
        end_seq: int,
        ts_from_ns: int,
        ts_to_ns: int,
        last_head: str,
    ) -> None:
        """
        Append a new segment entry to the index and recompute root_digest.

        This is called whenever a log rotation occurs (if enable_index).
        """
        if not self._cfg.enable_index:
            return

        idx_path = self._cfg.effective_index_path()
        idx = self._load_index()

        seg = {
            "file": rotated_file,
            "start_seq": int(start_seq),
            "end_seq": int(end_seq),
            "last_head": str(last_head),
            "ts_from_ns": int(ts_from_ns),
            "ts_to_ns": int(ts_to_ns),
        }
        idx["segments"].append(seg)

        # Recompute root digest over the segments array.
        seg_json = json.dumps(
            idx["segments"],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        h = sha256()
        h.update(seg_json.encode("utf-8"))
        idx["root_digest"] = h.hexdigest()

        tmp_path = idx_path + ".tmp"
        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                json.dump(idx, fh, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, idx_path)
            _fsync_dir_for_path(idx_path)
        except Exception:
            # If index update fails, the ledger remains usable. Index
            # integrity should be monitored separately.
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass

    def _rotate(self) -> None:
        """
        Rotate the current log file once rotate_bytes is exceeded.

        The old file is renamed to:

            <path>.<epoch>.<head_prefix>

        where head_prefix is the first 8 characters of the last head at
        the time of rotation.

        When index is enabled, the segment metadata is recorded in the
        index file along with an index root digest.
        """
        if self._fh is None:
            return

        try:
            self._fh.close()
        except Exception:
            pass

        ts = int(time.time())
        head_prefix = (self._prev or "")[:8]
        rotated_name = f"{self.path}.{ts}.{head_prefix}"

        try:
            os.rename(self.path, rotated_name)
        except Exception:
            # If rename fails (e.g., concurrent rotation or filesystem issues),
            # we will still attempt to reopen the active path without updating
            # the index.
            rotated_name = self.path  # best-effort fallback

        # Update index with the segment we just closed, if possible.
        if (
            self._cfg.enable_index
            and self._segment_start_seq is not None
            and self._segment_last_seq is not None
            and self._segment_start_ts_ns is not None
            and self._segment_last_ts_ns is not None
        ):
            self._update_index(
                rotated_file=os.path.basename(rotated_name),
                start_seq=self._segment_start_seq,
                end_seq=self._segment_last_seq,
                ts_from_ns=self._segment_start_ts_ns,
                ts_to_ns=self._segment_last_ts_ns,
                last_head=self._prev,
            )

        # Reset per-segment metadata for the new active file.
        self._segment_start_seq = None
        self._segment_start_ts_ns = None
        self._segment_last_seq = None
        self._segment_last_ts_ns = None

        # Reopen current path and recover head/seq if file already had content.
        self._open_and_recover()
        _fsync_dir_for_path(self.path)

    # ------------------------------------------------------------------ #
    # Public API                                                         #
    # ------------------------------------------------------------------ #

    def head(self) -> str:
        """
        Return the current head hash of the ledger (last appended head).

        For a fresh ledger with no entries, this is an all-zero hex string
        whose length depends on the configured digest_size.
        """
        with self._lock:
            return self._prev

    def append(
        self,
        record: Dict[str, Any],
        *,
        ts_ns: Optional[int] = None,
        policy_overrides: Optional[Dict[str, Optional[str]]] = None,
    ) -> str:
        """
        Append a new record to the ledger and return the new head hash.

        Parameters:
          - record          : arbitrary JSON-serializable mapping to store
                              under the "payload" key.
          - ts_ns           : optional timestamp (unix nanoseconds). If None,
                              time.time_ns() is used.
          - policy_overrides:
                              optional mapping with keys among:
                                "auth_policy", "calib_policy",
                                "chain_audit_policy", "cfg_digest"
                              to override the defaults from config.

        Behaviour:
          - validates `record` via config.record_validator if provided;
          - assigns a strictly increasing seq (starting from 0);
          - constructs an inner record with ts_ns, seq, prev, origin, policy,
            payload, and optional signature;
          - serializes inner to compact JSON (sorted keys for determinism);
          - computes head hash over the body;
          - writes an outer JSON line {head, body} to the log;
          - flushes and optionally fsyncs;
          - updates internal head/seq and performs rotation if needed.

        The schema of `record` is not enforced here beyond being a mapping
        and JSON-serializable. Higher-level components (e-process, auth,
        calibrators) are expected to agree on their own payload schemas.
        """
        if ts_ns is None:
            ts_ns = time.time_ns()

        if not isinstance(record, dict):
            raise TypeError("AuditLedger.append(): record must be a dict-like mapping")

        if self._cfg.record_validator is not None:
            # Let the validator raise if it sees something invalid.
            self._cfg.record_validator(record)

        with self._lock:
            # Compute next sequence number.
            self._seq += 1
            seq_val = self._seq

            # Initialize per-segment metadata if needed.
            if self._segment_start_seq is None:
                self._segment_start_seq = seq_val
                self._segment_start_ts_ns = ts_ns
            self._segment_last_seq = seq_val
            self._segment_last_ts_ns = ts_ns

            # Build origin block.
            origin_block: Dict[str, Any] = {}
            if self._cfg.node_id:
                origin_block["node_id"] = self._cfg.node_id
            if self._cfg.proc_id:
                origin_block["proc_id"] = self._cfg.proc_id

            # Build policy block.
            policy_block: Dict[str, Any] = {}
            if self._cfg.include_policy_block:
                # Base: ledger policy digest.
                ledger_policy = self._cfg.policy_digest()
                policy_block["ledger_policy"] = ledger_policy

                # Prepare overrides.
                overrides = policy_overrides or {}

                auth_policy = overrides.get("auth_policy", self._cfg.default_auth_policy)
                if auth_policy:
                    policy_block["auth_policy"] = auth_policy

                calib_policy = overrides.get("calib_policy", self._cfg.default_calib_policy)
                if calib_policy:
                    policy_block["calib_policy"] = calib_policy

                chain_audit_policy = overrides.get(
                    "chain_audit_policy",
                    self._cfg.default_chain_audit_policy,
                )
                if chain_audit_policy:
                    policy_block["chain_audit_policy"] = chain_audit_policy

                cfg_digest = overrides.get("cfg_digest", self._cfg.default_cfg_digest)
                if cfg_digest:
                    policy_block["cfg_digest"] = cfg_digest

            # Construct inner record.
            inner: Dict[str, Any] = {
                "v": 1,
                "ts_ns": int(ts_ns),
                "seq": int(seq_val),
                "prev": self._prev,
                "payload": record,
            }
            if origin_block:
                inner["origin"] = origin_block
            if policy_block:
                inner["policy"] = policy_block

            # Deterministic JSON for hashing.
            body = json.dumps(
                inner,
                separators=(",", ":"),
                ensure_ascii=False,
                sort_keys=True,
            )
            head = self._hash_body(body)

            # Optional signing hook.
            if self._cfg.sign_func is not None and self._cfg.sig_alg:
                try:
                    sig_bytes = self._cfg.sign_func(body.encode("utf-8"))
                    sig_val = b64encode(sig_bytes).decode("ascii")
                    sig_block = {
                        "alg": self._cfg.sig_alg,
                        "val": sig_val,
                    }
                    if self._cfg.sig_key_id:
                        sig_block["key_id"] = self._cfg.sig_key_id
                    # Insert signature into inner and recompute body/head.
                    inner["sig"] = sig_block
                    body = json.dumps(
                        inner,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        sort_keys=True,
                    )
                    head = self._hash_body(body)
                except Exception as e:
                    # In high-assurance deployments, callers may prefer to
                    # treat signature failure as fatal.
                    raise RuntimeError(f"AuditLedger signing failed: {e}") from e

            if self._fh is None:
                # Defensive: if the file handle somehow disappeared, reopen.
                self._open_and_recover()

            if self._fh is None:
                # Still None: treat as a hard failure.
                raise RuntimeError("AuditLedger file handle not available")

            outer = {"head": head, "body": body}
            line = json.dumps(
                outer,
                separators=(",", ":"),
                ensure_ascii=False,
            ) + "\n"

            self._fh.write(line)
            self._fh.flush()
            if self._cfg.sync_on_write:
                try:
                    os.fsync(self._fh.fileno())
                except Exception:
                    # Disk sync failure should be surfaced via higher-level
                    # monitoring but does not change the logical head chain.
                    pass

            # Update current head and rotate if needed.
            self._prev = head
            try:
                if self._fh.tell() >= self.rotate_bytes:
                    self._rotate()
            except Exception:
                # If tell() or rotation fails, we continue with the current
                # handle; the ledger remains appendable.
                pass

            return head

    def close(self) -> None:
        """
        Close the underlying file handle, if open.

        The ledger can be reopened by creating a new AuditLedger instance
        pointing at the same path.
        """
        with self._lock:
            fh = self._fh
            self._fh = None
        if fh is not None:
            try:
                fh.close()
            except Exception:
                pass

    # Optional context manager interface for short-lived usage.

    def __enter__(self) -> "AuditLedger":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()