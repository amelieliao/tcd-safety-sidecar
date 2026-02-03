from __future__ import annotations

"""
tcd/audit.py — append-only audit ledger (L6/L7 platform-hardened, stdlib-only)

Key upgrades vs naive JSONL:
- Transactional append semantics (no seq/head advancement on any failure).
- Robust tail repair: truncate to last-good record boundary to prevent half-line poisoning.
- Deterministic sanitization with bounded complexity and stable ordering (incl. set/frozenset).
- Dual head mode:
  - head: public hash (verifiable without secrets)
  - head_mac: optional keyed MAC hash (tamper resistance)
- Optional signature stored OUTSIDE body (avoids circular canonicalization pitfalls):
  - sign_over = "body" or "head"
- Rotation with segment index that supports cross-segment chain verification.
- Optional framing format (L7) to avoid JSONL boundary issues entirely.

This module is stdlib-only and intended as a local trust anchor.
"""

import dataclasses
import errno
import json
import os
import random
import re
import stat
import struct
import threading
import time
import zlib
from base64 import b64encode
from collections import OrderedDict, deque
from hashlib import blake2s, sha256
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# Optional platform-specific file locking (best-effort)
try:  # pragma: no cover
    import fcntl  # type: ignore
except Exception:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

try:  # pragma: no cover
    import msvcrt  # type: ignore
except Exception:  # pragma: no cover
    msvcrt = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Error taxonomy (platform-friendly)
# ---------------------------------------------------------------------------


class AuditLedgerError(RuntimeError):
    code = "AUDIT_ERROR"


class AuditConfigError(AuditLedgerError):
    code = "CONFIG_ERROR"


class AuditOverloadedError(AuditLedgerError):
    code = "OVERLOADED"


class AuditLockTimeoutError(AuditLedgerError):
    code = "LOCK_TIMEOUT"


class AuditIOError(AuditLedgerError):
    code = "IO_ERROR"


class AuditRecoveryError(AuditLedgerError):
    code = "RECOVERY_FAILED"


class AuditCorruptTailError(AuditLedgerError):
    code = "CORRUPT_TAIL"


class AuditRotationError(AuditLedgerError):
    code = "ROTATION_FAILED"


class AuditIndexError(AuditLedgerError):
    code = "INDEX_FAILED"


class AuditRollbackDetected(AuditLedgerError):
    code = "ROLLBACK_DETECTED"


class AuditDiscontinuityDetected(AuditLedgerError):
    code = "DISCONTINUITY"


class AuditVerifyError(AuditLedgerError):
    code = "VERIFY_FAILED"


# ---------------------------------------------------------------------------
# Utilities (safe text, canonical JSON, hashing, I/O)
# ---------------------------------------------------------------------------

_CTRL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Some extra token shapes (best-effort DLP)
_AWS_AKIA_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")


def _truncate_chars(s: str, n: int) -> str:
    if n <= 0:
        return ""
    if len(s) <= n:
        return s
    return s[: max(0, n - 3)] + "..."


def _utf8_clean(s: str) -> str:
    # Remove invalid surrogate sequences deterministically.
    return s.encode("utf-8", errors="replace").decode("utf-8", errors="strict")


def _strip_ctrl(s: str) -> str:
    return _CTRL_CHARS_RE.sub("", s)


def _safe_text(x: Any, *, max_len: int = 256) -> str:
    try:
        s = str(x)
    except Exception:
        s = "<unprintable>"
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = _strip_ctrl(s).strip()
    s = _utf8_clean(s)
    return _truncate_chars(s, max_len)


def _truncate_utf8_bytes(s: str, max_bytes: int) -> str:
    if max_bytes <= 0:
        return ""
    bs = s.encode("utf-8", errors="replace")
    if len(bs) <= max_bytes:
        return s
    bs2 = bs[:max_bytes]
    # Avoid cutting in middle of UTF-8 sequence
    while bs2 and (bs2[-1] & 0xC0) == 0x80:
        bs2 = bs2[:-1]
    return bs2.decode("utf-8", errors="ignore")


def _looks_like_secret(s: str) -> bool:
    if not s:
        return False
    ss = s.strip()
    # JWT-ish
    if ss.count(".") == 2 and all(len(p) >= 8 for p in ss.split(".")):
        return True
    # PEM-ish
    if "-----BEGIN " in ss and "-----END " in ss:
        return True
    # bearer-ish
    if "bearer " in ss.lower():
        return True
    # long base64-ish
    if len(ss) >= 120 and all(c.isalnum() or c in "+/=_-." for c in ss):
        return True
    # common service tokens
    if _AWS_AKIA_RE.search(ss):
        return True
    if _GITHUB_TOKEN_RE.search(ss):
        return True
    return False


def _redact_value(_: Any) -> str:
    return "[redacted]"


def _canonical_json(obj: Any) -> str:
    """
    Canonical JSON:
    - sorted keys
    - compact separators
    - ensure_ascii=False
    - allow_nan=False
    """
    return json.dumps(
        obj,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )


def _canonical_kv_hash(obj: Dict[str, Any], *, ctx: str) -> str:
    data = _canonical_json(obj).encode("utf-8")
    h = blake2s()
    h.update(ctx.encode("utf-8"))
    h.update(b"\x00")
    h.update(data)
    return h.hexdigest()


def _hex_fingerprint(data: bytes, *, ctx: str, digest_size: int = 16) -> str:
    h = blake2s(digest_size=max(4, min(32, int(digest_size))))
    h.update(ctx.encode("utf-8"))
    h.update(b"\x00")
    h.update(data)
    return h.hexdigest()


def _fsync_dir_for_path(path: str, *, required: bool = False) -> None:
    try:
        dirname = os.path.dirname(path) or "."
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= getattr(os, "O_DIRECTORY")  # type: ignore[arg-type]
        fd = os.open(dirname, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except Exception as e:
        if required:
            raise AuditIOError(f"directory fsync failed: {_safe_text(e, max_len=200)}") from e


def _write_all(fd: int, data: bytes) -> None:
    """
    Write all bytes to fd. Any short write is retried; non-recoverable errors raise.
    """
    view = memoryview(data)
    total = 0
    while total < len(data):
        try:
            n = os.write(fd, view[total:])
        except OSError as e:
            if e.errno == errno.EINTR:
                continue
            raise AuditIOError(f"os.write failed: {_safe_text(e, max_len=200)}") from e
        if n is None or n <= 0:
            raise AuditIOError("short/zero write")
        total += int(n)


def _safe_open_regular_file(
    path: str,
    *,
    flags: int,
    mode: int,
    require_regular: bool,
    require_nlink_one: bool,
    allowed_root_dir: Optional[str],
) -> Tuple[int, os.stat_result]:
    if allowed_root_dir:
        root = os.path.realpath(allowed_root_dir)
        rp = os.path.realpath(path)
        if not (rp == root or rp.startswith(root + os.sep)):
            raise AuditConfigError("path is outside allowed_root_dir")

    nofollow = getattr(os, "O_NOFOLLOW", 0)
    cloexec = getattr(os, "O_CLOEXEC", 0)

    fd = os.open(path, flags | nofollow | cloexec, mode)
    try:
        st = os.fstat(fd)
        if require_regular and not stat.S_ISREG(st.st_mode):
            raise AuditConfigError("audit log path is not a regular file")
        if require_nlink_one and getattr(st, "st_nlink", 1) != 1:
            raise AuditConfigError("audit log file has unexpected link count")
        return fd, st
    except Exception:
        try:
            os.close(fd)
        except Exception:
            pass
        raise


def _u32be(n: int) -> bytes:
    return struct.pack(">I", int(n) & 0xFFFFFFFF)


def _read_exact(fd: int, n: int) -> Optional[bytes]:
    """
    Read exactly n bytes; return None on EOF before n bytes.
    """
    buf = bytearray()
    while len(buf) < n:
        try:
            chunk = os.read(fd, n - len(buf))
        except OSError as e:
            if e.errno == errno.EINTR:
                continue
            raise AuditIOError(f"os.read failed: {_safe_text(e, max_len=200)}") from e
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Payload sanitization (bounded + deterministic + collision-safe)
# ---------------------------------------------------------------------------


def _default_redact_key_pred(key: str) -> bool:
    k = key.lower()
    return any(
        p in k
        for p in (
            "authorization",
            "auth",
            "token",
            "secret",
            "password",
            "passwd",
            "pwd",
            "api_key",
            "apikey",
            "private_key",
            "session",
            "cookie",
            "bearer",
            "credential",
            "credentials",
        )
    )


@dataclasses.dataclass
class _SanitizeBudget:
    max_nodes: int
    max_total_str_bytes: int
    max_total_bytes: int
    nodes: int = 0
    total_str_bytes: int = 0
    total_bytes: int = 0


def _sanitize_json_like(
    obj: Any,
    *,
    max_depth: int,
    max_items: int,
    max_key_len: int,
    max_str_len: int,
    max_str_bytes: int,
    redact: bool,
    redact_key_pred: Callable[[str], bool],
    budget: _SanitizeBudget,
    seen: Optional[set] = None,
) -> Any:
    if max_depth <= 0:
        return {"_tcd_truncated_depth": True}

    if seen is None:
        seen = set()

    # node budget
    budget.nodes += 1
    if budget.max_nodes > 0 and budget.nodes > budget.max_nodes:
        return {"_tcd_truncated_nodes": True}

    # primitives
    if obj is None or isinstance(obj, (bool, int)):
        return obj

    if isinstance(obj, float):
        if obj != obj or obj in (float("inf"), float("-inf")):
            return "<non_finite_float>"
        return obj

    if isinstance(obj, str):
        s = _strip_ctrl(_utf8_clean(obj))
        s = _truncate_utf8_bytes(s, max_str_bytes)
        s = _truncate_chars(s, max_str_len)
        if redact and _looks_like_secret(s):
            s = _redact_value(s)
        bs = s.encode("utf-8", errors="replace")
        budget.total_str_bytes += len(bs)
        budget.total_bytes += len(bs)
        if budget.max_total_str_bytes > 0 and budget.total_str_bytes > budget.max_total_str_bytes:
            return "<str_budget_exceeded>"
        if budget.max_total_bytes > 0 and budget.total_bytes > budget.max_total_bytes:
            return "<budget_exceeded>"
        return s

    if isinstance(obj, (bytes, bytearray, memoryview)):
        b = bytes(obj)
        budget.total_bytes += min(len(b), 64)
        return f"<bytes:{len(b)}>"

    # cycle detection for containers
    oid = id(obj)
    if isinstance(obj, (dict, list, tuple, set, frozenset, deque)):
        if oid in seen:
            return "<cycle>"
        seen.add(oid)

    # mappings (deterministic order + key collision resolution)
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        items: List[Tuple[str, str, Any, Any]] = []
        for k, v in obj.items():
            ks = _safe_text(k, max_len=max_key_len)
            # tie-breaker: stable-ish representation
            tb = _safe_text(type(k).__name__, max_len=32) + ":" + _safe_text(repr(k), max_len=128)
            items.append((ks, tb, k, v))
        items.sort(key=lambda t: (t[0], t[1]))

        key_counts: Dict[str, int] = {}
        n = 0
        for ks, _tb, _k, v in items:
            if n >= max_items:
                out["_tcd_truncated_items"] = True
                out["_tcd_truncated_count"] = max(0, len(items) - n)
                break

            # collision-safe key
            base = ks
            cnt = key_counts.get(base, 0) + 1
            key_counts[base] = cnt
            if cnt > 1:
                suffix = f"#{cnt}"
                # ensure key length bound
                if len(base) + len(suffix) > max_key_len:
                    base2 = base[: max(0, max_key_len - len(suffix))]
                    ks2 = base2 + suffix
                else:
                    ks2 = base + suffix
            else:
                ks2 = base

            if redact and redact_key_pred(ks2):
                out[ks2] = _redact_value(v)
            else:
                vv = _sanitize_json_like(
                    v,
                    max_depth=max_depth - 1,
                    max_items=max_items,
                    max_key_len=max_key_len,
                    max_str_len=max_str_len,
                    max_str_bytes=max_str_bytes,
                    redact=redact,
                    redact_key_pred=redact_key_pred,
                    budget=budget,
                    seen=seen,
                )
                if redact and isinstance(vv, str) and _looks_like_secret(vv):
                    vv = _redact_value(vv)
                out[ks2] = vv

            n += 1
        return out

    # sequences
    if isinstance(obj, (list, tuple, deque)):
        out_list: List[Any] = []
        for i, item in enumerate(obj):
            if i >= max_items:
                out_list.append({"_tcd_truncated_items": True, "_tcd_truncated_count": max(0, len(obj) - i) if hasattr(obj, "__len__") else None})
                break
            out_list.append(
                _sanitize_json_like(
                    item,
                    max_depth=max_depth - 1,
                    max_items=max_items,
                    max_key_len=max_key_len,
                    max_str_len=max_str_len,
                    max_str_bytes=max_str_bytes,
                    redact=redact,
                    redact_key_pred=redact_key_pred,
                    budget=budget,
                    seen=seen,
                )
            )
        return out_list

    # sets: sanitize -> sort deterministically
    if isinstance(obj, (set, frozenset)):
        tmp: List[Any] = []
        for item in obj:
            tmp.append(
                _sanitize_json_like(
                    item,
                    max_depth=max_depth - 1,
                    max_items=max_items,
                    max_key_len=max_key_len,
                    max_str_len=max_str_len,
                    max_str_bytes=max_str_bytes,
                    redact=redact,
                    redact_key_pred=redact_key_pred,
                    budget=budget,
                    seen=seen,
                )
            )
        # sort key: canonical json
        try:
            tmp.sort(key=lambda x: _canonical_json(x))
        except Exception:
            tmp.sort(key=lambda x: _safe_text(x, max_len=256))
        # enforce max_items after sort deterministically
        if len(tmp) > max_items:
            tmp = tmp[:max_items] + [{"_tcd_truncated_items": True, "_tcd_truncated_count": len(tmp) - max_items}]
        return tmp

    # fallback: string
    s2 = _safe_text(obj, max_len=max_str_len)
    s2 = _truncate_utf8_bytes(s2, max_str_bytes)
    if redact and _looks_like_secret(s2):
        return _redact_value(s2)
    return s2


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class AuditLedgerConfig:
    # Core
    path: str = "./audit/audit.log"
    rotate_mb: int = 50  # <=0 disables rotation
    hash_ctx: str = "tcd:audit_ledger"
    digest_size: int = 32  # 1..32
    sync_on_write: bool = True
    sync_on_rotate: bool = True
    file_mode: int = 0o600

    # format
    record_format: str = "jsonl"  # "jsonl" | "framed_v1"
    framed_enable_crc32: bool = True
    framed_magic: bytes = b"TCD1"

    # Strict IO semantics knobs
    fsync_required: bool = False
    dir_fsync_required: bool = False
    fsync_every_n: int = 1  # group commit: fsync every N appends (>=1)
    fsync_interval_ms: int = 0  # group commit: fsync at most once per interval

    # Path safety
    allowed_root_dir: Optional[str] = None
    require_regular_file: bool = True
    require_nlink_one: bool = False

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
    include_segment_markers: bool = False  # optional: insert segment_start marker record on new segment
    include_index_root_in_markers: bool = True

    # Validation hooks (not part of digest)
    record_validator: Optional[Callable[[Dict[str, Any]], None]] = None

    # Signing hook: sign_func(bytes) -> signature_bytes
    sign_func: Optional[Callable[[bytes], bytes]] = None
    sig_alg: Optional[str] = None
    sig_key_id: Optional[str] = None
    sign_over: str = "body"  # "body" | "head"
    max_signature_bytes: int = 8 * 1024

    # Payload safety budgets
    sanitize_payload: bool = True
    redact_secrets: bool = True
    max_payload_depth: int = 32
    max_payload_items: int = 512
    max_key_len: int = 128
    max_str_len: int = 4096
    max_str_bytes: int = 8192
    max_nodes: int = 20_000
    max_total_str_bytes: int = 256 * 1024
    max_total_bytes: int = 512 * 1024

    max_record_bytes: int = 256 * 1024  # inner JSON bytes
    max_line_bytes: int = 512 * 1024  # outer record bytes (jsonl line or framed payload)

    # Concurrency controls
    append_lock_timeout_s: Optional[float] = None
    admission_gate: int = 0  # 0 => disabled
    dedupe_cache_size: int = 0  # 0 => disabled
    dedupe_key_path: Optional[str] = "event_id"

    # Process safety
    enable_process_lock: bool = True
    require_process_lock_backend: bool = False
    process_lock_path: Optional[str] = None
    process_lock_timeout_s: float = 0.0
    process_lock_poll_s: float = 0.05
    process_lock_stale_after_s: float = 0.0
    process_lock_break_stale: bool = False

    # Recovery & tail repair
    verify_tail: bool = True
    verify_tail_chain: bool = False
    recover_tail_bytes: int = 256 * 1024
    recover_head_scan_lines: int = 512
    strict_recovery: bool = False
    strict_discontinuity: bool = False

    # State file (rollback detection + fast resume)
    enable_state: bool = True
    state_path: Optional[str] = None
    state_fsync: bool = True
    strict_rollback: bool = False

    def effective_index_path(self) -> str:
        return self.index_path or (self.path + ".index.json")

    def effective_process_lock_path(self) -> str:
        return self.process_lock_path or (self.path + ".lock")

    def effective_state_path(self) -> str:
        return self.state_path or (self.path + ".state.json")

    def policy_digest(self) -> str:
        mac_key_present = bool(self.mac_key_hex)
        mac_key_fpr: Optional[str] = None
        if self.mac_key_hex:
            try:
                kb = bytes.fromhex(self.mac_key_hex.strip().replace(" ", ""))
                mac_key_fpr = _hex_fingerprint(kb, ctx="tcd:audit_ledger:mac_key", digest_size=16)
            except Exception:
                mac_key_fpr = "invalid"

        material: Dict[str, Any] = {
            "path": self.path,
            "rotate_mb": int(self.rotate_mb),
            "record_format": self.record_format,
            "hash_ctx": self.hash_ctx,
            "digest_size": int(self.digest_size),
            "sync_on_write": bool(self.sync_on_write),
            "sync_on_rotate": bool(self.sync_on_rotate),
            "fsync_required": bool(self.fsync_required),
            "dir_fsync_required": bool(self.dir_fsync_required),
            "fsync_every_n": int(self.fsync_every_n),
            "fsync_interval_ms": int(self.fsync_interval_ms),
            "allowed_root_dir": self.allowed_root_dir,
            "require_regular_file": bool(self.require_regular_file),
            "require_nlink_one": bool(self.require_nlink_one),
            "node_id": self.node_id,
            "proc_id": self.proc_id,
            "include_policy_block": bool(self.include_policy_block),
            "default_auth_policy": self.default_auth_policy,
            "default_calib_policy": self.default_calib_policy,
            "default_chain_audit_policy": self.default_chain_audit_policy,
            "default_cfg_digest": self.default_cfg_digest,
            "mac_key_present": mac_key_present,
            "mac_key_fingerprint": mac_key_fpr,
            "enable_hash_self_test": bool(self.enable_hash_self_test),
            "enable_index": bool(self.enable_index),
            "index_path": self.index_path,
            "include_segment_markers": bool(self.include_segment_markers),
            "sig_alg": self.sig_alg,
            "sig_key_id": self.sig_key_id,
            "sign_over": self.sign_over,
            "max_signature_bytes": int(self.max_signature_bytes),
            "sanitize_payload": bool(self.sanitize_payload),
            "redact_secrets": bool(self.redact_secrets),
            "max_payload_depth": int(self.max_payload_depth),
            "max_payload_items": int(self.max_payload_items),
            "max_key_len": int(self.max_key_len),
            "max_str_len": int(self.max_str_len),
            "max_str_bytes": int(self.max_str_bytes),
            "max_nodes": int(self.max_nodes),
            "max_total_str_bytes": int(self.max_total_str_bytes),
            "max_total_bytes": int(self.max_total_bytes),
            "max_record_bytes": int(self.max_record_bytes),
            "max_line_bytes": int(self.max_line_bytes),
            "enable_process_lock": bool(self.enable_process_lock),
            "strict_recovery": bool(self.strict_recovery),
            "strict_discontinuity": bool(self.strict_discontinuity),
            "enable_state": bool(self.enable_state),
            "strict_rollback": bool(self.strict_rollback),
        }
        return _canonical_kv_hash(material, ctx="tcd:audit_policy")


# ---------------------------------------------------------------------------
# Admission gate + dedupe map
# ---------------------------------------------------------------------------

class _AdmissionGate:
    def __init__(self, limit: int) -> None:
        self.limit = max(0, int(limit))
        self._sem = threading.BoundedSemaphore(self.limit) if self.limit > 0 else None

    def try_acquire(self) -> bool:
        if self._sem is None:
            return True
        return bool(self._sem.acquire(blocking=False))

    def release(self) -> None:
        if self._sem is None:
            return
        try:
            self._sem.release()
        except Exception:
            pass


class _DedupeMap:
    """
    LRU map: event_id -> head
    Must be accessed under ledger lock for correctness.
    """
    def __init__(self, capacity: int) -> None:
        self.capacity = max(0, int(capacity))
        self._od: "OrderedDict[str, str]" = OrderedDict()

    def get(self, k: str) -> Optional[str]:
        if self.capacity <= 0:
            return None
        kk = str(k)
        if kk in self._od:
            self._od.move_to_end(kk)
            return self._od[kk]
        return None

    def put(self, k: str, head: str) -> None:
        if self.capacity <= 0:
            return
        kk = str(k)
        self._od[kk] = str(head)
        self._od.move_to_end(kk)
        while len(self._od) > self.capacity:
            try:
                self._od.popitem(last=False)
            except Exception:
                break


def _get_by_dot_path(obj: Any, path: str) -> Optional[Any]:
    if not path:
        return None
    cur = obj
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


# ---------------------------------------------------------------------------
# Append result for platform integrations
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class AppendResult:
    head: str
    seq: int
    ts_ns: int
    duplicated: bool = False
    rotated: bool = False
    fsync_ok: bool = True
    warning: Optional[str] = None


# ---------------------------------------------------------------------------
# Audit ledger implementation
# ---------------------------------------------------------------------------

class AuditLedger:
    """
    Append-only hash-chained audit ledger.

    JSONL format (record_format="jsonl"):
      one UTF-8 JSON object per line:
        {"head":"..","body":"..","head_mac":"..","sig":{...}}

    Framed format (record_format="framed_v1"):
      stream of frames:
        magic(4) + len(u32be) + payload_bytes + [crc32(u32be)]
      payload_bytes is UTF-8 JSON of the outer object.
    """

    def __init__(self, path: str = "./audit/audit.log", rotate_mb: int = 50, *, cfg: Optional[AuditLedgerConfig] = None):
        if cfg is None:
            cfg = AuditLedgerConfig(path=path, rotate_mb=rotate_mb)
        self._cfg = cfg

        if not cfg.path:
            raise AuditConfigError("AuditLedgerConfig.path must be non-empty")
        self.path = str(cfg.path)

        self.rotate_bytes = int(cfg.rotate_mb) * 1024 * 1024 if int(cfg.rotate_mb) > 0 else 0

        ds = int(cfg.digest_size)
        if ds <= 0 or ds > 32:
            raise AuditConfigError("AuditLedgerConfig.digest_size must be in [1, 32]")
        self._digest_size = ds

        self._hash_ctx_bytes = (cfg.hash_ctx or "tcd:audit_ledger").encode("utf-8")
        self._record_format = (cfg.record_format or "jsonl").lower().strip()
        if self._record_format not in ("jsonl", "framed_v1"):
            raise AuditConfigError("AuditLedgerConfig.record_format must be 'jsonl' or 'framed_v1'")

        if cfg.fsync_required and not cfg.sync_on_write:
            raise AuditConfigError("fsync_required=True requires sync_on_write=True")

        if int(cfg.fsync_every_n) < 1:
            raise AuditConfigError("fsync_every_n must be >= 1")

        if cfg.fsync_required and (int(cfg.fsync_every_n) != 1 or int(cfg.fsync_interval_ms) != 0):
            raise AuditConfigError("fsync_required=True disallows group commit (fsync_every_n/interval must be strict)")

        self._mac_key: Optional[bytes] = None
        if cfg.mac_key_hex:
            hex_s = cfg.mac_key_hex.strip().replace(" ", "")
            try:
                kb = bytes.fromhex(hex_s)
            except Exception as e:
                raise AuditConfigError("mac_key_hex must be valid hex") from e
            if len(kb) == 0:
                raise AuditConfigError("mac_key_hex must not be empty")
            if len(kb) > 32:
                raise AuditConfigError("mac_key_hex decoded length must be <= 32 bytes for blake2s")
            self._mac_key = kb

        if cfg.enable_hash_self_test:
            self._hash_self_test()

        # stable policy digest
        try:
            self._ledger_policy_digest: Optional[str] = cfg.policy_digest()
        except Exception:
            self._ledger_policy_digest = None

        # concurrency primitives
        self._lock = threading.RLock()
        self._gate = _AdmissionGate(cfg.admission_gate)
        self._dedupe = _DedupeMap(cfg.dedupe_cache_size)

        # file handles
        self._fd: Optional[int] = None
        self._file_stat: Optional[os.stat_result] = None
        self._file_sig: Optional[Tuple[int, int]] = None  # (st_dev, st_ino) best-effort
        self._bytes_written: int = 0

        # ledger chain state
        self._prev: str = "0" * (self._digest_size * 2)  # public head chain
        self._seq: int = -1

        # segment metadata
        self._segment_start_seq: Optional[int] = None
        self._segment_start_ts_ns: Optional[int] = None
        self._segment_start_head: Optional[str] = None
        self._segment_start_prev: Optional[str] = None
        self._segment_last_seq: Optional[int] = None
        self._segment_last_ts_ns: Optional[int] = None
        self._segment_last_head_mac: Optional[str] = None

        # resumable segment digest (rolling hash over heads)
        self._segment_digest: str = self._segment_digest_seed()

        # fsync bookkeeping (group commit)
        self._append_since_fsync: int = 0
        self._last_fsync_mono: float = time.monotonic()

        # health / warnings
        self._recovery_warning: Optional[str] = None
        self._last_error: Optional[str] = None

        # process lock
        self._proc_lock_fd: Optional[int] = None
        if cfg.enable_process_lock:
            self._acquire_process_lock()

        # ensure directory exists
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)

        # open + recover + repair tail boundary
        with self._lock:
            self._open_and_recover()

    # ------------------------------------------------------------------ #
    # Hashing                                                             #
    # ------------------------------------------------------------------ #

    def _hash_self_test(self) -> None:
        expected = "a71079d42853dea26e453004338670a53814b78137ffbed07603a41d76a483aa"
        got = blake2s(b"test").hexdigest()
        if got != expected:
            raise AuditConfigError("AuditLedger hash self-test failed")

    def _hash_public(self, body: str) -> str:
        data = body.encode("utf-8")
        h = blake2s(digest_size=self._digest_size)
        h.update(self._hash_ctx_bytes)
        h.update(b"\x00")
        h.update(data)
        return h.hexdigest()

    def _hash_mac(self, body: str) -> Optional[str]:
        if self._mac_key is None:
            return None
        data = body.encode("utf-8")
        h = blake2s(digest_size=self._digest_size, key=self._mac_key)
        h.update(self._hash_ctx_bytes)
        h.update(b"\x00")
        h.update(data)
        return h.hexdigest()

    def _segment_digest_seed(self) -> str:
        h = sha256()
        h.update(b"tcd:segment_digest")
        h.update(b"\x00")
        h.update(self._hash_ctx_bytes)
        h.update(b"\x00")
        h.update(_u32be(self._digest_size))
        return h.hexdigest()

    def _segment_digest_step(self, seg_digest_hex: str, head_hex: str) -> str:
        h = sha256()
        h.update(b"tcd:segment_digest_step")
        h.update(b"\x00")
        h.update(bytes.fromhex(seg_digest_hex))
        h.update(b"\x00")
        h.update(head_hex.encode("ascii"))
        return h.hexdigest()

    # ------------------------------------------------------------------ #
    # Process lock                                                        #
    # ------------------------------------------------------------------ #

    def _acquire_process_lock(self) -> None:
        cfg = self._cfg
        lock_path = cfg.effective_process_lock_path()
        os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)

        def _try_break_stale() -> None:
            if not cfg.process_lock_break_stale or float(cfg.process_lock_stale_after_s) <= 0:
                return
            try:
                st = os.stat(lock_path)
                age = time.time() - float(st.st_mtime)
                if age >= float(cfg.process_lock_stale_after_s):
                    os.remove(lock_path)
            except Exception:
                return

        timeout_s = max(0.0, float(cfg.process_lock_timeout_s))
        poll_s = max(0.01, float(cfg.process_lock_poll_s))
        deadline = time.monotonic() + timeout_s

        while True:
            _try_break_stale()
            try:
                # Create/open lock file securely
                flags = os.O_CREAT | os.O_RDWR
                if getattr(os, "O_CLOEXEC", 0):
                    flags |= getattr(os, "O_CLOEXEC")
                fd, _st = _safe_open_regular_file(
                    lock_path,
                    flags=flags,
                    mode=int(cfg.file_mode),
                    require_regular=True,
                    require_nlink_one=False,
                    allowed_root_dir=cfg.allowed_root_dir,
                )
                # Ensure file has at least 1 byte for some lock backends
                try:
                    if os.fstat(fd).st_size == 0:
                        _write_all(fd, b"\x00")
                except Exception:
                    pass

                # Preferred backends
                if fcntl is not None:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        self._proc_lock_fd = fd
                        return
                    except Exception:
                        os.close(fd)
                        raise

                if msvcrt is not None:
                    try:
                        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                        self._proc_lock_fd = fd
                        return
                    except Exception:
                        os.close(fd)
                        raise

                # Fallback: exclusive create lock (best-effort)
                try:
                    os.close(fd)
                except Exception:
                    pass
                flags2 = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                if getattr(os, "O_CLOEXEC", 0):
                    flags2 |= getattr(os, "O_CLOEXEC")
                fd2 = os.open(lock_path, flags2, int(cfg.file_mode))
                payload = _canonical_json({"v": 1, "pid": os.getpid(), "ts": time.time()}).encode("utf-8")
                _write_all(fd2, payload)
                self._proc_lock_fd = fd2
                return

            except Exception:
                if cfg.require_process_lock_backend:
                    raise AuditConfigError("process lock backend unavailable or lock held")
                if timeout_s <= 0:
                    raise AuditConfigError("process lock already held")
                if time.monotonic() >= deadline:
                    raise AuditConfigError("process lock timeout")
                time.sleep(poll_s)

    # ------------------------------------------------------------------ #
    # Index / State atomic writes                                          #
    # ------------------------------------------------------------------ #

    def _atomic_write_json(self, path: str, obj: Dict[str, Any], *, mode: int, fsync_dir: bool) -> None:
        tmp = path + ".tmp"
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        fd = None
        try:
            fd, _ = _safe_open_regular_file(
                tmp,
                flags=os.O_CREAT | os.O_TRUNC | os.O_WRONLY,
                mode=mode,
                require_regular=True,
                require_nlink_one=False,
                allowed_root_dir=self._cfg.allowed_root_dir,
            )
            data = (_canonical_json(obj) + "\n").encode("utf-8")
            _write_all(fd, data)
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.replace(tmp, path)
            if fsync_dir:
                _fsync_dir_for_path(path, required=self._cfg.dir_fsync_required)
        except Exception as e:
            try:
                if fd is not None:
                    os.close(fd)
            except Exception:
                pass
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
            raise AuditIOError(f"atomic write failed: {_safe_text(e, max_len=200)}") from e

    def _load_json_file(self, path: str) -> Optional[Dict[str, Any]]:
        try:
            with open(path, "rb") as fh:
                raw = fh.read()
            obj = json.loads(raw.decode("utf-8"))
            if isinstance(obj, dict):
                return obj
        except Exception:
            return None
        return None

    # ------------------------------------------------------------------ #
    # Index management                                                     #
    # ------------------------------------------------------------------ #

    def _load_index(self) -> Dict[str, Any]:
        idx_path = self._cfg.effective_index_path()
        obj = self._load_json_file(idx_path)
        if not obj:
            return {"v": 2, "segments": [], "root_digest": ""}
        segs = obj.get("segments")
        if not isinstance(segs, list):
            segs = []
        root = obj.get("root_digest")
        if not isinstance(root, str):
            root = ""
        v = obj.get("v")
        if not isinstance(v, int):
            v = 2
        return {"v": v, "segments": segs, "root_digest": root}

    def _index_root_digest(self, segments: List[Dict[str, Any]]) -> str:
        seg_json = _canonical_json(segments).encode("utf-8")
        h = sha256()
        h.update(b"tcd:audit_index")
        h.update(b"\x00")
        h.update(seg_json)
        return h.hexdigest()

    def _update_index(self, seg_entry: Dict[str, Any]) -> str:
        if not self._cfg.enable_index:
            return ""
        idx = self._load_index()
        segs = idx.get("segments")
        if not isinstance(segs, list):
            segs = []
        segs.append(seg_entry)
        idx["segments"] = segs
        idx["root_digest"] = self._index_root_digest(segs)
        self._atomic_write_json(
            self._cfg.effective_index_path(),
            idx,
            mode=int(self._cfg.file_mode),
            fsync_dir=True,
        )
        return str(idx["root_digest"])

    # ------------------------------------------------------------------ #
    # State file                                                          #
    # ------------------------------------------------------------------ #

    def _state_mac(self, payload: Dict[str, Any]) -> str:
        raw = _canonical_json(payload).encode("utf-8")
        if self._mac_key is not None:
            h = blake2s(digest_size=16, key=self._mac_key)
            h.update(b"tcd:audit_state")
            h.update(b"\x00")
            h.update(raw)
            return h.hexdigest()
        h2 = sha256()
        h2.update(b"tcd:audit_state")
        h2.update(b"\x00")
        h2.update(raw)
        return h2.hexdigest()

    def _load_state(self) -> Optional[Dict[str, Any]]:
        if not self._cfg.enable_state:
            return None
        return self._load_json_file(self._cfg.effective_state_path())

    def _write_state(self) -> None:
        if not self._cfg.enable_state:
            return
        path = self._cfg.effective_state_path()
        st = self._file_stat
        sig = None
        if st is not None:
            sig = {"dev": int(getattr(st, "st_dev", 0)), "ino": int(getattr(st, "st_ino", 0))}
        payload: Dict[str, Any] = {
            "v": 2,
            "path": os.path.basename(self.path),
            "format": self._record_format,
            "file_sig": sig,
            "file_size": int(self._bytes_written),
            "seq": int(self._seq),
            "head": str(self._prev),
            "segment_start_seq": self._segment_start_seq,
            "segment_start_head": self._segment_start_head,
            "segment_start_prev": self._segment_start_prev,
            "segment_digest": str(self._segment_digest),
            "updated_ts": time.time(),
        }
        payload["mac"] = self._state_mac(payload)

        self._atomic_write_json(
            path,
            payload,
            mode=int(self._cfg.file_mode),
            fsync_dir=bool(self._cfg.state_fsync),
        )

    # ------------------------------------------------------------------ #
    # Tail repair / recovery                                               #
    # ------------------------------------------------------------------ #

    def _parse_outer_json_bytes(self, outer_bytes: bytes) -> Optional[Dict[str, Any]]:
        try:
            outer = json.loads(outer_bytes.decode("utf-8"))
        except Exception:
            return None
        if not isinstance(outer, dict):
            return None
        if not isinstance(outer.get("head"), str) or not outer.get("head"):
            return None
        if not isinstance(outer.get("body"), str) or not outer.get("body"):
            return None
        return outer

    def _parse_inner_meta(self, body_str: str) -> Tuple[Optional[int], Optional[int], Optional[str]]:
        try:
            inner = json.loads(body_str)
        except Exception:
            return (None, None, None)
        if not isinstance(inner, dict):
            return (None, None, None)
        seq = inner.get("seq")
        ts_ns = inner.get("ts_ns")
        prev = inner.get("prev")
        return (
            int(seq) if isinstance(seq, int) else None,
            int(ts_ns) if isinstance(ts_ns, int) else None,
            str(prev) if isinstance(prev, str) else None,
        )

    def _recover_jsonl_and_repair(self, *, fd_rw: int, file_size: int) -> Tuple[bool, int]:
        """
        Returns (ok, truncate_to_offset).
        If ok=False, no valid record was found.
        """
        cfg = self._cfg
        tail_bytes = min(max(1, int(cfg.recover_tail_bytes)), int(file_size))
        base = int(file_size) - int(tail_bytes)

        try:
            os.lseek(fd_rw, base, os.SEEK_SET)
            tail = os.read(fd_rw, tail_bytes)
        except Exception as e:
            raise AuditIOError(f"tail read failed: {_safe_text(e, max_len=200)}") from e

        # find lines with offsets
        lines: List[Tuple[int, int]] = []  # (start, end_exclusive) within tail
        start = 0
        for i, b in enumerate(tail):
            if b == 0x0A:  # \n
                lines.append((start, i))
                start = i + 1
        # last fragment (may be empty)
        if start < len(tail):
            lines.append((start, len(tail)))
        elif start == len(tail) and len(tail) > 0 and tail[-1] == 0x0A:
            pass

        candidates: List[Tuple[str, int, int, Optional[int], Optional[int], Optional[str], Optional[str]]] = []
        # tuple: (head, offset_end_abs, has_newline, seq, ts_ns, prev, head_mac)
        for (s, e) in reversed(lines):
            if e <= s:
                continue
            line_bytes = tail[s:e]
            outer = self._parse_outer_json_bytes(line_bytes)
            if not outer:
                continue
            body = str(outer.get("body"))
            head = str(outer.get("head"))
            head_mac = outer.get("head_mac") if isinstance(outer.get("head_mac"), str) else None

            if cfg.verify_tail:
                try:
                    if head != self._hash_public(body):
                        continue
                    if self._mac_key is not None and head_mac is not None:
                        mac2 = self._hash_mac(body)
                        if mac2 is not None and mac2 != head_mac:
                            continue
                except Exception:
                    continue

            seq, ts_ns, prev = self._parse_inner_meta(body)
            # determine absolute end offset:
            # if this line ended at a newline in tail, then end_abs = base + e + 1
            # else it's end of file fragment; we will either truncate or add newline later.
            has_nl = 0
            if e < len(tail) and e >= 0:
                # line ended at newline delimiter in scan; only true if original tail had \n at position e
                # (we split at \n but removed it, so if next char exists and was \n, then line ended with \n)
                pass
            # we know delimiter at index e is \n if e < len(tail) and tail[e] == \n, but e is exclusive (points to \n)
            if e < len(tail) and tail[e:e+1] == b"\n":  # defensive
                has_nl = 1
            # better: in our construction, a line (s,e) where e is i at which tail[i] == '\n'
            # so has_nl is true when e < len(tail) and tail[e] == '\n' (not included)
            if e < len(tail) and e < len(tail) and (e < len(tail) and e >= 0) and (e < len(tail) and tail[e:e+1] == b"\n"):
                has_nl = 1

            # But because we stored e as index of '\n', the correct condition is: e < len(tail) and tail[e] == '\n'.
            if e < len(tail) and tail[e] == 0x0A:
                has_nl = 1

            end_abs = base + e + (1 if has_nl else 0)
            candidates.append((head, end_abs, has_nl, seq, ts_ns, prev, head_mac))
            if len(candidates) >= 256:
                break

        if not candidates:
            return (False, 0)

        # Optional tail-chain verification on recovered window
        chain = list(reversed(candidates))  # oldest->newest in this window
        if cfg.verify_tail_chain:
            best: List[Tuple[str, int, int, Optional[int], Optional[int], Optional[str], Optional[str]]] = []
            cur: List[Tuple[str, int, int, Optional[int], Optional[int], Optional[str], Optional[str]]] = []
            for rec in chain:
                if not cur:
                    cur = [rec]
                    continue
                prev_expect = cur[-1][0]
                prev_field = rec[5]
                if prev_field == prev_expect:
                    cur.append(rec)
                else:
                    if len(cur) > len(best):
                        best = cur
                    cur = [rec]
            if len(cur) > len(best):
                best = cur
            if best:
                chain = best

        last = chain[-1]
        head_hex, end_abs, has_nl, seq, ts_ns, prev, head_mac = last

        # repair tail: truncate after last valid line bytes
        truncate_to = int(end_abs)
        # If last valid line did not end with newline and is at end of file, we can add a newline instead of truncation.
        # But if there is trailing garbage after end_abs, truncation will remove it anyway.
        return (True, truncate_to)

    def _recover_framed_and_repair(self, *, fd_rw: int, file_size: int) -> Tuple[bool, int]:
        cfg = self._cfg
        magic = cfg.framed_magic
        crc_on = bool(cfg.framed_enable_crc32)

        # sequential scan; stop at first incomplete/bad frame; truncate to last_good_off
        off = 0
        last_good_off = 0
        ok_any = False

        while off < file_size:
            try:
                os.lseek(fd_rw, off, os.SEEK_SET)
            except Exception as e:
                raise AuditIOError(f"seek failed: {_safe_text(e, max_len=200)}") from e

            hdr = _read_exact(fd_rw, 8)
            if hdr is None:
                break
            if len(hdr) < 8:
                break
            if hdr[:4] != magic:
                # cannot resync safely; stop
                break
            ln = struct.unpack(">I", hdr[4:8])[0]
            if ln <= 0 or ln > int(cfg.max_line_bytes):
                break
            payload = _read_exact(fd_rw, ln)
            if payload is None or len(payload) < ln:
                break
            if crc_on:
                crc_bytes = _read_exact(fd_rw, 4)
                if crc_bytes is None or len(crc_bytes) < 4:
                    break
                crc_stored = struct.unpack(">I", crc_bytes)[0]
                crc_calc = zlib.crc32(payload) & 0xFFFFFFFF
                if crc_calc != crc_stored:
                    break

            outer = self._parse_outer_json_bytes(payload)
            if not outer:
                break

            body = str(outer.get("body"))
            head = str(outer.get("head"))
            head_mac = outer.get("head_mac") if isinstance(outer.get("head_mac"), str) else None
            if cfg.verify_tail:
                try:
                    if head != self._hash_public(body):
                        break
                    if self._mac_key is not None and head_mac is not None:
                        mac2 = self._hash_mac(body)
                        if mac2 is not None and mac2 != head_mac:
                            break
                except Exception:
                    break

            seq, ts_ns, prev = self._parse_inner_meta(body)
            if isinstance(seq, int):
                self._seq = seq
                self._segment_last_seq = seq
            if isinstance(ts_ns, int):
                self._segment_last_ts_ns = ts_ns
            self._prev = head
            self._segment_last_head_mac = head_mac if head_mac else self._segment_last_head_mac
            ok_any = True

            # advance
            frame_len = 8 + ln + (4 if crc_on else 0)
            off += frame_len
            last_good_off = off

        return (ok_any, int(last_good_off))

    def _truncate_file(self, fd_rw: int, to_off: int) -> None:
        try:
            os.ftruncate(fd_rw, int(to_off))
        except Exception as e:
            raise AuditIOError(f"truncate failed: {_safe_text(e, max_len=200)}") from e

    def _open_and_recover(self) -> None:
        """
        Open the active file for append, recover head/seq, and repair tail.
        """
        cfg = self._cfg

        # Open RW for recovery/repair (so we can truncate).
        fd_rw, st = _safe_open_regular_file(
            self.path,
            flags=os.O_CREAT | os.O_RDWR,
            mode=int(cfg.file_mode),
            require_regular=bool(cfg.require_regular_file),
            require_nlink_one=bool(cfg.require_nlink_one),
            allowed_root_dir=cfg.allowed_root_dir,
        )

        try:
            file_size = int(st.st_size)
            # Detect discontinuity: file is empty but we already had seq state (should only happen if external truncation or replacement)
            if file_size == 0 and self._seq >= 0:
                msg = "ledger file became empty while in-memory state had history"
                self._recovery_warning = msg
                if cfg.strict_discontinuity:
                    raise AuditDiscontinuityDetected(msg)
                # Reset chain
                self._prev = "0" * (self._digest_size * 2)
                self._seq = -1
                self._segment_start_seq = None
                self._segment_start_ts_ns = None
                self._segment_start_head = None
                self._segment_start_prev = None
                self._segment_last_seq = None
                self._segment_last_ts_ns = None
                self._segment_digest = self._segment_digest_seed()

            ok = True
            truncate_to = file_size
            if file_size > 0:
                if self._record_format == "jsonl":
                    ok, truncate_to = self._recover_jsonl_and_repair(fd_rw=fd_rw, file_size=file_size)
                else:
                    ok, truncate_to = self._recover_framed_and_repair(fd_rw=fd_rw, file_size=file_size)

                if not ok:
                    self._recovery_warning = "unable to recover any valid record (corrupt tail or policy mismatch)"
                    if cfg.strict_recovery:
                        raise AuditRecoveryError(self._recovery_warning)

                # Truncate to last-good boundary if needed
                if truncate_to < file_size:
                    self._truncate_file(fd_rw, truncate_to)
                    file_size = truncate_to

                # For JSONL: ensure newline boundary to prevent poisoning
                if self._record_format == "jsonl" and file_size > 0:
                    try:
                        os.lseek(fd_rw, file_size - 1, os.SEEK_SET)
                        lastb = os.read(fd_rw, 1)
                        if lastb != b"\n":
                            # append a newline safely (still within repair phase)
                            os.lseek(fd_rw, 0, os.SEEK_END)
                            _write_all(fd_rw, b"\n")
                            file_size += 1
                    except Exception as e:
                        raise AuditIOError(f"newline repair failed: {_safe_text(e, max_len=200)}") from e

            # close recovery fd and open append-only fd
            try:
                os.close(fd_rw)
            except Exception:
                pass
            fd_rw = -1  # type: ignore[assignment]

            fd, st2 = _safe_open_regular_file(
                self.path,
                flags=os.O_CREAT | os.O_APPEND | os.O_WRONLY,
                mode=int(cfg.file_mode),
                require_regular=bool(cfg.require_regular_file),
                require_nlink_one=bool(cfg.require_nlink_one),
                allowed_root_dir=cfg.allowed_root_dir,
            )
            self._fd = fd
            self._file_stat = st2
            self._file_sig = (int(getattr(st2, "st_dev", 0)), int(getattr(st2, "st_ino", 0)))
            self._bytes_written = int(os.fstat(fd).st_size)

            # Recover current segment start metadata (best-effort)
            self._recover_segment_start()

            # Load/validate state (rollback detection)
            self._check_state_for_rollback()

        finally:
            if fd_rw not in (None, -1):
                try:
                    os.close(fd_rw)  # type: ignore[arg-type]
                except Exception:
                    pass

    def _recover_segment_start(self) -> None:
        """
        Best-effort: scan the first few valid records to recover segment start fields.
        """
        if self._segment_start_seq is not None and self._segment_start_ts_ns is not None and self._segment_start_head and self._segment_start_prev is not None:
            return
        if self._fd is None:
            return
        max_lines = max(1, int(self._cfg.recover_head_scan_lines))

        try:
            with open(self.path, "rb") as rf:
                prev0 = "0" * (self._digest_size * 2)
                for _ in range(max_lines):
                    raw = rf.readline()
                    if not raw:
                        break
                    line = raw.rstrip(b"\r\n")
                    outer = self._parse_outer_json_bytes(line) if self._record_format == "jsonl" else None
                    if outer is None:
                        continue
                    body = str(outer.get("body"))
                    head = str(outer.get("head"))
                    if self._cfg.verify_tail and head != self._hash_public(body):
                        continue
                    seq, ts_ns, prev = self._parse_inner_meta(body)
                    if isinstance(seq, int) and isinstance(ts_ns, int) and isinstance(prev, str):
                        self._segment_start_seq = seq
                        self._segment_start_ts_ns = ts_ns
                        self._segment_start_head = head
                        self._segment_start_prev = prev
                        if self._segment_last_seq is None:
                            self._segment_last_seq = seq
                        if self._segment_last_ts_ns is None:
                            self._segment_last_ts_ns = ts_ns
                        if self._segment_start_prev is None:
                            self._segment_start_prev = prev0
                        return
        except Exception:
            return

    def _check_state_for_rollback(self) -> None:
        cfg = self._cfg
        if not cfg.enable_state:
            return
        st = self._load_state()
        if not st:
            return
        try:
            mac = st.get("mac")
            st2 = dict(st)
            st2.pop("mac", None)
            if isinstance(mac, str) and mac != self._state_mac(st2):
                # tampered state
                if cfg.strict_rollback:
                    raise AuditRollbackDetected("state file MAC mismatch")
                return
        except Exception as e:
            if cfg.strict_rollback:
                raise AuditRollbackDetected(_safe_text(e, max_len=200)) from e
            return

        # Compare state with recovered head/seq. If state claims a later seq/head than current, it's a rollback.
        try:
            seq_s = st.get("seq")
            head_s = st.get("head")
            if isinstance(seq_s, int) and isinstance(head_s, str):
                if self._seq < seq_s and self._seq >= 0:
                    msg = f"ledger rollback detected (seq {self._seq} < state {seq_s})"
                    self._recovery_warning = msg
                    if cfg.strict_rollback:
                        raise AuditRollbackDetected(msg)
                if self._seq == seq_s and self._prev != head_s:
                    msg = "ledger head mismatch vs state"
                    self._recovery_warning = msg
                    if cfg.strict_rollback:
                        raise AuditRollbackDetected(msg)
        except AuditRollbackDetected:
            raise
        except Exception:
            return

    # ------------------------------------------------------------------ #
    # Public API                                                          #
    # ------------------------------------------------------------------ #

    def head(self) -> str:
        with self._lock:
            return self._prev

    def seq(self) -> int:
        with self._lock:
            return int(self._seq)

    def recovery_warning(self) -> Optional[str]:
        with self._lock:
            return self._recovery_warning

    def runtime_status(self) -> Dict[str, Any]:
        with self._lock:
            size = None
            try:
                if self._fd is not None:
                    size = int(os.fstat(self._fd).st_size)
            except Exception:
                size = None
            return {
                "path": self.path,
                "format": self._record_format,
                "seq": int(self._seq),
                "head": self._prev,
                "file_size": size,
                "bytes_written": int(self._bytes_written),
                "rotate_bytes": int(self.rotate_bytes),
                "segment_start_seq": self._segment_start_seq,
                "segment_last_seq": self._segment_last_seq,
                "segment_digest": self._segment_digest,
                "policy_digest": self._ledger_policy_digest,
                "recovery_warning": self._recovery_warning,
                "last_error": self._last_error,
            }

    def append(self, record: Dict[str, Any], *, ts_ns: Optional[int] = None, policy_overrides: Optional[Dict[str, Optional[str]]] = None) -> str:
        return self.append_ex(record, ts_ns=ts_ns, policy_overrides=policy_overrides).head

    def append_ex(
        self,
        record: Dict[str, Any],
        *,
        ts_ns: Optional[int] = None,
        policy_overrides: Optional[Dict[str, Optional[str]]] = None,
        stage: Optional[str] = None,  # e.g., "prepare" | "commit"
    ) -> AppendResult:
        cfg = self._cfg
        if ts_ns is None:
            ts_ns = time.time_ns()

        if not isinstance(record, dict):
            raise AuditConfigError("append record must be a dict")

        if not self._gate.try_acquire():
            raise AuditOverloadedError("admission gate full")

        try:
            if cfg.record_validator is not None:
                cfg.record_validator(record)

            # lock (optional timeout)
            timeout = cfg.append_lock_timeout_s
            if timeout is None:
                acquired = self._lock.acquire()
            else:
                acquired = self._lock.acquire(timeout=max(0.0, float(timeout)))
            if not acquired:
                raise AuditLockTimeoutError("lock acquisition timed out")

            try:
                if self._fd is None:
                    self._open_and_recover()
                if self._fd is None:
                    raise AuditIOError("file descriptor unavailable")

                # Dedupe (correct, under lock)
                duplicated = False
                if cfg.dedupe_cache_size > 0 and cfg.dedupe_key_path:
                    dk = _get_by_dot_path(record, cfg.dedupe_key_path)
                    if dk is not None:
                        dk_s = _safe_text(dk, max_len=256)
                        if dk_s:
                            old = self._dedupe.get(dk_s)
                            if old is not None:
                                return AppendResult(head=str(old), seq=int(self._seq), ts_ns=int(ts_ns), duplicated=True)

                # Build policy block
                policy_block: Dict[str, Any] = {}
                if cfg.include_policy_block and self._ledger_policy_digest:
                    policy_block["ledger_policy"] = self._ledger_policy_digest
                    overrides = policy_overrides or {}

                    def _ov(key: str, default: Optional[str]) -> Optional[str]:
                        val = overrides.get(key, default)
                        if val is None:
                            return None
                        return _safe_text(val, max_len=256)

                    ap = _ov("auth_policy", cfg.default_auth_policy)
                    if ap:
                        policy_block["auth_policy"] = ap
                    cp = _ov("calib_policy", cfg.default_calib_policy)
                    if cp:
                        policy_block["calib_policy"] = cp
                    cap = _ov("chain_audit_policy", cfg.default_chain_audit_policy)
                    if cap:
                        policy_block["chain_audit_policy"] = cap
                    cd = _ov("cfg_digest", cfg.default_cfg_digest)
                    if cd:
                        policy_block["cfg_digest"] = cd

                # Origin
                origin_block: Dict[str, Any] = {}
                if cfg.node_id:
                    origin_block["node_id"] = _safe_text(cfg.node_id, max_len=128)
                if cfg.proc_id:
                    origin_block["proc_id"] = _safe_text(cfg.proc_id, max_len=256)

                # Payload sanitize + budgets
                payload_obj: Any = record
                if cfg.sanitize_payload:
                    budget = _SanitizeBudget(
                        max_nodes=int(cfg.max_nodes),
                        max_total_str_bytes=int(cfg.max_total_str_bytes),
                        max_total_bytes=int(cfg.max_total_bytes),
                    )
                    payload_obj = _sanitize_json_like(
                        record,
                        max_depth=int(cfg.max_payload_depth),
                        max_items=int(cfg.max_payload_items),
                        max_key_len=int(cfg.max_key_len),
                        max_str_len=int(cfg.max_str_len),
                        max_str_bytes=int(cfg.max_str_bytes),
                        redact=bool(cfg.redact_secrets),
                        redact_key_pred=_default_redact_key_pred,
                        budget=budget,
                        seen=set(),
                    )

                # Inner body (signature is OUTER to avoid circularity)
                prev_head = self._prev
                seq_val = self._seq + 1

                inner: Dict[str, Any] = {
                    "v": 2,
                    "ts_ns": int(ts_ns),
                    "seq": int(seq_val),
                    "prev": str(prev_head),
                    "payload": payload_obj,
                }
                if origin_block:
                    inner["origin"] = origin_block
                if policy_block:
                    inner["policy"] = policy_block
                if stage:
                    inner["stage"] = _safe_text(stage, max_len=32)

                body = _canonical_json(inner)
                body_bytes = body.encode("utf-8")
                if cfg.max_record_bytes > 0 and len(body_bytes) > int(cfg.max_record_bytes):
                    raise AuditConfigError("record too large (max_record_bytes)")

                head = self._hash_public(body)
                head_mac = self._hash_mac(body)

                # Outer object (signature outside body)
                outer: Dict[str, Any] = {"head": head, "body": body}
                if head_mac is not None:
                    outer["head_mac"] = head_mac

                # Optional signature (sign body or head)
                if cfg.sign_func is not None and cfg.sig_alg:
                    sign_over = (cfg.sign_over or "body").lower().strip()
                    if sign_over not in ("body", "head"):
                        raise AuditConfigError("sign_over must be 'body' or 'head'")
                    signed_bytes = body_bytes if sign_over == "body" else head.encode("ascii")
                    try:
                        sig_bytes = cfg.sign_func(signed_bytes)
                    except Exception as e:
                        raise AuditIOError(f"sign_func failed: {_safe_text(e, max_len=200)}") from e
                    if not isinstance(sig_bytes, (bytes, bytearray)):
                        raise AuditConfigError("sign_func must return bytes")
                    if cfg.max_signature_bytes > 0 and len(sig_bytes) > int(cfg.max_signature_bytes):
                        raise AuditConfigError("signature too large")
                    sig_val = b64encode(bytes(sig_bytes)).decode("ascii")
                    sig_block: Dict[str, Any] = {"alg": _safe_text(cfg.sig_alg, max_len=64), "val": sig_val, "signed_over": sign_over}
                    if cfg.sig_key_id:
                        sig_block["key_id"] = _safe_text(cfg.sig_key_id, max_len=128)
                    outer["sig"] = sig_block

                # Serialize outer
                outer_json = _canonical_json(outer).encode("utf-8")

                if cfg.max_line_bytes > 0 and len(outer_json) > int(cfg.max_line_bytes):
                    raise AuditConfigError("outer record too large (max_line_bytes)")

                # Pre-rotation decision (based on actual file size)
                rotated = False
                if self.rotate_bytes > 0:
                    try:
                        cur_size = int(os.fstat(self._fd).st_size)
                    except Exception:
                        cur_size = int(self._bytes_written)
                    # if record wouldn't fit in current segment and current segment is non-empty, rotate first
                    if cur_size > 0 and (cur_size + len(outer_json) + (1 if self._record_format == "jsonl" else 0)) > self.rotate_bytes:
                        rotated = self._rotate_before_write()

                # Optional segment marker (only after rotation, before writing user record)
                if rotated and cfg.include_segment_markers:
                    self._write_segment_marker(prev_segment_last_head=prev_head)

                # Write record (transactional I/O)
                fsync_ok = True
                try:
                    self._write_record_bytes(outer_json)
                    # Commit state AFTER successful write/flush/fsync (as configured)
                    self._seq = int(seq_val)
                    self._prev = str(head)
                    self._segment_last_seq = int(seq_val)
                    self._segment_last_ts_ns = int(ts_ns)
                    self._segment_last_head_mac = head_mac or self._segment_last_head_mac
                    if self._segment_start_seq is None:
                        self._segment_start_seq = int(seq_val)
                        self._segment_start_ts_ns = int(ts_ns)
                        self._segment_start_head = str(head)
                        self._segment_start_prev = str(prev_head)
                        self._segment_digest = self._segment_digest_seed()
                    self._segment_digest = self._segment_digest_step(self._segment_digest, str(head))

                    # Dedupe map update AFTER commit
                    if cfg.dedupe_cache_size > 0 and cfg.dedupe_key_path:
                        dk = _get_by_dot_path(record, cfg.dedupe_key_path)
                        if dk is not None:
                            dk_s = _safe_text(dk, max_len=256)
                            if dk_s:
                                self._dedupe.put(dk_s, str(head))

                    # State update best-effort (but strict_rollback wants it stable)
                    try:
                        self._write_state()
                    except Exception as e:
                        # state write failure should not break append unless strict IO semantics required
                        self._last_error = f"state_write_failed:{_safe_text(e, max_len=200)}"
                        if cfg.fsync_required:
                            raise

                except Exception as e:
                    self._last_error = f"append_failed:{_safe_text(e, max_len=200)}"
                    raise

                return AppendResult(head=str(head), seq=int(seq_val), ts_ns=int(ts_ns), duplicated=duplicated, rotated=rotated, fsync_ok=fsync_ok)

            finally:
                try:
                    self._lock.release()
                except Exception:
                    pass

        finally:
            self._gate.release()

    # ------------------------------------------------------------------ #
    # Low-level record writing                                             #
    # ------------------------------------------------------------------ #

    def _maybe_fsync(self) -> None:
        cfg = self._cfg
        if not cfg.sync_on_write or self._fd is None:
            return

        self._append_since_fsync += 1
        do_fsync = False

        if int(cfg.fsync_every_n) <= 1:
            do_fsync = True
        else:
            if self._append_since_fsync >= int(cfg.fsync_every_n):
                do_fsync = True

        if int(cfg.fsync_interval_ms) > 0:
            now = time.monotonic()
            if (now - self._last_fsync_mono) * 1000.0 >= float(cfg.fsync_interval_ms):
                do_fsync = True

        if not do_fsync:
            return

        try:
            os.fsync(self._fd)
            self._append_since_fsync = 0
            self._last_fsync_mono = time.monotonic()
        except Exception as e:
            if cfg.fsync_required:
                raise AuditIOError(f"fsync failed: {_safe_text(e, max_len=200)}") from e

    def _write_record_bytes(self, outer_json: bytes) -> None:
        """
        Write one record in the configured format, with transactional semantics.
        """
        if self._fd is None:
            raise AuditIOError("fd missing")

        cfg = self._cfg

        if self._record_format == "jsonl":
            data = outer_json + b"\n"
            _write_all(self._fd, data)
            self._bytes_written += len(data)
            self._maybe_fsync()
            return

        # framed_v1
        magic = cfg.framed_magic
        payload = outer_json
        ln = len(payload)
        if ln <= 0:
            raise AuditIOError("empty payload")
        header = magic + _u32be(ln)
        frame = header + payload
        if cfg.framed_enable_crc32:
            crc = zlib.crc32(payload) & 0xFFFFFFFF
            frame += _u32be(crc)
        _write_all(self._fd, frame)
        self._bytes_written += len(frame)
        self._maybe_fsync()

    # ------------------------------------------------------------------ #
    # Rotation (pre-write)                                                 #
    # ------------------------------------------------------------------ #

    def _rotate_before_write(self) -> bool:
        """
        Rotate current segment BEFORE writing the next record.
        Returns True if rotation succeeded.
        """
        if self.rotate_bytes <= 0 or self._fd is None:
            return False

        cfg = self._cfg

        # Close current writer
        try:
            if cfg.sync_on_rotate:
                try:
                    os.fsync(self._fd)
                except Exception as e:
                    if cfg.fsync_required:
                        raise AuditIOError(f"rotate fsync failed: {_safe_text(e, max_len=200)}") from e
            os.close(self._fd)
        except Exception:
            try:
                os.close(self._fd)
            except Exception:
                pass
        self._fd = None

        # Build unique rotated filename
        ts_ns = time.time_ns()
        pid = os.getpid()
        head_prefix = (self._prev or "")[:8]
        start_seq = self._segment_start_seq if self._segment_start_seq is not None else (self._seq if self._seq >= 0 else 0)
        end_seq = self._segment_last_seq if self._segment_last_seq is not None else (self._seq if self._seq >= 0 else 0)
        nonce = random.getrandbits(32)
        rotated_path = f"{self.path}.{start_seq}-{end_seq}.{ts_ns}.{pid}.{nonce:08x}.{head_prefix}"

        rename_ok = False
        try:
            if os.path.exists(rotated_path):
                rotated_path = rotated_path + f".{random.getrandbits(16):04x}"
            os.replace(self.path, rotated_path)
            rename_ok = True
        except Exception as e:
            self._last_error = f"rotate_rename_failed:{_safe_text(e, max_len=200)}"
            rename_ok = False

        if rename_ok:
            # Update index with full segment metadata
            idx_root = ""
            if cfg.enable_index and self._segment_start_seq is not None and self._segment_last_seq is not None and self._segment_start_ts_ns is not None and self._segment_last_ts_ns is not None:
                seg_entry: Dict[str, Any] = {
                    "v": 2,
                    "file": os.path.basename(rotated_path),
                    "format": self._record_format,
                    "start_seq": int(self._segment_start_seq),
                    "end_seq": int(self._segment_last_seq),
                    "start_head": self._segment_start_head,
                    "start_prev": self._segment_start_prev,
                    "last_head": str(self._prev),
                    "last_head_mac": self._segment_last_head_mac,
                    "ts_from_ns": int(self._segment_start_ts_ns),
                    "ts_to_ns": int(self._segment_last_ts_ns),
                    "segment_digest": str(self._segment_digest),
                    "hash_ctx": self._cfg.hash_ctx,
                    "digest_size": int(self._digest_size),
                    "policy_digest": self._ledger_policy_digest,
                }
                try:
                    idx_root = self._update_index(seg_entry)
                except Exception as e:
                    self._last_error = f"index_update_failed:{_safe_text(e, max_len=200)}"
                    if cfg.dir_fsync_required:
                        raise AuditIndexError(self._last_error) from e

            # Reset segment metadata for new active file
            self._segment_start_seq = None
            self._segment_start_ts_ns = None
            self._segment_start_head = None
            self._segment_start_prev = None
            self._segment_last_seq = None
            self._segment_last_ts_ns = None
            self._segment_last_head_mac = None
            self._segment_digest = self._segment_digest_seed()

            # Reopen new active file
            fd, st = _safe_open_regular_file(
                self.path,
                flags=os.O_CREAT | os.O_APPEND | os.O_WRONLY,
                mode=int(cfg.file_mode),
                require_regular=bool(cfg.require_regular_file),
                require_nlink_one=bool(cfg.require_nlink_one),
                allowed_root_dir=cfg.allowed_root_dir,
            )
            self._fd = fd
            self._file_stat = st
            self._file_sig = (int(getattr(st, "st_dev", 0)), int(getattr(st, "st_ino", 0)))
            self._bytes_written = int(os.fstat(fd).st_size)

            _fsync_dir_for_path(self.path, required=cfg.dir_fsync_required)
            return True

        # Rotation failed: reopen and recover without resetting segment metadata
        try:
            fd, st = _safe_open_regular_file(
                self.path,
                flags=os.O_CREAT | os.O_APPEND | os.O_WRONLY,
                mode=int(cfg.file_mode),
                require_regular=bool(cfg.require_regular_file),
                require_nlink_one=bool(cfg.require_nlink_one),
                allowed_root_dir=cfg.allowed_root_dir,
            )
            self._fd = fd
            self._file_stat = st
            self._file_sig = (int(getattr(st, "st_dev", 0)), int(getattr(st, "st_ino", 0)))
            self._bytes_written = int(os.fstat(fd).st_size)
            return False
        except Exception as e:
            raise AuditRotationError(f"rotation failed and reopen failed: {_safe_text(e, max_len=200)}") from e

    def _write_segment_marker(self, *, prev_segment_last_head: str) -> None:
        """
        Insert a small, low-leakage marker record at the start of a new segment.
        This does not change the semantics of append_ex return value because it is written before the user record in the same call.
        """
        cfg = self._cfg
        if self._fd is None:
            return
        ts_ns = time.time_ns()
        seq_val = self._seq + 1
        payload = {
            "kind": "segment_start",
            "ts_ns": int(ts_ns),
            "prev_segment_last_head": str(prev_segment_last_head),
            "policy_digest": self._ledger_policy_digest,
        }
        inner = {
            "v": 2,
            "ts_ns": int(ts_ns),
            "seq": int(seq_val),
            "prev": str(prev_segment_last_head),
            "system": True,
            "payload": payload,
        }
        body = _canonical_json(inner)
        body_bytes = body.encode("utf-8")
        if cfg.max_record_bytes > 0 and len(body_bytes) > int(cfg.max_record_bytes):
            return
        head = self._hash_public(body)
        head_mac = self._hash_mac(body)
        outer: Dict[str, Any] = {"head": head, "body": body}
        if head_mac is not None:
            outer["head_mac"] = head_mac
        outer_json = _canonical_json(outer).encode("utf-8")
        if cfg.max_line_bytes > 0 and len(outer_json) > int(cfg.max_line_bytes):
            return
        # write marker
        self._write_record_bytes(outer_json)
        # commit marker state
        self._seq = int(seq_val)
        self._prev = str(head)
        self._segment_last_seq = int(seq_val)
        self._segment_last_ts_ns = int(ts_ns)
        self._segment_last_head_mac = head_mac or self._segment_last_head_mac
        if self._segment_start_seq is None:
            self._segment_start_seq = int(seq_val)
            self._segment_start_ts_ns = int(ts_ns)
            self._segment_start_head = str(head)
            self._segment_start_prev = str(prev_segment_last_head)
            self._segment_digest = self._segment_digest_seed()
        self._segment_digest = self._segment_digest_step(self._segment_digest, str(head))
        try:
            self._write_state()
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Close / context manager                                              #
    # ------------------------------------------------------------------ #

    def close(self) -> None:
        with self._lock:
            fd = self._fd
            self._fd = None
            lock_fd = self._proc_lock_fd
            self._proc_lock_fd = None

        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass
        if lock_fd is not None:
            try:
                os.close(lock_fd)
            except Exception:
                pass

    def __enter__(self) -> "AuditLedger":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ------------------------------------------------------------------ #
    # Verification helpers (cross-segment correct)                         #
    # ------------------------------------------------------------------ #

    def verify_file(
        self,
        path: Optional[str] = None,
        *,
        start_prev: Optional[str] = None,
        strict_prev: bool = True,
        strict_seq: bool = True,
        verify_mac: bool = True,
        max_records: Optional[int] = None,
    ) -> Dict[str, Any]:
        fp = path or self.path
        total = 0
        ok = 0
        bad = 0

        prev = start_prev if start_prev is not None else ("0" * (self._digest_size * 2))
        last_seq: Optional[int] = None

        def _check_record(outer: Dict[str, Any]) -> bool:
            nonlocal prev, last_seq
            body = str(outer.get("body"))
            head = str(outer.get("head"))
            head_mac = outer.get("head_mac") if isinstance(outer.get("head_mac"), str) else None

            if head != self._hash_public(body):
                return False
            if verify_mac and self._mac_key is not None and head_mac is not None:
                mac2 = self._hash_mac(body)
                if mac2 is not None and mac2 != head_mac:
                    return False

            seq, _ts_ns, prev_inner = self._parse_inner_meta(body)
            if strict_prev and isinstance(prev_inner, str) and prev_inner != prev:
                return False
            if strict_seq and isinstance(seq, int):
                if last_seq is not None and seq != last_seq + 1:
                    return False
                last_seq = seq
            prev = head
            return True

        # Detect format by config (we don't autodetect here)
        fmt = self._record_format

        if fmt == "jsonl":
            with open(fp, "rb") as rf:
                for raw in rf:
                    if max_records is not None and total >= int(max_records):
                        break
                    total += 1
                    line = raw.rstrip(b"\r\n")
                    outer = self._parse_outer_json_bytes(line)
                    if not outer:
                        bad += 1
                        continue
                    if _check_record(outer):
                        ok += 1
                    else:
                        bad += 1
            return {"file": fp, "format": fmt, "total": total, "ok": ok, "bad": bad, "end_prev": prev, "end_seq": last_seq}

        # framed_v1
        magic = self._cfg.framed_magic
        crc_on = bool(self._cfg.framed_enable_crc32)
        fd = os.open(fp, os.O_RDONLY)
        try:
            off = 0
            size = int(os.fstat(fd).st_size)
            while off < size:
                if max_records is not None and total >= int(max_records):
                    break
                os.lseek(fd, off, os.SEEK_SET)
                hdr = _read_exact(fd, 8)
                if hdr is None or len(hdr) < 8:
                    break
                if hdr[:4] != magic:
                    bad += 1
                    break
                ln = struct.unpack(">I", hdr[4:8])[0]
                payload = _read_exact(fd, ln)
                if payload is None or len(payload) < ln:
                    bad += 1
                    break
                if crc_on:
                    crc_bytes = _read_exact(fd, 4)
                    if crc_bytes is None or len(crc_bytes) < 4:
                        bad += 1
                        break
                    crc_stored = struct.unpack(">I", crc_bytes)[0]
                    if (zlib.crc32(payload) & 0xFFFFFFFF) != crc_stored:
                        bad += 1
                        break
                outer = self._parse_outer_json_bytes(payload)
                total += 1
                if not outer:
                    bad += 1
                elif _check_record(outer):
                    ok += 1
                else:
                    bad += 1
                off += 8 + ln + (4 if crc_on else 0)
        finally:
            os.close(fd)

        return {"file": fp, "format": fmt, "total": total, "ok": ok, "bad": bad, "end_prev": prev, "end_seq": last_seq}

    def verify_all(
        self,
        *,
        include_rotated: bool = True,
        include_active: bool = True,
        strict_prev: bool = True,
        strict_seq: bool = True,
        verify_mac: bool = True,
    ) -> Dict[str, Any]:
        """
        Cross-segment verification:
        - uses index order for rotated segments
        - chains prev across segments correctly
        """
        out: Dict[str, Any] = {"rotated": [], "active": None, "ok": True}

        prev = "0" * (self._digest_size * 2)
        last_seq: Optional[int] = None

        base_dir = os.path.dirname(self.path) or "."

        if include_rotated and self._cfg.enable_index:
            idx = self._load_index()
            segs = idx.get("segments", [])
            if isinstance(segs, list):
                for seg in segs:
                    if not isinstance(seg, dict):
                        continue
                    fn = seg.get("file")
                    if not isinstance(fn, str) or not fn:
                        continue
                    fp = os.path.join(base_dir, fn)
                    res = self.verify_file(
                        fp,
                        start_prev=prev,
                        strict_prev=strict_prev,
                        strict_seq=strict_seq,
                        verify_mac=verify_mac,
                    )
                    out["rotated"].append(res)
                    prev = res.get("end_prev") or prev
                    last_seq = res.get("end_seq") if isinstance(res.get("end_seq"), int) else last_seq
                    if res.get("bad", 0) != 0:
                        out["ok"] = False

        if include_active:
            res2 = self.verify_file(
                self.path,
                start_prev=prev,
                strict_prev=strict_prev,
                strict_seq=strict_seq,
                verify_mac=verify_mac,
            )
            out["active"] = res2
            if res2.get("bad", 0) != 0:
                out["ok"] = False

        return out