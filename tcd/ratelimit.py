from __future__ import annotations

import hashlib
import heapq
import json
import math
import os
import struct
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Literal

try:
    from .otel_exporter import TCDOtelExporter
except ImportError:  # pragma: no cover
    TCDOtelExporter = None  # type: ignore[misc]

try:
    from .crypto import Blake3Hash
except ImportError:  # pragma: no cover
    Blake3Hash = None  # type: ignore[misc]


__all__ = [
    "RateKey",
    "RateLimitZoneConfig",
    "RateLimitConfig",
    "RateDecision",
    "RateLimiter",
]

# ---------------------------------------------------------------------------
# Constants / grammar
# ---------------------------------------------------------------------------

_SAFE_ZONE_CHARS = set("abcdefghijklmnopqrstuvwxyz0123456789_.:-")
_MAX_ZONE_LEN = 64

_MAX_KEY_PART_BYTES = 256
_MAX_KEY_TUPLE_LEN = 8
_MAX_KEY_DEPTH = 4
_MAX_KEY_STR_CHARS = 4096
_MAX_KEY_BYTES_HARD = 65536
_MAX_INT_BITS = 256

_DEFAULT_MAX_BLOCKLIST = 100_000
_DEFAULT_AUDIT_MAX_EVENT_BYTES = 2048
_DEFAULT_HASH_ALG = "blake2b"
_DEFAULT_KEY_VERSION = "kh1"
_DEFAULT_CFG_VERSION = "cf1"
_TOKEN_SCALE = 1_000_000  # 1 token = 1e6 fixed-point units

_CTX_KEY = b"tcd:ratelimit:key:v4"
_CTX_RAW = b"tcd:ratelimit:key_raw:v4"
_CTX_CFG = b"tcd:ratelimit:cfg:v2"
_CTX_ZONE_REQ = b"tcd:ratelimit:zone_req:v2"
_CTX_EVENT = b"tcd:ratelimit:event:v1"

HashAlgorithm = Literal["blake2b", "blake3"]
KeyErrorMode = Literal["allow", "deny"]
ZoneMissingMode = Literal["fallback_to_default", "create_if_allowed", "deny"]
CostOverCapacityMode = Literal["deny", "audit_only", "deny_without_bucket"]
NewKeyPolicy = Literal["deny_new_when_full", "evict_lru"]
ConfigErrorMode = Literal["fail_closed", "fallback", "raise"]


# ---------------------------------------------------------------------------
# Strong key type (recommended public API)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RateKey:
    """
    Strongly-typed rate-limit key.

    Recommended over passing arbitrary Any. Keeps identity semantics explicit.
    All fields are identifiers, not free-form content.
    """
    tenant_id: str
    principal_id: str
    subject_id: Optional[str] = None
    session_id: Optional[str] = None
    resource_id: Optional[str] = None
    route_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Safety primitives
# ---------------------------------------------------------------------------

def _is_finite_number(x: Any) -> bool:
    if type(x) is bool:
        return False
    if not isinstance(x, (int, float)):
        return False
    try:
        return math.isfinite(float(x))
    except Exception:
        return False


def _coerce_float(v: Any) -> Optional[float]:
    """
    Best-effort float coercion without invoking unknown __str__.
    Accepts exact int / float / str.
    """
    if _is_finite_number(v):
        return float(v)

    if type(v) is str:
        s = v.strip()
        if not s or len(s) > 64:
            return None
        try:
            x = float(s)
        except Exception:
            return None
        return x if math.isfinite(x) else None

    return None


def _coerce_int(v: Any) -> Optional[int]:
    """
    Best-effort int coercion without invoking unknown __str__.
    Accepts exact int or strict base-10 strings.
    """
    if type(v) is int:
        return int(v)

    if type(v) is str:
        s = v.strip()
        if not s or len(s) > 64:
            return None
        if s.startswith(("+", "-")):
            sign = s[0]
            digits = s[1:]
        else:
            sign = ""
            digits = s
        if not digits.isdigit():
            return None
        try:
            return int(sign + digits, 10)
        except Exception:
            return None

    return None


def _clamp_float(v: Any, *, default: float, lo: float, hi: float) -> float:
    x = _coerce_float(v)
    if x is None:
        return float(default)
    if x < lo:
        return float(lo)
    if x > hi:
        return float(hi)
    return float(x)


def _clamp_int(v: Any, *, default: int, lo: int, hi: int) -> int:
    x = _coerce_int(v)
    if x is None:
        return int(default)
    if x < lo:
        return int(lo)
    if x > hi:
        return int(hi)
    return int(x)


def _safe_zone_name(name: Any) -> Tuple[Optional[str], bool]:
    """
    Validate-only:
      - lower-case
      - no truncation
      - returns (sanitized, ok)
    """
    if type(name) is not str:
        return None, False
    s = name.strip().lower()
    if not s:
        return None, False
    if len(s) > _MAX_ZONE_LEN:
        return None, False
    for ch in s:
        if ch not in _SAFE_ZONE_CHARS:
            return None, False
    return s, True


def _hash_bytes(
    *,
    data: bytes,
    ctx: bytes,
    salt: Optional[bytes],
    alg: HashAlgorithm,
    out_hex_chars: int,
) -> str:
    """
    Explicit hash algorithm.
    No environment-dependent auto-switching.
    """
    payload = ctx + b"\x00"
    if salt:
        payload += salt + b"\x00"
    payload += data

    if alg == "blake3":
        if Blake3Hash is None:
            raise RuntimeError("hash algorithm 'blake3' requested but Blake3Hash is unavailable")
        h = Blake3Hash().hex(payload, ctx="tcd:ratelimit")
        return h[:out_hex_chars]

    d = hashlib.blake2b(payload, digest_size=max(16, out_hex_chars // 2)).hexdigest()
    return d[:out_hex_chars]


def _cfg_fingerprint(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", errors="strict")
    d = hashlib.blake2b(_CTX_CFG + b"\x00" + raw, digest_size=24).hexdigest()
    return f"{_DEFAULT_CFG_VERSION}:{d}"


def _event_id(instance_id: str, decision_seq: int, decision_ts_unix_ns: int) -> str:
    raw = (
        instance_id.encode("utf-8", errors="strict")
        + b"\x00"
        + str(decision_seq).encode("ascii", errors="strict")
        + b"\x00"
        + str(decision_ts_unix_ns).encode("ascii", errors="strict")
    )
    d = hashlib.blake2b(_CTX_EVENT + b"\x00" + raw, digest_size=16).hexdigest()
    return f"ev1:{d}"


# ---------------------------------------------------------------------------
# Collision-resistant length-delimited key encoding
# ---------------------------------------------------------------------------

def _u32be(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFF:
        raise ValueError("length out of range")
    return struct.pack(">I", n)


def _u64be(n: int) -> bytes:
    if n < 0 or n > 0xFFFFFFFFFFFFFFFF:
        raise ValueError("length out of range")
    return struct.pack(">Q", n)


def _ld(tag: bytes, payload: bytes) -> bytes:
    """
    Length-delimited encoding.
    Prevents delimiter ambiguity collisions.
    """
    if len(tag) > 16:
        tag = hashlib.blake2b(tag, digest_size=8).digest()
    return tag + _u32be(len(payload)) + payload


def _encode_int_exact(i: int) -> bytes:
    if i.bit_length() > _MAX_INT_BITS:
        raise ValueError("integer key component too large")
    sign = b"\x01" if i < 0 else b"\x00"
    mag = -i if i < 0 else i
    if mag == 0:
        mag_bytes = b"\x00"
    else:
        mag_bytes = mag.to_bytes((mag.bit_length() + 7) // 8, "big", signed=False)
    return _ld(b"i", sign + mag_bytes)


def _encode_bool_exact(bv: bool) -> bytes:
    return _ld(b"o", b"\x01" if bv else b"\x00")


def _encode_bytes_exact(b: bytes) -> bytes:
    if len(b) > _MAX_KEY_BYTES_HARD:
        raise ValueError("bytes key component too large")
    if len(b) > _MAX_KEY_PART_BYTES:
        d = hashlib.blake2b(b, digest_size=16).digest()
        return _ld(b"bh", _u32be(len(b)) + d)
    return _ld(b"b", b)


def _encode_str_exact(s: str) -> bytes:
    if len(s) > _MAX_KEY_STR_CHARS:
        raise ValueError("string key component too large")
    b = s.encode("utf-8", errors="surrogatepass")
    if len(b) > _MAX_KEY_BYTES_HARD:
        raise ValueError("utf-8 encoded key component too large")
    if len(b) > _MAX_KEY_PART_BYTES:
        d = hashlib.blake2b(b, digest_size=16).digest()
        return _ld(b"sh", _u32be(len(b)) + d)
    return _ld(b"s", b)


def _encode_rate_key_exact(k: RateKey, *, depth: int = 0) -> Optional[bytes]:
    if depth > _MAX_KEY_DEPTH:
        return None

    parts: list[bytes] = [b"rk"]
    for label, value in (
        ("tenant", k.tenant_id),
        ("principal", k.principal_id),
        ("subject", k.subject_id),
        ("session", k.session_id),
        ("resource", k.resource_id),
        ("route", k.route_id),
    ):
        if value is None:
            parts.append(_ld(label.encode("ascii", errors="strict"), b"\x00"))
            continue
        if type(value) is not str:
            return None
        try:
            parts.append(_ld(label.encode("ascii", errors="strict"), _encode_str_exact(value)))
        except Exception:
            return None
    return _ld(b"rk", b"".join(parts))


def _key_fingerprint_bytes(key: Any, *, depth: int = 0) -> Optional[bytes]:
    """
    Exact-type, structured, bounded encoding.
    No str()/repr() on unknown objects.
    """
    if depth > _MAX_KEY_DEPTH:
        return None

    t = type(key)
    try:
        if t is RateKey:
            return _encode_rate_key_exact(key, depth=depth + 1)
        if t is bytes:
            return _encode_bytes_exact(key)
        if t is str:
            return _encode_str_exact(key)
        if t is int:
            return _encode_int_exact(key)
        if t is bool:
            return _encode_bool_exact(key)

        if t is tuple or t is list:
            seq = key
            total_len = len(seq)
            if total_len > _MAX_KEY_TUPLE_LEN:
                return None
            out: list[bytes] = []
            out.append(_ld(b"n", _u32be(total_len)))
            for item in seq:
                b = _key_fingerprint_bytes(item, depth=depth + 1)
                if b is None:
                    return None
                out.append(_ld(b"p", b))
            tag = b"tp" if t is tuple else b"li"
            return _ld(tag, b"".join(out))
    except Exception:
        return None

    return None


# ---------------------------------------------------------------------------
# Public config / decisions
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RateLimitZoneConfig:
    """
    Per-zone token-bucket config.

    All values are normalized/clamped before use.
    """

    capacity: float = 10.0
    refill_per_s: float = 10.0
    temp_block_after_denies: int = 0
    temp_block_ttl: float = 0.0
    max_entries: int = 65_536
    idle_ttl_s: float = 0.0

    def normalized(self) -> "RateLimitZoneConfig":
        cap = _clamp_float(self.capacity, default=10.0, lo=0.0, hi=1_000_000_000.0)
        rps = _clamp_float(self.refill_per_s, default=10.0, lo=0.0, hi=1_000_000_000.0)
        denies = _clamp_int(self.temp_block_after_denies, default=0, lo=0, hi=1_000_000)
        ttl = _clamp_float(self.temp_block_ttl, default=0.0, lo=0.0, hi=1_000_000_000.0)
        me = _clamp_int(self.max_entries, default=65_536, lo=0, hi=10_000_000)
        idle = _clamp_float(self.idle_ttl_s, default=0.0, lo=0.0, hi=1_000_000_000.0)

        if ttl <= 0.0:
            denies = 0

        return RateLimitZoneConfig(
            capacity=cap,
            refill_per_s=rps,
            temp_block_after_denies=denies,
            temp_block_ttl=ttl,
            max_entries=me,
            idle_ttl_s=idle,
        )


@dataclass
class RateLimitConfig:
    """
    Mutable external config.

    Runtime compiles this into an immutable bundle and then stops reading
    this object directly. This avoids live/frozen/stale drift.
    """

    zones: Dict[str, RateLimitZoneConfig] = field(default_factory=dict)
    default_zone: str = "default"

    enable_audit: bool = True
    enable_metrics: bool = True

    exporter: Optional["TCDOtelExporter"] = None
    metrics_hook: Optional[Callable[[str, float, Dict[str, Any]], None]] = None
    audit_hook: Optional[Callable[[Dict[str, Any]], None]] = None

    global_max_entries: int = 200_000

    # Time sources may return float seconds or int ns
    monotonic_fn: Optional[Callable[[], Any]] = None
    wall_time_fn: Optional[Callable[[], Any]] = None

    # Zone governance
    allow_dynamic_zones: bool = False
    max_zones: int = 256
    on_unknown_zone: ZoneMissingMode = "fallback_to_default"
    new_key_policy: NewKeyPolicy = "deny_new_when_full"

    # Key governance / privacy
    anonymize_keys: bool = True
    key_error_mode: KeyErrorMode = "deny"
    key_hash_salt: Optional[bytes] = None
    auto_ephemeral_salt_if_missing: bool = True
    min_key_hash_salt_bytes: int = 16
    hash_algorithm: HashAlgorithm = _DEFAULT_HASH_ALG
    key_version: str = _DEFAULT_KEY_VERSION

    # Time override governance
    allow_time_override: bool = False
    max_time_skew_s: float = 0.05
    max_time_back_skew_s: float = 1.0

    # Cost governance
    min_cost: float = 1e-6
    max_cost: float = 1_000_000.0
    cost_over_capacity_mode: CostOverCapacityMode = "deny"

    # Temp-block persistence
    max_block_entries: int = _DEFAULT_MAX_BLOCKLIST
    blocklist_cleanup_budget: int = 2

    # Audit budget
    audit_max_event_bytes: int = _DEFAULT_AUDIT_MAX_EVENT_BYTES

    # Config error mode
    on_config_error: ConfigErrorMode = "fail_closed"

    # Compatibility helper only
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False, compare=False)

    def resolve_zone(self, zone: Optional[str]) -> Tuple[str, RateLimitZoneConfig, bool, bool]:
        """
        Backward-compatible helper.
        Prefer RateLimiter's compiled-bundle resolver.
        Returns (resolved_zone_name, cfg, input_ok, used_fallback).
        """
        with self._lock:
            default_zone, ok_def = _safe_zone_name(self.default_zone)
            if not ok_def or default_zone is None:
                default_zone = "default"

            zmap: Dict[str, RateLimitZoneConfig] = {}
            for raw_name, raw_cfg in (self.zones or {}).items():
                zn, ok = _safe_zone_name(raw_name)
                if not ok or zn is None:
                    continue
                if isinstance(raw_cfg, RateLimitZoneConfig):
                    zmap[zn] = raw_cfg.normalized()

            if default_zone not in zmap:
                zmap[default_zone] = RateLimitZoneConfig().normalized()

            if zone is None:
                return default_zone, zmap[default_zone], True, True

            req, ok = _safe_zone_name(zone)
            if not ok or req is None:
                if self.on_unknown_zone == "deny":
                    return default_zone, zmap[default_zone], False, True
                return default_zone, zmap[default_zone], False, True

            if req in zmap:
                return req, zmap[req], True, False

            if (
                self.on_unknown_zone == "create_if_allowed"
                and self.allow_dynamic_zones
                and len(zmap) < max(1, int(self.max_zones))
            ):
                return req, RateLimitZoneConfig().normalized(), True, False

            if self.on_unknown_zone == "deny":
                return default_zone, zmap[default_zone], True, True
            return default_zone, zmap[default_zone], True, True


@dataclass(frozen=True, slots=True)
class RateDecision:
    allowed: bool
    zone: str
    remaining_tokens: float
    blocked_until: Optional[float]
    reason: str

    retry_after_s: Optional[float] = None
    cost: float = 1.0
    key_id: Optional[str] = None
    cfg_fp: Optional[str] = None

    decision_seq: int = 0
    bundle_version: int = 0
    decision_ts_mono_ns: int = 0
    decision_ts_unix_ns: int = 0
    blocked_until_mono_ns: Optional[int] = None
    blocked_until_unix_ns: Optional[int] = None

    zone_resolution: str = "resolved"
    requested_zone_hash: Optional[str] = None

    algorithm_id: str = ""
    state_scope: str = "local_best_effort"


# ---------------------------------------------------------------------------
# Internal compiled state
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class _BucketState:
    tokens_q: int
    ts_ns: int
    denies: int = 0


@dataclass(slots=True)
class _ZoneState:
    cfg: "_CompiledZone"
    buckets: Dict[str, _BucketState] = field(default_factory=dict)
    lru: "OrderedDict[str, None]" = field(default_factory=OrderedDict)


@dataclass(frozen=True, slots=True)
class _CompiledZone:
    name: str
    capacity_q: int
    refill_q_per_s: int
    temp_block_after_denies: int
    temp_block_ttl_ns: int
    max_entries: int
    idle_ttl_ns: int


@dataclass(frozen=True, slots=True)
class _CompiledBundle:
    version: int
    updated_at_unix_ns: int
    cfg_fp: str
    errors: Tuple[str, ...]
    warnings: Tuple[str, ...]
    on_config_error: ConfigErrorMode

    default_zone: str
    zones: Mapping[str, _CompiledZone]
    allow_dynamic_zones: bool
    max_zones: int
    on_unknown_zone: ZoneMissingMode
    new_key_policy: NewKeyPolicy

    enable_audit: bool
    enable_metrics: bool
    exporter: Any
    metrics_hook: Optional[Callable[[str, float, Dict[str, Any]], None]]
    audit_hook: Optional[Callable[[Dict[str, Any]], None]]

    monotonic_fn: Callable[[], Any]
    wall_time_fn: Callable[[], Any]

    global_max_entries: int

    anonymize_keys: bool
    key_error_mode: KeyErrorMode
    hash_algorithm: HashAlgorithm
    key_version: str
    key_hash_salt: Optional[bytes]
    salt_mode: str

    allow_time_override: bool
    max_time_skew_ns: int
    max_time_back_skew_ns: int

    min_cost_q: int
    max_cost_q: int
    cost_over_capacity_mode: CostOverCapacityMode

    max_block_entries: int
    blocklist_cleanup_budget: int
    audit_max_event_bytes: int


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """
    L7+ hardened in-memory rate limiter.

    Properties:
      - immutable compiled bundle + atomic config swap
      - fixed-point integer token accounting
      - dual clocks (monotonic ns + wall unix ns)
      - no raw key storage
      - no silent config/live drift
      - state admission policy (no unconditional "insert then evict")
      - blocklist cleanup driven by expiry heap, not LRU order
      - audit/metrics emitted outside lock
    """

    @dataclass(frozen=True, slots=True)
    class _ZoneResolution:
        resolved_zone: str
        zone_cfg: _CompiledZone
        resolution_state: str  # resolved | defaulted | created_dynamic | denied | config_error
        reason: str
        requested_zone_hash: Optional[str]

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self._lock = threading.RLock()
        self._stats_lock = threading.Lock()
        self._instance_id = os.urandom(8).hex()

        self._decision_seq = 0

        initial_cfg = config or RateLimitConfig()
        bundle = self._compile_bundle(initial_cfg, previous=None)
        if bundle.errors and bundle.on_config_error == "raise":
            raise ValueError("invalid rate limiter config: " + "; ".join(bundle.errors[:3]))
        self._bundle = bundle

        # runtime state
        self._zones: Dict[str, _ZoneState] = {}
        self._global_lru: "OrderedDict[Tuple[str, str], None]" = OrderedDict()

        # blocklist: map + lru + expiry heap
        self._block_until: Dict[Tuple[str, str], Tuple[int, int]] = {}
        self._block_lru: "OrderedDict[Tuple[str, str], None]" = OrderedDict()
        self._block_heap: list[Tuple[int, int, Tuple[str, str]]] = []
        self._block_gen = 0

        self._total_entries = 0

        # health / counters
        self._evict_global_count = 0
        self._evict_zone_count = 0
        self._evict_idle_count = 0
        self._cleanup_expired_block_count = 0

        self._metrics_emit_count = 0
        self._metrics_emit_fail_count = 0
        self._audit_emit_count = 0
        self._audit_emit_fail_count = 0

        self._allowed_count = 0
        self._denied_count = 0
        self._config_error_count = 0

        self._last_metrics_error_code: Optional[str] = None
        self._last_audit_error_code: Optional[str] = None
        self._degraded_since_unix_ns: Optional[int] = None

    # ------------------------------------------------------------------
    # Public config API
    # ------------------------------------------------------------------

    @property
    def cfg_fp(self) -> str:
        return self._bundle.cfg_fp

    @property
    def bundle_version(self) -> int:
        return self._bundle.version

    @property
    def enforcement_scope(self) -> str:
        return "local_best_effort"

    def get_config_snapshot(self) -> Dict[str, Any]:
        b = self._bundle
        return {
            "instance_id": self._instance_id,
            "cfg_fp": b.cfg_fp,
            "bundle_version": b.version,
            "updated_at_unix_ns": b.updated_at_unix_ns,
            "default_zone": b.default_zone,
            "zone_count": len(b.zones),
            "zones": {
                z: {
                    "capacity": self._q_to_float(c.capacity_q),
                    "refill_per_s": self._q_to_float(c.refill_q_per_s),
                    "max_entries": c.max_entries,
                    "idle_ttl_s": c.idle_ttl_ns / 1_000_000_000.0,
                    "temp_block_after_denies": c.temp_block_after_denies,
                    "temp_block_ttl_s": c.temp_block_ttl_ns / 1_000_000_000.0,
                }
                for z, c in b.zones.items()
            },
            "errors": list(b.errors[:50]),
            "warnings": list(b.warnings[:50]),
            "on_config_error": b.on_config_error,
            "hash_algorithm": b.hash_algorithm,
            "key_version": b.key_version,
            "salt_mode": b.salt_mode,
            "state_scope": self.enforcement_scope,
        }

    def set_config(self, config: RateLimitConfig) -> None:
        old_bundle = self._bundle
        new_bundle = self._compile_bundle(config, previous=old_bundle)
        if new_bundle.errors and new_bundle.on_config_error == "raise":
            raise ValueError("invalid rate limiter config: " + "; ".join(new_bundle.errors[:3]))

        keyspace_changed = (
            old_bundle.hash_algorithm != new_bundle.hash_algorithm
            or old_bundle.key_version != new_bundle.key_version
            or old_bundle.anonymize_keys != new_bundle.anonymize_keys
            or old_bundle.key_hash_salt != new_bundle.key_hash_salt
        )

        with self._lock:
            self._bundle = new_bundle

            if keyspace_changed:
                # safest possible semantics: old key_ids are no longer comparable
                self._zones.clear()
                self._global_lru.clear()
                self._block_until.clear()
                self._block_lru.clear()
                self._block_heap.clear()
                self._total_entries = 0
                return

            if new_bundle.max_block_entries <= 0:
                self._block_until.clear()
                self._block_lru.clear()
                self._block_heap.clear()

            # reconcile immediately against new limits
            now_ns = self._mono_ns()
            for zname, zs in list(self._zones.items()):
                zcfg = new_bundle.zones.get(zname)
                if zcfg is None:
                    if not new_bundle.allow_dynamic_zones:
                        self._remove_zone_state_locked(zname)
                        continue
                    zcfg = new_bundle.zones[new_bundle.default_zone]
                zs.cfg = zcfg
                self._evict_idle_in_zone(zs, zname, now_ns)
                self._evict_zone_if_needed(zname, zs)

            self._evict_global_if_needed()
            self._cleanup_blocks_budgeted(now_ns, budget=10_000)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def consume(self, key: Any, cost: float = 1.0, zone: Optional[str] = None) -> bool:
        return self.consume_decision(key=key, cost=cost, zone=zone).allowed

    def consume_batch(
        self,
        items: Tuple[Tuple[Any, float, Optional[str]], ...],
    ) -> Tuple[RateDecision, ...]:
        out = []
        for key, cost, zone in items:
            out.append(self.consume_decision(key=key, cost=cost, zone=zone))
        return tuple(out)

    def peek_decision(self, key: Any, cost: float = 1.0, zone: Optional[str] = None) -> RateDecision:
        return self._peek_decision_impl(key=key, cost=cost, zone=zone)

    def refund(self, key: Any, cost: float = 1.0, zone: Optional[str] = None) -> bool:
        bundle = self._bundle
        zone_res = self._resolve_zone(bundle, zone)
        if zone_res.resolution_state == "denied":
            return False

        key_id = self._key_id(bundle, key)
        if key_id is None:
            return False

        refund_q = self._cost_to_q(bundle, cost)
        if refund_q <= 0:
            return False

        with self._lock:
            zs = self._zones.get(zone_res.resolved_zone)
            if zs is None:
                return False
            st = zs.buckets.get(key_id)
            if st is None:
                return False
            st.tokens_q = min(zs.cfg.capacity_q, st.tokens_q + refund_q)
            zs.lru.pop(key_id, None)
            zs.lru[key_id] = None
            self._touch_global_lru((zone_res.resolved_zone, key_id))
            return True

    def reset_key(self, key: Any, zone: Optional[str] = None) -> bool:
        bundle = self._bundle
        zone_res = self._resolve_zone(bundle, zone)
        if zone_res.resolution_state == "denied":
            return False
        key_id = self._key_id(bundle, key)
        if key_id is None:
            return False

        with self._lock:
            zs = self._zones.get(zone_res.resolved_zone)
            if zs is not None:
                self._evict_bucket(zone_res.resolved_zone, zs, key_id)
            self._clear_block((zone_res.resolved_zone, key_id))
        return True

    def ban_key(self, key: Any, *, ttl_s: float, zone: Optional[str] = None) -> bool:
        bundle = self._bundle
        zone_res = self._resolve_zone(bundle, zone)
        if zone_res.resolution_state == "denied":
            return False

        key_id = self._key_id(bundle, key)
        if key_id is None:
            return False

        ttl_ns = int(max(0.0, _clamp_float(ttl_s, default=0.0, lo=0.0, hi=1_000_000_000.0)) * 1_000_000_000.0)
        if ttl_ns <= 0:
            return False

        now_ns = self._mono_ns()
        with self._lock:
            self._set_block((zone_res.resolved_zone, key_id), now_ns + ttl_ns, bundle)
        return True

    def compact(self) -> None:
        now_ns = self._mono_ns()
        with self._lock:
            self._cleanup_blocks_budgeted(now_ns, budget=10_000)
            for zname, zs in list(self._zones.items()):
                self._evict_idle_in_zone(zs, zname, now_ns, budget=10_000)
                self._evict_zone_if_needed(zname, zs)
            self._evict_global_if_needed()

    def consume_decision(
        self,
        key: Any,
        cost: float = 1.0,
        zone: Optional[str] = None,
        *,
        now: Optional[float] = None,
    ) -> RateDecision:
        return self._consume_decision_impl(key=key, cost=cost, zone=zone, consume=True, now=now)

    def _consume_decision_impl(
        self,
        *,
        key: Any,
        cost: float,
        zone: Optional[str],
        consume: bool,
        now: Optional[float],
    ) -> RateDecision:
        bundle = self._bundle

        # config error behavior
        if bundle.errors:
            if bundle.on_config_error == "raise":
                raise RuntimeError("rate limiter config invalid")
            if bundle.on_config_error == "fail_closed":
                d = self._make_decision(
                    bundle=bundle,
                    allowed=False,
                    resolved_zone=bundle.default_zone,
                    reason="config_error",
                    remaining_tokens_q=0,
                    blocked_until_mono_ns=None,
                    retry_after_s=None,
                    cost_q=self._cost_to_q(bundle, cost),
                    key_id=None,
                    zone_resolution="config_error",
                    requested_zone_hash=self._requested_zone_hash(bundle, zone),
                    now_mono_ns=self._mono_ns(),
                    now_unix_ns=self._wall_ns(),
                )
                with self._stats_lock:
                    self._config_error_count += 1
                    self._denied_count += 1
                self._emit_after_decision(bundle=bundle, decision=d, zone_cfg=bundle.zones[bundle.default_zone], denies=None)
                return d
            # fallback => continue with sanitized compiled bundle

        now_mono_ns = self._resolve_now_ns(bundle, now)
        now_unix_ns = self._wall_ns()

        zone_res = self._resolve_zone(bundle, zone)
        if zone_res.resolution_state == "denied":
            d = self._make_decision(
                bundle=bundle,
                allowed=False,
                resolved_zone=zone_res.resolved_zone,
                reason=zone_res.reason,
                remaining_tokens_q=0,
                blocked_until_mono_ns=None,
                retry_after_s=None,
                cost_q=self._cost_to_q(bundle, cost),
                key_id=None,
                zone_resolution=zone_res.resolution_state,
                requested_zone_hash=zone_res.requested_zone_hash,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
            )
            with self._stats_lock:
                self._denied_count += 1
            self._emit_after_decision(bundle=bundle, decision=d, zone_cfg=zone_res.zone_cfg, denies=None)
            return d

        zone_name = zone_res.resolved_zone
        zone_cfg = zone_res.zone_cfg
        cost_q = self._cost_to_q(bundle, cost)

        key_id = self._key_id(bundle, key)
        if key_id is None:
            allowed = (bundle.key_error_mode == "allow")
            d = self._make_decision(
                bundle=bundle,
                allowed=allowed,
                resolved_zone=zone_name,
                reason="key_error_allow" if allowed else "key_error_deny",
                remaining_tokens_q=0,
                blocked_until_mono_ns=None,
                retry_after_s=None,
                cost_q=cost_q,
                key_id=None,
                zone_resolution=zone_res.resolution_state,
                requested_zone_hash=zone_res.requested_zone_hash,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
            )
            with self._stats_lock:
                if allowed:
                    self._allowed_count += 1
                else:
                    self._denied_count += 1
            self._emit_after_decision(bundle=bundle, decision=d, zone_cfg=zone_cfg, denies=None)
            return d

        denies_after: Optional[int] = None
        with self._lock:
            self._cleanup_blocks_budgeted(now_mono_ns)

            blk_key = (zone_name, key_id)
            blocked_until_ns = self._get_block_until(blk_key)
            if blocked_until_ns is not None and blocked_until_ns > now_mono_ns:
                self._touch_block(blk_key)
                d = self._make_decision(
                    bundle=bundle,
                    allowed=False,
                    resolved_zone=zone_name,
                    reason="temp_block",
                    remaining_tokens_q=0,
                    blocked_until_mono_ns=blocked_until_ns,
                    retry_after_s=max(0.0, (blocked_until_ns - now_mono_ns) / 1_000_000_000.0),
                    cost_q=cost_q,
                    key_id=key_id,
                    zone_resolution=zone_res.resolution_state,
                    requested_zone_hash=zone_res.requested_zone_hash,
                    now_mono_ns=now_mono_ns,
                    now_unix_ns=now_unix_ns,
                )
                denies_after = None
            else:
                if blocked_until_ns is not None and blocked_until_ns <= now_mono_ns:
                    self._clear_block(blk_key)

                zs = self._zones.get(zone_name)
                if zs is None:
                    zs = _ZoneState(cfg=zone_cfg)
                    self._zones[zone_name] = zs
                else:
                    zs.cfg = zone_cfg

                self._evict_idle_in_zone(zs, zone_name, now_mono_ns)

                st = zs.buckets.get(key_id)
                if st is None:
                    admission_reason = self._admit_new_key_locked(bundle, zone_name, zone_cfg, zs)
                    if admission_reason is not None:
                        d = self._make_decision(
                            bundle=bundle,
                            allowed=False,
                            resolved_zone=zone_name,
                            reason=admission_reason,
                            remaining_tokens_q=0,
                            blocked_until_mono_ns=None,
                            retry_after_s=None,
                            cost_q=cost_q,
                            key_id=key_id,
                            zone_resolution=zone_res.resolution_state,
                            requested_zone_hash=zone_res.requested_zone_hash,
                            now_mono_ns=now_mono_ns,
                            now_unix_ns=now_unix_ns,
                        )
                        denies_after = None
                    else:
                        st = _BucketState(tokens_q=zone_cfg.capacity_q, ts_ns=now_mono_ns, denies=0)
                        zs.buckets[key_id] = st
                        zs.lru[key_id] = None
                        self._global_lru[(zone_name, key_id)] = None
                        self._total_entries += 1
                        self._evict_zone_if_needed(zone_name, zs)
                        self._evict_global_if_needed()
                        d = None
                else:
                    d = None

                if d is None:
                    assert st is not None

                    elapsed_ns = now_mono_ns - st.ts_ns
                    if elapsed_ns < 0:
                        elapsed_ns = 0

                    if zone_cfg.refill_q_per_s > 0 and zone_cfg.capacity_q > 0:
                        add_q = (elapsed_ns * zone_cfg.refill_q_per_s) // 1_000_000_000
                        if add_q > 0:
                            st.tokens_q = min(zone_cfg.capacity_q, st.tokens_q + add_q)
                    else:
                        st.tokens_q = min(max(0, st.tokens_q), zone_cfg.capacity_q)

                    st.ts_ns = now_mono_ns
                    if st.tokens_q < 0 or st.tokens_q > zone_cfg.capacity_q:
                        st.tokens_q = min(max(0, st.tokens_q), zone_cfg.capacity_q)

                    # cost impossible to satisfy
                    if cost_q > zone_cfg.capacity_q:
                        if bundle.cost_over_capacity_mode == "audit_only":
                            d = self._make_decision(
                                bundle=bundle,
                                allowed=False,
                                resolved_zone=zone_name,
                                reason="cost_over_capacity",
                                remaining_tokens_q=max(0, st.tokens_q),
                                blocked_until_mono_ns=None,
                                retry_after_s=None,
                                cost_q=cost_q,
                                key_id=key_id,
                                zone_resolution=zone_res.resolution_state,
                                requested_zone_hash=zone_res.requested_zone_hash,
                                now_mono_ns=now_mono_ns,
                                now_unix_ns=now_unix_ns,
                            )
                            denies_after = st.denies
                        elif bundle.cost_over_capacity_mode == "deny_without_bucket":
                            d = self._make_decision(
                                bundle=bundle,
                                allowed=False,
                                resolved_zone=zone_name,
                                reason="cost_over_capacity",
                                remaining_tokens_q=max(0, st.tokens_q),
                                blocked_until_mono_ns=None,
                                retry_after_s=None,
                                cost_q=cost_q,
                                key_id=key_id,
                                zone_resolution=zone_res.resolution_state,
                                requested_zone_hash=zone_res.requested_zone_hash,
                                now_mono_ns=now_mono_ns,
                                now_unix_ns=now_unix_ns,
                            )
                            denies_after = st.denies
                        else:
                            st.denies += 1
                            denies_after = st.denies
                            if (
                                zone_cfg.temp_block_after_denies > 0
                                and st.denies >= zone_cfg.temp_block_after_denies
                                and zone_cfg.temp_block_ttl_ns > 0
                            ):
                                until = now_mono_ns + zone_cfg.temp_block_ttl_ns
                                self._set_block(blk_key, until, bundle)
                                st.denies = 0
                                denies_after = 0
                                d = self._make_decision(
                                    bundle=bundle,
                                    allowed=False,
                                    resolved_zone=zone_name,
                                    reason="temp_block",
                                    remaining_tokens_q=max(0, st.tokens_q),
                                    blocked_until_mono_ns=until,
                                    retry_after_s=max(0.0, (until - now_mono_ns) / 1_000_000_000.0),
                                    cost_q=cost_q,
                                    key_id=key_id,
                                    zone_resolution=zone_res.resolution_state,
                                    requested_zone_hash=zone_res.requested_zone_hash,
                                    now_mono_ns=now_mono_ns,
                                    now_unix_ns=now_unix_ns,
                                )
                            else:
                                d = self._make_decision(
                                    bundle=bundle,
                                    allowed=False,
                                    resolved_zone=zone_name,
                                    reason="cost_over_capacity",
                                    remaining_tokens_q=max(0, st.tokens_q),
                                    blocked_until_mono_ns=None,
                                    retry_after_s=None,
                                    cost_q=cost_q,
                                    key_id=key_id,
                                    zone_resolution=zone_res.resolution_state,
                                    requested_zone_hash=zone_res.requested_zone_hash,
                                    now_mono_ns=now_mono_ns,
                                    now_unix_ns=now_unix_ns,
                                )

                    elif not consume and st.tokens_q >= cost_q:
                        d = self._make_decision(
                            bundle=bundle,
                            allowed=True,
                            resolved_zone=zone_name,
                            reason="ok",
                            remaining_tokens_q=max(0, st.tokens_q),
                            blocked_until_mono_ns=None,
                            retry_after_s=None,
                            cost_q=cost_q,
                            key_id=key_id,
                            zone_resolution=zone_res.resolution_state,
                            requested_zone_hash=zone_res.requested_zone_hash,
                            now_mono_ns=now_mono_ns,
                            now_unix_ns=now_unix_ns,
                        )
                        denies_after = st.denies

                    elif st.tokens_q >= cost_q:
                        st.tokens_q = max(0, st.tokens_q - cost_q)
                        st.denies = 0
                        denies_after = 0
                        d = self._make_decision(
                            bundle=bundle,
                            allowed=True,
                            resolved_zone=zone_name,
                            reason="ok",
                            remaining_tokens_q=max(0, st.tokens_q),
                            blocked_until_mono_ns=None,
                            retry_after_s=0.0,
                            cost_q=cost_q,
                            key_id=key_id,
                            zone_resolution=zone_res.resolution_state,
                            requested_zone_hash=zone_res.requested_zone_hash,
                            now_mono_ns=now_mono_ns,
                            now_unix_ns=now_unix_ns,
                        )

                    else:
                        st.denies += 1
                        denies_after = st.denies
                        remaining_q = max(0, st.tokens_q)

                        if (
                            zone_cfg.temp_block_after_denies > 0
                            and st.denies >= zone_cfg.temp_block_after_denies
                            and zone_cfg.temp_block_ttl_ns > 0
                        ):
                            until = now_mono_ns + zone_cfg.temp_block_ttl_ns
                            self._set_block(blk_key, until, bundle)
                            st.denies = 0
                            denies_after = 0
                            d = self._make_decision(
                                bundle=bundle,
                                allowed=False,
                                resolved_zone=zone_name,
                                reason="temp_block",
                                remaining_tokens_q=remaining_q,
                                blocked_until_mono_ns=until,
                                retry_after_s=max(0.0, (until - now_mono_ns) / 1_000_000_000.0),
                                cost_q=cost_q,
                                key_id=key_id,
                                zone_resolution=zone_res.resolution_state,
                                requested_zone_hash=zone_res.requested_zone_hash,
                                now_mono_ns=now_mono_ns,
                                now_unix_ns=now_unix_ns,
                            )
                        else:
                            ra = None
                            if zone_cfg.refill_q_per_s > 0:
                                deficit_q = max(0, cost_q - st.tokens_q)
                                retry_ns = (deficit_q * 1_000_000_000 + zone_cfg.refill_q_per_s - 1) // zone_cfg.refill_q_per_s
                                ra = retry_ns / 1_000_000_000.0
                            d = self._make_decision(
                                bundle=bundle,
                                allowed=False,
                                resolved_zone=zone_name,
                                reason="exhausted",
                                remaining_tokens_q=remaining_q,
                                blocked_until_mono_ns=None,
                                retry_after_s=ra,
                                cost_q=cost_q,
                                key_id=key_id,
                                zone_resolution=zone_res.resolution_state,
                                requested_zone_hash=zone_res.requested_zone_hash,
                                now_mono_ns=now_mono_ns,
                                now_unix_ns=now_unix_ns,
                            )

                    zs.lru.pop(key_id, None)
                    zs.lru[key_id] = None
                    self._touch_global_lru((zone_name, key_id))

            decision = d
            self._decision_seq += 1
            decision = self._with_seq(decision, seq=self._decision_seq, bundle_version=bundle.version)

        with self._stats_lock:
            if decision.allowed:
                self._allowed_count += 1
            else:
                self._denied_count += 1

        self._emit_after_decision(bundle=bundle, decision=decision, zone_cfg=zone_cfg, denies=denies_after)
        return decision

    def snapshot(self) -> Dict[str, Any]:
        bundle = self._bundle
        with self._lock:
            now_ns = self._mono_ns()
            zones: Dict[str, int] = {z: len(zs.buckets) for z, zs in self._zones.items()}
            active_blocks: Dict[str, int] = {}
            for (z, _kid), (until_ns, _gen) in self._block_until.items():
                if until_ns > now_ns:
                    active_blocks[z] = active_blocks.get(z, 0) + 1

        with self._stats_lock:
            return {
                "instance_id": self._instance_id,
                "cfg_fp": bundle.cfg_fp,
                "bundle_version": bundle.version,
                "enforcement_scope": self.enforcement_scope,
                "bundle_errors": list(bundle.errors[:20]),
                "bundle_warnings": list(bundle.warnings[:20]),
                "on_config_error": bundle.on_config_error,
                "total_entries": int(self._total_entries),
                "zones": zones,
                "temp_blocks": active_blocks,
                "blocklist_size": len(self._block_until),
                "global_lru_size": len(self._global_lru),
                "evict_global_count": int(self._evict_global_count),
                "evict_zone_count": int(self._evict_zone_count),
                "evict_idle_count": int(self._evict_idle_count),
                "cleanup_expired_block_count": int(self._cleanup_expired_block_count),
                "metrics_emit_count": int(self._metrics_emit_count),
                "metrics_emit_fail_count": int(self._metrics_emit_fail_count),
                "audit_emit_count": int(self._audit_emit_count),
                "audit_emit_fail_count": int(self._audit_emit_fail_count),
                "allowed_count": int(self._allowed_count),
                "denied_count": int(self._denied_count),
                "config_error_count": int(self._config_error_count),
                "last_metrics_error_code": self._last_metrics_error_code,
                "last_audit_error_code": self._last_audit_error_code,
                "degraded_since_unix_ns": self._degraded_since_unix_ns,
            }

    # ------------------------------------------------------------------
    # Bundle compilation
    # ------------------------------------------------------------------

    def _compile_bundle(self, cfg: RateLimitConfig, previous: Optional[_CompiledBundle]) -> _CompiledBundle:
        errors: list[str] = []
        warnings: list[str] = []

        # normalize enums
        on_unknown_zone = cfg.on_unknown_zone if cfg.on_unknown_zone in {"fallback_to_default", "create_if_allowed", "deny"} else "fallback_to_default"
        key_error_mode = cfg.key_error_mode if cfg.key_error_mode in {"allow", "deny"} else "deny"
        cost_over_capacity_mode = (
            cfg.cost_over_capacity_mode
            if cfg.cost_over_capacity_mode in {"deny", "audit_only", "deny_without_bucket"}
            else "deny"
        )
        new_key_policy = cfg.new_key_policy if cfg.new_key_policy in {"deny_new_when_full", "evict_lru"} else "deny_new_when_full"
        on_config_error = cfg.on_config_error if cfg.on_config_error in {"fail_closed", "fallback", "raise"} else "fail_closed"

        # default zone
        default_zone, ok = _safe_zone_name(cfg.default_zone)
        if not ok or default_zone is None:
            warnings.append("invalid default_zone; using 'default'")
            default_zone = "default"

        # compile canonical zone map
        zones_in: Dict[str, _CompiledZone] = {}
        seen_raw_to_norm: Dict[str, str] = {}
        if isinstance(cfg.zones, Mapping):
            for raw_name, raw_cfg in cfg.zones.items():
                zn, okn = _safe_zone_name(raw_name)
                if not okn or zn is None:
                    warnings.append("invalid zone name dropped")
                    continue
                prev_raw = seen_raw_to_norm.get(zn)
                if prev_raw is not None and prev_raw != raw_name:
                    errors.append(f"zone name collision after normalization: {prev_raw!r} vs {raw_name!r}")
                    continue
                seen_raw_to_norm[zn] = str(raw_name)
                if not isinstance(raw_cfg, RateLimitZoneConfig):
                    warnings.append(f"zone {zn!r} has invalid config type; using defaults")
                    raw_cfg = RateLimitZoneConfig()
                zc = raw_cfg.normalized()
                zones_in[zn] = _CompiledZone(
                    name=zn,
                    capacity_q=max(0, int(round(zc.capacity * _TOKEN_SCALE))),
                    refill_q_per_s=max(0, int(round(zc.refill_per_s * _TOKEN_SCALE))),
                    temp_block_after_denies=int(zc.temp_block_after_denies),
                    temp_block_ttl_ns=max(0, int(round(zc.temp_block_ttl * 1_000_000_000.0))),
                    max_entries=int(zc.max_entries),
                    idle_ttl_ns=max(0, int(round(zc.idle_ttl_s * 1_000_000_000.0))),
                )

        if default_zone not in zones_in:
            zones_in[default_zone] = _CompiledZone(
                name=default_zone,
                capacity_q=int(round(10.0 * _TOKEN_SCALE)),
                refill_q_per_s=int(round(10.0 * _TOKEN_SCALE)),
                temp_block_after_denies=0,
                temp_block_ttl_ns=0,
                max_entries=65_536,
                idle_ttl_ns=0,
            )
            if cfg.zones:
                warnings.append("default_zone not present in zones; default zone inserted")

        # explicit hash algorithm (no hidden environment auto-switch)
        hash_alg = cfg.hash_algorithm if cfg.hash_algorithm in {"blake2b", "blake3"} else _DEFAULT_HASH_ALG
        effective_hash_alg = hash_alg
        if hash_alg == "blake3" and Blake3Hash is None:
            errors.append("hash_algorithm='blake3' requested but Blake3Hash unavailable")
            effective_hash_alg = "blake2b"

        # salt handling
        salt_mode = "none"
        salt: Optional[bytes] = None
        min_salt_bytes = _clamp_int(cfg.min_key_hash_salt_bytes, default=16, lo=1, hi=4096)
        if type(cfg.key_hash_salt) is bytes:
            if len(cfg.key_hash_salt) >= min_salt_bytes:
                salt = bytes(cfg.key_hash_salt)
                salt_mode = "configured"
            else:
                errors.append("key_hash_salt too short; ignoring")
        elif cfg.key_hash_salt is not None:
            errors.append("invalid key_hash_salt type; ignoring")

        if salt is None and cfg.anonymize_keys and cfg.auto_ephemeral_salt_if_missing:
            if previous is not None and previous.salt_mode == "ephemeral" and previous.key_hash_salt:
                salt = previous.key_hash_salt
            else:
                salt = os.urandom(16)
            salt_mode = "ephemeral"

        # if blocklist cap is zero, disable temp blocking globally
        max_block_entries = _clamp_int(cfg.max_block_entries, default=_DEFAULT_MAX_BLOCKLIST, lo=0, hi=5_000_000)
        if max_block_entries == 0:
            adjusted: Dict[str, _CompiledZone] = {}
            for zname, zc in zones_in.items():
                adjusted[zname] = _CompiledZone(
                    name=zc.name,
                    capacity_q=zc.capacity_q,
                    refill_q_per_s=zc.refill_q_per_s,
                    temp_block_after_denies=0,
                    temp_block_ttl_ns=0,
                    max_entries=zc.max_entries,
                    idle_ttl_ns=zc.idle_ttl_ns,
                )
            zones_in = adjusted
            warnings.append("max_block_entries=0 disables temp-block persistence and temp blocking")

        fp_payload = {
            "default_zone": default_zone,
            "zones": {
                z: {
                    "capacity_q": c.capacity_q,
                    "refill_q_per_s": c.refill_q_per_s,
                    "temp_block_after_denies": c.temp_block_after_denies,
                    "temp_block_ttl_ns": c.temp_block_ttl_ns,
                    "max_entries": c.max_entries,
                    "idle_ttl_ns": c.idle_ttl_ns,
                }
                for z, c in sorted(zones_in.items())
            },
            "global_max_entries": _clamp_int(cfg.global_max_entries, default=200_000, lo=0, hi=10_000_000),
            "allow_dynamic_zones": bool(cfg.allow_dynamic_zones),
            "max_zones": _clamp_int(cfg.max_zones, default=256, lo=1, hi=100_000),
            "on_unknown_zone": on_unknown_zone,
            "new_key_policy": new_key_policy,
            "anonymize_keys": bool(cfg.anonymize_keys),
            "key_error_mode": key_error_mode,
            "hash_algorithm_requested": hash_alg,
            "hash_algorithm_effective": effective_hash_alg,
            "key_version": cfg.key_version if type(cfg.key_version) is str and cfg.key_version else _DEFAULT_KEY_VERSION,
            "salt_mode": salt_mode,
            "allow_time_override": bool(cfg.allow_time_override),
            "max_time_skew_ns": int(round(_clamp_float(cfg.max_time_skew_s, default=0.05, lo=0.0, hi=60.0) * 1_000_000_000.0)),
            "max_time_back_skew_ns": int(round(_clamp_float(cfg.max_time_back_skew_s, default=1.0, lo=0.0, hi=600.0) * 1_000_000_000.0)),
            "min_cost_q": max(1, int(round(_clamp_float(cfg.min_cost, default=1e-6, lo=1e-12, hi=1_000_000.0) * _TOKEN_SCALE))),
            "max_cost_q": max(1, int(round(_clamp_float(cfg.max_cost, default=1_000_000.0, lo=1e-12, hi=1_000_000_000.0) * _TOKEN_SCALE))),
            "cost_over_capacity_mode": cost_over_capacity_mode,
            "max_block_entries": max_block_entries,
            "blocklist_cleanup_budget": _clamp_int(cfg.blocklist_cleanup_budget, default=2, lo=0, hi=1000),
            "audit_max_event_bytes": _clamp_int(cfg.audit_max_event_bytes, default=_DEFAULT_AUDIT_MAX_EVENT_BYTES, lo=256, hi=1_000_000),
            "on_config_error": on_config_error,
        }
        cfg_fp = _cfg_fingerprint(fp_payload)

        version = 1 if previous is None else previous.version + 1
        updated_at_unix_ns = self._call_time_ns(cfg.wall_time_fn or time.time_ns, fallback=time.time_ns)

        return _CompiledBundle(
            version=version,
            updated_at_unix_ns=updated_at_unix_ns,
            cfg_fp=cfg_fp,
            errors=tuple(errors),
            warnings=tuple(warnings),
            on_config_error=on_config_error,
            default_zone=default_zone,
            zones=MappingProxyType(dict(zones_in)),
            allow_dynamic_zones=bool(cfg.allow_dynamic_zones),
            max_zones=_clamp_int(cfg.max_zones, default=256, lo=1, hi=100_000),
            on_unknown_zone=on_unknown_zone,
            new_key_policy=new_key_policy,
            enable_audit=bool(cfg.enable_audit),
            enable_metrics=bool(cfg.enable_metrics),
            exporter=cfg.exporter,
            metrics_hook=cfg.metrics_hook,
            audit_hook=cfg.audit_hook,
            monotonic_fn=cfg.monotonic_fn if callable(cfg.monotonic_fn) else time.monotonic_ns,
            wall_time_fn=cfg.wall_time_fn if callable(cfg.wall_time_fn) else time.time_ns,
            global_max_entries=_clamp_int(cfg.global_max_entries, default=200_000, lo=0, hi=10_000_000),
            anonymize_keys=bool(cfg.anonymize_keys),
            key_error_mode=key_error_mode,
            hash_algorithm=effective_hash_alg,
            key_version=cfg.key_version if type(cfg.key_version) is str and cfg.key_version else _DEFAULT_KEY_VERSION,
            key_hash_salt=salt,
            salt_mode=salt_mode,
            allow_time_override=bool(cfg.allow_time_override),
            max_time_skew_ns=int(round(_clamp_float(cfg.max_time_skew_s, default=0.05, lo=0.0, hi=60.0) * 1_000_000_000.0)),
            max_time_back_skew_ns=int(round(_clamp_float(cfg.max_time_back_skew_s, default=1.0, lo=0.0, hi=600.0) * 1_000_000_000.0)),
            min_cost_q=max(1, int(round(_clamp_float(cfg.min_cost, default=1e-6, lo=1e-12, hi=1_000_000.0) * _TOKEN_SCALE))),
            max_cost_q=max(1, int(round(_clamp_float(cfg.max_cost, default=1_000_000.0, lo=1e-12, hi=1_000_000_000.0) * _TOKEN_SCALE))),
            cost_over_capacity_mode=cost_over_capacity_mode,
            max_block_entries=max_block_entries,
            blocklist_cleanup_budget=_clamp_int(cfg.blocklist_cleanup_budget, default=2, lo=0, hi=1000),
            audit_max_event_bytes=_clamp_int(cfg.audit_max_event_bytes, default=_DEFAULT_AUDIT_MAX_EVENT_BYTES, lo=256, hi=1_000_000),
        )

    # ------------------------------------------------------------------
    # Internal time / decision helpers
    # ------------------------------------------------------------------

    def _call_time_ns(self, fn: Callable[[], Any], *, fallback: Callable[[], int]) -> int:
        try:
            v = fn()
        except Exception:
            return int(fallback())
        if type(v) is int:
            return int(v)
        if _is_finite_number(v):
            return int(float(v) * 1_000_000_000.0)
        return int(fallback())

    def _mono_ns(self) -> int:
        return self._call_time_ns(self._bundle.monotonic_fn, fallback=time.monotonic_ns)

    def _wall_ns(self) -> int:
        return self._call_time_ns(self._bundle.wall_time_fn, fallback=time.time_ns)

    def _resolve_now_ns(self, bundle: _CompiledBundle, now: Optional[float]) -> int:
        real = self._mono_ns()
        if not bundle.allow_time_override:
            return real

        n = _coerce_float(now)
        if n is None:
            return real

        now_ns = int(n * 1_000_000_000.0)
        if now_ns > real + bundle.max_time_skew_ns:
            return real
        if now_ns < real - bundle.max_time_back_skew_ns:
            return real
        return now_ns

    def _cost_to_q(self, bundle: _CompiledBundle, cost: Any) -> int:
        x = _clamp_float(cost, default=1.0, lo=0.0, hi=1_000_000_000.0)
        q = int(round(x * _TOKEN_SCALE))
        if q < bundle.min_cost_q:
            q = bundle.min_cost_q
        if q > bundle.max_cost_q:
            q = bundle.max_cost_q
        return q

    def _q_to_float(self, q: int) -> float:
        return float(q) / float(_TOKEN_SCALE)

    def _with_seq(self, d: RateDecision, *, seq: int, bundle_version: int) -> RateDecision:
        return RateDecision(
            allowed=d.allowed,
            zone=d.zone,
            remaining_tokens=d.remaining_tokens,
            blocked_until=d.blocked_until,
            reason=d.reason,
            retry_after_s=d.retry_after_s,
            cost=d.cost,
            key_id=d.key_id,
            cfg_fp=d.cfg_fp,
            decision_seq=seq,
            bundle_version=bundle_version,
            decision_ts_mono_ns=d.decision_ts_mono_ns,
            decision_ts_unix_ns=d.decision_ts_unix_ns,
            blocked_until_mono_ns=d.blocked_until_mono_ns,
            blocked_until_unix_ns=d.blocked_until_unix_ns,
            zone_resolution=d.zone_resolution,
            requested_zone_hash=d.requested_zone_hash,
            algorithm_id=d.algorithm_id,
            state_scope=d.state_scope,
        )


    def _finalize_decision(self, d: RateDecision, *, bundle: _CompiledBundle) -> RateDecision:
        with self._lock:
            self._decision_seq += 1
            return self._with_seq(d, seq=self._decision_seq, bundle_version=bundle.version)

    def _peek_decision_impl(self, *, key: Any, cost: float, zone: Optional[str]) -> RateDecision:
        bundle = self._bundle
        now_mono_ns = self._mono_ns()
        now_unix_ns = self._wall_ns()
        cost_q = self._cost_to_q(bundle, cost)

        if bundle.errors:
            if bundle.on_config_error == "raise":
                raise RuntimeError("rate limiter config invalid")
            if bundle.on_config_error == "fail_closed":
                d = self._make_decision(
                    bundle=bundle,
                    allowed=False,
                    resolved_zone=bundle.default_zone,
                    reason="config_error",
                    remaining_tokens_q=0,
                    blocked_until_mono_ns=None,
                    retry_after_s=None,
                    cost_q=cost_q,
                    key_id=None,
                    zone_resolution="config_error",
                    requested_zone_hash=self._requested_zone_hash(bundle, zone),
                    now_mono_ns=now_mono_ns,
                    now_unix_ns=now_unix_ns,
                )
                return self._with_seq(d, seq=0, bundle_version=bundle.version)

        zone_res = self._resolve_zone(bundle, zone)
        if zone_res.resolution_state == "denied":
            d = self._make_decision(
                bundle=bundle,
                allowed=False,
                resolved_zone=zone_res.resolved_zone,
                reason=zone_res.reason,
                remaining_tokens_q=0,
                blocked_until_mono_ns=None,
                retry_after_s=None,
                cost_q=cost_q,
                key_id=None,
                zone_resolution=zone_res.resolution_state,
                requested_zone_hash=zone_res.requested_zone_hash,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
            )
            return self._with_seq(d, seq=0, bundle_version=bundle.version)

        zone_name = zone_res.resolved_zone
        zone_cfg = zone_res.zone_cfg
        key_id = self._key_id(bundle, key)
        if key_id is None:
            allowed = bundle.key_error_mode == "allow"
            d = self._make_decision(
                bundle=bundle,
                allowed=allowed,
                resolved_zone=zone_name,
                reason="key_error_allow" if allowed else "key_error_deny",
                remaining_tokens_q=0,
                blocked_until_mono_ns=None,
                retry_after_s=None,
                cost_q=cost_q,
                key_id=None,
                zone_resolution=zone_res.resolution_state,
                requested_zone_hash=zone_res.requested_zone_hash,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
            )
            return self._with_seq(d, seq=0, bundle_version=bundle.version)

        with self._lock:
            blocked_until_ns = self._get_block_until((zone_name, key_id))
            if blocked_until_ns is not None and blocked_until_ns > now_mono_ns:
                d = self._make_decision(
                    bundle=bundle,
                    allowed=False,
                    resolved_zone=zone_name,
                    reason="temp_block",
                    remaining_tokens_q=0,
                    blocked_until_mono_ns=blocked_until_ns,
                    retry_after_s=max(0.0, (blocked_until_ns - now_mono_ns) / 1_000_000_000.0),
                    cost_q=cost_q,
                    key_id=key_id,
                    zone_resolution=zone_res.resolution_state,
                    requested_zone_hash=zone_res.requested_zone_hash,
                    now_mono_ns=now_mono_ns,
                    now_unix_ns=now_unix_ns,
                )
                return self._with_seq(d, seq=0, bundle_version=bundle.version)

            zs = self._zones.get(zone_name)
            st = zs.buckets.get(key_id) if zs is not None else None
            if st is None:
                tokens_q = zone_cfg.capacity_q
            else:
                elapsed_ns = max(0, now_mono_ns - st.ts_ns)
                tokens_q = st.tokens_q
                if zone_cfg.refill_q_per_s > 0 and zone_cfg.capacity_q > 0:
                    add_q = (elapsed_ns * zone_cfg.refill_q_per_s) // 1_000_000_000
                    tokens_q = min(zone_cfg.capacity_q, tokens_q + max(0, add_q))
                else:
                    tokens_q = min(max(0, tokens_q), zone_cfg.capacity_q)

        if cost_q > zone_cfg.capacity_q:
            d = self._make_decision(
                bundle=bundle,
                allowed=False,
                resolved_zone=zone_name,
                reason="cost_over_capacity",
                remaining_tokens_q=max(0, tokens_q),
                blocked_until_mono_ns=None,
                retry_after_s=None,
                cost_q=cost_q,
                key_id=key_id,
                zone_resolution=zone_res.resolution_state,
                requested_zone_hash=zone_res.requested_zone_hash,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
            )
            return self._with_seq(d, seq=0, bundle_version=bundle.version)

        if tokens_q >= cost_q:
            d = self._make_decision(
                bundle=bundle,
                allowed=True,
                resolved_zone=zone_name,
                reason="ok",
                remaining_tokens_q=max(0, tokens_q),
                blocked_until_mono_ns=None,
                retry_after_s=None,
                cost_q=cost_q,
                key_id=key_id,
                zone_resolution=zone_res.resolution_state,
                requested_zone_hash=zone_res.requested_zone_hash,
                now_mono_ns=now_mono_ns,
                now_unix_ns=now_unix_ns,
            )
            return self._with_seq(d, seq=0, bundle_version=bundle.version)

        retry_after_s = None
        if zone_cfg.refill_q_per_s > 0:
            deficit_q = max(0, cost_q - tokens_q)
            retry_ns = (deficit_q * 1_000_000_000 + zone_cfg.refill_q_per_s - 1) // zone_cfg.refill_q_per_s
            retry_after_s = retry_ns / 1_000_000_000.0

        d = self._make_decision(
            bundle=bundle,
            allowed=False,
            resolved_zone=zone_name,
            reason="exhausted",
            remaining_tokens_q=max(0, tokens_q),
            blocked_until_mono_ns=None,
            retry_after_s=retry_after_s,
            cost_q=cost_q,
            key_id=key_id,
            zone_resolution=zone_res.resolution_state,
            requested_zone_hash=zone_res.requested_zone_hash,
            now_mono_ns=now_mono_ns,
            now_unix_ns=now_unix_ns,
        )
        return self._with_seq(d, seq=0, bundle_version=bundle.version)

    def _make_decision(
        self,
        *,
        bundle: _CompiledBundle,
        allowed: bool,
        resolved_zone: str,
        reason: str,
        remaining_tokens_q: int,
        blocked_until_mono_ns: Optional[int],
        retry_after_s: Optional[float],
        cost_q: int,
        key_id: Optional[str],
        zone_resolution: str,
        requested_zone_hash: Optional[str],
        now_mono_ns: int,
        now_unix_ns: int,
    ) -> RateDecision:
        blocked_until_unix_ns: Optional[int] = None
        blocked_until: Optional[float] = None

        if blocked_until_mono_ns is not None:
            blocked_until = blocked_until_mono_ns / 1_000_000_000.0
            delta_ns = max(0, blocked_until_mono_ns - now_mono_ns)
            blocked_until_unix_ns = now_unix_ns + delta_ns

        return RateDecision(
            allowed=allowed,
            zone=resolved_zone,
            remaining_tokens=self._q_to_float(max(0, remaining_tokens_q)),
            blocked_until=blocked_until,
            reason=reason,
            retry_after_s=retry_after_s,
            cost=self._q_to_float(cost_q),
            key_id=key_id,
            cfg_fp=bundle.cfg_fp,
            decision_seq=0,
            bundle_version=0,
            decision_ts_mono_ns=now_mono_ns,
            decision_ts_unix_ns=now_unix_ns,
            blocked_until_mono_ns=blocked_until_mono_ns,
            blocked_until_unix_ns=blocked_until_unix_ns,
            zone_resolution=zone_resolution,
            requested_zone_hash=requested_zone_hash,
            algorithm_id=f"{bundle.key_version}:{bundle.hash_algorithm}",
            state_scope=self.enforcement_scope,
        )

    # ------------------------------------------------------------------
    # Zone resolution
    # ------------------------------------------------------------------

    def _requested_zone_hash(self, bundle: _CompiledBundle, zone: Any) -> Optional[str]:
        if type(zone) is not str:
            return None
        try:
            b = _encode_str_exact(zone)
        except Exception:
            return None
        digest = _hash_bytes(
            data=b,
            ctx=_CTX_ZONE_REQ,
            salt=bundle.key_hash_salt,
            alg=bundle.hash_algorithm,
            out_hex_chars=32,
        )
        return f"{bundle.key_version}:{digest}"

    def _resolve_zone(self, bundle: _CompiledBundle, zone: Any) -> "RateLimiter._ZoneResolution":
        # Missing zone is valid and means default.
        if zone is None:
            zcfg = bundle.zones[bundle.default_zone]
            return self._ZoneResolution(
                resolved_zone=bundle.default_zone,
                zone_cfg=zcfg,
                resolution_state="defaulted",
                reason="ok",
                requested_zone_hash=None,
            )

        zreq, ok = _safe_zone_name(zone)
        req_hash = self._requested_zone_hash(bundle, zone)
        if not ok or zreq is None:
            zcfg = bundle.zones[bundle.default_zone]
            if bundle.on_unknown_zone == "deny":
                return self._ZoneResolution(
                    resolved_zone=bundle.default_zone,
                    zone_cfg=zcfg,
                    resolution_state="denied",
                    reason="invalid_zone",
                    requested_zone_hash=req_hash,
                )
            return self._ZoneResolution(
                resolved_zone=bundle.default_zone,
                zone_cfg=zcfg,
                resolution_state="defaulted",
                reason="ok",
                requested_zone_hash=req_hash,
            )

        zcfg = bundle.zones.get(zreq)
        if zcfg is not None:
            return self._ZoneResolution(
                resolved_zone=zreq,
                zone_cfg=zcfg,
                resolution_state="resolved",
                reason="ok",
                requested_zone_hash=req_hash,
            )

        if bundle.on_unknown_zone == "create_if_allowed" and bundle.allow_dynamic_zones:
            return self._ZoneResolution(
                resolved_zone=zreq,
                zone_cfg=bundle.zones[bundle.default_zone],
                resolution_state="created_dynamic",
                reason="ok",
                requested_zone_hash=req_hash,
            )

        if bundle.on_unknown_zone == "deny":
            return self._ZoneResolution(
                resolved_zone=bundle.default_zone,
                zone_cfg=bundle.zones[bundle.default_zone],
                resolution_state="denied",
                reason="unknown_zone",
                requested_zone_hash=req_hash,
            )

        return self._ZoneResolution(
            resolved_zone=bundle.default_zone,
            zone_cfg=bundle.zones[bundle.default_zone],
            resolution_state="defaulted",
            reason="ok",
            requested_zone_hash=req_hash,
        )

    # ------------------------------------------------------------------
    # Key hashing / admission
    # ------------------------------------------------------------------

    def _key_id(self, bundle: _CompiledBundle, key: Any) -> Optional[str]:
        b = _key_fingerprint_bytes(key)
        if b is None:
            return None
        ctx = _CTX_KEY if bundle.anonymize_keys else _CTX_RAW
        digest = _hash_bytes(
            data=b,
            ctx=ctx,
            salt=bundle.key_hash_salt,
            alg=bundle.hash_algorithm,
            out_hex_chars=48,
        )
        return f"{bundle.key_version}:{digest}"

    def _admit_new_key_locked(
        self,
        bundle: _CompiledBundle,
        zone_name: str,
        zone_cfg: _CompiledZone,
        zs: _ZoneState,
    ) -> Optional[str]:
        """
        Returns deny reason if the new key may not be admitted, else None.
        New state is not silently admitted when the limiter is full.
        """
        if zone_cfg.max_entries > 0 and len(zs.buckets) >= zone_cfg.max_entries:
            self._evict_idle_in_zone(zs, zone_name, self._mono_ns())
            if len(zs.buckets) >= zone_cfg.max_entries:
                if bundle.new_key_policy == "evict_lru" and zs.lru:
                    oldest = next(iter(zs.lru.keys()))
                    self._evict_bucket(zone_name, zs, oldest)
                    self._evict_zone_count += 1
                else:
                    return "zone_state_full"

        if bundle.global_max_entries > 0 and self._total_entries >= bundle.global_max_entries:
            if bundle.new_key_policy == "evict_lru" and self._global_lru:
                (z_old, k_old), _ = self._global_lru.popitem(last=False)
                zs_old = self._zones.get(z_old)
                if zs_old is not None:
                    self._evict_bucket(z_old, zs_old, k_old)
                    self._evict_global_count += 1
            else:
                return "global_state_full"

        if zone_name not in self._zones and bundle.allow_dynamic_zones:
            if len(self._zones) >= bundle.max_zones:
                return "zone_capacity_full"

        return None

    # ------------------------------------------------------------------
    # Blocklist
    # ------------------------------------------------------------------

    def _get_block_until(self, blk_key: Tuple[str, str]) -> Optional[int]:
        rec = self._block_until.get(blk_key)
        if rec is None:
            return None
        return rec[0]

    def _touch_block(self, blk_key: Tuple[str, str]) -> None:
        if blk_key in self._block_lru:
            self._block_lru.pop(blk_key, None)
            self._block_lru[blk_key] = None

    def _clear_block(self, blk_key: Tuple[str, str]) -> None:
        self._block_until.pop(blk_key, None)
        self._block_lru.pop(blk_key, None)

    def _set_block(self, blk_key: Tuple[str, str], until_ns: int, bundle: _CompiledBundle) -> None:
        self._block_gen += 1
        gen = self._block_gen
        self._block_until[blk_key] = (until_ns, gen)
        self._block_lru.pop(blk_key, None)
        self._block_lru[blk_key] = None
        heapq.heappush(self._block_heap, (until_ns, gen, blk_key))

        maxb = bundle.max_block_entries
        if maxb <= 0:
            self._clear_block(blk_key)
            return

        while len(self._block_lru) > maxb:
            oldest_key, _ = self._block_lru.popitem(last=False)
            self._block_until.pop(oldest_key, None)

    def _cleanup_blocks_budgeted(self, now_ns: int, budget: Optional[int] = None) -> None:
        b = self._bundle
        remaining = b.blocklist_cleanup_budget if budget is None else budget
        if remaining <= 0:
            return

        while remaining > 0 and self._block_heap:
            until_ns, gen, blk_key = self._block_heap[0]
            current = self._block_until.get(blk_key)
            if current is None:
                heapq.heappop(self._block_heap)
                remaining -= 1
                continue
            cur_until, cur_gen = current
            if cur_gen != gen or cur_until != until_ns:
                heapq.heappop(self._block_heap)
                remaining -= 1
                continue
            if until_ns > now_ns:
                break

            heapq.heappop(self._block_heap)
            self._clear_block(blk_key)
            self._cleanup_expired_block_count += 1
            remaining -= 1

    # ------------------------------------------------------------------
    # Eviction / state management
    # ------------------------------------------------------------------

    def _touch_global_lru(self, bucket_key: Tuple[str, str]) -> None:
        self._global_lru.pop(bucket_key, None)
        self._global_lru[bucket_key] = None

    def _remove_zone_state_locked(self, zone_name: str) -> None:
        zs = self._zones.pop(zone_name, None)
        if zs is None:
            return
        for key_id in list(zs.buckets.keys()):
            self._global_lru.pop((zone_name, key_id), None)
            self._clear_block((zone_name, key_id))
        self._total_entries = max(0, self._total_entries - len(zs.buckets))

    def _evict_idle_in_zone(self, zs: _ZoneState, zone_name: str, now_ns: int, budget: int = 4) -> None:
        ttl_ns = zs.cfg.idle_ttl_ns
        if ttl_ns <= 0:
            return

        while budget > 0 and zs.lru:
            oldest_key = next(iter(zs.lru.keys()))
            st = zs.buckets.get(oldest_key)
            if st is None:
                zs.lru.pop(oldest_key, None)
                budget -= 1
                continue
            if (now_ns - st.ts_ns) <= ttl_ns:
                break
            self._evict_bucket(zone_name, zs, oldest_key)
            self._evict_idle_count += 1
            budget -= 1

    def _evict_zone_if_needed(self, zone_name: str, zs: _ZoneState) -> None:
        me = zs.cfg.max_entries
        if me <= 0:
            return
        while len(zs.buckets) > me and zs.lru:
            oldest_key = next(iter(zs.lru.keys()))
            self._evict_bucket(zone_name, zs, oldest_key)
            self._evict_zone_count += 1

    def _evict_global_if_needed(self) -> None:
        limit = self._bundle.global_max_entries
        if limit <= 0:
            return
        while self._total_entries > limit and self._global_lru:
            (z, kid), _ = self._global_lru.popitem(last=False)
            zs = self._zones.get(z)
            if zs is not None:
                self._evict_bucket(z, zs, kid)
                self._evict_global_count += 1

    def _evict_bucket(self, zone_name: str, zs: _ZoneState, key_id: str) -> None:
        if key_id in zs.buckets:
            zs.buckets.pop(key_id, None)
            zs.lru.pop(key_id, None)
            self._global_lru.pop((zone_name, key_id), None)
            self._total_entries = max(0, self._total_entries - 1)

    # ------------------------------------------------------------------
    # Telemetry / audit
    # ------------------------------------------------------------------

    def _metrics_zone_label(self, decision: RateDecision) -> str:
        if decision.reason == "unknown_zone":
            return "__unknown__"
        if decision.reason == "invalid_zone":
            return "__invalid__"
        return decision.zone

    def _audit_classification(self, reason: str) -> str:
        if reason in {"unknown_zone", "invalid_zone", "key_error_deny"}:
            return "client_error"
        if reason in {"cost_over_capacity", "config_error", "zone_state_full", "global_state_full", "zone_capacity_full"}:
            return "policy_misconfig"
        if reason in {"exhausted", "temp_block"}:
            return "expected_rate_limit"
        return "security_event"

    def _mark_degraded(self, *, which: str, code: str, when_unix_ns: int) -> None:
        with self._stats_lock:
            if which == "metrics":
                self._last_metrics_error_code = code
            else:
                self._last_audit_error_code = code
            if self._degraded_since_unix_ns is None:
                self._degraded_since_unix_ns = when_unix_ns

    def _emit_after_decision(
        self,
        *,
        bundle: _CompiledBundle,
        decision: RateDecision,
        zone_cfg: _CompiledZone,
        denies: Optional[int],
    ) -> None:
        # Metrics: strict low cardinality
        if bundle.enable_metrics:
            labels: Dict[str, Any] = {
                "zone": self._metrics_zone_label(decision),
                "allowed": "1" if decision.allowed else "0",
                "reason": decision.reason,
            }
            emitted = False
            failed = False

            exp = bundle.exporter
            if exp is not None and hasattr(exp, "record_metric"):
                try:
                    exp.record_metric(name="tcd.rate_limit", value=1.0, labels=labels)
                    emitted = True
                except Exception:
                    failed = True

            if bundle.metrics_hook is not None:
                try:
                    bundle.metrics_hook("tcd.rate_limit", 1.0, labels)
                    emitted = True
                except Exception:
                    failed = True

            with self._stats_lock:
                if emitted:
                    self._metrics_emit_count += 1
                if failed:
                    self._metrics_emit_fail_count += 1

            if failed:
                self._mark_degraded(which="metrics", code="emit_failed", when_unix_ns=decision.decision_ts_unix_ns)

        # Audit
        if bundle.enable_audit and bundle.audit_hook is not None and (not decision.allowed or decision.reason != "ok"):
            event = {
                "schema": "tcd.ratelimit.audit",
                "schema_version": 1,
                "event_type": "tcd.rate_limit",
                "event_id": _event_id(self._instance_id, decision.decision_seq, decision.decision_ts_unix_ns),
                "instance_id": self._instance_id,
                "component": "ratelimit",
                "component_version": 1,
                "cfg_fp": bundle.cfg_fp,
                "bundle_version": bundle.version,
                "state_scope": self.enforcement_scope,
                "algorithm_id": decision.algorithm_id,
                "decision_seq": decision.decision_seq,
                "decision_ts_unix_ns": decision.decision_ts_unix_ns,
                "decision_ts_mono_ns": decision.decision_ts_mono_ns,
                "zone": decision.zone,
                "zone_resolution": decision.zone_resolution,
                "requested_zone_hash": decision.requested_zone_hash,
                "key_hash": decision.key_id,
                "allowed": bool(decision.allowed),
                "reason": decision.reason,
                "classification": self._audit_classification(decision.reason),
                "cost": float(decision.cost),
                "remaining_tokens": float(decision.remaining_tokens),
                "retry_after_s": float(decision.retry_after_s) if decision.retry_after_s is not None else None,
                "blocked_until_unix_ns": decision.blocked_until_unix_ns,
                "blocked_until_mono_ns": decision.blocked_until_mono_ns,
                "consecutive_denies": int(denies) if denies is not None else None,
                "capacity": self._q_to_float(zone_cfg.capacity_q),
                "refill_per_s": self._q_to_float(zone_cfg.refill_q_per_s),
                "temp_block_after_denies": int(zone_cfg.temp_block_after_denies),
                "temp_block_ttl_s": zone_cfg.temp_block_ttl_ns / 1_000_000_000.0,
            }
            event = self._shrink_audit_event(event, max_bytes=bundle.audit_max_event_bytes)

            try:
                bundle.audit_hook(event)
                with self._stats_lock:
                    self._audit_emit_count += 1
            except Exception:
                with self._stats_lock:
                    self._audit_emit_fail_count += 1
                self._mark_degraded(which="audit", code="emit_failed", when_unix_ns=decision.decision_ts_unix_ns)

    def _shrink_audit_event(self, event: Dict[str, Any], *, max_bytes: int) -> Dict[str, Any]:
        def _dumps_len(ev: Dict[str, Any]) -> int:
            return len(
                json.dumps(
                    ev,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8", errors="strict")
            )

        try:
            if _dumps_len(event) <= max_bytes:
                return event
        except Exception:
            pass

        shrunk = dict(event)
        shrunk["_tcd_shrunk"] = True

        for k in (
            "remaining_tokens",
            "retry_after_s",
            "consecutive_denies",
            "capacity",
            "refill_per_s",
            "temp_block_after_denies",
            "temp_block_ttl_s",
            "requested_zone_hash",
            "key_hash",
            "blocked_until_mono_ns",
            "blocked_until_unix_ns",
        ):
            shrunk.pop(k, None)
            try:
                if _dumps_len(shrunk) <= max_bytes:
                    return shrunk
            except Exception:
                pass

        return {
            "schema": "tcd.ratelimit.audit",
            "schema_version": 1,
            "event_type": "tcd.rate_limit",
            "instance_id": self._instance_id,
            "cfg_fp": event.get("cfg_fp"),
            "bundle_version": event.get("bundle_version"),
            "decision_seq": event.get("decision_seq"),
            "decision_ts_unix_ns": event.get("decision_ts_unix_ns"),
            "zone": event.get("zone"),
            "zone_resolution": event.get("zone_resolution"),
            "allowed": event.get("allowed"),
            "reason": event.get("reason"),
            "_tcd_shrunk": True,
        }