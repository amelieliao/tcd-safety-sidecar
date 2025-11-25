# FILE: tcd/kv.py
from __future__ import annotations

"""
Helpers for stable key/value hashing and deterministic IDs.

This module is used to build:
  - receipt heads and chain identifiers;
  - stable IDs for events, chains, and PQ attestations;
  - e-process / alpha-investing envelope hashes that are content-agnostic.

Key properties:
  - Deterministic, canonical encoding of basic Python types;
  - Streaming hasher with optional HMAC-style secret key for privacy;
  - Explicit domain separation via labels and context strings;
  - Guards against accidentally hashing raw content payloads.

The goal is to hash *envelopes* (tags, IDs, numeric scores) rather than
raw prompts/completions/bodies, so that derived IDs are stable, low-leakage,
and auditable.
"""

import hashlib
import hmac
import json
import os
import struct
from typing import Iterable, Any, Mapping, Optional, Set


# ---- Digest algorithm controls ----

_ALLOWED_DIGEST_ALGS: Set[str] = {"sha256", "blake2s"}
_ALLOW_LEGACY_ALGS = os.environ.get("TCD_KV_ALLOW_LEGACY_ALGS", "0") == "1"


def _resolve_digest(alg: str):
    """
    Map a requested algorithm name to a hashlib constructor.

    Security notes:
      - Only a small set of modern digests are allowed by default.
      - "blake3" is treated as an alias for SHA-256 for backwards compatibility.
      - Weak or unknown algorithms are rejected unless TCD_KV_ALLOW_LEGACY_ALGS=1.
    """
    name = (alg or "").lower()
    if name in ("sha256", "sha-256", "blake3", ""):
        return hashlib.sha256
    if name in ("blake2s", "b2s"):
        return getattr(hashlib, "blake2s", hashlib.sha256)

    if _ALLOW_LEGACY_ALGS:
        # Fallback to SHA-256 while still making misuse explicit to callers.
        return hashlib.sha256

    raise ValueError(f"Unsupported digest algorithm for kv hashing: {alg!r}")


# ---- Float encoding controls ----

_KV_FLOAT_MODE = os.environ.get("TCD_KV_FLOAT_MODE", "repr").lower()
# Allowed values:
#   "repr" - human-readable, compatible with previous behavior;
#   "ieee" - 8-byte big-endian IEEE-754, suitable for strict AE / PQ flows.


def _encode_float_bytes(value: float) -> bytes:
    """
    Encode float deterministically for hashing.

    Modes:
      - repr: use repr(value) UTF-8 encoded;
      - ieee: use IEEE-754 64-bit big-endian.
    NaN and infinities are rejected.
    """
    v = float(value)
    if not (v == v) or v in (float("inf"), float("-inf")):
        raise ValueError("NaN or infinite values are not allowed in kv float encoding")
    if _KV_FLOAT_MODE == "ieee":
        return struct.pack("!d", v)
    # Default "repr" mode (backwards compatible)
    return repr(v).encode("utf-8", errors="ignore")


# ---- Content-agnostic guards ----

# Keys that must never be hashed directly here (to keep content out of envelope hashes).
_FORBIDDEN_KV_KEYS = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "messages",
    "content",
    "body",
    "raw",
}
_KV_FORBID_CONTENT_KEYS = os.environ.get("TCD_KV_FORBID_CONTENT_KEYS", "1") == "1"

# Rough guard for total size of KV material before hashing (in bytes).
_KV_MAX_APPROX_BYTES = int(os.environ.get("TCD_KV_MAX_BYTES", "4096"))


# ---- HMAC key normalization ----

def _normalize_key(key: Optional[bytes]) -> Optional[bytes]:
    """
    Normalize and validate an HMAC key.

    Requirements:
      - Must be bytes or bytearray;
      - Minimum length 16 bytes (intended for production deployments).
    """
    if key is None:
        return None
    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("HMAC key must be bytes or bytearray")
    if len(key) < 16:
        # For tests you can use a longer random key; for production this
        # is intentionally strict to avoid weak HMAC configurations.
        raise ValueError("HMAC key too short; expected at least 16 bytes")
    return bytes(key)


# ---- Integer encoding ----

def _encode_u64_le(value: int) -> bytes:
    """
    Encode a non-negative integer as unsigned 64-bit little-endian.

    This is used for stable integer encoding in RollingHasher.update_ints.
    """
    iv = int(value)
    if iv < 0:
        raise ValueError("RollingHasher only supports non-negative integers")
    return iv.to_bytes(8, "little", signed=False)


class RollingHasher:
    """
    Streaming hasher for building stable digests over simple structures.

    Features:
      - Fixed digest algorithm (default SHA-256) chosen by a symbolic `alg`;
      - Optional HMAC-style secret key to avoid cross-system linkability;
      - Domain separation via an explicit `label` and user-provided `ctx`;
      - Helpers for integers, bytes, strings, and JSON-compatible values.

    Backwards compatibility:
      - The original implementation ignored `alg` and always used SHA-256.
      - Context was simply UTF-8 encoded and fed once at construction.
      - `update_ints` encoded each integer as 8-byte little-endian.

    The current implementation keeps those semantics for existing call sites:
      - Default `alg="blake3"` still maps to SHA-256 internally.
      - The `ctx` argument is encoded and fed exactly once at init.
      - `update_ints` uses the same 8-byte little-endian encoding.
    """

    def __init__(
        self,
        alg: str = "blake3",
        ctx: str = "",
        *,
        key: Optional[bytes] = None,
        label: str = "",
    ):
        """
        Create a new rolling hasher.

        Args:
          alg: symbolic name for the digest algorithm ("sha256", "blake2s", etc.).
               Currently, "blake3" is treated as an alias for SHA-256.
          ctx: free-form context string; encoded as UTF-8 and fed once.
          key: optional secret key for HMAC-style hashing; when provided,
               HMAC(key, data, digestmod=alg) is used.
          label: optional domain-separation label for this hash stream
                 (e.g. "receipt_head", "chain_id", "pq_attest").
        """
        digestmod = _resolve_digest(alg)
        self._alg = alg

        if key is not None:
            key = _normalize_key(key)
            self._h = hmac.new(key, digestmod=digestmod)
        else:
            self._h = digestmod()

        # Domain-separation label (does not change previous ctx semantics)
        if label:
            self._h.update(b"kv.label:")
            self._h.update(label.encode("utf-8", errors="ignore"))
            self._h.update(b"\x00")

        # Backwards-compatible context seeding
        if ctx:
            self._h.update(ctx.encode("utf-8", errors="ignore"))

    def update_ints(self, xs: Iterable[int]) -> None:
        """
        Update the rolling hash with a sequence of non-negative integers,
        each encoded as unsigned 64-bit little-endian.

        This method preserves the behavior of the original implementation.
        """
        for v in xs or []:
            self._h.update(_encode_u64_le(v))

    def update_bytes(self, data: bytes) -> None:
        """
        Update the hasher with a raw byte sequence.
        """
        if not data:
            return
        self._h.update(data)

    def update_str(self, value: str) -> None:
        """
        Update the hasher with a UTF-8 encoded string.
        """
        if not value:
            return
        self._h.update(value.encode("utf-8", errors="ignore"))

    def update_json(self, obj: Any) -> None:
        """
        Update the hasher with a canonical JSON encoding of the given object.

        Canonical JSON:
          - sort_keys=True for deterministic key ordering;
          - separators=(",", ":") for a compact, stable representation;
          - ensure_ascii=False to keep Unicode stable.
        """
        payload = json.dumps(
            obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        self._h.update(payload.encode("utf-8"))

    def hex(self) -> str:
        """
        Return the hex digest of the current hash state.

        Calling this does NOT reset the internal state; further updates
        are still allowed and will change subsequent hex() results.
        """
        return self._h.hexdigest()


def _feed_scalar(h: RollingHasher, value: Any) -> None:
    """
    Feed a scalar into the hasher in a stable, typed way.

    Scalars are encoded as a small type tag followed by a canonical string
    or byte representation to avoid ambiguity between, for example,
    "True" and "1".
    """
    if value is None:
        h.update_bytes(b"t:none;")
        return

    if isinstance(value, bool):
        h.update_bytes(b"t:bool;")
        h.update_bytes(b"1" if value else b"0")
        h.update_bytes(b";")
        return

    if isinstance(value, int):
        h.update_bytes(b"t:int;")
        h.update_str(str(int(value)))
        h.update_bytes(b";")
        return

    if isinstance(value, float):
        h.update_bytes(b"t:float;")
        h.update_bytes(_encode_float_bytes(value))
        h.update_bytes(b";")
        return

    if isinstance(value, str):
        h.update_bytes(b"t:str;")
        h.update_str(value)
        h.update_bytes(b";")
        return

    # For all remaining types, fall back to canonical JSON
    h.update_bytes(b"t:json;")
    h.update_json(value)
    h.update_bytes(b";")


def canonical_kv_hash(
    mapping: Mapping[str, Any],
    *,
    ctx: str = "",
    label: str = "kv",
    key: Optional[bytes] = None,
    alg: str = "blake3",
) -> str:
    """
    Compute a canonical hash for a mapping of key/value pairs.

    Intended usage:
      - Build stable IDs for receipts, chains, PQ attestations, and
        e-process envelopes (e_value, a_alloc, score, etc.).
      - Use small, tag-like keys and scalar values where possible.
      - Treat the mapping as an unordered set of key/value pairs.

    Rules:
      - Keys are converted to strings and sorted lexicographically.
      - For each key, we feed "k:<key>;v:<typed_value>;" into the hasher.
      - Values are encoded via `_feed_scalar`, using type tags.
      - The overall hash is independent of the original mapping insertion order.

    Security guards:
      - Forbids clearly content-like keys such as "prompt" or "completion".
      - Rejects overly large mappings based on an approximate byte estimate.
    """
    # 1) Basic misuse defense: forbid content-bearing keys by default.
    if _KV_FORBID_CONTENT_KEYS:
        for k in mapping.keys():
            ks = str(k)
            if ks.lower() in _FORBIDDEN_KV_KEYS:
                raise ValueError(f"canonical_kv_hash: forbidden key in mapping: {ks!r}")

    # 2) Approximate size guard to keep this strictly envelope-level.
    approx = 0
    for k, v in mapping.items():
        ks = str(k)
        approx += len(ks)
        if isinstance(v, bytes):
            approx += len(v)
        elif isinstance(v, str):
            approx += len(v.encode("utf-8", errors="ignore"))
        else:
            approx += len(repr(v))
        if approx > _KV_MAX_APPROX_BYTES:
            raise ValueError("canonical_kv_hash: mapping too large for envelope hashing")

    rh = RollingHasher(alg=alg, ctx=ctx, key=key, label=label)
    # Sort keys for canonical ordering
    for k in sorted(mapping.keys(), key=lambda x: str(x)):
        ks = str(k)
        rh.update_bytes(b"k:")
        rh.update_str(ks)
        rh.update_bytes(b";v:")
        _feed_scalar(rh, mapping[k])
        rh.update_bytes(b";")
    return rh.hex()


# ---- Standardized envelope helpers ----

def eprocess_envelope_hash(
    *,
    e_value: float,
    a_alloc: float,
    score: float,
    wealth_before: float,
    wealth_after: float,
    policy_ref: str,
    ctx: str = "",
    key: Optional[bytes] = None,
    alg: str = "blake3",
) -> str:
    """
    Hash for e-process / alpha-investing envelope.

    All inputs are expected to be already sanitized (finite and clipped).
    """
    mapping = {
        "e_value": float(e_value),
        "a_alloc": float(a_alloc),
        "score": float(score),
        "wealth_before": float(wealth_before),
        "wealth_after": float(wealth_after),
        "policy_ref": str(policy_ref),
    }
    return canonical_kv_hash(
        mapping,
        ctx=ctx,
        label="e_process",
        key=key,
        alg=alg,
    )


def pq_attestation_hash(
    *,
    pq_scheme: str,
    pq_required: bool,
    pq_ok: bool,
    chain_id: str,
    ctx: str = "",
    key: Optional[bytes] = None,
    alg: str = "blake3",
) -> str:
    """
    Hash for PQ attestation envelope (no raw signatures).

    Typically used to bind PQ checks into receipts without exposing keys.
    """
    mapping = {
        "pq_scheme": str(pq_scheme),
        "pq_required": bool(pq_required),
        "pq_ok": bool(pq_ok),
        "chain_id": str(chain_id),
    }
    return canonical_kv_hash(
        mapping,
        ctx=ctx,
        label="pq_attest",
        key=key,
        alg=alg,
    )


def chain_id_hash(
    *,
    tenant: str,
    route_profile: str,
    policy_ref: str,
    ctx: str = "",
    key: Optional[bytes] = None,
    alg: str = "blake3",
) -> str:
    """
    Stable chain identifier for receipts and routes.

    This helper uses only tag-like fields and does not hash raw content.
    """
    mapping = {
        "tenant": str(tenant),
        "route_profile": str(route_profile),
        "policy_ref": str(policy_ref),
    }
    return canonical_kv_hash(
        mapping,
        ctx=ctx,
        label="chain_id",
        key=key,
        alg=alg,
    )