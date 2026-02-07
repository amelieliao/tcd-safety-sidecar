from __future__ import annotations

import base64
import binascii
import collections
import dataclasses
import hashlib
import hmac
import json
import logging
import math
import os
import re
import stat
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Literal, Mapping, Optional, Sequence, Tuple, Union, cast

logger = logging.getLogger(__name__)

# Optional fast hash
try:
    import blake3  # type: ignore[import]
except Exception:  # pragma: no cover
    blake3 = None  # type: ignore[assignment]

# Optional canonical hash utility (preferred, aligns with other control planes)
try:
    from .kv import canonical_kv_hash  # type: ignore[import]
except Exception:  # pragma: no cover
    canonical_kv_hash = None  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

CryptoProfile = Literal[
    "DEV",
    "FIPS",
    "SECURE_DEV",
    "SECURE_PREP",
    "SECURE_PROD_TIER1",
    "SECURE_PROD_TIER2",
]

HashAlgo = Literal[
    "BLAKE3_256",
    "BLAKE2B_256",
    "SHA2_256",
    "SHA2_512",
    "SHA3_256",
]

MacAlgo = Literal[
    "HMAC_SHA2_256",
    "HMAC_SHA2_512",
    "BLAKE2B_MAC",  # keyed blake2b, NOT HMAC(blake2b)
]

KdfHashAlgo = Literal[
    "KDF_SHA2_256",
    "KDF_SHA2_512",
    "KDF_SHA3_256",
]

SignAlgo = Literal[
    "ED25519",
    "ECDSA_P256",
    "RSA_3072",
    "DILITHIUM2",
]

KeyStatus = Literal["active", "retiring", "expired"]
KeyRole = Literal["root_ca", "intermediate_ca", "online_signing", "audit_only"]
ClassificationLevel = Literal["public", "internal", "confidential", "restricted"]
KeyBackendType = Literal["software_dev", "hsm", "kms"]

HashLabel = Literal[
    "generic",
    "receipt",
    "ledger",
    "telemetry",
    "pubkey",
    "config",
    "attestation",
    "kdf",
    "chain",
    "hmac",
]

# Domain separation encoding version
DsVersion = Literal["ds_v1_concat", "ds_v2_lenprefix"]

_ALLOWED_HASH_LABELS: frozenset[str] = frozenset(
    {
        "generic",
        "receipt",
        "ledger",
        "telemetry",
        "pubkey",
        "config",
        "attestation",
        "kdf",
        "chain",
        "hmac",
    }
)

_ALLOWED_PROFILES: Tuple[CryptoProfile, ...] = (
    "DEV",
    "FIPS",
    "SECURE_DEV",
    "SECURE_PREP",
    "SECURE_PROD_TIER1",
    "SECURE_PROD_TIER2",
)

# ---------------------------------------------------------------------------
# Engine identity + compatibility
# ---------------------------------------------------------------------------

# This file implements crypto_v4 semantics. crypto_v3 envelopes remain verifiable.
_CRYPTO_ENGINE_VERSION = "crypto_v4"
_SUPPORTED_ENGINE_VERSIONS: frozenset[str] = frozenset({"crypto_v3", "crypto_v4"})

# Signing message versions:
# - v1: legacy delimiter-based
# - v2: length-prefix (legacy-ish) without binding policy digest
# - v3: length-prefix + binds engine_version + ds/policy digests
MessageVersion = Literal["v1", "v2", "v3"]

# ---------------------------------------------------------------------------
# Hardening constants
# ---------------------------------------------------------------------------

_MAX_STR_SMALL = 64
_MAX_STR_MED = 256
_MAX_STR_LARGE = 4096

_MAX_ENV_JSON_BYTES = 2_000_000
_MAX_ENV_PEM_BYTES = 200_000

_MAX_KEYSET_FILE_BYTES = 4_000_000
_MAX_KEY_PEM_BYTES = 50_000
_MAX_KEYS = 64

_MAX_HEX_INPUT_CHARS = 4096
_MAX_B64_INPUT_CHARS = 8192

# For signatures: Ed25519 signature length is fixed 64 bytes.
_ED25519_SIG_LEN = 64

# For measurement_hash: L6 default expects a digest (SHA-256 sized) unless explicitly governed.
_DEFAULT_MEASUREMENT_LEN = 32
_MAX_MEASUREMENT_LEN = 256

# Chain chunk size cap (hard clamp)
_HARD_MAX_CHAIN_CHUNK_BYTES = 8_000_000
_DEFAULT_CHAIN_CHUNK_BYTES = 2_000_000

# RNG cap
_HARD_MAX_RNG_BYTES_PER_CALL = 4_000_000

# Public key parse cache cap (verify DoS defense)
_DEFAULT_PUBKEY_CACHE_MAX_ENTRIES = 512
_HARD_MAX_PUBKEY_CACHE_MAX_ENTRIES = 4096
_HARD_MAX_PUBKEY_PEM_BYTES = 20_000

# Domain prefix governance
_DEFAULT_DOMAIN_PREFIX = "tcd:v1:"
_MAX_DOMAIN_PREFIX_LEN = 64

# Pubkey fingerprint governance (fixed, profile-independent)
_PUBKEY_FP_CTX = b"TCD-PUBKEY-FP-v1|"
_PUBKEY_FP_PREFIX = "pkfp_sha256_"
_PUBKEY_FP_BYTES = 16  # 128-bit minimum (your B.1 requirement)

# policy/state digest contexts (align with other control planes)
_POLICY_CTX = "tcd:crypto_policy"
_POLICY_LABEL = "crypto_policy"
_KEYREG_CTX = "tcd:crypto_key_registry"
_KEYREG_LABEL = "crypto_key_registry"
_STATE_CTX = "tcd:crypto_state"
_STATE_LABEL = "crypto_state"

# ---------------------------------------------------------------------------
# Regex / validators
# ---------------------------------------------------------------------------

_CTRL_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+")
_OP_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
# alias key_id is human-facing; fingerprint is canonical identity
_KEY_ID_ALIAS_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_PUBKEY_FP_RE = re.compile(r"^pkfp_sha256_[a-z2-7]{10,64}$")  # base32 lowercase, no padding

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")

_ALLOWED_KEY_STATUS: frozenset[str] = frozenset({"active", "retiring", "expired"})
_ALLOWED_KEY_ROLE: frozenset[str] = frozenset({"root_ca", "intermediate_ca", "online_signing", "audit_only"})
_ALLOWED_CLASSIFICATION: frozenset[str] = frozenset({"public", "internal", "confidential", "restricted"})
_ALLOWED_BACKEND: frozenset[str] = frozenset({"software_dev", "hsm", "kms"})

# Implemented backends & algorithms in this build
_IMPLEMENTED_SIGN_ALGOS: frozenset[str] = frozenset({"ED25519"})
_IMPLEMENTED_KEY_BACKENDS: frozenset[str] = frozenset({"software_dev"})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CryptoError(Exception):
    """Base crypto error for TCD."""


# ---------------------------------------------------------------------------
# Low-cardinality reason codes (metrics/audit)
# ---------------------------------------------------------------------------

VerifyReason = Literal[
    "OK",
    "BAD_ENVELOPE",
    "UNSUPPORTED_ENGINE",
    "UNSUPPORTED_SUITE",
    "UNSUPPORTED_ALGO",
    "BAD_PUBKEY",
    "BAD_SIGNATURE_FORMAT",
    "BAD_SIGNATURE_VERIFY",
    "BAD_DIGEST_FORMAT",
    "DIGEST_MISMATCH",
    "PUBKEY_FP_MISMATCH",
    "KEY_ID_MISMATCH",
    "POLICY_DIGEST_MISMATCH",
    "KEYREG_DIGEST_MISMATCH",
    "INTERNAL_ERROR",
]

LoadReason = Literal[
    "OK",
    "MISSING_KEYS",
    "KEYSET_TOO_LARGE",
    "KEYSET_BAD_JSON",
    "KEYSET_BAD_SCHEMA",
    "KEYSET_BAD_VERSION",
    "KEYSET_TOO_MANY_KEYS",
    "KEY_ENTRY_INVALID",
    "KEY_PEM_TOO_LARGE",
    "KEY_PEM_PARSE_FAIL",
    "KEYSET_SIGNATURE_REQUIRED",
    "KEYSET_SIGNATURE_INVALID",
    "KEYSET_SIGNER_MISSING",
    "ENV_KEYS_NOT_ALLOWED",
    "SOFTWARE_KEYS_NOT_ALLOWED",
    "BACKEND_NOT_IMPLEMENTED",
    "FILE_INSECURE",
    "FILE_READ_FAIL",
]

FallbackKind = Literal[
    "HASH_BLAKE3_TO_BLAKE2B",
]

# ---------------------------------------------------------------------------
# Metrics sink (optional)
# ---------------------------------------------------------------------------

class CryptoMetricsSink:
    """
    Minimal metrics hook (low-cardinality labels only).
    Integrate with Prometheus/OTEL externally.
    """
    def inc(self, name: str, value: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
        raise NotImplementedError

    def observe(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        raise NotImplementedError

    def set_gauge(self, name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
        raise NotImplementedError


_METRICS_SINK: Optional[CryptoMetricsSink] = None
_METRICS_LOCK = threading.Lock()


def register_crypto_metrics_sink(sink: CryptoMetricsSink) -> None:
    global _METRICS_SINK
    with _METRICS_LOCK:
        _METRICS_SINK = sink


def _m_inc(name: str, value: int = 1, labels: Optional[Dict[str, str]] = None) -> None:
    sink = _METRICS_SINK
    if sink is None:
        return
    try:
        sink.inc(name, value=value, labels=labels)
    except Exception:
        logger.exception("CryptoMetricsSink.inc failed")


def _m_obs(name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
    sink = _METRICS_SINK
    if sink is None:
        return
    try:
        sink.observe(name, value=value, labels=labels)
    except Exception:
        logger.exception("CryptoMetricsSink.observe failed")


def _m_gauge(name: str, value: float, labels: Optional[Dict[str, str]] = None) -> None:
    sink = _METRICS_SINK
    if sink is None:
        return
    try:
        sink.set_gauge(name, value=value, labels=labels)
    except Exception:
        logger.exception("CryptoMetricsSink.set_gauge failed")


# ---------------------------------------------------------------------------
# Audit sink (optional) + metadata hardening
# ---------------------------------------------------------------------------

class CryptoAuditSink:
    """Hook for structured audit events emitted by the crypto control plane."""
    def emit(self, event_type: str, metadata: Dict[str, Any]) -> None:
        raise NotImplementedError


_AUDIT_SINK: Optional[CryptoAuditSink] = None
_AUDIT_LOCK = threading.Lock()

# Low-cardinality event types (enforced)
_ALLOWED_AUDIT_EVENTS: frozenset[str] = frozenset(
    {
        "ContextReloaded",
        "KeyRegistryLoadFailed",
        "KeyRegistryLoaded",
        "KeyRegistered",
        "KeyStatusChanged",
        "KeyWipedPrivate",
        "SignOperation",
        "VerifyOperation",
        "VerifyEnvelope",
        "HashFallback",
        "PolicyRelaxation",
        "DomainPrefixReset",
        "KeysetSignatureVerified",
        "KeysetSignatureMissing",
        "RngBypassEnabled",
        "KdfNoSaltBypassEnabled",
    }
)


def register_crypto_audit_sink(sink: CryptoAuditSink) -> None:
    global _AUDIT_SINK
    with _AUDIT_LOCK:
        _AUDIT_SINK = sink


def _safe_text(x: Any, *, max_len: int) -> str:
    s = "" if x is None else str(x)
    s = _CTRL_RE.sub("", s).replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    if len(s) > max_len:
        s = s[:max_len]
    # prevent accidental secret/PEM leakage
    if "BEGIN PRIVATE KEY" in s or "BEGIN ENCRYPTED PRIVATE KEY" in s:
        return "<redacted>"
    return s


def _sanitize_audit_metadata(md: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in md.items():
        kk = _safe_text(k, max_len=_MAX_STR_SMALL)
        if kk == "":
            continue
        # allow only scalar-ish; drop nested to avoid huge / secret objects
        if isinstance(v, (str, int, float, bool)) or v is None:
            if isinstance(v, str):
                out[kk] = _safe_text(v, max_len=_MAX_STR_MED)
            else:
                out[kk] = v
        else:
            out[kk] = "<omitted>"
    return out


def _emit_audit_event(event_type: str, metadata: Dict[str, Any]) -> None:
    sink = _AUDIT_SINK
    if sink is None:
        return
    et = _safe_text(event_type, max_len=_MAX_STR_SMALL)
    if et not in _ALLOWED_AUDIT_EVENTS:
        # enforce low-cardinality
        et = "PolicyRelaxation"
        metadata = dict(metadata)
        metadata["original_event"] = _safe_text(event_type, max_len=_MAX_STR_SMALL)
    try:
        sink.emit(et, _sanitize_audit_metadata(metadata))
    except Exception:
        logger.exception("CryptoAuditSink.emit failed")


# ---------------------------------------------------------------------------
# Env helpers (safe parsing + bounds)
# ---------------------------------------------------------------------------

def _env_get(name: str) -> Optional[str]:
    raw = os.environ.get(name)
    if raw is None:
        return None
    s = raw.strip()
    return s if s != "" else None


def _env_bool(name: str, default: bool) -> Tuple[bool, bool]:
    raw = _env_get(name)
    if raw is None:
        return bool(default), False
    v = raw.strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True, True
    if v in ("0", "false", "no", "off"):
        return False, True
    return bool(default), True


def _env_int(name: str, default: int) -> Tuple[int, bool]:
    raw = _env_get(name)
    if raw is None:
        return int(default), False
    try:
        return int(raw), True
    except Exception:
        return int(default), True


def _env_str(name: str, default: str, *, max_len: int) -> Tuple[str, bool]:
    raw = _env_get(name)
    if raw is None:
        return _safe_text(default, max_len=max_len), False
    return _safe_text(raw, max_len=max_len), True


# ---------------------------------------------------------------------------
# Break-glass (time-bounded, reasoned, acked) – multiple scopes
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class BreakGlassState:
    enabled: bool
    scope: str
    reason: str  # sanitized (short)
    reason_hash: str
    expires_epoch: float
    nonce: str


_BG_LOCK = threading.Lock()
_BG_LAST_ENABLE_TS: Dict[str, float] = {}
_BG_LAST_NONCE: Dict[str, str] = {}

_BG_TOKEN_HEX_RE = re.compile(r"^[0-9a-fA-F]{64}$")


def _break_glass_state(
    *,
    scope: str,
    prefix: str,
    engine_version: str,
    max_valid_seconds: int = 24 * 3600,
    cooldown_seconds: int = 3600,
) -> BreakGlassState:
    """
    Break-glass requires:
      - {prefix}_TOKEN_SHA256: 64 hex chars
      - {prefix}_ACK: exactly "I_UNDERSTAND_{engine_version}"
      - {prefix}_REASON: non-empty (sanitized)
      - {prefix}_EXPIRES_EPOCH: required, finite, now<=expires, (expires-now)<=max_valid_seconds
      - {prefix}_NONCE: required, non-empty (prevents accidental reuse)
    Plus: 1-hour cooldown per scope unless nonce changes.
    """
    now = time.time()

    token_hex = (_env_get(f"{prefix}_TOKEN_SHA256") or "").strip()
    ack = (_env_get(f"{prefix}_ACK") or "").strip()
    reason = _safe_text(_env_get(f"{prefix}_REASON") or "", max_len=_MAX_STR_MED)
    nonce = _safe_text(_env_get(f"{prefix}_NONCE") or "", max_len=_MAX_STR_SMALL)

    exp_raw = _env_get(f"{prefix}_EXPIRES_EPOCH")
    expires = 0.0
    try:
        if exp_raw is None:
            raise ValueError("missing expires")
        expires = float(exp_raw)
        if not math.isfinite(expires):
            raise ValueError("non-finite expires")
    except Exception:
        return BreakGlassState(False, scope, reason, "", 0.0, nonce)

    enabled = True
    if not _BG_TOKEN_HEX_RE.match(token_hex):
        enabled = False
    if ack != f"I_UNDERSTAND_{engine_version}":
        enabled = False
    if not reason:
        enabled = False
    if not nonce:
        enabled = False
    if expires <= now:
        enabled = False
    if enabled and (expires - now) > float(max_valid_seconds):
        enabled = False

    # cooldown / nonce monotonicity (process-local)
    if enabled:
        with _BG_LOCK:
            last_ts = _BG_LAST_ENABLE_TS.get(scope, 0.0)
            last_nonce = _BG_LAST_NONCE.get(scope, "")
            if (now - last_ts) < float(cooldown_seconds) and nonce == last_nonce:
                enabled = False
            else:
                _BG_LAST_ENABLE_TS[scope] = now
                _BG_LAST_NONCE[scope] = nonce

    # reason hash for metrics bucketing without leaking info
    rh = ""
    if reason:
        rh = hashlib.sha256((scope + "|" + reason).encode("utf-8")).hexdigest()[:16]

    return BreakGlassState(enabled, scope, reason, rh, float(expires), nonce)


def _is_strict_profile(profile: CryptoProfile) -> bool:
    return profile in ("FIPS", "SECURE_PREP", "SECURE_PROD_TIER1", "SECURE_PROD_TIER2")


# ---------------------------------------------------------------------------
# FIPS runtime detection (best-effort) + governance
# ---------------------------------------------------------------------------

def _openssl_fips_enabled() -> Optional[bool]:
    """
    Best-effort detection:
      - OpenSSL 1.x: FIPS_mode()
      - OpenSSL 3.x: EVP_default_properties_is_fips_enabled(NULL)
    Returns: True / False / None (unknown).
    """
    try:
        from cryptography.hazmat.bindings.openssl.binding import Binding  # type: ignore[import]
        b = Binding()
        lib = b.lib
        if hasattr(lib, "FIPS_mode"):
            return bool(lib.FIPS_mode())  # type: ignore[attr-defined]
        if hasattr(lib, "EVP_default_properties_is_fips_enabled"):
            # signature may be (OSSL_LIB_CTX*) in OpenSSL3, NULL means default
            return bool(lib.EVP_default_properties_is_fips_enabled(b.ffi.NULL))  # type: ignore[attr-defined]
    except Exception:
        return None
    return None


def _require_fips_ack_if_needed(profile: CryptoProfile) -> None:
    """
    In FIPS profile, we require either:
      - runtime detection says FIPS enabled, OR
      - break-glass scope "fips_noncertified" is enabled
    """
    if profile != "FIPS":
        return
    enabled = _openssl_fips_enabled()
    if enabled is True:
        return

    bg = _break_glass_state(
        scope="fips_noncertified",
        prefix="TCD_FIPS_BREAK_GLASS",
        engine_version=_CRYPTO_ENGINE_VERSION,
        max_valid_seconds=6 * 3600,
    )
    if bg.enabled:
        _emit_audit_event(
            "PolicyRelaxation",
            {
                "scope": bg.scope,
                "reason_hash": bg.reason_hash,
                "expires_epoch": bg.expires_epoch,
            },
        )
        _m_gauge("tcd_crypto_break_glass_enabled", 1.0, {"scope": bg.scope})
        return

    raise CryptoError("FIPS profile requires OpenSSL FIPS mode or TCD_FIPS_BREAK_GLASS_* bypass")


# ---------------------------------------------------------------------------
# Domain prefix governance (D.1–D.3)
# ---------------------------------------------------------------------------

_DOMAIN_LOCK = threading.Lock()
_DOMAIN_PREFIX_BYTES: Optional[bytes] = None
_DOMAIN_PREFIX_ORIGIN: str = "default"  # default|env|reset


_PREFIX_ALLOWED_RE = re.compile(r"^[A-Za-z0-9:._\-]{1,64}$")


def _get_domain_prefix_bytes(profile: CryptoProfile) -> bytes:
    """
    Domain prefix is considered process-stable by default (cached).
    Strict profiles disallow env override unless break-glass scope permits it.
    """
    global _DOMAIN_PREFIX_BYTES, _DOMAIN_PREFIX_ORIGIN
    if _DOMAIN_PREFIX_BYTES is not None:
        return _DOMAIN_PREFIX_BYTES
    with _DOMAIN_LOCK:
        if _DOMAIN_PREFIX_BYTES is not None:
            return _DOMAIN_PREFIX_BYTES

        raw = os.getenv("TCD_HASH_DOMAIN_PREFIX", _DEFAULT_DOMAIN_PREFIX)
        s = _safe_text(raw, max_len=_MAX_DOMAIN_PREFIX_LEN)
        if not _PREFIX_ALLOWED_RE.match(s):
            s = _DEFAULT_DOMAIN_PREFIX
        if not s.endswith(":"):
            s = s + ":"

        if _is_strict_profile(profile):
            # In strict profiles: forbid env override away from default unless break-glass
            if s != _DEFAULT_DOMAIN_PREFIX and s != (_DEFAULT_DOMAIN_PREFIX + ":"):
                bg = _break_glass_state(
                    scope="domain_prefix_override",
                    prefix="TCD_DOMAIN_PREFIX_BREAK_GLASS",
                    engine_version=_CRYPTO_ENGINE_VERSION,
                    max_valid_seconds=6 * 3600,
                )
                if not bg.enabled:
                    raise CryptoError("Domain prefix override disallowed in strict profile without break-glass")
                _emit_audit_event(
                    "PolicyRelaxation",
                    {
                        "scope": bg.scope,
                        "reason_hash": bg.reason_hash,
                        "expires_epoch": bg.expires_epoch,
                    },
                )
                _m_gauge("tcd_crypto_break_glass_enabled", 1.0, {"scope": bg.scope})

        _DOMAIN_PREFIX_BYTES = s.encode("utf-8", errors="strict")
        _DOMAIN_PREFIX_ORIGIN = "env" if os.getenv("TCD_HASH_DOMAIN_PREFIX") else "default"
        return _DOMAIN_PREFIX_BYTES


def reset_domain_prefix_for_reload(*, profile: CryptoProfile) -> None:
    """
    Dev-only (or break-glass) domain prefix reset. Addresses D.2 explicitly.
    """
    global _DOMAIN_PREFIX_BYTES, _DOMAIN_PREFIX_ORIGIN
    allow = (profile in ("DEV", "SECURE_DEV"))
    if not allow:
        bg = _break_glass_state(
            scope="domain_prefix_reset",
            prefix="TCD_DOMAIN_PREFIX_RESET_BREAK_GLASS",
            engine_version=_CRYPTO_ENGINE_VERSION,
            max_valid_seconds=3600,
        )
        if not bg.enabled:
            raise CryptoError("Domain prefix reset disallowed without break-glass")
        _emit_audit_event(
            "PolicyRelaxation",
            {"scope": bg.scope, "reason_hash": bg.reason_hash, "expires_epoch": bg.expires_epoch},
        )
    with _DOMAIN_LOCK:
        _DOMAIN_PREFIX_BYTES = None
        _DOMAIN_PREFIX_ORIGIN = "reset"
    _emit_audit_event("DomainPrefixReset", {"profile": profile, "origin": _DOMAIN_PREFIX_ORIGIN})


def _domain_tag(label: HashLabel, *, profile: CryptoProfile) -> bytes:
    if label not in _ALLOWED_HASH_LABELS:
        raise CryptoError(f"Unsupported hash label: {label}")
    # Domain separation is length-prefixed at DS v2 layer; label itself stays fixed.
    return _get_domain_prefix_bytes(profile) + label.encode("utf-8")


def _domain_prefix_digest_hex(profile: CryptoProfile) -> str:
    p = _get_domain_prefix_bytes(profile)
    return hashlib.sha256(b"TCD-DOMAIN-PREFIX-v1|" + p).hexdigest()


# ---------------------------------------------------------------------------
# Strict hex/base64 helpers (P: system fields forbid odd-length)
# ---------------------------------------------------------------------------

def _hex_to_bytes(
    s: str,
    *,
    expected_len: Optional[int] = None,
    max_input_chars: int = _MAX_HEX_INPUT_CHARS,
    allow_odd_len: bool = False,
) -> bytes:
    t = _safe_text(s, max_len=max_input_chars)
    if t.startswith(("0x", "0X")):
        t = t[2:]
    if t == "":
        return b""
    if len(t) > max_input_chars:
        raise CryptoError("hex input too long")
    if not _HEX_RE.match(t):
        raise CryptoError("invalid hex characters")
    if len(t) % 2 == 1:
        if not allow_odd_len:
            raise CryptoError("odd-length hex not allowed for system fields")
        t = "0" + t
    try:
        b = binascii.unhexlify(t)
    except Exception as e:
        raise CryptoError(f"hex decode failed: {e}") from e
    if expected_len is not None and len(b) != int(expected_len):
        raise CryptoError(f"hex length mismatch: got={len(b)} expected={expected_len}")
    return b


def _bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode("ascii")


def _b64_decode_strict(s: str, *, max_chars: int = _MAX_B64_INPUT_CHARS) -> bytes:
    t = _safe_text(s, max_len=max_chars)
    if len(t) > max_chars:
        raise CryptoError("base64 input too long")
    try:
        return base64.b64decode(t.encode("ascii"), validate=True)
    except Exception as e:
        raise CryptoError(f"base64 decode failed: {e}") from e


# ---------------------------------------------------------------------------
# Canonical hashing helper (fallback if canonical_kv_hash absent)
# ---------------------------------------------------------------------------

def _canonical_hash(payload: Dict[str, Any], *, ctx: str, label: str) -> str:
    if canonical_kv_hash is not None:
        return str(canonical_kv_hash(payload, ctx=ctx, label=label))
    # Fallback: stable JSON + sha256
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256((ctx + "|" + label + "|").encode("utf-8") + raw).hexdigest()


# ---------------------------------------------------------------------------
# Hash/MAC policies (E.3: explicit downgrade matrix)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class HashPolicy:
    profile: CryptoProfile
    hash_algo: HashAlgo
    mac_algo: Optional[MacAlgo]
    ds_version: DsVersion
    reject_on_fallback: bool
    digest_size: int = 32  # fixed for all *_256

    @classmethod
    def for_profile(cls, profile: CryptoProfile, *, engine_version: str) -> "HashPolicy":
        # D.3: ds_v2_lenprefix is the L6 default; keep ds_v1_concat for crypto_v3 compatibility.
        ds: DsVersion = "ds_v2_lenprefix" if engine_version == "crypto_v4" else "ds_v1_concat"

        # E.3 matrix:
        # DEV: allow fallback + warn + audit
        # SECURE_DEV: default reject fallback (unless break-glass scope enables)
        # SECURE_PREP/PROD/FIPS: reject fallback
        if profile == "DEV":
            reject_fallback = False
        elif profile == "SECURE_DEV":
            bg = _break_glass_state(
                scope="secure_dev_allow_fallback",
                prefix="TCD_SECURE_DEV_FALLBACK_BREAK_GLASS",
                engine_version=_CRYPTO_ENGINE_VERSION,
                max_valid_seconds=6 * 3600,
            )
            reject_fallback = not bg.enabled
            if bg.enabled:
                _emit_audit_event(
                    "PolicyRelaxation",
                    {"scope": bg.scope, "reason_hash": bg.reason_hash, "expires_epoch": bg.expires_epoch},
                )
        else:
            reject_fallback = True

        if profile == "FIPS":
            return cls(profile=profile, hash_algo="SHA2_256", mac_algo="HMAC_SHA2_256", ds_version=ds, reject_on_fallback=True)

        if profile in ("SECURE_PREP", "SECURE_PROD_TIER1", "SECURE_PROD_TIER2"):
            return cls(profile=profile, hash_algo="SHA3_256", mac_algo="HMAC_SHA2_256", ds_version=ds, reject_on_fallback=True)

        # DEV / SECURE_DEV: prefer BLAKE3 if present else BLAKE2b; fallback policy applied in engine
        return cls(
            profile=profile,
            hash_algo="BLAKE3_256" if blake3 is not None else "BLAKE2B_256",
            mac_algo="BLAKE2B_MAC",
            ds_version=ds,
            reject_on_fallback=reject_fallback,
        )

    def output_size_bytes(self) -> int:
        if self.hash_algo == "SHA2_512":
            return 64
        return 32


# ---------------------------------------------------------------------------
# Hash Engine (D.3 length-prefix DS; E.1/E.4 MAC APIs)
# ---------------------------------------------------------------------------

def _pack_blob(b: bytes) -> bytes:
    return struct.pack("!I", len(b)) + b


class HashEngine:
    def __init__(self, policy: HashPolicy) -> None:
        self._policy = policy

    @property
    def policy(self) -> HashPolicy:
        return self._policy

    def _new_hasher(self, algo: HashAlgo):
        if algo == "BLAKE3_256":
            if blake3 is not None:
                return blake3.blake3()
            if self._policy.reject_on_fallback:
                raise CryptoError("BLAKE3 requested but blake3 is not available (fallback rejected)")
            # fallback allowed (DEV or break-glassed SECURE_DEV)
            _emit_audit_event(
                "HashFallback",
                {"kind": "HASH_BLAKE3_TO_BLAKE2B", "profile": self._policy.profile, "engine_version": _CRYPTO_ENGINE_VERSION},
            )
            _m_inc("tcd_crypto_fallback_total", 1, {"kind": "HASH_BLAKE3_TO_BLAKE2B"})
            algo = "BLAKE2B_256"

        if algo == "BLAKE2B_256":
            return hashlib.blake2b(digest_size=32)
        if algo == "SHA2_256":
            return hashlib.sha256()
        if algo == "SHA2_512":
            return hashlib.sha512()
        if algo == "SHA3_256":
            return hashlib.sha3_256()
        raise CryptoError(f"Unsupported hash algorithm: {algo}")

    def _ds_encode(self, tag: bytes, data: bytes) -> bytes:
        """
        D.3: length-prefix encoding for DS v2; keep v1 concat for crypto_v3 verification.
        """
        if self._policy.ds_version == "ds_v1_concat":
            return tag + data
        # ds_v2_lenprefix
        return b"TCD-DS-v2" + _pack_blob(tag) + _pack_blob(data)

    def digest_bytes(self, data: bytes, *, label: HashLabel) -> bytes:
        tag = _domain_tag(label, profile=self._policy.profile)
        payload = self._ds_encode(tag, data)
        h = self._new_hasher(self._policy.hash_algo)
        h.update(payload)
        out_len = self._policy.output_size_bytes()
        try:
            return h.digest(out_len)  # type: ignore[attr-defined]
        except TypeError:
            return h.digest()

    def digest_hex(self, data: bytes, *, label: HashLabel) -> str:
        return _bytes_to_hex(self.digest_bytes(data, label=label))

    # E.1: provide mac_* interfaces
    def mac_bytes(self, key: bytes, data: bytes, *, label: HashLabel = "hmac") -> bytes:
        if self._policy.mac_algo is None:
            raise CryptoError("MAC algorithm not configured")
        if not isinstance(key, (bytes, bytearray)):
            raise CryptoError("MAC key must be bytes")
        k = bytes(key)
        tag = _domain_tag(label, profile=self._policy.profile)

        # encode DS the same way
        payload = self._ds_encode(tag, data)

        algo = self._policy.mac_algo
        if algo == "BLAKE2B_MAC":
            if len(k) == 0 and _is_strict_profile(self._policy.profile):
                raise CryptoError("Empty MAC key not allowed in strict profile")
            if len(k) > 64:
                if _is_strict_profile(self._policy.profile):
                    raise CryptoError("BLAKE2B_MAC key too long in strict profile")
                # DEV: hash down
                k = hashlib.blake2b(k, digest_size=64).digest()
            mac = hashlib.blake2b(digest_size=32, key=k)
            mac.update(payload)
            return mac.digest()

        if algo == "HMAC_SHA2_256":
            hm = hmac.new(k, digestmod=hashlib.sha256)
            hm.update(payload)
            return hm.digest()

        if algo == "HMAC_SHA2_512":
            hm = hmac.new(k, digestmod=hashlib.sha512)
            hm.update(payload)
            return hm.digest()

        raise CryptoError(f"Unsupported MAC algorithm: {algo}")

    def mac_hex(self, key: bytes, data: bytes, *, label: HashLabel = "hmac") -> str:
        return _bytes_to_hex(self.mac_bytes(key, data, label=label))

    def verify_mac(self, key: bytes, data: bytes, mac: Union[str, bytes], *, label: HashLabel = "hmac") -> bool:
        """
        E.4: constant-time compare on bytes; hex only for serialization.
        Never throws.
        """
        try:
            expected = self.mac_bytes(key, data, label=label)
            if isinstance(mac, str):
                got = _hex_to_bytes(mac, expected_len=len(expected), allow_odd_len=False)
            else:
                got = bytes(mac)
            return hmac.compare_digest(expected, got)
        except Exception:
            return False

    # E.1: keep hmac() as compatibility alias; strict profiles can disable by governance
    def hmac(self, key: bytes, data: bytes, *, label: HashLabel = "hmac") -> str:
        # strict: default forbid alias unless break-glass
        if _is_strict_profile(self._policy.profile):
            allow, _ = _env_bool("TCD_ALLOW_HMAC_ALIAS", False)
            if not allow:
                bg = _break_glass_state(
                    scope="allow_hmac_alias",
                    prefix="TCD_HMAC_ALIAS_BREAK_GLASS",
                    engine_version=_CRYPTO_ENGINE_VERSION,
                    max_valid_seconds=3600,
                )
                if not bg.enabled:
                    raise CryptoError("hmac() alias disallowed in strict profile; use mac_hex()")
                _emit_audit_event(
                    "PolicyRelaxation",
                    {"scope": bg.scope, "reason_hash": bg.reason_hash, "expires_epoch": bg.expires_epoch},
                )
        return self.mac_hex(key, data, label=label)

    # Chain (F.1/F.2)
    def chain_hex(self, prev_hex: Optional[str], chunk: bytes, *, label: HashLabel = "chain") -> str:
        chunk_max, used = _env_int("TCD_CHAIN_MAX_CHUNK_BYTES", _DEFAULT_CHAIN_CHUNK_BYTES)
        if not math.isfinite(float(chunk_max)) or chunk_max <= 0:
            chunk_max = _DEFAULT_CHAIN_CHUNK_BYTES
        chunk_max = min(int(chunk_max), _HARD_MAX_CHAIN_CHUNK_BYTES)

        if used and _is_strict_profile(self._policy.profile):
            # strict: env override requires break-glass
            bg = _break_glass_state(
                scope="chain_max_override",
                prefix="TCD_CHAIN_BREAK_GLASS",
                engine_version=_CRYPTO_ENGINE_VERSION,
                max_valid_seconds=3600,
            )
            if not bg.enabled:
                raise CryptoError("TCD_CHAIN_MAX_CHUNK_BYTES override disallowed in strict profile without break-glass")
            _emit_audit_event(
                "PolicyRelaxation",
                {"scope": bg.scope, "reason_hash": bg.reason_hash, "expires_epoch": bg.expires_epoch},
            )

        if not isinstance(chunk, (bytes, bytearray)):
            raise CryptoError("chunk must be bytes")
        if len(chunk) > chunk_max:
            raise CryptoError("chunk too large")

        tag = _domain_tag(label, profile=self._policy.profile)
        prev_b = b""
        if prev_hex:
            prev_b = _hex_to_bytes(prev_hex, expected_len=self._policy.output_size_bytes(), allow_odd_len=False)

        # F.2: length-prefix all parts to remove any ambiguity
        if self._policy.ds_version == "ds_v1_concat":
            payload = tag + prev_b + bytes(chunk)
        else:
            payload = b"TCD-CHAIN-v2" + _pack_blob(tag) + _pack_blob(prev_b) + _pack_blob(bytes(chunk))

        h = self._new_hasher(self._policy.hash_algo)
        h.update(payload)
        out_len = self._policy.output_size_bytes()
        try:
            out = h.digest(out_len)  # type: ignore[attr-defined]
        except TypeError:
            out = h.digest()
        return _bytes_to_hex(out)


# ---------------------------------------------------------------------------
# KDF policy/engine (H.1–H.3)
# ---------------------------------------------------------------------------

_HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives import hashes  # type: ignore[import]
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # type: ignore[import]
    from cryptography.hazmat.primitives import serialization  # type: ignore[import]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey  # type: ignore[import]
    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    hashes = None  # type: ignore[assignment]
    HKDF = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]
    Ed25519PrivateKey = object  # type: ignore[assignment]
    Ed25519PublicKey = object  # type: ignore[assignment]


def _require_crypto_dep() -> None:
    if not _HAS_CRYPTOGRAPHY or serialization is None:
        raise CryptoError("cryptography is required for signing/verification/KDF but not available")


@dataclass(frozen=True, slots=True)
class KdfPolicy:
    profile: CryptoProfile
    kdf_hash_algo: KdfHashAlgo
    require_salt_in_strict: bool = True

    @classmethod
    def for_profile(cls, profile: CryptoProfile) -> "KdfPolicy":
        # H.2: explicit KDF hash (decoupled from hash_algo)
        if profile == "FIPS":
            return cls(profile=profile, kdf_hash_algo="KDF_SHA2_256", require_salt_in_strict=True)
        if profile in ("SECURE_PREP", "SECURE_PROD_TIER1", "SECURE_PROD_TIER2", "SECURE_DEV"):
            return cls(profile=profile, kdf_hash_algo="KDF_SHA2_256", require_salt_in_strict=True)
        return cls(profile=profile, kdf_hash_algo="KDF_SHA2_256", require_salt_in_strict=False)


class KdfEngine:
    def __init__(self, *, policy: KdfPolicy, suite_id: str, engine_version: str) -> None:
        self._policy = policy
        self._suite_id = _safe_text(suite_id, max_len=_MAX_STR_SMALL)
        self._engine_version = _safe_text(engine_version, max_len=_MAX_STR_SMALL)

    @property
    def policy(self) -> KdfPolicy:
        return self._policy

    def _select_hash(self):
        _require_crypto_dep()
        assert hashes is not None
        if self._policy.kdf_hash_algo == "KDF_SHA2_256":
            return hashes.SHA256()
        if self._policy.kdf_hash_algo == "KDF_SHA2_512":
            return hashes.SHA512()
        if self._policy.kdf_hash_algo == "KDF_SHA3_256":
            return hashes.SHA3_256()
        return hashes.SHA256()

    def derive_key(
        self,
        ikm: bytes,
        *,
        label: HashLabel = "kdf",
        length: int = 32,
        salt: Optional[bytes] = None,
        context: Optional[bytes] = None,
    ) -> bytes:
        _require_crypto_dep()
        assert HKDF is not None

        if not isinstance(ikm, (bytes, bytearray)):
            raise CryptoError("ikm must be bytes")
        ikm_b = bytes(ikm)

        L = int(length)
        if L <= 0 or L > 1024:
            raise CryptoError("invalid KDF length")

        strict = _is_strict_profile(self._policy.profile) or self._policy.profile == "SECURE_DEV"
        if strict and self._policy.require_salt_in_strict:
            if salt is None or not isinstance(salt, (bytes, bytearray)) or len(bytes(salt)) < 16:
                # H.1: no-salt is a break-glass relaxation
                bg = _break_glass_state(
                    scope="kdf_no_salt",
                    prefix="TCD_KDF_BREAK_GLASS",
                    engine_version=_CRYPTO_ENGINE_VERSION,
                    max_valid_seconds=3600,
                )
                if not bg.enabled:
                    raise CryptoError("salt required in strict profile; set TCD_KDF_BREAK_GLASS_* to bypass")
                _emit_audit_event(
                    "KdfNoSaltBypassEnabled",
                    {"scope": bg.scope, "reason_hash": bg.reason_hash, "expires_epoch": bg.expires_epoch},
                )
                _m_gauge("tcd_crypto_break_glass_enabled", 1.0, {"scope": bg.scope})

        if salt is not None and not isinstance(salt, (bytes, bytearray)):
            raise CryptoError("salt must be bytes")

        if context is not None and not isinstance(context, (bytes, bytearray)):
            raise CryptoError("context must be bytes")

        ctx_b = bytes(context) if context is not None else b""
        if len(ctx_b) > 1024:
            raise CryptoError("context too large")

        # H.3: info binds engine_version + suite_id + label + ctx under a stable version tag
        info = b"".join(
            [
                b"TCD-HKDF-v1",
                _pack_blob(self._engine_version.encode("ascii", errors="strict")),
                _pack_blob(self._suite_id.encode("ascii", errors="strict")),
                _pack_blob(label.encode("ascii", errors="strict")),
                _pack_blob(ctx_b),
            ]
        )

        hkdf_hash = self._select_hash()
        hkdf = HKDF(
            algorithm=hkdf_hash,
            length=L,
            salt=bytes(salt) if salt is not None else None,
            info=info,
        )
        out = hkdf.derive(ikm_b)
        _m_inc("tcd_crypto_kdf_total", 1, {"profile": self._policy.profile, "hash": self._policy.kdf_hash_algo})
        return out


# ---------------------------------------------------------------------------
# RNG policy/engine (G.1–G.3)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class RngPolicy:
    profile: CryptoProfile
    backend: Literal["os_urandom", "hsm", "kms_drbg"]
    require_certified: bool
    max_bytes_per_call: int = _HARD_MAX_RNG_BYTES_PER_CALL

    @classmethod
    def for_profile(cls, profile: CryptoProfile) -> "RngPolicy":
        # Allow override of backend in dev; strict profiles should be explicit.
        backend, used = _env_str("TCD_RNG_BACKEND", "os_urandom", max_len=_MAX_STR_SMALL)
        b = backend if backend in ("os_urandom", "hsm", "kms_drbg") else "os_urandom"

        require_cert = profile in ("FIPS", "SECURE_PROD_TIER1", "SECURE_PROD_TIER2")
        if profile in ("SECURE_PREP", "SECURE_DEV"):
            require_cert = True

        # strict: if backend is hsm/kms_drbg but build lacks adapters, fail-fast
        if _is_strict_profile(profile) and b in ("hsm", "kms_drbg"):
            # We do not implement these in this build.
            raise CryptoError(f"RNG backend {b} not implemented in this build (strict profile)")

        return cls(profile=profile, backend=cast(Literal["os_urandom", "hsm", "kms_drbg"], b), require_certified=require_cert)


class RngContext:
    def __init__(self, policy: RngPolicy) -> None:
        self._policy = policy
        self._lock = threading.Lock()
        self._last_block: bytes = b""

    def random_bytes(self, n: int) -> bytes:
        nn = int(n)
        if nn < 0:
            raise CryptoError("RNG n must be >= 0")
        if nn > int(self._policy.max_bytes_per_call):
            raise CryptoError("RNG request too large")

        if self._policy.backend != "os_urandom":
            raise CryptoError(f"RNG backend {self._policy.backend} not implemented in this build")

        # G.1/G.3: certified RNG requirement -> break-glass bypass (time-bounded)
        if self._policy.require_certified:
            # If we can't prove certification from Python, we require break-glass bypass explicitly.
            bg = _break_glass_state(
                scope="rng_uncertified",
                prefix="TCD_RNG_BREAK_GLASS",
                engine_version=_CRYPTO_ENGINE_VERSION,
                max_valid_seconds=3600,
            )
            if not bg.enabled:
                raise CryptoError("Certified RNG required; set TCD_RNG_BREAK_GLASS_* to bypass for this build")
            _emit_audit_event(
                "RngBypassEnabled",
                {"scope": bg.scope, "reason_hash": bg.reason_hash, "expires_epoch": bg.expires_epoch},
            )
            _m_gauge("tcd_crypto_break_glass_enabled", 1.0, {"scope": bg.scope})

        b = os.urandom(nn)

        # G.2: continuous test (very lightweight)
        with self._lock:
            block = b[:32] if len(b) >= 32 else b
            if block and self._last_block and block == self._last_block:
                raise CryptoError("rng_continuous_test_failed")
            self._last_block = block

        _m_inc("tcd_crypto_rng_bytes_total", nn, {"backend": "os_urandom", "profile": self._policy.profile})
        return b


# ---------------------------------------------------------------------------
# Attestation context (P: enforce length semantics)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class AttestationContext:
    measurement_hash: Optional[bytes] = None
    attestation_report: Optional[bytes] = None  # never embedded

    def measurement_or_empty(self, *, profile: CryptoProfile) -> bytes:
        mh = self.measurement_hash or b""
        if mh == b"":
            return b""
        if len(mh) > _MAX_MEASUREMENT_LEN:
            raise CryptoError("measurement_hash too large")
        strict = _is_strict_profile(profile) or profile == "SECURE_DEV"
        if strict:
            # P: enforce digest-like length for measurement by default (32 bytes)
            if len(mh) != _DEFAULT_MEASUREMENT_LEN:
                raise CryptoError("measurement_hash must be 32 bytes in strict profiles")
        return mh


# ---------------------------------------------------------------------------
# Public key fingerprint (B.1–B.3)
# ---------------------------------------------------------------------------

def _pubkey_spki_der(pub: Any) -> bytes:
    _require_crypto_dep()
    assert serialization is not None
    return pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def pubkey_fingerprint_from_spki_der(spki_der: bytes) -> str:
    """
    B.2: profile-independent stable fp:
      fp = base32( sha256(CTX || spki_der)[:16] )
    """
    d = hashlib.sha256(_PUBKEY_FP_CTX + spki_der).digest()[:_PUBKEY_FP_BYTES]
    b32 = base64.b32encode(d).decode("ascii").rstrip("=").lower()
    return _PUBKEY_FP_PREFIX + b32


def pubkey_fingerprint_from_public_key(pub: Any) -> str:
    spki = _pubkey_spki_der(pub)
    return pubkey_fingerprint_from_spki_der(spki)


def _validate_pubkey_fp(fp: str) -> str:
    s = _safe_text(fp, max_len=_MAX_STR_SMALL)
    if not _PUBKEY_FP_RE.match(s):
        raise CryptoError("invalid pubkey_fingerprint format")
    return s


def _validate_key_id_alias(alias: str) -> str:
    s = _safe_text(alias, max_len=_MAX_STR_SMALL)
    if s == "":
        return ""
    if not _KEY_ID_ALIAS_RE.match(s):
        raise CryptoError("invalid key_id alias format")
    return s


def _sanitize_operation(op: str) -> str:
    s = _safe_text(op, max_len=_MAX_STR_SMALL)
    if not _OP_RE.match(s):
        raise CryptoError("invalid operation name")
    return s


# ---------------------------------------------------------------------------
# Key records (A.1–A.3: no private keys in exposed objects)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SigningKeyHandle:
    """
    Public, immutable descriptor (no private key, no sign()).
    """
    pubkey_fingerprint: str
    key_id: str  # alias (human-friendly)
    algo: SignAlgo
    backend_type: KeyBackendType
    status: KeyStatus
    role: KeyRole
    classification_level: ClassificationLevel
    allowed_operations: Tuple[str, ...]
    not_before_epoch: Optional[float]
    not_after_epoch: Optional[float]


@dataclass(frozen=True, slots=True)
class _InternalKeyRecord:
    """
    Internal immutable record; private key is stored separately by fingerprint.
    """
    pubkey_fingerprint: str
    key_id: str
    algo: SignAlgo
    backend_type: KeyBackendType
    status: KeyStatus
    role: KeyRole
    classification_level: ClassificationLevel
    allowed_operations: Tuple[str, ...]
    not_before_epoch: Optional[float]
    not_after_epoch: Optional[float]

    def to_handle(self) -> SigningKeyHandle:
        return SigningKeyHandle(
            pubkey_fingerprint=self.pubkey_fingerprint,
            key_id=self.key_id,
            algo=self.algo,
            backend_type=self.backend_type,
            status=self.status,
            role=self.role,
            classification_level=self.classification_level,
            allowed_operations=self.allowed_operations,
            not_before_epoch=self.not_before_epoch,
            not_after_epoch=self.not_after_epoch,
        )


# ---------------------------------------------------------------------------
# Operation policy table (I.1)
# ---------------------------------------------------------------------------

_CLASS_ORDER: Dict[str, int] = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}

@dataclass(frozen=True, slots=True)
class OperationPolicy:
    operation: str
    required_role: KeyRole
    min_classification: ClassificationLevel
    allowed_algos: Tuple[SignAlgo, ...]


_OPERATION_POLICIES: Dict[str, OperationPolicy] = {
    # receipts: online signing, at least public
    "sign_receipt": OperationPolicy("sign_receipt", "online_signing", "public", ("ED25519",)),
    # ledger: audit-only recommended, at least internal
    "sign_ledger": OperationPolicy("sign_ledger", "audit_only", "internal", ("ED25519",)),
    # config: online signing but at least internal
    "sign_config": OperationPolicy("sign_config", "online_signing", "internal", ("ED25519",)),
}


def _classification_ok(key_cls: ClassificationLevel, required_min: ClassificationLevel) -> bool:
    return _CLASS_ORDER[key_cls] >= _CLASS_ORDER[required_min]


# ---------------------------------------------------------------------------
# Key registry (A.1–A.3, I.*, K.*)
# ---------------------------------------------------------------------------

class KeyRegistry:
    """
    Registry keeps:
      - immutable internal records keyed by pubkey_fingerprint
      - private keys in separate private map (never returned)
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._records: Dict[str, _InternalKeyRecord] = {}
        self._privkeys: Dict[str, Any] = {}  # fingerprint -> private key object
        self._loaded_at = time.time()

    def loaded_at_epoch(self) -> float:
        return float(self._loaded_at)

    def handles(self) -> Dict[str, SigningKeyHandle]:
        with self._lock:
            return {fp: rec.to_handle() for fp, rec in self._records.items()}

    def get_handle(self, pubkey_fingerprint: str) -> Optional[SigningKeyHandle]:
        fp = _validate_pubkey_fp(pubkey_fingerprint)
        with self._lock:
            rec = self._records.get(fp)
            return rec.to_handle() if rec else None

    def _put_record(self, rec: _InternalKeyRecord, *, priv: Optional[Any]) -> None:
        with self._lock:
            self._records[rec.pubkey_fingerprint] = rec
            if priv is not None:
                self._privkeys[rec.pubkey_fingerprint] = priv

    def add_or_replace_private_key(
        self,
        *,
        private_key: Any,
        key_id_alias: str,
        status: KeyStatus,
        role: KeyRole,
        classification_level: ClassificationLevel,
        allowed_operations: Sequence[str],
        not_before_epoch: Optional[float],
        not_after_epoch: Optional[float],
        backend_type: KeyBackendType,
        profile: CryptoProfile,
    ) -> SigningKeyHandle:
        """
        A.2: does NOT store external mutable handle reference; constructs internal immutable record.
        """
        _require_crypto_dep()
        if not isinstance(private_key, Ed25519PrivateKey):
            raise CryptoError("only ED25519 private keys supported in this build")

        if backend_type not in _ALLOWED_BACKEND:
            raise CryptoError("invalid backend_type")
        if backend_type not in _IMPLEMENTED_KEY_BACKENDS:
            raise CryptoError("backend not implemented in this build")

        if status not in _ALLOWED_KEY_STATUS:
            raise CryptoError("invalid status")
        if role not in _ALLOWED_KEY_ROLE:
            raise CryptoError("invalid role")
        if classification_level not in _ALLOWED_CLASSIFICATION:
            raise CryptoError("invalid classification_level")

        alias = _validate_key_id_alias(key_id_alias)

        ops = _sanitize_ops_for_profile(allowed_operations, profile=profile)

        pub = private_key.public_key()
        fp = pubkey_fingerprint_from_public_key(pub)

        rec = _InternalKeyRecord(
            pubkey_fingerprint=fp,
            key_id=alias,
            algo="ED25519",
            backend_type=backend_type,
            status=cast(KeyStatus, status),
            role=cast(KeyRole, role),
            classification_level=cast(ClassificationLevel, classification_level),
            allowed_operations=ops,
            not_before_epoch=_finite_or_none(not_before_epoch),
            not_after_epoch=_finite_or_none(not_after_epoch),
        )

        self._put_record(rec, priv=private_key)

        _emit_audit_event(
            "KeyRegistered",
            {
                "pubkey_fp": fp,
                "key_id": alias or "<empty>",
                "algo": rec.algo,
                "backend_type": rec.backend_type,
                "status": rec.status,
                "role": rec.role,
                "classification_level": rec.classification_level,
            },
        )
        _m_inc("tcd_crypto_key_registered_total", 1, {"profile": profile, "algo": rec.algo})

        return rec.to_handle()

    def set_status(self, pubkey_fingerprint: str, status: KeyStatus) -> None:
        fp = _validate_pubkey_fp(pubkey_fingerprint)
        if status not in _ALLOWED_KEY_STATUS:
            raise CryptoError("invalid key status")
        with self._lock:
            old = self._records.get(fp)
            if old is None:
                raise CryptoError("unknown key fingerprint")
            rec = dataclasses.replace(old, status=cast(KeyStatus, status))
            self._records[fp] = rec
        _emit_audit_event("KeyStatusChanged", {"pubkey_fp": fp, "status": status})

    def wipe_private_for_expired(self) -> None:
        """
        I.2/I.4: wipe private material for expired keys but keep public record for verification/publishing.
        """
        wiped: int = 0
        with self._lock:
            for fp, rec in list(self._records.items()):
                if rec.status == "expired" and fp in self._privkeys:
                    del self._privkeys[fp]
                    wiped += 1
        if wiped:
            _emit_audit_event("KeyWipedPrivate", {"count": wiped})
            _m_inc("tcd_crypto_key_private_wiped_total", wiped)

    def _select_candidate_fp(self, *, operation: str, profile: CryptoProfile) -> str:
        op = _sanitize_operation(operation)
        pol = _OPERATION_POLICIES.get(op)
        if pol is None:
            raise CryptoError("unknown operation")

        now = time.time()
        candidates: list[_InternalKeyRecord] = []

        with self._lock:
            for rec in self._records.values():
                # status machine: retiring is verify-only by default (I.2)
                if rec.status != "active":
                    continue
                if rec.algo not in pol.allowed_algos:
                    continue
                if rec.role != pol.required_role:
                    continue
                if not _classification_ok(rec.classification_level, pol.min_classification):
                    continue
                if op not in rec.allowed_operations:
                    continue
                # time bounds
                if rec.not_before_epoch is not None and now < rec.not_before_epoch:
                    continue
                if rec.not_after_epoch is not None and now > rec.not_after_epoch:
                    continue
                # backend policy
                if rec.backend_type == "software_dev" and _is_strict_profile(profile):
                    # strict: software keys require break-glass enablement (J.3)
                    bg = _break_glass_state(
                        scope="allow_software_keys",
                        prefix="TCD_KEY_BACKEND_BREAK_GLASS",
                        engine_version=_CRYPTO_ENGINE_VERSION,
                        max_valid_seconds=3600,
                    )
                    if not bg.enabled:
                        continue
                candidates.append(rec)

        if not candidates:
            raise CryptoError("no usable signing key")

        # deterministic: sort by not_after (soonest expiry first encourages rotation), then fp
        candidates.sort(key=lambda r: (r.not_after_epoch or float("inf"), r.pubkey_fingerprint))
        return candidates[0].pubkey_fingerprint

    def sign(
        self,
        message: bytes,
        *,
        operation: str,
        profile: CryptoProfile,
    ) -> Tuple[bytes, SigningKeyHandle]:
        """
        A.1/A.3: capability-style signing. No private key leaves registry.
        """
        _require_crypto_dep()
        op = _sanitize_operation(operation)

        fp = self._select_candidate_fp(operation=op, profile=profile)

        with self._lock:
            rec = self._records.get(fp)
            if rec is None:
                raise CryptoError("selected key missing")
            priv = self._privkeys.get(fp)
            if priv is None:
                raise CryptoError("private key unavailable (expired/wiped)")
            if not isinstance(priv, Ed25519PrivateKey):
                raise CryptoError("private key type mismatch")

        sig = priv.sign(message)
        return sig, rec.to_handle()

    def public_keys_pem(self) -> Dict[str, str]:
        """
        Export public key material: pubkey_fp -> PEM.
        """
        _require_crypto_dep()
        assert serialization is not None

        out: Dict[str, str] = {}
        with self._lock:
            items = list(self._records.items())
            privs = dict(self._privkeys)

        for fp, rec in items:
            # if private key present, derive pub; else cannot derive unless we stored pub separately.
            # For L6: we should store public keys too; but here we at least publish for keys still in memory.
            priv = privs.get(fp)
            if isinstance(priv, Ed25519PrivateKey):
                pub = priv.public_key()
                pem = pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")
                out[fp] = pem
        return out

    def key_registry_snapshot(self) -> Dict[str, Any]:
        """
        Secret-free snapshot for digests and auditing (I.4/K.1).
        """
        with self._lock:
            recs = list(self._records.values())
        recs.sort(key=lambda r: r.pubkey_fingerprint)
        keys_payload = []
        for r in recs:
            keys_payload.append(
                {
                    "pubkey_fingerprint": r.pubkey_fingerprint,
                    "key_id": r.key_id,
                    "algo": r.algo,
                    "backend_type": r.backend_type,
                    "status": r.status,
                    "role": r.role,
                    "classification_level": r.classification_level,
                    "allowed_operations": list(r.allowed_operations),
                    "not_before_epoch": r.not_before_epoch,
                    "not_after_epoch": r.not_after_epoch,
                }
            )
        return {"keys": keys_payload}

    def key_registry_digest_hex(self) -> str:
        snap = self.key_registry_snapshot()
        return _canonical_hash(snap, ctx=_KEYREG_CTX, label=_KEYREG_LABEL)


# ---------------------------------------------------------------------------
# Helpers for ops parsing / time bounds
# ---------------------------------------------------------------------------

def _finite_or_none(x: Optional[float]) -> Optional[float]:
    if x is None:
        return None
    try:
        v = float(x)
    except Exception:
        return None
    return v if math.isfinite(v) else None


def _sanitize_ops_for_profile(ops: Any, *, profile: CryptoProfile) -> Tuple[str, ...]:
    """
    I.3: strict profiles reject empty/invalid ops; dev may default with audit+warning.
    """
    strict = _is_strict_profile(profile) or profile == "SECURE_DEV"

    out: list[str] = []
    if isinstance(ops, (list, tuple, set)):
        seq = list(ops)
    elif ops is None:
        seq = []
    else:
        seq = [ops]

    for x in seq:
        if len(out) >= 32:
            break
        try:
            out.append(_sanitize_operation(str(x)))
        except Exception:
            continue

    out = sorted(set(out))
    if not out:
        if strict:
            raise CryptoError("allowed_operations empty/invalid in strict profile")
        # dev: default but record policy degradation
        _emit_audit_event("PolicyRelaxation", {"scope": "ops_defaulted", "reason_hash": "dev_default"})
        logger.warning("allowed_operations empty/invalid; defaulting to sign_receipt in dev")
        out = ["sign_receipt"]

    return tuple(out)


# ---------------------------------------------------------------------------
# Signature suites + registry (C.3/C.4: self-describing verification)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SignatureSuite:
    suite_id: str
    hash_algo: HashAlgo
    mac_algo: Optional[MacAlgo]
    sign_algo: SignAlgo  # current build supports ED25519 only
    digest_bytes: int  # digest output size (bytes) for digest_hex validation

    def hash_policy(self, *, profile: CryptoProfile, engine_version: str) -> HashPolicy:
        # Bind suite algo to hash policy while respecting profile ds_version and fallback governance.
        base = HashPolicy.for_profile(profile, engine_version=engine_version)
        # override base algo with suite requirements
        return HashPolicy(
            profile=profile,
            hash_algo=self.hash_algo,
            mac_algo=self.mac_algo,
            ds_version=base.ds_version,
            reject_on_fallback=base.reject_on_fallback,
            digest_size=32 if self.digest_bytes == 32 else 64,
        )


class SuiteRegistry:
    def __init__(self) -> None:
        self._suites: Dict[str, SignatureSuite] = {}

    def register(self, suite: SignatureSuite) -> None:
        self._suites[suite.suite_id] = suite

    def get(self, suite_id: str) -> Optional[SignatureSuite]:
        return self._suites.get(suite_id)

    @classmethod
    def default(cls) -> "SuiteRegistry":
        r = cls()
        # Existing suite ids
        r.register(SignatureSuite("TCD-ED25519-SHA2-256-v1", "SHA2_256", "HMAC_SHA2_256", "ED25519", 32))
        r.register(SignatureSuite("TCD-ED25519-SHA3-256-v1", "SHA3_256", "HMAC_SHA2_256", "ED25519", 32))
        # If blake3 missing, suite still exists but verification/sign will depend on policy fallback settings.
        r.register(SignatureSuite("TCD-ED25519-BLAKE3-256-v1", "BLAKE3_256", "BLAKE2B_MAC", "ED25519", 32))
        return r


_DEFAULT_SUITE_REGISTRY = SuiteRegistry.default()


# ---------------------------------------------------------------------------
# Envelope model (C.2/C.4/C.5/K.2)
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class SignatureEnvelope:
    engine_version: str
    message_version: MessageVersion
    profile: CryptoProfile
    suite_id: str
    label: HashLabel

    digest_hex: str

    pubkey_fingerprint: str  # canonical identity (B.2/B.3)
    key_id: str  # alias (B.3)
    algo: SignAlgo

    signature_b64: str
    measurement_hex: str = ""

    # K.2: bind policy/state
    policy_digest_hex: str = ""
    key_registry_digest_hex: str = ""
    domain_prefix_digest_hex: str = ""

    def to_json(self) -> str:
        # P: sanitize / cap sizes
        def cap(s: str, n: int) -> str:
            return _safe_text(s, max_len=n)

        d = {
            "engine_version": cap(self.engine_version, _MAX_STR_SMALL),
            "message_version": cap(self.message_version, _MAX_STR_SMALL),
            "profile": cap(self.profile, _MAX_STR_SMALL),
            "suite_id": cap(self.suite_id, _MAX_STR_SMALL),
            "label": cap(self.label, _MAX_STR_SMALL),
            "digest_hex": cap(self.digest_hex, 256),
            "pubkey_fingerprint": cap(self.pubkey_fingerprint, _MAX_STR_SMALL),
            "key_id": cap(self.key_id, _MAX_STR_SMALL),
            "algo": cap(self.algo, _MAX_STR_SMALL),
            "signature_b64": cap(self.signature_b64, 4096),
            "measurement_hex": cap(self.measurement_hex, 1024),
            "policy_digest_hex": cap(self.policy_digest_hex, 256),
            "key_registry_digest_hex": cap(self.key_registry_digest_hex, 256),
            "domain_prefix_digest_hex": cap(self.domain_prefix_digest_hex, 256),
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, s: str) -> "SignatureEnvelope":
        """
        C.2: strict validation (no cast() pretending).
        Raises CryptoError on invalid input.
        """
        try:
            obj = json.loads(s)
        except Exception as e:
            raise CryptoError(f"invalid envelope json: {e}") from e
        if not isinstance(obj, dict):
            raise CryptoError("invalid envelope json: not object")

        def req(name: str) -> str:
            if name not in obj:
                raise CryptoError(f"missing envelope field: {name}")
            v = obj[name]
            if not isinstance(v, str):
                raise CryptoError(f"envelope field {name} must be string")
            return _safe_text(v, max_len=_MAX_STR_LARGE)

        engine_version = req("engine_version")
        if engine_version not in _SUPPORTED_ENGINE_VERSIONS:
            raise CryptoError("unsupported engine_version")

        mv = req("message_version")
        if mv not in ("v1", "v2", "v3"):
            raise CryptoError("invalid message_version")
        message_version = cast(MessageVersion, mv)

        profile = req("profile").upper()
        if profile not in _ALLOWED_PROFILES:
            raise CryptoError("invalid profile")
        profile_t = cast(CryptoProfile, profile)

        suite_id = req("suite_id")
        if _DEFAULT_SUITE_REGISTRY.get(suite_id) is None:
            raise CryptoError("unsupported suite_id")

        label = req("label")
        if label not in _ALLOWED_HASH_LABELS:
            raise CryptoError("invalid label")
        label_t = cast(HashLabel, label)

        digest_hex = req("digest_hex")
        # digest length validated against suite at verification time; but enforce strict hex here too.
        if digest_hex.startswith(("0x", "0X")):
            raise CryptoError("digest_hex must not have 0x prefix")
        _ = _hex_to_bytes(digest_hex, max_input_chars=512, allow_odd_len=False)

        pubkey_fp = _validate_pubkey_fp(req("pubkey_fingerprint"))
        key_id = _validate_key_id_alias(req("key_id"))

        algo = req("algo")
        if algo not in _IMPLEMENTED_SIGN_ALGOS:
            raise CryptoError("unsupported algo")
        algo_t = cast(SignAlgo, algo)

        sig_b64 = req("signature_b64")
        if len(sig_b64) > _MAX_B64_INPUT_CHARS:
            raise CryptoError("signature_b64 too large")
        sig = _b64_decode_strict(sig_b64, max_chars=_MAX_B64_INPUT_CHARS)
        if algo_t == "ED25519" and len(sig) != _ED25519_SIG_LEN:
            raise CryptoError("invalid signature length for ED25519")

        meas_hex = _safe_text(obj.get("measurement_hex", ""), max_len=1024)
        if meas_hex:
            _ = _hex_to_bytes(meas_hex, max_input_chars=1024, allow_odd_len=False)
            if len(meas_hex) > 2 * _MAX_MEASUREMENT_LEN:
                raise CryptoError("measurement_hex too large")

        policy_digest_hex = _safe_text(obj.get("policy_digest_hex", ""), max_len=256)
        if policy_digest_hex:
            _ = _hex_to_bytes(policy_digest_hex, max_input_chars=256, allow_odd_len=False)

        keyreg_digest_hex = _safe_text(obj.get("key_registry_digest_hex", ""), max_len=256)
        if keyreg_digest_hex:
            _ = _hex_to_bytes(keyreg_digest_hex, max_input_chars=256, allow_odd_len=False)

        dp_digest_hex = _safe_text(obj.get("domain_prefix_digest_hex", ""), max_len=256)
        if dp_digest_hex:
            _ = _hex_to_bytes(dp_digest_hex, max_input_chars=256, allow_odd_len=False)

        # C.4: engine_version compatibility gates message_version
        if engine_version == "crypto_v3" and message_version == "v3":
            raise CryptoError("crypto_v3 does not support message_version v3")
        if engine_version == "crypto_v4" and message_version == "v1":
            # v1 is legacy; allow only if explicit
            allow_v1, _ = _env_bool("TCD_ALLOW_ENVELOPE_V1", False)
            if not allow_v1:
                raise CryptoError("crypto_v4 envelope v1 disallowed by default")

        return cls(
            engine_version=engine_version,
            message_version=message_version,
            profile=profile_t,
            suite_id=suite_id,
            label=label_t,
            digest_hex=digest_hex,
            pubkey_fingerprint=pubkey_fp,
            key_id=key_id,
            algo=algo_t,
            signature_b64=sig_b64,
            measurement_hex=meas_hex,
            policy_digest_hex=policy_digest_hex,
            key_registry_digest_hex=keyreg_digest_hex,
            domain_prefix_digest_hex=dp_digest_hex,
        )


# ---------------------------------------------------------------------------
# Public key parse cache (M.2)
# ---------------------------------------------------------------------------

_PUBKEY_CACHE_LOCK = threading.Lock()
_PUBKEY_CACHE: "collections.OrderedDict[str, Any]" = collections.OrderedDict()
_PUBKEY_CACHE_MAX = _DEFAULT_PUBKEY_CACHE_MAX_ENTRIES


def _pubkey_cache_configure() -> None:
    global _PUBKEY_CACHE_MAX
    n, used = _env_int("TCD_PUBKEY_CACHE_MAX_ENTRIES", _DEFAULT_PUBKEY_CACHE_MAX_ENTRIES)
    if not used:
        _PUBKEY_CACHE_MAX = _DEFAULT_PUBKEY_CACHE_MAX_ENTRIES
        return
    try:
        nn = int(n)
    except Exception:
        nn = _DEFAULT_PUBKEY_CACHE_MAX_ENTRIES
    nn = max(1, min(nn, _HARD_MAX_PUBKEY_CACHE_MAX_ENTRIES))
    _PUBKEY_CACHE_MAX = nn


def _load_pem_public_key_cached(pem_str: str) -> Any:
    """
    Never logs PEM. Uses cache keyed by sha256(pem_bytes).
    """
    _require_crypto_dep()
    assert serialization is not None

    if not isinstance(pem_str, str):
        raise CryptoError("public_key_pem must be str")
    if len(pem_str) > _HARD_MAX_PUBKEY_PEM_BYTES:
        raise CryptoError("public_key_pem too large")

    pem_bytes = pem_str.encode("utf-8", errors="strict")
    key = hashlib.sha256(pem_bytes).hexdigest()

    _pubkey_cache_configure()

    with _PUBKEY_CACHE_LOCK:
        v = _PUBKEY_CACHE.get(key)
        if v is not None:
            _PUBKEY_CACHE.move_to_end(key)
            _m_inc("tcd_crypto_pubkey_cache_total", 1, {"result": "hit"})
            return v
    _m_inc("tcd_crypto_pubkey_cache_total", 1, {"result": "miss"})

    pub = serialization.load_pem_public_key(pem_bytes)
    with _PUBKEY_CACHE_LOCK:
        _PUBKEY_CACHE[key] = pub
        _PUBKEY_CACHE.move_to_end(key)
        while len(_PUBKEY_CACHE) > _PUBKEY_CACHE_MAX:
            _PUBKEY_CACHE.popitem(last=False)
    return pub


# ---------------------------------------------------------------------------
# Signing message formats (C.4/K.2/D.1–D.3)
# ---------------------------------------------------------------------------

def _build_signing_message_v1(
    *,
    profile: CryptoProfile,
    suite_id: str,
    label: HashLabel,
    measurement: bytes,
    digest_bytes: bytes,
) -> bytes:
    return b"".join(
        [
            b"TCD-SIGN-v1|",
            profile.encode("ascii"),
            b"|",
            suite_id.encode("ascii"),
            b"|",
            label.encode("ascii"),
            b"|",
            measurement,
            b"|",
            digest_bytes,
        ]
    )


def _build_signing_message_v2(
    *,
    profile: CryptoProfile,
    suite_id: str,
    label: HashLabel,
    measurement: bytes,
    digest_bytes: bytes,
) -> bytes:
    # length-prefix: stable, unambiguous
    def pack(b: bytes) -> bytes:
        return _pack_blob(b)

    return b"".join(
        [
            b"TCD-SIGN-v2",
            pack(profile.encode("ascii")),
            pack(suite_id.encode("ascii")),
            pack(label.encode("ascii")),
            pack(measurement),
            pack(digest_bytes),
        ]
    )


def _build_signing_message_v3(
    *,
    engine_version: str,
    ds_version: DsVersion,
    profile: CryptoProfile,
    suite_id: str,
    label: HashLabel,
    domain_prefix_digest_hex: str,
    policy_digest_hex: str,
    measurement: bytes,
    digest_bytes: bytes,
) -> bytes:
    """
    K.2 / C.4: binds policy + DS + engine version into signature message.
    """
    def pack(b: bytes) -> bytes:
        return _pack_blob(b)

    dpd = _hex_to_bytes(domain_prefix_digest_hex, expected_len=32, allow_odd_len=False)
    pold = _hex_to_bytes(policy_digest_hex, expected_len=32, allow_odd_len=False)

    return b"".join(
        [
            b"TCD-SIGN-v3",
            pack(engine_version.encode("ascii")),
            pack(ds_version.encode("ascii")),
            pack(profile.encode("ascii")),
            pack(suite_id.encode("ascii")),
            pack(label.encode("ascii")),
            pack(dpd),
            pack(pold),
            pack(measurement),
            pack(digest_bytes),
        ]
    )


# ---------------------------------------------------------------------------
# File permission governance (O.1/O.2 + J.*)
# ---------------------------------------------------------------------------

def _parse_int_set(csv: Optional[str], *, max_items: int = 64) -> frozenset[int]:
    if not csv:
        return frozenset()
    out: set[int] = set()
    for part in csv.split(","):
        if len(out) >= max_items:
            break
        p = part.strip()
        if not p:
            continue
        try:
            out.add(int(p))
        except Exception:
            continue
    return frozenset(out)


def _check_file_permissions(path: str, *, profile: CryptoProfile) -> Tuple[bool, str]:
    """
    O.1: strict profiles enforce strongly; dev allows more but audits.
    O.2: support allowed uid/gid allowlists (governed).
    """
    p = _safe_text(path, max_len=_MAX_STR_LARGE)
    if not p:
        return False, "empty_path"

    strict = _is_strict_profile(profile) or profile == "SECURE_DEV"

    # allowlists
    allowed_uids = _parse_int_set(_env_get("TCD_KEYFILE_ALLOWED_UIDS"))
    allowed_gids = _parse_int_set(_env_get("TCD_KEYFILE_ALLOWED_GIDS"))

    try:
        if os.path.islink(p):
            return False, "symlink_disallowed"
    except Exception:
        if strict:
            return False, "link_check_failed"

    try:
        st = os.stat(p, follow_symlinks=False)  # type: ignore[call-arg]
    except Exception:
        return False, "stat_failed"

    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o002:
        return False, "world_writable"

    uid = os.getuid() if hasattr(os, "getuid") else None
    gid = os.getgid() if hasattr(os, "getgid") else None

    # owner check: root/current uid/allowed uids
    if uid is not None:
        ok_owner = st.st_uid in (0, uid) or st.st_uid in allowed_uids
        if not ok_owner:
            return False, "bad_owner"

    # group check: allow if group is current or allowed gid (common k8s fsGroup)
    if gid is not None:
        ok_group = st.st_gid in (gid,) or st.st_gid in allowed_gids or st.st_gid == 0
        if not ok_group and strict:
            return False, "bad_group"

    # parent directory checks
    try:
        parent = os.path.dirname(p) or "."
        pst = os.stat(parent, follow_symlinks=False)  # type: ignore[call-arg]
        pmode = stat.S_IMODE(pst.st_mode)
        if (pmode & 0o002) and not (pmode & stat.S_ISVTX):
            if strict:
                return False, "parent_world_writable_no_sticky"
            # dev: allow but audit
            _emit_audit_event("PolicyRelaxation", {"scope": "parent_world_writable", "reason_hash": "dev_allow"})
    except Exception:
        if strict:
            return False, "parent_stat_failed"
        _emit_audit_event("PolicyRelaxation", {"scope": "parent_stat_failed", "reason_hash": "dev_allow"})

    return True, "ok"


def _read_small_file_bytes(path: str, *, max_bytes: int, profile: CryptoProfile) -> bytes:
    """
    Bounded read with TOCTTOU guard.
    """
    ok, reason = _check_file_permissions(path, profile=profile)
    if not ok:
        _m_inc("tcd_crypto_key_file_reject_total", 1, {"reason": reason, "profile": profile})
        raise CryptoError(f"file_insecure:{reason}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= getattr(os, "O_NOFOLLOW")

    p = _safe_text(path, max_len=_MAX_STR_LARGE)
    st1 = os.stat(p, follow_symlinks=False)  # type: ignore[call-arg]
    fd: Optional[int] = None
    try:
        fd = os.open(p, flags)
        st2 = os.fstat(fd)
        if st1.st_ino != st2.st_ino or st1.st_dev != st2.st_dev:
            raise CryptoError("tocttou_mismatch")

        with os.fdopen(fd, "rb") as f:
            fd = None
            data = f.read(int(max_bytes) + 1)
            if len(data) > int(max_bytes):
                raise CryptoError("file_too_large")
            return data
    except Exception as e:
        raise CryptoError(f"file_read_fail:{e}") from e
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Keyset schema + signature verification (J.1–J.3)
# ---------------------------------------------------------------------------

_KEYSET_VERSION = "tcd-keyset-v1"

def _keyset_canonical_bytes(doc: Dict[str, Any]) -> bytes:
    """
    Canonicalize keyset for signing:
      - include version, signer, keys
      - exclude signature fields
    """
    canon = {
        "version": doc.get("version"),
        "signer": doc.get("signer", ""),
        "keys": doc.get("keys", []),
    }
    return json.dumps(canon, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _verify_keyset_signature_if_present(
    doc: Dict[str, Any],
    *,
    profile: CryptoProfile,
) -> Tuple[bool, str]:
    """
    Returns (ok, reason). Strict profiles require signature.
    Trust root is provided externally (env/file), not inside the keyset.
    """
    strict = _is_strict_profile(profile) or profile == "SECURE_DEV"

    sig_b64 = doc.get("sig_b64")
    signer = doc.get("signer")

    if sig_b64 is None:
        if strict:
            return False, "KEYSET_SIGNATURE_REQUIRED"
        _emit_audit_event("KeysetSignatureMissing", {"profile": profile})
        return True, "OK"

    if not isinstance(sig_b64, str) or not isinstance(signer, str):
        return False, "KEYSET_BAD_SCHEMA"

    # Load trusted signer public key from env/path
    pk_pem = _env_get("TCD_KEYSET_TRUSTED_SIGNER_PUBKEY_PEM")
    pk_path = _env_get("TCD_KEYSET_TRUSTED_SIGNER_PUBKEY_PATH")
    if pk_pem is None and pk_path is None:
        return False, "KEYSET_SIGNER_MISSING"

    try:
        if pk_path:
            pem_bytes = _read_small_file_bytes(pk_path, max_bytes=_MAX_KEY_PEM_BYTES, profile=profile)
            pk_pem = pem_bytes.decode("utf-8", errors="strict")
        assert pk_pem is not None
        pub = _load_pem_public_key_cached(pk_pem)
        if not isinstance(pub, Ed25519PublicKey):
            return False, "KEYSET_SIGNER_MISSING"
        sig = _b64_decode_strict(sig_b64, max_chars=_MAX_B64_INPUT_CHARS)
        if len(sig) != _ED25519_SIG_LEN:
            return False, "KEYSET_SIGNATURE_INVALID"

        msg = b"TCD-KEYSET-SIGN-v1|" + hashlib.sha256(_keyset_canonical_bytes(doc)).digest()
        pub.verify(sig, msg)
        _emit_audit_event("KeysetSignatureVerified", {"profile": profile, "signer": _safe_text(signer, max_len=_MAX_STR_SMALL)})
        return True, "OK"
    except Exception:
        return False, "KEYSET_SIGNATURE_INVALID"


# ---------------------------------------------------------------------------
# CryptoContext (policy/state digests, suite selection, strict governance)
# ---------------------------------------------------------------------------

@dataclass
class CryptoContext:
    profile: CryptoProfile
    suite_id: str
    hash_engine: HashEngine
    kdf_engine: KdfEngine
    rng_context: RngContext
    key_registry: KeyRegistry
    suite_registry: SuiteRegistry
    loaded_at_epoch: float
    revision: int
    profile_origin: str  # direct|legacy_map|default

    def policy_snapshot(self) -> Dict[str, Any]:
        """
        K.1: secret-free policy snapshot.
        """
        dpd = _domain_prefix_digest_hex(self.profile)
        suite = self.suite_registry.get(self.suite_id)
        assert suite is not None
        return {
            "engine_version": _CRYPTO_ENGINE_VERSION,
            "profile": self.profile,
            "profile_origin": self.profile_origin,
            "suite_id": self.suite_id,
            "hash_algo": suite.hash_algo,
            "mac_algo": suite.mac_algo,
            "ds_version": self.hash_engine.policy.ds_version,
            "reject_on_fallback": bool(self.hash_engine.policy.reject_on_fallback),
            "kdf_hash_algo": self.kdf_engine.policy.kdf_hash_algo,
            "rng_backend": self.rng_context._policy.backend,  # internal, but secret-free
            "rng_require_certified": bool(self.rng_context._policy.require_certified),
            "domain_prefix_digest_hex": dpd,
            "domain_prefix_origin": _DOMAIN_PREFIX_ORIGIN,
            "implemented_key_backends": sorted(_IMPLEMENTED_KEY_BACKENDS),
            "implemented_sign_algos": sorted(_IMPLEMENTED_SIGN_ALGOS),
        }

    def policy_digest_hex(self) -> str:
        snap = self.policy_snapshot()
        return _canonical_hash(snap, ctx=_POLICY_CTX, label=_POLICY_LABEL)

    def state_snapshot(self) -> Dict[str, Any]:
        """
        crypto_state = policy_digest + key_registry_digest + revision + loaded_at
        """
        return {
            "policy_digest_hex": self.policy_digest_hex(),
            "key_registry_digest_hex": self.key_registry.key_registry_digest_hex(),
            "revision": int(self.revision),
            "loaded_at_epoch": float(self.loaded_at_epoch),
        }

    def state_digest_hex(self) -> str:
        return _canonical_hash(self.state_snapshot(), ctx=_STATE_CTX, label=_STATE_LABEL)

    # -------------------
    # Signing / verifying
    # -------------------

    def sign_envelope(
        self,
        blob: bytes,
        *,
        label: HashLabel = "receipt",
        operation: str = "sign_receipt",
        attestation: Optional[AttestationContext] = None,
        message_version: MessageVersion = "v3",
    ) -> SignatureEnvelope:
        """
        M.1: preferred signing API.
        """
        op = _sanitize_operation(operation)
        suite = self.suite_registry.get(self.suite_id)
        if suite is None:
            raise CryptoError("unsupported suite")

        if suite.sign_algo not in _IMPLEMENTED_SIGN_ALGOS:
            raise CryptoError("sign algo not implemented")

        # digest
        digest_bytes = self.hash_engine.digest_bytes(blob, label=label)
        digest_hex = _bytes_to_hex(digest_bytes)

        mh = (attestation or AttestationContext()).measurement_or_empty(profile=self.profile)

        # message format
        dpd = _domain_prefix_digest_hex(self.profile)
        pol_digest = self.policy_digest_hex()

        if message_version == "v1":
            msg = _build_signing_message_v1(profile=self.profile, suite_id=self.suite_id, label=label, measurement=mh, digest_bytes=digest_bytes)
        elif message_version == "v2":
            msg = _build_signing_message_v2(profile=self.profile, suite_id=self.suite_id, label=label, measurement=mh, digest_bytes=digest_bytes)
        else:
            msg = _build_signing_message_v3(
                engine_version=_CRYPTO_ENGINE_VERSION,
                ds_version=self.hash_engine.policy.ds_version,
                profile=self.profile,
                suite_id=self.suite_id,
                label=label,
                domain_prefix_digest_hex=dpd,
                policy_digest_hex=pol_digest,
                measurement=mh,
                digest_bytes=digest_bytes,
            )

        sig, handle = self.key_registry.sign(msg, operation=op, profile=self.profile)

        env = SignatureEnvelope(
            engine_version=_CRYPTO_ENGINE_VERSION,
            message_version=message_version,
            profile=self.profile,
            suite_id=self.suite_id,
            label=label,
            digest_hex=digest_hex,
            pubkey_fingerprint=handle.pubkey_fingerprint,
            key_id=handle.key_id,
            algo=handle.algo,
            signature_b64=base64.b64encode(sig).decode("ascii"),
            measurement_hex=_bytes_to_hex(mh) if mh else "",
            policy_digest_hex=pol_digest,
            key_registry_digest_hex=self.key_registry.key_registry_digest_hex(),
            domain_prefix_digest_hex=dpd,
        )

        _emit_audit_event(
            "SignOperation",
            {
                "profile": self.profile,
                "suite_id": self.suite_id,
                "op": op,
                "label": label,
                "message_version": message_version,
                "pubkey_fp": handle.pubkey_fingerprint,
            },
        )
        _m_inc("tcd_crypto_sign_total", 1, {"profile": self.profile, "suite": self.suite_id, "op": op, "result": "ok"})

        return env

    def sign_blob(self, blob: bytes, *, label: HashLabel = "receipt", operation: str = "sign_receipt", attestation: Optional[AttestationContext] = None) -> Tuple[bytes, str, str, str]:
        """
        Backward-compatible tuple API.
        M.1: strict profiles disallow by default (use envelope) unless break-glass.
        """
        if _is_strict_profile(self.profile) or self.profile in ("SECURE_DEV", "SECURE_PREP"):
            allow, _ = _env_bool("TCD_ALLOW_TUPLE_SIGN_API", False)
            if not allow:
                bg = _break_glass_state(
                    scope="allow_tuple_sign_api",
                    prefix="TCD_TUPLE_SIGN_BREAK_GLASS",
                    engine_version=_CRYPTO_ENGINE_VERSION,
                    max_valid_seconds=3600,
                )
                if not bg.enabled:
                    raise CryptoError("tuple sign_blob() disallowed in strict profiles; use sign_envelope()")
                _emit_audit_event("PolicyRelaxation", {"scope": bg.scope, "reason_hash": bg.reason_hash, "expires_epoch": bg.expires_epoch})

        env = self.sign_envelope(blob, label=label, operation=operation, attestation=attestation, message_version="v3")
        sig = _b64_decode_strict(env.signature_b64)
        return sig, env.digest_hex, env.pubkey_fingerprint, env.algo

    def verify_envelope(self, blob: bytes, env: SignatureEnvelope, public_key_pem: str) -> bool:
        ok, _ = verify_envelope_any(
            blob,
            env,
            public_key_pem,
            suite_registry=self.suite_registry,
            key_registry=self.key_registry,
        )
        return ok

    def verify_blob(self, blob: bytes, signature: bytes, public_key_pem: str, *, label: HashLabel = "receipt", attestation: Optional[AttestationContext] = None) -> bool:
        """
        Backward-compatible verify without envelope.
        M.2: uses cached PEM parse.
        Never throws.
        """
        try:
            if not isinstance(signature, (bytes, bytearray)):
                return False
            sig = bytes(signature)
            if len(sig) != _ED25519_SIG_LEN:
                return False

            pub = _load_pem_public_key_cached(public_key_pem)
            if not isinstance(pub, Ed25519PublicKey):
                return False

            mh = (attestation or AttestationContext()).measurement_or_empty(profile=self.profile)

            # Try crypto_v4 digest+msg v3, then fall back to older combos.
            # This allows verification across upgrades even without envelope (best-effort).
            # 1) v3
            digest_b_v4 = self.hash_engine.digest_bytes(blob, label=label)
            msg_v3 = _build_signing_message_v3(
                engine_version=_CRYPTO_ENGINE_VERSION,
                ds_version=self.hash_engine.policy.ds_version,
                profile=self.profile,
                suite_id=self.suite_id,
                label=label,
                domain_prefix_digest_hex=_domain_prefix_digest_hex(self.profile),
                policy_digest_hex=self.policy_digest_hex(),
                measurement=mh,
                digest_bytes=digest_b_v4,
            )
            try:
                pub.verify(sig, msg_v3)
                return True
            except Exception:
                pass

            # 2) legacy v2 with current digest
            msg_v2 = _build_signing_message_v2(profile=self.profile, suite_id=self.suite_id, label=label, measurement=mh, digest_bytes=digest_b_v4)
            try:
                pub.verify(sig, msg_v2)
                return True
            except Exception:
                pass

            # 3) legacy v1
            msg_v1 = _build_signing_message_v1(profile=self.profile, suite_id=self.suite_id, label=label, measurement=mh, digest_bytes=digest_b_v4)
            try:
                pub.verify(sig, msg_v1)
                return True
            except Exception:
                return False
        except Exception:
            return False


# ---------------------------------------------------------------------------
# verify_envelope_any (C.1–C.5, C.3: self-describing verify, never-throw)
# ---------------------------------------------------------------------------

def verify_envelope_any(
    blob: bytes,
    env: SignatureEnvelope,
    public_key_pem: str,
    *,
    suite_registry: Optional[SuiteRegistry] = None,
    key_registry: Optional[KeyRegistry] = None,
) -> Tuple[bool, VerifyReason]:
    """
    C.1: never-throw boolean verify (returns reason code for metrics/audit).
    C.3: does NOT depend on current process CryptoContext profile/suite; uses env.suite_id.
    C.4: engine_version gates decoding/semantics.
    C.5/B.3: checks algo & pubkey_fingerprint mapping; optionally checks key_id mapping via key_registry.
    """
    sr = suite_registry or _DEFAULT_SUITE_REGISTRY
    try:
        if env.engine_version not in _SUPPORTED_ENGINE_VERSIONS:
            _m_inc("tcd_crypto_verify_total", 1, {"result": "fail", "reason": "UNSUPPORTED_ENGINE"})
            return False, "UNSUPPORTED_ENGINE"

        suite = sr.get(env.suite_id)
        if suite is None:
            _m_inc("tcd_crypto_verify_total", 1, {"result": "fail", "reason": "UNSUPPORTED_SUITE"})
            return False, "UNSUPPORTED_SUITE"

        if env.algo not in _IMPLEMENTED_SIGN_ALGOS or suite.sign_algo != env.algo:
            _m_inc("tcd_crypto_verify_total", 1, {"result": "fail", "reason": "UNSUPPORTED_ALGO"})
            return False, "UNSUPPORTED_ALGO"

        # parse signature strictly
        sig = _b64_decode_strict(env.signature_b64)
        if env.algo == "ED25519" and len(sig) != _ED25519_SIG_LEN:
            return False, "BAD_SIGNATURE_FORMAT"

        # parse pubkey (cached)
        pub = _load_pem_public_key_cached(public_key_pem)
        if not isinstance(pub, Ed25519PublicKey):
            return False, "BAD_PUBKEY"

        # B.2/B.3: compute fp and compare to envelope
        fp = pubkey_fingerprint_from_public_key(pub)
        if not hmac.compare_digest(fp, env.pubkey_fingerprint):
            return False, "PUBKEY_FP_MISMATCH"

        # Optional: enforce key_id alias mapping via registry (B.3/C.5)
        if key_registry is not None:
            h = key_registry.get_handle(fp)
            if h is None:
                return False, "KEY_ID_MISMATCH"
            # if env.key_id is non-empty, require match
            if env.key_id and h.key_id and not hmac.compare_digest(env.key_id, h.key_id):
                return False, "KEY_ID_MISMATCH"

        # Measurement parsing/validation (never throw)
        mh = b""
        if env.measurement_hex:
            mh = _hex_to_bytes(env.measurement_hex, max_input_chars=1024, allow_odd_len=False)
            if len(mh) > _MAX_MEASUREMENT_LEN:
                return False, "BAD_ENVELOPE"
            # strict length if strict profiles
            if (_is_strict_profile(env.profile) or env.profile == "SECURE_DEV") and len(mh) not in (0, _DEFAULT_MEASUREMENT_LEN):
                return False, "BAD_ENVELOPE"

        # Build hash engine for this envelope (C.3): based on suite+profile+engine_version
        _require_fips_ack_if_needed(env.profile)

        hp = suite.hash_policy(profile=env.profile, engine_version=env.engine_version)
        he = HashEngine(hp)

        digest_b = he.digest_bytes(blob, label=env.label)
        digest_hex = _bytes_to_hex(digest_b)

        # C.1: parse digest_hex safely
        try:
            env_digest_b = _hex_to_bytes(env.digest_hex, expected_len=suite.digest_bytes, allow_odd_len=False)
        except Exception:
            return False, "BAD_DIGEST_FORMAT"

        if not hmac.compare_digest(digest_b, env_digest_b):
            return False, "DIGEST_MISMATCH"

        # K.2: if envelope carries policy digest, enforce it for v3 in crypto_v4
        if env.message_version == "v3":
            # domain prefix digest must match for verification semantics
            dpd = _domain_prefix_digest_hex(env.profile)
            if env.domain_prefix_digest_hex and not hmac.compare_digest(env.domain_prefix_digest_hex, dpd):
                return False, "POLICY_DIGEST_MISMATCH"

            # policy digest is *envelope producer* policy; verifier may not match. But v3 message binds it.
            # We must use env.policy_digest_hex when reconstructing message; if missing -> reject.
            if not env.policy_digest_hex:
                return False, "BAD_ENVELOPE"
            # ensure policy_digest_hex is valid hex length 32 bytes
            try:
                _ = _hex_to_bytes(env.policy_digest_hex, expected_len=32, allow_odd_len=False)
            except Exception:
                return False, "BAD_ENVELOPE"

        # Build message according to message_version (C.4)
        if env.message_version == "v1":
            msg = _build_signing_message_v1(profile=env.profile, suite_id=env.suite_id, label=env.label, measurement=mh, digest_bytes=digest_b)
        elif env.message_version == "v2":
            msg = _build_signing_message_v2(profile=env.profile, suite_id=env.suite_id, label=env.label, measurement=mh, digest_bytes=digest_b)
        else:
            # v3 binds ds/policy digests
            dpd = env.domain_prefix_digest_hex or _domain_prefix_digest_hex(env.profile)
            msg = _build_signing_message_v3(
                engine_version=env.engine_version if env.engine_version == "crypto_v4" else _CRYPTO_ENGINE_VERSION,
                ds_version=hp.ds_version,
                profile=env.profile,
                suite_id=env.suite_id,
                label=env.label,
                domain_prefix_digest_hex=dpd,
                policy_digest_hex=env.policy_digest_hex,
                measurement=mh,
                digest_bytes=digest_b,
            )

        try:
            pub.verify(sig, msg)
        except Exception:
            return False, "BAD_SIGNATURE_VERIFY"

        _emit_audit_event(
            "VerifyEnvelope",
            {
                "engine_version": env.engine_version,
                "profile": env.profile,
                "suite_id": env.suite_id,
                "label": env.label,
                "message_version": env.message_version,
                "pubkey_fp": env.pubkey_fingerprint,
                "result": "ok",
            },
        )
        _m_inc("tcd_crypto_verify_total", 1, {"result": "ok", "reason": "OK"})
        return True, "OK"
    except Exception:
        _m_inc("tcd_crypto_verify_total", 1, {"result": "fail", "reason": "INTERNAL_ERROR"})
        return False, "INTERNAL_ERROR"


# ---------------------------------------------------------------------------
# Key loading from env/files (J.1–J.4, A.2)
# ---------------------------------------------------------------------------

def _load_pem_private_key(pem: bytes, password: Optional[bytes]) -> Any:
    _require_crypto_dep()
    assert serialization is not None
    return serialization.load_pem_private_key(pem, password=password)


def _load_password_bytes(profile: CryptoProfile) -> Optional[bytes]:
    """
    J.4: support password file.
    """
    pw = _env_get("TCD_ED25519_PRIVATE_KEY_PASSWORD")
    pwf = _env_get("TCD_ED25519_PRIVATE_KEY_PASSWORD_FILE")
    if pwf:
        b = _read_small_file_bytes(pwf, max_bytes=8192, profile=profile)
        # strip trailing newlines
        return b.strip() or None
    if pw:
        return pw.encode("utf-8")
    return None


def _load_key_registry(profile: CryptoProfile, *, suite_registry: SuiteRegistry) -> Tuple[Optional[KeyRegistry], LoadReason]:
    """
    J.1: keyset schema versioning + signature verify
    J.2: caps on key count & pem sizes
    J.3: strict profiles require break-glass for env/software keys relaxation
    """
    reg = KeyRegistry()

    # Determine whether env keys allowed in strict profile (J.3)
    allow_env_keys, used_env_allow = _env_bool("TCD_CRYPTO_ALLOW_ENV_KEYS", False)
    if (_is_strict_profile(profile) or profile == "SECURE_DEV") and allow_env_keys:
        bg = _break_glass_state(
            scope="allow_env_keys",
            prefix="TCD_ENV_KEYS_BREAK_GLASS",
            engine_version=_CRYPTO_ENGINE_VERSION,
            max_valid_seconds=3600,
        )
        if not bg.enabled:
            return None, "ENV_KEYS_NOT_ALLOWED"
        _emit_audit_event(
            "PolicyRelaxation",
            {"scope": bg.scope, "reason_hash": bg.reason_hash, "expires_epoch": bg.expires_epoch},
        )
        _m_gauge("tcd_crypto_break_glass_enabled", 1.0, {"scope": bg.scope})

    # Determine whether software keys allowed in strict profile (J.3)
    allow_software_keys, _ = _env_bool("TCD_CRYPTO_ALLOW_SOFTWARE_KEYS", False)
    if (_is_strict_profile(profile) or profile == "SECURE_DEV") and allow_software_keys:
        bg = _break_glass_state(
            scope="allow_software_keys",
            prefix="TCD_KEY_BACKEND_BREAK_GLASS",
            engine_version=_CRYPTO_ENGINE_VERSION,
            max_valid_seconds=3600,
        )
        if not bg.enabled:
            return None, "SOFTWARE_KEYS_NOT_ALLOWED"
        _emit_audit_event(
            "PolicyRelaxation",
            {"scope": bg.scope, "reason_hash": bg.reason_hash, "expires_epoch": bg.expires_epoch},
        )
        _m_gauge("tcd_crypto_break_glass_enabled", 1.0, {"scope": bg.scope})

    # Keyset source priority:
    # 1) KEYSET_PATH (file)
    # 2) KEYSET_JSON (env)
    # 3) PRIVATE_KEY_PATH (file)
    # 4) PRIVATE_KEY_PEM (env)
    keyset_path = _env_get("TCD_ED25519_KEYSET_PATH")
    keyset_json = _env_get("TCD_ED25519_KEYSET_JSON")

    if keyset_path:
        try:
            raw = _read_small_file_bytes(keyset_path, max_bytes=_MAX_KEYSET_FILE_BYTES, profile=profile)
        except Exception:
            return None, "FILE_READ_FAIL"
        if len(raw) > _MAX_KEYSET_FILE_BYTES:
            return None, "KEYSET_TOO_LARGE"
        try:
            doc = json.loads(raw.decode("utf-8", errors="strict"))
        except Exception:
            return None, "KEYSET_BAD_JSON"
        ok, reason = _load_keyset_doc_into_registry(doc, reg, profile=profile)
        return (reg, "OK") if ok else (None, cast(LoadReason, reason))

    if keyset_json:
        if len(keyset_json.encode("utf-8", errors="ignore")) > _MAX_ENV_JSON_BYTES:
            return None, "KEYSET_TOO_LARGE"
        if (_is_strict_profile(profile) or profile == "SECURE_DEV") and not allow_env_keys:
            return None, "ENV_KEYS_NOT_ALLOWED"
        try:
            doc = json.loads(keyset_json)
        except Exception:
            return None, "KEYSET_BAD_JSON"
        ok, reason = _load_keyset_doc_into_registry(doc, reg, profile=profile)
        return (reg, "OK") if ok else (None, cast(LoadReason, reason))

    # Single key file
    key_path = _env_get("TCD_ED25519_PRIVATE_KEY_PATH")
    if key_path:
        try:
            pem = _read_small_file_bytes(key_path, max_bytes=_MAX_KEY_PEM_BYTES, profile=profile)
        except Exception:
            return None, "FILE_READ_FAIL"
        pwd = _load_password_bytes(profile)
        try:
            priv = _load_pem_private_key(pem, password=pwd)
        except Exception:
            return None, "KEY_PEM_PARSE_FAIL"
        if not isinstance(priv, Ed25519PrivateKey):
            return None, "KEY_PEM_PARSE_FAIL"
        if (_is_strict_profile(profile) or profile == "SECURE_DEV") and not allow_software_keys:
            return None, "SOFTWARE_KEYS_NOT_ALLOWED"

        key_id = _validate_key_id_alias(_env_get("TCD_ED25519_KEY_ID") or "")
        reg.add_or_replace_private_key(
            private_key=priv,
            key_id_alias=key_id,
            status="active",
            role="online_signing",
            classification_level="public",
            allowed_operations=("sign_receipt", "sign_ledger", "sign_config"),
            not_before_epoch=None,
            not_after_epoch=None,
            backend_type="software_dev",
            profile=profile,
        )
        reg.wipe_private_for_expired()
        return reg, "OK"

    # Single key env PEM
    pem_str = _env_get("TCD_ED25519_PRIVATE_KEY_PEM")
    if pem_str:
        if len(pem_str.encode("utf-8", errors="ignore")) > _MAX_ENV_PEM_BYTES:
            return None, "KEY_PEM_TOO_LARGE"
        if (_is_strict_profile(profile) or profile == "SECURE_DEV") and not allow_env_keys:
            return None, "ENV_KEYS_NOT_ALLOWED"
        if (_is_strict_profile(profile) or profile == "SECURE_DEV") and not allow_software_keys:
            return None, "SOFTWARE_KEYS_NOT_ALLOWED"

        pwd = _load_password_bytes(profile)
        try:
            priv = _load_pem_private_key(pem_str.encode("utf-8"), password=pwd)
        except Exception:
            return None, "KEY_PEM_PARSE_FAIL"
        if not isinstance(priv, Ed25519PrivateKey):
            return None, "KEY_PEM_PARSE_FAIL"

        key_id = _validate_key_id_alias(_env_get("TCD_ED25519_KEY_ID") or "")
        reg.add_or_replace_private_key(
            private_key=priv,
            key_id_alias=key_id,
            status="active",
            role="online_signing",
            classification_level="public",
            allowed_operations=("sign_receipt", "sign_ledger", "sign_config"),
            not_before_epoch=None,
            not_after_epoch=None,
            backend_type="software_dev",
            profile=profile,
        )
        reg.wipe_private_for_expired()
        return reg, "OK"

    return None, "MISSING_KEYS"


def _load_keyset_doc_into_registry(doc: Any, reg: KeyRegistry, *, profile: CryptoProfile) -> Tuple[bool, str]:
    """
    Supports:
      - J.1: {"version":"tcd-keyset-v1","keys":[...],"signer":"...","sig_b64":"..."}
      - Legacy list format: allowed only in DEV/SECURE_DEV (for backward compat)
    """
    strict = _is_strict_profile(profile) or profile == "SECURE_DEV"

    # Legacy list format
    if isinstance(doc, list):
        if strict:
            return False, "KEYSET_BAD_SCHEMA"
        # treat as legacy: wrap
        doc = {"version": _KEYSET_VERSION, "keys": doc}

    if not isinstance(doc, dict):
        return False, "KEYSET_BAD_SCHEMA"

    version = doc.get("version")
    if version != _KEYSET_VERSION:
        return False, "KEYSET_BAD_VERSION"

    keys = doc.get("keys")
    if not isinstance(keys, list):
        return False, "KEYSET_BAD_SCHEMA"

    if len(keys) > _MAX_KEYS:
        return False, "KEYSET_TOO_MANY_KEYS"

    # Signature verify (J.1)
    ok_sig, sig_reason = _verify_keyset_signature_if_present(doc, profile=profile)
    if not ok_sig:
        return False, sig_reason

    # Parse keys
    for entry in keys:
        if not isinstance(entry, dict):
            return False, "KEY_ENTRY_INVALID"

        pem = entry.get("pem")
        if not isinstance(pem, str) or not pem.strip():
            return False, "KEY_ENTRY_INVALID"
        if len(pem.encode("utf-8", errors="ignore")) > _MAX_KEY_PEM_BYTES:
            return False, "KEY_PEM_TOO_LARGE"

        kid = _validate_key_id_alias(str(entry.get("id") or entry.get("key_id") or ""))

        status = str(entry.get("status", "active"))
        if status not in _ALLOWED_KEY_STATUS:
            return False, "KEY_ENTRY_INVALID"

        role = str(entry.get("role", "online_signing"))
        if role not in _ALLOWED_KEY_ROLE:
            return False, "KEY_ENTRY_INVALID"

        cls = str(entry.get("classification_level", "public"))
        if cls not in _ALLOWED_CLASSIFICATION:
            return False, "KEY_ENTRY_INVALID"

        ops_raw = entry.get("allowed_operations", [])
        try:
            ops = _sanitize_ops_for_profile(ops_raw, profile=profile)
        except Exception:
            return False, "KEY_ENTRY_INVALID"

        nbf = _finite_or_none(entry.get("not_before_epoch"))
        naf = _finite_or_none(entry.get("not_after_epoch"))
        # enforce reasonable ordering if both
        if nbf is not None and naf is not None and nbf > naf:
            return False, "KEY_ENTRY_INVALID"

        # backend/algo in keyset are informational for now; build supports only software_dev + ed25519
        backend = str(entry.get("backend_type", "software_dev"))
        if backend not in _ALLOWED_BACKEND:
            return False, "KEY_ENTRY_INVALID"
        if backend != "software_dev":
            return False, "BACKEND_NOT_IMPLEMENTED"

        # load private key
        pwd = None
        # per-entry password_file/password not supported here to avoid complexity; use global.
        try:
            priv = _load_pem_private_key(pem.encode("utf-8"), password=pwd)
        except Exception:
            return False, "KEY_PEM_PARSE_FAIL"
        if not isinstance(priv, Ed25519PrivateKey):
            return False, "KEY_PEM_PARSE_FAIL"

        reg.add_or_replace_private_key(
            private_key=priv,
            key_id_alias=kid,
            status=cast(KeyStatus, status),
            role=cast(KeyRole, role),
            classification_level=cast(ClassificationLevel, cls),
            allowed_operations=ops,
            not_before_epoch=nbf,
            not_after_epoch=naf,
            backend_type="software_dev",
            profile=profile,
        )

    reg.wipe_private_for_expired()
    return True, "OK"


# ---------------------------------------------------------------------------
# Context factory + default context (reloadable)
# ---------------------------------------------------------------------------

_DEFAULT_CONTEXT: Optional[CryptoContext] = None
_CONTEXT_LOCK = threading.RLock()
_CONTEXT_REVISION = 0


def _select_profile() -> Tuple[CryptoProfile, str]:
    """
    Returns (profile, origin).
    """
    profile_str = (_env_get("TCD_CRYPTO_PROFILE") or "DEV").strip().upper()

    legacy_map: Dict[str, CryptoProfile] = {
        "NATDEF_DEV": "SECURE_DEV",
        "NATDEF_PREP": "SECURE_PREP",
        "NATDEF_PROD_CLASSIFIED_LOW": "SECURE_PROD_TIER1",
        "NATDEF_PROD_CLASSIFIED_HIGH": "SECURE_PROD_TIER2",
    }

    if profile_str in legacy_map:
        return legacy_map[profile_str], "legacy_map"
    if profile_str in _ALLOWED_PROFILES:
        return cast(CryptoProfile, profile_str), "direct"
    logger.warning("Unknown TCD_CRYPTO_PROFILE=%s, falling back to DEV", profile_str)
    return "DEV", "default"


def build_context_from_env(*, suite_registry: Optional[SuiteRegistry] = None) -> CryptoContext:
    """
    Loads profile/suite/policies/keys with strict governance and observable failures.
    """
    _require_crypto_dep()

    profile, profile_origin = _select_profile()
    _require_fips_ack_if_needed(profile)

    sr = suite_registry or _DEFAULT_SUITE_REGISTRY

    # Choose suite id: env override allowed in dev only; strict profiles pin by profile defaults.
    default_suite_by_profile: Dict[CryptoProfile, str] = {
        "DEV": "TCD-ED25519-BLAKE3-256-v1",
        "SECURE_DEV": "TCD-ED25519-SHA3-256-v1",
        "SECURE_PREP": "TCD-ED25519-SHA3-256-v1",
        "SECURE_PROD_TIER1": "TCD-ED25519-SHA3-256-v1",
        "SECURE_PROD_TIER2": "TCD-ED25519-SHA3-256-v1",
        "FIPS": "TCD-ED25519-SHA2-256-v1",
    }

    suite_id_env, used_suite_env = _env_str("TCD_CRYPTO_SUITE_ID", default_suite_by_profile[profile], max_len=_MAX_STR_SMALL)
    suite_id = suite_id_env if sr.get(suite_id_env) else default_suite_by_profile[profile]
    if used_suite_env and (_is_strict_profile(profile) or profile == "SECURE_DEV"):
        # suite override is a relaxation surface in strict
        bg = _break_glass_state(
            scope="suite_override",
            prefix="TCD_SUITE_BREAK_GLASS",
            engine_version=_CRYPTO_ENGINE_VERSION,
            max_valid_seconds=3600,
        )
        if not bg.enabled:
            raise CryptoError("suite override disallowed in strict profile without break-glass")
        _emit_audit_event("PolicyRelaxation", {"scope": bg.scope, "reason_hash": bg.reason_hash, "expires_epoch": bg.expires_epoch})

    suite = sr.get(suite_id)
    if suite is None:
        raise CryptoError("unsupported suite_id")

    # Hash policy binds profile + engine ds_version + fallback governance
    hp = suite.hash_policy(profile=profile, engine_version=_CRYPTO_ENGINE_VERSION)
    he = HashEngine(hp)

    # RNG/KDF policies
    rp = RngPolicy.for_profile(profile)
    rng = RngContext(rp)

    kp = KdfPolicy.for_profile(profile)
    kdf = KdfEngine(policy=kp, suite_id=suite_id, engine_version=_CRYPTO_ENGINE_VERSION)

    # Keys
    reg, reason = _load_key_registry(profile, suite_registry=sr)
    if reg is None:
        _emit_audit_event("KeyRegistryLoadFailed", {"profile": profile, "reason": reason})
        _m_inc("tcd_crypto_key_registry_load_total", 1, {"result": "fail", "reason": reason, "profile": profile})
        # strict: fail-fast
        if _is_strict_profile(profile) or profile == "SECURE_DEV":
            raise CryptoError(f"key registry load failed: {reason}")
        # dev: empty registry allowed (but signing will fail)
        reg = KeyRegistry()
    else:
        _emit_audit_event("KeyRegistryLoaded", {"profile": profile, "reason": "OK"})
        _m_inc("tcd_crypto_key_registry_load_total", 1, {"result": "ok", "reason": "OK", "profile": profile})

    # Domain prefix is loaded here so failures are explicit
    _ = _get_domain_prefix_bytes(profile)

    # revision
    global _CONTEXT_REVISION
    with _CONTEXT_LOCK:
        _CONTEXT_REVISION += 1
        rev = _CONTEXT_REVISION

    ctx = CryptoContext(
        profile=profile,
        suite_id=suite_id,
        hash_engine=he,
        kdf_engine=kdf,
        rng_context=rng,
        key_registry=reg,
        suite_registry=sr,
        loaded_at_epoch=time.time(),
        revision=rev,
        profile_origin=profile_origin,
    )

    _emit_audit_event(
        "ContextReloaded",
        {
            "engine_version": _CRYPTO_ENGINE_VERSION,
            "profile": ctx.profile,
            "profile_origin": ctx.profile_origin,
            "suite_id": ctx.suite_id,
            "ds_version": ctx.hash_engine.policy.ds_version,
            "policy_digest_hex": ctx.policy_digest_hex()[:16],
            "key_registry_digest_hex": ctx.key_registry.key_registry_digest_hex()[:16],
        },
    )

    return ctx


def get_default_context() -> CryptoContext:
    global _DEFAULT_CONTEXT
    if _DEFAULT_CONTEXT is not None:
        return _DEFAULT_CONTEXT
    with _CONTEXT_LOCK:
        if _DEFAULT_CONTEXT is None:
            _DEFAULT_CONTEXT = build_context_from_env()
    return _DEFAULT_CONTEXT


def reload_default_context_from_env() -> CryptoContext:
    global _DEFAULT_CONTEXT
    with _CONTEXT_LOCK:
        _DEFAULT_CONTEXT = build_context_from_env()
        return _DEFAULT_CONTEXT


# ---------------------------------------------------------------------------
# Convenience top-level APIs (kept)
# ---------------------------------------------------------------------------

def sign_blob(
    blob: bytes,
    *,
    label: HashLabel = "receipt",
    operation: str = "sign_receipt",
    attestation: Optional[AttestationContext] = None,
) -> Tuple[bytes, str, str, str]:
    """
    Tuple API; strict profiles may reject unless break-glass (M.1).
    """
    ctx = get_default_context()
    return ctx.sign_blob(blob, label=label, operation=operation, attestation=attestation)


def sign_envelope(
    blob: bytes,
    *,
    label: HashLabel = "receipt",
    operation: str = "sign_receipt",
    attestation: Optional[AttestationContext] = None,
    message_version: MessageVersion = "v3",
) -> SignatureEnvelope:
    ctx = get_default_context()
    return ctx.sign_envelope(blob, label=label, operation=operation, attestation=attestation, message_version=message_version)


def verify_blob(
    blob: bytes,
    signature: bytes,
    public_key_pem: str,
    *,
    label: HashLabel = "receipt",
    attestation: Optional[AttestationContext] = None,
) -> bool:
    ctx = get_default_context()
    return ctx.verify_blob(blob, signature, public_key_pem, label=label, attestation=attestation)


def verify_envelope(
    blob: bytes,
    env: SignatureEnvelope,
    public_key_pem: str,
) -> bool:
    ctx = get_default_context()
    return ctx.verify_envelope(blob, env, public_key_pem)


class Blake3Hash:
    """
    Backwards-compatible facade name.
    Hash/MAC semantics are governed by profile+suite+engine_version.
    """

    @staticmethod
    def digest(data: bytes, *, label: HashLabel = "generic") -> str:
        ctx = get_default_context()
        return ctx.hash_engine.digest_hex(data, label=label)

    @staticmethod
    def mac(key: bytes, data: bytes, *, label: HashLabel = "hmac") -> str:
        ctx = get_default_context()
        return ctx.hash_engine.mac_hex(key, data, label=label)

    @staticmethod
    def verify_mac(key: bytes, data: bytes, mac: Union[str, bytes], *, label: HashLabel = "hmac") -> bool:
        ctx = get_default_context()
        return ctx.hash_engine.verify_mac(key, data, mac, label=label)

    @staticmethod
    def hmac(key: bytes, data: bytes, *, label: HashLabel = "hmac") -> str:
        # compatibility alias; may be disallowed in strict profiles unless break-glass
        ctx = get_default_context()
        return ctx.hash_engine.hmac(key, data, label=label)

    @staticmethod
    def chain(prev_hex: Optional[str], chunk: bytes, *, label: HashLabel = "chain") -> str:
        ctx = get_default_context()
        return ctx.hash_engine.chain_hex(prev_hex, chunk, label=label)