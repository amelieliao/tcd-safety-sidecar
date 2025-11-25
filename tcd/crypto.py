from __future__ import annotations

import binascii
import hashlib
import hmac
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Literal, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

try:
    import blake3  # type: ignore[import]
except Exception:
    blake3 = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Type definitions
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
    "BLAKE2B_MAC",
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

_ALLOWED_HASH_LABELS = {
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

HASH_DOMAIN_PREFIX = os.getenv("TCD_HASH_DOMAIN_PREFIX", "tcd:v1:").encode("utf-8")


class CryptoError(Exception):
    """Base crypto error for TCD."""


def _validate_label(label: str) -> None:
    if label not in _ALLOWED_HASH_LABELS:
        raise CryptoError(f"Unsupported hash label: {label}")
    if any(ch.isspace() for ch in label):
        raise CryptoError("Hash label must not contain whitespace")
    if ":" in label:
        raise CryptoError("Hash label must not contain ':'")


def _domain_tag(label: str) -> bytes:
    _validate_label(label)
    return HASH_DOMAIN_PREFIX + label.encode("utf-8")


# ---------------------------------------------------------------------------
# Hashing / MAC policy and engine
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HashPolicy:
    profile: CryptoProfile
    hash_algo: HashAlgo
    mac_algo: Optional[MacAlgo]
    digest_size: int = 32
    reject_on_fallback: bool = True

    @classmethod
    def for_profile(cls, profile: CryptoProfile) -> "HashPolicy":
        if profile == "FIPS":
            return cls(
                profile=profile,
                hash_algo="SHA2_256",
                mac_algo="HMAC_SHA2_256",
                digest_size=32,
                reject_on_fallback=True,
            )
        if profile in ("SECURE_PREP", "SECURE_PROD_TIER1", "SECURE_PROD_TIER2"):
            return cls(
                profile=profile,
                hash_algo="SHA3_256",
                mac_algo="HMAC_SHA2_256",
                digest_size=32,
                reject_on_fallback=True,
            )
        # DEV / SECURE_DEV default
        return cls(
            profile=profile,
            hash_algo="BLAKE3_256" if blake3 is not None else "BLAKE2B_256",
            mac_algo="BLAKE2B_MAC",
            digest_size=32,
            reject_on_fallback=False,
        )


class HashEngine:
    def __init__(self, policy: HashPolicy) -> None:
        self._policy = policy

    @property
    def policy(self) -> HashPolicy:
        return self._policy

    def _hash_bytes(self, payload: bytes) -> bytes:
        algo = self._policy.hash_algo

        if algo == "BLAKE3_256":
            if blake3 is not None:
                return blake3.blake3(payload).digest()
            if self._policy.reject_on_fallback:
                raise CryptoError("BLAKE3_256 requested but blake3 is not available")
            logger.warning("Falling back from BLAKE3_256 to BLAKE2B_256")
            algo = "BLAKE2B_256"

        if algo == "BLAKE2B_256":
            h = hashlib.blake2b(payload, digest_size=self._policy.digest_size)
            return h.digest()
        if algo == "SHA2_256":
            return hashlib.sha256(payload).digest()
        if algo == "SHA2_512":
            return hashlib.sha512(payload).digest()
        if algo == "SHA3_256":
            return hashlib.sha3_256(payload).digest()

        raise CryptoError(f"Unsupported hash algorithm: {algo}")

    def digest(self, data: bytes, *, label: HashLabel = "generic") -> str:
        tag = _domain_tag(label)
        payload = tag + data
        return binascii.hexlify(self._hash_bytes(payload)).decode("ascii")

    def hmac(self, key: bytes, data: bytes, *, label: HashLabel = "hmac") -> str:
        if self._policy.mac_algo is None:
            raise CryptoError("MAC algorithm not configured in HashPolicy")

        tag = _domain_tag(label)
        payload = tag + data

        algo = self._policy.mac_algo
        if algo == "BLAKE2B_MAC":
            mac = hmac.new(key, payload, hashlib.blake2b)
        elif algo == "HMAC_SHA2_256":
            mac = hmac.new(key, payload, hashlib.sha256)
        elif algo == "HMAC_SHA2_512":
            mac = hmac.new(key, payload, hashlib.sha512)
        else:
            raise CryptoError(f"Unsupported MAC algorithm: {algo}")

        return mac.hexdigest()

    def chain(self, prev_hex: Optional[str], chunk: bytes, *, label: HashLabel = "chain") -> str:
        tag = _domain_tag(label)
        parts = [tag]
        if prev_hex:
            parts.append(binascii.unhexlify(prev_hex))
        parts.append(chunk)
        return binascii.hexlify(self._hash_bytes(b"".join(parts))).decode("ascii")


# ---------------------------------------------------------------------------
# RNG and KDF
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RngPolicy:
    profile: CryptoProfile
    backend: Literal["os_urandom", "hsm", "kms_drbg"]
    require_certified: bool = False

    @classmethod
    def for_profile(cls, profile: CryptoProfile) -> "RngPolicy":
        if profile in ("SECURE_PROD_TIER1", "SECURE_PROD_TIER2"):
            return cls(profile=profile, backend="os_urandom", require_certified=True)
        return cls(profile=profile, backend="os_urandom", require_certified=False)


class RngContext:
    def __init__(self, policy: RngPolicy) -> None:
        self._policy = policy

    def random_bytes(self, n: int) -> bytes:
        if self._policy.backend == "os_urandom":
            return os.urandom(n)
        # HSM / KMS_DRBG backends should be wired via adapters in production
        raise CryptoError(f"RNG backend {self._policy.backend} not implemented in this build")


from cryptography.hazmat.backends import default_backend  # type: ignore[import]
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # type: ignore[import]
from cryptography.hazmat.primitives import hashes  # type: ignore[import]


class KdfEngine:
    """
    KDF for session / ephemeral keys only.

    Long-lived key generation for high-security profiles should be handled
    by external key management (such as HSM/KMS) and not through this module.
    """

    def __init__(self, hash_engine: HashEngine) -> None:
        self._hash_engine = hash_engine

    def derive_key(
        self,
        ikm: bytes,
        *,
        label: HashLabel = "kdf",
        length: int = 32,
        salt: Optional[bytes] = None,
    ) -> bytes:
        tag = _domain_tag(label)
        info = tag
        algo = self._hash_engine.policy.hash_algo
        if algo in ("SHA2_256", "BLAKE2B_256", "BLAKE3_256"):
            hkdf_hash = hashes.SHA256()
        elif algo in ("SHA2_512", "SHA3_256"):
            hkdf_hash = hashes.SHA512()
        else:
            hkdf_hash = hashes.SHA256()
        hkdf = HKDF(
            algorithm=hkdf_hash,
            length=length,
            salt=salt,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(ikm)


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttestationContext:
    measurement_hash: Optional[bytes] = None
    attestation_report: Optional[bytes] = None

    def measurement_or_empty(self) -> bytes:
        return self.measurement_hash or b""


# ---------------------------------------------------------------------------
# Audit sink
# ---------------------------------------------------------------------------

class CryptoAuditSink:
    """Hook for structured audit events emitted by the crypto control plane."""

    def emit(self, event_type: str, metadata: Dict[str, Any]) -> None:
        raise NotImplementedError


_AUDIT_SINK: Optional[CryptoAuditSink] = None
_AUDIT_LOCK = threading.Lock()


def register_crypto_audit_sink(sink: CryptoAuditSink) -> None:
    """
    Register a global audit sink.

    In production this should forward to an external audit or telemetry system.
    This module never logs payload contents.
    """
    global _AUDIT_SINK
    with _AUDIT_LOCK:
        _AUDIT_SINK = sink


def _emit_audit_event(event_type: str, metadata: Dict[str, Any]) -> None:
    sink = _AUDIT_SINK
    if sink is None:
        return
    try:
        sink.emit(event_type, metadata)
    except Exception:
        logger.exception("CryptoAuditSink.emit failed")


# ---------------------------------------------------------------------------
# Signing backends and key handles
# ---------------------------------------------------------------------------

from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore[import]
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization  # type: ignore[import]


@dataclass
class SigningKeyHandle:
    """
    Abstract handle for a signing key, including role and usage metadata.

    For now only ED25519 with a software_dev backend is implemented here.
    HSM / KMS integration should be wired via backend_type-specific adapters.
    """

    key_id: str
    algo: SignAlgo
    backend_type: KeyBackendType
    status: KeyStatus
    role: KeyRole
    classification_level: ClassificationLevel
    allowed_operations: Sequence[str] = field(default_factory=tuple)
    meta: Dict[str, Any] = field(default_factory=dict)
    _private_key: Optional[Ed25519PrivateKey] = field(default=None, repr=False)

    def _ensure_signable(self, operation: str, profile: CryptoProfile) -> None:
        if self.status not in ("active", "retiring"):
            raise CryptoError(f"Key {self.key_id} is not signable in status={self.status}")
        if operation not in self.allowed_operations:
            raise CryptoError(f"Operation {operation} not allowed for key_id={self.key_id}")
        if profile.startswith("SECURE_") and self.backend_type == "software_dev":
            raise CryptoError(f"Software key backend not allowed for profile={profile}")

    def sign(self, message: bytes, *, operation: str, profile: CryptoProfile) -> bytes:
        self._ensure_signable(operation, profile)
        if self.algo == "ED25519":
            if self._private_key is None:
                raise CryptoError(f"Missing private key for key_id={self.key_id}")
            return self._private_key.sign(message)
        raise CryptoError(f"Signing algorithm {self.algo} not implemented in this build")

    def public_key_pem(self) -> str:
        if self.algo != "ED25519":
            raise CryptoError(f"Public key export not implemented for algo={self.algo}")
        if self._private_key is None:
            raise CryptoError("Private key not loaded; cannot derive public key")
        pub = self._private_key.public_key()
        pem_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("utf-8")

    def wipe_private(self) -> None:
        self._private_key = None


def _fingerprint_public_key(pub: Ed25519PublicKey, hash_engine: HashEngine) -> str:
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hash_engine.digest(pub_bytes, label="pubkey")
    # Short fingerprint is usually enough for key_id defaults
    return fp[:16]


def _load_software_ed25519_from_pem(
    pem: bytes,
    password: Optional[bytes],
    *,
    hash_engine: HashEngine,
    key_id: Optional[str],
    status: KeyStatus,
    role: KeyRole,
    classification_level: ClassificationLevel,
    allowed_operations: Sequence[str],
) -> SigningKeyHandle:
    try:
        priv = serialization.load_pem_private_key(pem, password=password, backend=default_backend())
    except Exception as e:
        raise CryptoError(f"Failed to load Ed25519 private key: {e}") from e
    if not isinstance(priv, Ed25519PrivateKey):
        raise CryptoError("Provided private key is not Ed25519")

    pub = priv.public_key()
    kid = key_id or _fingerprint_public_key(pub, hash_engine)
    return SigningKeyHandle(
        key_id=kid,
        algo="ED25519",
        backend_type="software_dev",
        status=status,
        role=role,
        classification_level=classification_level,
        allowed_operations=tuple(allowed_operations),
        _private_key=priv,
    )


# ---------------------------------------------------------------------------
# Key registry
# ---------------------------------------------------------------------------

class KeyRegistry:
    """
    In-memory registry of signing keys with roles and usage constraints.
    """

    def __init__(self, keys: Optional[Iterable[SigningKeyHandle]] = None) -> None:
        self._lock = threading.RLock()
        self._keys: Dict[str, SigningKeyHandle] = {}
        if keys:
            for k in keys:
                self._keys[k.key_id] = k

    def _snapshot(self) -> Dict[str, SigningKeyHandle]:
        with self._lock:
            return dict(self._keys)

    def add_or_replace(self, key: SigningKeyHandle) -> None:
        with self._lock:
            self._keys[key.key_id] = key
        _emit_audit_event(
            "KeyRegistered",
            {
                "key_id": key.key_id,
                "algo": key.algo,
                "backend_type": key.backend_type,
                "status": key.status,
                "role": key.role,
                "classification_level": key.classification_level,
            },
        )

    def set_status(self, key_id: str, status: KeyStatus) -> None:
        with self._lock:
            if key_id not in self._keys:
                raise CryptoError(f"Unknown key_id={key_id}")
            self._keys[key_id].status = status
        _emit_audit_event(
            "KeyStatusChanged",
            {
                "key_id": key_id,
                "status": status,
            },
        )

    def get(self, key_id: str) -> Optional[SigningKeyHandle]:
        with self._lock:
            return self._keys.get(key_id)

    def select_signing_key(
        self,
        *,
        operation: str,
        required_role: Optional[KeyRole],
        profile: CryptoProfile,
    ) -> SigningKeyHandle:
        snapshot = self._snapshot()
        candidates: list[SigningKeyHandle] = []
        for key in snapshot.values():
            if key.status not in ("active", "retiring"):
                continue
            if operation not in key.allowed_operations:
                continue
            if required_role is not None and key.role != required_role:
                continue
            if profile.startswith("SECURE_") and key.backend_type == "software_dev":
                continue
            candidates.append(key)

        if not candidates:
            raise CryptoError(f"No usable signing key for operation={operation} profile={profile}")

        for k in candidates:
            if k.status == "active":
                return k
        return candidates[0]

    def public_keys(self) -> Dict[str, str]:
        snapshot = self._snapshot()
        result: Dict[str, str] = {}
        for kid, key in snapshot.items():
            try:
                result[kid] = key.public_key_pem()
            except CryptoError:
                continue
        return result

    def wipe_expired_keys(self) -> None:
        removed: list[str] = []
        with self._lock:
            for kid, key in list(self._keys.items()):
                if key.status == "expired":
                    key.wipe_private()
                    removed.append(kid)
                    del self._keys[kid]
        for kid in removed:
            _emit_audit_event("KeyWiped", {"key_id": kid})


# ---------------------------------------------------------------------------
# Signature suite
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SignatureSuite:
    """
    Suite describing hash/MAC/signature algorithms and hybrid/PQ requirements.
    """

    suite_id: str
    profile: CryptoProfile
    hash_policy: HashPolicy
    sign_algos: Tuple[SignAlgo, ...]
    require_all_signatures: bool = True
    require_pq_component: bool = False

    @classmethod
    def default_for_profile(cls, profile: CryptoProfile) -> "SignatureSuite":
        hash_policy = HashPolicy.for_profile(profile)
        if profile == "FIPS":
            return cls(
                suite_id="TCD-ED25519-SHA2-256-v1",
                profile=profile,
                hash_policy=hash_policy,
                sign_algos=("ED25519",),
                require_all_signatures=True,
                require_pq_component=False,
            )
        if profile in ("SECURE_PREP", "SECURE_PROD_TIER1"):
            return cls(
                suite_id="TCD-ED25519-SHA3-256-v1",
                profile=profile,
                hash_policy=hash_policy,
                sign_algos=("ED25519",),
                require_all_signatures=True,
                require_pq_component=False,
            )
        if profile == "SECURE_PROD_TIER2":
            # PQ/hybrid reserved; for now still ED25519 + SHA3
            return cls(
                suite_id="TCD-ED25519-SHA3-256-v1",
                profile=profile,
                hash_policy=hash_policy,
                sign_algos=("ED25519",),
                require_all_signatures=True,
                require_pq_component=False,
            )
        # DEV / SECURE_DEV default
        return cls(
            suite_id="TCD-ED25519-BLAKE3-256-v1",
            profile=profile,
            hash_policy=hash_policy,
            sign_algos=("ED25519",),
            require_all_signatures=True,
            require_pq_component=False,
        )


# ---------------------------------------------------------------------------
# Crypto context
# ---------------------------------------------------------------------------

@dataclass
class CryptoContext:
    """
    High-level crypto control plane: profile + suite + keys + RNG/KDF + attestation.
    """

    profile: CryptoProfile
    suite: SignatureSuite
    hash_engine: HashEngine
    key_registry: KeyRegistry
    rng_context: RngContext
    kdf_engine: KdfEngine
    attestation_context: Optional[AttestationContext] = None

    @classmethod
    def from_env(cls) -> "CryptoContext":
        profile_str = os.getenv("TCD_CRYPTO_PROFILE", "DEV").strip().upper()

        # Backward compatibility: map legacy profile names onto the new ones.
        legacy_map: Dict[str, CryptoProfile] = {
            "NATDEF_DEV": "SECURE_DEV",
            "NATDEF_PREP": "SECURE_PREP",
            "NATDEF_PROD_CLASSIFIED_LOW": "SECURE_PROD_TIER1",
            "NATDEF_PROD_CLASSIFIED_HIGH": "SECURE_PROD_TIER2",
        }

        allowed: Tuple[CryptoProfile, ...] = (
            "DEV",
            "FIPS",
            "SECURE_DEV",
            "SECURE_PREP",
            "SECURE_PROD_TIER1",
            "SECURE_PROD_TIER2",
        )

        if profile_str in legacy_map:
            profile: CryptoProfile = legacy_map[profile_str]
        elif profile_str in allowed:
            profile = profile_str  # type: ignore[assignment]
        else:
            logger.warning("Unknown TCD_CRYPTO_PROFILE=%s, falling back to DEV", profile_str)
            profile = "DEV"

        suite = SignatureSuite.default_for_profile(profile)
        hash_engine = HashEngine(suite.hash_policy)
        rng_policy = RngPolicy.for_profile(profile)
        rng_context = RngContext(rng_policy)
        kdf_engine = KdfEngine(hash_engine)

        key_registry = _load_key_registry_from_env(hash_engine=hash_engine, profile=profile)

        ctx = cls(
            profile=profile,
            suite=suite,
            hash_engine=hash_engine,
            key_registry=key_registry,
            rng_context=rng_context,
            kdf_engine=kdf_engine,
            attestation_context=None,
        )

        _emit_audit_event(
            "ContextReloaded",
            {
                "profile": ctx.profile,
                "suite_id": ctx.suite.suite_id,
                "hash_algo": ctx.suite.hash_policy.hash_algo,
                "mac_algo": ctx.suite.hash_policy.mac_algo,
            },
        )
        return ctx

    def _build_signing_message(
        self,
        *,
        digest_hex: str,
        label: HashLabel,
        attestation: Optional[AttestationContext],
    ) -> bytes:
        measurement = attestation.measurement_or_empty() if attestation else b""
        parts = [
            b"TCD-SIGN-v1|",
            self.profile.encode("ascii"),
            b"|",
            self.suite.suite_id.encode("ascii"),
            b"|",
            label.encode("ascii"),
            b"|",
            measurement,
            b"|",
            binascii.unhexlify(digest_hex),
        ]
        return b"".join(parts)

    def sign_blob(
        self,
        blob: bytes,
        *,
        label: HashLabel = "receipt",
        operation: str = "sign_receipt",
        attestation: Optional[AttestationContext] = None,
    ) -> Tuple[bytes, str, str, str]:
        """
        Sign an arbitrary blob under the current suite and profile.

        Returns (signature_bytes, digest_hex, key_id, algo).
        """
        digest_hex = self.hash_engine.digest(blob, label=label)
        message = self._build_signing_message(
            digest_hex=digest_hex,
            label=label,
            attestation=attestation or self.attestation_context,
        )

        key = self.key_registry.select_signing_key(
            operation=operation,
            required_role="online_signing",
            profile=self.profile,
        )

        signature = key.sign(message, operation=operation, profile=self.profile)

        _emit_audit_event(
            "SignOperation",
            {
                "key_id": key.key_id,
                "algo": key.algo,
                "suite_id": self.suite.suite_id,
                "profile": self.profile,
                "label": label,
                "operation": operation,
            },
        )

        return signature, digest_hex, key.key_id, key.algo

    def verify_blob(
        self,
        blob: bytes,
        signature: bytes,
        public_key_pem: str,
        *,
        label: HashLabel = "receipt",
        attestation: Optional[AttestationContext] = None,
    ) -> bool:
        """
        Verify a signature produced by sign_blob against a public key.
        """
        digest_hex = self.hash_engine.digest(blob, label=label)
        message = self._build_signing_message(
            digest_hex=digest_hex,
            label=label,
            attestation=attestation or self.attestation_context,
        )

        try:
            pub = serialization.load_pem_public_key(public_key_pem.encode("utf-8"), backend=default_backend())
        except Exception:
            return False

        if not isinstance(pub, Ed25519PublicKey):
            return False

        try:
            pub.verify(signature, message)
            return True
        except Exception:
            return False

    def publish_public_keys(self) -> Dict[str, str]:
        """
        Export non-sensitive public key material: key_id -> PEM.
        """
        return self.key_registry.public_keys()

    def cleanup_expired_keys(self) -> None:
        """
        Wipe and drop expired keys from the registry.
        """
        self.key_registry.wipe_expired_keys()


_DEFAULT_CONTEXT: Optional[CryptoContext] = None
_CONTEXT_LOCK = threading.RLock()


def get_default_context() -> CryptoContext:
    global _DEFAULT_CONTEXT
    if _DEFAULT_CONTEXT is not None:
        return _DEFAULT_CONTEXT
    with _CONTEXT_LOCK:
        if _DEFAULT_CONTEXT is None:
            _DEFAULT_CONTEXT = CryptoContext.from_env()
    return _DEFAULT_CONTEXT


def reload_default_context_from_env() -> None:
    global _DEFAULT_CONTEXT
    with _CONTEXT_LOCK:
        _DEFAULT_CONTEXT = CryptoContext.from_env()


def _load_key_registry_from_env(
    *,
    hash_engine: HashEngine,
    profile: CryptoProfile,
) -> KeyRegistry:
    """
    Build a KeyRegistry from environment.

    Two modes:
      - TCD_ED25519_KEYSET_JSON: list of key objects:
        { "pem": "...PEM...", "id": "key-id", "status": "active", "role": "online_signing", ... }
      - TCD_ED25519_PRIVATE_KEY_PEM: single PEM; optional TCD_ED25519_KEY_ID and password.
    """
    keyset_json = os.getenv("TCD_ED25519_KEYSET_JSON")
    keys: list[SigningKeyHandle] = []

    if keyset_json:
        try:
            raw = json.loads(keyset_json)
        except Exception as e:
            raise CryptoError(f"Failed to parse TCD_ED25519_KEYSET_JSON: {e}") from e
        if not isinstance(raw, list):
            raise CryptoError("TCD_ED25519_KEYSET_JSON must be a list of key objects")

        for entry in raw:
            if not isinstance(entry, dict):
                raise CryptoError("Each key entry in keyset JSON must be an object")
            pem = entry.get("pem")
            kid = entry.get("id")
            status = entry.get("status", "active")
            role = entry.get("role", "online_signing")
            classification = entry.get("classification_level", "public")
            allowed_operations = entry.get("allowed_operations", ["sign_receipt"])
            if not pem or not kid:
                raise CryptoError("Each key entry must include 'pem' and 'id'")
            if status not in ("active", "retiring", "expired"):
                raise CryptoError(f"Invalid key status={status} for key_id={kid}")
            handle = _load_software_ed25519_from_pem(
                pem=pem.encode("utf-8"),
                password=None,
                hash_engine=hash_engine,
                key_id=kid,
                status=status,  # type: ignore[arg-type]
                role=role,  # type: ignore[arg-type]
                classification_level=classification,  # type: ignore[arg-type]
                allowed_operations=allowed_operations,
            )
            keys.append(handle)
        registry = KeyRegistry(keys)
    else:
        pem_str = os.getenv("TCD_ED25519_PRIVATE_KEY_PEM")
        if not pem_str:
            raise CryptoError(
                "Missing Ed25519 private key PEM. "
                "Configure TCD_ED25519_KEYSET_JSON or TCD_ED25519_PRIVATE_KEY_PEM."
            )
        password = os.getenv("TCD_ED25519_PRIVATE_KEY_PASSWORD")
        key_id_override = os.getenv("TCD_ED25519_KEY_ID")
        handle = _load_software_ed25519_from_pem(
            pem=pem_str.encode("utf-8"),
            password=password.encode("utf-8") if password else None,
            hash_engine=hash_engine,
            key_id=key_id_override.strip() if key_id_override else None,
            status="active",
            role="online_signing",
            classification_level="public",
            allowed_operations=("sign_receipt", "sign_ledger", "sign_config"),
        )
        registry = KeyRegistry([handle])

    registry.wipe_expired_keys()
    return registry


# ---------------------------------------------------------------------------
# Convenience top-level helpers
# ---------------------------------------------------------------------------

def sign_blob(
    blob: bytes,
    *,
    label: HashLabel = "receipt",
    operation: str = "sign_receipt",
    attestation: Optional[AttestationContext] = None,
) -> Tuple[bytes, str, str, str]:
    """
    Convenience wrapper around the default CryptoContext.sign_blob.
    """
    ctx = get_default_context()
    return ctx.sign_blob(blob, label=label, operation=operation, attestation=attestation)


def verify_blob(
    blob: bytes,
    signature: bytes,
    public_key_pem: str,
    *,
    label: HashLabel = "receipt",
    attestation: Optional[AttestationContext] = None,
) -> bool:
    """
    Convenience wrapper around the default CryptoContext.verify_blob.
    """
    ctx = get_default_context()
    return ctx.verify_blob(blob, signature, public_key_pem, label=label, attestation=attestation)


class Blake3Hash:
    """
    Backwards-compatible hashing facade over the configured HashEngine.

    Name is kept for historical reasons; the underlying algorithm is driven
    by HashPolicy and may be BLAKE3, BLAKE2b, SHA2, or SHA3.
    """

    @staticmethod
    def digest(data: bytes, *, label: HashLabel = "generic") -> str:
        ctx = get_default_context()
        return ctx.hash_engine.digest(data, label=label)

    @staticmethod
    def hmac(key: bytes, data: bytes, *, label: HashLabel = "hmac") -> str:
        ctx = get_default_context()
        return ctx.hash_engine.hmac(key, data, label=label)

    @staticmethod
    def chain(prev_hex: Optional[str], chunk: bytes, *, label: HashLabel = "chain") -> str:
        ctx = get_default_context()
        return ctx.hash_engine.chain(prev_hex, chunk, label=label)