






 

    "SHA2_512",
    "SHA3_256",
]

MacAlgo = Literal[
    "HMAC_SHA2_256",
    "HMAC_SHA2_512",
    "BLAKE2B_MAC",  # keyed blake2b (NOT HMAC(blake2b))
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

# ---------------------------------------------------------------------------
# Engine identity / hardening constants
# ---------------------------------------------------------------------------

_CRYPTO_ENGINE_VERSION = "crypto_v3"

_DEFAULT_DOMAIN_PREFIX = "tcd:v1:"
_MAX_DOMAIN_PREFIX_LEN = 64

# hex parsing bounds
_MAX_HEX_INPUT_CHARS = 4096  # prevents giant prev_hex strings DoS
_MAX_CHAIN_CHUNK_BYTES = 8_000_000  # defensive; adjust via env if needed

# env size bounds
_MAX_ENV_JSON_BYTES = 2_000_000
_MAX_ENV_PEM_BYTES = 200_000

# keyset file bounds
_MAX_KEY_FILE_BYTES = 2_000_000

# RNG bounds
_MAX_RNG_BYTES_PER_CALL = 4_000_000

# signing message constraints
_MAX_MEASUREMENT_BYTES = 256  # measurement_hash is expected to be small digest

# operation/key_id hygiene
_OP_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

_ALLOWED_KEY_STATUS = {"active", "retiring", "expired"}
_ALLOWED_KEY_ROLE = {"root_ca", "intermediate_ca", "online_signing", "audit_only"}
_ALLOWED_CLASSIFICATION = {"public", "internal", "confidential", "restricted"}
_ALLOWED_BACKEND = {"software_dev", "hsm", "kms"}

d-crash module import)
# 

_HAS_CRYPTOGRAPHY = False
try:
    from cryptography.hazmat.primitives import serialization  # type: ignore[import]
    from cryptography.hazmat.primitives import hashes  # type: ignore[import]
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # type: ignore[import]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # type: ignore[import]
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    _HAS_CRYPTOGRAPHY = True
except Exception:  # pragma: no cover
    serialization = None  # type: ignore[assignment]
    hashes = None  # type: ignore[assignment]
    HKDF = None  # type: ignore[assignment]
    Ed25519PrivateKey = object  # type: ignore[assignment]
    Ed25519PublicKey = object  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class CryptoError(Exception):
    """Base crypto error for TCD."""


# ---------------------------------------------------------------------------
# Domain prefix + label handling
# ---------------------------------------------------------------------------

_DOMAIN_LOCK = threading.Lock()
_DOMAIN_PREFIX_BYTES: Optional[bytes] = None

_PREFIX_ALLOWED_RE = re.compile(r"^[A-Za-z0-9:._\-]{1,64}$")


def _get_domain_prefix() -> bytes:
    """
    Lazily load and sanitize TCD_HASH_DOMAIN_PREFIX.
    This avoids import-time surprises and caps resource impact.
    """
    global _DOMAIN_PREFIX_BYTES
    if _DOMAIN_PREFIX_BYTES is not None:
        return _DOMAIN_PREFIX_BYTES
    with _DOMAIN_LOCK:
        if _DOMAIN_PREFIX_BYTES is not None:
            return _DOMAIN_PREFIX_BYTES
        raw = os.getenv("TCD_HASH_DOMAIN_PREFIX", _DEFAULT_DOMAIN_PREFIX)
        s = str(raw).strip()
        if len(s) > _MAX_DOMAIN_PREFIX_LEN:
            s = s[:_MAX_DOMAIN_PREFIX_LEN]
        if not _PREFIX_ALLOWED_RE.match(s):
            s = _DEFAULT_DOMAIN_PREFIX
        # ensure it ends with ":" for readability; not required for security
        if not s.endswith(":"):
            s = s + ":"
        _DOMAIN_PREFIX_BYTES = s.encode("utf-8", errors="strict")
        return _DOMAIN_PREFIX_BYTES


def _validate_label(label: str) -> None:
    if label not in _ALLOWED_HASH_LABELS:
        raise CryptoError(f"Unsupported hash label: {label}")
    if any(ch.isspace() for ch in label):
        raise CryptoError("Hash label must not contain whitespace")
    if ":" in label:
        raise CryptoError("Hash label must not contain ':'")


def _domain_tag(label: str) -> bytes:
    _validate_label(label)
    return _get_domain_prefix() + label.encode("utf-8")



_HEX_RE = re.compile(r"^[0-9a-fA-F]*$")


def _hex_to_bytes(
    s: str,
    *,
    expected_len: Optional[int] = None,
    max_input_chars: int = _MAX_HEX_INPUT_CHARS,
) -> bytes:
    """
    Hardened hex parser:
      - supports 0x/0X prefix
      - odd length is left-padded with '0'
      - max input length to avoid DoS
      - optional expected_len check
    """
    if s is None:
        raise CryptoError("hex input is None")
    t = str(s).strip()
    if len(t) > max_input_chars:
        raise CryptoError("hex input too long")
    if t.startswith(("0x", "0X")):
        t = t[2:]
    if t == "":
        return b""
    if not _HEX_RE.match(t):
        raise CryptoError("invalid hex characters")
    if len(t) % 2 == 1:
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



@dataclass(frozen=True)
class HashPolicy:
    profile: CryptoProfile
    hash_algo: HashAlgo
    mac_algo: Optional[MacAlgo]
    digest_size: int = 32  # used for blake2b digest + keyed blake2b MAC
    reject_on_fallback: bool = True

    def __post_init__(self) -> None:
        # digest_size sanity
        ds = int(self.digest_size)
        if ds < 16:
            ds = 16
        if ds > 64:
            ds = 64

        # enforce fixed-size semantics for *_256 algos
        if self.hash_algo in ("BLAKE3_256", "BLAKE2B_256", "SHA2_256", "SHA3_256"):
            ds = 32
        elif self.hash_algo == "SHA2_512":
            # output is always 64 for sha512 digest()
            ds = 64

        object.__setattr__(self, "digest_size", ds)

        # DEV profile should not be reject-on-fallback by default
        if self.profile == "DEV" and self.reject_on_fallback:
            object.__setattr__(self, "reject_on_fallback", False)

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

    def output_size_bytes(self) -> int:
        # hash output size (bytes)
        if self.hash_algo == "SHA2_512":
            return 64
        return 32


class HashEngine:
    def __init__(self, policy: HashPolicy) -> None:
        self._policy = policy

    @property
    def policy(self) -> HashPolicy:
        return self._policy

    def _new_hasher(self, algo: HashAlgo):
        if algo == "BLAKE3_256":
            if blake3 is None:
                if self._policy.reject_on_fallback:
                    raise CryptoError("BLAKE3_256 requested but blake3 is not available")
                logger.warning("Falling back from BLAKE3_256 to BLAKE2B_256")
                algo = "BLAKE2B_256"
            else:
                return blake3.blake3()

        if algo == "BLAKE2B_256":
            return hashlib.blake2b(digest_size=32)
        if algo == "SHA2_256":
            return hashlib.sha256()
        if algo == "SHA2_512":
            return hashlib.sha512()
        if algo == "SHA3_256":
            return hashlib.sha3_256()

        raise CryptoError(f"Unsupported hash algorithm: {algo}")

    def _hash_parts(self, parts: Iterable[bytes]) -> bytes:
        h = self._new_hasher(self._policy.hash_algo)
        for p in parts:
            if p:
                h.update(p)
        # blake3 has digest() (possibly supports length); hashlib has digest()
        out_len = self._policy.output_size_bytes()
        try:
            # type: ignore[attr-defined]
            return h.digest(out_len)
        except TypeError:
            return h.digest()

    def digest_bytes(self, data: bytes, *, label: HashLabel = "generic") -> bytes:
        """
        Returns raw digest bytes. Streaming-safe (no tag+data concatenation).
        Digest bytes correspond to hashing tag||data (v1 semantics) for compatibility.
        """
        tag = _domain_tag(label)
        return self._hash_parts((tag, data))

    def digest(self, data: bytes, *, label: HashLabel = "generic") -> str:
        return _bytes_to_hex(self.digest_bytes(data, label=label))

    def _normalize_blake2b_key(self, key: bytes) -> bytes:
        """
        keyed blake2b requires key length <= 64 bytes.
        In strict profiles we reject oversize keys; in dev we hash it down.
        """
        if len(key) <= 64:
            return key
        strict = self._policy.profile in ("FIPS", "SECURE_PREP", "SECURE_PROD_TIER1", "SECURE_PROD_TIER2")
        if strict:
            raise CryptoError("BLAKE2B_MAC key too long (>64) in strict profile")
        # dev: hash down to 64
        return hashlib.blake2b(key, digest_size=64).digest()

    def hmac(self, key: bytes, data: bytes, *, label: HashLabel = "hmac") -> str:
        """
        Returns MAC hex.

        Semantics:
          - tag||data domain separation
          - MAC algorithm determined by policy.mac_algo
        """
        if self._policy.mac_algo is None:
            raise CryptoError("MAC algorithm not configured in HashPolicy")

        if not isinstance(key, (bytes, bytearray)):
            raise CryptoError("MAC key must be bytes")
        k = bytes(key)
        if len(k) == 0 and self._policy.profile in ("FIPS", "SECURE_PREP", "SECURE_PROD_TIER1", "SECURE_PROD_TIER2"):
            raise CryptoError("Empty MAC key not allowed in strict profile")

        tag = _domain_tag(label)
        algo = self._policy.mac_algo

        if algo == "BLAKE2B_MAC":
            k2 = self._normalize_blake2b_key(k)
            mac = hashlib.blake2b(digest_size=32, key=k2)
            mac.update(tag)
            mac.update(data)
            return mac.hexdigest()

        if algo == "HMAC_SHA2_256":
            hm = hmac.new(k, digestmod=hashlib.sha256)
            hm.update(tag)
            hm.update(data)
            return hm.hexdigest()

        if algo == "HMAC_SHA2_512":
            hm = hmac.new(k, digestmod=hashlib.sha512)
            hm.update(tag)
            hm.update(data)
            return hm.hexdigest()

        raise CryptoError(f"Unsupported MAC algorithm: {algo}")

    def chain(self, prev_hex: Optional[str], chunk: bytes, *, label: HashLabel = "chain") -> str:
        """
        Chain hash:
          H(tag || prev_digest_bytes || chunk)
        """
        if not isinstance(chunk, (bytes, bytearray)):
            raise CryptoError("chunk must be bytes")
        if len(chunk) > int(os.getenv("TCD_CHAIN_MAX_CHUNK_BYTES", str(_MAX_CHAIN_CHUNK_BYTES))):
            raise CryptoError("chunk too large")

        tag = _domain_tag(label)
        prev_b = b""
        if prev_hex:
            prev_b = _hex_to_bytes(prev_hex, expected_len=self._policy.output_size_bytes())

        out = self._hash_parts((tag, prev_b, bytes(chunk)))
        return _bytes_to_hex(out)




@dataclass(frozen=True)
class RngPolicy:
    profile: CryptoProfile
    backend: Literal["os_urandom", "hsm", "kms_drbg"]
    require_certified: bool = False
    max_bytes_per_call: int = _MAX_RNG_BYTES_PER_CALL

    @classmethod
    def for_profile(cls, profile: CryptoProfile) -> "RngPolicy":
        # In real secure deployments, hsm/kms_drbg should be used; os_urandom certification is environment-dependent.
        if profile in ("SECURE_PROD_TIER1", "SECURE_PROD_TIER2", "FIPS"):
            return cls(profile=profile, backend="os_urandom", require_certified=True)
        return cls(profile=profile, backend="os_urandom", require_certified=False)


def _rng_cert_ack_ok() -> bool:
    """
    Operator ack for cases where require_certified=True but backend is os_urandom in this build.
    """
    ack = os.getenv("TCD_RNG_CERTIFIED_ACK", "").strip()
    return ack == f"I_UNDERSTAND_{_CRYPTO_ENGINE_VERSION}"


class RngContext:
    def __init__(self, policy: RngPolicy) -> None:
        self._policy = policy

    def random_bytes(self, n: int) -> bytes:
        try:
            nn = int(n)
        except Exception as e:
            raise CryptoError(f"RNG n invalid: {e}") from e
        if nn < 0:
            raise CryptoError("RNG n must be >= 0")
        if nn > int(self._policy.max_bytes_per_call):
            raise CryptoError("RNG request too large")

        if self._policy.require_certified and self._policy.backend == "os_urandom":
            # We cannot prove certification from inside Python; require explicit operator ack.
            if not _rng_cert_ack_ok():
                raise CryptoError("Certified RNG required but not acknowledged (set TCD_RNG_CERTIFIED_ACK)")

        if self._policy.backend == "os_urandom":
            return os.urandom(nn)

        # HSM / KMS_DRBG backends should be wired via adapters in production
        raise CryptoError(f"RNG backend {self._policy.backend} not implemented in this build")


class KdfEngine:
    """
    KDF for session / ephemeral keys only.

    Hardening:
      - cryptography dependency optional at import-time (feature-gated at runtime)
      - strict profiles can require salt + min IKM length
      - deterministic domain tag is used as HKDF info
    """

    def __init__(self, hash_engine: HashEngine) -> None:
        self._hash_engine = hash_engine

    def _require_strict(self) -> bool:
        return self._hash_engine.policy.profile in ("FIPS", "SECURE_PREP", "SECURE_PROD_TIER1", "SECURE_PROD_TIER2")

    def _select_hkdf_hash(self):
        if not _HAS_CRYPTOGRAPHY or hashes is None:
            raise CryptoError("cryptography is required for KDF but not available")

        algo = self._hash_engine.policy.hash_algo
        if algo == "SHA2_256":
            return hashes.SHA256()
        if algo == "SHA2_512":
            return hashes.SHA512()
        if algo == "SHA3_256":
            return hashes.SHA3_256()
        if algo == "BLAKE2B_256":
            return hashes.BLAKE2b(32)

        # BLAKE3 is not supported by cryptography HKDF; use SHA256 only when policy allows.
        if algo == "BLAKE3_256":
            if self._hash_engine.policy.reject_on_fallback and self._require_strict():
                raise CryptoError("BLAKE3_256 selected but HKDF cannot use BLAKE3 in strict mode")
            logger.warning("HKDF hash fallback: BLAKE3_256 -> SHA256")
            return hashes.SHA256()

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
        if not isinstance(ikm, (bytes, bytearray)):
            raise CryptoError("ikm must be bytes")
        ikm_b = bytes(ikm)

        # strict mode: require minimum entropy input length
        if self._require_strict() and len(ikm_b) < 16:
            raise CryptoError("IKM too short for strict profile (min 16 bytes)")

        try:
            L = int(length)
        except Exception:
            raise CryptoError("length must be int")
        if L <= 0 or L > 1024:
            raise CryptoError("invalid KDF length (1..1024)")

        strict = self._require_strict()
        if strict:
            if salt is None or not isinstance(salt, (bytes, bytearray)) or len(bytes(salt)) < 16:
                allow = os.getenv("TCD_KDF_ALLOW_NO_SALT", "").strip().lower() in ("1", "true", "yes", "on")
                if not allow:
                    raise CryptoError("salt required in strict profile (>=16 bytes)")

        tag = _domain_tag(label)
        info = tag
        if context:
            if not isinstance(context, (bytes, bytearray)):
                raise CryptoError("context must be bytes")
            ctx_b = bytes(context)
            if len(ctx_b) > 1024:
                raise CryptoError("context too large")
            # length-prefix to avoid ambiguity
            info = tag + b"|ctx|" + struct.pack("!I", len(ctx_b)) + ctx_b

        hkdf_hash = self._select_hkdf_hash()

        if not _HAS_CRYPTOGRAPHY or HKDF is None:
            raise CryptoError("cryptography HKDF not available")

        # cryptography API compatibility: backend arg may or may not exist in newer versions
        try:
            hkdf = HKDF(algorithm=hkdf_hash, length=L, salt=salt, info=info)  # type: ignore[call-arg]
        except TypeError:
            from cryptography.hazmat.backends import default_backend  # type: ignore[import]
            hkdf = HKDF(algorithm=hkdf_hash, length=L, salt=salt, info=info, backend=default_backend())

        return hkdf.derive(ikm_b)


# ---------------------------------------------------------------------------
# Attestation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttestationContext:
    measurement_hash: Optional[bytes] = None
    attestation_report: Optional[bytes] = None  # not embedded into signing message

    def measurement_or_empty(self) -> bytes:
        mh = self.measurement_hash or b""
        if len(mh) > _MAX_MEASUREMENT_BYTES:
            raise CryptoError("measurement_hash too large")
        return mh



class CryptoAuditSink:
    """Hook for structured audit events emitted by the crypto control plane."""
    def emit(self, event_type: str, metadata: Dict[str, Any]) -> None:
        raise NotImplementedError


_AUDIT_SINK: Optional[CryptoAuditSink] = None
_AUDIT_LOCK = threading.Lock()


def register_crypto_audit_sink(sink: CryptoAuditSink) -> None:
    global _AUDIT_SINK
    with _AUDIT_LOCK:
        _AUDIT_SINK = sink


def _emit_audit_event(event_type: str, metadata: Dict[str, Any]) -> None:
    # read without lock (atomic ref); sink must be thread-safe or wrap it externally
    sink = _AUDIT_SINK
    if sink is None:
        return
    try:
        # never log payload contents here
        sink.emit(event_type, metadata)
    except Exception:
        logger.exception("CryptoAuditSink.emit failed")



def _ensure_cryptography() -> None:
    if not _HAS_CRYPTOGRAPHY or serialization is None:
        raise CryptoError("cryptography is required for signing/verification but not available")


def _profile_allows_software_keys(profile: CryptoProfile) -> bool:
    """
    Governance:
      - DEV / SECURE_DEV: allow software keys by default
      - SECURE_PREP: allow only if explicitly enabled
      - SECURE_PROD_* / FIPS: disallow by default
    Override env:
      - TCD_CRYPTO_ALLOW_SOFTWARE_KEYS=1
    """
    allow = os.getenv("TCD_CRYPTO_ALLOW_SOFTWARE_KEYS", "").strip().lower() in ("1", "true", "yes", "on")
    if allow:
        return True
    if profile in ("DEV", "SECURE_DEV"):
        return True
    return False


def _profile_allows_env_keys(profile: CryptoProfile) -> bool:
    """
    Whether private key material is allowed to come from environment variables.
    Default: only DEV/SECURE_DEV (unless explicitly enabled).
    Override env:
      - TCD_CRYPTO_ALLOW_ENV_KEYS=1
    """
    allow = os.getenv("TCD_CRYPTO_ALLOW_ENV_KEYS", "").strip().lower() in ("1", "true", "yes", "on")
    if allow:
        return True
    return profile in ("DEV", "SECURE_DEV")


def _sanitize_key_id(kid: str) -> str:
    s = str(kid).strip()
    if not _KEY_ID_RE.match(s):
        raise CryptoError("Invalid key_id format")
    return s


def _sanitize_operation(op: str) -> str:
    s = str(op).strip()
    if not _OP_RE.match(s):
        raise CryptoError("Invalid operation name")
    return s


def _sanitize_ops(ops: Any) -> Tuple[str, ...]:
    out: list[str] = []
    if isinstance(ops, (list, tuple, set)):
        it = list(ops)
    else:
        it = [ops]
    for x in it:
        if len(out) >= 32:
            break
        try:
            out.append(_sanitize_operation(str(x)))
        except CryptoError:
            continue
    if not out:
        out = ["sign_receipt"]
    return tuple(sorted(set(out)))


def _validate_enum_value(value: Any, allowed: set[str], default: str, name: str) -> str:
    s = str(value).strip()
    if s in allowed:
        return s
    if value is not None:
        logger.warning("Invalid %s=%r; using default=%s", name, value, default)
    return default


@dataclass
class SigningKeyHandle:
    """
    Handle for a signing key, including role and usage metadata.

    NOTE:
      - registry keeps internal instances; callers receive clones to avoid external mutation.
      - software_dev backend is supported; hsm/kms are placeholders for adapters.
    """

    key_id: str
    algo: SignAlgo
    backend_type: KeyBackendType
    status: KeyStatus
    role: KeyRole
    classification_level: ClassificationLevel
    allowed_operations: Tuple[str, ...] = field(default_factory=tuple)
    meta: Dict[str, Any] = field(default_factory=dict)
    _private_key: Optional[Any] = field(default=None, repr=False)

    def clone_for_use(self) -> "SigningKeyHandle":
        # clone so external code cannot mutate registry-held object
        return SigningKeyHandle(
            key_id=self.key_id,
            algo=self.algo,
            backend_type=self.backend_type,
            status=self.status,
            role=self.role,
            classification_level=self.classification_level,
            allowed_operations=tuple(self.allowed_operations),
            meta=dict(self.meta),
            _private_key=self._private_key,
        )

    def _ensure_signable(self, operation: str, profile: CryptoProfile) -> None:
        op = _sanitize_operation(operation)

        if self.status not in ("active", "retiring"):
            raise CryptoError(f"Key {self.key_id} is not signable in status={self.status}")
        if op not in self.allowed_operations:
            raise CryptoError(f"Operation {op} not allowed for key_id={self.key_id}")

        if self.backend_type == "software_dev" and not _profile_allows_software_keys(profile):
            raise CryptoError(f"Software key backend not allowed for profile={profile}")

    def sign(self, message: bytes, *, operation: str, profile: CryptoProfile) -> bytes:
        _ensure_cryptography()
        self._ensure_signable(operation, profile)
        if self.algo == "ED25519":
            if self._private_key is None:
                raise CryptoError(f"Missing private key for key_id={self.key_id}")
            if not isinstance(self._private_key, Ed25519PrivateKey):
                raise CryptoError("Private key object is not Ed25519PrivateKey")
            return self._private_key.sign(message)
        raise CryptoError(f"Signing algorithm {self.algo} not implemented in this build")

    def public_key_pem(self) -> str:
        _ensure_cryptography()
        if self.algo != "ED25519":
            raise CryptoError(f"Public key export not implemented for algo={self.algo}")
        if self._private_key is None:
            raise CryptoError("Private key not loaded; cannot derive public key")
        if not isinstance(self._private_key, Ed25519PrivateKey):
            raise CryptoError("Private key object is not Ed25519PrivateKey")
        pub = self._private_key.public_key()
        pem_bytes = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem_bytes.decode("utf-8")

    def wipe_private(self) -> None:
        # best-effort: drop reference; cannot guarantee memory wipe in Python
        self._private_key = None


def _fingerprint_public_key(pub: Any, hash_engine: HashEngine) -> str:
    _ensure_cryptography()
    if not isinstance(pub, Ed25519PublicKey):
        raise CryptoError("pub must be Ed25519PublicKey")
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hash_engine.digest(pub_bytes, label="pubkey")
    return fp[:16]


def _load_pem_private_key(pem: bytes, password: Optional[bytes]) -> Any:
    _ensure_cryptography()
    # cryptography API compat: backend may be optional
    try:
        return serialization.load_pem_private_key(pem, password=password)  # type: ignore[call-arg]
    except TypeError:
        from cryptography.hazmat.backends import default_backend  # type: ignore[import]
        return serialization.load_pem_private_key(pem, password=password, backend=default_backend())


def _load_pem_public_key(pem: bytes) -> Any:
    _ensure_cryptography()
    try:
        return serialization.load_pem_public_key(pem)  # type: ignore[call-arg]
    except TypeError:
        from cryptography.hazmat.backends import default_backend  # type: ignore[import]
        return serialization.load_pem_public_key(pem, backend=default_backend())


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
    priv = _load_pem_private_key(pem, password=password)
    if not isinstance(priv, Ed25519PrivateKey):
        raise CryptoError("Provided private key is not Ed25519")

    pub = priv.public_key()
    kid = _sanitize_key_id(key_id) if key_id else _fingerprint_public_key(pub, hash_engine)

    return SigningKeyHandle(
        key_id=kid,
        algo="ED25519",
        backend_type="software_dev",
        status=status,
        role=role,
        classification_level=classification_level,
        allowed_operations=_sanitize_ops(allowed_operations),
        meta={},
        _private_key=priv,
    )


# ---------------------------------------------------------------------------
# File helpers (bounded read + permission checks) for key loading
# ---------------------------------------------------------------------------

def _check_file_permissions(path: str) -> Tuple[bool, str]:
    """
    Basic permission hardening:
      - reject symlink
      - reject world-writable file
      - require owner root or current uid (when available)
      - reject parent world-writable w/o sticky bit
    """
    p = str(path).strip()
    if not p:
        return False, "empty_path"

    try:
        if os.path.islink(p):
            return False, "symlink_disallowed"
    except Exception:
        pass

    try:
        st = os.stat(p, follow_symlinks=False)  # type: ignore[call-arg]
    except Exception:
        return False, "stat_failed"

    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o002:
        return False, "world_writable"

    uid = os.getuid() if hasattr(os, "getuid") else None
    if uid is not None and st.st_uid not in (0, uid):
        return False, "bad_owner"

    try:
        parent = os.path.dirname(p) or "."
        pst = os.stat(parent, follow_symlinks=False)  # type: ignore[call-arg]
        pmode = stat.S_IMODE(pst.st_mode)
        if (pmode & 0o002) and not (pmode & stat.S_ISVTX):
            return False, "parent_world_writable_no_sticky"
    except Exception:
        return False, "parent_stat_failed"

    return True, "ok"


def _read_small_file_bytes(path: str, *, max_bytes: int) -> bytes:
    """
    Bounded read with TOCTTOU guard (stat + fstat inode/dev).
    """
    p = str(path).strip()
    ok, reason = _check_file_permissions(p)
    if not ok:
        raise CryptoError(f"insecure_key_file:{reason}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= getattr(os, "O_NOFOLLOW")

    st1 = os.stat(p, follow_symlinks=False)  # type: ignore[call-arg]
    fd: Optional[int] = None
    try:
        fd = os.open(p, flags)
        st2 = os.fstat(fd)
        if st1.st_ino != st2.st_ino or st1.st_dev != st2.st_dev:
            raise CryptoError("tocttou_inode_mismatch")

        with os.fdopen(fd, "rb") as f:
            fd = None
            data = f.read(int(max_bytes) + 1)
            if len(data) > int(max_bytes):
                raise CryptoError("file_too_large")
            return data
    finally:
        try:
            if fd is not None:
                os.close(fd)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Key registry
# ---------------------------------------------------------------------------

class KeyRegistry:
    """
    In-memory registry of signing keys with roles and usage constraints.

    Hardening:
      - returns clones to callers (prevents external mutation of registry objects)
      - selection operates under lock (stronger correctness)
    """

    def __init__(self, keys: Optional[Iterable[SigningKeyHandle]] = None) -> None:
        self._lock = threading.RLock()
        self._keys: Dict[str, SigningKeyHandle] = {}
        if keys:
            for k in keys:
                self._keys[k.key_id] = k

    def add_or_replace(self, key: SigningKeyHandle) -> None:
        kid = _sanitize_key_id(key.key_id)
        with self._lock:
            existed = kid in self._keys
            self._keys[kid] = key
        _emit_audit_event(
            "KeyRegistered",
            {
                "key_id": kid,
                "algo": key.algo,
                "backend_type": key.backend_type,
                "status": key.status,
                "role": key.role,
                "classification_level": key.classification_level,
                "replaced": bool(existed),
            },
        )

    def set_status(self, key_id: str, status: KeyStatus) -> None:
        kid = _sanitize_key_id(key_id)
        if status not in _ALLOWED_KEY_STATUS:
            raise CryptoError("Invalid key status")

        with self._lock:
            if kid not in self._keys:
                raise CryptoError(f"Unknown key_id={kid}")
            self._keys[kid].status = status  # internal mutation under lock

        _emit_audit_event("KeyStatusChanged", {"key_id": kid, "status": status})

    def get(self, key_id: str) -> Optional[SigningKeyHandle]:
        kid = str(key_id).strip()
        with self._lock:
            k = self._keys.get(kid)
            return k.clone_for_use() if k else None

    def select_signing_key(
        self,
        *,
        operation: str,
        required_role: Optional[KeyRole],
        profile: CryptoProfile,
    ) -> SigningKeyHandle:
        op = _sanitize_operation(operation)

        with self._lock:
            candidates: list[SigningKeyHandle] = []
            for key in self._keys.values():
                if key.status not in ("active", "retiring"):
                    continue
                if op not in key.allowed_operations:
                    continue
                if required_role is not None and key.role != required_role:
                    continue
                if key.backend_type == "software_dev" and not _profile_allows_software_keys(profile):
                    continue
                candidates.append(key)

        if not candidates:
            raise CryptoError(f"No usable signing key for operation={op} profile={profile}")

        # Prefer active over retiring; deterministic order by key_id
        candidates.sort(key=lambda k: (0 if k.status == "active" else 1, k.key_id))
        return candidates[0].clone_for_use()

    def public_keys(self) -> Dict[str, str]:
        with self._lock:
            snapshot = list(self._keys.values())
        result: Dict[str, str] = {}
        for key in snapshot:
            try:
                result[key.key_id] = key.clone_for_use().public_key_pem()
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
            return cls(
                suite_id="TCD-ED25519-SHA3-256-v1",
                profile=profile,
                hash_policy=hash_policy,
                sign_algos=("ED25519",),
                require_all_signatures=True,
                require_pq_component=False,
            )
        return cls(
            suite_id="TCD-ED25519-BLAKE3-256-v1",
            profile=profile,
            hash_policy=hash_policy,
            sign_algos=("ED25519",),
            require_all_signatures=True,
            require_pq_component=False,
        )


# ---------------------------------------------------------------------------
# Signature envelope (recommended API for receipts/attestation)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SignatureEnvelope:
    """
    Self-describing signature output so verification does not depend on current in-process suite/profile.

    Fields are designed to be JSON-safe and stable.
    """
    engine_version: str
    message_version: Literal["v1", "v2"]
    profile: CryptoProfile
    suite_id: str
    label: HashLabel
    digest_hex: str
    key_id: str
    algo: SignAlgo
    signature_b64: str
    measurement_hex: str = ""

    def to_json(self) -> str:
        d = {
            "engine_version": self.engine_version,
            "message_version": self.message_version,
            "profile": self.profile,
            "suite_id": self.suite_id,
            "label": self.label,
            "digest_hex": self.digest_hex,
            "key_id": self.key_id,
            "algo": self.algo,
            "signature_b64": self.signature_b64,
            "measurement_hex": self.measurement_hex,
        }
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    @classmethod
    def from_json(cls, s: str) -> "SignatureEnvelope":
        try:
            obj = json.loads(s)
        except Exception as e:
            raise CryptoError(f"invalid envelope json: {e}") from e
        if not isinstance(obj, dict):
            raise CryptoError("invalid envelope json: not object")
        return cls(
            engine_version=str(obj.get("engine_version", "")),
            message_version=cast(Literal["v1", "v2"], obj.get("message_version", "v2")),
            profile=cast(CryptoProfile, obj.get("profile", "DEV")),
            suite_id=str(obj.get("suite_id", "")),
            label=cast(HashLabel, obj.get("label", "receipt")),
            digest_hex=str(obj.get("digest_hex", "")),
            key_id=str(obj.get("key_id", "")),
            algo=cast(SignAlgo, obj.get("algo", "ED25519")),
            signature_b64=str(obj.get("signature_b64", "")),
            measurement_hex=str(obj.get("measurement_hex", "")),
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
            profile = cast(CryptoProfile, profile_str)
        else:
            logger.warning("Unknown TCD_CRYPTO_PROFILE=%s, falling back to DEV", profile_str)
            profile = "DEV"

        # fail-fast governance
        env_fail_fast = os.getenv("TCD_CRYPTO_FAIL_FAST")
        if env_fail_fast is None:
            fail_fast = profile in ("FIPS", "SECURE_PROD_TIER1", "SECURE_PROD_TIER2")
        else:
            fail_fast = env_fail_fast.strip().lower() in ("1", "true", "yes", "on")

        require_keys_env = os.getenv("TCD_CRYPTO_REQUIRE_KEYS")
        if require_keys_env is None:
            require_keys = fail_fast
        else:
            require_keys = require_keys_env.strip().lower() in ("1", "true", "yes", "on")

        suite = SignatureSuite.default_for_profile(profile)
        hash_engine = HashEngine(suite.hash_policy)

        rng_policy = RngPolicy.for_profile(profile)
        rng_context = RngContext(rng_policy)
        kdf_engine = KdfEngine(hash_engine)

        # key loading
        try:
            key_registry = _load_key_registry_from_env(hash_engine=hash_engine, profile=profile)
        except Exception as e:
            _emit_audit_event(
                "KeyRegistryLoadFailed",
                {"profile": profile, "fail_fast": bool(fail_fast), "require_keys": bool(require_keys), "error": str(e)[:256]},
            )
            if require_keys or fail_fast:
                raise
            logger.warning("Key registry load failed (continuing with empty registry): %s", e)
            key_registry = KeyRegistry()

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
                "engine_version": _CRYPTO_ENGINE_VERSION,
                "profile": ctx.profile,
                "suite_id": ctx.suite.suite_id,
                "hash_algo": ctx.suite.hash_policy.hash_algo,
                "mac_algo": ctx.suite.hash_policy.mac_algo,
                "allow_software_keys": bool(_profile_allows_software_keys(profile)),
                "allow_env_keys": bool(_profile_allows_env_keys(profile)),
                "fail_fast": bool(fail_fast),
                "require_keys": bool(require_keys),
                "rng_backend": rng_policy.backend,
                "rng_require_certified": bool(rng_policy.require_certified),
            },
        )
        return ctx

    # ---- signing message formats ----

    def _build_signing_message_v1(
        self,
        *,
        digest_hex: str,
        label: HashLabel,
        attestation: Optional[AttestationContext],
    ) -> bytes:
        measurement = attestation.measurement_or_empty() if attestation else b""
        digest_bytes = _hex_to_bytes(digest_hex, expected_len=self.hash_engine.policy.output_size_bytes())
        # legacy: delimiter-based, binary-safe only by convention (kept for compatibility)
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
            digest_bytes,
        ]
        return b"".join(parts)

    def _build_signing_message_v2(
        self,
        *,
        digest_hex: str,
        label: HashLabel,
        attestation: Optional[AttestationContext],
    ) -> bytes:
        measurement = attestation.measurement_or_empty() if attestation else b""
        digest_bytes = _hex_to_bytes(digest_hex, expected_len=self.hash_engine.policy.output_size_bytes())

        # length-prefixed binary encoding (unambiguous)
        prof = self.profile.encode("ascii")
        suite = self.suite.suite_id.encode("ascii")
        lab = label.encode("ascii")

        def pack_blob(b: bytes) -> bytes:
            return struct.pack("!I", len(b)) + b

        return b"".join(
            [
                b"TCD-SIGN-v2",
                pack_blob(prof),
                pack_blob(suite),
                pack_blob(lab),
                pack_blob(measurement),
                pack_blob(digest_bytes),
            ]
        )

    def sign_blob(
        self,
        blob: bytes,
        *,
        label: HashLabel = "receipt",
        operation: str = "sign_receipt",
        attestation: Optional[AttestationContext] = None,
    ) -> Tuple[bytes, str, str, str]:
        """
        Backward-compatible signature API.

        Returns (signature_bytes, digest_hex, key_id, algo).

        NOTE:
          - message format uses v2 by default for new signatures.
          - verify_blob will try v2 then v1 for backward compatibility.
        """
        op = _sanitize_operation(operation)
        digest_hex = self.hash_engine.digest(blob, label=label)

        # v2 by default
        message = self._build_signing_message_v2(
            digest_hex=digest_hex,
            label=label,
            attestation=attestation or self.attestation_context,
        )

        key = self.key_registry.select_signing_key(
            operation=op,
            required_role="online_signing",
            profile=self.profile,
        )
        signature = key.sign(message, operation=op, profile=self.profile)

        _emit_audit_event(
            "SignOperation",
            {
                "engine_version": _CRYPTO_ENGINE_VERSION,
                "key_id": key.key_id,
                "algo": key.algo,
                "suite_id": self.suite.suite_id,
                "profile": self.profile,
                "label": label,
                "operation": op,
                "message_version": "v2",
            },
        )

        return signature, digest_hex, key.key_id, key.algo

    def sign_envelope(
        self,
        blob: bytes,
        *,
        label: HashLabel = "receipt",
        operation: str = "sign_receipt",
        attestation: Optional[AttestationContext] = None,
        message_version: Literal["v1", "v2"] = "v2",
    ) -> SignatureEnvelope:
        """
        Recommended API: returns a self-describing envelope suitable for receipts/attestation.
        """
        op = _sanitize_operation(operation)
        digest_hex = self.hash_engine.digest(blob, label=label)
        att = attestation or self.attestation_context

        if message_version == "v1":
            msg = self._build_signing_message_v1(digest_hex=digest_hex, label=label, attestation=att)
        else:
            msg = self._build_signing_message_v2(digest_hex=digest_hex, label=label, attestation=att)

        key = self.key_registry.select_signing_key(
            operation=op,
            required_role="online_signing",
            profile=self.profile,
        )
        sig = key.sign(msg, operation=op, profile=self.profile)

        mh = att.measurement_or_empty() if att else b""
        env = SignatureEnvelope(
            engine_version=_CRYPTO_ENGINE_VERSION,
            message_version=message_version,
            profile=self.profile,
            suite_id=self.suite.suite_id,
            label=label,
            digest_hex=digest_hex,
            key_id=key.key_id,
            algo=key.algo,
            signature_b64=base64.b64encode(sig).decode("ascii"),
            measurement_hex=_bytes_to_hex(mh) if mh else "",
        )

        _emit_audit_event(
            "SignEnvelope",
            {
                "engine_version": _CRYPTO_ENGINE_VERSION,
                "key_id": key.key_id,
                "algo": key.algo,
                "suite_id": self.suite.suite_id,
                "profile": self.profile,
                "label": label,
                "operation": op,
                "message_version": message_version,
            },
        )
        return env

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
        Tries v2 then v1 message formats for backward compatibility.
        """
        if not isinstance(signature, (bytes, bytearray)):
            return False
        if not isinstance(public_key_pem, str) or len(public_key_pem) > 20_000:
            return False

        digest_hex = self.hash_engine.digest(blob, label=label)
        att = attestation or self.attestation_context

        try:
            pub = _load_pem_public_key(public_key_pem.encode("utf-8"))
        except Exception:
            return False
        if not isinstance(pub, Ed25519PublicKey):
            return False

        # try v2 then v1
        try:
            msg2 = self._build_signing_message_v2(digest_hex=digest_hex, label=label, attestation=att)
            pub.verify(bytes(signature), msg2)
            return True
        except Exception:
            pass

        try:
            msg1 = self._build_signing_message_v1(digest_hex=digest_hex, label=label, attestation=att)
            pub.verify(bytes(signature), msg1)
            return True
        except Exception:
            return False

    def verify_envelope(self, blob: bytes, env: SignatureEnvelope, public_key_pem: str) -> bool:
        """
        Verify an envelope (recommended).
        Ensures digest matches blob, and signature verifies under declared message_version/profile/suite/label.
        """
        if env.profile != self.profile:
            # profile mismatch does not necessarily mean invalid; but this context cannot verify that suite/profile.
            # caller should create a CryptoContext configured for env.profile if needed.
            return False
        if env.suite_id != self.suite.suite_id:
            return False
        if env.label not in _ALLOWED_HASH_LABELS:
            return False

        # digest check (prevents signature replay on different blob)
        digest_hex = self.hash_engine.digest(blob, label=env.label)
        if not hmac.compare_digest(digest_hex, env.digest_hex):
            return False

        # attestation/measurement
        mh = b""
        if env.measurement_hex:
            try:
                mh = _hex_to_bytes(env.measurement_hex, max_input_chars=2048)
            except CryptoError:
                return False
            if len(mh) > _MAX_MEASUREMENT_BYTES:
                return False

        att = AttestationContext(measurement_hash=mh) if mh else None

        # reconstruct message
        try:
            sig = base64.b64decode(env.signature_b64.encode("ascii"), validate=True)
        except Exception:
            return False

        if env.message_version == "v1":
            msg = self._build_signing_message_v1(digest_hex=env.digest_hex, label=env.label, attestation=att)
        else:
            msg = self._build_signing_message_v2(digest_hex=env.digest_hex, label=env.label, attestation=att)

        try:
            pub = _load_pem_public_key(public_key_pem.encode("utf-8"))
        except Exception:
            return False
        if not isinstance(pub, Ed25519PublicKey):
            return False

        try:
            pub.verify(sig, msg)
            return True
        except Exception:
            return False

    def publish_public_keys(self) -> Dict[str, str]:
        return self.key_registry.public_keys()

    def cleanup_expired_keys(self) -> None:
        self.key_registry.wipe_expired_keys()


# ---------------------------------------------------------------------------
# Default context (lazy singleton)
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Key registry loader (env/file, bounded, governance-aware)
# ---------------------------------------------------------------------------

def _load_key_registry_from_env(
    *,
    hash_engine: HashEngine,
    profile: CryptoProfile,
) -> KeyRegistry:
    """
    Build a KeyRegistry from environment / files.

    Supported sources (priority order):
      1) TCD_ED25519_KEYSET_PATH (JSON file)
      2) TCD_ED25519_KEYSET_JSON (env JSON)
      3) TCD_ED25519_PRIVATE_KEY_PATH (PEM file)
      4) TCD_ED25519_PRIVATE_KEY_PEM (env PEM)

    Governance:
      - env-provided private keys are disallowed by default in SECURE_PREP/PROD/FIPS
        unless TCD_CRYPTO_ALLOW_ENV_KEYS=1.
      - software keys are disallowed by default in SECURE_PREP/PROD/FIPS
        unless TCD_CRYPTO_ALLOW_SOFTWARE_KEYS=1.
    """
    allow_env_keys = _profile_allows_env_keys(profile)
    allow_software = _profile_allows_software_keys(profile)

    # source 1: keyset path
    keyset_path = os.getenv("TCD_ED25519_KEYSET_PATH", "").strip()
    if keyset_path:
        raw = _read_small_file_bytes(keyset_path, max_bytes=_MAX_KEY_FILE_BYTES)
        try:
            doc = json.loads(raw.decode("utf-8", errors="strict"))
        except Exception as e:
            raise CryptoError(f"Failed to parse keyset file JSON: {e}") from e
        keys = _parse_keyset_doc(doc, hash_engine=hash_engine, profile=profile, allow_software=allow_software)
        reg = KeyRegistry(keys)
        reg.wipe_expired_keys()
        return reg

    # source 2: keyset json env
    keyset_json = os.getenv("TCD_ED25519_KEYSET_JSON")
    if keyset_json:
        if not allow_env_keys:
            raise CryptoError("Env keyset not allowed in this profile (set TCD_CRYPTO_ALLOW_ENV_KEYS=1 to override)")
        if len(keyset_json.encode("utf-8", errors="ignore")) > _MAX_ENV_JSON_BYTES:
            raise CryptoError("TCD_ED25519_KEYSET_JSON too large")
        try:
            doc = json.loads(keyset_json)
        except Exception as e:
            raise CryptoError(f"Failed to parse TCD_ED25519_KEYSET_JSON: {e}") from e
        keys = _parse_keyset_doc(doc, hash_engine=hash_engine, profile=profile, allow_software=allow_software)
        reg = KeyRegistry(keys)
        reg.wipe_expired_keys()
        return reg

    # source 3: single key file
    key_path = os.getenv("TCD_ED25519_PRIVATE_KEY_PATH", "").strip()
    if key_path:
        pem = _read_small_file_bytes(key_path, max_bytes=_MAX_KEY_FILE_BYTES)
        password = os.getenv("TCD_ED25519_PRIVATE_KEY_PASSWORD")
        key_id_override = os.getenv("TCD_ED25519_KEY_ID")
        if not allow_software:
            raise CryptoError("software_dev keys are not allowed in this profile (set TCD_CRYPTO_ALLOW_SOFTWARE_KEYS=1 to override)")
        handle = _load_software_ed25519_from_pem(
            pem=pem,
            password=password.encode("utf-8") if password else None,
            hash_engine=hash_engine,
            key_id=key_id_override.strip() if key_id_override else None,
            status="active",
            role="online_signing",
            classification_level="public",
            allowed_operations=("sign_receipt", "sign_ledger", "sign_config"),
        )
        reg = KeyRegistry([handle])
        reg.wipe_expired_keys()
        return reg

    # source 4: single key pem in env
    pem_str = os.getenv("TCD_ED25519_PRIVATE_KEY_PEM", "")
    if pem_str:
        if not allow_env_keys:
            raise CryptoError("Env private key not allowed in this profile (set TCD_CRYPTO_ALLOW_ENV_KEYS=1 to override)")
        if len(pem_str.encode("utf-8", errors="ignore")) > _MAX_ENV_PEM_BYTES:
            raise CryptoError("TCD_ED25519_PRIVATE_KEY_PEM too large")
        if not allow_software:
            raise CryptoError("software_dev keys are not allowed in this profile (set TCD_CRYPTO_ALLOW_SOFTWARE_KEYS=1 to override)")

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
        reg = KeyRegistry([handle])
        reg.wipe_expired_keys()
        return reg

    # nothing found
    raise CryptoError(
        "Missing Ed25519 private key material. Configure one of: "
        "TCD_ED25519_KEYSET_PATH, TCD_ED25519_KEYSET_JSON, "
        "TCD_ED25519_PRIVATE_KEY_PATH, TCD_ED25519_PRIVATE_KEY_PEM."
    )


def _parse_keyset_doc(
    doc: Any,
    *,
    hash_engine: HashEngine,
    profile: CryptoProfile,
    allow_software: bool,
) -> list[SigningKeyHandle]:
    if not isinstance(doc, list):
        raise CryptoError("Keyset must be a list of key objects")

    keys: list[SigningKeyHandle] = []
    for entry in doc:
        if not isinstance(entry, dict):
            raise CryptoError("Each key entry must be an object")

        pem = entry.get("pem")
        if not isinstance(pem, str) or not pem.strip():
            raise CryptoError("Each key entry must include non-empty 'pem'")

        kid_raw = entry.get("id") or entry.get("key_id")
        kid = None
        if kid_raw is not None:
            kid = _sanitize_key_id(str(kid_raw))

        status_s = _validate_enum_value(entry.get("status", "active"), _ALLOWED_KEY_STATUS, "active", "status")
        role_s = _validate_enum_value(entry.get("role", "online_signing"), _ALLOWED_KEY_ROLE, "online_signing", "role")
        cls_s = _validate_enum_value(entry.get("classification_level", "public"), _ALLOWED_CLASSIFICATION, "public", "classification_level")

        ops = _sanitize_ops(entry.get("allowed_operations", ("sign_receipt",)))

        if not allow_software:
            raise CryptoError(f"software_dev keys not allowed for profile={profile} (set TCD_CRYPTO_ALLOW_SOFTWARE_KEYS=1 to override)")

        handle = _load_software_ed25519_from_pem(
            pem=pem.encode("utf-8"),
            password=None,
            hash_engine=hash_engine,
            key_id=kid,
            status=cast(KeyStatus, status_s),
            role=cast(KeyRole, role_s),
            classification_level=cast(ClassificationLevel, cls_s),
            allowed_operations=ops,
        )
        keys.append(handle)

    if not keys:
        raise CryptoError("Keyset empty")
    return keys


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