# FILE: tcd/attest.py
from __future__ import annotations

"""
tcd/attest.py — Structured attestation generator for verifiable receipts (platform-grade, L6/L7)

This file is a "regulator-grade" attestation primitive. It is designed for:
- cross-domain verification (customer/auditor can verify offline)
- strong governance (strict_mode) for financial / gov / regulated environments
- DoS hardening and redaction to prevent leakage into receipts
- deterministic canonicalization (JCS-like subset + NFC) and verifiable invariants

Compatibility:
- Attestor(hash_alg="...") remains valid.
- Attestor.issue(...) signature unchanged; returned required keys unchanged.
- verify_attestation_record(...) keeps required args; hardening features added via optional kwargs.
- Adds verify_attestation_record_ex(...) for reason codes (low-cardinality) and debug details.

IMPORTANT PROTOCOL NOTES (v=1):
- Body is canonical JSON (sort_keys, compact separators, allow_nan=False) over sanitized data.
- Head is computed from a fixed subset derived from the FINAL body (after all compaction/signature),
  so receipt/head never drifts from receipt_body.
- receipt_sig is an integrity hash (NOT a signature):
      SHA-256("tcd:attest_sig" || head || body_bytes)
  External authenticity is provided via body["sig"] and verifier callback.

Canonicalization scope:
- We implement an RFC 8785 (JCS) compatible SUBSET:
  - keys sorted
  - no NaN/Inf
  - strings NFC-normalized
  - strict_mode forbids float; non-strict converts float to a tagged string wrapper
  This makes cross-language verification practical in strict_mode.

"""

import dataclasses
import hashlib
import json
import logging
import math
import re
import secrets
import time
import unicodedata
from base64 import b64decode, b64encode
from collections import deque
from typing import (
    Any,
    Callable,
    Deque,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
    Union,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants / low-cardinality enums
# ---------------------------------------------------------------------------

ALLOWED_WITNESS_KINDS = frozenset(
    [
        "audit_ledger_head",
        "receipt_head",
        "tcd_chain_report",
        "zk_proof",
        "tpm_quote",
        "external",
        "other",
    ]
)

_SUPPORTED_HASH_ALGS = frozenset({"blake3", "sha256", "sha3_256", "blake2s"})

# Conservative patterns to avoid control chars / injection.
# NOTE: used for identifiers (attestor_id, key_id, witness ids), not for general content.
_SAFE_ASCII_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+=@,-]{0,255}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{8,256}$")

# Tags should be low-cardinality and safe; default recommended charset.
_DEFAULT_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

# Signature base64 is validated and decoded to bytes (size checks).
_BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]+$")

# Value-based secret detectors (heuristic; configurable)
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")
_PEM_RE = re.compile(r"-----BEGIN [A-Z0-9 _-]+-----")
_BEARER_RE = re.compile(r"^\s*Bearer\s+[A-Za-z0-9._\-+/=]{10,}\s*$", re.IGNORECASE)

# crude base64-ish detector for large blobs
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/=]{80,}$")

# For opaque object repr normalization (avoid memory addresses)
_REPR_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")

# ---------------------------------------------------------------------------
# Error taxonomy (library-level)
# ---------------------------------------------------------------------------


class AttestationError(RuntimeError):
    """Base class for attestation generation/verification errors."""


class PolicyError(AttestationError):
    """Configuration violates governance rules (strict mode etc.)."""


class SerializationError(AttestationError):
    """Object could not be normalized/serialized safely."""


class WitnessError(AttestationError):
    """Witness segments/tags invalid or exceed governance bounds."""


class SigningError(AttestationError):
    """Signing backend failed or returned invalid output."""


# ---------------------------------------------------------------------------
# Verify reason codes (low-cardinality)
# ---------------------------------------------------------------------------

# Keep this list small & stable (ops/runbooks).
VR_OK = "OK"
VR_BODY_TOO_LARGE = "BODY_TOO_LARGE"
VR_JSON_TOO_DEEP = "JSON_TOO_DEEP"
VR_JSON_PARSE = "JSON_PARSE_ERROR"
VR_NOT_CANONICAL = "BODY_NOT_CANONICAL"
VR_SCHEMA = "SCHEMA_ERROR"
VR_COMPLEXITY = "COMPLEXITY_LIMIT"
VR_HASH_ALG = "HASH_ALG_FORBIDDEN"
VR_ATTESTOR_POLICY = "ATTESTOR_POLICY_REJECTED"
VR_ATTESTOR_ID = "ATTESTOR_ID_REJECTED"
VR_TIER = "DEPLOYMENT_TIER_REJECTED"
VR_VERIFY_KEY = "VERIFY_KEY_REJECTED"
VR_WITNESS_DIGEST = "WITNESS_DIGEST_MISMATCH"
VR_HEAD_MISMATCH = "HEAD_MISMATCH"
VR_INTEGRITY = "INTEGRITY_HASH_MISMATCH"
VR_SIG_REQUIRED = "SIGNATURE_REQUIRED"
VR_SIG_MISSING = "SIGNATURE_MISSING"
VR_SIG_BAD = "SIGNATURE_INVALID"
VR_SIG_VERIFY_UNAVAILABLE = "SIGNATURE_VERIFY_UNAVAILABLE"
VR_INTERNAL = "INTERNAL_ERROR"

# ---------------------------------------------------------------------------
# Public helper: canonical KV hash (imported by other modules)
# ---------------------------------------------------------------------------


def canonical_kv_hash(obj: Dict[str, Any], *, ctx: str, label: str = "") -> str:
    """
    Canonical hash of a mapping:
      - canonical JSON bytes (see _canonical_json_bytes)
      - SHA-256 with explicit domain separation (ctx + optional label)

    Intended for stable policy/config fingerprints across trust domains.
    """
    if not isinstance(obj, dict):
        raise TypeError("canonical_kv_hash expects a dict")
    data = _canonical_json_bytes(obj)
    h = hashlib.sha256()
    h.update(ctx.encode("utf-8"))
    if label:
        h.update(b"\x1f")
        h.update(label.encode("utf-8"))
    h.update(data)
    return h.hexdigest()


# Back-compat alias (older internal name).
_canonical_kv_hash = canonical_kv_hash


# ---------------------------------------------------------------------------
# Optional hooks (library-level observability without hard deps)
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class AttestorHooks:
    on_truncate: Optional[Callable[[str, Dict[str, Any]], None]] = None
    on_redact: Optional[Callable[[str, Dict[str, Any]], None]] = None
    on_verify_fail: Optional[Callable[[str, Dict[str, Any]], None]] = None


# ---------------------------------------------------------------------------
# Config (expanded per your L6/L7 checklist)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class AttestorConfig:
    # Hashing (governance)
    hash_alg: str = "blake3"
    hash_ctx: str = "tcd:attest"
    digest_size: int = 32  # blake2s only (1..32)
    strict_mode: bool = False
    allowed_hash_algs: Optional[List[str]] = None
    disallowed_hash_algs: Optional[List[str]] = None
    min_digest_size: int = 16  # blake2s lower bound governance (strict recommended >= 16)

    # Optional dual-hash migration (P2)
    secondary_hash_alg: Optional[str] = None
    secondary_hash_ctx: Optional[str] = None
    secondary_digest_size: int = 32

    # Identity / origin / supply-chain
    attestor_id: str = "tcd-attestor"
    proc_id: Optional[str] = None
    build_digest: Optional[str] = None
    runtime_env_digest: Optional[str] = None
    hw_root_id: Optional[str] = None
    tpm_quote_digest: Optional[str] = None
    deployment_tier: Optional[str] = None

    # Identity governance
    max_identity_len: int = 256
    require_safe_identity: bool = True  # strict recommended
    allowed_deployment_tiers: Optional[List[str]] = None

    # Policy block
    include_policy_block: bool = True
    default_auth_policy: Optional[str] = None
    default_chain_policy: Optional[str] = None
    default_ledger_policy: Optional[str] = None
    default_cfg_digest: Optional[str] = None

    # Signing governance
    sign_func: Optional[Callable[[bytes], bytes]] = None
    sig_alg: Optional[str] = None
    sig_key_id: Optional[str] = None
    allowed_sig_algs: Optional[List[str]] = None
    require_sig_in_strict: bool = True
    min_signature_bytes: int = 16
    max_signature_bytes: int = 8 * 1024  # PQ-safe upper bound

    # Normalization hooks
    normalize_req: Optional[Callable[[Any], Dict[str, Any]]] = None
    normalize_comp: Optional[Callable[[Any], Dict[str, Any]]] = None
    normalize_e: Optional[Callable[[Any], Dict[str, Any]]] = None
    normalize_meta: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None

    # Canonicalization & JSON safety
    max_json_depth: int = 96
    max_nodes: int = 50_000
    max_list_items: int = 2_000
    max_dict_items: int = 2_000
    max_string_bytes: int = 16 * 1024
    max_key_bytes: int = 2 * 1024
    max_total_sanitized_bytes: int = 512 * 1024  # estimate budget during sanitize (prevents "few nodes, huge bytes" DoS)
    enforce_nfc: bool = True
    forbid_float_in_strict: bool = True  # recommended

    # Witness bounds / governance
    max_witness_segments: int = 256
    max_witness_meta_bytes: int = 8 * 1024
    max_digest_len: int = 256
    max_witness_id_len: int = 128

    allowed_witness_kinds: Optional[List[str]] = None
    disallowed_witness_kinds: Optional[List[str]] = None
    forbid_other_in_strict: bool = True
    allowed_external_ids: Optional[List[str]] = None  # for kind="external"
    canonicalize_witness_segments_order: bool = False  # recommended True in strict deployments

    # core witness requirements (kind presence + optional cardinality)
    core_witness_kinds: Optional[List[str]] = None
    core_witness_kind_cardinality: Optional[Dict[str, Tuple[int, int]]] = None  # {kind: (min,max)}

    # Tags governance
    max_tags: int = 64
    max_tag_len: int = 64
    tag_regex: Optional[str] = None  # defaults to _DEFAULT_TAG_RE

    # Receipt body cap + per-field budgets
    max_body_bytes: int = 64 * 1024

    # budgets: <=0 means "no per-field cap" (per your requirement 9.1)
    meta_budget_bytes: int = 8 * 1024
    req_budget_bytes: int = 24 * 1024
    comp_budget_bytes: int = 12 * 1024
    e_budget_bytes: int = 12 * 1024
    witness_budget_bytes: int = 24 * 1024

    # previews (dangerous): strict_mode forces off; non-strict uses SAFE previews only
    include_truncation_previews: bool = False
    truncation_preview_bytes: int = 256  # applied only to safe previews (keys/shape), not raw bytes

    # Redaction
    redact_keys: Optional[List[str]] = dataclasses.field(
        default_factory=lambda: [
            "authorization",
            "proxy-authorization",
            "x-api-key",
            "api_key",
            "apikey",
            "token",
            "access_token",
            "refresh_token",
            "id_token",
            "secret",
            "password",
            "passwd",
            "session",
            "cookie",
            "set-cookie",
        ]
    )
    redact_key_patterns: Optional[List[str]] = dataclasses.field(
        default_factory=lambda: [
            r"(token|secret|passw|authorization|cookie|api[-_]?key|session)",
        ]
    )
    enable_value_redaction: bool = True
    redact_value: str = "[REDACTED]"

    # Idempotency / deterministic retry (control keys in meta, removed before embedding)
    allow_control_meta_keys: bool = True
    control_meta_event_id_key: str = "_tcd_event_id"
    control_meta_nonce_key: str = "_tcd_nonce"
    control_meta_ts_ns_key: str = "_tcd_ts_ns"
    deterministic_nonce_from_event_id: bool = True  # if event_id exists and nonce not provided
    allow_custom_nonce: bool = True
    allow_custom_ts_ns: bool = True

    # Bounded bookkeeping to avoid truncation metadata DoS
    max_truncated_paths: int = 256
    max_truncation_records: int = 256

    # Optional library hooks
    hooks: Optional[AttestorHooks] = None

    # Optional self-check (CI/gray; expensive): verify the record we just emitted
    self_check: bool = False
    self_check_strict_structure: bool = True
    self_check_require_canonical: bool = True

    def __post_init__(self) -> None:
        # normalize base strings
        self.hash_alg = (self.hash_alg or "").strip().lower() or "blake3"
        self.hash_ctx = (self.hash_ctx or "").strip() or "tcd:attest"
        self.attestor_id = (self.attestor_id or "").strip() or "tcd-attestor"

        if self.hash_alg not in _SUPPORTED_HASH_ALGS:
            raise PolicyError(f"unsupported hash_alg '{self.hash_alg}' (supported={sorted(_SUPPORTED_HASH_ALGS)})")

        disallowed = {a.strip().lower() for a in (self.disallowed_hash_algs or []) if a}
        if self.hash_alg in disallowed:
            raise PolicyError(f"hash_alg '{self.hash_alg}' is disallowed by policy")

        allowed = None
        if self.allowed_hash_algs is not None:
            allowed = {a.strip().lower() for a in self.allowed_hash_algs if a}
            if self.hash_alg not in allowed:
                raise PolicyError(f"hash_alg '{self.hash_alg}' not in allowed_hash_algs={sorted(allowed)}")

        # digest_size constraints
        self.digest_size = int(self.digest_size)
        if not (1 <= self.digest_size <= 32):
            raise PolicyError("digest_size must be in [1, 32] (blake2s constraint)")
        self.min_digest_size = int(self.min_digest_size)
        if self.digest_size < self.min_digest_size and self.hash_alg == "blake2s":
            raise PolicyError(f"digest_size {self.digest_size} below min_digest_size {self.min_digest_size}")

        # strict mode enforcement
        if self.strict_mode:
            # default strict allowlist is conservative / portable
            strict_allowed = [a.strip().lower() for a in (self.allowed_hash_algs or ["sha256", "sha3_256"]) if a]
            if self.hash_alg not in set(strict_allowed):
                raise PolicyError(f"hash_alg '{self.hash_alg}' not allowed in strict_mode; allowed={strict_allowed}")

            if self.require_sig_in_strict:
                if self.sign_func is None or not (self.sig_alg or "").strip():
                    raise PolicyError("strict_mode requires sign_func and sig_alg (require_sig_in_strict=True)")
                if not (self.sig_key_id or "").strip():
                    raise PolicyError("strict_mode requires sig_key_id (key locator for auditors/verifiers)")

            if self.forbid_float_in_strict:
                # enforced in sanitizer
                pass

            # previews are forbidden in strict mode
            self.include_truncation_previews = False

        # signature governance
        if self.sig_alg is not None:
            self.sig_alg = self.sig_alg.strip()
        if self.sig_key_id is not None:
            self.sig_key_id = self.sig_key_id.strip() or None

        if self.allowed_sig_algs is not None:
            self.allowed_sig_algs = sorted({str(a).strip().lower() for a in self.allowed_sig_algs if a})

        self.min_signature_bytes = max(1, int(self.min_signature_bytes))
        self.max_signature_bytes = max(256, int(self.max_signature_bytes))
        if self.min_signature_bytes > self.max_signature_bytes:
            raise PolicyError("min_signature_bytes > max_signature_bytes")

        # secondary hash config
        if self.secondary_hash_alg is not None:
            self.secondary_hash_alg = self.secondary_hash_alg.strip().lower()
            if self.secondary_hash_alg not in _SUPPORTED_HASH_ALGS:
                raise PolicyError(f"unsupported secondary_hash_alg '{self.secondary_hash_alg}'")
            if self.secondary_hash_alg in disallowed:
                raise PolicyError(f"secondary_hash_alg '{self.secondary_hash_alg}' is disallowed by policy")
            if allowed is not None and self.secondary_hash_alg not in allowed:
                raise PolicyError(f"secondary_hash_alg '{self.secondary_hash_alg}' not in allowed_hash_algs={sorted(allowed)}")
            self.secondary_hash_ctx = (self.secondary_hash_ctx or "").strip() or (self.hash_ctx + ":secondary")
            self.secondary_digest_size = int(self.secondary_digest_size)
            if not (1 <= self.secondary_digest_size <= 32):
                raise PolicyError("secondary_digest_size must be in [1,32]")
            if self.secondary_hash_alg == "blake2s" and self.secondary_digest_size < self.min_digest_size:
                raise PolicyError("secondary_digest_size below min_digest_size")

        # bounds normalization
        self.max_json_depth = max(8, int(self.max_json_depth))
        self.max_nodes = max(1_000, int(self.max_nodes))
        self.max_list_items = max(0, int(self.max_list_items))
        self.max_dict_items = max(0, int(self.max_dict_items))
        self.max_string_bytes = max(256, int(self.max_string_bytes))
        self.max_key_bytes = max(64, int(self.max_key_bytes))
        self.max_total_sanitized_bytes = max(8 * 1024, int(self.max_total_sanitized_bytes))

        self.max_witness_segments = max(0, int(self.max_witness_segments))
        self.max_witness_meta_bytes = max(0, int(self.max_witness_meta_bytes))
        self.max_digest_len = max(16, int(self.max_digest_len))
        self.max_witness_id_len = max(16, int(self.max_witness_id_len))

        self.max_tags = max(0, int(self.max_tags))
        self.max_tag_len = max(8, int(self.max_tag_len))

        self.max_body_bytes = max(8 * 1024, int(self.max_body_bytes))

        # budgets: keep as-is; semantics applied in _cap_field (<=0 => no cap)
        self.meta_budget_bytes = int(self.meta_budget_bytes)
        self.req_budget_bytes = int(self.req_budget_bytes)
        self.comp_budget_bytes = int(self.comp_budget_bytes)
        self.e_budget_bytes = int(self.e_budget_bytes)
        self.witness_budget_bytes = int(self.witness_budget_bytes)

        self.truncation_preview_bytes = max(0, int(self.truncation_preview_bytes))

        # identity governance
        self.max_identity_len = max(32, int(self.max_identity_len))
        self.attestor_id = _normalize_id(self.attestor_id, max_len=self.max_identity_len, require_safe=self.require_safe_identity, field="attestor_id")
        if self.proc_id is not None:
            self.proc_id = _normalize_id(self.proc_id, max_len=self.max_identity_len, require_safe=False, field="proc_id")
        for f in ["build_digest", "runtime_env_digest", "hw_root_id", "tpm_quote_digest", "deployment_tier"]:
            v = getattr(self, f)
            if v is not None:
                setattr(self, f, _normalize_id(str(v), max_len=self.max_identity_len, require_safe=False, field=f))

        if self.allowed_deployment_tiers is not None:
            self.allowed_deployment_tiers = sorted({str(x).strip() for x in self.allowed_deployment_tiers if x and str(x).strip()})

        # redact config normalization
        if self.redact_keys is not None:
            self.redact_keys = sorted({str(k).strip().lower() for k in self.redact_keys if k})
        if self.redact_key_patterns is not None:
            self.redact_key_patterns = [str(p) for p in self.redact_key_patterns if p]

        # witness governance normalization
        if self.allowed_witness_kinds is not None:
            ak = [str(k).strip() for k in self.allowed_witness_kinds if k and str(k).strip()]
            for k in ak:
                if k not in ALLOWED_WITNESS_KINDS:
                    raise PolicyError(f"allowed_witness_kinds contains unknown kind '{k}'")
            self.allowed_witness_kinds = sorted(set(ak))
        if self.disallowed_witness_kinds is not None:
            dk = [str(k).strip() for k in self.disallowed_witness_kinds if k and str(k).strip()]
            for k in dk:
                if k not in ALLOWED_WITNESS_KINDS:
                    raise PolicyError(f"disallowed_witness_kinds contains unknown kind '{k}'")
            self.disallowed_witness_kinds = sorted(set(dk))
        if self.allowed_external_ids is not None:
            self.allowed_external_ids = sorted({_normalize_id(x, max_len=128, require_safe=True, field="allowed_external_ids") for x in self.allowed_external_ids if x})

        # tag regex normalization
        if self.tag_regex:
            try:
                re.compile(self.tag_regex)
            except Exception as e:
                raise PolicyError(f"invalid tag_regex: {e}") from e

        # core witness kinds + cardinality
        if self.core_witness_kinds is not None:
            kinds = []
            for k in self.core_witness_kinds:
                ks = (k or "").strip()
                if not ks:
                    continue
                if ks not in ALLOWED_WITNESS_KINDS:
                    raise PolicyError(f"core_witness_kinds contains unknown kind '{ks}'")
                kinds.append(ks)
            self.core_witness_kinds = kinds

        if self.core_witness_kind_cardinality is not None:
            # Validate mapping and normalize kinds.
            norm: Dict[str, Tuple[int, int]] = {}
            for k, mm in self.core_witness_kind_cardinality.items():
                ks = (k or "").strip()
                if ks not in ALLOWED_WITNESS_KINDS:
                    raise PolicyError(f"core_witness_kind_cardinality unknown kind '{ks}'")
                if not isinstance(mm, tuple) or len(mm) != 2:
                    raise PolicyError("core_witness_kind_cardinality values must be (min,max)")
                mn, mx = int(mm[0]), int(mm[1])
                if mn < 0 or mx < 0 or (mx and mn > mx):
                    raise PolicyError(f"invalid cardinality for {ks}: {(mn,mx)}")
                norm[ks] = (mn, mx)
            self.core_witness_kind_cardinality = norm

        # bounded bookkeeping
        self.max_truncated_paths = max(32, int(self.max_truncated_paths))
        self.max_truncation_records = max(32, int(self.max_truncation_records))

        # control meta keys
        if self.allow_control_meta_keys:
            for k in [self.control_meta_event_id_key, self.control_meta_nonce_key, self.control_meta_ts_ns_key]:
                if not k or not isinstance(k, str):
                    raise PolicyError("control meta keys must be non-empty strings")

    def policy_digest(self) -> str:
        """
        Stable digest of the attestor policy.
        Excludes runtime-only bindings (sign_func).
        """
        material: Dict[str, Any] = {
            "hash_alg": self.hash_alg,
            "hash_ctx": self.hash_ctx,
            "digest_size": int(self.digest_size),
            "strict_mode": bool(self.strict_mode),
            "allowed_hash_algs": list(self.allowed_hash_algs or []),
            "disallowed_hash_algs": list(self.disallowed_hash_algs or []),
            "min_digest_size": int(self.min_digest_size),
            "secondary_hash_alg": self.secondary_hash_alg,
            "secondary_hash_ctx": self.secondary_hash_ctx,
            "secondary_digest_size": int(self.secondary_digest_size),
            "attestor_id": self.attestor_id,
            "proc_id": self.proc_id,
            "build_digest": self.build_digest,
            "runtime_env_digest": self.runtime_env_digest,
            "hw_root_id": self.hw_root_id,
            "tpm_quote_digest": self.tpm_quote_digest,
            "deployment_tier": self.deployment_tier,
            "max_identity_len": int(self.max_identity_len),
            "require_safe_identity": bool(self.require_safe_identity),
            "allowed_deployment_tiers": list(self.allowed_deployment_tiers or []),
            "include_policy_block": bool(self.include_policy_block),
            "default_auth_policy": self.default_auth_policy,
            "default_chain_policy": self.default_chain_policy,
            "default_ledger_policy": self.default_ledger_policy,
            "default_cfg_digest": self.default_cfg_digest,
            "sig_alg": self.sig_alg,
            "sig_key_id": self.sig_key_id,
            "allowed_sig_algs": list(self.allowed_sig_algs or []),
            "require_sig_in_strict": bool(self.require_sig_in_strict),
            "min_signature_bytes": int(self.min_signature_bytes),
            "max_signature_bytes": int(self.max_signature_bytes),
            "max_json_depth": int(self.max_json_depth),
            "max_nodes": int(self.max_nodes),
            "max_list_items": int(self.max_list_items),
            "max_dict_items": int(self.max_dict_items),
            "max_string_bytes": int(self.max_string_bytes),
            "max_key_bytes": int(self.max_key_bytes),
            "max_total_sanitized_bytes": int(self.max_total_sanitized_bytes),
            "enforce_nfc": bool(self.enforce_nfc),
            "forbid_float_in_strict": bool(self.forbid_float_in_strict),
            "max_witness_segments": int(self.max_witness_segments),
            "max_witness_meta_bytes": int(self.max_witness_meta_bytes),
            "max_digest_len": int(self.max_digest_len),
            "max_witness_id_len": int(self.max_witness_id_len),
            "allowed_witness_kinds": list(self.allowed_witness_kinds or []),
            "disallowed_witness_kinds": list(self.disallowed_witness_kinds or []),
            "forbid_other_in_strict": bool(self.forbid_other_in_strict),
            "allowed_external_ids": list(self.allowed_external_ids or []),
            "canonicalize_witness_segments_order": bool(self.canonicalize_witness_segments_order),
            "max_tags": int(self.max_tags),
            "max_tag_len": int(self.max_tag_len),
            "tag_regex": self.tag_regex,
            "max_body_bytes": int(self.max_body_bytes),
            "meta_budget_bytes": int(self.meta_budget_bytes),
            "req_budget_bytes": int(self.req_budget_bytes),
            "comp_budget_bytes": int(self.comp_budget_bytes),
            "e_budget_bytes": int(self.e_budget_bytes),
            "witness_budget_bytes": int(self.witness_budget_bytes),
            "include_truncation_previews": bool(self.include_truncation_previews),
            "truncation_preview_bytes": int(self.truncation_preview_bytes),
            "redact_keys": list(self.redact_keys or []),
            "redact_key_patterns": list(self.redact_key_patterns or []),
            "enable_value_redaction": bool(self.enable_value_redaction),
            "redact_value": self.redact_value,
            "allow_control_meta_keys": bool(self.allow_control_meta_keys),
            "control_meta_event_id_key": self.control_meta_event_id_key,
            "control_meta_nonce_key": self.control_meta_nonce_key,
            "control_meta_ts_ns_key": self.control_meta_ts_ns_key,
            "deterministic_nonce_from_event_id": bool(self.deterministic_nonce_from_event_id),
            "allow_custom_nonce": bool(self.allow_custom_nonce),
            "allow_custom_ts_ns": bool(self.allow_custom_ts_ns),
            "max_truncated_paths": int(self.max_truncated_paths),
            "max_truncation_records": int(self.max_truncation_records),
            "self_check": bool(self.self_check),
            "self_check_strict_structure": bool(self.self_check_strict_structure),
            "self_check_require_canonical": bool(self.self_check_require_canonical),
            "core_witness_kinds": list(self.core_witness_kinds or []),
            "core_witness_kind_cardinality": dict(self.core_witness_kind_cardinality or {}),
        }
        return canonical_kv_hash(material, ctx="tcd:attestor_policy", label="attestor_policy")


# ---------------------------------------------------------------------------
# Canonical JSON + hashing (domain-separated)
# ---------------------------------------------------------------------------


def _canonical_json_bytes(obj: Any) -> bytes:
    """
    Canonical JSON bytes: deterministic for Python and compatible with JCS subset:
    - sort_keys
    - compact separators
    - UTF-8
    - allow_nan=False
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _hash_bytes(data: bytes, *, alg: str, ctx: str, digest_size: int) -> str:
    """
    Hash with explicit domain separation.
    Domain separation scheme is LOCKED:
        payload = ctx_utf8 || 0x1f || data
    """
    alg = (alg or "").lower().strip() or "blake3"
    payload = ctx.encode("utf-8") + b"\x1f" + data

    if alg == "sha256":
        return hashlib.sha256(payload).hexdigest()
    if alg == "sha3_256":
        return hashlib.sha3_256(payload).hexdigest()
    if alg == "blake2s":
        h = hashlib.blake2s(digest_size=int(digest_size))
        h.update(payload)
        return h.hexdigest()
    if alg == "blake3":
        # Prefer a single backend to avoid ctx semantics drift.
        try:
            from .crypto import Blake3Hash  # type: ignore

            # Blake3Hash is assumed to implement raw BLAKE3; we pass ctx-separated payload ourselves.
            return Blake3Hash().hex(payload, ctx="tcd:blake3_raw")
        except Exception as e:
            # If blake3 is configured but backend missing, fail hard (portable verification).
            raise PolicyError(f"blake3 backend unavailable: {e}") from e

    # should not happen due to config validation
    h = hashlib.blake2s(digest_size=int(digest_size))
    h.update(payload)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Helpers: identity normalization & safe previews
# ---------------------------------------------------------------------------


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def _normalize_id(s: str, *, max_len: int, require_safe: bool, field: str) -> str:
    ss = (s or "").strip()
    if not ss:
        return ""
    if len(ss) > max_len:
        ss = ss[:max_len]
    ss = _nfc(ss)
    if require_safe and ss and not _SAFE_ASCII_ID_RE.match(ss):
        raise PolicyError(f"{field} contains unsafe characters")
    # remove control characters even if not strict safe-ascii
    ss = "".join(ch for ch in ss if ch >= " " or ch in ("\t", "\n", "\r"))
    return ss


def _safe_preview(obj: Any, *, max_bytes: int) -> Dict[str, Any]:
    """
    Safe preview that does NOT expose raw values.
    """
    try:
        if isinstance(obj, dict):
            keys = list(obj.keys())
            # keys may be non-str; stringify safely
            sk = [str(k)[:64] for k in keys[:50]]
            preview = {"type": "dict", "keys": sk, "n_keys": len(keys)}
        elif isinstance(obj, list):
            preview = {"type": "list", "n_items": len(obj)}
        else:
            preview = {"type": type(obj).__name__}
        b = _canonical_json_bytes(preview)
        if len(b) > max_bytes > 0:
            return {"type": preview.get("type"), "truncated": True}
        return preview
    except Exception:
        return {"type": "unknown"}


# ---------------------------------------------------------------------------
# JSON safety / normalization (cycle guard + key/value budgets + NFC + redaction)
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _BoundedLog:
    max_items: int
    items: Deque[Dict[str, Any]] = dataclasses.field(default_factory=deque)
    dropped: int = 0

    def add(self, rec: Dict[str, Any]) -> None:
        if self.max_items <= 0:
            return
        if len(self.items) >= self.max_items:
            self.items.popleft()
            self.dropped += 1
        self.items.append(rec)

    def to_list(self) -> List[Dict[str, Any]]:
        out = list(self.items)
        if self.dropped:
            out.append({"_tcd_dropped": self.dropped})
        return out


@dataclasses.dataclass
class _SanitizeState:
    cfg: AttestorConfig
    redact_exact: Set[str]
    redact_patterns: List[re.Pattern]
    tag_re: re.Pattern
    hooks: Optional[AttestorHooks]
    nodes: int = 0
    bytes_seen: int = 0  # approximate size budget
    stack: Set[int] = dataclasses.field(default_factory=set)
    truncated_paths: Deque[str] = dataclasses.field(default_factory=deque)
    truncated_paths_dropped: int = 0
    trunc_records: _BoundedLog = dataclasses.field(default_factory=lambda: _BoundedLog(256))
    redactions: _BoundedLog = dataclasses.field(default_factory=lambda: _BoundedLog(256))

    def bump(self) -> None:
        self.nodes += 1
        if self.nodes > self.cfg.max_nodes:
            raise SerializationError(f"object graph too large (nodes>{self.cfg.max_nodes})")

    def bump_bytes(self, n: int) -> None:
        self.bytes_seen += max(0, int(n))
        if self.bytes_seen > self.cfg.max_total_sanitized_bytes:
            raise SerializationError(f"sanitized bytes budget exceeded ({self.bytes_seen}>{self.cfg.max_total_sanitized_bytes})")

    def record_path(self, path: str) -> None:
        if len(self.truncated_paths) >= self.cfg.max_truncated_paths:
            self.truncated_paths.popleft()
            self.truncated_paths_dropped += 1
        self.truncated_paths.append(path)

    def record_trunc(self, rec: Dict[str, Any]) -> None:
        self.trunc_records.max_items = self.cfg.max_truncation_records
        self.trunc_records.add(rec)
        if self.hooks and self.hooks.on_truncate:
            try:
                self.hooks.on_truncate("truncate", rec)
            except Exception:
                pass

    def record_redact(self, rec: Dict[str, Any]) -> None:
        self.redactions.max_items = self.cfg.max_truncation_records
        self.redactions.add(rec)
        if self.hooks and self.hooks.on_redact:
            try:
                self.hooks.on_redact("redact", rec)
            except Exception:
                pass


def _is_json_primitive(x: Any) -> bool:
    return x is None or isinstance(x, (bool, int, str))


def _looks_like_secret_value(s: str) -> bool:
    if not s:
        return False
    if _BEARER_RE.match(s):
        return True
    if _PEM_RE.search(s):
        return True
    if _JWT_RE.match(s.strip()):
        return True
    if len(s) >= 120 and _BASE64ISH_RE.match(s.strip()):
        return True
    return False


def _normalize_key(ks: str, *, st: _SanitizeState) -> str:
    cfg = st.cfg
    ks = _nfc(ks) if cfg.enforce_nfc else ks
    kb = ks.encode("utf-8", errors="replace")
    st.bump_bytes(len(kb))
    if len(kb) <= cfg.max_key_bytes:
        return ks

    # Overlong key: strict rejects; non-strict truncates deterministically with hash suffix.
    if cfg.strict_mode:
        raise SerializationError("dict key exceeds max_key_bytes in strict_mode")

    digest = hashlib.sha256(kb).hexdigest()[:12]
    prefix_bytes = kb[: max(8, cfg.max_key_bytes - 16)]
    prefix = prefix_bytes.decode("utf-8", errors="replace")
    new_key = f"{prefix}~{digest}"
    st.record_path("key:" + digest)
    st.record_trunc({"path": "dict_key", "reason": "key_too_large", "bytes": len(kb), "digest": digest})
    return new_key


def _child_path(parent: str, child: str) -> str:
    if not parent:
        return child
    # Avoid path explosion (truncate)
    out = f"{parent}.{child}"
    if len(out) > 256:
        return out[:252] + "..."
    return out


def _to_jsonable(x: Any, *, st: _SanitizeState, path: str, depth: int) -> Any:
    st.bump()
    cfg = st.cfg

    if depth > cfg.max_json_depth:
        st.record_path(path or "$")
        st.record_trunc({"path": path or "$", "reason": "max_depth"})
        return {"_tcd_truncated": True, "reason": "max_depth"}

    # primitives
    if _is_json_primitive(x):
        if isinstance(x, str):
            s = _nfc(x) if cfg.enforce_nfc else x
            sb = s.encode("utf-8", errors="replace")
            st.bump_bytes(len(sb))
            # value-based redaction
            if cfg.enable_value_redaction and _looks_like_secret_value(s):
                st.record_redact({"path": path or "$", "reason": "value_pattern"})
                return cfg.redact_value
            if len(sb) > cfg.max_string_bytes:
                st.record_path(path or "$")
                st.record_trunc({"path": path or "$", "reason": "string_too_large", "bytes": len(sb)})
                if cfg.strict_mode:
                    raise SerializationError("string exceeds max_string_bytes in strict_mode")
                # digest-only wrapper (no preview of raw bytes)
                return {"_tcd_truncated": True, "reason": "string_too_large", "bytes": len(sb)}
            return s
        return x

    # floats
    if isinstance(x, float):
        if not math.isfinite(x):
            st.record_path(path or "$")
            st.record_trunc({"path": path or "$", "reason": "nonfinite_float"})
            if cfg.strict_mode:
                raise SerializationError("non-finite float not allowed in strict_mode")
            return {"_tcd_nonfinite_float": True, "val": str(x)}
        if cfg.strict_mode and cfg.forbid_float_in_strict:
            raise SerializationError("float not allowed in strict_mode")
        # non-strict: encode float as tagged string wrapper to avoid cross-language ambiguity
        # Use a stable formatting; still not perfect across languages, but explicit wrapper makes it a string.
        s = format(x, ".17g")
        s = _nfc(s) if cfg.enforce_nfc else s
        st.bump_bytes(len(s.encode("utf-8", errors="replace")))
        return {"_tcd_float": s}

    # bytes-like
    if isinstance(x, (bytes, bytearray, memoryview)):
        if cfg.strict_mode:
            raise SerializationError("bytes-like value not allowed in strict_mode")
        b = bytes(x)
        st.bump_bytes(len(b))
        # Always digest-wrapper by default (safer + avoids base64 explosion)
        d = _hash_bytes(b, alg=cfg.hash_alg, ctx="tcd:attest:bytes", digest_size=cfg.digest_size)
        st.record_trunc({"path": path or "$", "reason": "bytes_digest_only", "bytes": len(b), "digest": d})
        return {"_tcd_bytes": True, "digest": d, "bytes": len(b)}

    # cycle guard for containers / objects
    obj_id = id(x)
    if obj_id in st.stack:
        st.record_path(path or "$")
        st.record_trunc({"path": path or "$", "reason": "cycle"})
        if cfg.strict_mode:
            raise SerializationError("cycle detected in strict_mode")
        return {"_tcd_cycle": True}

    # mappings
    if isinstance(x, Mapping):
        st.stack.add(obj_id)
        try:
            out: Dict[str, Any] = {}
            # Headers-like structure detection: if keys resemble headers, enforce redaction for auth-like keys.
            # (still handled by key-based exact/pattern checks below)
            n = 0
            total = len(x) if hasattr(x, "__len__") else None
            for k, v in x.items():
                n += 1
                if cfg.max_dict_items and n > cfg.max_dict_items:
                    omitted = (total - cfg.max_dict_items) if (total is not None and total >= cfg.max_dict_items) else None
                    st.record_path(path or "$")
                    st.record_trunc({"path": path or "$", "reason": "dict_items_limit", "limit": cfg.max_dict_items, "omitted": omitted})
                    break
                ks = _normalize_key(str(k), st=st)
                child_path = _child_path(path, ks) if path else ks
                k_lower = ks.strip().lower()

                # key-based exact/pattern redaction
                if k_lower in st.redact_exact or any(p.search(k_lower) for p in st.redact_patterns):
                    st.record_redact({"path": child_path or "$", "reason": "key_match", "key": ks[:64]})
                    out[ks] = cfg.redact_value
                else:
                    out[ks] = _to_jsonable(v, st=st, path=child_path, depth=depth + 1)
            return out
        finally:
            st.stack.discard(obj_id)

    # dataclasses
    if dataclasses.is_dataclass(x):
        st.stack.add(obj_id)
        try:
            out = {}
            for f in dataclasses.fields(x):
                name = _normalize_key(str(f.name), st=st)
                child_path = _child_path(path, name) if path else name
                name_l = name.strip().lower()
                if name_l in st.redact_exact or any(p.search(name_l) for p in st.redact_patterns):
                    st.record_redact({"path": child_path or "$", "reason": "key_match", "key": name[:64]})
                    out[name] = cfg.redact_value
                else:
                    out[name] = _to_jsonable(getattr(x, f.name), st=st, path=child_path, depth=depth + 1)
            return out
        finally:
            st.stack.discard(obj_id)

    # pydantic v2/v1 models
    if hasattr(x, "model_dump") and callable(getattr(x, "model_dump")):
        st.stack.add(obj_id)
        try:
            return _to_jsonable(x.model_dump(), st=st, path=path, depth=depth + 1)
        except Exception as e:
            raise SerializationError(f"failed model_dump at {path or '$'}: {e}") from e
        finally:
            st.stack.discard(obj_id)

    if hasattr(x, "dict") and callable(getattr(x, "dict")):
        st.stack.add(obj_id)
        try:
            return _to_jsonable(x.dict(), st=st, path=path, depth=depth + 1)
        except Exception as e:
            raise SerializationError(f"failed dict() at {path or '$'}: {e}") from e
        finally:
            st.stack.discard(obj_id)

    # list/tuple
    if isinstance(x, (list, tuple)):
        st.stack.add(obj_id)
        try:
            out_list: List[Any] = []
            total = len(x)
            for i, v in enumerate(x):
                if cfg.max_list_items and i >= cfg.max_list_items:
                    omitted = total - cfg.max_list_items
                    st.record_path(path or "$")
                    st.record_trunc({"path": path or "$", "reason": "list_items_limit", "limit": cfg.max_list_items, "omitted": omitted})
                    break
                child_path = f"{path}[{i}]" if path else f"[{i}]"
                out_list.append(_to_jsonable(v, st=st, path=child_path, depth=depth + 1))
            return out_list
        finally:
            st.stack.discard(obj_id)

    # set/frozenset: stable ordering by canonical bytes of sanitized elements
    if isinstance(x, (set, frozenset)):
        if cfg.strict_mode:
            # set ordering semantics are ambiguous; require caller to pass list/tuple in strict mode
            raise SerializationError("set/frozenset not allowed in strict_mode")
        st.stack.add(obj_id)
        try:
            elems = list(x)
            if cfg.max_list_items and len(elems) > cfg.max_list_items:
                st.record_path(path or "$")
                st.record_trunc({"path": path or "$", "reason": "set_items_limit", "limit": cfg.max_list_items, "omitted": len(elems) - cfg.max_list_items})
                elems = elems[: cfg.max_list_items]
            sanitized_elems: List[Tuple[bytes, Any]] = []
            for i, v in enumerate(elems):
                child_path = f"{path}[{i}]" if path else f"[{i}]"
                sv = _to_jsonable(v, st=st, path=child_path, depth=depth + 1)
                sb = _canonical_json_bytes(sv)
                sanitized_elems.append((sb, sv))
            sanitized_elems.sort(key=lambda t: t[0])
            return [sv for _, sv in sanitized_elems]
        finally:
            st.stack.discard(obj_id)

    # unknown type: strict rejects; non-strict opaque digest wrapper (no repr leak)
    if cfg.strict_mode:
        raise SerializationError(f"unsupported type at {path or '$'}: {type(x).__name__}")

    type_name = type(x).__name__
    # normalize repr to reduce nondeterminism & avoid leaking raw content
    try:
        r = repr(x)
        r = _REPR_ADDR_RE.sub("0x?", r)
        r = _nfc(r) if cfg.enforce_nfc else r
        if cfg.enable_value_redaction and _looks_like_secret_value(r):
            r = cfg.redact_value
        rb = r.encode("utf-8", errors="replace")
    except Exception:
        rb = type_name.encode("utf-8", errors="replace")
    d = _hash_bytes(rb, alg=cfg.hash_alg, ctx="tcd:attest:opaque", digest_size=cfg.digest_size)
    st.record_trunc({"path": path or "$", "reason": "opaque_type", "type": type_name, "digest": d, "bytes": len(rb)})
    return {"_tcd_opaque": True, "type": type_name, "digest": d, "bytes": len(rb)}


def _sanitize_obj(x: Any, *, cfg: AttestorConfig, path: str) -> Tuple[Any, Dict[str, Any]]:
    # compile redaction patterns once per sanitize call
    redact_exact = {k.strip().lower() for k in (cfg.redact_keys or []) if k}
    patterns = []
    for p in (cfg.redact_key_patterns or []):
        try:
            patterns.append(re.compile(p, re.IGNORECASE))
        except Exception:
            continue
    tag_re = re.compile(cfg.tag_regex, re.IGNORECASE) if cfg.tag_regex else _DEFAULT_TAG_RE

    st = _SanitizeState(
        cfg=cfg,
        redact_exact=redact_exact,
        redact_patterns=patterns,
        tag_re=tag_re,
        hooks=cfg.hooks,
    )
    st.trunc_records.max_items = cfg.max_truncation_records
    st.redactions.max_items = cfg.max_truncation_records

    out = _to_jsonable(x, st=st, path=path, depth=0)

    info = {
        "truncated_paths": list(st.truncated_paths) + ([f"...(+{st.truncated_paths_dropped} more)"] if st.truncated_paths_dropped else []),
        "truncations": st.trunc_records.to_list(),
        "redactions": st.redactions.to_list(),
        "nodes": st.nodes,
        "bytes_seen": st.bytes_seen,
    }
    return out, info


# ---------------------------------------------------------------------------
# Digest wrappers (include ctx/alg/digest_size for offline reproduction)
# ---------------------------------------------------------------------------


def _digest_wrapper(
    *,
    cfg: AttestorConfig,
    data_bytes: bytes,
    ctx: str,
    reason: str,
    extra: Optional[Dict[str, Any]] = None,
    preview_obj: Optional[Any] = None,
) -> Dict[str, Any]:
    d = _hash_bytes(data_bytes, alg=cfg.hash_alg, ctx=ctx, digest_size=cfg.digest_size)
    w: Dict[str, Any] = {
        "_tcd_truncated": True,
        "reason": reason,
        "ctx": ctx,
        "alg": cfg.hash_alg,
        "digest_size": int(cfg.digest_size),
        "digest": d,
        "bytes": int(len(data_bytes)),
    }
    if extra:
        w.update(extra)

    # Safe previews only (keys/shape); strict_mode always disables previews.
    if (not cfg.strict_mode) and cfg.include_truncation_previews and cfg.truncation_preview_bytes > 0:
        w["preview"] = _safe_preview(preview_obj if preview_obj is not None else {}, max_bytes=cfg.truncation_preview_bytes)

    return w


def _cap_field(
    obj: Any,
    *,
    cfg: AttestorConfig,
    budget_bytes: int,
    ctx: str,
    path: str,
) -> Tuple[Any, Optional[Dict[str, Any]]]:
    """
    Per-field budget enforcement:
      - budget_bytes <= 0 means "no cap" (per your requirement 9.1)
      - if capped, return digest wrapper that includes ctx/alg/digest_size
    """
    if budget_bytes <= 0:
        return obj, None

    b = _canonical_json_bytes(obj)
    if len(b) <= budget_bytes:
        return obj, None

    w = _digest_wrapper(cfg=cfg, data_bytes=b, ctx=ctx, reason="field_budget", extra={"path": path}, preview_obj=obj)
    return w, {"path": path, "bytes": len(b), "digest": w.get("digest"), "ctx": ctx}


# ---------------------------------------------------------------------------
# Witness normalization (governed + bounded + optional canonical order)
# ---------------------------------------------------------------------------


def _validate_digest_str(d: Any, *, cfg: AttestorConfig, field: str) -> str:
    if not isinstance(d, str) or not d:
        raise WitnessError(f"{field} must be a non-empty string")
    if len(d) > cfg.max_digest_len:
        raise WitnessError(f"{field} too long (>{cfg.max_digest_len})")
    # allow hex or safe-id ascii
    if not (_HEX_RE.match(d) or _SAFE_ASCII_ID_RE.match(d)):
        raise WitnessError(f"{field} contains unsafe characters")
    return d


def _validate_id_str(s: Any, *, cfg: AttestorConfig, field: str) -> str:
    if s is None:
        return ""
    ss = str(s)
    ss = _nfc(ss) if cfg.enforce_nfc else ss
    if len(ss) > cfg.max_witness_id_len:
        if cfg.strict_mode:
            raise WitnessError(f"{field} too long in strict_mode")
        ss = ss[: cfg.max_witness_id_len]
    if ss and not _SAFE_ASCII_ID_RE.match(ss):
        raise WitnessError(f"{field} contains unsafe characters")
    return ss


def _normalize_tags(tags: Optional[Iterable[str]], *, cfg: AttestorConfig) -> List[str]:
    if not tags:
        return []
    tag_re = re.compile(cfg.tag_regex, re.IGNORECASE) if cfg.tag_regex else _DEFAULT_TAG_RE

    uniq: List[str] = []
    seen = set()
    for t in tags:
        if t is None:
            continue
        ts = str(t).strip()
        if not ts:
            continue
        ts = _nfc(ts) if cfg.enforce_nfc else ts
        if len(ts) > cfg.max_tag_len:
            if cfg.strict_mode:
                raise WitnessError("tag too long in strict_mode")
            ts = ts[: cfg.max_tag_len]
        # charset constraint
        if not tag_re.match(ts.lower()):
            if cfg.strict_mode:
                raise WitnessError("tag contains unsafe characters in strict_mode")
            # non-strict: replace with digest tag
            td = hashlib.sha256(ts.encode("utf-8", errors="replace")).hexdigest()[:16]
            ts = f"tag_digest:{td}"
        if ts not in seen:
            uniq.append(ts)
            seen.add(ts)

    uniq_sorted = sorted(uniq)
    if cfg.max_tags and len(uniq_sorted) > cfg.max_tags:
        if cfg.strict_mode:
            raise WitnessError("too many tags in strict_mode")
        uniq_sorted = uniq_sorted[: cfg.max_tags]
    return uniq_sorted


def _normalize_segments(segments: Optional[Sequence[Any]], *, cfg: AttestorConfig) -> List[Dict[str, Any]]:
    if not segments:
        return []
    if cfg.max_witness_segments and len(segments) > cfg.max_witness_segments:
        raise WitnessError(f"too many witness segments (>{cfg.max_witness_segments})")

    allowed = set(cfg.allowed_witness_kinds) if cfg.allowed_witness_kinds else None
    disallowed = set(cfg.disallowed_witness_kinds) if cfg.disallowed_witness_kinds else set()
    out: List[Dict[str, Any]] = []

    for i, s in enumerate(segments):
        if not isinstance(s, dict):
            raise WitnessError("witness segment must be a dict")

        kind = str(s.get("kind") or "").strip()
        if not kind:
            raise WitnessError("witness segment missing 'kind'")
        if kind not in ALLOWED_WITNESS_KINDS:
            raise WitnessError(f"witness kind '{kind}' not in allowed set")
        if allowed is not None and kind not in allowed:
            raise WitnessError(f"witness kind '{kind}' not allowed by policy")
        if kind in disallowed:
            raise WitnessError(f"witness kind '{kind}' is disallowed by policy")
        if cfg.strict_mode and cfg.forbid_other_in_strict and kind == "other":
            raise WitnessError("witness kind 'other' forbidden in strict_mode")

        digest_s = _validate_digest_str(s.get("digest"), cfg=cfg, field="witness.segment.digest")
        seg_id_s = _validate_id_str(s.get("id"), cfg=cfg, field="witness.segment.id")

        # strict external governance
        if kind == "external":
            if cfg.strict_mode:
                if not seg_id_s:
                    raise WitnessError("external witness requires non-empty id in strict_mode")
                if cfg.allowed_external_ids is not None and seg_id_s not in set(cfg.allowed_external_ids):
                    raise WitnessError("external witness id not in allowlist")

        meta = s.get("meta") or {}
        if meta is None:
            meta = {}
        if not isinstance(meta, dict):
            raise WitnessError("witness.segment.meta must be a dict if provided")

        # sanitize meta (bounded)
        meta_s, meta_info = _sanitize_obj(meta, cfg=cfg, path=f"witness[{i}].meta")
        meta_bytes = _canonical_json_bytes(meta_s)
        if cfg.max_witness_meta_bytes and len(meta_bytes) > cfg.max_witness_meta_bytes:
            if cfg.strict_mode:
                raise WitnessError("witness.meta too large in strict_mode")
            meta_s = _digest_wrapper(
                cfg=cfg,
                data_bytes=meta_bytes,
                ctx="tcd:attest:witness_meta",
                reason="witness_meta_budget",
                extra={"path": f"witness[{i}].meta"},
                preview_obj=meta_s,
            )

        seg_obj = {"kind": kind, "id": seg_id_s, "digest": digest_s, "meta": meta_s}

        # if the caller injected unknown keys, keep them out to avoid schema pollution
        out.append(seg_obj)

    # optional canonical order for dedupe stability
    if cfg.canonicalize_witness_segments_order:
        def _seg_sort_key(seg: Dict[str, Any]) -> Tuple[str, str, str, str]:
            mb = _canonical_json_bytes(seg.get("meta", {}))
            md = hashlib.sha256(mb).hexdigest()
            return (str(seg.get("kind") or ""), str(seg.get("id") or ""), str(seg.get("digest") or ""), md)

        out.sort(key=_seg_sort_key)

    return out


def _enforce_core_witness_requirements(segments: List[Dict[str, Any]], *, cfg: AttestorConfig) -> None:
    if cfg.core_witness_kinds:
        present = {seg["kind"] for seg in segments}
        missing = [k for k in cfg.core_witness_kinds if k not in present]
        if missing:
            raise WitnessError(f"missing required witness kinds: {missing}")

    if cfg.core_witness_kind_cardinality:
        counts: Dict[str, int] = {}
        for seg in segments:
            counts[seg["kind"]] = counts.get(seg["kind"], 0) + 1
        for kind, (mn, mx) in cfg.core_witness_kind_cardinality.items():
            c = counts.get(kind, 0)
            if c < mn:
                raise WitnessError(f"witness kind '{kind}' below min cardinality {mn} (got {c})")
            if mx and c > mx:
                raise WitnessError(f"witness kind '{kind}' above max cardinality {mx} (got {c})")


# ---------------------------------------------------------------------------
# Control meta keys extraction (idempotent retry support)
# ---------------------------------------------------------------------------


def _extract_control_meta(meta: Dict[str, Any], *, cfg: AttestorConfig) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Extract optional control keys from meta and remove them before embedding:
      - event_id (string)
      - nonce (hex)
      - ts_ns (int)
    """
    if not cfg.allow_control_meta_keys or not isinstance(meta, dict):
        return meta, {}

    meta2 = dict(meta)  # shallow copy
    out: Dict[str, Any] = {}

    def _pop(k: str) -> Any:
        if k in meta2:
            return meta2.pop(k)
        return None

    ev = _pop(cfg.control_meta_event_id_key)
    nn = _pop(cfg.control_meta_nonce_key)
    ts = _pop(cfg.control_meta_ts_ns_key)

    if ev is not None:
        evs = str(ev).strip()
        evs = _nfc(evs) if cfg.enforce_nfc else evs
        if len(evs) > 128:
            evs = evs[:128]
        if cfg.strict_mode and not _SAFE_ASCII_ID_RE.match(evs):
            raise SerializationError("event_id contains unsafe characters in strict_mode")
        out["event_id"] = evs

    if nn is not None:
        nns = str(nn).strip().lower()
        if cfg.strict_mode and not cfg.allow_custom_nonce:
            raise SerializationError("custom nonce not allowed in strict_mode by policy")
        if not re.fullmatch(r"[0-9a-f]{16,128}", nns):
            raise SerializationError("invalid custom nonce format")
        out["nonce"] = nns

    if ts is not None:
        if cfg.strict_mode and not cfg.allow_custom_ts_ns:
            raise SerializationError("custom ts_ns not allowed in strict_mode by policy")
        try:
            tsi = int(ts)
        except Exception as e:
            raise SerializationError(f"invalid ts_ns: {e}") from e
        if tsi <= 0:
            raise SerializationError("ts_ns must be positive")
        out["ts_ns"] = tsi

    return meta2, out


def _derive_nonce_from_event_id(event_id: str) -> str:
    h = hashlib.sha256()
    h.update(b"tcd:attest:nonce\x1f")
    h.update(event_id.encode("utf-8", errors="replace"))
    return h.hexdigest()[:32]


# ---------------------------------------------------------------------------
# Attestor
# ---------------------------------------------------------------------------


class Attestor:
    """
    Structured attestation generator.

    Returns (required keys):
      - receipt      : head hash (hex)
      - receipt_body : canonical JSON body string
      - receipt_sig  : integrity hash SHA-256("tcd:attest_sig" || head || body_bytes)
      - verify_key   : verification-key handle (sig_key_id preferred)

    Additional (optional) keys may be returned when configured:
      - receipt_secondary / receipt_sig_secondary (hash migration)
      - receipt_integrity (string descriptor)
    """

    def __init__(self, hash_alg: str = "blake3", *, cfg: Optional[AttestorConfig] = None):
        if cfg is None:
            cfg = AttestorConfig(hash_alg=hash_alg)
        self._cfg = cfg
        self.hash_alg = cfg.hash_alg  # backward-compat

        # cache policy digest (pure)
        self._policy_digest = cfg.policy_digest()

    def issue(
        self,
        *,
        req_obj: Any,
        comp_obj: Any,
        e_obj: Any,
        witness_segments: Optional[Sequence[Any]],
        witness_tags: Optional[Iterable[str]],
        meta: Dict[str, Any],
    ) -> Dict[str, Any]:
        cfg = self._cfg

        # 1) control meta extraction (idempotency), without leaking control keys into receipt
        meta_in = meta or {}
        if cfg.normalize_meta:
            try:
                meta_in = cfg.normalize_meta(meta_in)
            except Exception as e:
                raise SerializationError(f"normalize_meta failed: {e}") from e
        meta_clean, ctrl = _extract_control_meta(meta_in, cfg=cfg)

        # 2) select ts_ns / nonce deterministically if requested
        ts_ns = int(ctrl.get("ts_ns") or time.time_ns())
        if "nonce" in ctrl:
            nonce = str(ctrl["nonce"])
        else:
            ev = str(ctrl.get("event_id") or "")
            if ev and cfg.deterministic_nonce_from_event_id:
                nonce = _derive_nonce_from_event_id(ev)
            else:
                nonce = secrets.token_hex(16)

        # 3) normalize other objects (hooks)
        try:
            req_in = cfg.normalize_req(req_obj) if cfg.normalize_req else req_obj
            comp_in = cfg.normalize_comp(comp_obj) if cfg.normalize_comp else comp_obj
            e_in = cfg.normalize_e(e_obj) if cfg.normalize_e else e_obj
        except Exception as e:
            raise SerializationError(f"normalization hook failed: {e}") from e

        # 4) sanitize + bound all objects
        req_s, req_info = _sanitize_obj(req_in, cfg=cfg, path="req")
        comp_s, comp_info = _sanitize_obj(comp_in, cfg=cfg, path="comp")
        e_s, e_info = _sanitize_obj(e_in, cfg=cfg, path="e")
        meta_s, meta_info = _sanitize_obj(meta_clean, cfg=cfg, path="meta")

        # 5) witness normalize + governance
        segments_full = _normalize_segments(witness_segments, cfg=cfg)
        _enforce_core_witness_requirements(segments_full, cfg=cfg)
        tags = _normalize_tags(witness_tags, cfg=cfg)

        # 6) per-field cap (<=0 means no cap)
        truncations: List[Dict[str, Any]] = []
        meta_cap, tr = _cap_field(meta_s, cfg=cfg, budget_bytes=cfg.meta_budget_bytes, ctx="tcd:attest:meta", path="meta")
        if tr:
            truncations.append(tr)
        req_cap, tr = _cap_field(req_s, cfg=cfg, budget_bytes=cfg.req_budget_bytes, ctx="tcd:attest:req", path="req")
        if tr:
            truncations.append(tr)
        comp_cap, tr = _cap_field(comp_s, cfg=cfg, budget_bytes=cfg.comp_budget_bytes, ctx="tcd:attest:comp", path="comp")
        if tr:
            truncations.append(tr)
        e_cap, tr = _cap_field(e_s, cfg=cfg, budget_bytes=cfg.e_budget_bytes, ctx="tcd:attest:e", path="e")
        if tr:
            truncations.append(tr)

        # 7) witness budget (if over, deterministic prefix + full digest info)
        segments = segments_full
        witness_full_info: Optional[Dict[str, Any]] = None
        if cfg.witness_budget_bytes > 0:
            full_bytes = _canonical_json_bytes({"segments": segments_full})
            if len(full_bytes) > cfg.witness_budget_bytes:
                if cfg.strict_mode:
                    raise WitnessError("witness segments exceed witness_budget_bytes in strict_mode")
                full_digest = _hash_bytes(full_bytes, alg=cfg.hash_alg, ctx="tcd:attest:witness_full", digest_size=cfg.digest_size)
                keep_n = min(len(segments_full), max(1, min(16, cfg.max_witness_segments or 16)))
                segments = segments_full[:keep_n]
                witness_full_info = {"ctx": "tcd:attest:witness_full", "alg": cfg.hash_alg, "digest_size": int(cfg.digest_size), "digest": full_digest, "count": len(segments_full), "bytes": len(full_bytes)}
                truncations.append({"path": "witness.segments", "bytes": len(full_bytes), "digest": full_digest, "ctx": "tcd:attest:witness_full"})

        # 8) compute witness digest over EMBEDDED segments
        segments_json = _canonical_json_bytes({"segments": segments})
        witness_digest = _hash_bytes(segments_json, alg=cfg.hash_alg, ctx="tcd:attest:witness", digest_size=cfg.digest_size)

        # 9) build attestor block (include policy digest, supply chain anchors, hash migration info)
        attestor_block: Dict[str, Any] = {
            "id": cfg.attestor_id,
            "proc_id": cfg.proc_id,
            "policy_digest": self._policy_digest,
            "build_digest": cfg.build_digest,
            "hw_root_id": cfg.hw_root_id,
            "strict": bool(cfg.strict_mode),
            "hash_alg": cfg.hash_alg,
            "hash_ctx": cfg.hash_ctx,
            "digest_size": int(cfg.digest_size),
            "deployment_tier": cfg.deployment_tier,
        }
        if cfg.secondary_hash_alg:
            attestor_block["hash_secondary_alg"] = cfg.secondary_hash_alg
            attestor_block["hash_secondary_ctx"] = cfg.secondary_hash_ctx
            attestor_block["hash_secondary_digest_size"] = int(cfg.secondary_digest_size)

        # 10) embedded policy block
        policy_block: Dict[str, Any] = {}
        if cfg.include_policy_block:
            if cfg.default_auth_policy:
                policy_block["auth_policy"] = cfg.default_auth_policy
            if cfg.default_chain_policy:
                policy_block["chain_policy"] = cfg.default_chain_policy
            if cfg.default_ledger_policy:
                policy_block["ledger_policy"] = cfg.default_ledger_policy
            if cfg.default_cfg_digest:
                policy_block["cfg_digest"] = cfg.default_cfg_digest
            if cfg.runtime_env_digest:
                policy_block["runtime_env_digest"] = cfg.runtime_env_digest
            if cfg.tpm_quote_digest:
                policy_block["tpm_quote_digest"] = cfg.tpm_quote_digest

        # 11) build body (FINAL semantic content before signature)
        body_obj: Dict[str, Any] = {
            "v": 1,
            "ts_ns": int(ts_ns),
            "nonce": nonce,
            "attestor": attestor_block,
            "meta": meta_cap,
            "req": req_cap,
            "comp": comp_cap,
            "e": e_cap,
            "witness": {
                "segments": segments,
                "digest": witness_digest,
                "tags": tags,
            },
        }
        if witness_full_info is not None:
            body_obj["witness"]["full"] = witness_full_info
        if policy_block:
            body_obj["policy"] = policy_block

        # 12) attach bounded truncation metadata (safe, low-cardinality)
        # Avoid leaking raw values; only paths + reasons + digests.
        trunc_meta: Dict[str, Any] = {}
        trunc_meta["fields"] = [t.get("path") for t in truncations if t.get("path")][: cfg.max_truncation_records]
        trunc_meta["sanitizer"] = {
            "req": {"trunc": req_info.get("truncations", [])[: cfg.max_truncation_records], "redact": req_info.get("redactions", [])[: cfg.max_truncation_records]},
            "comp": {"trunc": comp_info.get("truncations", [])[: cfg.max_truncation_records], "redact": comp_info.get("redactions", [])[: cfg.max_truncation_records]},
            "e": {"trunc": e_info.get("truncations", [])[: cfg.max_truncation_records], "redact": e_info.get("redactions", [])[: cfg.max_truncation_records]},
            "meta": {"trunc": meta_info.get("truncations", [])[: cfg.max_truncation_records], "redact": meta_info.get("redactions", [])[: cfg.max_truncation_records]},
        }
        if truncations or req_info.get("truncated_paths") or comp_info.get("truncated_paths") or e_info.get("truncated_paths") or meta_info.get("truncated_paths"):
            body_obj["_tcd_trunc"] = trunc_meta

        # 13) canonicalize body bytes (pre-sign)
        body_bytes = _canonical_json_bytes(body_obj)

        # 14) enforce max_body_bytes with LAST-RESORT compaction
        # IMPORTANT: after any compaction that affects head-src fields, we will recompute head later from FINAL body.
        if len(body_bytes) > cfg.max_body_bytes:
            if cfg.strict_mode:
                raise SerializationError("attestation body exceeds max_body_bytes in strict_mode")

            # digest-only wrappers for the big fields (ctx included)
            for key, ctx in (
                ("meta", "tcd:attest:meta"),
                ("req", "tcd:attest:req"),
                ("comp", "tcd:attest:comp"),
                ("e", "tcd:attest:e"),
            ):
                val = body_obj.get(key)
                vb = _canonical_json_bytes(val)
                body_obj[key] = _digest_wrapper(cfg=cfg, data_bytes=vb, ctx=ctx, reason="body_oversize", extra={"path": key}, preview_obj=val)

            # Optionally drop policy + trunc meta if still too large (policy is derivable from policy_digest)
            body_bytes = _canonical_json_bytes(body_obj)
            if len(body_bytes) > cfg.max_body_bytes:
                body_obj.pop("_tcd_trunc", None)
                body_obj.pop("policy", None)
                body_bytes = _canonical_json_bytes(body_obj)

            if len(body_bytes) > cfg.max_body_bytes:
                raise SerializationError("attestation body exceeds max_body_bytes after oversize compaction")

        # 15) optional signing over FINAL body_bytes (authenticity)
        sig_block: Optional[Dict[str, Any]] = None
        if cfg.sign_func is not None and (cfg.sig_alg or "").strip():
            # governance: sig_alg allowlist
            alg_norm = str(cfg.sig_alg).strip()
            if cfg.allowed_sig_algs is not None:
                if alg_norm.lower() not in set(cfg.allowed_sig_algs):
                    raise SigningError(f"sig_alg '{alg_norm}' not allowed by policy")

            try:
                sig_raw = cfg.sign_func(body_bytes)
            except Exception as e:
                raise SigningError(f"sign_func failed: {e}") from e

            if not isinstance(sig_raw, (bytes, bytearray)):
                raise SigningError("sign_func must return bytes")
            sig_b = bytes(sig_raw)
            if len(sig_b) < cfg.min_signature_bytes:
                raise SigningError("signature too short")
            if len(sig_b) > cfg.max_signature_bytes:
                raise SigningError("signature too large")

            sig_block = {"alg": alg_norm, "val": b64encode(sig_b).decode("ascii")}
            if cfg.sig_key_id:
                sig_block["key_id"] = _normalize_id(cfg.sig_key_id, max_len=cfg.max_identity_len, require_safe=True, field="sig_key_id")

            body_obj["sig"] = sig_block
            body_bytes = _canonical_json_bytes(body_obj)

            # if signature pushes body over cap, drop non-critical blocks
            if len(body_bytes) > cfg.max_body_bytes:
                if cfg.strict_mode:
                    raise SerializationError("body exceeds max_body_bytes after adding signature in strict_mode")
                body_obj.pop("_tcd_trunc", None)
                body_obj.pop("policy", None)
                body_bytes = _canonical_json_bytes(body_obj)
            if len(body_bytes) > cfg.max_body_bytes:
                raise SerializationError("body exceeds max_body_bytes after adding signature")

        # strict-mode signature requirement
        if cfg.strict_mode and cfg.require_sig_in_strict:
            if "sig" not in body_obj:
                raise SigningError("strict_mode requires signature block")

        # 16) compute HEAD from FINAL body (fixes the 0.1 fatal drift bug)
        head = _compute_head_from_body(body_obj)

        # optional secondary head for migration
        head_secondary = None
        if cfg.secondary_hash_alg:
            head_secondary = _compute_head_from_body(body_obj, override_alg=cfg.secondary_hash_alg, override_ctx=cfg.secondary_hash_ctx, override_digest_size=cfg.secondary_digest_size)

        # 17) compute integrity hash (receipt_sig) over head + FINAL body bytes
        receipt_sig = _integrity_hash(head, body_bytes)

        receipt_sig_secondary = None
        if head_secondary is not None:
            receipt_sig_secondary = _integrity_hash(head_secondary, body_bytes)

        # 18) verify_key handle
        verify_key = cfg.sig_key_id or (cfg.attestor_id if cfg.sign_func is not None else cfg.attestor_id + ":hash-only")

        out = {
            "receipt": head,
            "receipt_body": body_bytes.decode("utf-8"),
            "receipt_sig": receipt_sig,
            "verify_key": verify_key,
            # clarify semantics without breaking existing fields
            "receipt_integrity": "sha256:tcd:attest_sig",
        }
        if head_secondary is not None and receipt_sig_secondary is not None:
            out["receipt_secondary"] = head_secondary
            out["receipt_sig_secondary"] = receipt_sig_secondary

        # 19) optional self-check (CI/gray)
        if cfg.self_check:
            ok, reason, details = verify_attestation_record_ex(
                receipt=head,
                receipt_body=out["receipt_body"],
                receipt_sig=receipt_sig,
                max_body_bytes=cfg.max_body_bytes,
                max_json_depth=cfg.max_json_depth,
                max_nodes=cfg.max_nodes,
                max_list_items=cfg.max_list_items,
                max_dict_items=cfg.max_dict_items,
                max_string_bytes=cfg.max_string_bytes,
                max_key_bytes=cfg.max_key_bytes,
                allowed_hash_algs=cfg.allowed_hash_algs,
                disallowed_hash_algs=cfg.disallowed_hash_algs,
                require_witness_digest=True,
                strict_structure=cfg.self_check_strict_structure,
                require_canonical_body=cfg.self_check_require_canonical,
                require_sig=(cfg.strict_mode and cfg.require_sig_in_strict),
            )
            if not ok:
                raise AttestationError(f"self_check failed: {reason} {details}")

        return out


def _compute_head_from_body(
    body_obj: Dict[str, Any],
    *,
    override_alg: Optional[str] = None,
    override_ctx: Optional[str] = None,
    override_digest_size: Optional[int] = None,
) -> str:
    """
    Derive head_src from FINAL body (v=1) and hash it.
    Only covers a fixed subset for stability; signature is not part of head_src.
    """
    v = int(body_obj.get("v", 1))
    ts_ns = int(body_obj.get("ts_ns"))
    nonce = body_obj.get("nonce")
    att = body_obj.get("attestor", {}) or {}
    witness = body_obj.get("witness", {}) or {}

    # derive hash suite from attestor block (or override)
    hash_alg = (override_alg or att.get("hash_alg") or "blake3").strip().lower()
    hash_ctx = (override_ctx or att.get("hash_ctx") or "tcd:attest").strip() or "tcd:attest"
    digest_size = int(override_digest_size or att.get("digest_size") or 32)

    attestor_subset = {
        "id": att.get("id"),
        "proc_id": att.get("proc_id"),
        "policy_digest": att.get("policy_digest"),
        "build_digest": att.get("build_digest"),
        "hw_root_id": att.get("hw_root_id"),
        "strict": bool(att.get("strict", False)),
        "hash_alg": hash_alg,
        "hash_ctx": hash_ctx,
        "digest_size": digest_size,
        "deployment_tier": att.get("deployment_tier"),
    }

    head_src = {
        "v": v,
        "ts_ns": ts_ns,
        "nonce": nonce,
        "attestor": attestor_subset,
        "meta": body_obj.get("meta"),
        "req": body_obj.get("req"),
        "comp": body_obj.get("comp"),
        "e": body_obj.get("e"),
        "witness_digest": witness.get("digest"),
        "witness_tags": witness.get("tags") or [],
        "policy_digest": att.get("policy_digest"),
    }
    head_src_bytes = _canonical_json_bytes(head_src)
    return _hash_bytes(head_src_bytes, alg=hash_alg, ctx=hash_ctx, digest_size=digest_size)


def _integrity_hash(head: str, body_bytes: bytes) -> str:
    h = hashlib.sha256()
    h.update(b"tcd:attest_sig")
    h.update(head.encode("utf-8"))
    h.update(body_bytes)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Verifier hardening (DoS bounds + schema + trust policy + optional sig verify)
# ---------------------------------------------------------------------------


def _json_bracket_depth_guard(s: str, *, max_depth: int) -> bool:
    depth = 0
    in_str = False
    esc = False
    for ch in s:
        if in_str:
            if esc:
                esc = False
                continue
            if ch == "\\":
                esc = True
                continue
            if ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            continue
        if ch in "{[":
            depth += 1
            if depth > max_depth:
                return False
        elif ch in "}]":
            depth = max(0, depth - 1)
    return True


def _is_hexish(s: str, *, max_len: int) -> bool:
    if not isinstance(s, str):
        return False
    if len(s) > max_len or len(s) < 8:
        return False
    return bool(re.fullmatch(r"[0-9a-fA-F]+", s))


def _measure_complexity(
    obj: Any,
    *,
    max_nodes: int,
    max_list_items: int,
    max_dict_items: int,
    max_string_bytes: int,
    max_key_bytes: int,
) -> Tuple[bool, Dict[str, Any]]:
    """
    Post-parse complexity traversal to prevent CPU/memory blowups.
    """
    nodes = 0
    strings = 0
    string_bytes = 0
    key_bytes = 0
    max_depth = 0

    def walk(x: Any, depth: int) -> bool:
        nonlocal nodes, strings, string_bytes, key_bytes, max_depth
        nodes += 1
        max_depth = max(max_depth, depth)
        if nodes > max_nodes:
            return False
        if isinstance(x, str):
            strings += 1
            b = x.encode("utf-8", errors="replace")
            string_bytes += len(b)
            if len(b) > max_string_bytes:
                return False
            return True
        if x is None or isinstance(x, (bool, int, float)):
            return True
        if isinstance(x, list):
            if max_list_items and len(x) > max_list_items:
                return False
            for v in x:
                if not walk(v, depth + 1):
                    return False
            return True
        if isinstance(x, dict):
            if max_dict_items and len(x) > max_dict_items:
                return False
            for k, v in x.items():
                ks = str(k)
                kb = ks.encode("utf-8", errors="replace")
                key_bytes += len(kb)
                if len(kb) > max_key_bytes:
                    return False
                if not walk(v, depth + 1):
                    return False
            return True
        return False

    ok = walk(obj, 0)
    return ok, {"nodes": nodes, "strings": strings, "string_bytes": string_bytes, "key_bytes": key_bytes, "max_depth": max_depth}


def verify_attestation_record_ex(
    *,
    receipt: str,
    receipt_body: str,
    receipt_sig: str,
    # Hardening knobs (DoS)
    max_body_bytes: int = 256 * 1024,
    max_json_depth: int = 96,
    max_nodes: int = 100_000,
    max_list_items: int = 5_000,
    max_dict_items: int = 5_000,
    max_string_bytes: int = 64 * 1024,
    max_key_bytes: int = 8 * 1024,
    max_receipt_len: int = 256,
    max_receipt_sig_len: int = 256,
    # Trust policy
    allowed_hash_algs: Optional[List[str]] = None,
    disallowed_hash_algs: Optional[List[str]] = None,
    allowed_attestor_ids: Optional[List[str]] = None,
    allowed_policy_digests: Optional[List[str]] = None,
    allowed_verify_keys: Optional[List[str]] = None,
    allowed_deployment_tiers: Optional[List[str]] = None,
    require_attestor_strict_flag: Optional[bool] = None,
    # Semantics / schema
    require_witness_digest: bool = False,
    strict_structure: bool = False,
    require_canonical_body: bool = False,
    # Signature verification
    require_sig: bool = False,
    verify_sig_func: Optional[Callable[[str, Optional[str], bytes, bytes], bool]] = None,
    # optional hooks
    hooks: Optional[AttestorHooks] = None,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Returns (ok, reason_code, details).

    Checks:
      - bounded body length
      - bracket depth scan
      - JSON parse
      - optional canonical roundtrip
      - complexity traversal limits
      - schema validation (optional strict_structure)
      - witness.digest recompute
      - head recompute (from FINAL body subset)
      - integrity hash recompute
      - optional external signature verify via callback
      - allowlist/denylist trust policy (attestor_id, policy_digest, verify_key, tier, hash alg)

    verify_sig_func signature:
        (alg, key_id, body_bytes, sig_bytes) -> bool
    """
    details: Dict[str, Any] = {}

    def fail(code: str, extra: Optional[Dict[str, Any]] = None) -> Tuple[bool, str, Dict[str, Any]]:
        if extra:
            details.update(extra)
        if hooks and hooks.on_verify_fail:
            try:
                hooks.on_verify_fail(code, dict(details))
            except Exception:
                pass
        return False, code, details

    try:
        if not isinstance(receipt, str) or not receipt:
            return fail(VR_SCHEMA, {"field": "receipt"})
        if not isinstance(receipt_sig, str) or not receipt_sig:
            return fail(VR_SCHEMA, {"field": "receipt_sig"})
        if not isinstance(receipt_body, str) or not receipt_body:
            return fail(VR_SCHEMA, {"field": "receipt_body"})

        if len(receipt) > max_receipt_len or not _is_hexish(receipt, max_len=max_receipt_len):
            return fail(VR_SCHEMA, {"field": "receipt", "reason": "bad_hex_or_len"})
        if len(receipt_sig) > max_receipt_sig_len or not _is_hexish(receipt_sig, max_len=max_receipt_sig_len):
            return fail(VR_SCHEMA, {"field": "receipt_sig", "reason": "bad_hex_or_len"})

        body_bytes = receipt_body.encode("utf-8", errors="strict")
        if len(body_bytes) > int(max_body_bytes):
            return fail(VR_BODY_TOO_LARGE, {"bytes": len(body_bytes), "max": int(max_body_bytes)})

        if not _json_bracket_depth_guard(receipt_body, max_depth=int(max_json_depth)):
            return fail(VR_JSON_TOO_DEEP, {"max_depth": int(max_json_depth)})

    except Exception as e:
        return fail(VR_INTERNAL, {"exc": str(e)})

    try:
        body_obj = json.loads(receipt_body)
    except Exception:
        return fail(VR_JSON_PARSE)

    # canonical roundtrip check (prevents non-canonical JSON entering evidence pipelines)
    if require_canonical_body:
        try:
            re_bytes = _canonical_json_bytes(body_obj)
            if re_bytes != body_bytes:
                return fail(VR_NOT_CANONICAL)
        except Exception:
            return fail(VR_NOT_CANONICAL)

    ok_complex, cx = _measure_complexity(
        body_obj,
        max_nodes=int(max_nodes),
        max_list_items=int(max_list_items),
        max_dict_items=int(max_dict_items),
        max_string_bytes=int(max_string_bytes),
        max_key_bytes=int(max_key_bytes),
    )
    details["complexity"] = cx
    if not ok_complex:
        return fail(VR_COMPLEXITY)

    # Basic schema extraction
    try:
        v = int(body_obj.get("v", 1))
        ts_ns = int(body_obj.get("ts_ns"))
        nonce = body_obj.get("nonce")
        att = body_obj.get("attestor", {}) or {}
        witness = body_obj.get("witness", {}) or {}
        verify_key = None
        if isinstance(att, dict):
            # verifier may use external key registry; key_id preferred if present
            verify_key = (body_obj.get("sig") or {}).get("key_id") if isinstance(body_obj.get("sig"), dict) else None
            if not verify_key:
                verify_key = att.get("id")
    except Exception:
        return fail(VR_SCHEMA)

    if strict_structure:
        if v != 1:
            return fail(VR_SCHEMA, {"reason": "unsupported_version"})
        if not isinstance(nonce, str) or not nonce:
            return fail(VR_SCHEMA, {"field": "nonce"})
        if not isinstance(att, dict):
            return fail(VR_SCHEMA, {"field": "attestor"})
        if not isinstance(witness, dict):
            return fail(VR_SCHEMA, {"field": "witness"})
        if "digest" not in witness or "segments" not in witness or "tags" not in witness:
            return fail(VR_SCHEMA, {"field": "witness", "reason": "missing_fields"})
        if not isinstance(witness.get("segments"), list):
            return fail(VR_SCHEMA, {"field": "witness.segments"})
        if not isinstance(witness.get("tags"), list):
            return fail(VR_SCHEMA, {"field": "witness.tags"})
        # attestor id should be safe-ish
        aid = att.get("id")
        if not isinstance(aid, str) or not aid or not _SAFE_ASCII_ID_RE.match(aid):
            return fail(VR_SCHEMA, {"field": "attestor.id"})

    # Trust policy checks
    attestor_id = att.get("id")
    policy_digest = att.get("policy_digest")
    tier = att.get("deployment_tier")

    if allowed_attestor_ids is not None:
        allowed_set = set(str(x) for x in allowed_attestor_ids if x)
        if str(attestor_id) not in allowed_set:
            return fail(VR_ATTESTOR_ID, {"attestor_id": attestor_id})
    if allowed_policy_digests is not None:
        allowed_pd = set(str(x) for x in allowed_policy_digests if x)
        if str(policy_digest) not in allowed_pd:
            return fail(VR_ATTESTOR_POLICY, {"policy_digest": policy_digest})
    if allowed_deployment_tiers is not None and tier is not None:
        allowed_t = set(str(x) for x in allowed_deployment_tiers if x)
        if str(tier) not in allowed_t:
            return fail(VR_TIER, {"deployment_tier": tier})
    if allowed_verify_keys is not None and verify_key is not None:
        allowed_vk = set(str(x) for x in allowed_verify_keys if x)
        if str(verify_key) not in allowed_vk:
            return fail(VR_VERIFY_KEY, {"verify_key": verify_key})

    if require_attestor_strict_flag is not None:
        if bool(att.get("strict", False)) != bool(require_attestor_strict_flag):
            return fail(VR_ATTESTOR_POLICY, {"reason": "strict_flag_mismatch"})

    # Hash suite governance
    hash_alg = str(att.get("hash_alg") or "blake3").strip().lower()
    hash_ctx = str(att.get("hash_ctx") or "tcd:attest").strip() or "tcd:attest"
    digest_size = int(att.get("digest_size") or 32)

    if disallowed_hash_algs is not None:
        dis = {str(a).strip().lower() for a in disallowed_hash_algs if a}
        if hash_alg in dis:
            return fail(VR_HASH_ALG, {"hash_alg": hash_alg, "reason": "disallowed"})
    if allowed_hash_algs is not None:
        al = {str(a).strip().lower() for a in allowed_hash_algs if a}
        if hash_alg not in al:
            return fail(VR_HASH_ALG, {"hash_alg": hash_alg, "reason": "not_allowed"})
    if hash_alg not in _SUPPORTED_HASH_ALGS:
        return fail(VR_HASH_ALG, {"hash_alg": hash_alg, "reason": "unsupported"})
    if not (1 <= digest_size <= 32):
        return fail(VR_HASH_ALG, {"digest_size": digest_size})

    # Recompute witness digest (schema hardening optional)
    try:
        segments = witness.get("segments", [])
        tags = witness.get("tags", [])
        stored_witness_digest = witness.get("digest")
        if require_witness_digest and stored_witness_digest is None:
            return fail(VR_SCHEMA, {"field": "witness.digest", "reason": "required_missing"})

        if strict_structure:
            # Validate witness segments schema (reject pollution)
            for seg in segments:
                if not isinstance(seg, dict):
                    return fail(VR_SCHEMA, {"field": "witness.segment", "reason": "not_dict"})
                if set(seg.keys()) - {"kind", "id", "digest", "meta"}:
                    return fail(VR_SCHEMA, {"field": "witness.segment", "reason": "unknown_keys"})
                k = seg.get("kind")
                if not isinstance(k, str) or k not in ALLOWED_WITNESS_KINDS:
                    return fail(VR_SCHEMA, {"field": "witness.segment.kind"})
                d = seg.get("digest")
                if not isinstance(d, str) or not d:
                    return fail(VR_SCHEMA, {"field": "witness.segment.digest"})
                if not (_HEX_RE.match(d) or _SAFE_ASCII_ID_RE.match(d)):
                    return fail(VR_SCHEMA, {"field": "witness.segment.digest", "reason": "unsafe"})
                sid = seg.get("id", "")
                if sid is not None and sid != "" and (not isinstance(sid, str) or not _SAFE_ASCII_ID_RE.match(sid)):
                    return fail(VR_SCHEMA, {"field": "witness.segment.id"})
                m = seg.get("meta", {})
                if m is not None and not isinstance(m, dict):
                    return fail(VR_SCHEMA, {"field": "witness.segment.meta"})

            # Validate tags shape
            if not isinstance(tags, list):
                return fail(VR_SCHEMA, {"field": "witness.tags"})

        segments_json = json.dumps(
            {"segments": segments},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")

        computed_witness_digest = _hash_bytes(
            segments_json,
            alg=hash_alg,
            ctx="tcd:attest:witness",
            digest_size=digest_size,
        )
        if stored_witness_digest is not None:
            if not secrets.compare_digest(str(stored_witness_digest), computed_witness_digest):
                return fail(VR_WITNESS_DIGEST)

    except PolicyError as e:
        # hash backend missing (blake3) etc
        return fail(VR_HASH_ALG, {"exc": str(e)})
    except Exception as e:
        return fail(VR_SCHEMA, {"exc": str(e)})

    # Recompute head from FINAL body subset
    try:
        computed_head = _compute_head_from_body(body_obj)
        if not secrets.compare_digest(computed_head, receipt):
            return fail(VR_HEAD_MISMATCH, {"computed": computed_head, "given": receipt})
    except PolicyError as e:
        return fail(VR_HASH_ALG, {"exc": str(e)})
    except Exception as e:
        return fail(VR_INTERNAL, {"exc": str(e)})

    # Recompute integrity hash
    try:
        computed_sig = _integrity_hash(computed_head, body_bytes)
        if not secrets.compare_digest(computed_sig, receipt_sig):
            return fail(VR_INTEGRITY)
    except Exception as e:
        return fail(VR_INTERNAL, {"exc": str(e)})

    # Optional external signature verification
    sig_obj = body_obj.get("sig")
    if require_sig:
        if sig_obj is None:
            return fail(VR_SIG_MISSING)
        if not isinstance(sig_obj, dict):
            return fail(VR_SIG_BAD, {"reason": "sig_not_dict"})
        alg = sig_obj.get("alg")
        val = sig_obj.get("val")
        key_id = sig_obj.get("key_id")
        if not isinstance(alg, str) or not alg.strip():
            return fail(VR_SIG_BAD, {"field": "sig.alg"})
        if key_id is not None and (not isinstance(key_id, str) or not _SAFE_ASCII_ID_RE.match(key_id)):
            return fail(VR_SIG_BAD, {"field": "sig.key_id"})
        if not isinstance(val, str) or not val or len(val) > 4 * 1024 * 1024 or not _BASE64_RE.match(val):
            return fail(VR_SIG_BAD, {"field": "sig.val"})
        try:
            sig_bytes = b64decode(val.encode("ascii"), validate=True)
        except Exception:
            return fail(VR_SIG_BAD, {"field": "sig.val", "reason": "b64decode"})
        if verify_sig_func is None:
            return fail(VR_SIG_VERIFY_UNAVAILABLE)
        try:
            ok = bool(verify_sig_func(str(alg), str(key_id) if key_id is not None else None, body_bytes, sig_bytes))
        except Exception as e:
            return fail(VR_SIG_BAD, {"reason": "verify_sig_func_exc", "exc": str(e)})
        if not ok:
            return fail(VR_SIG_BAD, {"reason": "sig_verify_failed"})

    return True, VR_OK, details


def verify_attestation_record(
    *,
    receipt: str,
    receipt_body: str,
    receipt_sig: str,
    **kwargs: Any,
) -> bool:
    ok, _, _ = verify_attestation_record_ex(
        receipt=receipt,
        receipt_body=receipt_body,
        receipt_sig=receipt_sig,
        **kwargs,
    )
    return ok