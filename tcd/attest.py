# FILE: tcd/attest.py
from __future__ import annotations

"""
Structured attestation generator for verifiable receipts.

Role:
  Attestor is a cross-component security anchor. For each safety-relevant
  decision, it produces a compact, structured, replayable attestation that:

    - cryptographically binds:
        * request shape / content (req)
        * computation description (comp)
        * e-process state snapshot (e)
        * a typed witness set (receipt heads, audit-ledger heads, zk-proof
          digests, TPM quotes, etc.)
        * attestor identity and full policy fingerprint

    - can be backed by HSM / PQ-capable signers;

    - can be cross-checked against:
        * receipt chains,
        * local audit ledgers,
        * chain-auditor policy,
        * auth policy,
        * runtime attestation / TPM quotes,
        * PQ / zk proof systems.

The API is kept backward-compatible with the original helper while lifting it
to a "high-assurance / regulator-grade" attestation primitive.
"""

import dataclasses
import hashlib
import json
import secrets
import time
from base64 import b64encode
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

# ---------------------------------------------------------------------------
# Constants / witness typing
# ---------------------------------------------------------------------------

# Allowed witness segment kinds. This is intentionally small and stable so that
# downstream verifiers and zk-circuits can treat "kind" as a low-cardinality
# discriminator.
ALLOWED_WITNESS_KINDS = frozenset(
    [
        "audit_ledger_head",  # local append-only audit ledger head
        "receipt_head",       # remote receipt chain head
        "tcd_chain_report",   # chain-auditor report digest / summary
        "zk_proof",           # zk proof digest / public-input summary
        "tpm_quote",          # runtime attestation / measured boot quote
        "external",           # external system witness (e.g. SIEM / log sink)
        "other",              # catch-all; should be documented by caller
    ]
)


# ---------------------------------------------------------------------------
# Config and helpers
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class AttestorConfig:
    """
    Configuration for Attestor.

    Hashing / domain separation:
      - hash_alg         : "blake3" (default), "sha256", "sha3_256", "blake2s"
      - hash_ctx         : domain-separation label for head hashing
      - digest_size      : digest length in bytes (used for blake2s etc.)
      - strict_mode      : if True, enforce a restricted hash set and require
                           a signing backend
      - allowed_hash_algs: optional allowlist when strict_mode is enabled
                           (e.g. ["sha256", "sha3_256"])

    Identity / origin / supply-chain:
      - attestor_id      : logical identifier ("tcd-attestor-0", "edge-a", ...)
      - proc_id          : build or process id (git commit, image digest, ...)
      - build_digest     : build-time fingerprint (container image digest, SBOM)
      - runtime_env_digest:
                         : digest of runtime environment (OS/kernel/hypervisor
                           summary, attested platform profile, etc.)
      - hw_root_id       : identifier for hardware root-of-trust (TPM EK, RoT)
      - tpm_quote_digest : digest of the latest measured-boot quote or similar

      - deployment_tier  : "prod" | "dev" | "canary" | ... (for diagnostics)

    Policy embedding:
      - include_policy_block : if True, attach a policy block into the body
      - default_auth_policy  : digest of current auth policy
      - default_chain_policy : digest of chain-auditor / chain policy
      - default_ledger_policy: digest of local audit ledger policy
      - default_cfg_digest   : digest of global TCD configuration

    Signing (optional, recommended in strict mode):
      - sign_func        : callable body_bytes -> signature_bytes
      - sig_alg          : textual identifier for signature algorithm
                           ("ed25519", "ecdsa-p256", "dilithium3", ...)
      - sig_key_id       : key identifier / verification-key handle

    Normalization hooks (optional, but recommended in high-assurance profiles):
      - normalize_req    : req_obj -> JSON-safe dict
      - normalize_comp   : comp_obj -> JSON-safe dict
      - normalize_e      : e_obj -> JSON-safe dict
      - normalize_meta   : meta dict -> JSON-safe dict

    Witness governance:
      - core_witness_kinds : optional list of witness kinds that must be
                             present at least once when strict_mode=True
                             (e.g. ["audit_ledger_head", "receipt_head"])

    Notes:
      - sign_func is a runtime binding to an external signer (HSM / PQ stack);
        it is *not* included in the policy digest.
      - In strict_mode, sign_func + sig_alg must be configured, and hash_alg
        is restricted by allowed_hash_algs (or a safe default list).
    """

    # Hashing
    hash_alg: str = "blake3"
    hash_ctx: str = "tcd:attest"
    digest_size: int = 32
    strict_mode: bool = False
    allowed_hash_algs: Optional[List[str]] = None

    # Identity / origin / supply-chain
    attestor_id: str = "tcd-attestor"
    proc_id: Optional[str] = None
    build_digest: Optional[str] = None
    runtime_env_digest: Optional[str] = None
    hw_root_id: Optional[str] = None
    tpm_quote_digest: Optional[str] = None
    deployment_tier: Optional[str] = None

    # Policy block
    include_policy_block: bool = True
    default_auth_policy: Optional[str] = None
    default_chain_policy: Optional[str] = None
    default_ledger_policy: Optional[str] = None
    default_cfg_digest: Optional[str] = None

    # Signing
    sign_func: Optional[Callable[[bytes], bytes]] = None
    sig_alg: Optional[str] = None
    sig_key_id: Optional[str] = None

    # Normalization hooks
    normalize_req: Optional[Callable[[Any], Dict[str, Any]]] = None
    normalize_comp: Optional[Callable[[Any], Dict[str, Any]]] = None
    normalize_e: Optional[Callable[[Any], Dict[str, Any]]] = None
    normalize_meta: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None

    # Witness governance
    core_witness_kinds: Optional[List[str]] = None

    # ------------------------------------------------------------------ #
    # Post-init validation                                               #
    # ------------------------------------------------------------------ #

    def __post_init__(self) -> None:
        # Strict-mode governance: restrict hash algorithms and require signing.
        if self.strict_mode:
            allowed = self.allowed_hash_algs or ["sha256", "sha3_256"]
            if self.hash_alg not in allowed:
                raise ValueError(
                    f"hash_alg '{self.hash_alg}' not allowed in strict_mode; "
                    f"allowed={allowed}"
                )
            if self.sign_func is None or not self.sig_alg:
                raise ValueError(
                    "strict_mode requires sign_func and sig_alg to be configured"
                )

    # ------------------------------------------------------------------ #
    # Policy digest                                                      #
    # ------------------------------------------------------------------ #

    def policy_digest(self) -> str:
        """
        Stable digest of the attestor policy and its supply-chain anchors.

        Includes (non-exhaustive):
          - hash_alg / hash_ctx / digest_size
          - strict_mode flag and allowed_hash_algs (if provided)
          - attestor_id / proc_id
          - build_digest / runtime_env_digest / hw_root_id / tpm_quote_digest
          - deployment_tier
          - include_policy_block flag
          - default_*_policy digests and default_cfg_digest
          - sig_alg and sig_key_id

        Excludes:
          - sign_func (runtime binding only)
        """
        material: Dict[str, Any] = {
            "hash_alg": self.hash_alg,
            "hash_ctx": self.hash_ctx,
            "digest_size": int(self.digest_size),
            "strict_mode": bool(self.strict_mode),
            "allowed_hash_algs": list(self.allowed_hash_algs or []),
            "attestor_id": self.attestor_id,
            "proc_id": self.proc_id,
            "build_digest": self.build_digest,
            "runtime_env_digest": self.runtime_env_digest,
            "hw_root_id": self.hw_root_id,
            "tpm_quote_digest": self.tpm_quote_digest,
            "deployment_tier": self.deployment_tier,
            "include_policy_block": bool(self.include_policy_block),
            "default_auth_policy": self.default_auth_policy,
            "default_chain_policy": self.default_chain_policy,
            "default_ledger_policy": self.default_ledger_policy,
            "default_cfg_digest": self.default_cfg_digest,
            "sig_alg": self.sig_alg,
            "sig_key_id": self.sig_key_id,
        }
        return _canonical_kv_hash(material, ctx="tcd:attestor_policy")


def _canonical_kv_hash(obj: Dict[str, Any], *, ctx: str) -> str:
    """
    Canonical hash of a mapping with:
      - JSON encoding (sort_keys=True, compact separators)
      - UTF-8 bytes
      - SHA-256 with an explicit context prefix.

    Used for policy digests and similar fingerprints.
    """
    data = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    h = hashlib.sha256()
    h.update(ctx.encode("utf-8"))
    h.update(data)
    return h.hexdigest()


def _hash_bytes(data: bytes, *, alg: str, ctx: str, digest_size: int) -> str:
    """
    Hash a byte string under a given algorithm with domain separation.

    Supported alg values:
      - "blake3"   : uses the blake3 package if available, otherwise falls
                     back to blake2s(digest_size)
      - "sha256"   : hashlib.sha256
      - "sha3_256" : hashlib.sha3_256
      - "blake2s"  : hashlib.blake2s(digest_size=digest_size)
      - anything else: falls back to blake2s(digest_size)
    """
    alg = (alg or "").lower().strip() or "blake3"
    ctx_b = ctx.encode("utf-8")

    if alg == "sha256":
        h = hashlib.sha256()
        h.update(ctx_b)
        h.update(data)
        return h.hexdigest()

    if alg == "sha3_256":
        h = hashlib.sha3_256()
        h.update(ctx_b)
        h.update(data)
        return h.hexdigest()

    if alg == "blake2s":
        h = hashlib.blake2s(digest_size=digest_size)
        h.update(ctx_b)
        h.update(data)
        return h.hexdigest()

    if alg == "blake3":
        try:
            from blake3 import blake3  # type: ignore

            h = blake3()
            h.update(ctx_b)
            h.update(data)
            return h.hexdigest()
        except Exception:
            # Fall through to blake2s
            h = hashlib.blake2s(digest_size=digest_size)
            h.update(ctx_b)
            h.update(data)
            return h.hexdigest()

    # Default fallback
    h = hashlib.blake2s(digest_size=digest_size)
    h.update(ctx_b)
    h.update(data)
    return h.hexdigest()


def _normalize_tags(tags: Optional[Iterable[str]]) -> List[str]:
    """
    Normalize witness tags:
      - stringify
      - deduplicate
      - sort for canonical ordering
    """
    if not tags:
        return []
    uniq = {str(t) for t in tags if t is not None}
    return sorted(uniq)


def _normalize_segments(segments: Optional[Iterable[Any]]) -> List[Dict[str, Any]]:
    """
    Normalize witness segments into a typed, schema-checked list.

    Each segment is required to be a mapping with:
      - kind   : str, in ALLOWED_WITNESS_KINDS
      - digest : str, hex or generic digest string
      - id     : optional, coerced to str
      - meta   : optional, small dict (JSON-safe)

    This keeps witness structure compact while making it easy for
    verifiers and zk-circuits to interpret the witness graph.
    """
    if not segments:
        return []
    out: List[Dict[str, Any]] = []
    for s in segments:
        if not isinstance(s, dict):
            raise TypeError("witness segment must be a dict")
        kind = str(s.get("kind") or "")
        if not kind:
            raise ValueError("witness segment missing 'kind'")
        if kind not in ALLOWED_WITNESS_KINDS:
            raise ValueError(f"witness kind '{kind}' not in allowed set")
        digest = s.get("digest")
        if not isinstance(digest, str) or not digest:
            raise ValueError("witness segment missing or invalid 'digest'")
        seg_id = s.get("id")
        meta = s.get("meta") or {}
        if meta is None:
            meta = {}
        out.append(
            {
                "kind": kind,
                "id": "" if seg_id is None else str(seg_id),
                "digest": digest,
                "meta": meta,
            }
        )
    return out


# ---------------------------------------------------------------------------
# Attestor
# ---------------------------------------------------------------------------


class Attestor:
    """
    Structured attestation generator.

    Backward-compatible surface:
      - __init__(hash_alg="blake3") still works; internally this builds
        an AttestorConfig with the given hash_alg.
      - issue(...) keeps the same keyword-only argument set:

            issue(
                *,
                req_obj,
                comp_obj,
                e_obj,
                witness_segments,
                witness_tags,
                meta,
            )

        and returns a dict containing:
            "receipt"       : head hash (hex)
            "receipt_body"  : body JSON string
            "receipt_sig"   : signature/digest (hex)
            "verify_key"    : verification-key handle (string)

    Body JSON structure (top-level):

        {
          "v": 1,
          "ts_ns": <int>,
          "nonce": "<hex>",
          "attestor": {
            "id": "<attestor_id>",
            "proc_id": "<proc_id or null>",
            "policy_digest": "<attestor policy digest>",
            "build_digest": "<optional>",
            "hw_root_id": "<optional>",
            "strict": <bool>,
            "hash_alg": "<hash_alg>",
            "hash_ctx": "<hash_ctx>",
            "digest_size": <int>,
            "deployment_tier": "<optional>"
          },
          "meta": {...},       # normalized from meta
          "req":  {...},       # normalized from req_obj
          "comp": {...},       # normalized from comp_obj
          "e":    {...},       # normalized from e_obj (e-process state)
          "witness": {
            "segments": [...],   # typed witness segments
            "digest": "<hex>",   # digest of the segments array
            "tags":   [...]      # normalized witness_tags
          },
          "policy": {
            "auth_policy":   "<optional>",
            "chain_policy":  "<optional>",
            "ledger_policy": "<optional>",
            "cfg_digest":    "<optional>"
          },
          "sig": {
            "alg": "<sig_alg>",
            "key_id": "<sig_key_id>",
            "val": "<base64 signature>"
          }
        }

    Head hash:

      head = H_attest(
          canonical_json({
              "v": 1,
              "ts_ns": ts_ns,
              "nonce": nonce,
              "attestor": {
                  "id", "proc_id", "policy_digest",
                  "build_digest", "hw_root_id",
                  "strict", "hash_alg", "hash_ctx", "digest_size",
                  "deployment_tier"
              },
              "meta": meta_norm,
              "req": req_norm,
              "comp": comp_norm,
              "e": e_norm,
              "witness_digest": witness_digest,
              "witness_tags": tags,
              "policy_digest": policy_digest
          })
      )

      where H_attest is configured via AttestorConfig.hash_alg/hash_ctx.

    Signature / receipt_sig:

      - If config.sign_func and config.sig_alg are set:
            * body bytes are passed to sign_func,
            * the returned signature is embedded as base64 in body["sig"],
            * receipt_sig is a SHA-256 hash over:
                  "tcd:attest_sig" || head || body_bytes

      - If no sign_func is configured:
            * no "sig" block is embedded in the body,
            * receipt_sig is still a SHA-256 hash over:
                  "tcd:attest_sig" || head || body_bytes

    High-assurance profiles are expected to run with strict_mode=True,
    a restricted hash suite, and an HSM / PQ signer bound via sign_func.
    """

    def __init__(self, hash_alg: str = "blake3", *, cfg: Optional[AttestorConfig] = None):
        if cfg is None:
            cfg = AttestorConfig(hash_alg=hash_alg)
        # Treat cfg as immutable after Attestor construction.
        self._cfg = cfg
        # Backward-compat attribute for callers that introspect hash_alg.
        self.hash_alg = cfg.hash_alg

    # ------------------------------------------------------------------ #
    # Core attestation                                                   #
    # ------------------------------------------------------------------ #

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
        """
        Issue a new attestation.

        Parameters:
          - req_obj          : request description / payload
          - comp_obj         : computation description (model, version, etc.)
          - e_obj            : e-process state snapshot
          - witness_segments : list/sequence describing attached witnesses
                               (e.g. receipt-chain heads, audit-ledger heads,
                               chain-auditor reports, zk-proof digests, TPM
                               quotes, etc.)
          - witness_tags     : small set of tags describing witness semantics
          - meta             : arbitrary metadata (tenant, session id, etc.);
                               passed through normalize_meta() when configured

        Returns:
          dict with:
            "receipt"       : head hash (hex)
            "receipt_body"  : canonical JSON string of the attestation body
            "receipt_sig"   : signature/digest over head+body (hex)
            "verify_key"    : verification-key handle (string)
        """
        ts_ns = time.time_ns()
        nonce = secrets.token_hex(16)

        # Normalize primary objects through optional hooks.
        if self._cfg.normalize_req:
            req_norm = self._cfg.normalize_req(req_obj)
        else:
            req_norm = req_obj

        if self._cfg.normalize_comp:
            comp_norm = self._cfg.normalize_comp(comp_obj)
        else:
            comp_norm = comp_obj

        if self._cfg.normalize_e:
            e_norm = self._cfg.normalize_e(e_obj)
        else:
            e_norm = e_obj

        meta = meta or {}
        if self._cfg.normalize_meta:
            meta_norm = self._cfg.normalize_meta(meta)
        else:
            meta_norm = meta

        # Normalize witness data.
        segments = _normalize_segments(witness_segments)
        tags = _normalize_tags(witness_tags)

        # Enforce core witness presence in strict mode (if configured).
        if self._cfg.strict_mode and self._cfg.core_witness_kinds:
            present_kinds = {seg["kind"] for seg in segments}
            missing = [k for k in self._cfg.core_witness_kinds if k not in present_kinds]
            if missing:
                raise ValueError(
                    f"strict_mode requires witness kinds {self._cfg.core_witness_kinds}, "
                    f"missing={missing}"
                )

        segments_wrapper = {"segments": segments}
        segments_json = json.dumps(
            segments_wrapper,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        witness_digest = _hash_bytes(
            segments_json,
            alg=self._cfg.hash_alg,
            ctx="tcd:attest:witness",
            digest_size=self._cfg.digest_size,
        )

        # Build attestor block with policy digest and supply-chain anchors.
        policy_digest = self._cfg.policy_digest()
        attestor_block: Dict[str, Any] = {
            "id": self._cfg.attestor_id,
            "proc_id": self._cfg.proc_id,
            "policy_digest": policy_digest,
            "build_digest": self._cfg.build_digest,
            "hw_root_id": self._cfg.hw_root_id,
            "strict": bool(self._cfg.strict_mode),
            "hash_alg": self._cfg.hash_alg,
            "hash_ctx": self._cfg.hash_ctx,
            "digest_size": int(self._cfg.digest_size),
            "deployment_tier": self._cfg.deployment_tier,
        }

        # Optional embedded policy block for downstream auditing.
        policy_block: Dict[str, Any] = {}
        if self._cfg.include_policy_block:
            if self._cfg.default_auth_policy:
                policy_block["auth_policy"] = self._cfg.default_auth_policy
            if self._cfg.default_chain_policy:
                policy_block["chain_policy"] = self._cfg.default_chain_policy
            if self._cfg.default_ledger_policy:
                policy_block["ledger_policy"] = self._cfg.default_ledger_policy
            if self._cfg.default_cfg_digest:
                policy_block["cfg_digest"] = self._cfg.default_cfg_digest

            # Optional runtime environment / quote digests can also be surfaced
            # here if desired for explicit cross-checking.
            if self._cfg.runtime_env_digest:
                policy_block["runtime_env_digest"] = self._cfg.runtime_env_digest
            if self._cfg.tpm_quote_digest:
                policy_block["tpm_quote_digest"] = self._cfg.tpm_quote_digest

        # Construct head source: compact subset binding all relevant semantics.
        head_src = {
            "v": 1,
            "ts_ns": int(ts_ns),
            "nonce": nonce,
            "attestor": attestor_block,
            "meta": meta_norm,
            "req": req_norm,
            "comp": comp_norm,
            "e": e_norm,
            "witness_digest": witness_digest,
            "witness_tags": tags,
            "policy_digest": policy_digest,
        }
        head_src_bytes = json.dumps(
            head_src,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        head = _hash_bytes(
            head_src_bytes,
            alg=self._cfg.hash_alg,
            ctx=self._cfg.hash_ctx,
            digest_size=self._cfg.digest_size,
        )

        # Full body: includes the full witness segments and tags.
        body_obj: Dict[str, Any] = {
            "v": 1,
            "ts_ns": int(ts_ns),
            "nonce": nonce,
            "attestor": attestor_block,
            "meta": meta_norm,
            "req": req_norm,
            "comp": comp_norm,
            "e": e_norm,
            "witness": {
                "segments": segments,
                "digest": witness_digest,
                "tags": tags,
            },
        }
        if policy_block:
            body_obj["policy"] = policy_block

        # Optional signing hook (HSM / PQ signer).
        sig_block: Optional[Dict[str, Any]] = None
        body_bytes = json.dumps(
            body_obj,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")

        if self._cfg.sign_func is not None and self._cfg.sig_alg:
            try:
                sig_bytes = self._cfg.sign_func(body_bytes)
                sig_block = {
                    "alg": self._cfg.sig_alg,
                    "val": b64encode(sig_bytes).decode("ascii"),
                }
                if self._cfg.sig_key_id:
                    sig_block["key_id"] = self._cfg.sig_key_id
            except Exception as e:
                # In high-assurance profiles, this is expected to be treated
                # as a hard failure by the caller.
                raise RuntimeError(f"Attestor signing failed: {e}") from e

        if sig_block is not None:
            body_obj["sig"] = sig_block
            # Re-encode body with sig included.
            body_bytes = json.dumps(
                body_obj,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")

        body_str = body_bytes.decode("utf-8")

        # Compute receipt_sig over (head || body) using a fixed hash, so
        # verifiers can implement this without needing the full config.
        sig_hasher = hashlib.sha256()
        sig_hasher.update(b"tcd:attest_sig")
        sig_hasher.update(head.encode("utf-8"))
        sig_hasher.update(body_bytes)
        receipt_sig = sig_hasher.hexdigest()

        # Verification-key handle:
        #   - prefer configured sig_key_id
        #   - otherwise attestor_id (for external key registries)
        #   - final fallback: attestor_id + ":hash-only" (no external key)
        if self._cfg.sig_key_id:
            verify_key = self._cfg.sig_key_id
        elif self._cfg.sign_func is not None:
            verify_key = self._cfg.attestor_id
        else:
            verify_key = self._cfg.attestor_id + ":hash-only"

        return {
            "receipt": head,
            "receipt_body": body_str,
            "receipt_sig": receipt_sig,
            "verify_key": verify_key,
        }


# ---------------------------------------------------------------------------
# Pure verifier helper
# ---------------------------------------------------------------------------


def verify_attestation_record(
    *,
    receipt: str,
    receipt_body: str,
    receipt_sig: str,
) -> bool:
    """
    Lightweight consistency checker for an attestation record.

    Given:
      - receipt:      head hash (hex)
      - receipt_body: body JSON string
      - receipt_sig:  hex digest over "tcd:attest_sig" || head || body

    This function:
      1. Parses the body JSON.
      2. Recomputes the witness digest from witness.segments.
      3. Reconstructs head_src from body fields and recomputes the head,
         using the hash suite annotations in body["attestor"].
      4. Verifies:
           * witness.digest matches the recomputed witness digest;
           * computed head matches the given receipt;
           * computed signature hash matches receipt_sig.

    It does *not* verify any external signature contained in body["sig"];
    that must be done separately by a caller that understands sig_alg/key_id.
    """
    try:
        body_obj = json.loads(receipt_body)
    except Exception:
        return False

    try:
        v = int(body_obj.get("v", 1))
        ts_ns = int(body_obj.get("ts_ns"))
        nonce = body_obj.get("nonce")
        att = body_obj.get("attestor", {}) or {}
        meta = body_obj.get("meta", {}) or {}
        req = body_obj.get("req")
        comp = body_obj.get("comp")
        e = body_obj.get("e")
        witness = body_obj.get("witness", {}) or {}
        tags = witness.get("tags", []) or []
        witness_segments = witness.get("segments", []) or []

        # Extract hash configuration from attestor block (with defaults).
        hash_alg = att.get("hash_alg") or "blake3"
        hash_ctx = att.get("hash_ctx") or "tcd:attest"
        digest_size = int(att.get("digest_size") or 32)
        policy_digest = att.get("policy_digest")
        strict_flag = bool(att.get("strict", False))
        deployment_tier = att.get("deployment_tier")
        build_digest = att.get("build_digest")
        hw_root_id = att.get("hw_root_id")

        # Recompute witness digest.
        segments_wrapper = {"segments": witness_segments}
        segments_json = json.dumps(
            segments_wrapper,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        computed_witness_digest = _hash_bytes(
            segments_json,
            alg=hash_alg,
            ctx="tcd:attest:witness",
            digest_size=digest_size,
        )
        stored_witness_digest = witness.get("digest")
        if stored_witness_digest is not None and stored_witness_digest != computed_witness_digest:
            return False

        # Rebuild attestor block subset that participates in head_src.
        attestor_block = {
            "id": att.get("id"),
            "proc_id": att.get("proc_id"),
            "policy_digest": policy_digest,
            "build_digest": build_digest,
            "hw_root_id": hw_root_id,
            "strict": strict_flag,
            "hash_alg": hash_alg,
            "hash_ctx": hash_ctx,
            "digest_size": digest_size,
            "deployment_tier": deployment_tier,
        }

        # Rebuild head_src as in issue().
        head_src = {
            "v": v,
            "ts_ns": ts_ns,
            "nonce": nonce,
            "attestor": attestor_block,
            "meta": meta,
            "req": req,
            "comp": comp,
            "e": e,
            "witness_digest": computed_witness_digest,
            "witness_tags": _normalize_tags(tags),
            "policy_digest": policy_digest,
        }
        head_src_bytes = json.dumps(
            head_src,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        computed_head = _hash_bytes(
            head_src_bytes,
            alg=hash_alg,
            ctx=hash_ctx,
            digest_size=digest_size,
        )
        if computed_head != receipt:
            return False

        # Recompute receipt_sig from head and body.
        sig_hasher = hashlib.sha256()
        sig_hasher.update(b"tcd:attest_sig")
        sig_hasher.update(computed_head.encode("utf-8"))
        sig_hasher.update(receipt_body.encode("utf-8"))
        computed_sig = sig_hasher.hexdigest()
        if computed_sig != receipt_sig:
            return False

        return True
    except Exception:
        # Any structural inconsistency is treated as failure.
        return False