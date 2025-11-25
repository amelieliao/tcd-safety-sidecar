# FILE: tcd/verify.py
from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .utils import (
    canonical_json_dumps,
    commitment_hex,
    secure_compare_hex,
    enforce_metadata_keys,
)

# Domain tags for commitments (must match the writer side)
_RECEIPT_HEAD_DOMAIN = "tcd-receipt-head-v1"
_REQ_SCHEMA = "tcd.req.v1"
_COMP_SCHEMA = "tcd.comp.v1"
_E_SCHEMA = "tcd.e.v1"

# Receipt body constraints (content-agnostic but structurally strict)
_MAX_RECEIPT_BODY_BYTES = 16_384  # 16 KiB upper bound to avoid bloated receipts

# Keys that must never appear in receipt bodies (to avoid raw content leakage)
_FORBIDDEN_RECEIPT_KEYS = {
    "prompt",
    "completion",
    "input_text",
    "output_text",
    "messages",
    "content",
    "raw",
    "body",
}

# Allowed trust_zone values (aligned with router / TrustGraph)
_ALLOWED_TRUST_ZONES = {
    "internet",
    "internal",
    "partner",
    "admin",
    "ops",
}

# Allowed route_profile values
_ALLOWED_ROUTE_PROFILES = {
    "inference",
    "admin",
    "control",
    "metrics",
    "health",
}

# Allowed override levels
_ALLOWED_OVERRIDE_LEVELS = {
    "none",
    "break_glass",
    "maintenance",
}

# Allowed PQ schemes (can be extended as needed)
_ALLOWED_PQ_SCHEMES = {
    "",
    "dilithium2",
    "dilithium3",
    "falcon",
    "sphincs+",
}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _safe_json_loads(body_json: str) -> Optional[Any]:
    """
    Parse JSON and return the object, or None on failure.
    """
    if not isinstance(body_json, str):
        return None
    try:
        return json.loads(body_json)
    except Exception:
        return None


def _is_hex_string(s: Any, *, min_len: int = 0) -> bool:
    """
    Check whether `s` is a hex string with at least `min_len` characters.
    """
    if not isinstance(s, str):
        return False
    if len(s) < min_len:
        return False
    try:
        int(s, 16)
    except Exception:
        return False
    return True


def _compute_receipt_head(body_obj: Any) -> str:
    """
    Compute the canonical commitment used as receipt head.

    This must match the writer-side behavior; here we assume
    the writer used `commitment_hex` over the entire body object
    with a fixed domain/schema.
    """
    payload = {"body": body_obj}
    return commitment_hex(payload, schema="tcd.receipt.v1", domain=_RECEIPT_HEAD_DOMAIN)


def _verify_optional_commit_field(
    body: Mapping[str, Any],
    *,
    obj: Any,
    body_field: str,
    schema: str,
    strict: bool,
) -> bool:
    """
    Best-effort check that `obj` matches the commitment stored in `body[body_field]`.

    Rules:
      - If `obj` is None:
          Always succeeds (nothing to verify).
      - If `obj` is not None and `body_field` is present:
          - The field must be a hex string and must match the computed commitment.
      - If `obj` is not None and `body_field` is missing:
          - In strict mode: fail.
          - In non-strict mode: succeed (caller accepts weaker guarantees).
    """
    if obj is None:
        return True

    expected_hex = commitment_hex({"value": obj}, schema=schema, domain="tcd.obj.v1")
    in_body = body.get(body_field)

    if in_body is None:
        if strict:
            return False
        return True

    if not isinstance(in_body, str) or not _is_hex_string(in_body, min_len=8):
        return False

    if not secure_compare_hex(in_body, expected_hex):
        return False

    return True


def _validate_supply_chain_section(
    supply: Mapping[str, Any],
    *,
    strict: bool,
) -> bool:
    """
    Validate the structure of the body["supply_chain"] section.

    Expectations:
      - build_id / image_digest: short strings.
      - sbom_commit / attestation_commit: hex strings.
      - not_before / not_after: numeric.
      - issuer: short string.
      - In strict mode: attestation_commit must be present.
    """
    build_id = supply.get("build_id")
    if build_id is not None and not isinstance(build_id, str):
        return False
    if isinstance(build_id, str) and len(build_id) > 256:
        return False

    image_digest = supply.get("image_digest")
    if image_digest is not None and not isinstance(image_digest, str):
        return False
    if isinstance(image_digest, str) and len(image_digest) > 256:
        return False

    sbom_commit = supply.get("sbom_commit")
    if sbom_commit is not None:
        if not _is_hex_string(sbom_commit, min_len=16):
            return False

    attest_commit = supply.get("attestation_commit")
    if attest_commit is not None:
        if not _is_hex_string(attest_commit, min_len=16):
            return False

    for time_field in ("not_before", "not_after"):
        tf = supply.get(time_field)
        if tf is None:
            continue
        try:
            float(tf)
        except Exception:
            return False

    issuer = supply.get("issuer")
    if issuer is not None and not isinstance(issuer, str):
        return False
    if isinstance(issuer, str) and len(issuer) > 256:
        return False

    if strict and attest_commit is None:
        return False

    return True


def _validate_body_security(
    body: Mapping[str, Any],
    *,
    strict: bool,
) -> bool:
    """
    Apply structural and security constraints to a single receipt body.

    This enforces:
      - Metadata key constraints (forbids prompt/completion-like keys).
      - trust_zone / route_profile vocab.
      - override fields (insider override / break-glass shape).
      - supply_chain section structure.
      - PQ section structure.
      - Basic constraints on e_value.
    """
    # 1) Key-level constraints: forbid content-like keys; score/e_value/p_value numeric-only
    try:
        enforce_metadata_keys(
            body,
            forbid_keys=_FORBIDDEN_RECEIPT_KEYS,
            numeric_only_keys=("score", "p_value", "e_value"),
            max_depth=3,
        )
    except Exception:
        return False

    # 2) trust_zone / route_profile vocab
    tz = body.get("trust_zone")
    if tz is not None:
        if not isinstance(tz, str):
            return False
        if strict and tz not in _ALLOWED_TRUST_ZONES:
            return False

    rp = body.get("route_profile")
    if rp is not None:
        if not isinstance(rp, str):
            return False
        if strict and rp not in _ALLOWED_ROUTE_PROFILES:
            return False

    # 3) override / break-glass fields
    override_applied = body.get("override_applied")
    override_actor = body.get("override_actor")
    override_level = body.get("override_level")

    if override_applied is not None:
        if not isinstance(override_applied, bool):
            return False
        if override_applied:
            if not isinstance(override_actor, str) or not override_actor:
                return False
            if override_level is not None:
                if not isinstance(override_level, str):
                    return False
                if strict and override_level not in _ALLOWED_OVERRIDE_LEVELS:
                    return False

    # 4) supply_chain section
    supply_chain = body.get("supply_chain")
    if supply_chain is not None:
        if not isinstance(supply_chain, Mapping):
            return False
        if not _validate_supply_chain_section(supply_chain, strict=strict):
            return False

    # 5) PQ posture / structure
    pq_scheme = body.get("pq_scheme", "")
    pq_pub_hex = body.get("pq_pub_hex")
    pq_sig_hex = body.get("pq_sig_hex")

    if pq_scheme is not None:
        if not isinstance(pq_scheme, str):
            return False
        if strict and pq_scheme not in _ALLOWED_PQ_SCHEMES:
            return False

    if pq_pub_hex is not None:
        if not _is_hex_string(pq_pub_hex, min_len=16):
            return False

    if pq_sig_hex is not None:
        if not _is_hex_string(pq_sig_hex, min_len=32):
            return False

    # 6) e_value basic constraints (finite and non-negative)
    e_val = body.get("e_value")
    if e_val is not None:
        try:
            e_f = float(e_val)
        except Exception:
            return False
        if not (e_f >= 0.0 and e_f < float("inf")):
            return False

    return True


def _verify_witness_segments(
    witness_segments: Any,
    *,
    strict: bool,
) -> bool:
    """
    Lightweight structural validation for witness segments.

    This does NOT implement Merkle or proof validation; it only ensures:
      - witness_segments is a list/tuple;
      - each element is a mapping;
      - each mapping has a "hash" field that looks like hex;
      - each mapping is canonically JSON-serializable.
    """
    if witness_segments is None:
        return True

    if not isinstance(witness_segments, (list, tuple)):
        return False

    for seg in witness_segments:
        if not isinstance(seg, Mapping):
            return False
        h = seg.get("hash")
        if not isinstance(h, str) or not _is_hex_string(h, min_len=8):
            return False
        try:
            canonical_json_dumps(seg)
        except Exception:
            return False

    return True


# ---------------------------------------------------------------------------
# Public API: single receipt verification
# ---------------------------------------------------------------------------


def verify_receipt(
    *,
    receipt_head_hex: str,
    receipt_body_json: str,
    verify_key_hex: Optional[str] = None,
    receipt_sig_hex: Optional[str] = None,
    req_obj: Any = None,
    comp_obj: Any = None,
    e_obj: Any = None,
    witness_segments: Any = None,
    strict: bool = True,
) -> bool:
    """
    Content-agnostic verification of a single receipt.

    This function does not inspect or store raw prompt/output content.
    It only works with compact metadata and cryptographic commitments.

    Checks performed:
      1. Basic type and shape checks:
         - `receipt_body_json` must be valid JSON and must respect a size bound.
         - `receipt_head_hex` must be a non-empty hex string.
         - If provided, `verify_key_hex` and `receipt_sig_hex` must be
           hex strings.
      2. Receipt body structural and security checks:
         - Key-level constraints via `enforce_metadata_keys` (forbid content-like keys).
         - trust_zone / route_profile vocab.
         - override, supply_chain, and PQ sections.
      3. Head commitment:
         - Recompute a canonical commitment over the parsed body object,
           and compare it against `receipt_head_hex`.
      4. Optional object-commitment checks (if `req_obj`, `comp_obj`,
         `e_obj` are provided):
         - For each provided object, compute a canonical commitment and
           compare it against the corresponding field in the receipt body:
               * req_obj  -> body["req_commit"]
               * comp_obj -> body["comp_commit"]
               * e_obj    -> body["e_commit"]
         - In strict mode: if an object is provided but the field is missing,
           this is treated as a failure.
         - In any mode: if the field is present but does not match the
           computed commitment, this is treated as a failure.
      5. Optional witness segment checks:
         - Structural validation only (see `_verify_witness_segments`).
      6. Signature fields:
         - This function does not perform cryptographic signature
           verification. It only enforces structural sanity of key/signature
           fields (hex-shaped, minimal length). Full signature and PQ
           attestation verification is left to higher-level components.

    The `strict` flag controls how aggressively missing optional
    commitments are treated:
      - strict=True:
          Missing commitment fields for provided objects cause failure.
      - strict=False:
          Missing commitment fields are allowed; only mismatches cause failure.
    """
    # 1. Basic receipt head checks
    if not isinstance(receipt_head_hex, str) or not _is_hex_string(
        receipt_head_hex, min_len=8
    ):
        return False

    # 1.1 Body size bound (defensive against oversized receipts)
    if not isinstance(receipt_body_json, str):
        return False
    if len(receipt_body_json.encode("utf-8", errors="ignore")) > _MAX_RECEIPT_BODY_BYTES:
        return False

    # 2. Parse body JSON
    body_obj = _safe_json_loads(receipt_body_json)
    if body_obj is None or not isinstance(body_obj, Mapping):
        return False

    # 2.1 Structural & security checks (content-agnostic)
    if not _validate_body_security(body_obj, strict=strict):
        return False

    # 3. Signature field shape checks (no crypto verification here)
    if verify_key_hex is not None:
        if not _is_hex_string(verify_key_hex, min_len=16):
            return False
    if receipt_sig_hex is not None:
        if not _is_hex_string(receipt_sig_hex, min_len=32):
            return False

    # 4. Recompute the canonical head and compare
    recomputed_head = _compute_receipt_head(body_obj)
    if not secure_compare_hex(recomputed_head, receipt_head_hex):
        return False

    # 5. Optional object commitments: req / comp / e
    if not _verify_optional_commit_field(
        body_obj,
        obj=req_obj,
        body_field="req_commit",
        schema=_REQ_SCHEMA,
        strict=strict,
    ):
        return False

    if not _verify_optional_commit_field(
        body_obj,
        obj=comp_obj,
        body_field="comp_commit",
        schema=_COMP_SCHEMA,
        strict=strict,
    ):
        return False

    if not _verify_optional_commit_field(
        body_obj,
        obj=e_obj,
        body_field="e_commit",
        schema=_E_SCHEMA,
        strict=strict,
    ):
        return False

    # 6. Witness segments (optional structural check)
    if not _verify_witness_segments(witness_segments, strict=strict):
        return False

    # At this layer we only guarantee structural and commitment-level checks.
    # Signature and PQ verification must be performed by a higher-level module.
    return True


# ---------------------------------------------------------------------------
# Public API: chain verification
# ---------------------------------------------------------------------------


def verify_chain(
    heads: Sequence[str],
    bodies: Sequence[str],
    *,
    strict: bool = True,
) -> bool:
    """
    Verify a linear chain of receipts in a content-agnostic way.

    The chain is defined by:
      - `heads[i]`: hex-encoded head commitment of receipt i;
      - `bodies[i]`: JSON-encoded body of receipt i.

    This function performs:
      1. Shape and length checks for the `heads` and `bodies` sequences.
      2. Per-receipt structural checks via `verify_receipt` (without
         signature or object verification).
      3. Chain linkage checks:
         - For i > 0, the `prev` pointer in bodies[i] (if present) must
           match `heads[i-1]`. Supported field names (first match wins):
             * "prev"
             * "prev_head"
             * "prev_receipt"
             * "prev_receipt_head"
         - For i == 0, if a `prev` field is present it must be null/empty.
      4. Chain metadata checks:
         - If any body has a `chain_id`, all bodies that specify `chain_id`
           must agree. In strict mode, all receipts must specify it.
         - If timestamps are present ("ts" or "timestamp"), they must be
           non-decreasing along the chain.
      5. PQ scheme consistency:
         - If any body specifies `pq_scheme`, all receipts that specify it
           must agree. In strict mode, all receipts must specify the same
           scheme consistently.
    """
    # 1. Basic sequence checks
    if not isinstance(heads, Sequence) or not isinstance(bodies, Sequence):
        return False
    if len(heads) != len(bodies):
        return False
    if len(heads) == 0:
        return False

    # Pre-parse bodies and run per-receipt checks
    parsed_bodies: List[Mapping[str, Any]] = []
    for i, (h, b) in enumerate(zip(heads, bodies)):
        if not isinstance(h, str) or not _is_hex_string(h, min_len=8):
            return False
        if not isinstance(b, str):
            return False

        # Structural and commitment-level checks only
        if not verify_receipt(
            receipt_head_hex=h,
            receipt_body_json=b,
            verify_key_hex=None,
            receipt_sig_hex=None,
            req_obj=None,
            comp_obj=None,
            e_obj=None,
            witness_segments=None,
            strict=strict,
        ):
            return False

        body_obj = _safe_json_loads(b)
        if body_obj is None or not isinstance(body_obj, Mapping):
            return False
        parsed_bodies.append(body_obj)

    # 2. Chain linkage and metadata checks

    # Chain ID consistency
    chain_ids: List[str] = []
    for body in parsed_bodies:
        cid = body.get("chain_id")
        if isinstance(cid, str) and cid:
            chain_ids.append(cid)

    if chain_ids:
        # All non-empty chain_ids must match
        first_cid = chain_ids[0]
        if any(cid != first_cid for cid in chain_ids[1:]):
            return False
        if strict:
            # In strict mode, if some receipts have chain_id and others do not,
            # treat it as a configuration mismatch.
            for body in parsed_bodies:
                cid = body.get("chain_id")
                if not isinstance(cid, str) or not cid:
                    return False

    # PQ scheme consistency across the chain
    pq_schemes: List[str] = []
    for body in parsed_bodies:
        pq_scheme = body.get("pq_scheme")
        if isinstance(pq_scheme, str) and pq_scheme:
            pq_schemes.append(pq_scheme)

    if pq_schemes:
        first_scheme = pq_schemes[0]
        if any(s != first_scheme for s in pq_schemes[1:]):
            return False
        if strict:
            # In strict mode, if any receipt declares a scheme,
            # all receipts must declare the same scheme.
            for body in parsed_bodies:
                pq_scheme = body.get("pq_scheme")
                if not isinstance(pq_scheme, str) or pq_scheme != first_scheme:
                    return False

    # Timestamp monotonicity
    last_ts: Optional[float] = None
    for body in parsed_bodies:
        ts = body.get("ts", body.get("timestamp"))
        if ts is None:
            if strict and last_ts is not None:
                # Once a timestamp has appeared, strict mode expects
                # timestamps on all subsequent receipts.
                return False
            continue
        try:
            ts_f = float(ts)
        except Exception:
            return False
        if last_ts is not None and ts_f < last_ts:
            return False
        last_ts = ts_f

    # prev-link checks
    prev_field_candidates = (
        "prev",
        "prev_head",
        "prev_receipt",
        "prev_receipt_head",
    )

    for i, (head, body) in enumerate(zip(heads, parsed_bodies)):
        prev_value: Optional[str] = None
        prev_field_present = False

        for fn in prev_field_candidates:
            if fn in body:
                prev_field_present = True
                prev_raw = body.get(fn)
                if prev_raw is None or prev_raw == "":
                    prev_value = None
                elif isinstance(prev_raw, str):
                    prev_value = prev_raw
                else:
                    return False
                break

        if i == 0:
            # First element in chain
            if prev_field_present and prev_value not in (None, ""):
                # First element must not point backwards
                return False
            # Absence of prev for the first element is allowed in both modes
            continue

        # For i > 0: prev must match heads[i-1] if present
        if prev_field_present:
            if prev_value is None:
                # Explicit null/empty prev for non-first element is invalid
                return False
            if not secure_compare_hex(prev_value, heads[i - 1]):
                return False
        else:
            # Missing prev field for non-first element:
            if strict:
                return False
            # Non-strict mode: tolerate missing prev, with weaker guarantees

    return True