# FILE: tcd/receipt_v2.py
# Structured, audit-friendly receipt body builder for TCD.
#
# Design goals:
# - Make each receipt a small, self-contained record of *how* a decision was
#   produced, without ever storing prompts / completions.
# - Use a fixed, documented schema with nested sections so that:
#     * review / audit teams can reason about fields,
#     * verifiers can hash + sign a stable representation,
#     * future versions (v3, v4, …) can evolve without breaking v2.
# - Keep the module small and dependency-light (stdlib only), so it is easy to
#   review line-by-line in strict environments.
#
# NOTE:
#   This module intentionally does *not* deal with cryptography. Hashing and
#   signing are handled in tcd.crypto; this file is only about the structured
#   body that will later be hashed/signed/linked into a ledger.

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, Mapping, MutableMapping, Optional


RECEIPT_VERSION = "v2"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _utc_now_iso() -> str:
    """
    Return a UTC timestamp in a stable, audit-friendly format.

    Example: "2025-11-22T05:12:34.123456Z"
    """
    return datetime.now(tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _to_shallow_dict(obj: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    """
    Defensive conversion of a mapping-like object to a plain dict.

    - None  -> {}
    - dict  -> shallow copy
    - other Mapping -> shallow copy via items()
    """
    if obj is None:
        return {}
    if isinstance(obj, dict):
        return dict(obj)
    return {str(k): v for k, v in obj.items()}


def _ensure_json_primitive(value: Any) -> Any:
    """
    Ensure a value is JSON-serializable (for shallow fields).

    This is intentionally conservative: we only special-case a few
    common types; everything else is stringified so that encoding
    never fails in a production pipeline.
    """
    if value is None:
        return None
    if isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, (list, tuple)):
        return [_ensure_json_primitive(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _ensure_json_primitive(v) for k, v in value.items()}
    # Fallback: best-effort string representation.
    return str(value)


def _normalize_mapping_for_json(m: Mapping[str, Any]) -> Dict[str, Any]:
    """
    Apply `_ensure_json_primitive` to all values in a mapping.
    """
    return {str(k): _ensure_json_primitive(v) for k, v in m.items()}


# ---------------------------------------------------------------------------
# Receipt sections
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ModelSection:
    """
    Model-side identifiers.

    - model_hash:     hash/fingerprint of the model weights *as deployed*.
    - tokenizer_hash: hash/fingerprint of the tokenizer / vocab.
    - sampler_cfg:    (shallow) snapshot of sampling configuration:
                      temperature, top_p, max_tokens, etc.
    """

    model_hash: str
    tokenizer_hash: str
    sampler_cfg: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(
        cls,
        *,
        model_hash: str,
        tokenizer_hash: str,
        sampler_cfg: Mapping[str, Any] | None,
    ) -> "ModelSection":
        return cls(
            model_hash=str(model_hash),
            tokenizer_hash=str(tokenizer_hash),
            sampler_cfg=_normalize_mapping_for_json(_to_shallow_dict(sampler_cfg)),
        )


@dataclass(frozen=True)
class RuntimeSection:
    """
    Per-request runtime metrics.

    All time/throughput fields are recorded as numeric scalars with units:

    - latency_ms:        end-to-end latency in milliseconds.
    - throughput_tok_s:  decoded tokens / second.
    - context_len:       number of tokens in the effective context window.
    - kv_digest:         hash/fingerprint of the KV-cache layout for this call.
    - rng_seed:          RNG seed / seed material bound to this request.

    Additional optional fields improve ordering and timeline reconstruction:

    - ts_unix_ms:        wall-clock timestamp in milliseconds since epoch.
    - monotonic_ms:      monotonic clock reading in milliseconds.
    - request_seq:       engine-local sequence number for this request.
    """

    latency_ms: float
    throughput_tok_s: float
    context_len: int
    kv_digest: str
    rng_seed: Any  # kept generic; calling code may enforce a stricter type

    ts_unix_ms: Optional[int] = None
    monotonic_ms: Optional[int] = None
    request_seq: Optional[int] = None

    @classmethod
    def from_raw(
        cls,
        *,
        latency_ms: Any,
        throughput_tok_s: Any,
        context_len: Any,
        kv_digest: str,
        rng_seed: Any,
        ts_unix_ms: Any = None,
        monotonic_ms: Any = None,
        request_seq: Any = None,
    ) -> "RuntimeSection":
        # Be defensive about numeric types; we coerce where reasonable.
        try:
            lat = float(latency_ms) if latency_ms is not None else 0.0
        except Exception:
            lat = 0.0

        try:
            thr = float(throughput_tok_s) if throughput_tok_s is not None else 0.0
        except Exception:
            thr = 0.0

        try:
            ctx = int(context_len)
        except Exception:
            ctx = 0

        ts_val: Optional[int]
        try:
            ts_val = int(ts_unix_ms) if ts_unix_ms is not None else None
        except Exception:
            ts_val = None

        mono_val: Optional[int]
        try:
            mono_val = int(monotonic_ms) if monotonic_ms is not None else None
        except Exception:
            mono_val = None

        req_seq_val: Optional[int]
        try:
            req_seq_val = int(request_seq) if request_seq is not None else None
        except Exception:
            req_seq_val = None

        return cls(
            latency_ms=lat,
            throughput_tok_s=thr,
            context_len=ctx,
            kv_digest=str(kv_digest),
            rng_seed=_ensure_json_primitive(rng_seed),
            ts_unix_ms=ts_val,
            monotonic_ms=mono_val,
            request_seq=req_seq_val,
        )


@dataclass(frozen=True)
class BatchSection:
    """
    Placement of this request inside its batch.

    - batch_index:  index within the batch [0, batch_size).
    - batch_size:   total number of requests in the batch.
    """

    batch_index: int
    batch_size: int

    @classmethod
    def from_raw(cls, *, batch_index: Any, batch_size: Any) -> "BatchSection":
        try:
            idx = int(batch_index)
        except Exception:
            idx = 0
        try:
            size = int(batch_size)
        except Exception:
            size = 1
        return cls(batch_index=idx, batch_size=size)


@dataclass(frozen=True)
class EvidenceSection:
    """
    Snapshot of the controller / e-process / risk accumulator state.

    The concrete structure is intentionally flexible and comes from the
    caller (typically the decision engine), but we enforce that:

      - keys are strings,
      - values are JSON-encodable via `_ensure_json_primitive`.

    Example contents (depending on your decision engine):

      - current e-value / wealth,
      - per-policy risk scores,
      - anomaly flags,
      - routing decision that was taken.
    """

    snapshot: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_raw(cls, e_snapshot: Mapping[str, Any] | None) -> "EvidenceSection":
        return cls(snapshot=_normalize_mapping_for_json(_to_shallow_dict(e_snapshot)))


@dataclass(frozen=True)
class ControlSection:
    """
    Control / decision information for this request.

    - decision:       final action taken (e.g., "allow", "block", "degrade", "slow").
    - reason:         short, non-sensitive reason code (e.g., "policy_match").
    - policy_id:      identifier of the policy bundle used.
    - policy_version: version or hash of the policy configuration.
    - rule_path:      ordered list of rule identifiers that fired or were evaluated.
    - risk_level:     coarse risk classification ("low", "medium", "high", "critical").
    """

    decision: str
    reason: Optional[str] = None
    policy_id: Optional[str] = None
    policy_version: Optional[str] = None
    rule_path: list[str] = field(default_factory=list)
    risk_level: Optional[str] = None

    @classmethod
    def from_raw(
        cls,
        *,
        decision: str,
        reason: Optional[str],
        policy_id: Optional[str],
        policy_version: Optional[str],
        rule_path: Any,
        risk_level: Optional[str],
    ) -> "ControlSection":
        if isinstance(rule_path, (list, tuple)):
            path = [str(x) for x in rule_path]
        elif rule_path is None:
            path = []
        else:
            path = [str(rule_path)]

        return cls(
            decision=str(decision),
            reason=str(reason) if reason is not None else None,
            policy_id=str(policy_id) if policy_id is not None else None,
            policy_version=str(policy_version) if policy_version is not None else None,
            rule_path=path,
            risk_level=str(risk_level) if risk_level is not None else None,
        )


@dataclass(frozen=True)
class EnvironmentSection:
    """
    Environment / topology context (de-identified).

    - host_handle:     opaque identifier for the host (e.g., hashed hostname).
    - cluster_id:      opaque cluster identifier.
    - region:          short region code (e.g., "region-a").
    - zone:            short zone/az code.
    - runtime_profile: "online_inference", "batch_eval", etc.
    """

    host_handle: Optional[str] = None
    cluster_id: Optional[str] = None
    region: Optional[str] = None
    zone: Optional[str] = None
    runtime_profile: Optional[str] = None

    @classmethod
    def from_raw(
        cls,
        *,
        host_handle: Optional[str],
        cluster_id: Optional[str],
        region: Optional[str],
        zone: Optional[str],
        runtime_profile: Optional[str],
    ) -> "EnvironmentSection":
        return cls(
            host_handle=str(host_handle) if host_handle is not None else None,
            cluster_id=str(cluster_id) if cluster_id is not None else None,
            region=str(region) if region is not None else None,
            zone=str(zone) if zone is not None else None,
            runtime_profile=str(runtime_profile) if runtime_profile is not None else None,
        )


@dataclass(frozen=True)
class MetaSection:
    """
    Receipt-level metadata that is orthogonal to the model / runtime.

    Core metadata:
    - version:      receipt schema version ("v2").
    - created_at:   UTC creation timestamp (ISO-8601).
    - schema_id:    stable identifier of this schema ("tcd.receipt.v2").

    Security / profile metadata (purely descriptive; no crypto here):
    - crypto_profile: profile name selected by the caller.
    - pq_mode:        post-quantum mode indicator.
    - hash_algo:      name of the hash algorithm used by crypto layer.
    - mac_algo:       name of the MAC algorithm used by crypto layer.
    - sign_algo:      name of the signature algorithm used by crypto layer.

    Classification / sequencing:
    - classification: coarse data handling label.
    - receipt_id:     external identifier for this receipt (e.g., UUID).
    - session_id:     logical session/flow identifier.
    - decision_seq:   increasing sequence number (global or per-session).
    """

    version: str = RECEIPT_VERSION
    created_at: str = field(default_factory=_utc_now_iso)
    schema_id: str = "tcd.receipt.v2"

    crypto_profile: Optional[str] = None
    pq_mode: Optional[str] = None
    hash_algo: Optional[str] = None
    mac_algo: Optional[str] = None
    sign_algo: Optional[str] = None

    classification: str = "unclassified"
    receipt_id: Optional[str] = None
    session_id: Optional[str] = None
    decision_seq: Optional[int] = None


@dataclass(frozen=True)
class ReceiptBodyV2:
    """
    Top-level v2 receipt body.

    This is the object that will be hashed/signed and later embedded in a
    cryptographic receipt. It deliberately does *not* contain prompts,
    completions, or any other user text.
    """

    model: ModelSection
    runtime: RuntimeSection
    batch: BatchSection
    evidence: EvidenceSection
    meta: MetaSection
    control: Optional[ControlSection] = None
    env: Optional[EnvironmentSection] = None

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to a plain dict suitable for JSON encoding and hashing.

        The structure is:

        {
          "version": "...",
          "created_at": "...",
          "schema_id": "...",
          "model": { ... },
          "runtime": { ... },
          "batch": { ... },
          "evidence": { ... },
          "control": { ... },   # optional
          "env": { ... },       # optional
          ...
        }
        """
        # Flatten meta to the top level for convenience, but keep the
        # other sections grouped.
        meta_dict = asdict(self.meta)
        body: Dict[str, Any] = {
            "model": asdict(self.model),
            "runtime": asdict(self.runtime),
            "batch": asdict(self.batch),
            "evidence": asdict(self.evidence),
        }
        if self.control is not None:
            body["control"] = asdict(self.control)
        if self.env is not None:
            body["env"] = asdict(self.env)
        body.update(meta_dict)
        return body


# ---------------------------------------------------------------------------
# Public builder (backwards-compatible entry point)
# ---------------------------------------------------------------------------


def build_v2_body(
    *,
    model_hash: str,
    tokenizer_hash: str,
    sampler_cfg: Mapping[str, Any] | None,
    context_len: int,
    kv_digest: str,
    rng_seed: Any,
    latency_ms: Any,
    throughput_tok_s: Any,
    batch_index: int,
    batch_size: int,
    e_snapshot: Mapping[str, Any] | None,
    # Runtime extensions (optional)
    ts_unix_ms: Any = None,
    monotonic_ms: Any = None,
    request_seq: Any = None,
    # Control section (optional)
    decision: Optional[str] = None,
    decision_reason: Optional[str] = None,
    policy_id: Optional[str] = None,
    policy_version: Optional[str] = None,
    rule_path: Any = None,
    risk_level: Optional[str] = None,
    # Environment section (optional)
    host_handle: Optional[str] = None,
    cluster_id: Optional[str] = None,
    region: Optional[str] = None,
    zone: Optional[str] = None,
    runtime_profile: Optional[str] = None,
    # Meta / security (optional)
    crypto_profile: Optional[str] = None,
    pq_mode: Optional[str] = None,
    hash_algo: Optional[str] = None,
    mac_algo: Optional[str] = None,
    sign_algo: Optional[str] = None,
    classification: str = "unclassified",
    receipt_id: Optional[str] = None,
    session_id: Optional[str] = None,
    decision_seq: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Build a structured v2 receipt body.

    This function intentionally takes only *non-text* inputs related to
    decisions and system state. It is typically called by the decision
    engine once a routing action has been chosen, and its output is what
    later gets hashed and signed by tcd.crypto.

    Parameters
    ----------
    model_hash:
        Identifier / hash of the deployed model weights.
    tokenizer_hash:
        Identifier / hash of the tokenizer / vocab.
    sampler_cfg:
        Shallow sampler configuration (temperature, top_p, etc.).
    context_len:
        Effective context length (number of tokens) for this request.
    kv_digest:
        Digest / fingerprint of KV cache layout tied to this call.
    rng_seed:
        RNG seed or seed material used for sampling.
    latency_ms:
        End-to-end latency (ms).
    throughput_tok_s:
        Decoded tokens per second.
    batch_index:
        Index of this request in the batch.
    batch_size:
        Total batch size.
    e_snapshot:
        Snapshot of controller / risk / e-process state at decision time.

    Optional additions (all keyword-only):
    - ts_unix_ms, monotonic_ms, request_seq: runtime ordering hints.
    - decision, decision_reason, policy_id, policy_version, rule_path, risk_level:
      structured control/decision information.
    - host_handle, cluster_id, region, zone, runtime_profile:
      de-identified environment context.
    - crypto_profile, pq_mode, hash_algo, mac_algo, sign_algo:
      descriptive crypto-related metadata provided by the caller.
    - classification, receipt_id, session_id, decision_seq:
      handling label and sequencing identifiers.

    Returns
    -------
    dict
        A nested dict conforming to the v2 schema, safe for JSON encoding
        and ready to be fed into the hashing / signing pipeline.
    """
    model_section = ModelSection.from_raw(
        model_hash=model_hash,
        tokenizer_hash=tokenizer_hash,
        sampler_cfg=sampler_cfg,
    )
    runtime_section = RuntimeSection.from_raw(
        latency_ms=latency_ms,
        throughput_tok_s=throughput_tok_s,
        context_len=context_len,
        kv_digest=kv_digest,
        rng_seed=rng_seed,
        ts_unix_ms=ts_unix_ms,
        monotonic_ms=monotonic_ms,
        request_seq=request_seq,
    )
    batch_section = BatchSection.from_raw(
        batch_index=batch_index,
        batch_size=batch_size,
    )
    evidence_section = EvidenceSection.from_raw(e_snapshot=e_snapshot)

    control_section: Optional[ControlSection] = None
    if decision is not None:
        control_section = ControlSection.from_raw(
            decision=decision,
            reason=decision_reason,
            policy_id=policy_id,
            policy_version=policy_version,
            rule_path=rule_path,
            risk_level=risk_level,
        )

    env_section: Optional[EnvironmentSection] = None
    if any(v is not None for v in (host_handle, cluster_id, region, zone, runtime_profile)):
        env_section = EnvironmentSection.from_raw(
            host_handle=host_handle,
            cluster_id=cluster_id,
            region=region,
            zone=zone,
            runtime_profile=runtime_profile,
        )

    meta_section = MetaSection(
        crypto_profile=crypto_profile,
        pq_mode=pq_mode,
        hash_algo=hash_algo,
        mac_algo=mac_algo,
        sign_algo=sign_algo,
        classification=classification,
        receipt_id=receipt_id,
        session_id=session_id,
        decision_seq=decision_seq,
    )

    receipt = ReceiptBodyV2(
        model=model_section,
        runtime=runtime_section,
        batch=batch_section,
        evidence=evidence_section,
        meta=meta_section,
        control=control_section,
        env=env_section,
    )
    return receipt.to_dict()