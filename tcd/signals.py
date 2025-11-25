# FILE: tcd/signals.py
"""
Structured, content-agnostic signal bus for TCD.

This module defines:

  - Typed signal payloads for:
      * risk decisions (diagnose),
      * routing decisions,
      * receipt / verification results,
      * PQ signer / key health.

  - A synchronous, in-process signal bus that:
      * is deterministic (no background threads, no async),
      * does not store prompts, completions, or other raw content,
      * only carries IDs, hashes, numeric summaries and narrow enums,
      * can be wired into logging, metrics, SIEM, or audit sinks.

Design goals:

  - Content-agnostic:
      No raw text, no token streams, no personal identifiers. Only tenant/user
      IDs that are already opaque (or hashed) and coarse categories such as
      trust_zone, threat_kind, etc.

  - Deterministic:
      For a fixed (config, inputs, metadata), all signal payloads must be
      reproducible bit-for-bit.

  - Audit-friendly:
      Fields are aligned with the rest of TCD
      (AV controller, strategy router, receipts, PQ verification) so that an
      auditor can reconstruct the full path of a decision from signals alone.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, Iterable, List, Optional, Protocol, Type, TypeVar, Union

logger = logging.getLogger(__name__)

try:  # optional, used only for hashing opaque IDs
    from .crypto import Blake3Hash  # type: ignore
except Exception:  # pragma: no cover
    Blake3Hash = None  # type: ignore


# ---------------------------------------------------------------------------
# Common context / enums (string-based, no external deps)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SubjectContext:
    """
    Coarse, opaque subject identifiers.

    All values are expected to be tenant-scoped opaque IDs or hashes.

    IMPORTANT:
      - These fields MUST NOT contain emails, real names, phone numbers,
        addresses, or other direct personal identifiers.
      - Upstream code is expected to hash or tokenize any such values before
        constructing a SubjectContext.

    subject_hash is a deterministic hash derived from (tenant, user, session)
    and is suitable for long-term audit / metrics use.
    """

    tenant: str = "tenant0"
    user: str = "user0"
    session: str = "sess0"
    subject_hash: Optional[str] = None

    def key(self) -> str:
        """Compact, deterministic key used for in-memory maps and metrics."""
        return f"{self.tenant}:{self.user}:{self.session}"


@dataclass(frozen=True)
class ModelContext:
    """
    Context about the model / hardware / runtime surface of a decision.

    Fields:
      - model_id: logical model identifier.
      - gpu_id: hardware slot / accelerator identifier.
      - task: logical task (e.g. "chat", "embed").
      - lang: coarse language tag (e.g. "en", "fr").

    Optional audit fields:
      - model_version: semantic or internal model version.
      - model_config_hash: stable hash of the model configuration.
      - region: deployment region identifier (e.g. "region-a-1").
      - runtime_env: runtime type string (e.g. "k8s", "baremetal").
    """

    model_id: str = "model0"
    gpu_id: str = "gpu0"
    task: str = "chat"
    lang: str = "en"

    model_version: Optional[str] = None
    model_config_hash: Optional[str] = None
    region: Optional[str] = None
    runtime_env: Optional[str] = None


@dataclass(frozen=True)
class SecurityContext:
    """
    Coarse security posture around a decision.

    All values are string enums with deliberately small vocabularies:

      - trust_zone:
          "internet", "internal", "partner", "admin"
      - route_profile:
          "inference", "admin", "control"
      - threat_kind:
          "apt", "insider", "supply_chain", or None

    PQ and policy fields mirror the rest of TCD:

      - pq_required / pq_ok:
          Policy requirement vs. actual PQ usage.
      - policy_ref / policyset_ref:
          Which policy and policy set governed the decision.

    Supply-chain and override fields allow audits to see when break-glass
    or suspicious runtime conditions were involved.
    """

    trust_zone: str = "internet"
    route_profile: str = "inference"

    threat_kind: Optional[str] = None
    threat_confidence: Optional[float] = None

    pq_required: bool = False
    pq_ok: Optional[bool] = None

    policy_ref: Optional[str] = None
    policyset_ref: Optional[str] = None

    build_id: Optional[str] = None
    image_digest: Optional[str] = None
    compliance_tags: List[str] = field(default_factory=list)

    # Override / break-glass signals
    override_requested: bool = False
    override_applied: bool = False
    override_reason_code: Optional[str] = None  # e.g. "incident_response"
    override_actor: Optional[str] = None        # opaque admin ID or role

    # Supply-chain risk posture
    supply_chain_risk: Optional[str] = None     # "none","suspect","compromised"
    supply_chain_source: Optional[str] = None   # e.g. "image_digest_mismatch"


@dataclass(frozen=True)
class StreamContext:
    """
    Logical stream identifiers for e-process and routing.

    These are content-agnostic identifiers:
      - stream_id: human-readable composite (e.g. "tenant:user:model").
      - stream_hash: deterministic hash (e.g. BLAKE3) computed elsewhere.
      - route_id: deterministic hash of routing inputs (from StrategyRouter).

    AV / e-process metadata:
      - av_label: label of the AV controller (e.g. "grpc", "http", "admin").
      - av_policyset_ref: AV policy set reference.
      - e_process_id: identifier for a specific e-process instance when
        multiple processes exist per subject.
    """

    stream_id: str = ""
    stream_hash: Optional[str] = None
    route_id: Optional[str] = None

    av_label: Optional[str] = None
    av_policyset_ref: Optional[str] = None
    e_process_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Signal payloads
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RiskDecisionSignal:
    """
    Emitted when TCD finishes a risk decision (Diagnose).

    This is the main "decision" fact record consuming systems will care about.
    It is fully content-agnostic; all statistics are aggregate numbers and
    hashes.

    Semantics:

      - verdict == True means "risk triggered" (not "allow").
      - action describes what a caller should do: "none", "degrade", "block".
      - cause describes which subsystem triggered first:
          "detector", "av", "pq", "supply_chain", etc.
    """

    ts: float
    subject: SubjectContext
    model: ModelContext
    security: SecurityContext
    stream: StreamContext

    verdict: bool
    action: str
    cause: str

    score: float
    threshold: float
    budget_remaining: float
    e_value: float
    alpha_alloc: float
    alpha_spent: float

    # Optional fine-grained counters
    step: int = 0
    detector_trigger: bool = False
    av_trigger: bool = False

    # Optional tags used for alerts / dashboards
    tags: List[str] = field(default_factory=list)

    # Optional decomposed scores for multi-axis risk
    apt_score: Optional[float] = None
    insider_score: Optional[float] = None
    supply_chain_score: Optional[float] = None
    drift_score: Optional[float] = None

    # Coarse risk band for compliance / reporting: "low","medium","high","critical"
    risk_band: Optional[str] = None

    # Override / break-glass results (mirrors SecurityContext)
    override_requested: bool = False
    override_applied: bool = False
    override_reason_code: Optional[str] = None
    override_actor: Optional[str] = None

    # Configuration / component version snapshots
    config_hash: Optional[str] = None
    detector_version: Optional[str] = None
    av_version: Optional[str] = None
    router_version: Optional[str] = None

    # Small auxiliary structures (already sanitized and compact)
    detector_components: Dict[str, Any] = field(default_factory=dict)
    multivar_components: Dict[str, Any] = field(default_factory=dict)
    e_process_state: Dict[str, Any] = field(default_factory=dict)
    route_info: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a plain dict suitable for logging / JSON export."""
        return asdict(self)


@dataclass(frozen=True)
class RouteDecisionSignal:
    """
    Emitted when StrategyRouter chooses a route.

    Mirrors Route / RouteView fields and adds context. Useful for:
      - tracing how risk decisions influence decoding,
      - per-tier / per-zone routing dashboards,
      - auditing that high-risk scenarios were actually routed to strict paths.
    """

    ts: float
    subject: SubjectContext
    model: ModelContext
    security: SecurityContext
    stream: StreamContext

    # Core routing knobs
    temperature: float
    top_p: float
    decoder: str
    safety_tier: str

    # Identity / policy binding
    route_id: str
    policy_ref: Optional[str] = None

    # Security extras (duplicated for ease of use)
    trust_zone: str = "internet"
    threat_tags: List[str] = field(default_factory=list)
    av_label: Optional[str] = None
    av_trigger: Optional[bool] = None
    pq_required: Optional[bool] = None
    pq_ok: Optional[bool] = None

    # Logical tags (aligned with StrategyRouter.tags conventions)
    tags: List[str] = field(default_factory=list)

    # Override flags: "manual_override", "break_glass", "policy_bypass", etc.
    override_flags: List[str] = field(default_factory=list)

    # Optional limits / reasons
    max_tokens: Optional[int] = None
    degrade_reason: Optional[str] = None

    # Optional override attribution
    override_actor: Optional[str] = None
    override_reason_code: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ReceiptSignal:
    """
    Emitted when a receipt is successfully produced or verified.

    This signal is designed to give external audit / monitoring systems a
    stable view of PQ usage, key chains, and supply-chain anchoring, without
    exposing the receipt body itself.
    """

    ts: float
    subject: SubjectContext

    # Receipt identity
    head_hex: Optional[str] = None
    sig_scheme: Optional[str] = None
    sig_chain_id: Optional[str] = None

    # Signature / PQ posture
    pq_required: bool = False
    pq_ok: Optional[bool] = None
    sig_class: Optional[str] = None          # "pq", "classical", "hybrid"
    sig_strength_bits: Optional[int] = None  # effective security estimate

    # Supply-chain attachments (as found in receipt / runtime)
    build_id: Optional[str] = None
    image_digest: Optional[str] = None
    env_fingerprint: Optional[str] = None

    # Chain-level metadata for prev-chain receipts
    chain_length: Optional[int] = None
    chain_root_hex: Optional[str] = None

    # KMS / HSM / key metadata
    signer_id: Optional[str] = None
    key_id: Optional[str] = None
    key_rotation_epoch: Optional[int] = None

    # Compliance tags relevant to this receipt
    compliance_tags: List[str] = field(default_factory=list)

    # Outcome of the operation that triggered this signal
    op_kind: str = "issue"  # "issue" or "verify"
    ok: bool = True
    error_code: Optional[str] = None
    error_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class PQHealthSignal:
    """
    Low-frequency signal about PQ signer / key health.

    Emitted by the attestor or signing subsystem when PQ health changes.
    This is intended for dashboards and watch alerts, not for per-request
    logic (per-request logic should be based on ReceiptSignal / Verify).
    """

    ts: float
    sig_chain_id: str
    sig_scheme: str

    healthy: bool
    reason: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    # Coarse health state enumerator: "ok","degraded","down","unknown"
    health_state: str = "ok"

    # Optional grace window until which temporary fallback is acceptable
    grace_until_ts: Optional[float] = None

    # Deployment / cluster metadata
    cluster_id: Optional[str] = None
    region: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Union of all known signal types (for type-checkers / sinks)
AnySignal = Union[RiskDecisionSignal, RouteDecisionSignal, ReceiptSignal, PQHealthSignal]


# ---------------------------------------------------------------------------
# Signal sink protocol and bus
# ---------------------------------------------------------------------------

S = TypeVar("S", bound=AnySignal)


class SignalSink(Protocol):
    """
    Consumer of signals.

    Requirements:

      - handle() MUST be synchronous and MUST NOT block indefinitely.
      - handle() MUST treat all payloads as content-agnostic metadata; sinks
        MUST NOT attempt to reconstruct or log raw prompts, completions, or
        other content from these signals.
      - handle() MUST NOT call SignalBus.emit() recursively; sinks are not
        allowed to re-emit signals derived from the same decision in a way
        that creates cycles.
    """

    def handle(self, signal: AnySignal) -> None:
        ...


class LoggingSink:
    """
    Default sink that logs signals as structured entries.

    This is intended for local debugging or very small deployments. Larger
    deployments are expected to implement custom sinks that push to metrics,
    SIEM, or dedicated audit systems.
    """

    def __init__(self, logger_obj: Optional[logging.Logger] = None) -> None:
        self._logger = logger_obj or logger.getChild("signals")

    def handle(self, signal: AnySignal) -> None:  # pragma: no cover (logging side-effect)
        try:
            name = type(signal).__name__
            payload = signal.to_dict() if hasattr(signal, "to_dict") else asdict(signal)
            self._logger.info("tcd.signal.%s %s", name, payload)
        except Exception:
            self._logger.exception("Failed to log signal of type %s", type(signal).__name__)


class SignalBus:
    """
    Synchronous, in-process signal bus.

    Features:

      - No background threads, no async; emit() calls each sink directly.
      - Separate sink lists per signal type for efficient dispatch.
      - Registration / deregistration are O(1) per sink.
      - Deterministic ordering: sinks are called in registration order.
      - Simple recursion guard to prevent cycles created by misconfigured sinks.

    The bus is content-agnostic: it only sees structured signal objects.
    """

    def __init__(self) -> None:
        # Mapping from signal class to list of sinks.
        self._sinks_by_type: Dict[Type[AnySignal], List[SignalSink]] = {}
        # Optional global sinks that see all signals.
        self._global_sinks: List[SignalSink] = []
        # Thread-local recursion guard
        self._local = threading.local()

    # --- registration API -------------------------------------------------

    def register_sink(self, signal_type: Type[S], sink: SignalSink) -> None:
        """
        Register `sink` for a specific signal type.

        The same sink may be registered for multiple signal types; it is the
        sink's responsibility to branch on the signal class if needed.
        """
        sinks = self._sinks_by_type.setdefault(signal_type, [])
        if sink not in sinks:
            sinks.append(sink)

    def unregister_sink(self, signal_type: Type[S], sink: SignalSink) -> None:
        """Unregister `sink` from a specific signal type."""
        sinks = self._sinks_by_type.get(signal_type)
        if not sinks:
            return
        try:
            sinks.remove(sink)
        except ValueError:
            pass

    def register_global_sink(self, sink: SignalSink) -> None:
        """
        Register a global sink that receives all signals emitted through this
        bus, regardless of type.
        """
        if sink not in self._global_sinks:
            self._global_sinks.append(sink)

    def unregister_global_sink(self, sink: SignalSink) -> None:
        """Unregister a global sink."""
        try:
            self._global_sinks.remove(sink)
        except ValueError:
            pass

    # --- emission API -----------------------------------------------------

    def emit(self, signal: AnySignal) -> None:
        """
        Emit a signal to all registered sinks.

        The call is synchronous; all sinks are invoked in registration order.
        Exceptions raised by sinks are logged and swallowed so that one faulty
        sink cannot break the decision path.

        A simple thread-local guard prevents recursive emit() calls from
        creating cycles. Sinks MUST NOT call emit() for signals derived from
        the same decision in a way that re-enters this method.
        """
        # Recursion guard
        if getattr(self._local, "emitting", False):  # pragma: no cover (defensive)
            logger.warning("Recursive SignalBus.emit() detected; dropping signal %r", signal)
            return

        self._local.emitting = True
        try:
            # Per-type sinks
            sinks = self._sinks_by_type.get(type(signal), [])
            # Global sinks
            all_sinks: Iterable[SignalSink] = list(sinks) + list(self._global_sinks)

            for sink in all_sinks:
                try:
                    sink.handle(signal)
                except Exception:  # pragma: no cover (defensive)
                    logger.exception("Signal sink %r failed for signal %r", sink, signal)
        finally:
            self._local.emitting = False


# ---------------------------------------------------------------------------
# Convenience helpers for building contexts / signals
# ---------------------------------------------------------------------------


def _compute_subject_hash(tenant: str, user: str, session: str) -> Optional[str]:
    """
    Compute a deterministic hash for (tenant, user, session) if Blake3Hash
    is available. Returns None on any error.
    """
    if Blake3Hash is None:
        return None
    try:
        h = Blake3Hash()
        raw = f"{tenant}:{user}:{session}".encode("utf-8", "ignore")
        # Use a dedicated context string for subject hashing.
        return h.hex(raw, ctx="tcd:subject")[:64]
    except Exception:  # pragma: no cover
        return None


def make_subject_context(tenant: str, user: str, session: str) -> SubjectContext:
    """
    Construct a SubjectContext.

    Callers are responsible for ensuring that the inputs are opaque identifiers
    or hashes, not raw personal information.

    A lightweight sanity check is applied to the user field:
      - if it appears to contain an email-like pattern or spaces, a warning is
        logged and the user component is replaced with a neutral placeholder.
    """
    t = (tenant or "tenant0").strip()
    u = (user or "user0").strip()
    s = (session or "sess0").strip()

    # Soft PII check on user; do not log the raw value.
    if "@" in u or " " in u:
        logger.warning("SubjectContext.user looks like PII; upstream must hash/tokenize it")
        u = "user_invalid"

    subject_hash = _compute_subject_hash(t, u, s)
    return SubjectContext(tenant=t, user=u, session=s, subject_hash=subject_hash)


def make_model_context(
    model_id: str,
    gpu_id: str,
    task: str = "chat",
    lang: str = "en",
    model_version: Optional[str] = None,
    model_config_hash: Optional[str] = None,
    region: Optional[str] = None,
    runtime_env: Optional[str] = None,
) -> ModelContext:
    """
    Construct a ModelContext.

    Extra parameters (model_version, model_config_hash, region, runtime_env)
    are optional and may be omitted by callers that do not track them.
    """
    return ModelContext(
        model_id=model_id,
        gpu_id=gpu_id,
        task=task,
        lang=lang,
        model_version=model_version,
        model_config_hash=model_config_hash,
        region=region,
        runtime_env=runtime_env,
    )


def make_security_context(
    *,
    trust_zone: str,
    route_profile: str,
    threat_kind: Optional[str],
    threat_confidence: Optional[float],
    pq_required: bool,
    pq_ok: Optional[bool],
    policy_ref: Optional[str],
    policyset_ref: Optional[str],
    build_id: Optional[str],
    image_digest: Optional[str],
    compliance_tags: Optional[List[str]] = None,
    override_requested: bool = False,
    override_applied: bool = False,
    override_reason_code: Optional[str] = None,
    override_actor: Optional[str] = None,
    supply_chain_risk: Optional[str] = None,
    supply_chain_source: Optional[str] = None,
) -> SecurityContext:
    """
    Construct a normalized SecurityContext.

    Normalization rules:

      - trust_zone is forced into {"internet","internal","partner","admin"},
        with "internet" as fallback default.

      - route_profile is forced into {"inference","admin","control"},
        with "inference" as fallback default.

      - threat_kind is normalized into {"apt","insider","supply_chain"} or None.

      - compliance_tags are lowercased and deduplicated.

      - pq_required may be elevated based on (trust_zone, threat_kind):
          * partner/admin zones default to pq_required=True if not set;
          * "apt" / "supply_chain" threats force pq_required=True.
    """
    # trust_zone normalization
    allowed_zones = {"internet", "internal", "partner", "admin"}
    tz = (trust_zone or "internet").strip().lower()
    if tz not in allowed_zones:
        tz = "internet"

    # route_profile normalization
    allowed_profiles = {"inference", "admin", "control"}
    rp = (route_profile or "inference").strip().lower()
    if rp not in allowed_profiles:
        rp = "inference"

    # threat_kind normalization
    tk: Optional[str]
    if threat_kind is None:
        tk = None
    else:
        k = threat_kind.strip().lower()
        if k in {"apt", "insider", "supply_chain"}:
            tk = k
        else:
            tk = None

    # PQ requirement elevation
    pq_req = bool(pq_required)
    if not pq_req and tz in {"admin", "partner"}:
        pq_req = True
    if tk in {"apt", "supply_chain"}:
        pq_req = True

    # Compliance tags normalization
    tags: List[str] = []
    if compliance_tags:
        tags = sorted({(c or "").strip().lower() for c in compliance_tags if c})

    return SecurityContext(
        trust_zone=tz,
        route_profile=rp,
        threat_kind=tk,
        threat_confidence=threat_confidence,
        pq_required=pq_req,
        pq_ok=pq_ok,
        policy_ref=policy_ref,
        policyset_ref=policyset_ref,
        build_id=build_id,
        image_digest=image_digest,
        compliance_tags=tags,
        override_requested=override_requested,
        override_applied=override_applied,
        override_reason_code=override_reason_code,
        override_actor=override_actor,
        supply_chain_risk=supply_chain_risk,
        supply_chain_source=supply_chain_source,
    )


def make_stream_context(
    stream_id: str,
    stream_hash: Optional[str],
    route_id: Optional[str],
    av_label: Optional[str] = None,
    av_policyset_ref: Optional[str] = None,
    e_process_id: Optional[str] = None,
) -> StreamContext:
    """
    Construct a StreamContext.

    stream_id / stream_hash / route_id are content-agnostic identifiers.
    AV-related fields help bind this stream to a particular AV controller and
    policy set.
    """
    return StreamContext(
        stream_id=stream_id,
        stream_hash=stream_hash,
        route_id=route_id,
        av_label=av_label,
        av_policyset_ref=av_policyset_ref,
        e_process_id=e_process_id,
    )


def now_ts() -> float:
    """
    Helper to get a wall-clock timestamp in seconds.

    This uses time.time() to remain compatible with existing logs and
    timestamp formats.
    """
    return float(time.time())


__all__ = [
    # Contexts
    "SubjectContext",
    "ModelContext",
    "SecurityContext",
    "StreamContext",
    # Signals
    "RiskDecisionSignal",
    "RouteDecisionSignal",
    "ReceiptSignal",
    "PQHealthSignal",
    "AnySignal",
    # Bus / sinks
    "SignalSink",
    "LoggingSink",
    "SignalBus",
    # Helpers
    "make_subject_context",
    "make_model_context",
    "make_security_context",
    "make_stream_context",
    "now_ts",
]