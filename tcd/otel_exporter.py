# FILE: tcd/otel_exporter.py
from __future__ import annotations

import json
import random
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional, Tuple

JsonDict = Dict[str, Any]
SinkFn = Callable[[JsonDict], None]
HashFn = Callable[[str, str], str]


@dataclass
class OtelExporterConfig:
    """
    Configuration for TCDOtelExporter.

    This exporter is a lightweight, OpenTelemetry-style sink with:
      - enable/disable switch;
      - compliance profiles;
      - sampling for metrics / traces / events;
      - attribute redaction / hashing / truncation;
      - resource metadata for topology/attestation;
      - explicit hook for a cryptographic hash function (PQ-safe in production).
    """

    # Global enable flag; when False, all public methods become no-op.
    enabled: bool = False

    # Service identity.
    service_name: str = "tcd-safety-sidecar"
    service_version: str = "0.3.0"

    # Deployment / topology metadata.
    # These are merged into each record's attributes.
    resource_attributes: Dict[str, Any] = field(
        default_factory=lambda: {
            "service.namespace": "tcd",
            "service.instance.id": uuid.uuid4().hex[:16],
            "deployment.env": "prod",          # dev|staging|prod|airgapped
            "deployment.region": "unknown",    # caller should set
            "deployment.trust_zone": "default",
            "tcd.version": "0.0.0",
            "crypto.profile": "unspecified",
            "audit.schema.version": "1.0",
        }
    )

    # Compliance / security profile:
    # - DEV: relaxed, debug friendly;
    # - FINREG: regulated finance-style constraints;
    # - LOCKDOWN: strictest, minimal attributes, aggressive truncation/redaction.
    compliance_profile: str = "PROD"
    compliance_profile_version: str = "1.0"

    # Sampling ratios (0.0–1.0).
    sample_metrics: float = 1.0
    sample_traces: float = 1.0
    sample_events: float = 1.0

    # Attribute redaction / truncation.
    # Keys (case-insensitive) that must never be logged verbatim.
    redact_keys: Tuple[str, ...] = (
        "authorization",
        "cookie",
        "set-cookie",
        "password",
        "token",
        "secret",
        "api_key",
        "api-key",
        "access_key",
        "access-key",
        "id_token",
        "prompt",
        "completion",
        "body",
        "payload",
    )

    # Per-attribute policy (case-insensitive key):
    #   "allow"  -> keep (subject to truncation);
    #   "hash"   -> replace with hash(value, label);
    #   "forbid" -> replace with "[forbidden]".
    attribute_policy: Dict[str, str] = field(
        default_factory=lambda: {
            "request_id": "allow",
            "session_id": "hash",
            "tenant": "hash",
            "tenant_id": "hash",
            "user": "hash",
            "user_id": "hash",
            "client_ip": "hash",
            "ip": "hash",
            "operator_id": "hash",
            "policy_id": "hash",
        }
    )

    # Maximum string length for any attribute; longer values are truncated.
    max_attr_len: int = 256
    # Maximum nesting depth for attribute sanitization; beyond this, values are replaced.
    max_attr_depth: int = 5

    # Hash function used for attribute hashing:
    #   hash_fn(value, label) -> hex string.
    # Should normally be provided by the cryptographic layer with proper
    # domain separation and PQ-safe primitives.
    hash_fn: Optional[HashFn] = None
    # Base label prefix for hashing attributes.
    crypto_label_base: str = "otel"

    # In stricter profiles, a hash_fn is mandatory.
    require_hash_fn_for_strict_profiles: bool = True

    # Sink for final JSON records. If None, records are printed as JSON lines.
    sink: Optional[SinkFn] = None

    # Time sources; overridable for tests.
    time_fn: Callable[[], float] = time.time
    monotonic_fn: Callable[[], float] = time.perf_counter

    def __post_init__(self) -> None:
        # Normalize profile name.
        self.compliance_profile = (self.compliance_profile or "PROD").upper()
        if self.compliance_profile not in {"DEV", "PROD", "FINREG", "LOCKDOWN"}:
            self.compliance_profile = "PROD"

        # Clamp sampling in high-security profiles so traces are not entirely disabled.
        if self.compliance_profile in {"FINREG", "LOCKDOWN"}:
            if self.sample_traces < 0.5:
                self.sample_traces = 0.5
            # Metrics / events can be reduced but should not be fully disabled by default.
            if self.sample_metrics <= 0.0:
                self.sample_metrics = 0.1
            if self.sample_events <= 0.0:
                self.sample_events = 0.1

        # In the strictest profile, enforce shorter attribute values by default.
        if self.compliance_profile == "LOCKDOWN":
            if self.max_attr_len > 64:
                self.max_attr_len = 64
            if self.max_attr_depth > 4:
                self.max_attr_depth = 4


@dataclass
class SpanContext:
    """
    Minimal span context for trace correlation.
    """

    trace_id: str
    span_id: str
    parent_span_id: Optional[str] = None
    sampled: bool = True


class _Span:
    """
    Simple span object with context-manager support.

    Instances are created by TCDOtelExporter.start_span() and normally
    finished by TCDOtelExporter.end_span(), or automatically via
    the context-manager protocol.
    """

    __slots__ = ("_exporter", "name", "ctx", "attributes", "start_ns", "end_ns")

    def __init__(
        self,
        exporter: "TCDOtelExporter",
        name: str,
        ctx: SpanContext,
        attributes: Optional[Dict[str, Any]] = None,
        start_ns: Optional[int] = None,
    ) -> None:
        self._exporter = exporter
        self.name = name
        self.ctx = ctx
        self.attributes: Dict[str, Any] = attributes or {}
        self.start_ns = start_ns or time.time_ns()
        self.end_ns: Optional[int] = None

    def __enter__(self) -> "_Span":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        status = "OK" if exc is None else "ERROR"
        status_description = None
        if exc is not None:
            status_description = f"{type(exc).__name__}: {exc}"
        self._exporter.end_span(self, status=status, status_description=status_description)


class TCDOtelExporter:
    """
    Lightweight OpenTelemetry-style exporter for TCD.

    It is designed as a single, profile-aware telemetry gateway:
      - no-op when disabled;
      - JSON-line output for metrics, events, and spans;
      - sampling per signal kind;
      - attribute redaction / hashing / truncation;
      - resource metadata for deployment / crypto / attestation;
      - minimal, explicit surface for regulated and high-security use.

    All content payload (prompt, completion, raw bodies) must be kept out of
    attributes by upstream code. This exporter enforces a conservative last
    barrier via attribute_policy and redact_keys.
    """

    def __init__(
        self,
        enabled: bool = False,
        service_name: str = "tcd-safety-sidecar",
        version: str = "0.3.0",
        *,
        config: Optional[OtelExporterConfig] = None,
    ) -> None:
        # Backwards-compatible initialization:
        # - if config is provided, respect it and override service_name/version/enabled
        #   with the legacy arguments when explicitly given;
        # - otherwise construct a config from legacy parameters.
        if config is not None:
            self._cfg = config
            self._cfg.enabled = bool(enabled) if enabled is not None else config.enabled
            self._cfg.service_name = service_name or config.service_name
            self._cfg.service_version = version or config.service_version
        else:
            self._cfg = OtelExporterConfig(
                enabled=enabled,
                service_name=service_name,
                service_version=version,
            )

        if self._cfg.sink is None:
            # Default sink: print JSON lines.
            self._cfg.sink = lambda rec: print(
                json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
            )

        # In stricter profiles, require a hash function if requested.
        if (
            self._cfg.require_hash_fn_for_strict_profiles
            and self._cfg.compliance_profile in {"FINREG", "LOCKDOWN"}
            and self._cfg.hash_fn is None
        ):
            raise ValueError(
                "OtelExporterConfig.hash_fn must be provided for FINREG/LOCKDOWN profiles "
                "when require_hash_fn_for_strict_profiles is True."
            )

        # Simple lock to serialize writes to the sink.
        self._lock = threading.Lock()
        self._rand = random.Random()

    # ------------------------------------------------------------------
    # Public API: metrics
    # ------------------------------------------------------------------

    def push_metrics(
        self,
        value: float,
        name: str = "diagnose_count",
        attrs: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Legacy metric API (backwards compatible).

        Emits a single metric sample with the given value and attributes.
        Internally calls record_metric().
        """
        self.record_metric(name=name, value=value, labels=attrs)

    def record_metric(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a metric sample.

        Metrics are sampled according to config.sample_metrics, and emitted
        as JSON records with type="metric".

        Recommended names (conventions only, not enforced here):
          - "tcd.decision.count"
          - "tcd.e_wealth"
          - "tcd.apt_signal"
          - "tcd.gpu.health"
          - "tcd.gpu.util"
          - "tcd.gpu.mem_ratio"
        """
        if not self._cfg.enabled:
            return
        if not self._should_sample(self._cfg.sample_metrics):
            return

        now = self._cfg.time_fn()
        mono = self._cfg.monotonic_fn()
        rec: JsonDict = {
            "type": "metric",
            "ts_unix_nano": int(now * 1e9),
            "ts_mono": mono,
            "service": self._cfg.service_name,
            "service_version": self._cfg.service_version,
            "compliance_profile": self._cfg.compliance_profile,
            "metric": name,
            "value": float(value),
            "attributes": labels or {},
        }
        self._emit(rec)

    # ------------------------------------------------------------------
    # Public API: events
    # ------------------------------------------------------------------

    def push_event(
        self,
        name: str,
        attrs: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Record a discrete event.

        Events are sampled according to config.sample_events and emitted
        as JSON records with type="event".

        Example event names:
          - "tcd.decision"
          - "tcd.policy.change"
          - "tcd.deployment.artifact"
          - "tcd.crypto.profile"
          - "tcd.attestation"
          - "tcd.apt.verdict"
        """
        if not self._cfg.enabled:
            return
        if not self._should_sample(self._cfg.sample_events):
            return

        now = self._cfg.time_fn()
        mono = self._cfg.monotonic_fn()
        rec: JsonDict = {
            "type": "event",
            "ts_unix_nano": int(now * 1e9),
            "ts_mono": mono,
            "service": self._cfg.service_name,
            "service_version": self._cfg.service_version,
            "compliance_profile": self._cfg.compliance_profile,
            "event": name,
            "attributes": attrs or {},
        }
        self._emit(rec)

    # Convenience, strongly-typed event helpers ------------------------

    def record_decision_event(
        self,
        *,
        request_id: Optional[str],
        session_id: Optional[str],
        tenant: Optional[str],
        policy_id: Optional[str],
        rule_path: Optional[str],
        action: str,
        wealth_before: Optional[float] = None,
        wealth_after: Optional[float] = None,
        risk_level: Optional[str] = None,
        receipt_id: Optional[str] = None,
        extra_attrs: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Helper to emit a structured "tcd.decision" audit event.
        """

        attrs: Dict[str, Any] = {
            "request_id": request_id,
            "session_id": session_id,
            "tenant": tenant,
            "policy_id": policy_id,
            "rule_path": rule_path,
            "action": action,
            "risk_level": risk_level,
            "wealth_before": wealth_before,
            "wealth_after": wealth_after,
            "receipt_id": receipt_id,
        }
        if extra_attrs:
            attrs.update(extra_attrs)
        self.push_event("tcd.decision", attrs=attrs)

    def record_policy_change_event(
        self,
        *,
        operator_id: Optional[str],
        policy_id: Optional[str],
        old_version: Optional[str],
        new_version: Optional[str],
        four_eyes: Optional[bool] = None,
        extra_attrs: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Helper to emit a structured "tcd.policy.change" event.
        """

        attrs: Dict[str, Any] = {
            "operator_id": operator_id,
            "policy_id": policy_id,
            "old_version": old_version,
            "new_version": new_version,
            "four_eyes": four_eyes,
        }
        if extra_attrs:
            attrs.update(extra_attrs)
        self.push_event("tcd.policy.change", attrs=attrs)

    def record_deployment_artifact_event(
        self,
        *,
        artifact_type: str,
        artifact_hash: str,
        sig_status: str,
        source: Optional[str] = None,
        extra_attrs: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Helper to emit a structured "tcd.deployment.artifact" event.
        """

        attrs: Dict[str, Any] = {
            "artifact_type": artifact_type,
            "artifact_hash": artifact_hash,
            "sig_status": sig_status,
            "source": source,
        }
        if extra_attrs:
            attrs.update(extra_attrs)
        self.push_event("tcd.deployment.artifact", attrs=attrs)

    def record_crypto_profile_event(
        self,
        *,
        profile_id: str,
        kem: Optional[str],
        signature_scheme: Optional[str],
        rollover: Optional[bool] = None,
        extra_attrs: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Helper to emit a structured "tcd.crypto.profile" event.
        """

        attrs: Dict[str, Any] = {
            "profile_id": profile_id,
            "kem": kem,
            "signature_scheme": signature_scheme,
            "rollover": rollover,
        }
        if extra_attrs:
            attrs.update(extra_attrs)
        self.push_event("tcd.crypto.profile", attrs=attrs)

    def record_attestation_event(
        self,
        *,
        attestation_id: str,
        status: str,
        extra_attrs: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Helper to emit a structured "tcd.attestation" event for node/artefact attestation.
        """

        attrs: Dict[str, Any] = {
            "attestation_id": attestation_id,
            "status": status,
        }
        if extra_attrs:
            attrs.update(extra_attrs)
        self.push_event("tcd.attestation", attrs=attrs)

    def record_apt_verdict_event(
        self,
        *,
        request_id: Optional[str],
        tenant: Optional[str],
        score: float,
        signal_type: str,
        decision: str,
        extra_attrs: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Helper to emit a structured "tcd.apt.verdict" event for multivariate detection.
        """

        attrs: Dict[str, Any] = {
            "request_id": request_id,
            "tenant": tenant,
            "score": float(score),
            "signal_type": signal_type,
            "decision": decision,
        }
        if extra_attrs:
            attrs.update(extra_attrs)
        self.push_event("tcd.apt.verdict", attrs=attrs)

    # ------------------------------------------------------------------
    # Public API: tracing
    # ------------------------------------------------------------------

    def start_span(
        self,
        name: str,
        attributes: Optional[Dict[str, Any]] = None,
        parent: Optional[SpanContext] = None,
        sampled: Optional[bool] = None,
    ) -> _Span:
        """
        Start a new span and return a span object.

        The returned span supports the context manager protocol:

            with exporter.start_span("span_name") as span:
                ...

        If tracing is not sampled (based on config.sample_traces), the span
        object is still returned, but it will be marked as not sampled and
        end_span() will not emit a record.

        Recommended span names:
          - "tcd.request"
          - "tcd.auth.verify"
          - "tcd.policy.bind"
          - "tcd.multivar.detect"
          - "tcd.decision"
          - "tcd.receipt.build"
          - "tcd.crypto.sign"
        """
        if sampled is None:
            sampled = self._should_sample(self._cfg.sample_traces)

        if parent is not None:
            trace_id = parent.trace_id
            parent_span_id = parent.span_id
        else:
            trace_id = uuid.uuid4().hex
            parent_span_id = None

        span_id = uuid.uuid4().hex[:16]
        ctx = SpanContext(
            trace_id=trace_id,
            span_id=span_id,
            parent_span_id=parent_span_id,
            sampled=sampled,
        )
        return _Span(self, name=name, ctx=ctx, attributes=attributes)

    def end_span(
        self,
        span: _Span,
        *,
        status: str = "OK",
        status_description: Optional[str] = None,
    ) -> None:
        """
        Finish a span and emit a trace record if sampled.

        The span's end_ns field is set; a JSON record with type="span" is
        emitted when tracing is enabled and the span context is sampled.
        """
        if not self._cfg.enabled:
            return
        if not span.ctx.sampled:
            return

        if span.end_ns is None:
            span.end_ns = time.time_ns()

        rec: JsonDict = {
            "type": "span",
            "service": self._cfg.service_name,
            "service_version": self._cfg.service_version,
            "compliance_profile": self._cfg.compliance_profile,
            "name": span.name,
            "trace_id": span.ctx.trace_id,
            "span_id": span.ctx.span_id,
            "parent_span_id": span.ctx.parent_span_id,
            "start_unix_nano": span.start_ns,
            "end_unix_nano": span.end_ns,
            "status": status,
            "attributes": span.attributes or {},
        }
        if status_description:
            rec["status_description"] = status_description
        self._emit(rec)

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def shutdown(self) -> None:
        """
        Placeholder shutdown hook.

        No buffering is used, so there is nothing to flush. The method
        exists for interface completeness.
        """
        return

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _should_sample(self, rate: float) -> bool:
        if rate <= 0.0:
            return False
        if rate >= 1.0:
            return True
        return self._rand.random() < rate

    def _hash_value(self, value: str, label: str) -> str:
        """
        Hash a single attribute value with domain separation.

        The label is combined with config.crypto_label_base to form the
        domain separation string. When no hash_fn is provided, this
        returns a simple placeholder; in strict profiles, hash_fn is
        required and enforced at init-time.
        """
        domain = f"{self._cfg.crypto_label_base}/{label}"
        if self._cfg.hash_fn is not None:
            return self._cfg.hash_fn(value, domain)
        # Fallback: short, non-cryptographic placeholder; only used when
        # hash_fn is not required by profile.
        return f"{domain}:{hash((domain, value)) & 0xFFFFFFFF:08x}"

    def _emit(self, rec: JsonDict) -> None:
        """
        Apply resource attributes, compliance rules, redaction and then
        forward the record to the configured sink as a JSON object.
        """
        # Attach resource attributes.
        attrs = rec.get("attributes") or {}
        attrs = dict(attrs)
        resource_attrs = self._cfg.resource_attributes or {}
        for k, v in resource_attrs.items():
            attrs.setdefault(k, v)
        rec["attributes"] = attrs

        # Apply compliance profile and attribute redaction/truncation.
        rec = self._sanitize_record(rec)

        # Finally send to sink.
        with self._lock:
            try:
                assert self._cfg.sink is not None
                self._cfg.sink(rec)
            except Exception:
                # Export failures must not raise into the main code path.
                pass

    def _sanitize_record(self, rec: JsonDict) -> JsonDict:
        """
        Redact, hash or truncate attributes according to config.

        This function avoids logging sensitive keys and very deep structures.
        """
        attributes = rec.get("attributes")
        if not isinstance(attributes, dict):
            return rec

        redact_keys_lower = {k.lower() for k in self._cfg.redact_keys}
        policy_map = {k.lower(): v.lower() for k, v in (self._cfg.attribute_policy or {}).items()}
        strict = self._cfg.compliance_profile in {"FINREG", "LOCKDOWN"}

        def _apply_policy(key: str, value: Any) -> Any:
            """
            Apply attribute_policy and redact_keys to a single key/value pair.
            """
            key_lower = key.lower()

            # Hard redaction by key.
            if key_lower in redact_keys_lower:
                return "[redacted]"

            # Attribute policy overrides.
            policy = policy_map.get(key_lower)
            if policy == "forbid":
                return "[forbidden]"
            if policy == "hash":
                return self._hash_value(str(value), label=key_lower)
            # policy == "allow" or None -> handled by recursive sanitizer.
            return value

        def _sanitize(obj: Any, depth: int) -> Any:
            if depth > self._cfg.max_attr_depth:
                return "[truncated-depth]"

            if isinstance(obj, dict):
                cleaned: Dict[str, Any] = {}
                for k, v in obj.items():
                    if not isinstance(k, str):
                        key_str = str(k)
                        cleaned[key_str] = _sanitize(v, depth + 1)
                        continue

                    # First apply key-based policy and redaction.
                    v2 = _apply_policy(k, v)

                    # If policy hashed/forbid/redacted, no further recursion.
                    if isinstance(v2, str) and v2 in {"[forbidden]", "[redacted]"}:
                        cleaned[k] = v2
                        continue
                    # If hashed, treat as leaf string.
                    if isinstance(v2, str) and v2.startswith(f"{self._cfg.crypto_label_base}/"):
                        # This is unlikely for the default fallback, but
                        # hash_fn outputs are treated as final strings.
                        cleaned[k] = v2
                        continue

                    cleaned[k] = _sanitize(v2, depth + 1)
                return cleaned

            if isinstance(obj, (list, tuple)):
                return [_sanitize(v, depth + 1) for v in obj]

            if isinstance(obj, str):
                # Global length truncation.
                if len(obj) > self._cfg.max_attr_len:
                    return obj[: self._cfg.max_attr_len] + "...[truncated]"
                # In strict profiles, be more conservative with long strings.
                if strict and len(obj) > 64:
                    return obj[:64] + "...[truncated]"
                return obj

            # Leave numbers and booleans as-is.
            return obj

        rec["attributes"] = _sanitize(attributes, depth=0)
        return rec


__all__ = ["TCDOtelExporter", "OtelExporterConfig", "SpanContext"]