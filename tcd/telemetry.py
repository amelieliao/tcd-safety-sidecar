# FILE: tcd/telemetry_gpu.py
"""
GPU telemetry sampler.

This module provides a small abstraction layer for GPU telemetry that:
  - is safe to call in production (no hard failure if GPU libraries are missing);
  - exposes a stable, content-agnostic schema for downstream metrics / audit;
  - never touches model inputs, prompts, completions or other sensitive content.

Design goals:
  - Content-agnostic:
      The sampler only reports numeric and small string fields about GPU
      utilization, temperature, memory and related hardware / runtime stats.
  - Security-aligned:
      Every sample carries node identity, build / image fingerprint, trust zone,
      routing profile and PQ posture. It can also flag simple APT-like and
      misuse patterns (e.g. unexpected GPU UUID, excessive ECC errors).
  - Override-aware:
      If hardware telemetry is force-disabled (for example by configuration),
      samples explicitly record this as an insider_override flag for audit.
  - Robust:
      If the underlying telemetry backend fails, the sampler degrades
      gracefully and reports a neutral sample with an appropriate health_state.
  - Pluggable:
      GpuSampler is a façade that selects a backend implementation
      (NVML if available, otherwise a dummy sampler).
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)

# Optional NVML import (for NVIDIA GPUs). This is best-effort and not required.
try:
    import pynvml  # type: ignore[attr-defined]

    _NVML_AVAILABLE = True
except Exception:  # pragma: no cover - import failure path
    pynvml = None  # type: ignore[assignment]
    _NVML_AVAILABLE = False


# ------------------------------
# Policy / posture
# ------------------------------

@dataclass(frozen=True, slots=True)
class GpuSamplerPolicy:
    """
    Static security / supply-chain posture for this sampler.

    This is node-level metadata; it does not depend on prompts, users or
    per-request content. All fields are small strings or numeric thresholds
    and are safe to emit into metrics, logs or audit records.

    Fields:
      - node_id:
          Stable identifier for the host / node / pod running this sampler.
      - build_id:
          Build / release identifier for the running binary or container.
      - image_digest:
          Container image digest (or equivalent runtime artifact hash).
      - driver_version:
          GPU driver version string.
      - runtime_env:
          Environment tag such as "prod", "staging", "dev".

      - trust_zone:
          Security zone of this node, aligned with routing / policy code.
          Recommended values: "internet", "internal", "partner", "admin".
      - route_profile:
          Routing profile for workloads served by this node, for example
          "inference", "admin", "control".
      - policyset_ref:
          Stable reference to the active policy set governing this node.

      - expected_vendor:
          Expected GPU vendor label (for informational purposes).
      - expected_uuids:
          Set of allowed GPU UUID strings. If non-empty, a mismatch will cause
          hw_integrity_state="mismatch" and apt_suspect=True.

      - max_temp_c:
          Temperature threshold above which apt_suspect may be raised.
      - max_ecc_errors:
          ECC error threshold above which apt_suspect may be raised.

      - pq_required:
          Whether this node is expected to satisfy a PQ posture.
      - pq_ok:
          Whether that PQ posture is currently satisfied (as attested
          elsewhere). None means "unknown".
      - pq_chain_id:
          Identifier of the signer chain / attestation root used for PQ
          verification.
    """
    # Node / deployment identity
    node_id: str = ""
    build_id: str = ""
    image_digest: str = ""
    driver_version: str = ""
    runtime_env: str = ""

    # Security / routing posture
    trust_zone: str = "internet"   # "internet","internal","partner","admin"
    route_profile: str = "inference"
    policyset_ref: str = ""

    # Supply-chain expectations
    expected_vendor: str = "nvidia"
    expected_uuids: Optional[Set[str]] = None

    # Health thresholds (simple APT / misuse heuristics)
    max_temp_c: float = 90.0
    max_ecc_errors: int = 0

    # PQ posture for this node (attested elsewhere)
    pq_required: bool = False
    pq_ok: Optional[bool] = None
    pq_chain_id: str = ""


# ------------------------------
# Data model
# ------------------------------

@dataclass(frozen=True, slots=True)
class GpuSample:
    """
    Single GPU telemetry snapshot.

    Core hardware / runtime metrics:
      - index:
          Zero-based GPU index.
      - uuid:
          Device UUID string (empty if unknown).
      - name:
          Device name (empty if unknown).
      - ts:
          Unix timestamp (float, seconds since epoch) when the sample was taken.
      - util_pct:
          GPU core utilization in percent (0.0–100.0).
      - mem_used_mb / mem_total_mb:
          Memory usage and capacity in MiB.
      - temp_c:
          GPU temperature in degrees Celsius.
      - power_w / power_limit_w:
          Instantaneous power draw and enforced power limit in Watts.
      - fan_pct:
          Fan speed in percent (0.0–100.0); may be 0.0 if unsupported.
      - compute_mode:
          Compute mode string (backend-specific).
      - ecc_errors_total:
          Total ECC error count if available, otherwise 0.

      - backend:
          Telemetry backend identifier:
            "nvml"   -> NVML-based sampler;
            "dummy"  -> dummy sampler (no real GPU data);
            other    -> reserved for future backends.
      - health_state:
          High-level status of the telemetry layer:
            "ok"        -> sampler is operating normally;
            "degraded"  -> sampler is returning partial / approximate data;
            "down"      -> sampler failed to talk to the backend, fields are
                           best-effort defaults;
            "unknown"   -> sampler is not configured.
      - extra:
          Free-form numeric / string fields for future extensions, such as:
            {"sm_clock_mhz": 1350}

    Security / supply-chain posture (node-level, content-agnostic):
      - node_id, build_id, image_digest, driver_version, runtime_env:
          Copied from GpuSamplerPolicy for this sampler.
      - trust_zone, route_profile, policyset_ref:
          Routing / security posture for this node.
      - hw_integrity_state:
          "ok"         -> device matches expected policy (UUID set, etc.);
          "mismatch"   -> mismatch vs policy (for example unexpected UUID);
          "unverified" -> backend down or no policy configured.
      - apt_suspect / apt_reason:
          Content-agnostic flags for possible misuse / anomaly, such as:
          unexpected GPU UUID, temperature above threshold, ECC errors above
          threshold, backend exceptions.
      - insider_override / override_reason:
          If telemetry has been force-disabled or replaced by a dummy backend
          via configuration, this will be set for audit.
      - pq_required / pq_ok / pq_chain_id:
          PQ posture for this node, copied from GpuSamplerPolicy.
    """
    # Core device identity and metrics
    index: int
    uuid: str
    name: str
    ts: float

    util_pct: float
    mem_used_mb: float
    mem_total_mb: float
    temp_c: float
    power_w: float
    power_limit_w: float
    fan_pct: float
    compute_mode: str
    ecc_errors_total: int

    backend: str
    health_state: str = "ok"
    extra: Dict[str, Any] = field(default_factory=dict)

    # Node / deployment identity
    node_id: str = ""
    build_id: str = ""
    image_digest: str = ""
    driver_version: str = ""
    runtime_env: str = ""

    # Security / routing posture
    trust_zone: str = "internet"
    route_profile: str = "inference"
    policyset_ref: str = ""

    # Hardware / supply-chain integrity state
    hw_integrity_state: str = "unverified"  # "ok","mismatch","unverified"

    # APT / misuse heuristic flags (content-agnostic)
    apt_suspect: bool = False
    apt_reason: str = ""

    # Internal override / break-glass
    insider_override: bool = False
    override_reason: str = ""

    # PQ posture (attestation status for this node)
    pq_required: bool = False
    pq_ok: Optional[bool] = None
    pq_chain_id: str = ""


# ------------------------------
# Abstract base
# ------------------------------

class BaseGpuSampler(ABC):
    """
    Abstract base class for GPU telemetry samplers.

    Implementations MUST:
      - never raise on sample() in normal operation;
      - return a GpuSample instance with all numeric fields finite;
      - set health_state to reflect backend status;
      - copy node-level posture from the provided GpuSamplerPolicy.

    Implementations MUST NOT:
      - inspect or store any model input / output content;
      - block for long periods of time (sampling should be fast).
    """

    def __init__(self, policy: Optional[GpuSamplerPolicy] = None) -> None:
        self._policy: GpuSamplerPolicy = policy or GpuSamplerPolicy()

    @abstractmethod
    def sample(self) -> GpuSample:
        """Return a single GPU telemetry snapshot."""


# ------------------------------
# Dummy implementation
# ------------------------------

class DummyGpuSampler(BaseGpuSampler):
    """
    Dummy sampler that returns neutral telemetry values.

    This is used when no GPU telemetry backend is available, or when GPU
    monitoring is intentionally disabled. It reports:
      - util_pct = 0.0
      - temp_c = 0.0
      - mem_used_mb = 0.0, mem_total_mb = 0.0
      - backend = "dummy"

    The health_state and insider_override flags indicate whether this is a
    normal fallback (for example in a test environment) or a configuration
    override that disabled real hardware telemetry.
    """

    def __init__(
        self,
        index: int = 0,
        health_state: str = "unknown",
        *,
        policy: Optional[GpuSamplerPolicy] = None,
        insider_override: bool = False,
        override_reason: str = "",
    ) -> None:
        super().__init__(policy=policy)
        self._index = int(index)
        self._health_state = health_state
        self._insider_override = insider_override
        self._override_reason = override_reason

    def sample(self) -> GpuSample:
        now = time.time()
        p = self._policy

        return GpuSample(
            index=self._index,
            uuid="",
            name="",
            ts=now,
            util_pct=0.0,
            mem_used_mb=0.0,
            mem_total_mb=0.0,
            temp_c=0.0,
            power_w=0.0,
            power_limit_w=0.0,
            fan_pct=0.0,
            compute_mode="",
            ecc_errors_total=0,
            backend="dummy",
            health_state=self._health_state,
            extra={},
            node_id=p.node_id,
            build_id=p.build_id,
            image_digest=p.image_digest,
            driver_version=p.driver_version,
            runtime_env=p.runtime_env,
            trust_zone=p.trust_zone,
            route_profile=p.route_profile,
            policyset_ref=p.policyset_ref,
            hw_integrity_state="unverified",
            apt_suspect=False,
            apt_reason="",
            insider_override=self._insider_override,
            override_reason=self._override_reason,
            pq_required=p.pq_required,
            pq_ok=p.pq_ok,
            pq_chain_id=p.pq_chain_id,
        )


# ------------------------------
# NVML-based implementation
# ------------------------------

class NvmlGpuSampler(BaseGpuSampler):
    """
    NVML-based GPU telemetry sampler (for NVIDIA GPUs).

    This sampler:
      - initializes NVML on first use and caches a device handle by index;
      - samples utilization, memory, temperature, power and fan metrics;
      - performs simple, content-agnostic integrity checks against the
        provided GpuSamplerPolicy (UUID set, temperature / ECC thresholds);
      - gracefully handles NVML errors by returning a degraded sample.

    It does not perform any control operations (no power or clock changes).
    """

    def __init__(self, index: int = 0, *, policy: Optional[GpuSamplerPolicy] = None) -> None:
        if not _NVML_AVAILABLE:  # pragma: no cover - guarded by import
            raise RuntimeError("pynvml is not available; cannot use NvmlGpuSampler")

        super().__init__(policy=policy)
        self._index = int(index)
        self._handle = None
        self._initialized = False

    def _ensure_handle(self) -> None:
        if self._initialized:
            return
        try:
            pynvml.nvmlInit()  # type: ignore[union-attr]
        except Exception as exc:  # pragma: no cover - NVML failure
            logger.warning("NVML initialization failed: %r", exc)
            self._initialized = True
            self._handle = None
            return
        try:
            self._handle = pynvml.nvmlDeviceGetHandleByIndex(self._index)  # type: ignore[union-attr]
        except Exception as exc:  # pragma: no cover - invalid index
            logger.warning("NVML could not get device handle for index %d: %r", self._index, exc)
            self._handle = None
        self._initialized = True

    def sample(self) -> GpuSample:
        now = time.time()
        self._ensure_handle()
        p = self._policy

        # Backend not available or failed; degrade gracefully.
        if self._handle is None:
            return GpuSample(
                index=self._index,
                uuid="",
                name="",
                ts=now,
                util_pct=0.0,
                mem_used_mb=0.0,
                mem_total_mb=0.0,
                temp_c=0.0,
                power_w=0.0,
                power_limit_w=0.0,
                fan_pct=0.0,
                compute_mode="",
                ecc_errors_total=0,
                backend="nvml",
                health_state="down",
                extra={},
                node_id=p.node_id,
                build_id=p.build_id,
                image_digest=p.image_digest,
                driver_version=p.driver_version,
                runtime_env=p.runtime_env,
                trust_zone=p.trust_zone,
                route_profile=p.route_profile,
                policyset_ref=p.policyset_ref,
                hw_integrity_state="unverified",
                apt_suspect=False,
                apt_reason="nvml_handle_unavailable",
                insider_override=False,
                override_reason="",
                pq_required=p.pq_required,
                pq_ok=p.pq_ok,
                pq_chain_id=p.pq_chain_id,
            )

        util_pct = 0.0
        mem_used_mb = 0.0
        mem_total_mb = 0.0
        temp_c = 0.0
        power_w = 0.0
        power_limit_w = 0.0
        fan_pct = 0.0
        ecc_errors_total = 0
        uuid = ""
        name = ""
        compute_mode = ""
        extra: Dict[str, Any] = {}
        health_state = "ok"

        # Integrity / APT-related flags
        hw_integrity_state = "ok"
        apt_suspect = False
        apt_reason = ""

        try:
            # Basic identity
            try:
                uuid_val = pynvml.nvmlDeviceGetUUID(self._handle)  # type: ignore[union-attr]
                uuid = uuid_val if isinstance(uuid_val, str) else str(uuid_val)
            except Exception:
                uuid = ""
            try:
                name_bytes = pynvml.nvmlDeviceGetName(self._handle)  # type: ignore[union-attr]
                name = (
                    name_bytes.decode("utf-8", errors="ignore")
                    if isinstance(name_bytes, bytes)
                    else str(name_bytes)
                )
            except Exception:
                name = ""

            # Utilization
            try:
                util = pynvml.nvmlDeviceGetUtilizationRates(self._handle)  # type: ignore[union-attr]
                util_pct = float(getattr(util, "gpu", 0.0))
            except Exception:
                util_pct = 0.0
                health_state = "degraded"

            # Memory
            try:
                mem = pynvml.nvmlDeviceGetMemoryInfo(self._handle)  # type: ignore[union-attr]
                mem_used_mb = float(getattr(mem, "used", 0) / (1024 * 1024))
                mem_total_mb = float(getattr(mem, "total", 0) / (1024 * 1024))
            except Exception:
                mem_used_mb = 0.0
                mem_total_mb = 0.0
                health_state = "degraded"

            # Temperature
            try:
                temp_c = float(
                    pynvml.nvmlDeviceGetTemperature(  # type: ignore[union-attr]
                        self._handle,
                        pynvml.NVML_TEMPERATURE_GPU,  # type: ignore[union-attr]
                    )
                )
            except Exception:
                temp_c = 0.0
                health_state = "degraded"

            # Power and limits
            try:
                power_limit_mw = float(
                    pynvml.nvmlDeviceGetEnforcedPowerLimit(self._handle)  # type: ignore[union-attr]
                )
                power_limit_w = power_limit_mw / 1000.0
            except Exception:
                power_limit_w = 0.0
                health_state = "degraded"
            try:
                power_usage_mw = float(
                    pynvml.nvmlDeviceGetPowerUsage(self._handle)  # type: ignore[union-attr]
                )
                power_w = power_usage_mw / 1000.0
            except Exception:
                power_w = 0.0
                health_state = "degraded"

            # Fan speed (may not be supported on all devices)
            try:
                fan_pct = float(
                    pynvml.nvmlDeviceGetFanSpeed(self._handle)  # type: ignore[union-attr]
                )
            except Exception:
                fan_pct = 0.0

            # Compute mode
            try:
                mode = pynvml.nvmlDeviceGetComputeMode(self._handle)  # type: ignore[union-attr]
                compute_mode = str(mode)
            except Exception:
                compute_mode = ""

            # ECC errors (if supported)
            try:
                err = pynvml.nvmlDeviceGetTotalEccErrors(  # type: ignore[union-attr]
                    self._handle,
                    pynvml.NVML_MEMORY_ERROR_TYPE_UNCORRECTED,  # type: ignore[union-attr]
                    pynvml.NVML_VOLATILE_ECC,  # type: ignore[union-attr]
                )
                ecc_errors_total = int(err)
            except Exception:
                ecc_errors_total = 0

            # Additional optional metrics (clocks, etc.)
            try:
                sm_clock = pynvml.nvmlDeviceGetClockInfo(  # type: ignore[union-attr]
                    self._handle,
                    pynvml.NVML_CLOCK_SM,  # type: ignore[union-attr]
                )
                extra["sm_clock_mhz"] = float(sm_clock)
            except Exception:
                pass
            try:
                mem_clock = pynvml.nvmlDeviceGetClockInfo(  # type: ignore[union-attr]
                    self._handle,
                    pynvml.NVML_CLOCK_MEM,  # type: ignore[union-attr]
                )
                extra["mem_clock_mhz"] = float(mem_clock)
            except Exception:
                pass

            # --- Supply-chain / integrity checks (policy-aligned, content-agnostic) ---

            # UUID expectation
            if p.expected_uuids:
                if not uuid or uuid not in p.expected_uuids:
                    hw_integrity_state = "mismatch"
                    apt_suspect = True
                    apt_reason = "gpu_uuid_not_in_expected_set"

            # Temperature threshold
            if temp_c > p.max_temp_c:
                apt_suspect = True
                if apt_reason:
                    apt_reason += ";"
                apt_reason += "temp_above_threshold"

            # ECC error threshold
            if ecc_errors_total > p.max_ecc_errors:
                apt_suspect = True
                if apt_reason:
                    apt_reason += ";"
                apt_reason += "ecc_errors_above_threshold"

        except Exception as exc:  # pragma: no cover - unforeseen NVML failure
            logger.warning("NVML sampling failed for GPU index %d: %r", self._index, exc)
            # On a hard failure, treat backend as down and return neutral values.
            return GpuSample(
                index=self._index,
                uuid=uuid,
                name=name,
                ts=now,
                util_pct=0.0,
                mem_used_mb=0.0,
                mem_total_mb=0.0,
                temp_c=0.0,
                power_w=0.0,
                power_limit_w=0.0,
                fan_pct=0.0,
                compute_mode=compute_mode,
                ecc_errors_total=0,
                backend="nvml",
                health_state="down",
                extra=extra,
                node_id=p.node_id,
                build_id=p.build_id,
                image_digest=p.image_digest,
                driver_version=p.driver_version,
                runtime_env=p.runtime_env,
                trust_zone=p.trust_zone,
                route_profile=p.route_profile,
                policyset_ref=p.policyset_ref,
                hw_integrity_state="unverified",
                apt_suspect=True,
                apt_reason="nvml_sampling_exception",
                insider_override=False,
                override_reason="",
                pq_required=p.pq_required,
                pq_ok=p.pq_ok,
                pq_chain_id=p.pq_chain_id,
            )

        return GpuSample(
            index=self._index,
            uuid=uuid,
            name=name,
            ts=now,
            util_pct=util_pct,
            mem_used_mb=mem_used_mb,
            mem_total_mb=mem_total_mb,
            temp_c=temp_c,
            power_w=power_w,
            power_limit_w=power_limit_w,
            fan_pct=fan_pct,
            compute_mode=compute_mode,
            ecc_errors_total=ecc_errors_total,
            backend="nvml",
            health_state=health_state,
            extra=extra,
            node_id=p.node_id,
            build_id=p.build_id,
            image_digest=p.image_digest,
            driver_version=p.driver_version,
            runtime_env=p.runtime_env,
            trust_zone=p.trust_zone,
            route_profile=p.route_profile,
            policyset_ref=p.policyset_ref,
            hw_integrity_state=hw_integrity_state,
            apt_suspect=apt_suspect,
            apt_reason=apt_reason,
            insider_override=False,
            override_reason="",
            pq_required=p.pq_required,
            pq_ok=p.pq_ok,
            pq_chain_id=p.pq_chain_id,
        )


# ------------------------------
# Public façade
# ------------------------------

class GpuSampler:
    """
    Small façade around GPU telemetry backends.

    Default behaviour:
      - If NVML is available, use NvmlGpuSampler(index, policy).
      - Otherwise, fall back to DummyGpuSampler(index, policy).

    If force_dummy=True is provided, DummyGpuSampler will be used even when
    NVML is available. This is recorded as insider_override=True in samples
    for audit purposes.

    sample() returns a flat dictionary suitable for logging / metrics sinks.

    The dictionary includes, at minimum:
      {
        "index": int,
        "uuid": str,
        "name": str,
        "ts": float,
        "util_pct": float,
        "mem_used_mb": float,
        "mem_total_mb": float,
        "temp_c": float,
        "power_w": float,
        "power_limit_w": float,
        "fan_pct": float,
        "compute_mode": str,
        "ecc_errors_total": int,
        "backend": str,
        "health_state": str,
        "node_id": str,
        "build_id": str,
        "image_digest": str,
        "driver_version": str,
        "runtime_env": str,
        "trust_zone": str,
        "route_profile": str,
        "policyset_ref": str,
        "hw_integrity_state": str,
        "apt_suspect": bool,
        "apt_reason": str,
        "insider_override": bool,
        "override_reason": str,
        "pq_required": bool,
        "pq_ok": Optional[bool],
        "pq_chain_id": str,
        ...
      }

    All extra fields from GpuSample.extra are flattened into the result
    dictionary as-is.

    Content note:
      No prompts, completions or other input / output content is ever inspected
      or stored by this sampler.
    """

    def __init__(
        self,
        index: int = 0,
        *,
        force_dummy: bool = False,
        policy: Optional[GpuSamplerPolicy] = None,
        override_reason: str = "",
    ) -> None:
        """
        Args:
          index:
            GPU index.
          force_dummy:
            If True, force the use of DummyGpuSampler even when NVML is
            available. This is treated as an "insider override" for audit.
          policy:
            Optional GpuSamplerPolicy describing node / build / PQ posture.
          override_reason:
            Optional free-form reason for forcing dummy mode. This is written
            into samples as override_reason when insider_override is set.
        """
        self._index = int(index)
        self._policy: GpuSamplerPolicy = policy or GpuSamplerPolicy()
        self._override_reason = override_reason

        if not force_dummy and _NVML_AVAILABLE:
            try:
                self._impl: BaseGpuSampler = NvmlGpuSampler(
                    index=self._index,
                    policy=self._policy,
                )
            except Exception as exc:  # pragma: no cover - guarded path
                logger.warning(
                    "Falling back to DummyGpuSampler for GPU index %d due to NVML error: %r",
                    self._index,
                    exc,
                )
                # NVML failed: backend down, but not an explicit override.
                self._impl = DummyGpuSampler(
                    index=self._index,
                    health_state="down",
                    policy=self._policy,
                    insider_override=False,
                    override_reason="nvml_error",
                )
        else:
            # Either forced dummy or NVML is not available at all.
            insider = bool(force_dummy)
            reason = override_reason or ("force_dummy" if insider else "")
            self._impl = DummyGpuSampler(
                index=self._index,
                health_state="unknown" if force_dummy else "down",
                policy=self._policy,
                insider_override=insider,
                override_reason=reason,
            )

    def sample_struct(self) -> GpuSample:
        """
        Return a structured GpuSample.

        This method is useful for internal callers that prefer a typed
        dataclass representation.
        """
        return self._impl.sample()

    def sample(self) -> Dict[str, Any]:
        """
        Return a flat dictionary representation of a GpuSample.

        This is convenient for logging, metrics emission, or JSON encoding.
        """
        sample_obj = self._impl.sample()
        data = asdict(sample_obj)
        # Flatten 'extra' into the top-level dictionary while keeping the
        # original nested copy.
        extra = data.get("extra") or {}
        if isinstance(extra, dict):
            for k, v in extra.items():
                if k not in data:
                    data[k] = v
        return data