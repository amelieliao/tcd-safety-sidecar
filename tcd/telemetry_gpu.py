# FILE: tcd/telemetry_gpu.py
# GPU telemetry sampler for TCD.
#
# Design goals:
# - Small, auditable module with a clear data model.
# - Prefer a stable, battle-tested backend (NVIDIA NVML via `pynvml`) when available.
# - Degrade gracefully when GPUs / NVML are not present or telemetry is disabled.
# - Be safe under concurrent use (multiple threads calling sample()).
# - Provide optional caching and fleet-wide sampling for production deployments.
# - Integrate cleanly with the crypto control plane for integrity / signing when desired.
#
# This module intentionally does *not* push metrics anywhere. It only:
#   - discovers basic GPU health / utilization signals, and
#   - returns them as small, JSON-friendly dicts or signed TelemetryReports.
#
# Higher layers (Prometheus exporters, logging, decision engines) decide how
# to store, aggregate, or react to these metrics.
#
# NOTE:
#   - For non-NVIDIA environments, this will report a "backend=none"
#     sample with zeros and an explanatory reason.
#   - For regulated deployments where telemetry itself may be sensitive,
#     behavior is governed by TelemetryPolicy (profile / classification / field
#     minimization) and environment flags.

from __future__ import annotations

import binascii
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, asdict
from typing import Any, Dict, FrozenSet, List, Literal, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional NVML backend (NVIDIA GPUs)
# ---------------------------------------------------------------------------

try:
    import pynvml as _pynvml  # type: ignore[import]
except Exception:  # pragma: no cover - import-time fallback
    _pynvml = None
    logger.info(
        "pynvml not available; GPU telemetry will fall back to a no-op backend. "
        "Install 'nvidia-ml-py3' or 'pynvml' to enable NVIDIA GPU telemetry."
    )

_NVML_INIT_LOCK = threading.Lock()
_NVML_INITIALIZED = False
_NVML_INIT_ERROR: Optional[str] = None


def _ensure_nvml_initialized() -> bool:
    """
    Initialize NVML once in a thread-safe way.

    Returns True if NVML is ready to use, False otherwise.
    """
    global _NVML_INITIALIZED, _NVML_INIT_ERROR

    if _pynvml is None:
        _NVML_INIT_ERROR = "pynvml_not_installed"
        return False

    if _NVML_INITIALIZED:
        return True

    with _NVML_INIT_LOCK:
        if _NVML_INITIALIZED:
            return True
        try:
            _pynvml.nvmlInit()
        except Exception as e:  # pragma: no cover - environment dependent
            _NVML_INIT_ERROR = "nvml_init_failed"
            logger.warning("Failed to initialize NVML for GPU telemetry: %s", e)
            return False
        _NVML_INITIALIZED = True
        _NVML_INIT_ERROR = None
        logger.info("NVML initialized successfully for GPU telemetry.")
        return True


# ---------------------------------------------------------------------------
# Telemetry profile / policy
# ---------------------------------------------------------------------------

TelemetryProfile = Literal["DEV", "PROD", "NATIONAL_DEFENSE"]


@dataclass(frozen=True)
class TelemetryPolicy:
    """
    Policy describing how GPU telemetry should behave in a given environment.

    Fields:
      - profile: telemetry profile (DEV / PROD / NATIONAL_DEFENSE).
      - classification: coarse classification label for produced samples.
      - minimize_fields: whether to aggressively drop sensitive fields.
      - require_signing: whether integrity/signed reports are required.
      - max_sampling_hz: recommended max sampling rate (advisory).
      - allow_gpu_name: whether raw GPU names are allowed to be emitted.
      - export_precision: "full" | "coarse" | "flags_only".
      - allowed_sample_fields: set of allowed keys in the final sample dict.
    """

    profile: TelemetryProfile
    classification: str
    minimize_fields: bool
    require_signing: bool
    max_sampling_hz: float
    allow_gpu_name: bool
    export_precision: Literal["full", "coarse", "flags_only"]
    allowed_sample_fields: FrozenSet[str]

    @classmethod
    def _allowed_fields_for_profile(cls, profile: TelemetryProfile) -> FrozenSet[str]:
        # Base field universe, including derived health fields.
        base_fields = {
            "index",
            "backend",
            "ok",
            "reason",
            "gpu_name",
            "gpu_util",
            "gpu_mem_used_mib",
            "gpu_mem_total_mib",
            "gpu_temp_c",
            "gpu_power_w",
            "classification",
            "profile",
            "ts_unix_ms",
            "ts_monotonic_ms",
            "sample_seq",
            "sample_uuid",
            "driver_version",
            "nvml_version",
            "host_handle",
            "health_level",
            "health_flags",
            "gpu_util_bucket",
            "gpu_temp_bucket",
            "gpu_mem_usage_bucket",
        }

        if profile == "DEV":
            return frozenset(base_fields)

        if profile == "PROD":
            # Drop direct identifiers and fine-grained numeric fields.
            return frozenset(
                {
                    "index",
                    "backend",
                    "ok",
                    "reason",
                    "classification",
                    "profile",
                    "ts_unix_ms",
                    "ts_monotonic_ms",
                    "sample_seq",
                    "driver_version",
                    "nvml_version",
                    "health_level",
                    "health_flags",
                    "gpu_util_bucket",
                    "gpu_temp_bucket",
                    "gpu_mem_usage_bucket",
                }
            )

        # NATIONAL_DEFENSE: strongly minimized view.
        return frozenset(
            {
                "index",
                "backend",
                "ok",
                "reason",
                "classification",
                "profile",
                "ts_unix_ms",
                "sample_seq",
                "health_level",
                "health_flags",
            }
        )

    @classmethod
    def from_env(cls) -> "TelemetryPolicy":
        # Determine profile. Prefer explicit telemetry profile; fall back to crypto profile.
        tele_profile_env = os.getenv("TCD_TELEMETRY_PROFILE", "").strip().upper()
        crypto_profile_env = os.getenv("TCD_CRYPTO_PROFILE", "").strip().upper()

        if tele_profile_env in ("DEV", "PROD", "NATIONAL_DEFENSE"):
            profile: TelemetryProfile = tele_profile_env  # type: ignore[assignment]
        else:
            # Map crypto profiles into telemetry profiles as a fallback.
            if crypto_profile_env.startswith("NATDEF"):
                profile = "NATIONAL_DEFENSE"
            elif crypto_profile_env in ("FIPS", "PROD"):
                profile = "PROD"
            else:
                profile = "DEV"

        if profile == "DEV":
            classification = "unclassified"
            minimize_fields = False
            require_signing = False
            max_sampling_hz = 10.0
            allow_gpu_name = True
            export_precision = "full"
        elif profile == "PROD":
            classification = "internal"
            minimize_fields = True
            require_signing = False
            max_sampling_hz = 2.0
            allow_gpu_name = False
            export_precision = "coarse"
        else:  # NATIONAL_DEFENSE
            classification = "sensitive"
            minimize_fields = True
            require_signing = True
            max_sampling_hz = 1.0
            allow_gpu_name = False
            export_precision = "flags_only"

        allowed_fields = cls._allowed_fields_for_profile(profile)

        return cls(
            profile=profile,
            classification=classification,
            minimize_fields=minimize_fields,
            require_signing=require_signing,
            max_sampling_hz=max_sampling_hz,
            allow_gpu_name=allow_gpu_name,
            export_precision=export_precision,  # type: ignore[arg-type]
            allowed_sample_fields=allowed_fields,
        )


# ---------------------------------------------------------------------------
# Optional crypto integration (for signed telemetry reports)
# ---------------------------------------------------------------------------

try:  # pragma: no cover - optional dependency
    from .crypto import (  # type: ignore[import]
        AttestationContext as _AttestationContext,
        get_default_context as _get_crypto_context,
    )
except Exception:  # pragma: no cover
    _AttestationContext = None  # type: ignore[assignment]
    _get_crypto_context = None  # type: ignore[assignment]


@dataclass(frozen=True)
class TelemetryReport:
    """
    Signed or unsigned wrapper around a telemetry sample.

    Fields:
      - sample: policy-minimized GPU sample.
      - meta: profile / classification / version info.
      - integrity: digest / signature info; may be unsigned.
      - chain: optional hash-chain linkage for audit flows.
    """

    sample: Dict[str, Any]
    meta: Dict[str, Any]
    integrity: Dict[str, Any]
    chain: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sample": self.sample,
            "meta": self.meta,
            "integrity": self.integrity,
            "chain": self.chain,
        }


def build_telemetry_report(
    sample: Dict[str, Any],
    *,
    policy: TelemetryPolicy,
    prev_hash: Optional[str] = None,
    chain_label: str = "telemetry",
    attestation: Optional["_AttestationContext"] = None,
) -> TelemetryReport:
    """
    Build a TelemetryReport around a single sample, optionally signed and chained.

    If the crypto control plane is available, this will:
      - compute a digest under the current crypto suite, and
      - sign the blob using a key with operation="sign_telemetry".

    If signing is required by policy but unavailable, the report will mark
    integrity.status as "required_but_missing".
    """
    meta: Dict[str, Any] = {
        "profile": policy.profile,
        "classification": policy.classification,
        "telemetry_version": "TCD-GPU-TELEM-v1",
    }

    # Canonical JSON encoding for hashing/signing.
    blob = json.dumps(
        sample,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")

    ctx = None
    signed = False
    signing_reason: Optional[str] = None
    digest_hex: Optional[str] = None
    signature_hex: Optional[str] = None
    key_id: Optional[str] = None
    sign_algo: Optional[str] = None
    suite_id: Optional[str] = None
    crypto_profile: Optional[str] = None

    if callable(_get_crypto_context):
        try:
            ctx = _get_crypto_context()
            sig, digest_hex, key_id, sign_algo = ctx.sign_blob(
                blob,
                label="telemetry",  # must match crypto.HashLabel
                operation="sign_telemetry",
                attestation=attestation,
            )
            signature_hex = binascii.hexlify(sig).decode("ascii")
            suite_id = ctx.suite.suite_id
            crypto_profile = ctx.profile
            signed = True
        except Exception as e:  # pragma: no cover
            signing_reason = f"signing_failed:{type(e).__name__}"
            logger.warning("Telemetry signing failed: %s", e)
    else:
        signing_reason = "crypto_unavailable"

    if signed:
        status = "ok"
    elif policy.require_signing:
        status = "required_but_missing"
    else:
        status = "unsigned"

    # Optional hash chain using crypto hash engine if available.
    prev = prev_hash
    curr: Optional[str] = None
    if ctx is not None:
        try:
            curr = ctx.hash_engine.chain(prev_hash, blob, label="ledger")
        except Exception:  # pragma: no cover
            curr = None
    else:
        curr = None

    integrity = {
        "status": status,
        "signed": signed,
        "digest_hex": digest_hex,
        "signature_hex": signature_hex,
        "key_id": key_id,
        "sign_algo": sign_algo,
        "suite_id": suite_id,
        "crypto_profile": crypto_profile or policy.profile,
        "reason": signing_reason,
    }

    chain = {
        "prev_hash": prev,
        "curr_hash": curr,
        "label": chain_label,
    }

    return TelemetryReport(sample=sample, meta=meta, integrity=integrity, chain=chain)


# ---------------------------------------------------------------------------
# Health thresholds (env-tunable)
# ---------------------------------------------------------------------------

def _env_float(name: str, default: float) -> float:
    val = os.getenv(name)
    if not val:
        return default
    try:
        return float(val)
    except Exception:
        logger.warning("Invalid %s=%r, falling back to %s", name, val, default)
        return default


# GPU temperature above which we start flagging "hot".
_GPU_HOT_TEMP_C = _env_float("TCD_GPU_HOT_TEMP_C", 80.0)
# Utilization (0–1) above which we consider the device "busy".
_GPU_HIGH_UTIL = _env_float("TCD_GPU_HIGH_UTIL_FRACTION", 0.9)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GpuSample:
    """
    Single GPU telemetry snapshot.

    Fields are kept intentionally small and unit-annotated:

    - index:            GPU index as seen by NVML (0-based).
    - backend:          "pynvml" if NVIDIA telemetry is active, "none" otherwise.
    - ok:               True if telemetry was successfully collected.
    - reason:           Short string when ok=False (e.g., "telemetry_disabled").
    - gpu_name:         Human-readable name of the device (if available).
    - gpu_util:         Floating point fraction in [0.0, 1.0]; 0.75 means 75% GPU utilization.
    - gpu_mem_used_mib: Used device memory in MiB.
    - gpu_mem_total_mib:Total device memory in MiB.
    - gpu_temp_c:       Temperature in Celsius, or None if unavailable.
    - gpu_power_w:      Power draw in Watts, or None if unavailable.

    Additional metadata:

    - classification:   Classification label for this sample.
    - profile:          Telemetry profile under which this sample was produced.
    - ts_unix_ms:       Wall-clock timestamp in Unix milliseconds.
    - ts_monotonic_ms:  Monotonic clock timestamp in milliseconds.
    - sample_seq:       Monotonic sample sequence number for this sampler.
    - sample_uuid:      Optional UUID assigned by higher layers.
    - driver_version:   GPU driver version if available.
    - nvml_version:     NVML library version if available.
    - host_handle:      Opaque host handle (pre-hashed or tokenized).

    Derived health fields (not stored, but computed on demand):

    - health_level: one of "unknown", "normal", "busy", "hot", "degraded".
    - health_flags: small set of strings like {"hot", "high_util"}.
    """

    index: int
    backend: str
    ok: bool
    reason: Optional[str] = None

    gpu_name: Optional[str] = None
    gpu_util: float = 0.0
    gpu_mem_used_mib: float = 0.0
    gpu_mem_total_mib: float = 0.0
    gpu_temp_c: Optional[float] = None
    gpu_power_w: Optional[float] = None

    classification: Optional[str] = None
    profile: Optional[str] = None
    ts_unix_ms: Optional[int] = None
    ts_monotonic_ms: Optional[int] = None
    sample_seq: Optional[int] = None
    sample_uuid: Optional[str] = None
    driver_version: Optional[str] = None
    nvml_version: Optional[str] = None
    host_handle: Optional[str] = None

    def to_dict(self, policy: Optional[TelemetryPolicy] = None) -> Dict[str, Any]:
        """
        JSON-friendly representation for logging / metrics.

        The TelemetryPolicy, when supplied, controls field minimization and
        precision for regulated profiles.
        """
        d = asdict(self)
        d["health_level"] = self.health_level
        d["health_flags"] = sorted(self.health_flags)

        if policy is None:
            # Backwards-compatible behavior: DEV-like output.
            return d

        # Ensure profile/classification are set consistently.
        d.setdefault("profile", policy.profile)
        d.setdefault("classification", policy.classification)

        # Apply precision rules.
        if policy.minimize_fields:
            if not policy.allow_gpu_name:
                d.pop("gpu_name", None)

            # Coarse buckets.
            if policy.export_precision in ("coarse", "flags_only"):
                util = float(d.get("gpu_util", 0.0))
                mem_used = float(d.get("gpu_mem_used_mib", 0.0))
                mem_total = float(d.get("gpu_mem_total_mib", 0.0))
                temp_c = d.get("gpu_temp_c")

                # Utilization bucket.
                if util < 0.1:
                    util_bucket = "idle"
                elif util < 0.4:
                    util_bucket = "light"
                elif util < 0.7:
                    util_bucket = "medium"
                else:
                    util_bucket = "high"

                d["gpu_util_bucket"] = util_bucket

                # Memory usage bucket.
                if mem_total > 0:
                    frac = mem_used / mem_total
                    if frac < 0.3:
                        mem_bucket = "low"
                    elif frac < 0.7:
                        mem_bucket = "medium"
                    elif frac < 0.9:
                        mem_bucket = "high"
                    else:
                        mem_bucket = "near_full"
                else:
                    mem_bucket = "unknown"
                d["gpu_mem_usage_bucket"] = mem_bucket

                # Temperature bucket.
                if temp_c is None:
                    temp_bucket = "unknown"
                elif temp_c < 60.0:
                    temp_bucket = "cool"
                elif temp_c < _GPU_HOT_TEMP_C:
                    temp_bucket = "warm"
                else:
                    temp_bucket = "hot"
                d["gpu_temp_bucket"] = temp_bucket

            # Remove fine-grained numeric values for flags_only.
            if policy.export_precision == "flags_only":
                for key in ("gpu_util", "gpu_mem_used_mib", "gpu_mem_total_mib", "gpu_temp_c", "gpu_power_w"):
                    d.pop(key, None)

        # Enforce field-level whitelist.
        if policy.allowed_sample_fields:
            d = {k: v for k, v in d.items() if k in policy.allowed_sample_fields}

        return d

    @property
    def health_flags(self) -> set:
        """
        Return a small set of string flags describing potential issues.

        Example:
            {"hot", "high_util"} when temperature > threshold and util high.
        """
        flags: set = set()
        if not self.ok:
            flags.add("unavailable")
            if self.reason:
                flags.add(f"reason:{self.reason}")
            return flags

        if self.gpu_temp_c is not None and self.gpu_temp_c >= _GPU_HOT_TEMP_C:
            flags.add("hot")

        if self.gpu_util >= _GPU_HIGH_UTIL:
            flags.add("high_util")

        # Simple heuristic: if memory is very close to full, mark as constrained.
        if self.gpu_mem_total_mib > 0 and self.gpu_mem_used_mib / self.gpu_mem_total_mib >= 0.95:
            flags.add("mem_full")

        return flags

    @property
    def health_level(self) -> str:
        """
        Coarse-grained health classification.

        - "unknown": telemetry not available.
        - "degraded": severe or multiple flags.
        - "hot": temperature critical.
        - "busy": mostly high utilization / mem pressure.
        - "normal": none of the above.
        """
        if not self.ok:
            return "unknown"

        flags = self.health_flags

        if "hot" in flags and "high_util" in flags:
            return "degraded"
        if "hot" in flags:
            return "hot"
        if "high_util" in flags or "mem_full" in flags:
            return "busy"
        return "normal"


# ---------------------------------------------------------------------------
# GPU sampler
# ---------------------------------------------------------------------------


class GpuSampler:
    """
    Lightweight GPU telemetry sampler with profile-aware policy.

    Typical use:

        sampler = GpuSampler(index=0)
        sample_dict = sampler.sample()        # fresh, policy-minimized sample
        sample_dict2 = sampler.sample_cached(max_age_ms=200)  # cached if recent

        report = sampler.sample_report(prev_hash=prev_hash)   # signed TelemetryReport dict

    Features:
    - Thread-safe NVML init and sampling.
    - TelemetryPolicy controls behavior for DEV / PROD / NATIONAL_DEFENSE.
    - Environment flags to enable/disable telemetry:
        TCD_GPU_TELEMETRY_DISABLE = "1" / "true" / "yes"
        TCD_GPU_TELEMETRY_ENABLE  = "1" / "true" / "yes"  (required for PROD/NATIONAL_DEFENSE)
    - Optional caching to avoid hammering NVML:
        TCD_GPU_TELEMETRY_CACHE_MAX_AGE_MS (default 250 ms in DEV).
    - Always returns a dict; never raises on missing GPU / NVML.
    """

    # Internal NVML sampling is guarded by a lock to avoid surprising behavior
    # if NVML bindings are not fully thread-safe on a given platform.
    _SAMPLE_LOCK = threading.Lock()

    def __init__(self, index: int = 0, policy: Optional[TelemetryPolicy] = None) -> None:
        self.index = int(index)
        self._policy = policy or TelemetryPolicy.from_env()

        # Enable/disable logic with profile awareness.
        disable_flag = os.getenv("TCD_GPU_TELEMETRY_DISABLE", "").strip().lower() in {"1", "true", "yes"}
        enable_flag = os.getenv("TCD_GPU_TELEMETRY_ENABLE", "").strip().lower() in {"1", "true", "yes"}

        if self._policy.profile in ("PROD", "NATIONAL_DEFENSE"):
            # In high-security profiles, telemetry must be explicitly enabled.
            enabled = enable_flag and not disable_flag
        else:
            # In DEV, telemetry is enabled by default unless explicitly disabled.
            enabled = not disable_flag

        self._disabled = not enabled

        # Decide backend once; if NVML is not available or init fails, we keep
        # the backend as "none" and sample() will return a no-op snapshot.
        if self._disabled:
            self._backend = "none"
        else:
            self._backend = "pynvml" if _ensure_nvml_initialized() else "none"

        if self._backend == "none":
            logger.debug(
                "GpuSampler initialized with backend=none (disabled=%s, nvml_error=%s)",
                self._disabled,
                _NVML_INIT_ERROR,
            )

        # Cache for sample_cached()
        self._cache_lock = threading.Lock()
        self._last_sample: Optional[GpuSample] = None
        self._last_sample_ts: float = 0.0

        # Default max cache age, in milliseconds (can be overridden per-call).
        default_cache_ms_env = os.getenv("TCD_GPU_TELEMETRY_CACHE_MAX_AGE_MS", "").strip()
        if default_cache_ms_env:
            try:
                self._default_cache_max_age_ms = int(default_cache_ms_env)
            except Exception:
                logger.warning(
                    "Invalid TCD_GPU_TELEMETRY_CACHE_MAX_AGE_MS=%r, falling back to profile-based default.",
                    default_cache_ms_env,
                )
                self._default_cache_max_age_ms = 250
        else:
            # Simple mapping: slower sampling for stricter profiles.
            if self._policy.profile == "DEV":
                self._default_cache_max_age_ms = 250
            elif self._policy.profile == "PROD":
                self._default_cache_max_age_ms = 500
            else:  # NATIONAL_DEFENSE
                self._default_cache_max_age_ms = 1000

        # Local sample sequence counter.
        self._seq_lock = threading.Lock()
        self._seq_counter: int = 0

        # Host handle (opaque identifier) if provided by control plane.
        self._host_handle = os.getenv("TCD_HOST_HANDLE") or None

    # ----------------- internal helpers ----------------- #

    def _next_seq(self) -> int:
        with self._seq_lock:
            self._seq_counter += 1
            return self._seq_counter

    def _sample_nvml(self) -> GpuSample:
        """
        Collect telemetry using NVML for a single device index.

        This assumes NVML has been initialized successfully.
        """
        assert _pynvml is not None  # for type checkers

        # Timestamps and sample sequence.
        ts_unix_ms = int(time.time() * 1000.0)
        ts_monotonic_ms = int(time.monotonic() * 1000.0)
        sample_seq = self._next_seq()

        try:
            handle = _pynvml.nvmlDeviceGetHandleByIndex(self.index)
        except Exception:
            # Could be invalid index or driver issue.
            return GpuSample(
                index=self.index,
                backend="pynvml",
                ok=False,
                reason="nvml_device_handle_error",
                classification=self._policy.classification,
                profile=self._policy.profile,
                ts_unix_ms=ts_unix_ms,
                ts_monotonic_ms=ts_monotonic_ms,
                sample_seq=sample_seq,
                host_handle=self._host_handle,
            )

        # Name
        try:
            raw_name = _pynvml.nvmlDeviceGetName(handle)
            name = (
                raw_name.decode("utf-8", errors="replace")
                if isinstance(raw_name, bytes)
                else str(raw_name)
            )
        except Exception:
            name = None

        # Utilization
        try:
            util = _pynvml.nvmlDeviceGetUtilizationRates(handle)
            # Convert percent to fraction in [0, 1].
            gpu_util = max(0.0, min(1.0, float(util.gpu) / 100.0))
        except Exception:
            gpu_util = 0.0

        # Memory
        try:
            mem = _pynvml.nvmlDeviceGetMemoryInfo(handle)
            # NVML reports bytes; convert to MiB.
            used_mib = float(mem.used) / (1024.0 * 1024.0)
            total_mib = float(mem.total) / (1024.0 * 1024.0)
        except Exception:
            used_mib = 0.0
            total_mib = 0.0

        # Temperature
        temp_c: Optional[float]
        try:
            temp_c = float(
                _pynvml.nvmlDeviceGetTemperature(handle, _pynvml.NVML_TEMPERATURE_GPU)
            )
        except Exception:
            temp_c = None

        # Power
        power_w: Optional[float]
        try:
            # NVML returns milliwatts.
            power_mw = float(_pynvml.nvmlDeviceGetPowerUsage(handle))
            power_w = power_mw / 1000.0
        except Exception:
            power_w = None

        # Driver / NVML versions.
        try:
            raw_driver = _pynvml.nvmlSystemGetDriverVersion()
            driver_version = (
                raw_driver.decode("utf-8", errors="replace")
                if isinstance(raw_driver, bytes)
                else str(raw_driver)
            )
        except Exception:
            driver_version = None

        try:
            raw_nvml = _pynvml.nvmlSystemGetNVMLVersion()
            nvml_version = (
                raw_nvml.decode("utf-8", errors="replace")
                if isinstance(raw_nvml, bytes)
                else str(raw_nvml)
            )
        except Exception:
            nvml_version = None

        return GpuSample(
            index=self.index,
            backend="pynvml",
            ok=True,
            reason=None,
            gpu_name=name,
            gpu_util=gpu_util,
            gpu_mem_used_mib=used_mib,
            gpu_mem_total_mib=total_mib,
            gpu_temp_c=temp_c,
            gpu_power_w=power_w,
            classification=self._policy.classification,
            profile=self._policy.profile,
            ts_unix_ms=ts_unix_ms,
            ts_monotonic_ms=ts_monotonic_ms,
            sample_seq=sample_seq,
            sample_uuid=None,
            driver_version=driver_version,
            nvml_version=nvml_version,
            host_handle=self._host_handle,
        )

    def _sample_noop(self) -> GpuSample:
        """
        No-op sample used when telemetry is disabled or unavailable.
        """
        ts_unix_ms = int(time.time() * 1000.0)
        ts_monotonic_ms = int(time.monotonic() * 1000.0)
        sample_seq = self._next_seq()

        if self._disabled:
            reason = "telemetry_disabled"
        elif _pynvml is None:
            reason = "pynvml_not_installed"
        elif _NVML_INIT_ERROR:
            reason = _NVML_INIT_ERROR
        else:
            reason = "backend_unavailable"

        return GpuSample(
            index=self.index,
            backend="none",
            ok=False,
            reason=reason,
            gpu_name=None,
            gpu_util=0.0,
            gpu_mem_used_mib=0.0,
            gpu_mem_total_mib=0.0,
            gpu_temp_c=None,
            gpu_power_w=None,
            classification=self._policy.classification,
            profile=self._policy.profile,
            ts_unix_ms=ts_unix_ms,
            ts_monotonic_ms=ts_monotonic_ms,
            sample_seq=sample_seq,
            sample_uuid=None,
            driver_version=None,
            nvml_version=None,
            host_handle=self._host_handle,
        )

    def _sample_raw(self) -> GpuSample:
        """
        Internal helper returning a GpuSample object (not dict).
        """
        if not self.is_enabled():
            return self._sample_noop()

        # Guard NVML access with a shared lock.
        with self._SAMPLE_LOCK:
            return self._sample_nvml()

    # ----------------- public API ----------------- #

    def is_enabled(self) -> bool:
        """
        Return True if this sampler is expected to provide real GPU telemetry.
        """
        return not self._disabled and self._backend != "none"

    def sample(self) -> Dict[str, Any]:
        """
        Take a single telemetry sample (no caching).

        Returns a JSON-friendly dict with the fields from GpuSample, filtered
        and minimized according to TelemetryPolicy.

        This function is safe to call from multiple threads; it will not raise
        on missing GPUs or backend issues.
        """
        sample = self._sample_raw()
        return sample.to_dict(self._policy)

    def sample_cached(self, max_age_ms: Optional[int] = None) -> Dict[str, Any]:
        """
        Take a telemetry sample with simple time-based caching.

        - If the last sample is newer than `max_age_ms`, returns the cached one.
        - Otherwise, triggers a fresh sample and updates the cache.

        This is helpful when multiple subsystems query GPU state frequently and
        you want to avoid hammering NVML.

        If `max_age_ms` is None, the default comes from:
            TCD_GPU_TELEMETRY_CACHE_MAX_AGE_MS  (profile-based default).
        """
        if max_age_ms is None:
            max_age_ms = self._default_cache_max_age_ms

        if max_age_ms <= 0:
            # Caller explicitly requested no caching.
            return self.sample()

        now = time.monotonic()
        with self._cache_lock:
            if self._last_sample is not None:
                age_ms = (now - self._last_sample_ts) * 1000.0
                if age_ms <= max_age_ms:
                    return self._last_sample.to_dict(self._policy)

        # Cache miss or expired; take a fresh sample.
        fresh = self._sample_raw()
        with self._cache_lock:
            self._last_sample = fresh
            self._last_sample_ts = now

        return fresh.to_dict(self._policy)

    def sample_report(
        self,
        *,
        max_age_ms: Optional[int] = None,
        prev_hash: Optional[str] = None,
        chain_label: str = "telemetry",
        attestation: Optional["_AttestationContext"] = None,
    ) -> Dict[str, Any]:
        """
        Take a sample (optionally cached) and wrap it into a TelemetryReport.

        If the crypto control plane is available, the report will include a
        digest and signature. If policy.require_signing is True and signing
        fails or crypto is unavailable, integrity.status will be set to
        "required_but_missing".
        """
        if max_age_ms is None:
            sample_dict = self.sample_cached()
        else:
            sample_dict = self.sample_cached(max_age_ms=max_age_ms)

        report = build_telemetry_report(
            sample_dict,
            policy=self._policy,
            prev_hash=prev_hash,
            chain_label=chain_label,
            attestation=attestation if _AttestationContext is not None else None,
        )
        return report.to_dict()

    # ----------------- fleet-wide helpers ----------------- #

    @classmethod
    def sample_fleet(cls) -> Dict[str, Any]:
        """
        Sample all GPUs visible to NVML.

        Returns a dict:

            {
              "backend": "pynvml" | "none",
              "ok": true/false,
              "reason": <str or null>,
              "count": <int>,
              "profile": <TelemetryProfile>,
              "classification": <str>,
              "telemetry_version": "TCD-GPU-TELEM-v1",
              "driver_version": <str or null>,
              "nvml_version": <str or null>,
              "host_handle": <str or null>,
              "gpus": [ <GpuSample dict> , ... ]
            }

        In environments without GPUs or with telemetry disabled, this will
        return backend="none" with an explanatory reason.
        """
        policy = TelemetryPolicy.from_env()

        disable_flag = os.getenv("TCD_GPU_TELEMETRY_DISABLE", "").strip().lower() in {"1", "true", "yes"}
        enable_flag = os.getenv("TCD_GPU_TELEMETRY_ENABLE", "").strip().lower() in {"1", "true", "yes"}
        host_handle = os.getenv("TCD_HOST_HANDLE") or None

        if policy.profile in ("PROD", "NATIONAL_DEFENSE"):
            enabled = enable_flag and not disable_flag
        else:
            enabled = not disable_flag

        if not enabled or _pynvml is None or not _ensure_nvml_initialized():
            if not enabled:
                reason = "telemetry_disabled"
            elif _pynvml is None:
                reason = "pynvml_not_installed"
            elif _NVML_INIT_ERROR:
                reason = _NVML_INIT_ERROR
            else:
                reason = "backend_unavailable"

            return {
                "backend": "none",
                "ok": False,
                "reason": reason,
                "count": 0,
                "profile": policy.profile,
                "classification": policy.classification,
                "telemetry_version": "TCD-GPU-TELEM-v1",
                "driver_version": None,
                "nvml_version": None,
                "host_handle": host_handle,
                "gpus": [],
            }

        assert _pynvml is not None  # for type checkers

        try:
            count = _pynvml.nvmlDeviceGetCount()
        except Exception as e:  # pragma: no cover
            logger.warning("Failed to get NVML device count: %s", e)
            return {
                "backend": "pynvml",
                "ok": False,
                "reason": "nvml_device_count_error",
                "count": 0,
                "profile": policy.profile,
                "classification": policy.classification,
                "telemetry_version": "TCD-GPU-TELEM-v1",
                "driver_version": None,
                "nvml_version": None,
                "host_handle": host_handle,
                "gpus": [],
            }

        # Optional cap on number of devices to sample, to avoid surprises in
        # large multi-GPU servers.
        max_devices_env = os.getenv("TCD_GPU_MAX_DEVICES", "").strip()
        max_devices: Optional[int]
        if max_devices_env:
            try:
                max_devices = max(0, int(max_devices_env))
            except Exception:
                logger.warning(
                    "Invalid TCD_GPU_MAX_DEVICES=%r, ignoring and sampling all devices.",
                    max_devices_env,
                )
                max_devices = None
        else:
            max_devices = None

        limit = count if max_devices is None else min(count, max_devices)

        gpus: List[Dict[str, Any]] = []
        driver_version: Optional[str] = None
        nvml_version: Optional[str] = None

        # Use a shared class-level lock for NVML operations.
        with cls._SAMPLE_LOCK:
            for idx in range(limit):
                sampler = cls(index=idx, policy=policy)
                sample = sampler._sample_nvml() if sampler.is_enabled() else sampler._sample_noop()
                sample_dict = sample.to_dict(policy)
                gpus.append(sample_dict)

                if driver_version is None:
                    driver_version = sample.driver_version
                if nvml_version is None:
                    nvml_version = sample.nvml_version

        return {
            "backend": "pynvml",
            "ok": True,
            "reason": None,
            "count": len(gpus),
            "profile": policy.profile,
            "classification": policy.classification,
            "telemetry_version": "TCD-GPU-TELEM-v1",
            "driver_version": driver_version,
            "nvml_version": nvml_version,
            "host_handle": host_handle,
            "gpus": gpus,
        }