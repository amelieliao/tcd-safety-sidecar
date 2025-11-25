# tcd/config.py
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, FrozenSet, Optional

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None

from pydantic import BaseModel

from .kv import canonical_kv_hash


_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Env helpers
# ---------------------------------------------------------------------------


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    v = raw.strip().lower()
    return v in ("1", "true", "yes", "on")


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except Exception:
        return default


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except Exception:
        return default


def _load_yaml_mapping(path: str) -> Dict[str, Any]:
    """
    Load a simple top-level mapping from YAML.

    Constraints:
      - Ignore if path missing or YAML not available.
      - Only accept dict at top-level.
      - Coerce non-scalar values via str() to avoid arbitrary structures.
    """
    if not path or yaml is None:
        return {}
    if not os.path.exists(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except Exception:
        _log.warning("failed to load YAML config from %s", path, exc_info=True)
        return {}
    if not isinstance(doc, dict):
        return {}
    out: Dict[str, Any] = {}
    for k, v in doc.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[str(k)] = v
        else:
            out[str(k)] = str(v)
    return out


def _break_glass_enabled() -> bool:
    """
    Break-glass mode: if this returns True, runtime is allowed to relax
    certain safety constraints. This should be coupled with strong
    operational controls (not implemented here).
    """
    token = os.environ.get("TCD_BREAK_GLASS_TOKEN", "").strip()
    return bool(token)


# ---------------------------------------------------------------------------
# Security / governance metadata
# ---------------------------------------------------------------------------

# Fields that are considered security-critical for directional constraints.
_SECURITY_CRITICAL_FIELDS: FrozenSet[str] = frozenset(
    {
        "debug",
        "config_version",
        "pq_required_global",
        "decision_engine_enabled",
        "detector_enabled",
        "receipts_enabled",
    }
)

# Fields that must only tighten security when changed as bools:
# False -> True allowed; True -> False blocked (unless break-glass).
_TIGHTEN_ONLY_BOOL_FIELDS: FrozenSet[str] = frozenset(
    {
        "pq_required_global",
        "decision_engine_enabled",
        "detector_enabled",
        "receipts_enabled",
    }
)

# Float fields that are "significance level" knobs: smaller means stricter.
# Allowed: new <= old without break-glass; new > old only in break-glass.
_TIGHTEN_ONLY_ALPHA_FIELDS: FrozenSet[str] = frozenset(
    {
        "alpha",
        "eprocess_alpha_default",
    }
)

# ---------------------------------------------------------------------------
# Settings model (single canonical control-plane snapshot)
# ---------------------------------------------------------------------------


class Settings(BaseModel):
    # --- Core / identity --------------------------------------------------

    debug: bool = True
    version: str = "dev"
    app_name: str = "TCD Safety Sidecar"
    author: str = "Amelie Liao"

    # Indicates how this config reached the process (yaml/env/bundle/etc.)
    config_origin: str = "defaults"
    # Optional identity of the signer / issuer of this config bundle.
    config_signer_id: str = ""
    # Marker indicating whether the config has been signed/verified upstream.
    config_signed: bool = False

    # --- Runtime features -------------------------------------------------

    gpu_enable: bool = False

    # Receipts / audit toggles
    receipts_enabled: bool = False

    # Metrics / observability
    prometheus_port: int = 8001
    prom_http_enable: bool = True

    otel_enable: bool = False
    otel_endpoint: str = ""

    # --- Global SLO / statistical control --------------------------------

    # Base significance level used when no module-specific alpha is given.
    alpha: float = 0.05
    # Soft latency target in milliseconds for fast-path responses.
    slo_latency_ms: float = 200.0
    # Human-readable config version tag.
    config_version: str = "v0.1"

    # --- HTTP rate limiting (token bucket) --------------------------------

    http_rate_capacity: float = 60.0
    http_rate_refill_per_s: float = 30.0

    # --- Token cost normalization -----------------------------------------

    token_cost_divisor_default: float = 50.0

    # --- PQ policy --------------------------------------------------------

    pq_required_global: bool = False
    pq_min_scheme: str = "dilithium2"  # logical tag, not an implementation detail
    pq_audit_enabled: bool = False

    # --- e-process / alpha investing policy -------------------------------

    # Default alpha for e-processes.
    eprocess_alpha_default: float = 0.05
    # Max allowed change in e-process alpha per reload (absolute difference).
    eprocess_alpha_max_delta_per_reload: float = 0.02
    # Wealth floor.
    eprocess_min_wealth: float = 0.0
    # Logical policy identifier for envelopes.
    eprocess_policy_ref: str = "tcd-default-eprocess-policy"

    # --- Governance / routing toggles -------------------------------------

    decision_engine_enabled: bool = True
    detector_enabled: bool = True
    trust_graph_enabled: bool = False

    # Hints for detector / decision engine default bands.
    default_risk_band_low: float = 0.20
    default_risk_band_high: float = 0.80

    # --- Ledger / persistence hints ---------------------------------------

    ledger_backend: str = "memory"  # "memory", "kv", "sql", "noop"
    ledger_namespace: str = "tcd-default"

    # --- Config / override safety -----------------------------------------

    # Global toggle: if False, ReloadableSettings.set() is effectively a no-op.
    allow_runtime_override: bool = True

    # Fields that are treated as immutable inside this process without
    # explicit break-glass. refresh() and set() will preserve them.
    immutable_fields: FrozenSet[str] = frozenset(
        {
            "debug",
            "config_version",
            "pq_required_global",
            "receipts_enabled",
        }
    )

    class Config:
        extra = "forbid"
        allow_mutation = False

    # ------------------------------------------------------------------ #
    # Derived helpers
    # ------------------------------------------------------------------ #

    def config_hash(self) -> str:
        """
        Stable, content-agnostic hash of the current settings.

        Safe to embed in receipts / logs / ledger. Secrets should not be
        stored in Settings.
        """
        try:
            payload = self.model_dump(mode="json")
        except Exception:
            payload = self.dict()
        return canonical_kv_hash(
            payload,
            ctx="tcd:settings",
            label="settings",
        )


# ---------------------------------------------------------------------------
# Loading / merging
# ---------------------------------------------------------------------------


def _load_settings() -> Settings:
    """
    Load Settings from defaults, optional YAML, and environment variables.

    Priority:
      1. Settings defaults (in-code).
      2. YAML file pointed to by TCD_CONFIG_PATH.
      3. Environment variables (TCD_*), with security-conscious bounds.

    Some security-critical fields are not overridden via environment to keep
    their supply chain restricted to config bundles / files.
    """
    base = Settings()

    try:
        merged: Dict[str, Any] = base.model_dump()
    except Exception:
        merged = base.dict()

    origin = "defaults"

    # 1) YAML overlay
    yaml_path = os.environ.get("TCD_CONFIG_PATH", "").strip()
    yaml_doc = _load_yaml_mapping(yaml_path)
    if yaml_doc:
        tmp = dict(merged)
        tmp.update(yaml_doc)
        cfg_from_yaml = Settings(**tmp)  # will enforce extra="forbid"
        try:
            merged = cfg_from_yaml.model_dump()
        except Exception:
            merged = cfg_from_yaml.dict()
        origin = "yaml"

    # 2) Environment overrides (only for non-locked fields)

    # Fields that we explicitly do NOT override from env.
    # These should be steered through config files / bundles instead.
    env_locked_fields: FrozenSet[str] = frozenset(
        {
            "pq_required_global",
            "receipts_enabled",
            "config_version",
        }
    )

    def _env_override(name: str, key: str, parser, bounds=None) -> None:
        if key in env_locked_fields:
            return
        old = merged.get(key)
        new = parser(name, old)
        if bounds is not None:
            lo, hi = bounds
            if isinstance(new, (int, float)):
                if new < lo or new > hi:
                    return
        merged[key] = new

    # Core / runtime
    _env_override("TCD_DEBUG", "debug", _env_bool)
    merged["version"] = os.environ.get("TCD_VERSION", merged["version"])
    _env_override("TCD_GPU_ENABLE", "gpu_enable", _env_bool)

    # Receipts
    _env_override("TCD_RECEIPTS_ENABLE", "receipts_enabled", _env_bool)

    # Metrics / OTEL
    port = _env_int("TCD_PROM_PORT", merged["prometheus_port"])
    merged["prometheus_port"] = max(0, port)
    _env_override("TCD_PROM_HTTP_ENABLE", "prom_http_enable", _env_bool)

    _env_override("TCD_OTEL_ENABLE", "otel_enable", _env_bool)
    merged["otel_endpoint"] = os.environ.get("TCD_OTEL_ENDPOINT", merged["otel_endpoint"])

    # SLO / alpha, with bounds
    alpha_env = _env_float("TCD_ALPHA", merged["alpha"])
    if 0.0 < alpha_env <= 1.0:
        merged["alpha"] = alpha_env

    slo_env = _env_float("TCD_SLO_MS", merged["slo_latency_ms"])
    if 1.0 <= slo_env <= 120_000.0:
        merged["slo_latency_ms"] = slo_env

    # Rate limiting
    cap_env = _env_float("TCD_HTTP_RATE_CAP", merged["http_rate_capacity"])
    if cap_env >= 0.0:
        merged["http_rate_capacity"] = cap_env

    refill_env = _env_float("TCD_HTTP_RATE_REFILL", merged["http_rate_refill_per_s"])
    if refill_env >= 0.0:
        merged["http_rate_refill_per_s"] = refill_env

    # Token cost divisor
    tcost_env = _env_float("TCD_TOKEN_COST_DIVISOR", merged["token_cost_divisor_default"])
    if tcost_env > 0.0:
        merged["token_cost_divisor_default"] = tcost_env

    # PQ policy: required flag is env-locked; scheme / audit toggles are not.
    merged["pq_min_scheme"] = os.environ.get("TCD_PQ_MIN_SCHEME", merged["pq_min_scheme"])
    _env_override("TCD_PQ_AUDIT_ENABLED", "pq_audit_enabled", _env_bool)

    # e-process policy
    e_alpha_env = _env_float("TCD_EPROC_ALPHA", merged["eprocess_alpha_default"])
    if 0.0 < e_alpha_env <= 1.0:
        merged["eprocess_alpha_default"] = e_alpha_env

    e_delta_env = _env_float(
        "TCD_EPROC_ALPHA_MAX_DELTA",
        merged["eprocess_alpha_max_delta_per_reload"],
    )
    if 0.0 < e_delta_env <= 0.5:
        merged["eprocess_alpha_max_delta_per_reload"] = e_delta_env

    e_minw_env = _env_float("TCD_EPROC_MIN_WEALTH", merged["eprocess_min_wealth"])
    if e_minw_env >= 0.0:
        merged["eprocess_min_wealth"] = e_minw_env

    merged["eprocess_policy_ref"] = os.environ.get(
        "TCD_EPROC_POLICY_REF",
        merged["eprocess_policy_ref"],
    )

    # Governance toggles
    _env_override("TCD_DECISION_ENGINE_ENABLED", "decision_engine_enabled", _env_bool)
    _env_override("TCD_DETECTOR_ENABLED", "detector_enabled", _env_bool)
    _env_override("TCD_TRUST_GRAPH_ENABLED", "trust_graph_enabled", _env_bool)

    # Risk band hints: keep ordered and inside [0,1].
    low_band_env = _env_float("TCD_RISK_BAND_LOW", merged["default_risk_band_low"])
    high_band_env = _env_float("TCD_RISK_BAND_HIGH", merged["default_risk_band_high"])
    low_band = min(max(low_band_env, 0.0), 1.0)
    high_band = min(max(high_band_env, 0.0), 1.0)
    if low_band > high_band:
        low_band, high_band = high_band, low_band
    merged["default_risk_band_low"] = low_band
    merged["default_risk_band_high"] = high_band

    # Ledger hints
    merged["ledger_backend"] = os.environ.get("TCD_LEDGER_BACKEND", merged["ledger_backend"])
    merged["ledger_namespace"] = os.environ.get("TCD_LEDGER_NAMESPACE", merged["ledger_namespace"])

    # Runtime override toggle
    _env_override("TCD_ALLOW_RUNTIME_OVERRIDE", "allow_runtime_override", _env_bool)

    # config_origin update
    merged["config_origin"] = origin

    return Settings(**merged)


# ---------------------------------------------------------------------------
# Reloadable wrapper
# ---------------------------------------------------------------------------


class ReloadableSettings:
    """
    Thread-safe wrapper around Settings with controlled refresh/override.

    Properties:
      - get(): returns an immutable Settings snapshot.
      - refresh(): reloads, applies directional/tighten-only constraints,
                   preserves immutable_fields unless break-glass.
      - set(): bounded in-memory overrides with the same constraints.
    """

    def __init__(self, initial: Optional[Settings] = None) -> None:
        self._lock = threading.RLock()
        self._settings = initial or _load_settings()

    def get(self) -> Settings:
        with self._lock:
            return self._settings

    # ---- internal helpers ---------------------------------------------- #

    @staticmethod
    def _apply_tighten_only(
        field: str,
        old_value: Any,
        new_value: Any,
        *,
        break_glass: bool,
        alpha_max_delta: float,
    ) -> Any:
        """
        Apply directional constraints for security-sensitive fields.

        - For bool fields in _TIGHTEN_ONLY_BOOL_FIELDS:
          * False -> True allowed.
          * True -> False blocked without break-glass.
        - For float fields in _TIGHTEN_ONLY_ALPHA_FIELDS:
          * new <= old always allowed (stricter).
          * new > old allowed only in break-glass mode.
          * For e-process alpha, enforce per-reload delta bound.
        """
        if field in _TIGHTEN_ONLY_BOOL_FIELDS and isinstance(old_value, bool) and isinstance(
            new_value, bool
        ):
            if old_value and not new_value and not break_glass:
                # Block relaxation.
                return old_value
            return new_value

        if field in _TIGHTEN_ONLY_ALPHA_FIELDS and isinstance(old_value, (int, float)) and isinstance(
            new_value, (int, float)
        ):
            old_f = float(old_value)
            new_f = float(new_value)
            if new_f <= old_f:
                # Tightening is always allowed.
                return new_f
            # Relaxation only under break-glass.
            if not break_glass:
                return old_f
            # If this is the e-process alpha, enforce delta bound.
            if field == "eprocess_alpha_default":
                if abs(new_f - old_f) > alpha_max_delta:
                    return old_f
            return new_f

        # Default: no special directional constraint.
        return new_value

    # ---- public API ----------------------------------------------------- #

    def refresh(self) -> Settings:
        """
        Reload configuration from file and environment.

        Rules:
          - immutable_fields from the current snapshot are preserved unless
            break-glass is enabled.
          - security-critical fields follow tighten-only rules unless
            break-glass is enabled.
        """
        with self._lock:
            old = self._settings
            new = _load_settings()

            try:
                old_data = old.model_dump()
                new_data = new.model_dump()
            except Exception:
                old_data = old.dict()
                new_data = new.dict()

            immutables = set(old.immutable_fields)
            break_glass = _break_glass_enabled()

            # Always keep immutable_fields value itself unless break-glass.
            if not break_glass and "immutable_fields" in old_data:
                new_data["immutable_fields"] = old_data["immutable_fields"]

            # Directional constraints & immutability
            alpha_delta = float(old_data.get("eprocess_alpha_max_delta_per_reload", 0.02))

            for key, old_value in old_data.items():
                if key not in new_data:
                    # New config dropped a key; keep old value.
                    new_data[key] = old_value
                    continue

                if not break_glass and key in immutables:
                    # Preserve immutable fields.
                    new_data[key] = old_value
                    continue

                # Apply tighten-only constraints to security-critical fields.
                if key in _SECURITY_CRITICAL_FIELDS or key in _TIGHTEN_ONLY_ALPHA_FIELDS:
                    new_data[key] = self._apply_tighten_only(
                        key,
                        old_value,
                        new_data[key],
                        break_glass=break_glass,
                        alpha_max_delta=alpha_delta,
                    )

            updated = Settings(**new_data)
            self._settings = updated
            return updated

    def set(self, **overrides: Any) -> Settings:
        """
        Apply restricted in-memory overrides.

        Rules:
          - If allow_runtime_override is False, this is a no-op.
          - Fields in immutable_fields are not changed unless break-glass.
          - immutable_fields itself is never changed unless break-glass.
          - Security-critical and alpha fields follow tighten-only rules.
        """
        with self._lock:
            current = self._settings

            if not current.allow_runtime_override and not _break_glass_enabled():
                return current

            try:
                data = current.model_dump()
            except Exception:
                data = current.dict()

            immutables = set(current.immutable_fields)
            break_glass = _break_glass_enabled()
            alpha_delta = float(data.get("eprocess_alpha_max_delta_per_reload", 0.02))

            for key, value in overrides.items():
                if key not in data:
                    continue

                if not break_glass and (key in immutables or key == "immutable_fields"):
                    continue

                old_value = data[key]

                if key in _SECURITY_CRITICAL_FIELDS or key in _TIGHTEN_ONLY_ALPHA_FIELDS:
                    data[key] = self._apply_tighten_only(
                        key,
                        old_value,
                        value,
                        break_glass=break_glass,
                        alpha_max_delta=alpha_delta,
                    )
                else:
                    data[key] = value

            updated = Settings(**data)
            self._settings = updated
            return updated


def make_reloadable_settings() -> ReloadableSettings:
    return ReloadableSettings(_load_settings())