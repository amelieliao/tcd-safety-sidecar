# FILE: tcd/exporter.py
# Prometheus exporter wrapper for TCD.
#
# Threat / compliance oriented design:
# - Metrics are structured around:
#     * safety decisions (actions, risk, decision paths),
#     * statistical control (e-process, alpha/FDR),
#     * budgets (per tenant/user/session),
#     * SLO / failure modes (fail-open/closed, detector fallback),
#     * threat / red-team scenarios,
#     * exporter self-health (dropped samples, backend status).
# - Label sets are small and controlled; any extra labels are filtered and
#   recorded in a "dropped_samples" meta metric.
# - Exporter can be disabled globally via env, and degrades to a no-op when
#   prometheus_client is not present.
#
# This module does NOT itself expose an HTTP endpoint unless explicitly
# requested. In typical deployments:
#   - TCDPrometheusExporter is used to register/update metrics; and
#   - The main ASGI app exposes a single /metrics endpoint.
#
# In high-stakes / regulated environments (finance, healthcare, critical
# infrastructure, high-compliance SaaS), these metrics can be used as:
#   - a low-cardinality operational view of TCD,
#   - evidence to cross-check receipts / logs,
#   - an early-warning system for fail-open / drift / adversarial probing.

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional Prometheus backend
# ---------------------------------------------------------------------------

try:
    from prometheus_client import (
        Counter,
        Histogram,
        Gauge,
        Info,
        CollectorRegistry,
        start_http_server,
        REGISTRY,
    )

    _PROM_AVAILABLE = True
except Exception:  # pragma: no cover - import-time fallback
    Counter = Histogram = Gauge = Info = CollectorRegistry = None  # type: ignore[assignment]
    start_http_server = None  # type: ignore[assignment]
    REGISTRY = None  # type: ignore[assignment]
    _PROM_AVAILABLE = False
    logger.info("prometheus_client not available; TCDPrometheusExporter will act as a no-op backend.")

# Global switch: allow disabling all metrics in sensitive environments.
_METRICS_DISABLED = os.getenv("TCD_METRICS_DISABLE", "").strip().lower() in {"1", "true", "yes"}

# Singleton-level state to avoid multiple standalone servers per process.
_STANDALONE_SERVER_STARTED = False
_STANDALONE_SERVER_LOCK = threading.Lock()


def _safe_str(value: Any) -> str:
    """
    Convert values to short strings for labels.

    - None → ""
    - Long strings are truncated to 64 characters to limit label explosion.
    """
    if value is None:
        return ""
    s = str(value)
    if len(s) > 64:
        s = s[:61] + "..."
    return s


# For simple label whitelisting: metric_name -> allowed label keys.
# Anything outside this set will be dropped and counted as "label_filtered".
_METRIC_LABEL_WHITELIST: Dict[str, set[str]] = {
    # Core decision / latency / SLO metrics
    "tcd_request_latency_seconds": {"action"},
    "tcd_decision_total": {"action", "model_id"},
    "tcd_decision_risk": {"action"},
    "tcd_action_total": {"model_id", "gpu_id", "action"},
    "tcd_slo_violation_total": {"key", "model_id", "gpu_id"},
    "tcd_decision_seq_total": {"tenant", "policy"},

    # Statistical control / budget
    "tcd_eprocess_wealth": {"tenant", "policy"},
    "tcd_eprocess_pvalue": {"tenant", "policy"},
    "tcd_budget_remaining": {"tenant", "user", "session"},
    "tcd_budget_spent_total": {"tenant", "user", "session"},
    "tcd_alpha_budget_initial": {"tenant", "policy"},
    "tcd_alpha_budget_used": {"tenant", "policy"},
    "tcd_alpha_budget_reset_total": {"tenant", "policy", "reason"},
    "tcd_fdr_estimate": {"tenant", "policy"},

    # Safety / threat taxonomy
    "tcd_safety_event_total": {
        "event_type", "stage", "severity", "policy", "scenario_id", "traffic_class"
    },
    "tcd_decision_path_total": {"path", "fallback_used", "policy"},
    "tcd_fail_open_total": {"reason", "policy"},
    "tcd_fail_closed_total": {"reason", "policy"},
    "tcd_detector_fallback_total": {"stage", "reason", "policy"},
    "tcd_adversarial_pattern_total": {"pattern_type", "tenant", "policy"},

    # Meta / exporter self-health
    "tcd_metrics_dropped_samples_total": {"reason"},
    "tcd_metrics_observe_errors_total": {"metric_name"},
    # tcd_metrics_last_success_timestamp has no labels.
    # tcd_metrics_backend_info is Info, labels inferred from .info() mapping.
}


class TCDPrometheusExporter:
    """
    Threat-aware Prometheus exporter for TCD.

    Constructor (backwards compatible):

        exporter = TCDPrometheusExporter(
            port=9100,
            version="1.0.0",
            config_hash="abc123",
        )

    Additional optional env-based configuration:
        - TCD_METRICS_DISABLE: "1"/"true"/"yes" -> disable all metrics (no-op).
        - TCD_PROM_STANDALONE_SERVER: "1"/"true"/"yes" -> start an HTTP server.
        - TCD_METRICS_PROFILE: "internal" (default) or "external" (for a more
          restrictive / minimal view; currently just a label on backend_info).

    Methods kept for compatibility with existing code:
        - ensure_server()
        - observe_latency(s: float, action: str = "unknown")
        - push(verdict_pack, labels: Optional[Dict[str,Any]] = None)
        - push_eprocess(...)
        - update_budget_metrics(...)
        - record_action(...)
        - slo_violation_by_model(...)
        - slo_violation(...)
    """

    def __init__(
        self,
        port: int,
        version: str,
        config_hash: str,
        *,
        profile: Optional[str] = None,
        policy_version: Optional[str] = None,
        ruleset_hash: Optional[str] = None,
        metric_surface_version: Optional[str] = None,
    ) -> None:
        self.port = int(port)
        self.version = str(version)
        self.config_hash_value = str(config_hash)
        self.profile = profile or os.getenv("TCD_METRICS_PROFILE", "internal")

        # Optional fields surfaced via build_info.
        self.policy_version = policy_version or os.getenv("TCD_POLICY_VERSION", "")
        self.ruleset_hash = ruleset_hash or os.getenv("TCD_RULESET_HASH", "")
        self.metric_surface_version = metric_surface_version or os.getenv(
            "TCD_METRIC_SURFACE_VERSION", "v1"
        )

        # Local lock for lazy metric initialization and server startup.
        self._lock = threading.Lock()
        self._initialized = False

        # Core metrics
        self._build_info: Optional[Info] = None
        self._backend_info: Optional[Info] = None
        self._latency_hist: Optional[Histogram] = None
        self._decision_counter: Optional[Counter] = None
        self._decision_risk_hist: Optional[Histogram] = None
        self._decision_seq_gauge: Optional[Gauge] = None
        self._eprocess_wealth_gauge: Optional[Gauge] = None
        self._eprocess_pvalue_gauge: Optional[Gauge] = None
        self._budget_remaining_gauge: Optional[Gauge] = None
        self._budget_spent_counter: Optional[Counter] = None
        self._action_counter: Optional[Counter] = None
        self._slo_violation_counter: Optional[Counter] = None

        # Statistical control / alpha / FDR
        self._alpha_initial_gauge: Optional[Gauge] = None
        self._alpha_used_gauge: Optional[Gauge] = None
        self._alpha_reset_counter: Optional[Counter] = None
        self._fdr_estimate_gauge: Optional[Gauge] = None

        # Safety / threat taxonomy
        self._safety_event_counter: Optional[Counter] = None
        self._decision_path_counter: Optional[Counter] = None
        self._fail_open_counter: Optional[Counter] = None
        self._fail_closed_counter: Optional[Counter] = None
        self._detector_fallback_counter: Optional[Counter] = None
        self._adversarial_pattern_counter: Optional[Counter] = None

        # Exporter self-health
        self._metrics_dropped_counter: Optional[Counter] = None
        self._metrics_error_counter: Optional[Counter] = None
        self._metrics_last_success_ts: Optional[Gauge] = None

    # -----------------------------------------------------------------------
    # Internal helpers
    # -----------------------------------------------------------------------

    def _metrics_enabled(self) -> bool:
        """
        Return True if Prometheus is available and metrics are not globally disabled.
        """
        if _METRICS_DISABLED:
            return False
        if not _PROM_AVAILABLE:
            return False
        return True

    def _metric_labels(self, metric_name: str, label_values: Dict[str, Any]) -> Dict[str, str]:
        """
        Apply label whitelist + value cleaning for a given metric_name.

        Any label key not in the whitelist is dropped and counted as a
        "label_filtered" dropped-sample reason.
        """
        allowed = _METRIC_LABEL_WHITELIST.get(metric_name)
        if not allowed:
            # If we don't know the metric, just keep what we have but still
            # normalize the values.
            return {k: _safe_str(v) for k, v in label_values.items()}

        filtered: Dict[str, str] = {}
        dropped_any = False
        for k, v in label_values.items():
            if k in allowed:
                filtered[k] = _safe_str(v)
            else:
                dropped_any = True

        if dropped_any:
            self._record_dropped_sample(reason="label_filtered")

        return filtered

    def _record_dropped_sample(self, reason: str) -> None:
        """
        Increment meta metric for dropped/ignored metric updates.
        """
        if not self._metrics_enabled() or not self._initialized:
            return
        if self._metrics_dropped_counter is None:
            return
        try:
            self._metrics_dropped_counter.labels(reason=_safe_str(reason)).inc()
        except Exception:
            # Drop silently; we don't want meta-metrics to explode either.
            return

    def _record_observe_error(self, metric_name: str, exc: Exception) -> None:
        """
        Increment meta metric for metric-update errors.
        """
        if not self._metrics_enabled() or not self._initialized:
            return
        if self._metrics_error_counter is None:
            return
        try:
            self._metrics_error_counter.labels(metric_name=_safe_str(metric_name)).inc()
        except Exception:
            return
        # Optional: log at debug to avoid noisy logs in prod.
        logger.debug("Metric update error for %s: %s", metric_name, exc)

    def _mark_success(self) -> None:
        """
        Update the 'last_success_timestamp' gauge when a metric update succeeds.
        """
        if not self._metrics_enabled() or not self._initialized:
            return
        if self._metrics_last_success_ts is None:
            return
        try:
            self._metrics_last_success_ts.set(time.time())
        except Exception:
            return

    def _init_metrics_if_needed(self) -> None:
        """
        Lazily create metric objects and publish build/backend info.

        This method is idempotent and guarded by a lock.
        """
        if not self._metrics_enabled():
            return

        if self._initialized:
            return

        with self._lock:
            if self._initialized:
                return

            registry = REGISTRY

            # Build info: static labels for version, config hash, and policy surface.
            try:
                self._build_info = Info(
                    "tcd_build_info",
                    "TCD build metadata",
                    registry=registry,
                )
                self._build_info.info(
                    {
                        "version": self.version,
                        "config_hash": self.config_hash_value,
                        "policy_version": self.policy_version,
                        "ruleset_hash": self.ruleset_hash,
                        "metric_surface_version": self.metric_surface_version,
                    }
                )
            except Exception as e:  # pragma: no cover
                logger.warning("Failed to register tcd_build_info: %s", e)

            # Backend info: exporter-level health.
            try:
                self._backend_info = Info(
                    "tcd_metrics_backend_info",
                    "TCD metrics backend status and profile",
                    registry=registry,
                )
                self._backend_info.info(
                    {
                        "prom_available": "1" if _PROM_AVAILABLE else "0",
                        "metrics_disabled": "1" if _METRICS_DISABLED else "0",
                        "standalone_server": "0",
                        "profile": self.profile,
                    }
                )
            except Exception as e:
                logger.warning("Failed to register tcd_metrics_backend_info: %s", e)

            # Latency histogram (seconds).
            try:
                self._latency_hist = Histogram(
                    "tcd_request_latency_seconds",
                    "Latency of requests passing through TCD",
                    ["action"],
                    buckets=(0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0),
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register tcd_request_latency_seconds: %s", e)

            # Decision counter + risk histogram.
            try:
                self._decision_counter = Counter(
                    "tcd_decision_total",
                    "Number of decisions taken by TCD",
                    ["action", "model_id"],
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register tcd_decision_total: %s", e)

            try:
                self._decision_risk_hist = Histogram(
                    "tcd_decision_risk",
                    "Distribution of risk scores at decision time",
                    ["action"],
                    buckets=(0.0, 0.1, 0.2, 0.4, 0.6, 0.8, 0.9, 0.95, 0.99, 1.0),
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register tcd_decision_risk: %s", e)

            # Decision sequence (for cross-checking with receipts).
            try:
                self._decision_seq_gauge = Gauge(
                    "tcd_decision_seq_total",
                    "Monotone decision sequence index for TCD (per tenant/policy)",
                    ["tenant", "policy"],
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register tcd_decision_seq_total: %s", e)

            # e-process / alpha-wealth gauges.
            try:
                self._eprocess_wealth_gauge = Gauge(
                    "tcd_eprocess_wealth",
                    "Current e-process / alpha-wealth for the safety controller",
                    ["tenant", "policy"],
                    registry=registry,
                )
                self._eprocess_pvalue_gauge = Gauge(
                    "tcd_eprocess_pvalue",
                    "Last p-value / test statistic snapshot for the safety controller",
                    ["tenant", "policy"],
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register e-process gauges: %s", e)

            # Budget metrics (e.g., per-tenant/session budget).
            try:
                self._budget_remaining_gauge = Gauge(
                    "tcd_budget_remaining",
                    "Remaining safety / call budget per tenant-user-session",
                    ["tenant", "user", "session"],
                    registry=registry,
                )
                self._budget_spent_counter = Counter(
                    "tcd_budget_spent_total",
                    "Number of times budget was spent/exhausted",
                    ["tenant", "user", "session"],
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register budget metrics: %s", e)

            # Action metrics (per model/GPU/action).
            try:
                self._action_counter = Counter(
                    "tcd_action_total",
                    "Actions taken by TCD, broken down by model and GPU",
                    ["model_id", "gpu_id", "action"],
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register tcd_action_total: %s", e)

            # SLO violations.
            try:
                self._slo_violation_counter = Counter(
                    "tcd_slo_violation_total",
                    "SLO violations observed by TCD",
                    ["key", "model_id", "gpu_id"],
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register tcd_slo_violation_total: %s", e)

            # Alpha / FDR control.
            try:
                self._alpha_initial_gauge = Gauge(
                    "tcd_alpha_budget_initial",
                    "Initial alpha budget for a tenant/policy",
                    ["tenant", "policy"],
                    registry=registry,
                )
                self._alpha_used_gauge = Gauge(
                    "tcd_alpha_budget_used",
                    "Used alpha budget for a tenant/policy",
                    ["tenant", "policy"],
                    registry=registry,
                )
                self._alpha_reset_counter = Counter(
                    "tcd_alpha_budget_reset_total",
                    "Number of times alpha budget was reset",
                    ["tenant", "policy", "reason"],
                    registry=registry,
                )
                self._fdr_estimate_gauge = Gauge(
                    "tcd_fdr_estimate",
                    "Current FDR estimate under the safety controller",
                    ["tenant", "policy"],
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register alpha/FDR metrics: %s", e)

            # Safety / threat taxonomy.
            try:
                self._safety_event_counter = Counter(
                    "tcd_safety_event_total",
                    "Categorized safety events observed by TCD",
                    ["event_type", "stage", "severity", "policy", "scenario_id", "traffic_class"],
                    registry=registry,
                )
                self._decision_path_counter = Counter(
                    "tcd_decision_path_total",
                    "Decision paths taken by TCD (allow/slow/degrade/block + path)",
                    ["path", "fallback_used", "policy"],
                    registry=registry,
                )
                self._fail_open_counter = Counter(
                    "tcd_fail_open_total",
                    "Fail-open events in TCD",
                    ["reason", "policy"],
                    registry=registry,
                )
                self._fail_closed_counter = Counter(
                    "tcd_fail_closed_total",
                    "Fail-closed events in TCD",
                    ["reason", "policy"],
                    registry=registry,
                )
                self._detector_fallback_counter = Counter(
                    "tcd_detector_fallback_total",
                    "Detector / calibrator fallback usage in TCD",
                    ["stage", "reason", "policy"],
                    registry=registry,
                )
                self._adversarial_pattern_counter = Counter(
                    "tcd_adversarial_pattern_total",
                    "Adversarial pattern detections (e.g., probing, injection attempts)",
                    ["pattern_type", "tenant", "policy"],
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register safety/threat metrics: %s", e)

            # Exporter self-health.
            try:
                self._metrics_dropped_counter = Counter(
                    "tcd_metrics_dropped_samples_total",
                    "Number of dropped/ignored metric updates",
                    ["reason"],
                    registry=registry,
                )
                self._metrics_error_counter = Counter(
                    "tcd_metrics_observe_errors_total",
                    "Number of errors while updating metrics",
                    ["metric_name"],
                    registry=registry,
                )
                self._metrics_last_success_ts = Gauge(
                    "tcd_metrics_last_success_timestamp",
                    "Unix timestamp of the last successful metric update",
                    registry=registry,
                )
            except Exception as e:
                logger.warning("Failed to register metrics self-health: %s", e)

            self._initialized = True

    # -----------------------------------------------------------------------
    # Server management
    # -----------------------------------------------------------------------

    def ensure_server(self) -> bool:
        """
        Optionally start a standalone Prometheus HTTP server, if enabled.

        Behavior:
        - If metrics are disabled or prometheus_client is missing, returns False.
        - If TCD_PROM_STANDALONE_SERVER in {"1","true","yes"}, starts a single
          HTTP server on self.port (idempotent) and returns True.
        - Otherwise, just initializes metrics and returns True.
        """
        if not self._metrics_enabled():
            return False

        self._init_metrics_if_needed()

        standalone_flag = os.getenv("TCD_PROM_STANDALONE_SERVER", "").strip().lower()
        if standalone_flag not in {"1", "true", "yes"}:
            # No standalone server; host app is expected to expose /metrics.
            return True

        if start_http_server is None:
            return False

        global _STANDALONE_SERVER_STARTED
        if _STANDALONE_SERVER_STARTED:
            # Update backend_info to reflect this as well.
            if self._backend_info is not None:
                try:
                    self._backend_info.info(
                        {
                            "prom_available": "1" if _PROM_AVAILABLE else "0",
                            "metrics_disabled": "1" if _METRICS_DISABLED else "0",
                            "standalone_server": "1",
                            "profile": self.profile,
                        }
                    )
                except Exception:
                    pass
            return True

        with _STANDALONE_SERVER_LOCK:
            if _STANDALONE_SERVER_STARTED:
                return True
            try:
                start_http_server(self.port)
                _STANDALONE_SERVER_STARTED = True
                logger.info("TCD Prometheus standalone server started on port %d", self.port)
                if self._backend_info is not None:
                    try:
                        self._backend_info.info(
                            {
                                "prom_available": "1" if _PROM_AVAILABLE else "0",
                                "metrics_disabled": "1" if _METRICS_DISABLED else "0",
                                "standalone_server": "1",
                                "profile": self.profile,
                            }
                        )
                    except Exception:
                        pass
                return True
            except Exception as e:  # pragma: no cover
                logger.error("Failed to start Prometheus standalone server on port %d: %s", self.port, e)
                return False

    # -----------------------------------------------------------------------
    # Core metrics (backwards-compatible entry points)
    # -----------------------------------------------------------------------

    def observe_latency(self, s: float, action: str = "unknown") -> None:
        """
        Observe a latency value (seconds) for a given action.

        `action` is typically one of: allow, slow, degrade, block, error, etc.
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        if self._latency_hist is None:
            return

        try:
            labels = self._metric_labels(
                "tcd_request_latency_seconds",
                {"action": action},
            )
            self._latency_hist.labels(**labels).observe(float(s))
            self._mark_success()
        except Exception as e:
            self._record_observe_error("tcd_request_latency_seconds", e)

    def push(self, verdict_pack: Any, labels: Optional[Dict[str, Any]] = None) -> None:
        """
        Record a decision event.

        Expected fields on `verdict_pack` (dict or object-like):
            - action:         "allow" | "slow" | "degrade" | "block" | ...
            - risk:           float in [0,1], if available.
            - model_id:       short model identifier.
            - gpu_id:         GPU identifier.
            - tenant:         tenant ID or hashed tenant ID (optional).
            - policy:         policy ID/name (optional).
            - decision_seq:   monotone sequence number from receipts (optional).
            - path:           decision path (optional).
            - fallback_used:  e.g., "none", "conformal", "fail_closed" (optional).
            - scenario_id:    red-team / scenario identifier (optional).
            - traffic_class:  "prod" | "shadow" | "replay" | ... (optional).

        `labels` can override or add low-cardinality tags (e.g., pre-hashed IDs).
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        def _get(field: str, default: Any = "") -> Any:
            if isinstance(verdict_pack, dict):
                return verdict_pack.get(field, default)
            return getattr(verdict_pack, field, default)

        base_labels = labels or {}

        action = base_labels.get("action", _get("action", "unknown"))
        model_id = base_labels.get("model_id", _get("model_id", ""))
        gpu_id = base_labels.get("gpu_id", _get("gpu_id", ""))
        risk = _get("risk", None)
        tenant = base_labels.get("tenant", _get("tenant", ""))
        policy = base_labels.get("policy", _get("policy", ""))
        decision_seq = _get("decision_seq", None)
        path = base_labels.get("path", _get("path", ""))
        fallback_used = base_labels.get("fallback_used", _get("fallback_used", "none"))
        scenario_id = base_labels.get("scenario_id", _get("scenario_id", ""))
        traffic_class = base_labels.get("traffic_class", _get("traffic_class", "prod"))

        # Decision counter.
        if self._decision_counter is not None:
            try:
                label_values = self._metric_labels(
                    "tcd_decision_total",
                    {"action": action, "model_id": model_id},
                )
                self._decision_counter.labels(**label_values).inc()
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_decision_total", e)

        # Risk histogram.
        if risk is not None and self._decision_risk_hist is not None:
            try:
                label_values = self._metric_labels(
                    "tcd_decision_risk",
                    {"action": action},
                )
                self._decision_risk_hist.labels(**label_values).observe(float(risk))
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_decision_risk", e)

        # Generic action counter.
        if self._action_counter is not None:
            try:
                label_values = self._metric_labels(
                    "tcd_action_total",
                    {"model_id": model_id, "gpu_id": gpu_id, "action": action},
                )
                self._action_counter.labels(**label_values).inc()
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_action_total", e)

        # Decision sequence gauge (if provided).
        if decision_seq is not None and self._decision_seq_gauge is not None:
            try:
                label_values = self._metric_labels(
                    "tcd_decision_seq_total",
                    {"tenant": tenant, "policy": policy},
                )
                self._decision_seq_gauge.labels(**label_values).set(float(decision_seq))
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_decision_seq_total", e)

        # Decision path / fallback.
        if self._decision_path_counter is not None and (path or fallback_used):
            try:
                label_values = self._metric_labels(
                    "tcd_decision_path_total",
                    {"path": path or "unknown", "fallback_used": fallback_used or "none", "policy": policy},
                )
                self._decision_path_counter.labels(**label_values).inc()
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_decision_path_total", e)

        # Threat / scenario tagging (optional).
        # If verdict_pack carries an event_type / stage / severity, treat it
        # as a categorized safety event.
        event_type = _get("event_type", None)
        stage = _get("stage", None)
        severity = _get("severity", None)
        if self._safety_event_counter is not None and event_type and stage:
            try:
                label_values = self._metric_labels(
                    "tcd_safety_event_total",
                    {
                        "event_type": event_type,
                        "stage": stage,
                        "severity": severity or "low",
                        "policy": policy,
                        "scenario_id": scenario_id,
                        "traffic_class": traffic_class,
                    },
                )
                self._safety_event_counter.labels(**label_values).inc()
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_safety_event_total", e)

    def push_eprocess(
        self,
        *,
        tenant: str = "",
        policy: str = "",
        wealth: float,
        p_value: Optional[float] = None,
    ) -> None:
        """
        Update e-process / alpha-wealth gauges.

        Example:
            exporter.push_eprocess(
                tenant="tenantA",
                policy="default",
                wealth=current_wealth,
                p_value=current_p_value,
            )
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        tenant_label = tenant
        policy_label = policy

        if self._eprocess_wealth_gauge is not None:
            try:
                labels = self._metric_labels(
                    "tcd_eprocess_wealth",
                    {"tenant": tenant_label, "policy": policy_label},
                )
                self._eprocess_wealth_gauge.labels(**labels).set(float(wealth))
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_eprocess_wealth", e)

        if p_value is not None and self._eprocess_pvalue_gauge is not None:
            try:
                labels = self._metric_labels(
                    "tcd_eprocess_pvalue",
                    {"tenant": tenant_label, "policy": policy_label},
                )
                self._eprocess_pvalue_gauge.labels(**labels).set(float(p_value))
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_eprocess_pvalue", e)

    def update_budget_metrics(
        self,
        tenant: str,
        user: str,
        session: str,
        *,
        remaining: float,
        spent: bool,
    ) -> None:
        """
        Update budget-related metrics for a given (tenant, user, session).

        - remaining: remaining budget fraction or absolute units.
        - spent:     if True, increments the "budget_spent_total" counter.
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        if self._budget_remaining_gauge is not None:
            try:
                labels = self._metric_labels(
                    "tcd_budget_remaining",
                    {"tenant": tenant, "user": user, "session": session},
                )
                self._budget_remaining_gauge.labels(**labels).set(float(remaining))
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_budget_remaining", e)

        if spent and self._budget_spent_counter is not None:
            try:
                labels = self._metric_labels(
                    "tcd_budget_spent_total",
                    {"tenant": tenant, "user": user, "session": session},
                )
                self._budget_spent_counter.labels(**labels).inc()
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_budget_spent_total", e)

    def record_action(self, model_id: str, gpu_id: str, action: str) -> None:
        """
        Record a simple action event for a given model/GPU.

        This is a thinner wrapper than push(), useful when you don't have a
        full verdict_pack but still want per-model/gpu action counts.
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        if self._action_counter is None:
            return

        try:
            labels = self._metric_labels(
                "tcd_action_total",
                {"model_id": model_id, "gpu_id": gpu_id, "action": action},
            )
            self._action_counter.labels(**labels).inc()
            self._mark_success()
        except Exception as e:
            self._record_observe_error("tcd_action_total", e)

    def slo_violation_by_model(self, key: str, model_id: str, gpu_id: str) -> None:
        """
        Record an SLO violation for a specific model/GPU and key.

        `key` can be:
            - "latency_p95"
            - "error_rate"
            - "risk_budget"
            - "fdr_violation"
            - "alpha_budget_overshoot"
            - ...
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        if self._slo_violation_counter is None:
            return

        try:
            labels = self._metric_labels(
                "tcd_slo_violation_total",
                {"key": key, "model_id": model_id, "gpu_id": gpu_id},
            )
            self._slo_violation_counter.labels(**labels).inc()
            self._mark_success()
        except Exception as e:
            self._record_observe_error("tcd_slo_violation_total", e)

    def slo_violation(self, key: str) -> None:
        """
        Record a global SLO violation (model_id / gpu_id left empty).

        Useful when SLOs are checked at a higher aggregation level.
        """
        self.slo_violation_by_model(key=key, model_id="", gpu_id="")

    # -----------------------------------------------------------------------
    # Additional helpers for threat / control plane (optional to use)
    # -----------------------------------------------------------------------

    def record_fail_open(self, *, reason: str = "", policy: str = "") -> None:
        """
        Record a fail-open event.
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        if self._fail_open_counter is None:
            return

        try:
            labels = self._metric_labels(
                "tcd_fail_open_total",
                {"reason": reason or "unspecified", "policy": policy},
            )
            self._fail_open_counter.labels(**labels).inc()
            self._mark_success()
        except Exception as e:
            self._record_observe_error("tcd_fail_open_total", e)

    def record_fail_closed(self, *, reason: str = "", policy: str = "") -> None:
        """
        Record a fail-closed event.
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        if self._fail_closed_counter is None:
            return

        try:
            labels = self._metric_labels(
                "tcd_fail_closed_total",
                {"reason": reason or "unspecified", "policy": policy},
            )
            self._fail_closed_counter.labels(**labels).inc()
            self._mark_success()
        except Exception as e:
            self._record_observe_error("tcd_fail_closed_total", e)

    def record_detector_fallback(
        self,
        *,
        stage: str,
        reason: str = "",
        policy: str = "",
    ) -> None:
        """
        Record a detector / calibrator fallback event.

        `stage` might be:
            - "pre_filter"
            - "post_model"
            - "calibrator"
            - "conformal"
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        if self._detector_fallback_counter is None:
            return

        try:
            labels = self._metric_labels(
                "tcd_detector_fallback_total",
                {"stage": stage, "reason": reason or "unspecified", "policy": policy},
            )
            self._detector_fallback_counter.labels(**labels).inc()
            self._mark_success()
        except Exception as e:
            self._record_observe_error("tcd_detector_fallback_total", e)

    def record_safety_event(
        self,
        *,
        event_type: str,
        stage: str,
        severity: str = "low",
        policy: str = "",
        scenario_id: str = "",
        traffic_class: str = "prod",
    ) -> None:
        """
        Explicitly record a categorized safety event.

        Examples:
            event_type = "prompt_injection"
            stage      = "pre_filter"
            severity   = "high"
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        if self._safety_event_counter is None:
            return

        try:
            labels = self._metric_labels(
                "tcd_safety_event_total",
                {
                    "event_type": event_type,
                    "stage": stage,
                    "severity": severity,
                    "policy": policy,
                    "scenario_id": scenario_id,
                    "traffic_class": traffic_class,
                },
            )
            self._safety_event_counter.labels(**labels).inc()
            self._mark_success()
        except Exception as e:
            self._record_observe_error("tcd_safety_event_total", e)

    def record_adversarial_pattern(
        self,
        *,
        pattern_type: str,
        tenant: str = "",
        policy: str = "",
    ) -> None:
        """
        Record an adversarial pattern detection (e.g., probing, exfil attempt).
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        if self._adversarial_pattern_counter is None:
            return

        try:
            labels = self._metric_labels(
                "tcd_adversarial_pattern_total",
                {"pattern_type": pattern_type, "tenant": tenant, "policy": policy},
            )
            self._adversarial_pattern_counter.labels(**labels).inc()
            self._mark_success()
        except Exception as e:
            self._record_observe_error("tcd_adversarial_pattern_total", e)

    def update_alpha_budget(
        self,
        *,
        tenant: str,
        policy: str,
        initial: Optional[float] = None,
        used: Optional[float] = None,
        fdr_estimate: Optional[float] = None,
        reset_reason: Optional[str] = None,
    ) -> None:
        """
        Update alpha-budget / FDR-related metrics.

        - initial:      if provided, sets tcd_alpha_budget_initial.
        - used:         if provided, sets tcd_alpha_budget_used.
        - fdr_estimate: if provided, sets tcd_fdr_estimate.
        - reset_reason: if provided, increments tcd_alpha_budget_reset_total
                        with the given reason.
        """
        if not self._metrics_enabled():
            return
        self._init_metrics_if_needed()

        if initial is not None and self._alpha_initial_gauge is not None:
            try:
                labels = self._metric_labels(
                    "tcd_alpha_budget_initial",
                    {"tenant": tenant, "policy": policy},
                )
                self._alpha_initial_gauge.labels(**labels).set(float(initial))
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_alpha_budget_initial", e)

        if used is not None and self._alpha_used_gauge is not None:
            try:
                labels = self._metric_labels(
                    "tcd_alpha_budget_used",
                    {"tenant": tenant, "policy": policy},
                )
                self._alpha_used_gauge.labels(**labels).set(float(used))
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_alpha_budget_used", e)

        if fdr_estimate is not None and self._fdr_estimate_gauge is not None:
            try:
                labels = self._metric_labels(
                    "tcd_fdr_estimate",
                    {"tenant": tenant, "policy": policy},
                )
                self._fdr_estimate_gauge.labels(**labels).set(float(fdr_estimate))
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_fdr_estimate", e)

        if reset_reason is not None and self._alpha_reset_counter is not None:
            try:
                labels = self._metric_labels(
                    "tcd_alpha_budget_reset_total",
                    {"tenant": tenant, "policy": policy, "reason": reset_reason},
                )
                self._alpha_reset_counter.labels(**labels).inc()
                self._mark_success()
            except Exception as e:
                self._record_observe_error("tcd_alpha_budget_reset_total", e)