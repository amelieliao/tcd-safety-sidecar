# FILE: tcd/otel_exporter.py
from typing import Any, Dict, Optional

class TCDOtelExporter:
    """
    Minimal OTEL-like stub. Safe no-op when disabled, prints JSON lines when enabled.
    """
    def __init__(self, enabled: bool = False, service_name: str = "tcd-safety-sidecar", version: str = "0.3.0") -> None:
        self.enabled = enabled
        self.service_name = service_name
        self.version = version

    def push_metrics(self, value: float, name: str = "diagnose_count", attrs: Optional[Dict[str, Any]] = None) -> None:
        if not self.enabled:
            return
        rec = {
            "service": self.service_name,
            "version": self.version,
            "metric": name,
            "value": float(value),
            "attrs": attrs or {},
        }
        print(__import__("json").dumps(rec, ensure_ascii=False))

    def record_metric(self, name: str, value: float, labels: Optional[Dict[str, Any]] = None) -> None:
        self.push_metrics(value, name=name, attrs=labels)

    def push_event(self, name: str, attrs: Optional[Dict[str, Any]] = None) -> None:
        if not self.enabled:
            return
        self.push_metrics(1.0, name=name, attrs=attrs)

    def shutdown(self) -> None:
        return

__all__ = ["TCDOtelExporter"]
