# FILE: tcd/otel_exporter.py
from typing import Any, Dict, Optional

class TCDOtelExporter:
    def __init__(self, enabled: bool = False, service_name: str = "tcd-safety-sidecar", version: str = "0.3.0") -> None:
        self.enabled = enabled
        self.service_name = service_name
        self.version = version

    def push_metrics(self, name: str = "diagnose_count", value: float = 1.0, attrs: Optional[Dict[str, Any]] = None) -> None:
        return

    def record_metric(self, name: str, value: float, labels: Optional[Dict[str, Any]] = None) -> None:
        self.push_metrics(name=name, value=value, attrs=labels)

    def push_event(self, name: str, attrs: Optional[Dict[str, Any]] = None) -> None:
        return

    def shutdown(self) -> None:
        return

__all__ = ["TCDOtelExporter"]