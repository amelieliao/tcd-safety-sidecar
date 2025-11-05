# FILE: tcd/exporter.py
import threading

class TCDPrometheusExporter:
    def __init__(self, port: int, version: str, config_hash: str):
        self.port = port
        self.version = version
        self.config_hash_value = config_hash
        self._lock = threading.Lock()

    def ensure_server(self):
        return True

    def observe_latency(self, s: float):
        pass

    def push(self, verdict_pack, labels=None):
        pass

    def push_eprocess(self, **kwargs):
        pass

    def update_budget_metrics(self, tenant, user, session, *, remaining: float, spent: bool):
        pass

    def record_action(self, model_id: str, gpu_id: str, action: str):
        pass

    def slo_violation_by_model(self, key: str, model_id: str, gpu_id: str):
        pass

    def slo_violation(self, key: str):
        pass
