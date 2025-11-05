# tcd/config.py
from __future__ import annotations

import os
import json
import hashlib
import threading
from typing import Any, Dict

try:
    import yaml  # optional
except Exception:  # pragma: no cover
    yaml = None

from pydantic import BaseModel


def _env_bool(name: str, default: bool) -> bool:
    v = os.environ.get(name, "")
    if v == "":
        return default
    v = v.strip().lower()
    return v in ("1", "true", "yes", "on")


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except Exception:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except Exception:
        return default


def _from_yaml(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path) or yaml is None:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        return dict(doc)
    except Exception:
        return {}


class Settings(BaseModel):
    debug: bool = True
    version: str = "dev"
    app_name: str = "TCD Safety Sidecar"
    author: str = "Amelie Liao"

    gpu_enable: bool = False
    receipts_enabled: bool = False

    prometheus_port: int = 8001
    prom_http_enable: bool = True

    otel_enable: bool = False
    otel_endpoint: str = ""

    alpha: float = 0.05
    slo_latency_ms: float = 200.0
    config_version: str = "v0.1"

    http_rate_capacity: float = 60.0
    http_rate_refill_per_s: float = 30.0

    token_cost_divisor_default: float = 50.0

    def config_hash(self) -> str:
        try:
            payload = self.model_dump(mode="json")
        except Exception:  # pydantic v1 fallback
            payload = self.dict()
        blob = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.blake2s(blob).hexdigest()


def _load_settings() -> Settings:
    base = Settings()

    ypath = os.environ.get("TCD_CONFIG_PATH", "").strip()
    ydoc = _from_yaml(ypath)

    merged: Dict[str, Any] = {}
    try:
        merged.update(base.model_dump())
    except Exception:
        merged.update(base.dict())

    if ydoc:
        merged.update({k: v for k, v in ydoc.items() if k in merged})

    merged["debug"] = _env_bool("TCD_DEBUG", merged["debug"])
    merged["version"] = os.environ.get("TCD_VERSION", merged["version"])
    merged["gpu_enable"] = _env_bool("TCD_GPU_ENABLE", merged["gpu_enable"])
    merged["receipts_enabled"] = _env_bool("TCD_RECEIPTS_ENABLE", merged["receipts_enabled"])

    merged["prometheus_port"] = _env_int("TCD_PROM_PORT", merged["prometheus_port"])
    merged["prom_http_enable"] = _env_bool("TCD_PROM_HTTP_ENABLE", merged["prom_http_enable"])

    merged["otel_enable"] = _env_bool("TCD_OTEL_ENABLE", merged["otel_enable"])
    merged["otel_endpoint"] = os.environ.get("TCD_OTEL_ENDPOINT", merged["otel_endpoint"])

    merged["alpha"] = _env_float("TCD_ALPHA", merged["alpha"])
    merged["slo_latency_ms"] = _env_float("TCD_SLO_MS", merged["slo_latency_ms"])
    merged["config_version"] = os.environ.get("TCD_CONFIG_VERSION", merged["config_version"])

    merged["http_rate_capacity"] = _env_float("TCD_HTTP_RATE_CAP", merged["http_rate_capacity"])
    merged["http_rate_refill_per_s"] = _env_float("TCD_HTTP_RATE_REFILL", merged["http_rate_refill_per_s"])

    merged["token_cost_divisor_default"] = _env_float(
        "TCD_TOKEN_COST_DIVISOR", merged["token_cost_divisor_default"]
    )

    return Settings(**merged)


class ReloadableSettings:
    def __init__(self, initial: Settings):
        self._lock = threading.RLock()
        self._settings = initial

    def get(self) -> Settings:
        with self._lock:
            return self._settings

    def refresh(self) -> Settings:
        with self._lock:
            self._settings = _load_settings()
            return self._settings

    def set(self, **overrides: Any) -> Settings:
        with self._lock:
            curr = self._settings
            try:
                data = curr.model_dump()
            except Exception:
                data = curr.dict()
            data.update(overrides)
            self._settings = Settings(**data)
            return self._settings


def make_reloadable_settings() -> ReloadableSettings:
    return ReloadableSettings(_load_settings())