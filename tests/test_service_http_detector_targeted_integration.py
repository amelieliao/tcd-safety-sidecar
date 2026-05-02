from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional

from fastapi.testclient import TestClient

from tcd.service_http import ServiceHttpConfig, create_app, create_http_runtime


class _FakeSettings:
    alpha = 0.05
    prometheus_port = 0
    prom_http_enable = False
    otel_enable = False
    gpu_enable = False

    token_cost_divisor_default = 1_000_000.0
    http_rate_capacity = 1_000_000.0
    http_rate_refill_per_s = 1_000_000.0

    config_version = "test"
    slo_latency_ms = 0.0

    def config_hash(self) -> str:
        return "test-settings-config-hash"


class _FakeSettingsProvider:
    def get(self) -> _FakeSettings:
        return _FakeSettings()


class _NoopPromExporter:
    def __getattr__(self, name: str):
        def _noop(*args: Any, **kwargs: Any) -> None:
            return None

        return _noop


class _NoopOtelExporter:
    enabled = False

    def push_metrics(self, *args: Any, **kwargs: Any) -> None:
        return None


class _AllowStrategyRouter:
    def decide(self, **kwargs: Any) -> Dict[str, Any]:
        return {
            "schema": "test.route.v1",
            "required_action": "allow",
            "action_hint": "allow",
            "enforcement_mode": "advisory",
            "decision_id": "test-route-decision",
            "route_plan_id": "test-route-plan",
            "primary_reason_code": "DEFAULT_ALLOW",
            "reason_codes": ["DEFAULT_ALLOW"],
        }


class _DetectorBlockRuntime:
    def detect(self, req: Any) -> Dict[str, Any]:
        return {
            "ok": False,
            "decision": "block",
            "action_hint": "BLOCK",
            "reason_code": "DETECTOR_ACTION_BLOCK",
            "score_raw": 1.0,
            "risk": 1.0,
            "p_value": 1e-12,
            "hard_block": True,
            "hard_block_reasons": ["targeted_detector_test"],
            "threat_tags": ["policy_bypass"],
            "engine_version": "test-detector",
            "config_hash": "test-detector-config",
            "policy_digest": "test-detector-policy",
            "state_digest": "test-detector-state",
            "decision_id": "test-detector-decision",
            "evidence_hash": "test-detector-evidence",
            "evidence": {
                "hard_block": True,
                "risk_label": "critical",
                "threat_tags": ["policy_bypass"],
            },
        }


@dataclass
class _FakeSecurityDecision:
    allowed: bool = False
    required_action: str = "block"
    action: str = "block"
    enforcement_mode: str = "must_enforce"
    primary_reason_code: str = "DETECTOR_ACTION_BLOCK"

    policy_ref: Optional[str] = "test-policy"
    policyset_ref: Optional[str] = "test-policyset"
    config_fingerprint: Optional[str] = "test-security-cfg"
    bundle_version: int = 1
    state_domain_id: Optional[str] = "test-state-domain"
    controller_mode: Optional[str] = "normal"
    guarantee_scope: Optional[str] = "strict_direct_p"

    decision_id: str = "test-security-decision"
    route_plan_id: str = "test-security-route-plan"
    audit_ref: Optional[str] = None
    receipt_ref: Optional[str] = None

    route: Mapping[str, Any] = field(
        default_factory=lambda: {
            "required_action": "block",
            "action_hint": "block",
            "enforcement_mode": "must_enforce",
            "decision_id": "test-security-decision",
            "route_plan_id": "test-security-route-plan",
            "primary_reason_code": "DETECTOR_ACTION_BLOCK",
            "reason_codes": ["DETECTOR_ACTION_BLOCK"],
        }
    )
    security: Mapping[str, Any] = field(
        default_factory=lambda: {
            "source": "fake_security_router",
            "reason_code": "DETECTOR_ACTION_BLOCK",
        }
    )
    evidence_identity: Mapping[str, Any] = field(default_factory=dict)
    artifacts: Mapping[str, Any] = field(default_factory=dict)
    receipt: Mapping[str, Any] = field(default_factory=dict)
    receipt_public: Mapping[str, Any] = field(default_factory=dict)
    receipt_verification: Optional[Mapping[str, Any]] = None
    receipt_private: Mapping[str, Any] = field(default_factory=dict)

    def to_public_view(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "required_action": self.required_action,
            "action": self.action,
            "enforcement_mode": self.enforcement_mode,
            "primary_reason_code": self.primary_reason_code,
            "decision_id": self.decision_id,
            "route_plan_id": self.route_plan_id,
        }


class _DetectorAwareFakeSecurityRouter:
    """
    This fake router intentionally reads the detector signal through the
    service_http detector_adapter. It blocks only when the bound detector payload
    says action=block and reason=DETECTOR_ACTION_BLOCK.
    """

    def __init__(self, detector_adapter: Any) -> None:
        self.detector_adapter = detector_adapter
        self.seen_payload: Dict[str, Any] = {}

    def route(self, security_context: Any) -> _FakeSecurityDecision:
        payload = dict(self.detector_adapter.evaluate(security_context, None))
        self.seen_payload = payload

        assert payload.get("action") == "block"
        assert payload.get("reason") == "DETECTOR_ACTION_BLOCK"
        assert payload.get("trigger") is True

        return _FakeSecurityDecision()


def _test_cfg() -> ServiceHttpConfig:
    return ServiceHttpConfig(
        strict_mode=False,
        enable_docs=False,
        require_service_token=False,
        allow_no_auth_local=True,
        enable_authenticator=False,
        require_authenticator=False,
        allow_service_token_fallback=True,
        receipts_enable_default=False,
        require_receipts_on_fail=False,
        require_receipts_when_pq=False,
        require_attestor_when_receipt_required=False,
        require_finalized_receipt_surface_when_strict=False,
        edge_rps=1_000_000.0,
        edge_burst=1_000_000,
        subject_capacity=1_000_000.0,
        subject_refill_per_s=1_000_000.0,
        tokens_divisor_default=1_000_000.0,
        hash_alg="sha256",
    )


def _runtime():
    return create_http_runtime(
        cfg=_test_cfg(),
        settings_provider=_FakeSettingsProvider(),
        prom_exporter=_NoopPromExporter(),
        otel_exporter=_NoopOtelExporter(),
        strategy_router=_AllowStrategyRouter(),
        trust_runtime={},
        attestor=None,
        authenticator=None,
    )


def test_runtime_diagnostics_detector_count_zero_is_inventory_only() -> None:
    rt = _runtime()
    app = create_app(runtime=rt)
    client = TestClient(app)

    resp = client.get("/runtime/diagnostics")
    assert resp.status_code == 200, resp.text

    body = resp.json()

    assert body["detector_count"] == 0
    assert "detector_block" not in body
    assert "DETECTOR_ACTION_BLOCK" not in body


def test_detector_action_block_is_reason_code_driven_not_count_driven(monkeypatch) -> None:
    rt = _runtime()

    # Keep detector inventory empty while still returning a targeted detector runtime.
    monkeypatch.setattr(
        rt.detector_registry,
        "get_detector_runtime",
        lambda key: _DetectorBlockRuntime(),
    )

    fake_security_router = _DetectorAwareFakeSecurityRouter(rt.detector_adapter)
    rt.security_router = fake_security_router

    assert rt.diagnostics()["detector_count"] == 0

    app = create_app(runtime=rt)
    client = TestClient(app)

    resp = client.post(
        "/diagnose",
        json={
            "tenant": "tenant-test",
            "user": "user-test",
            "session": "session-test",
            "model_id": "model-test",
            "gpu_id": "gpu-test",
            "task": "chat",
            "lang": "en",
            "trace_vector": [0.1, 0.2, 0.3],
            "spectrum": [],
            "features": [],
            "tokens_delta": 1,
            "context": {
                "detector_text": "targeted detector integration test input",
            },
        },
    )

    assert resp.status_code == 200, resp.text

    body = resp.json()

    assert rt.diagnostics()["detector_count"] == 0

    assert fake_security_router.seen_payload["action"] == "block"
    assert fake_security_router.seen_payload["reason"] == "DETECTOR_ACTION_BLOCK"

    assert body["decision"] == "block"
    assert body["required_action"] == "block"
    assert body["action"] == "block"
    assert body["allowed"] is False
    assert body["verdict"] is True
    assert body["cause"] == "DETECTOR_ACTION_BLOCK"

    assert body["components"]["terminal"]["decision"] == "block"
    assert body["components"]["terminal"]["required_action"] == "block"
    assert body["components"]["security_router"]["primary_reason_code"] == "DETECTOR_ACTION_BLOCK"
