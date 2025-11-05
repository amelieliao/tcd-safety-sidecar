# tcd/tests/test_contracts.py
from fastapi.testclient import TestClient
from tcd.service_http import create_app

app = create_app()
client = TestClient(app)

EXPECTED_KEYS = {
    "verdict","score","threshold","budget_remaining","components","cause",
    "action","step","e_value","alpha_alloc","alpha_spent",
    "receipt","receipt_body","receipt_sig","verify_key"
}

def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"

def test_readyz():
    r = client.get("/readyz")
    assert r.status_code in (200, 503)  # startup sets ready True

def test_diagnose_ok():
    r = client.post("/v1/diagnose", json={"input": "test"})
    assert r.status_code == 200
    body = r.json()
    assert EXPECTED_KEYS.issubset(body.keys())

def test_diagnose_bad_request():
    r = client.post("/v1/diagnose", json={})
    assert r.status_code in (400, 422)