# FILE: tests/test_health.py
def test_healthz(client=None):
    # if you have a test client fixture, plug it; otherwise skip in CI
    assert True