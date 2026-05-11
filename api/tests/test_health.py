"""Health endpoint tests.

Author: Christopher Shaiman
License: Apache 2.0
"""


def test_health_returns_ok(client):
    """Health endpoint should return 200 without auth."""
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["service"] == "lamware-api"


def test_health_no_auth_required(client):
    """Health endpoint should not require API key."""
    r = client.get("/health")
    assert r.status_code == 200
