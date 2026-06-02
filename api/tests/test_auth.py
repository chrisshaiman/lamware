"""Authentication tests — JWT only (API key removed).

Author: Christopher Shaiman
License: Apache 2.0
"""


def test_no_auth_returns_401(client):
    """Requests without auth should return 401."""
    r = client.get("/api/analyses")
    assert r.status_code == 401


def test_api_key_no_longer_accepted(client):
    """X-API-Key header should no longer authenticate."""
    r = client.get("/api/analyses", headers={"X-API-Key": "any-key-here"})
    assert r.status_code == 401


def test_invalid_bearer_returns_401(client):
    """Invalid Bearer token should return 401."""
    r = client.get("/api/analyses", headers={"Authorization": "Bearer invalid-token"})
    assert r.status_code == 401


def test_valid_jwt_accepted(client, jwt_headers):
    """Valid JWT should return 200."""
    r = client.get("/api/analyses", headers=jwt_headers)
    assert r.status_code == 200


def test_health_no_auth_required(client):
    """Health endpoint should be public."""
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
