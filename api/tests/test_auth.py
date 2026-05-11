"""Authentication tests.

Author: Christopher Shaiman
License: Apache 2.0
"""


def test_analyses_requires_auth(client):
    """Protected endpoints should return 401 without API key."""
    r = client.get("/api/analyses")
    assert r.status_code == 401


def test_stats_requires_auth(client):
    """Stats endpoint should return 401 without API key."""
    r = client.get("/api/stats")
    assert r.status_code == 401


def test_iocs_requires_auth(client):
    """IOCs endpoint should return 401 without API key."""
    r = client.get("/api/iocs")
    assert r.status_code == 401


def test_invalid_key_rejected(client):
    """Invalid API key should return 401."""
    r = client.get("/api/analyses", headers={"X-API-Key": "wrong-key-12345"})
    assert r.status_code == 401


def test_valid_key_accepted(client, auth_headers):
    """Valid API key should return 200."""
    r = client.get("/api/analyses", headers=auth_headers)
    assert r.status_code == 200
