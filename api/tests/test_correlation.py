# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""IOC-to-analyses correlation endpoint tests.

Author: Christopher Shaiman
License: Apache 2.0
"""


def test_ioc_analyses_returns_list(client, jwt_headers):
    """GET /api/iocs/{id}/analyses returns a list of related analyses."""
    # First, grab an IOC id from the list endpoint
    r = client.get("/api/iocs?limit=1", headers=jwt_headers)
    assert r.status_code == 200
    iocs = r.json()
    if not iocs:
        return  # No seed data — nothing to test

    ioc_id = iocs[0]["id"]
    r = client.get(f"/api/iocs/{ioc_id}/analyses", headers=jwt_headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)


def test_ioc_analyses_fields(client, jwt_headers):
    """Each result has the expected fields."""
    r = client.get("/api/iocs?limit=1", headers=jwt_headers)
    assert r.status_code == 200
    iocs = r.json()
    if not iocs:
        return

    ioc_id = iocs[0]["id"]
    r = client.get(f"/api/iocs/{ioc_id}/analyses", headers=jwt_headers)
    assert r.status_code == 200
    data = r.json()
    if not data:
        return  # IOC exists but no linked analyses

    entry = data[0]
    expected_fields = {"analysis_id", "sha256", "family", "submitted_at",
                       "source_stage", "confidence"}
    assert expected_fields.issubset(entry.keys()), (
        f"Missing fields: {expected_fields - entry.keys()}"
    )


def test_ioc_analyses_not_found(client, jwt_headers):
    """Non-existent IOC returns 404."""
    r = client.get("/api/iocs/999999999/analyses", headers=jwt_headers)
    assert r.status_code == 404


def test_ioc_analyses_no_auth(client):
    """Unauthenticated request returns 401."""
    r = client.get("/api/iocs/1/analyses")
    assert r.status_code == 401
