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


# ── Technique-to-analyses correlation tests ──────────────────────────


def test_technique_analyses_happy_path(client, jwt_headers):
    """GET /api/techniques/{id}/analyses returns a list with expected fields."""
    # Grab a technique id from the list endpoint
    r = client.get("/api/techniques?limit=1", headers=jwt_headers)
    assert r.status_code == 200
    techniques = r.json()
    if not techniques:
        return  # No seed data — nothing to test

    tech_id = techniques[0]["id"]
    r = client.get(f"/api/techniques/{tech_id}/analyses", headers=jwt_headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data, list)

    if data:
        entry = data[0]
        expected_fields = {"analysis_id", "sha256", "family", "submitted_at",
                           "source_stage"}
        assert expected_fields.issubset(entry.keys()), (
            f"Missing fields: {expected_fields - entry.keys()}"
        )


def test_technique_analyses_not_found(client, jwt_headers):
    """Non-existent technique returns 404."""
    r = client.get("/api/techniques/999999999/analyses", headers=jwt_headers)
    assert r.status_code == 404


# ── Family filter tests ─────────────────────────────────────────────


def test_iocs_family_filter(client, jwt_headers):
    """GET /api/iocs?family=... returns 200 and a list."""
    resp = client.get("/api/iocs", params={"family": "Emotet"}, headers=jwt_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_techniques_family_filter(client, jwt_headers):
    """GET /api/techniques?family=... returns 200 and a list."""
    resp = client.get("/api/techniques", params={"family": "Emotet"}, headers=jwt_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


# ── IOC cluster (campaign detection) tests ─────────────────────────


def test_ioc_clusters_returns_list(client, jwt_headers):
    resp = client.get("/api/iocs/clusters", headers=jwt_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    for cluster in data:
        assert "cluster_id" in cluster
        assert "analyses" in cluster
        assert "shared_iocs" in cluster
        assert "shared_techniques" in cluster


def test_ioc_clusters_high_thresholds_empty(client, jwt_headers):
    resp = client.get(
        "/api/iocs/clusters",
        params={"min_shared_iocs": 100, "min_analyses": 100},
        headers=jwt_headers,
    )
    assert resp.status_code == 200
    assert resp.json() == []


# ── Analysis detail overlap data tests ─────────────────────────────


def test_analysis_detail_includes_overlap(client, jwt_headers):
    """GET /api/analyses/{id} response includes overlap fields."""
    import pytest

    analyses_resp = client.get("/api/analyses", params={"limit": 1}, headers=jwt_headers)
    assert analyses_resp.status_code == 200
    body = analyses_resp.json()
    analyses = body.get("analyses", body) if isinstance(body, dict) else body
    if not analyses:
        pytest.skip("No analysis data")
    analysis_id = analyses[0]["id"]
    resp = client.get(f"/api/analyses/{analysis_id}", headers=jwt_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "overlapping_iocs" in data
    assert "overlapping_techniques" in data
    assert isinstance(data["overlapping_iocs"], list)
    assert isinstance(data["overlapping_techniques"], list)
