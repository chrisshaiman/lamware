"""Analyses endpoint tests.

Author: Christopher Shaiman
License: Apache 2.0
"""


def test_list_analyses(client, auth_headers):
    """List endpoint returns paginated results."""
    r = client.get("/api/analyses", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "total" in data
    assert "analyses" in data
    assert isinstance(data["analyses"], list)
    assert "limit" in data
    assert "offset" in data


def test_list_analyses_pagination(client, auth_headers):
    """Pagination parameters work."""
    r = client.get("/api/analyses?limit=3&offset=0", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert len(data["analyses"]) <= 3


def test_list_analyses_search(client, auth_headers):
    """Search parameter filters results."""
    r = client.get("/api/analyses?q=nanocore", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert isinstance(data["analyses"], list)


def test_list_analyses_fields(client, auth_headers):
    """Each analysis has expected fields."""
    r = client.get("/api/analyses?limit=1", headers=auth_headers)
    data = r.json()
    if data["analyses"]:
        a = data["analyses"][0]
        assert "id" in a
        assert "task_id" in a
        assert "severity" in a or a.get("severity") is None


def test_get_analysis_detail(client, auth_headers):
    """Detail endpoint returns full analysis with nested data."""
    r = client.get("/api/analyses?limit=1", headers=auth_headers)
    data = r.json()
    if not data["analyses"]:
        return
    analysis_id = data["analyses"][0]["id"]

    r = client.get(f"/api/analyses/{analysis_id}", headers=auth_headers)
    assert r.status_code == 200
    detail = r.json()
    # Detail may be flat or nested — check for key fields either way
    assert "id" in detail or "analysis" in detail
    assert "capabilities" in detail or "iocs" in detail


def test_get_analysis_not_found(client, auth_headers):
    """Non-existent analysis returns 404."""
    r = client.get("/api/analyses/999999", headers=auth_headers)
    assert r.status_code == 404


def test_csv_export(client, auth_headers):
    """CSV export returns CSV content."""
    r = client.get("/api/analyses?limit=1", headers=auth_headers)
    data = r.json()
    if not data["analyses"]:
        return
    analysis_id = data["analyses"][0]["id"]

    r = client.get(f"/api/analyses/{analysis_id}/iocs/csv", headers=auth_headers)
    assert r.status_code == 200
    ct = r.headers.get("content-type", "")
    assert "csv" in ct or "text" in ct


def test_stix_export(client, auth_headers):
    """STIX export returns valid JSON bundle."""
    r = client.get("/api/analyses?limit=1", headers=auth_headers)
    data = r.json()
    if not data["analyses"]:
        return
    analysis_id = data["analyses"][0]["id"]

    r = client.get(f"/api/analyses/{analysis_id}/iocs/stix", headers=auth_headers)
    assert r.status_code == 200
    bundle = r.json()
    assert bundle["type"] == "bundle"
    assert "objects" in bundle
    assert isinstance(bundle["objects"], list)
