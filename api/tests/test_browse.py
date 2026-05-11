"""IOC, technique, and family browser endpoint tests.

Author: Christopher Shaiman
License: Apache 2.0
"""


def test_list_iocs(client, auth_headers):
    """IOC browser returns results."""
    r = client.get("/api/iocs", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    # May be wrapped in {"iocs": [...]} or a bare list
    iocs = data.get("iocs", data) if isinstance(data, dict) else data
    assert isinstance(iocs, list)
    if iocs:
        ioc = iocs[0]
        assert "type" in ioc or "value" in ioc


def test_iocs_search(client, auth_headers):
    """IOC search parameter works."""
    r = client.get("/api/iocs?q=192.168", headers=auth_headers)
    assert r.status_code == 200


def test_iocs_type_filter(client, auth_headers):
    """IOC type filter works."""
    r = client.get("/api/iocs?type=domain-name", headers=auth_headers)
    assert r.status_code == 200


def test_list_techniques(client, auth_headers):
    """Technique browser returns results with frequency."""
    r = client.get("/api/techniques", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    techniques = data.get("techniques", data) if isinstance(data, dict) else data
    assert isinstance(techniques, list)
    if techniques:
        t = techniques[0]
        assert "technique_id" in t or "id" in t
        assert "analysis_count" in t


def test_list_families(client, auth_headers):
    """Family browser returns families with counts."""
    r = client.get("/api/families", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    families = data.get("families", data) if isinstance(data, dict) else data
    assert isinstance(families, list)
    if families:
        f = families[0]
        assert "family" in f
        assert "count" in f
