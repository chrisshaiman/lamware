"""IOC, technique, and family browser endpoint tests.

Author: Christopher Shaiman
License: Apache 2.0
"""


def test_list_iocs(client, auth_headers):
    """IOC browser returns paginated results."""
    r = client.get("/api/iocs", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "iocs" in data
    assert isinstance(data["iocs"], list)
    if data["iocs"]:
        ioc = data["iocs"][0]
        assert "type" in ioc
        assert "value" in ioc
        assert "analysis_count" in ioc


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
    assert "techniques" in data
    assert isinstance(data["techniques"], list)
    if data["techniques"]:
        t = data["techniques"][0]
        assert "technique_id" in t
        assert "technique_name" in t
        assert "tactics" in t
        assert "analysis_count" in t


def test_list_families(client, auth_headers):
    """Family browser returns families with counts."""
    r = client.get("/api/families", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "families" in data
    assert isinstance(data["families"], list)
    if data["families"]:
        f = data["families"][0]
        assert "family" in f
        assert "count" in f
        assert "last_seen" in f
