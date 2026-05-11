"""Pipeline, alerts, stats, and feeder endpoint tests.

Author: Christopher Shaiman
License: Apache 2.0
"""


def test_pipeline_status(client, auth_headers):
    """Pipeline status returns analyses list."""
    r = client.get("/api/pipeline/status", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "analyses" in data or "running" in data


def test_alerts(client, auth_headers):
    """Alerts endpoint returns operational health data."""
    r = client.get("/api/alerts", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "paused" in data
    assert "disk" in data


def test_stats(client, auth_headers):
    """Stats endpoint returns aggregate counts."""
    r = client.get("/api/stats", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "total_analyses" in data
    assert "total_samples" in data
    assert "total_iocs" in data
    assert "total_techniques" in data
    assert "families_detected" in data
    assert "cost_today" in data
    assert isinstance(data["total_analyses"], int)
    assert isinstance(data["cost_today"], float)


def test_feeder_status(client, auth_headers):
    """Feeder status returns state data."""
    r = client.get("/api/feeder/status", headers=auth_headers)
    assert r.status_code == 200
    data = r.json()
    assert "paused" in data


def test_feeder_pause_resume(client, auth_headers):
    """Feeder pause and resume work."""
    # Pause
    r = client.post("/api/feeder/pause", headers=auth_headers)
    assert r.status_code == 200

    # Verify paused
    r = client.get("/api/feeder/status", headers=auth_headers)
    assert r.json().get("paused") is True

    # Resume
    r = client.post("/api/feeder/resume", headers=auth_headers)
    assert r.status_code == 200

    # Verify resumed
    r = client.get("/api/feeder/status", headers=auth_headers)
    assert r.json().get("paused") is False


def test_feeder_reset(client, auth_headers):
    """Feeder reset clears failure counter."""
    r = client.post("/api/feeder/reset", headers=auth_headers)
    assert r.status_code == 200
