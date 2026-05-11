"""OpenAPI documentation tests.

Author: Christopher Shaiman
License: Apache 2.0
"""


def test_swagger_ui(client):
    """Swagger UI loads without auth."""
    r = client.get("/docs")
    assert r.status_code == 200
    assert "swagger" in r.text.lower() or "openapi" in r.text.lower()


def test_openapi_schema(client):
    """OpenAPI JSON schema is valid and contains all routers."""
    r = client.get("/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    assert schema["info"]["title"] == "lamware API"
    paths = list(schema["paths"].keys())

    # Verify key endpoints are registered
    assert "/health" in paths
    assert "/api/analyses" in paths
    assert "/api/iocs" in paths
    assert "/api/techniques" in paths
    assert "/api/families" in paths
    assert "/api/pipeline/status" in paths
    assert "/api/alerts" in paths
    assert "/api/stats" in paths
    assert "/api/feeder/status" in paths
    assert "/api/samples/submit" in paths
