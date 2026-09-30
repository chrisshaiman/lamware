# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""GET /api/analyses/{id}/flow: same auth as the detail route, derived graph out (#653).

Behavioural: requests go through FastAPI's TestClient against the real app.
Only the database session is replaced (there is no PostgreSQL in this job);
authentication is left real for the 401 test and overridden for the rest.
"""
import json
from pathlib import Path

import pytest
from app.auth import AuthContext, require_auth
from app.database import get_session
from app.main import app
from app.models import Analysis
from app.routers.analyses import router as analyses_router
from fastapi.testclient import TestClient

FIXTURE = Path(__file__).parent / "fixtures" / "flow" / "rednat_d22c96565d26.json"


class _Session:
    def __init__(self, analysis: Analysis | None):
        self._analysis = analysis

    def get(self, model, pk):
        return self._analysis if self._analysis is not None and pk == self._analysis.id else None


def _client(analysis: Analysis | None, authed: bool = True) -> TestClient:
    app.dependency_overrides[get_session] = lambda: _Session(analysis)
    if authed:
        app.dependency_overrides[require_auth] = lambda: AuthContext(
            user_id="t", email="t@example.invalid", name="t", roles=["viewer"])
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides():
    yield
    app.dependency_overrides.clear()


def _analysis(report: dict | None) -> Analysis:
    return Analysis(id=42, sample_id=1, task_id="rednat_d22c96565d26", report_json=report)


def _route(path: str):
    return next(r for r in analyses_router.routes if getattr(r, "path", None) == path
                and "GET" in getattr(r, "methods", set()))


def test_flow_requires_the_same_auth_as_the_detail_route():
    """Compared on FastAPI's resolved dependency tree, not the source text."""
    def auth_calls(path):
        return [d.call for d in _route(path).dependant.dependencies]
    detail = auth_calls("/api/analyses/{analysis_id}")
    flow = auth_calls("/api/analyses/{analysis_id}/flow")
    assert require_auth in detail
    assert flow == detail


def test_flow_without_a_token_is_401():
    client = _client(_analysis({}), authed=False)
    assert client.get("/api/analyses/42/flow").status_code == 401


def test_flow_returns_the_derived_graph_and_not_the_report():
    report = json.loads(FIXTURE.read_text(encoding="utf-8"))
    marker = "SECRET_DECOMPILED_BODY_7f3a"
    report["ghidra"]["analyzed_files"][1]["decompiled_functions"] = [{"code": marker}]
    resp = _client(_analysis(report)).get("/api/analyses/42/flow")
    assert resp.status_code == 200
    body = resp.json()
    assert body["has_report"] is True
    assert set(body) == {"analysis_id", "has_report", "nodes", "edges"}
    assert marker not in resp.text
    e = next(e for e in body["edges"] if e["id"] == "sample-ghidra")
    assert e["status"] == "failed" and "Import failed" in e["reason"]


def test_an_analysis_without_a_report_is_absent_not_empty():
    body = _client(_analysis(None)).get("/api/analyses/42/flow").json()
    assert body["has_report"] is False
    assert {e["status"] for e in body["edges"]} == {"absent"}


def test_unknown_analysis_is_404():
    assert _client(None).get("/api/analyses/7/flow").status_code == 404
