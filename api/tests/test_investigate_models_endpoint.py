# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""GET /api/investigate/models and a new session's model (ADR-038, PR 5).

Behavioural: requests go through FastAPI's TestClient against the real app. Only
authentication and the database session are replaced (no Keycloak or PostgreSQL in
this job). The panel used to hard-code its three models in the frontend; now it reads
this endpoint, which serves the operator's investigate_models, priced ones only.
"""
from types import SimpleNamespace

import pytest
from app.auth import AuthContext, require_auth
from app.config import settings
from app.database import get_session
from app.main import app
from fastapi.testclient import TestClient


class _Session:
    """Enough of a DB session for create_session: the analysis exists; add/commit work."""
    def __init__(self):
        self.added = []

    def exec(self, *a, **k):
        return SimpleNamespace(first=lambda: (1,))

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        pass

    def refresh(self, obj):
        obj.id = obj.id or 7


def _client(roles=("analyst",), db=None) -> TestClient:
    app.dependency_overrides[require_auth] = lambda: AuthContext(
        user_id="t", email="t@example.invalid", name="t", roles=list(roles))
    app.dependency_overrides[get_session] = lambda: db or _Session()
    return TestClient(app)


@pytest.fixture(autouse=True)
def _clear_overrides(monkeypatch):
    monkeypatch.setattr("app.routers.investigate.log_audit", lambda *a, **k: None)
    # LiteLLM's prices (pricing.py); there is no LiteLLM in this job. Patched on the
    # `pricing` the router holds, which import order across test files decides.
    from app.routers import investigate as router
    monkeypatch.setattr(router.pricing, "prices", lambda: {
        m: (1e-6, 5e-6) for m in ("claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5")})
    yield
    app.dependency_overrides.clear()


def test_the_endpoint_serves_the_operators_list_in_order(monkeypatch):
    monkeypatch.setattr(settings, "investigate_models", [
        SimpleNamespace(name="claude-haiku-4-5", label="Fast"),
        SimpleNamespace(name="claude-opus-4-6", label="Deep")])
    r = _client().get("/api/investigate/models")
    assert r.status_code == 200
    assert r.json() == {"models": [{"name": "claude-haiku-4-5", "label": "Fast"},
                                   {"name": "claude-opus-4-6", "label": "Deep"}]}


def test_an_unpriced_model_is_not_served(monkeypatch):
    monkeypatch.setattr(settings, "investigate_models", [
        SimpleNamespace(name="claude-sonnet-9", label="Future"),
        SimpleNamespace(name="claude-sonnet-4-6", label="Sonnet")])
    assert [m["name"] for m in _client().get("/api/investigate/models").json()["models"]] == ["claude-sonnet-4-6"]


def test_the_endpoint_needs_the_analyst_role():
    assert _client(roles=("viewer",)).get("/api/investigate/models").status_code == 403


def test_a_new_session_starts_on_the_first_listed_model(monkeypatch):
    monkeypatch.setattr(settings, "investigate_models", [
        SimpleNamespace(name="claude-haiku-4-5", label="Fast"),
        SimpleNamespace(name="claude-sonnet-4-6", label="Sonnet")])
    db = _Session()
    r = _client(db=db).post("/api/investigate/1/sessions")
    assert r.status_code == 201, r.text
    assert r.json()["model"] == "claude-haiku-4-5" and db.added[0].model == "claude-haiku-4-5"


def test_with_nothing_priced_no_session_is_created(monkeypatch):
    monkeypatch.setattr(settings, "investigate_models", [SimpleNamespace(name="claude-sonnet-9", label="X")])
    db = _Session()
    assert _client(db=db).post("/api/investigate/1/sessions").status_code == 503
    assert db.added == []
