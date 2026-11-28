# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""/api/evasions groups by MITRE technique, and pages the detail (2026-11-28).

The page grouped by (technique, mitre_id, evidence). Evidence is per-sample text, so
1,436 of its 1,447 rows had a count of 1 and the browser received ~718k characters
of evidence plus ~751k of recommendations. The LLM names one technique many ways, so
names do not group either; the MITRE ID does (1,467 of 1,473 entries, 73 groups).
"""
from types import SimpleNamespace

import pytest
from app.auth import AuthContext, require_auth
from app.database import get_session
from app.main import app
from app.routers.evasions import EXAMPLE_CHARS, aggregate
from fastapi.testclient import TestClient

ENTRIES = [
    # (analysis_id, technique, mitre_id, evidence)
    (3, "Language/Locale Geofencing via Registry", "T1614.001", "GetUserDefaultLangID == 0x419"),
    (2, "Geofencing via Locale/Language Check", "t1614.001 ", "checks locale " + "x" * 400),
    (2, "Language/Locale Geofencing", "T1614.001", "second entry, same sample"),
    (1, "Language/Locale Geofencing via Registry", "T1614.001", None),
    (1, "Anti-Debug via SetUnhandledExceptionFilter", "T1622", "SetUnhandledExceptionFilter"),
    (4, "Odd thing", "not-an-id", "free text"),
    (5, "Another odd thing", None, None),
]


def test_one_row_per_mitre_id_counting_distinct_samples():
    rows = {r["group"]: r for r in aggregate(ENTRIES)}
    geo = rows["T1614.001"]
    assert geo["sample_count"] == 3                 # analyses 1, 2, 3; 2 has two entries
    assert geo["name_variants"] == 3
    assert geo["technique"] == "Language/Locale Geofencing via Registry"   # most common name
    assert geo["mitre_id"] == "T1614.001"           # " t1614.001 " normalised into the same group
    assert rows["T1622"]["sample_count"] == 1


def test_entries_without_a_valid_id_group_by_category():
    unmapped = [r for r in aggregate(ENTRIES) if r["group"].startswith("unmapped:")]
    assert sum(r["sample_count"] for r in unmapped) == 2
    assert all(r["mitre_id"] is None and r["technique"].startswith("No MITRE ID") for r in unmapped)


def test_the_example_is_short_and_the_rows_are_few():
    rows = aggregate(ENTRIES)
    assert len(rows) <= 4
    assert all(r["evidence"] is None or len(r["evidence"]) <= EXAMPLE_CHARS + 1 for r in rows)
    assert rows[0]["group"] == "T1614.001"          # most samples first


class _Session:
    """Answers the router's three queries by their SQL text."""
    def __init__(self, entries, recs, total):
        self.entries, self.recs, self.total = entries, recs, total

    def exec(self, stmt):
        sql = str(stmt)
        if "jsonb_array_elements_text" in sql:
            return SimpleNamespace(all=lambda: self.recs)
        if "evasion_techniques" in sql and "a.id" in sql:
            return SimpleNamespace(all=lambda: self.entries)
        return SimpleNamespace(scalar=lambda: self.total)


@pytest.fixture
def client():
    recs = [(f"advice {i}", 100 - i) for i in range(60)]
    app.dependency_overrides[require_auth] = lambda: AuthContext(
        user_id="t", email="t@example.invalid", name="t", roles=["viewer"])
    app.dependency_overrides[get_session] = lambda: _Session(ENTRIES, recs, 5)
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_the_page_gets_groups_and_only_the_top_recommendations(client):
    body = client.get("/api/evasions").json()
    assert body["total_analyses_with_evasion"] == 5
    assert [t["group"] for t in body["techniques"]][0] == "T1614.001"
    assert len(body["recommendations"]) == 25 and body["recommendations_total"] == 60
    assert body["recommendations"][0] == {"recommendation": "advice 0", "frequency": 100}


def test_a_groups_evidence_is_paged_newest_first(client):
    page = client.get("/api/evasions/evidence", params={"group": "T1614.001", "limit": 2}).json()
    assert page["total"] == 4 and len(page["items"]) == 2
    assert [i["analysis_id"] for i in page["items"]] == [3, 2]
    nxt = client.get("/api/evasions/evidence", params={"group": "T1614.001", "offset": 2, "limit": 2}).json()
    assert [i["analysis_id"] for i in nxt["items"]] == [2, 1]


def test_recommendations_are_paged_and_the_page_size_is_capped(client):
    page = client.get("/api/evasions/recommendations", params={"offset": 25, "limit": 20}).json()
    assert page["total"] == 60 and page["offset"] == 25 and page["items"][0]["recommendation"] == "advice 25"
    capped = client.get("/api/evasions/recommendations", params={"limit": 500}).json()
    assert len(capped["items"]) == 50                   # MAX_PAGE
