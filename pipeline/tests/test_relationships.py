# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the cross-sample relationship writer.

Pure functions are tested with inline data (no DB). The compare function for
ssdeep is injected, so these tests don't need ppdeep installed.
"""
from lamware_pipeline.relationships import (
    normalize_edge,
    select_shared_ioc_edges,
    select_ssdeep_edges,
)


# --- normalize_edge ---

def test_normalize_edge_orders_min_parent_max_child():
    a = normalize_edge(5, 2, "shares_ja3", "ctx")
    b = normalize_edge(2, 5, "shares_ja3", "ctx")
    assert a == b
    assert a == {"parent_id": 2, "child_id": 5, "relationship": "shares_ja3", "context": "ctx"}


def test_normalize_edge_rejects_self():
    assert normalize_edge(7, 7, "ssdeep_similar", "x") is None


# --- select_shared_ioc_edges ---

def test_shared_ioc_edge_network_type():
    candidates = [{"other_sample_id": 9, "ioc_id": 1, "ioc_type": "ipv4-addr", "ioc_value": "203.0.113.7"}]
    edges = select_shared_ioc_edges(2, candidates, {1: 3}, max_freq=20)
    assert len(edges) == 1
    assert edges[0]["relationship"] == "shares_network_ioc"
    assert edges[0]["parent_id"] == 2 and edges[0]["child_id"] == 9
    assert "203.0.113.7" in edges[0]["context"]


def test_shared_ioc_edge_ja3_type_distinct_relationship():
    candidates = [{"other_sample_id": 9, "ioc_id": 1, "ioc_type": "ja3", "ioc_value": "abcd"}]
    edges = select_shared_ioc_edges(2, candidates, {1: 3}, max_freq=20)
    assert len(edges) == 1
    assert edges[0]["relationship"] == "shares_ja3"


def test_shared_ioc_peer_sharing_both_yields_two_edges():
    candidates = [
        {"other_sample_id": 9, "ioc_id": 1, "ioc_type": "ipv4-addr", "ioc_value": "203.0.113.7"},
        {"other_sample_id": 9, "ioc_id": 2, "ioc_type": "ja3", "ioc_value": "abcd"},
    ]
    edges = select_shared_ioc_edges(2, candidates, {1: 3, 2: 3}, max_freq=20)
    rels = sorted(e["relationship"] for e in edges)
    assert rels == ["shares_ja3", "shares_network_ioc"]


def test_shared_ioc_drops_over_frequency_cap():
    candidates = [{"other_sample_id": 9, "ioc_id": 1, "ioc_type": "ipv4-addr", "ioc_value": "8.8.8.8"}]
    edges = select_shared_ioc_edges(2, candidates, {1: 99}, max_freq=20)
    assert edges == []


def test_shared_ioc_context_summarizes_multiple_values():
    candidates = [
        {"other_sample_id": 9, "ioc_id": 1, "ioc_type": "domain-name", "ioc_value": "a.evil.com"},
        {"other_sample_id": 9, "ioc_id": 2, "ioc_type": "domain-name", "ioc_value": "b.evil.com"},
    ]
    edges = select_shared_ioc_edges(2, candidates, {1: 2, 2: 2}, max_freq=20)
    assert len(edges) == 1
    assert edges[0]["context"].startswith("2 shared")


# --- select_ssdeep_edges ---

def _fake_compare(a, b):
    # deterministic stub: equal hashes -> 100, else 50
    return 100 if a == b else 50


def test_ssdeep_edge_fires_at_or_above_threshold():
    others = [(9, "HASH")]
    edges = select_ssdeep_edges(2, "HASH", others, threshold=80, compare_fn=_fake_compare)
    assert len(edges) == 1
    assert edges[0]["relationship"] == "ssdeep_similar"
    assert "score=100" in edges[0]["context"]


def test_ssdeep_edge_skipped_below_threshold():
    edges = select_ssdeep_edges(2, "HASH", [(9, "OTHER")], threshold=80, compare_fn=_fake_compare)
    assert edges == []


def test_ssdeep_skips_empty_and_self():
    others = [(2, "HASH"), (9, ""), (10, None)]
    edges = select_ssdeep_edges(2, "HASH", others, threshold=80, compare_fn=_fake_compare)
    assert edges == []


def test_ssdeep_no_hash_returns_empty():
    assert select_ssdeep_edges(2, "", [(9, "HASH")], threshold=80, compare_fn=_fake_compare) == []


def test_ssdeep_compare_error_skips_pair_not_crash():
    def boom(a, b):
        raise ValueError("malformed hash")
    edges = select_ssdeep_edges(2, "HASH", [(9, "OTHER")], threshold=80, compare_fn=boom)
    assert edges == []


def test_shared_ioc_skips_disallowed_type():
    candidates = [{"other_sample_id": 9, "ioc_id": 1, "ioc_type": "file:name", "ioc_value": "evil.dll"}]
    edges = select_shared_ioc_edges(2, candidates, {1: 1}, max_freq=20)
    assert edges == []


def test_ssdeep_edge_fires_at_exact_threshold():
    edges = select_ssdeep_edges(2, "HASH", [(9, "X")], threshold=80, compare_fn=lambda a, b: 80)
    assert len(edges) == 1


def test_ssdeep_edge_skipped_just_below_threshold():
    edges = select_ssdeep_edges(2, "HASH", [(9, "X")], threshold=80, compare_fn=lambda a, b: 79)
    assert edges == []


def test_upsert_sql_is_idempotent_on_conflict():
    from lamware_pipeline.relationships import _UPSERT_SQL
    sql = _UPSERT_SQL.upper()
    assert "INSERT INTO SAMPLE_RELATIONSHIPS" in sql
    assert "ON CONFLICT" in sql and "DO NOTHING" in sql


def test_upsert_edges_empty_is_noop():
    from lamware_pipeline.relationships import upsert_edges
    # No edges -> returns 0 without touching the connection.
    assert upsert_edges(conn=None, edges=[]) == 0


import lamware_pipeline.relationships as rel


class _FakeCursor:
    def __init__(self, rows):
        self._rows = rows
    def __enter__(self):
        return self
    def __exit__(self, *a):
        return False
    def execute(self, *a, **k):
        pass
    def fetchall(self):
        return self._rows


class _FakeConn:
    def __init__(self, rows=None):
        self._rows = rows or []
        self.rolled_back = False
        self.committed = False
    def cursor(self):
        return _FakeCursor(self._rows)
    def rollback(self):
        self.rolled_back = True
    def commit(self):
        self.committed = True


def test_write_relationships_safe_swallows_errors(monkeypatch):
    def boom(conn, sample_id, config):
        raise RuntimeError("db exploded")
    monkeypatch.setattr(rel, "compute_and_write_edges", boom)
    conn = _FakeConn()
    # Must not raise; returns 0; rolls back the edge work so the conn stays usable.
    assert rel.write_relationships_safe(conn, 1, config=object()) == 0
    assert conn.rolled_back is True


def test_write_relationships_safe_returns_count(monkeypatch):
    monkeypatch.setattr(rel, "compute_and_write_edges", lambda conn, sid, config: 4)
    assert rel.write_relationships_safe(_FakeConn(), 1, config=object()) == 4


def test_backfill_all_runs_every_sample(monkeypatch):
    calls = []
    monkeypatch.setattr(rel, "compute_and_write_edges",
                        lambda conn, sid, config: calls.append(sid) or 2)
    conn = _FakeConn(rows=[(10,), (11,), (12,)])  # samples query result
    total = rel.backfill_all(conn, config=object())
    assert calls == [10, 11, 12]
    assert total == 6
