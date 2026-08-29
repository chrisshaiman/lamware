# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The PDF called fifty truncated connections "TCP Destinations (50)".

#479 changed `tcp_connections` from a truncated list of CONNECTIONS to a list of
DESTINATIONS carrying `attempts`, and updated the consumers to match — but
unconditionally, so every report written before the code landed is read under a
convention that did not produce it. Fifteen reports on the host are in that
state: the header claimed fifty destinations for two, `attempts` was absent so
every row lost its count, and `tcp_attempts_total` was absent so the one line
that would have contradicted the header never printed.

The tests below fix the LEGACY direction, not the current one. A renderer that
handles today's shape correctly is the easy half and was never broken; what
matters is that it stops making confident claims about data written under the
other convention. So each legacy case asserts on what must NOT appear.
"""
import importlib.util
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"


def _load_generate_report():
    """Import generate-report.py, whose dash means it needs a manual load."""
    stubbed = {}
    for name in ("markdown", "weasyprint"):
        if name not in sys.modules:
            stub = types.ModuleType(name)
            stub.markdown = lambda text, **kw: text
            stub.CSS = stub.HTML = lambda *a, **kw: None
            sys.modules[name] = stub
            stubbed[name] = True
    try:
        spec = importlib.util.spec_from_file_location(
            "_generate_report_tcp_shapes", FILES / "generate-report.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod
    finally:
        for name in stubbed:
            sys.modules.pop(name, None)


def _legacy_truncated():
    """What all fifteen post-DNS-fix reports actually contain: fifty rows at the
    old cap, two destinations, ephemeral source ports doing all the varying."""
    rows = []
    for i in range(50):
        port = 443 if i % 2 == 0 else 80
        rows.append({"dst": f"192.168.100.1:{port}",
                     "src": f"192.168.100.10:{49000 + i}"})
    return {"tcp_connections": rows}


def _legacy_complete():
    """Pre-#479 and under the cap, so the connection count is real."""
    return {"tcp_connections": [
        {"dst": "192.168.100.1:443", "src": "192.168.100.10:49001"},
        {"dst": "192.168.100.1:443", "src": "192.168.100.10:49002"},
        {"dst": "192.168.100.1:80", "src": "192.168.100.10:49003"},
    ]}


def _deduped():
    """Post-#479."""
    return {"tcp_connections": [{"dst": "192.168.100.1:443", "attempts": 121},
                                {"dst": "192.168.100.1:80", "attempts": 73}],
            "tcp_attempts_total": 194,
            "tcp_destinations_total": 2}


# --- shape detection ---


def test_shapes_are_told_apart():
    mod = _load_generate_report()
    assert mod.tcp_shape(_legacy_truncated()) == "truncated"
    assert mod.tcp_shape(_legacy_complete()) == "connections"
    assert mod.tcp_shape(_deduped()) == "destinations"
    assert mod.tcp_shape({}) == "none"
    assert mod.tcp_shape({"tcp_connections": []}) == "none"


def test_one_destination_contacted_once_is_still_the_new_shape():
    """`attempts: 1` is truthful but looks like a legacy row on its own, so the
    total is what settles it. Without this the smallest real post-#479 report
    would be rendered under the old convention."""
    mod = _load_generate_report()
    net = {"tcp_connections": [{"dst": "10.0.0.5:443", "attempts": 1}],
           "tcp_attempts_total": 1, "tcp_destinations_total": 1}
    assert mod.tcp_shape(net) == "destinations"


# --- the heading ---


def test_a_truncated_report_is_not_called_destinations():
    """THE bug. 50 is not the destination count, and it is not the connection
    count either — it is a cap, and the real total is gone."""
    mod = _load_generate_report()
    head = mod.tcp_heading(_legacy_truncated())
    assert "Destinations" not in head, head
    assert "truncated" in head, head
    assert "2 destinations" in head, head


def test_a_truncated_report_does_not_claim_an_attempt_total():
    """The count the old cap destroyed must not be implied by the row count."""
    mod = _load_generate_report()
    head = mod.tcp_heading(_legacy_truncated())
    assert "connection attempts" not in head, head
    assert "not recorded" in head, head


def test_a_complete_legacy_report_reports_connections_and_destinations():
    mod = _load_generate_report()
    head = mod.tcp_heading(_legacy_complete())
    assert "TCP Connections (3" in head, head
    assert "2 destinations" in head, head
    assert "truncated" not in head, head


def test_the_new_shape_still_reads_as_before():
    mod = _load_generate_report()
    head = mod.tcp_heading(_deduped())
    assert head == "TCP Destinations (2) — 194 connection attempts", head


# --- the rows ---


def test_legacy_rows_collapse_with_a_floor_not_an_exact_count():
    """Twenty repetitions of one address say nothing a single counted line does
    not. The count is fenced because the cap makes it a floor."""
    mod = _load_generate_report()
    rows = mod.tcp_display_rows(_legacy_truncated())
    assert len(rows) == 2, rows
    assert {d for d, _ in rows} == {"192.168.100.1:443", "192.168.100.1:80"}
    assert all(s.startswith("×≥") for _, s in rows), rows


def test_complete_legacy_counts_are_not_fenced():
    mod = _load_generate_report()
    rows = mod.tcp_display_rows(_legacy_complete())
    assert dict(rows) == {"192.168.100.1:443": "×2", "192.168.100.1:80": "×1"}


def test_deduped_rows_carry_their_own_counts():
    mod = _load_generate_report()
    rows = mod.tcp_display_rows(_deduped())
    assert dict(rows) == {"192.168.100.1:443": "×121", "192.168.100.1:80": "×73"}


# --- wiring: the helpers are useless if render_cape does not call them ---


def test_render_cape_uses_the_legacy_heading():
    """Asserting on the helpers alone would pass with render_cape still holding
    its old hardcoded f-string — the same gap that let a +corr arm receive no
    evidence while nine tests passed."""
    mod = _load_generate_report()
    html = mod.render_cape({"cape": {"network": _legacy_truncated()}})
    assert "TCP Destinations" not in html, html
    assert "truncated at 50" in html, html
    # 50 rows collapsed to 2 lines, not 20 near-identical ones
    assert html.count("192.168.100.1:443") == 1, html


def test_render_cape_still_renders_the_new_shape():
    mod = _load_generate_report()
    html = mod.render_cape({"cape": {"network": _deduped()}})
    assert "TCP Destinations (2)" in html
    assert "194 connection attempts" in html
    assert "×121" in html


# --- the database side ---


def test_legacy_rows_ingest_as_connections_with_no_attempt_count():
    """NULL attempts is the signal that a row is one connection. A default of 1
    would make fifty truncated rows claim to be fifty destinations."""
    import db_ingest
    rows = db_ingest.tcp_event_rows(_legacy_complete())
    assert len(rows) == 3
    assert all(r[4] is None for r in rows), rows
    # src is preserved rather than discarded to match the newer convention
    assert rows[0][0] == "192.168.100.10" and rows[0][1] == 49001


def test_deduped_rows_ingest_as_destinations_carrying_their_attempts():
    import db_ingest
    rows = db_ingest.tcp_event_rows(_deduped())
    assert len(rows) == 2
    assert [r[4] for r in rows] == [121, 73]
    assert [r[2] for r in rows] == ["192.168.100.1", "192.168.100.1"]
    assert [r[3] for r in rows] == [443, 80]
    # the new shape has no src at all; it must not be invented
    assert all(r[0] == "" and r[1] == 0 for r in rows), rows


def test_the_row_count_alone_cannot_distinguish_the_eras():
    """Why the column exists: three connections and three destinations produce
    three rows each, and `count(*)` cannot tell them apart. `attempts` can."""
    import db_ingest
    legacy = db_ingest.tcp_event_rows(_legacy_complete())
    modern = db_ingest.tcp_event_rows(
        {"tcp_connections": [{"dst": "1.1.1.1:80", "attempts": 5},
                             {"dst": "2.2.2.2:80", "attempts": 5},
                             {"dst": "3.3.3.3:80", "attempts": 5}],
         "tcp_attempts_total": 15})
    assert len(legacy) == len(modern) == 3
    assert {r[4] for r in legacy} == {None}
    assert {r[4] for r in modern} == {5}


def test_malformed_entries_do_not_sink_the_ingest():
    import db_ingest
    rows = db_ingest.tcp_event_rows(
        {"tcp_connections": ["not-a-dict", None, {"dst": "1.1.1.1:80"}]})
    assert len(rows) == 1
    assert rows[0][2] == "1.1.1.1"


# --- deploy ordering: the column arrives in a different Ansible role ---


class _FakeCursor:
    """Records executed statements. `has_attempts` decides what the catalogue
    probe finds, standing in for a database that has or has not been migrated."""

    def __init__(self, has_attempts: bool):
        self._has_attempts = has_attempts
        self.statements: list = []

    def execute(self, sql, params=None):
        self.statements.append((" ".join(sql.split()), params))

    def fetchone(self):
        last = self.statements[-1][0]
        assert "information_schema.columns" in last, last
        return (1,) if self._has_attempts else None


def test_the_probe_reads_the_catalogue_not_a_flag():
    import db_ingest
    assert db_ingest.network_events_has_attempts(_FakeCursor(True)) is True
    assert db_ingest.network_events_has_attempts(_FakeCursor(False)) is False


def test_a_migrated_schema_stores_the_attempt_count():
    import db_ingest
    cur = _FakeCursor(True)
    assert db_ingest.insert_tcp_events(cur, 7, _deduped()) == 2
    inserts = [s for s in cur.statements if s[0].startswith("INSERT")]
    assert len(inserts) == 2
    assert all("attempts" in sql for sql, _ in inserts), inserts
    assert [params[-1] for _, params in inserts] == [121, 73]


def test_an_unmigrated_schema_does_not_lose_the_whole_analysis(capsys):
    """`make deploy TAGS=pipeline` ships this file without the migration, which
    the postgres role owns. Referencing a column that does not exist yet raises
    inside the ingest's blanket except and discards every IOC, technique and
    correlation for the analysis, not just these rows (#450)."""
    import db_ingest
    cur = _FakeCursor(False)
    assert db_ingest.insert_tcp_events(cur, 7, _deduped()) == 2
    inserts = [s for s in cur.statements if s[0].startswith("INSERT")]
    assert len(inserts) == 2
    assert not any("attempts" in sql for sql, _ in inserts), inserts
    assert "attempts is missing" in capsys.readouterr().out


def test_no_probe_and_no_warning_when_there_is_nothing_to_write():
    import db_ingest
    cur = _FakeCursor(False)
    assert db_ingest.insert_tcp_events(cur, 7, {}) == 0
    assert cur.statements == []


def test_ingest_to_db_delegates_the_tcp_insert():
    """Parsed, not grepped: db_ingest's comments name both INSERT variants, so a
    text search finds them whether or not ingest_to_db still calls the helper.
    Without this the helper could be perfect and unreachable."""
    import ast
    src = (FILES / "db_ingest.py").read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "ingest_to_db")

    calls = {n.func.id for n in ast.walk(fn)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "insert_tcp_events" in calls, sorted(calls)

    # and no tcp INSERT left behind in the caller to race the helper
    inline = [n for n in ast.walk(fn)
              if isinstance(n, ast.Call)
              and isinstance(n.func, ast.Attribute) and n.func.attr == "execute"
              and n.args and isinstance(n.args[0], ast.Constant)
              and "network_events" in n.args[0].value and "'tcp'" in n.args[0].value]
    assert not inline, [n.lineno for n in inline]
