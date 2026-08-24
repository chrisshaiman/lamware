# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Correlation findings have to survive the run that produced them (#423).

Correlation is the project's stated thesis and was the only analysis output that
was computed, severity-scored, rendered into the PDF, and then discarded. Across
998 analyses there was no way to ask whether it has ever fired, which blocks #420
— whose first requirement is a corpus of samples where correlation produces
something.

`correlation_rows` is the shaping step between the rules' dicts and the
`correlations` table. Tested here rather than through the ingest because the
ingest needs PostgreSQL and this does not, and because every value it handles is
adversary-derived: a finding's title embeds a dropped file's path and its detail
embeds a command line the sample chose.
"""
import lamware_pipeline.correlation_rules as cr
from lamware_pipeline.correlation_rules import CORRELATION_COLUMNS, correlation_rows

FINDING = {
    "type": "dropped_file_loaded",
    "severity": "high",
    "title": "Dropped file 'evil.dll' was loaded and executed",
    "detail": "Cape observed this file being written to C:\\Temp\\evil.dll.",
    "sources": ["Cape", "Volatility"],
    "mitre": "T1059 — Execution",
}


def _row(finding) -> dict:
    rows = correlation_rows([finding])
    assert len(rows) == 1
    return dict(zip(CORRELATION_COLUMNS, rows[0], strict=True))


def test_a_finding_maps_onto_the_table_columns():
    row = _row(FINDING)
    assert row["type"] == "dropped_file_loaded"
    assert row["severity"] == "high"
    assert row["sources"] == ["Cape", "Volatility"]
    assert row["mitre"] == "T1059 — Execution"
    assert row["pid"] is None


def test_the_column_list_matches_what_the_rows_carry():
    """The ingest zips these together positionally, so a column added to one and
    not the other writes values into the wrong fields rather than failing."""
    assert len(correlation_rows([FINDING])[0]) == len(CORRELATION_COLUMNS)


def test_every_rule_in_the_registry_produces_a_shapeable_finding():
    """Guards the coupling: a new rule whose dict omits a key must not break
    ingestion for the findings alongside it."""
    for rule in cr._RULES:
        for finding in rule({}):  # empty report -> [] today, but the shape is the contract
            _row(finding)
    assert correlation_rows([]) == []


# --- adversary-derived values must not abort the transaction ---------------

def test_an_over_long_title_is_trimmed_not_raised():
    """title is varchar(500) and embeds a sample-chosen path. psycopg2 aborts the
    WHOLE transaction on an over-length value, which would lose the IOCs and
    techniques ingested alongside it — so the finding is trimmed instead."""
    row = _row({**FINDING, "title": "A" * 5000})
    assert len(row["title"]) == 500


def test_an_over_long_detail_is_trimmed():
    row = _row({**FINDING, "detail": "B" * 99999})
    assert len(row["detail"]) == 4000


def test_an_over_long_source_name_is_trimmed():
    row = _row({**FINDING, "sources": ["C" * 300]})
    assert len(row["sources"][0]) == 50


def test_an_integer_pid_becomes_a_string():
    """rule_shellcode_self_modified emits an int pid and rule_cmdline_spoofing a
    string, because one comes from Volatility's renderer and the other from a
    JSON dict key. The column is one type."""
    assert _row({**FINDING, "pid": 4444})["pid"] == "4444"
    assert _row({**FINDING, "pid": "4444"})["pid"] == "4444"


def test_a_missing_type_does_not_produce_a_null_column():
    """`type` is NOT NULL and is what the per-rule base rate groups on."""
    row = _row({"severity": "high", "title": "x"})
    assert row["type"] == "unknown"
    assert row["severity"] == "high"


def test_a_missing_severity_does_not_produce_a_null_column():
    assert _row({"type": "x", "title": "y"})["severity"] == "unknown"


def test_a_non_list_sources_value_is_still_an_array():
    """The column is text[]; a rule emitting a bare string must not write a
    scalar into it."""
    assert _row({**FINDING, "sources": "Cape"})["sources"] == ["Cape"]


def test_absent_sources_is_null_rather_than_an_empty_array():
    """NULL means "this rule did not say"; [] would claim it corroborated
    nothing, which is a different statement for a CORRELATION finding."""
    assert _row({**FINDING, "sources": None})["sources"] is None


def test_non_dict_entries_are_skipped_rather_than_crashing_the_ingest():
    assert correlation_rows([FINDING, "not a dict", None, 42]) == correlation_rows([FINDING])
