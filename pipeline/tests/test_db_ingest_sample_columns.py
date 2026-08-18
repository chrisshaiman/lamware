# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""db_ingest never stored the triage columns it was handed.

`create_analysis_row` (pipeline_status.py) inserts the samples row at the START
of a run, with only (sha256, filename) — triage has not run yet. So by the time
`ingest_to_db` arrives, EVERY sample is an ON CONFLICT, and the old conflict
clause updated only last_seen and filename. file_type, file_mime, entropy and
ssdeep were computed by triage, passed to the INSERT, and dropped on the floor.

Not "stale on re-ingest" — never written at all, for any run.

ssdeep is the costly one. `select_ssdeep_edges` filters candidates with
`ssdeep IS NOT NULL AND ssdeep <> ''`, so no sample ever qualified and the
`ssdeep_similar` relationship could not be built for any pair: a whole
campaign-clustering signal silently absent, with nothing in any log to say so.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILES = ROOT / "ansible" / "roles" / "pipeline" / "files"
DB_INGEST_SRC = (FILES / "db_ingest.py").read_text(encoding="utf-8")


def _conflict_clause() -> str:
    start = DB_INGEST_SRC.index("INSERT INTO samples")
    return DB_INGEST_SRC[start:DB_INGEST_SRC.index("RETURNING id", start)]


@pytest.mark.parametrize("column", ["file_type", "file_mime", "entropy", "ssdeep"])
def test_the_conflict_path_writes_the_triage_columns(column):
    """THE bug. Every run is an ON CONFLICT because pipeline_status created the
    row first, so a column missing here is a column never stored."""
    clause = _conflict_clause()
    conflict = clause[clause.index("DO UPDATE SET"):]
    assert re.search(rf"\b{column}\s*=", conflict), (
        f"{column} is computed by triage, passed to the INSERT, and then dropped "
        f"on the conflict path — which is the only path a pipeline run takes")


def test_the_row_really_is_created_before_triage_runs():
    """The premise, asserted rather than assumed: if create_analysis_row ever
    stopped inserting the samples row, this whole class of bug would change
    shape and the test above would be guarding the wrong thing."""
    status_src = (FILES / "pipeline_status.py").read_text(encoding="utf-8")
    assert "INSERT INTO samples (sha256, filename)" in status_src, (
        "pipeline_status no longer pre-creates the samples row; re-check whether "
        "ingest_to_db still always takes the ON CONFLICT path")


@pytest.mark.parametrize("column", ["filename", "file_type", "file_mime", "ssdeep"])
def test_an_empty_value_does_not_overwrite_a_stored_one(column):
    """These arrive as "" rather than NULL, so a bare COALESCE never falls back
    and a later run with nothing to say would blank a good stored value. The
    original filename line had exactly that defect."""
    conflict = _conflict_clause()
    assert re.search(rf"{column}\s*=\s*COALESCE\(NULLIF\(EXCLUDED\.{column}, ''\)",
                     conflict), (
        f"{column} needs NULLIF(...,'') inside COALESCE or an empty incoming "
        f"value silently overwrites the stored one")


def test_entropy_is_coalesced_but_not_nullif_d():
    """entropy is numeric and genuinely arrives as None, so NULLIF('') would be
    a type error rather than a safeguard."""
    conflict = _conflict_clause()
    assert "entropy   = COALESCE(EXCLUDED.entropy, samples.entropy)" in conflict
