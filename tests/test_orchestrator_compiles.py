# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Compile gate for the de-templated pipeline orchestrator.

run-pipeline.py is now plain Python deployed verbatim (Phase 2b-3). A full runtime
import/--help smoke is deferred to Phase 3 (its sibling modules — stages.cape, ioc_extract,
db_ingest, pipeline_status — are still secret-bearing .py.j2 templates, not importable here).
This gate proves the deployed file stays syntactically valid Python so a bad edit or a stray
Jinja remnant fails CI.
"""
import py_compile
from pathlib import Path

ORCHESTRATOR = (
    Path(__file__).resolve().parents[1]
    / "ansible" / "roles" / "pipeline" / "files" / "run-pipeline.py"
)


def test_orchestrator_is_valid_python():
    assert ORCHESTRATOR.is_file(), f"missing: {ORCHESTRATOR}"
    py_compile.compile(str(ORCHESTRATOR), doraise=True)
