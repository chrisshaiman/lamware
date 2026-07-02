# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Ghidra stage's container->host project-path propagation.

Regression guard for the native-PE agentic-interpret bug: run-ghidra.py (in the
container) records project_dir="/output/project", and the native-PE interpret
path brokers tool calls off that per-file dict on the HOST. If the container
path leaks through, every run-ghidra --tool call fails with
"realpath: No such file or directory".
"""
from pathlib import Path

from stages.ghidra import propagate_project_dir

CONTAINER_PROJECT = "/output/project"


def test_normalizes_container_path_to_host_path():
    output_dir = Path("/opt/pipeline/reports/abc123")
    analyzed = [{"analysis_success": True, "project_dir": CONTAINER_PROJECT,
                 "program_name": "sample.exe"}]

    project_dir, program_name = propagate_project_dir(analyzed, output_dir)

    assert project_dir == "/opt/pipeline/reports/abc123/project"
    assert program_name == "sample.exe"
    # The per-file dict must be rewritten in place — the interpret broker reads
    # this exact dict, not the top-level result.
    assert analyzed[0]["project_dir"] == "/opt/pipeline/reports/abc123/project"
    assert analyzed[0]["project_dir"] != CONTAINER_PROJECT


def test_picks_first_successful_analysis():
    output_dir = Path("/opt/pipeline/reports/xyz")
    analyzed = [
        {"analysis_success": False, "project_dir": CONTAINER_PROJECT, "program_name": "bad"},
        {"analysis_success": True, "project_dir": CONTAINER_PROJECT, "program_name": "good"},
    ]

    project_dir, program_name = propagate_project_dir(analyzed, output_dir)

    assert project_dir == "/opt/pipeline/reports/xyz/project"
    assert program_name == "good"
    # The failed record is left untouched.
    assert analyzed[0]["project_dir"] == CONTAINER_PROJECT


def test_missing_program_name_defaults_to_empty_string():
    output_dir = Path("/opt/pipeline/reports/np")
    analyzed = [{"analysis_success": True, "project_dir": CONTAINER_PROJECT}]

    project_dir, program_name = propagate_project_dir(analyzed, output_dir)

    assert project_dir == "/opt/pipeline/reports/np/project"
    assert program_name == ""


def test_no_successful_analysis_returns_none():
    output_dir = Path("/opt/pipeline/reports/none")
    analyzed = [
        {"analysis_success": False, "project_dir": CONTAINER_PROJECT},
        {"analysis_success": True},  # success but no project_dir
    ]

    project_dir, program_name = propagate_project_dir(analyzed, output_dir)

    assert project_dir is None
    assert program_name is None


def test_empty_analyzed_files_returns_none():
    project_dir, program_name = propagate_project_dir([], Path("/opt/pipeline/reports/e"))
    assert project_dir is None
    assert program_name is None
