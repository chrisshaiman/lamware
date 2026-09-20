# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""run-pipeline must hand Volatility the pids the correlation rule joins on (#614).

`run_volatility` now dumps the union of `cape.injection_pids` and the injection
buffers' `target_pid`s, but only the first of those was ever computed in
run-pipeline. A fix confined to the stage would have changed nothing in
production: the new parameter would default to None on every real run.

run-pipeline.py is a script, not an importable module, so the derivation is
lifted out by AST and EXECUTED against report fixtures rather than pattern
matched. A structural test here would pass against `cape_buffer_pids = []`.
"""
import ast
from pathlib import Path

import pytest

SRC = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
       / "files" / "run-pipeline.py")
TREE = ast.parse(SRC.read_text(encoding="utf-8"))


def _derivation():
    """The `cape_buffer_pids = ...` assignment, as an executable module."""
    for node in ast.walk(TREE):
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == "cape_buffer_pids"):
            return ast.Module(body=[node], type_ignores=[])
    pytest.fail("run-pipeline.py never computes cape_buffer_pids")


def buffer_pids_for(report: dict) -> list:
    scope = {"report": report, "sorted": sorted}
    exec(compile(_derivation(), str(SRC), "exec"), scope)
    return scope["cape_buffer_pids"]


def _report(buffers):
    return {"cape": {"injection_pids": [972], "injection_buffers": buffers}}


def test_the_buffer_target_pids_are_collected():
    assert buffer_pids_for(_report([{"target_pid": 4192}])) == [4192]


def test_repeated_targets_collapse():
    """31 buffers into one process is the common shape, not the exception."""
    assert buffer_pids_for(_report([{"target_pid": 4192}] * 31)) == [4192]


def test_several_targets_are_all_kept():
    assert buffer_pids_for(_report(
        [{"target_pid": 8588}, {"target_pid": 972}])) == [972, 8588]


@pytest.mark.parametrize("buffers", [
    [],
    [{"target_pid": None}],
    [{"target_pid": 0}],       # pid 0 is the idle process; never an injection target
    [{"size": 32}],            # CAPE does not always record a target
])
def test_nothing_usable_yields_nothing(buffers):
    """An empty list must not become [None] or [0] — those reach vol's argv."""
    assert buffer_pids_for(_report(buffers)) == []


def test_a_report_with_no_cape_section_does_not_raise():
    """The stage runs on reports from failed detonations too."""
    assert buffer_pids_for({}) == []
    assert buffer_pids_for({"cape": {}}) == []
    assert buffer_pids_for({"cape": {"injection_buffers": None}}) == []


def test_the_value_is_passed_to_run_volatility():
    """Computing it and not passing it is the whole failure mode being fixed."""
    for node in ast.walk(TREE):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "run_volatility"):
            kwargs = {k.arg: k.value for k in node.keywords}
            assert "cape_buffer_pids" in kwargs, \
                "run_volatility is called without the buffer pids"
            assert isinstance(kwargs["cape_buffer_pids"], ast.Name) and \
                kwargs["cape_buffer_pids"].id == "cape_buffer_pids"
            return
    pytest.fail("run-pipeline.py does not call run_volatility")
