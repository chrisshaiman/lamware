# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Synthesis tokens reach the run's usage totals (#765, CLAUDE.md §10).

Phorpiex 13464460 v0 (2026-10-10): result.json usage said 1,705 output
tokens; the trail's request_result for synth_2a alone said 16,384. Only the
loop's turns were added to `totals`, so the priced usage left out 2a, 2b and
the legacy fallback, which on a runaway cell is nearly all of it.
"""
import ast
import importlib.util
import json
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "ansible/roles/interpret/files/interpret-ghidra.py"


@pytest.fixture(scope="module")
def ig():
    name = "_ig_usage_totals"
    try:
        spec = importlib.util.spec_from_file_location(name, SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    except ImportError as e:   # container-only deps
        pytest.skip(f"interpret-ghidra.py needs container deps: {e}")
    yield mod
    sys.modules.pop(name, None)


class _Resp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        return None

    def json(self):
        return self._body


class _Http:
    def __init__(self, body):
        self.body = body

    def post(self, *a, **kw):
        return _Resp(self.body)


def _body(tool_args=None):
    msg = {"content": "prose instead"} if tool_args is None else {
        "tool_calls": [{"function": {"name": "submit_analysis", "arguments": json.dumps(tool_args)}}]}
    return {"choices": [{"message": msg, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 8837, "completion_tokens": 1135}}


def test_2b_usage_is_added_to_the_totals_it_is_given(ig, monkeypatch):
    monkeypatch.setattr(ig, "emit", lambda *_: None)
    totals = ig.empty_usage()
    got = ig.synthesize_analysis(_Http(_body({"malware_family_guess": "x"})), "http://x", "k",
                                 "m", [{"role": "user", "content": "c"}], usage_out=totals)
    assert got is not None
    assert totals["input_tokens"] == 8837 and totals["output_tokens"] == 1135


def test_2b_is_billed_even_when_it_answers_in_prose(ig, monkeypatch):
    monkeypatch.setattr(ig, "emit", lambda *_: None)
    totals = ig.empty_usage()
    got = ig.synthesize_analysis(_Http(_body(None)), "http://x", "k", "m",
                                 [{"role": "user", "content": "c"}], usage_out=totals)
    assert got is None and totals["output_tokens"] == 1135


def _local_synthesize():
    tree = ast.parse(SCRIPT.read_text())
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "local_synthesize")


def _adds_after(fn, var):
    """Lines of add_usage(totals, usage_from_response(<var>)) in fn."""
    out = []
    for n in ast.walk(fn):
        if (isinstance(n, ast.Call) and getattr(n.func, "id", "") == "add_usage"
                and isinstance(n.args[0], ast.Name) and n.args[0].id == "totals"
                and isinstance(n.args[1], ast.Call)
                and getattr(n.args[1].func, "id", "") == "usage_from_response"
                and isinstance(n.args[1].args[0], ast.Name) and n.args[1].args[0].id == var):
            out.append(n.lineno)
    return out


def test_2a_and_the_legacy_fallback_add_their_usage_to_totals():
    """Structural: local_synthesize is a closure over a live client."""
    fn = _local_synthesize()
    assert _adds_after(fn, "concl"), "phase 2a's usage is not added to totals"
    assert _adds_after(fn, "resp"), "the legacy fallback's usage is not added to totals"


def test_2b_is_handed_the_runs_totals():
    fn = _local_synthesize()
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
             and getattr(n.func, "id", "") == "synthesize_analysis"]
    assert calls and all(any(k.arg == "usage_out" and getattr(k.value, "id", "") == "totals"
                             for k in c.keywords) for c in calls)
