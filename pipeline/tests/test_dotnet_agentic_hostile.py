# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Hostile C# must not be able to end the run (review of #673).

Reproduced on the first version of this branch: a decompiled source with ~600
nested interpolated strings (`'$"{' * 600`) raised RecursionError from the C#
indexer's string scanner. It raised in Stage 4.5's `build_dotnet_interpret_init`
with no handler around it, so `main()` exited with no report and no DB row —
after CAPE, Volatility and Ghidra had run. A sample could deny its own analysis.

Three properties, each observed by calling the code with the hostile input:

  * the indexer accepts any input — iterative masking, no call-stack depth —
    and stays near-linear (the quadratic paths the probe found are covered by
    time bounds here);
  * if building the agentic map or toolbox fails anyway, the run falls back to
    the single-shot payload and records why, in the payload, the result, the
    trail and `llm_interpretation.input`;
  * one failing tool call costs one turn: `DotnetToolbox.call` answers any
    exception with `{"error": ...}` naming its type.
"""
import ast
import importlib.util
import json
import logging
import sys
import textwrap
import time
from pathlib import Path

import pytest
from stages.dotnet_agentic import build_dotnet_interpret_init, dotnet_input_record
from stages.dotnet_tools import CSharpIndex, DotnetToolbox, build_map, mask_source
from stages.interpret import run_interpret

ROOT = Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "dotnet_formbook_shape", Path(__file__).parent / "fixtures" / "dotnet_formbook_shape.py")
shape = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(shape)


def _analysis(src: str) -> dict:
    return {"analysis_success": True, "decompilation": {"source": src},
            "strings_of_interest": []}


# Every construct the scanner nests on, deeper than the default recursion limit
# (1000) — the review's shape first.
HOSTILE = {
    "interpolation x600 (review)": 'class A { string s = ' + '$"{' * 600 + '1' + '}"' * 600 + '; }',
    "interpolation x20000": 'class A { string s = ' + '$"{' * 20000 + '1' + '}"' * 20000 + '; }',
    "unclosed interpolation x20000": 'class A { string s = ' + '$"{' * 20000,
    "verbatim interpolation x20000": 'class A { string s = ' + '$@"{' * 20000 + '1' + '}"' * 20000 + '; }',
    "interpolation holes with braces x5000": 'class A { string s = ' + '$"{ new[] {' * 5000 + '1' + '}}"' * 5000 + '; }',
    "nested braces x100000": 'class A { void M() ' + '{' * 100000 + '}' * 100000 + ' }',
    "unbalanced open x100000": 'class A { void M() ' + '{' * 100000,
    "unbalanced close x100000": '}' * 100000 + 'class A { }',
    "nested classes x3000": ''.join(f'class C{i} {{ ' for i in range(3000)) + 'string s = "Load";' + '}' * 3000,
    "sibling classes with hits x20000": ''.join(f'class C{i} {{ string s = "Load"; }}\n' for i in range(20000)),
    "nested block comments x50000": 'class A { ' + '/*' * 50000 + '*/' * 50000 + ' }',
    "stray char quotes x100000": "class A { " + "'" * 100000 + " }",
    "attribute brackets x100000": 'class A { ' + '[' * 100000 + ' void M() { } }',
    "generic brackets x50000": 'class A { void M' + '<' * 50000 + 'T' + '>' * 50000 + '() { } }',
    "control bytes": 'class A\x00 { void M\x01() { "\x02Load" } }',
    "empty": "",
}


@pytest.mark.parametrize("label", list(HOSTILE))
def test_no_hostile_source_raises_or_stalls(label):
    """Through the three entry points run-pipeline and run_interpret use: the
    init builder, the toolbox, and a tool call. Bounded in time as well: a
    stall is the same denial as a crash once the stage budget is spent."""
    src = HOSTILE[label]
    t0 = time.monotonic()
    init = build_dotnet_interpret_init(_analysis(src), {}, [], "agentic")
    assert "dotnet_agentic_failed" not in init, init.get("dotnet_agentic_failed")
    assert init["dotnet_mode"] == "agentic"
    # The tools in-process: this is the code the sandbox runs, and the property
    # is that it answers, whatever the input (the broker's handling of a
    # sandbox that does not is tested in test_dotnet_tool_sandbox.py).
    tb = DotnetToolbox.from_payload(init)
    for tool, args in [("search_source", {"pattern": '"Load"'}),
                       ("get_class_source", {"class_name": "A"}),
                       ("list_classes", {}),
                       ("get_source_lines", {"start_line": 1, "end_line": 3})]:
        r = tb.call(tool, args)
        assert "tool failed" not in json.dumps(r), (tool, r)
    assert time.monotonic() - t0 < 15, f"{label} took {time.monotonic() - t0:.1f}s"


def _build_seconds(src: str) -> float:
    """The map build itself (the sandbox's work), without process start-up noise."""
    t0 = time.perf_counter()
    build_map(src)
    return time.perf_counter() - t0


def test_many_small_classes_scale_linearly():
    """The probe found three per-hit or per-location scans over every type
    (15 s on 20,000 classes). A wall-clock bound loose enough for CI could
    not see one of them come back; the growth rate can. 10x the input must
    cost well under 100x the time."""
    def classes(n):
        return "".join(f'class C{i} {{ string s = "Load"; }}\n' for i in range(n))
    _build_seconds(classes(200))                          # warm-up
    small = min(_build_seconds(classes(2_000)) for _ in range(2))
    big = _build_seconds(classes(20_000))
    assert big / small < 30, f"2,000 classes {small:.2f}s, 20,000 classes {big:.2f}s"


def test_the_review_shape_does_not_touch_the_call_stack():
    """Asserted at a recursion limit far below the input's depth."""
    old = sys.getrecursionlimit()
    sys.setrecursionlimit(200)
    try:
        CSharpIndex(HOSTILE["interpolation x600 (review)"])
    finally:
        sys.setrecursionlimit(old)


def test_nested_interpolation_is_still_masked_correctly():
    """Iterative must mean the same, not merely not crashing: a `}` inside a
    string inside a hole inside a string is not code."""
    src = 'class A { string s = $"{ f($"{ "}" }") }"; void M() { } }'
    idx = CSharpIndex(src)
    assert [m.name for m in idx.find_types("A")[0].members] == ["M"]
    assert mask_source(src).count("}") == 2


def test_the_formbook_shaped_corpus_masks_as_before():
    """The fixture's traps (verbatim ending in a backslash, a string inside a
    hole, char literals) still parse to the same members."""
    idx = CSharpIndex(shape.formbook_shaped_source())
    names = [m.name for m in idx.find_types("BattleForm")[0].members]
    assert names == ["BattleForm", "Animatsiya", "Ignite", "Sarlavha", "VirtualAlloc",
                     "InitializeComponent"]


# --- fallback: the run goes on as single-shot, and says why --------------------

def _dead_sandbox(tmp_path: Path, code: int = 137) -> dict:
    """An interpret config whose tool sandbox dies the way an OOM kill does."""
    dead = tmp_path / "dead-sandbox"
    dead.write_text(f"#!/bin/sh\ncat >/dev/null\nexit {code}\n")
    dead.chmod(0o755)
    return {"dotnet_tools_cmd": str(dead)}


def test_a_failing_map_falls_back_to_single_shot_and_says_why(tmp_path, caplog):
    src = shape.formbook_shaped_source()
    with caplog.at_level(logging.WARNING, logger="stages.dotnet_agentic"):
        init = build_dotnet_interpret_init(shape.dotnet_analysis(src), {}, [], "agentic",
                                           _dead_sandbox(tmp_path))
    assert "dotnet_mode" not in init, "the fallback must be the single-shot payload"
    assert init["decompiled_source"].startswith(src[:1000])
    assert "killed" in init["dotnet_agentic_failed"]
    assert "falling back to single-shot" in caplog.text
    rec = dotnet_input_record(init, "agentic")
    assert rec == {"kind": "dotnet", "dotnet_mode": "single_shot",
                   "requested_mode": "agentic",
                   "agentic_failed": init["dotnet_agentic_failed"]}


def _echo_container(tmp_path: Path) -> str:
    fake = tmp_path / "echo"
    fake.write_text(f"#!{sys.executable}\n" + textwrap.dedent('''
        import json, sys
        init = json.loads(sys.stdin.readline())
        print(json.dumps({"type": "final", "analysis": {"seen": init["ghidra_data"]},
                          "model_used": "m", "tool_calls_used": 0}), flush=True)
    '''))
    fake.chmod(0o755)
    return str(fake)


def test_stage_45_falls_back_end_to_end(tmp_path):
    """The Stage 4.5 sequence as run-pipeline runs it — build the init, run the
    interpret, record the input — with the sandbox dead. No exception; the
    container receives the single-shot payload; the record says why."""
    init = build_dotnet_interpret_init(
        shape.dotnet_analysis(shape.formbook_shaped_source()), {}, [], "agentic",
        _dead_sandbox(tmp_path))
    out = tmp_path / "out"
    out.mkdir()
    res = run_interpret(init, out, _echo_container(tmp_path), True, 30, {"model": "m"},
                        "/nonexistent/run-ghidra")
    assert "error" not in res, res
    assert shape.DECOY_MARK in res["analysis"]["seen"]["decompiled_source"]
    assert "killed" in dotnet_input_record(init, "agentic")["agentic_failed"]


def test_run_pipeline_records_what_actually_ran():
    """Structural, because run-pipeline's main() is one function that needs a
    host to run: the .NET branch must build through the never-raising selector
    and record the input with dotnet_input_record (which sees fallbacks), not
    from the requested mode. The behaviour of both is tested above."""
    tree = ast.parse((ROOT / "ansible/roles/pipeline/files/run-pipeline.py").read_text())
    called = {n.func.id for n in ast.walk(tree)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert {"build_dotnet_interpret_init", "dotnet_input_record"} <= called
    assert not {"CSharpIndex", "DotnetToolbox", "build_map",
                "build_dotnet_agentic_init"} & called


# --- one bad tool call costs one turn -------------------------------------------

def test_any_tool_exception_is_answered_not_raised(monkeypatch):
    tb = DotnetToolbox(shape.formbook_shaped_source())

    def broken(self, args):
        raise KeyError("lines")
    monkeypatch.setattr(DotnetToolbox, "_t_list_classes", broken)
    r = tb.call("list_classes", {})
    assert r == {"error": "tool failed: KeyError: 'lines'"}
