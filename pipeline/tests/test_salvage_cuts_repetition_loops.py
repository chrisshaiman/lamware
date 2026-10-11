# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A 2a that ended in an enumeration loop salvages the analysis, not the loop (#761).

Phorpiex 13464460 v0 (deterministic, three runs): 4.5 KB of sound analysis, then
"- T1132 (Data Encoding) - Not seen", "- T1133 (...) - Not seen" ... through
invented IDs past T2168, 987 lines, to the 16,384-token cap. Salvage took the
last 24,000 chars, which were all loop, and 2b reported "no findings".

On the host, the new cut kept 5,507 of 48,260 chars of that reasoning, and fired
on none of the other 930 stored reasoning turns, whose longest same-shape run is
4 lines (quoted decompiled code). The fixture below is synthetic.
"""
import ast
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "ansible/roles/interpret/files/interpret-ghidra.py"

ANALYSIS = """The sample builds SMTP messages by hand over raw sockets.
- FUN_00401a10 writes forged Received: headers.
- FUN_00401900 fetches a URL with WinINet and can save it to %TEMP%.
**MITRE Techniques**:
- T1071.001 (Web Protocols) - HTTP fetch
- T1105 (Ingress Tool Transfer) - HTTP download
- T1055 (Process Injection) - no evidence in the code
"""
NAMES = ["Data Encoding", "External Remote Services", "Create Account", "BITS Jobs",
         "Rootkit", "Native API", "Time Sources", "Tool Transfer"]
LOOP = "".join(f"- T{1132 + i} ({NAMES[i % len(NAMES)]}) - Not seen\n" for i in range(400))


@pytest.fixture(scope="module")
def ig():
    name = "_ig_repetition"
    try:
        spec = importlib.util.spec_from_file_location(name, SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    except ImportError as e:   # container-only deps
        pytest.skip(f"interpret-ghidra.py needs container deps: {e}")
    yield mod
    sys.modules.pop(name, None)


def _msg(text):
    return NS(content=[NS(type="thinking", thinking=text)], stop_reason="max_tokens")


def test_the_loop_is_cut_and_the_analysis_kept(ig):
    kept, info = ig.cut_repetition(ANALYSIS + LOOP)
    assert kept == ANALYSIS.rstrip()
    assert info["run_lines"] == 400 and info["cut_at_char"] == len(ANALYSIS)


def test_salvage_hands_2b_the_analysis_and_says_a_loop_was_removed(ig):
    cut = {}
    out = ig.salvage_reasoning(_msg(ANALYSIS + LOOP), cut=cut)
    assert "Ingress Tool Transfer" in out and "Time Sources" not in out
    assert "repetition loop" in out.splitlines()[0]
    assert cut["run_lines"] == 400


def test_without_a_loop_nothing_changes(ig):
    assert ig.cut_repetition(ANALYSIS) == (ANALYSIS, None)
    cut = {}
    out = ig.salvage_reasoning(_msg(ANALYSIS), cut=cut)
    assert out.endswith(ANALYSIS.strip()) and cut == {}
    assert "may be cut off" in out.splitlines()[0]


def test_seven_same_shaped_lines_are_reasoning_and_eight_are_a_loop(ig):
    """Normal reasoning on the host peaks at 4; the threshold keeps a 2x margin."""
    seven = "".join(f"- T{1132 + i} ({NAMES[i]}) - Not seen\n" for i in range(7))
    assert ig.cut_repetition(ANALYSIS + seven)[1] is None
    eight = "".join(f"- T{1132 + i} ({NAMES[i]}) - Not seen\n" for i in range(8))
    assert ig.cut_repetition(ANALYSIS + eight)[1] is not None


def test_a_loop_from_the_first_line_keeps_the_old_salvage(ig):
    """Cutting would leave 2b nothing; the tail is still better than that."""
    assert ig.cut_repetition(LOOP) == (LOOP, None)


def test_the_cut_is_recorded_on_the_analysis_marker():
    tree = ast.parse(SCRIPT.read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "local_synthesize")
    records = [n.value for n in ast.walk(fn) if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "no_prose" for t in n.targets)
               and isinstance(n.value, ast.Dict)]
    assert records, "no_prose is never assigned a record"
    assert "repetition_cut" in {k.value for k in records[0].keys}
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)
             and getattr(n.func, "id", "") == "salvage_reasoning"]
    assert calls and any(k.arg == "cut" for k in calls[0].keywords), \
        "local_synthesize must collect what the cut removed"
