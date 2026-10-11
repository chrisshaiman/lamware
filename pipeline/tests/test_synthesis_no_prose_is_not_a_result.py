# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A synthesis that wrote no prose is recorded as such, not scored as an analysis (#755).

Phorpiex 13464460 v0, 2026-10-10, twice on identical input: phase 2a spent all
16,384 output tokens reasoning, 2b serialised the tail, and the cell scored as a
completed analysis with zero claims and family "Unknown". The reasoning itself
was nowhere in the trail.
"""
import ast
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest
from lamware_eval.metrics import cell_error
from llm_ab_re import analysis_completed

SCRIPT = Path(__file__).resolve().parents[2] / "ansible/roles/interpret/files/interpret-ghidra.py"

NO_PROSE = {"phase": "synth_2a", "stop_reason": "max_tokens",
            "output_tokens": 16384, "salvaged_chars": 24112}
PHORPIEX = {"malware_family_guess": "Unknown", "capabilities": [], "narrative": "x",
            "synthesis_no_prose": NO_PROSE}


def _res(analysis):
    return {"enabled": True, "analysis": analysis}


def test_a_no_prose_synthesis_is_not_a_completed_analysis():
    assert analysis_completed(_res(PHORPIEX)) is False
    clean = {k: v for k, v in PHORPIEX.items() if k != "synthesis_no_prose"}
    assert analysis_completed(_res(clean)) is True, "the probe must differ only by the marker"


def test_the_error_column_says_why_the_cell_is_empty():
    err = cell_error(_res(PHORPIEX), PHORPIEX)
    assert err is not None
    assert "synth_2a" in err and "max_tokens" in err and "16384" in err


def test_a_real_error_is_not_overwritten_by_the_marker():
    res = {"enabled": True, "error": "timeout", "analysis": PHORPIEX}
    assert cell_error(res, PHORPIEX).startswith("timeout")


@pytest.fixture(scope="module")
def ig():
    name = "_ig_no_prose"
    try:
        spec = importlib.util.spec_from_file_location(name, SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    except ImportError as e:   # container-only deps
        pytest.skip(f"interpret-ghidra.py needs container deps: {e}")
    yield mod
    sys.modules.pop(name, None)


def test_2a_reasoning_reaches_the_trail_in_full(ig, monkeypatch):
    sent = []
    monkeypatch.setattr(ig, "emit", sent.append)
    reasoning = "r" * 60_000 + " still weighing T1071 vs T1105"
    concl = NS(content=[NS(type="thinking", thinking=reasoning)], stop_reason="max_tokens",
               usage=NS(input_tokens=1, output_tokens=16384,
                        cache_creation_input_tokens=0, cache_read_input_tokens=0))
    ig.emit_turn(concl, "synth_2a")
    (ev,) = sent
    assert ev["type"] == "turn" and ev["turn_index"] == "synth_2a"
    assert ev["thinking"] == reasoning, "untruncated: the trail is the chain of custody"
    assert ev["stop_reason"] == "max_tokens"


def _local_synthesize():
    tree = ast.parse(SCRIPT.read_text())
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "local_synthesize"), None)
    assert fn is not None, "local_synthesize not found: the probe is broken"
    return fn


def test_every_return_after_2a_carries_the_marker():
    """Structural, because local_synthesize is a closure inside main() over a live
    client. Every return that follows the 2a call must go through tagged(), or a
    path that skipped it would score a no-prose run as an analysis again."""
    fn = _local_synthesize()
    call_2a = min(n.lineno for n in ast.walk(fn)
                  if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "emit_turn")
    rets = [n for n in ast.walk(fn) if isinstance(n, ast.Return) and n.lineno > call_2a
            and not any(isinstance(p, ast.FunctionDef) and p.name == "tagged"
                        and p.lineno <= n.lineno <= p.end_lineno for p in ast.walk(fn))]
    assert len(rets) >= 4, f"expected the 2b, prose-parse, legacy and failure returns, got {len(rets)}"
    untagged = [r.lineno for r in rets
                if not (isinstance(r.value, ast.Call) and getattr(r.value.func, "id", "") == "tagged")]
    assert not untagged, f"returns at lines {untagged} bypass tagged()"


def test_the_marker_is_set_on_the_no_text_branch():
    fn = _local_synthesize()
    sets = [n for n in ast.walk(fn) if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == "no_prose" for t in n.targets)
            and isinstance(n.value, ast.Dict)]
    assert sets, "no_prose is never assigned a record"
    keys = {k.value for k in sets[0].value.keys}
    assert {"phase", "stop_reason", "output_tokens", "salvaged_chars"} <= keys
