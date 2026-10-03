# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A phase 2a that only reasons hands its reasoning to 2b instead of losing the run (#260).

formbook, dotnet-agentic-vs-ss-2610 (2026-10-03): a good tool loop, then
synthesis 2a produced 16,384 output tokens and no text block (thinking cannot be
switched off on this route, measured on #260), concl_text was empty, 2b was
skipped, the legacy fallback failed (#675) and the run ended with an empty
analysis. The reasoning held the agent's conclusions; now 2b serializes its tail.
"""
import ast
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "ansible/roles/interpret/files/interpret-ghidra.py"


@pytest.fixture(scope="module")
def ig():
    name = "_ig_salvage"
    try:
        spec = importlib.util.spec_from_file_location(name, SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    except ImportError as e:   # container-only deps
        pytest.skip(f"interpret-ghidra.py needs container deps: {e}")
    yield mod
    sys.modules.pop(name, None)


def _msg(*blocks):
    return NS(content=list(blocks), stop_reason="max_tokens")


def test_reasoning_only_reply_becomes_2b_input(ig):
    m = _msg(NS(type="thinking", thinking="looked at Anneal_Crucible_Batch: builds bytes, "
                                          "LateGet Load -> reflective loader"))
    out = ig.salvage_reasoning(m)
    assert "reflective loader" in out
    assert out.startswith("[Phase 2a produced no prose"), "the marker tells 2b what it is reading"


def test_the_tail_is_kept_when_it_is_long(ig):
    long = "x" * 50_000 + " CONCLUSION: process injection"
    out = ig.salvage_reasoning(_msg(NS(type="thinking", thinking=long)), limit=1_000)
    assert out.endswith("CONCLUSION: process injection"), "conclusions accumulate at the end"
    assert len(out) < 1_200


def test_nothing_to_salvage_stays_empty(ig):
    assert ig.salvage_reasoning(_msg()) == ""
    assert ig.salvage_reasoning(_msg(NS(type="thinking", thinking="   "))) == ""
    assert ig.salvage_reasoning(_msg(NS(type="text", text="prose"))) == "", \
        "visible text is 2a's normal path, not salvage"


def test_local_synthesize_salvages_when_2a_has_no_text():
    """Structural: local_synthesize lives inside main() with a live client and
    cannot be called alone. The salvage must sit on the no-visible-text branch,
    before 2b reads concl_text."""
    tree = ast.parse(SCRIPT.read_text())
    fn = next((n for n in ast.walk(tree)
               if isinstance(n, ast.FunctionDef) and n.name == "local_synthesize"), None)
    assert fn is not None, "local_synthesize not found: the probe is broken"
    salvage = [n for n in ast.walk(fn)
               if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "concl_text" for t in n.targets)
               and isinstance(n.value, ast.Call) and getattr(n.value.func, "id", "") == "salvage_reasoning"]
    assert salvage, "local_synthesize no longer assigns concl_text = salvage_reasoning(...)"
    serialize = [n for n in ast.walk(fn)
                 if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "serialize_msgs" for t in n.targets)]
    assert serialize and salvage[0].lineno < serialize[0].lineno, \
        "salvage must happen before phase 2b builds its input"
