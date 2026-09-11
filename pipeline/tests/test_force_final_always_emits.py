# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A forced final must always produce a final message (#588).

force_final exists to SALVAGE a run that is out of time. Measured on
salat_d26bc055, 2026-09-09:

    timed_out      : True
    container_exit : exited cleanly (0) without sending a final result

Ten tool calls of real work — list_functions filtered by *crypt*/*http*/*socket*,
four decompile_function calls, three get_strings_at — were discarded, because
the local branch called

    emit({"analysis": local_synthesize(messages), ...})

with no handler. local_synthesize is the expensive call (one was measured at
1041s); when it failed, nothing was emitted, the container unwound silently, and
the orchestrator saw stdout EOF with no final.

The cloud branch beside it had been wrapped all along, and caught only
anthropic.APIError — so a transport failure there was equally silent.
"""
import ast
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "ansible" / "roles" / "interpret" / "files" / "interpret-ghidra.py"
TEXT = SRC.read_text(encoding="utf-8")


def _force_final_block() -> str:
    start = TEXT.index('if result_msg.get("type") == "force_final":')
    end = TEXT.index('elif result_msg.get("type") == "tool_result":', start)
    return TEXT[start:end]


def test_the_local_synthesis_cannot_escape_without_emitting():
    """The exact defect: an unguarded call inside emit()."""
    block = _force_final_block()
    assert "analysis = local_synthesize(messages)" in block, \
        "local_synthesize is still called inline, so a raise skips the emit entirely"
    assert "except Exception" in block, "the local synthesis has no handler"


def _force_final_node():
    """The force_final `if` node, parsed from the whole file.

    Slicing text and splitting handler bodies on blank lines let a handler that
    raises instead of emitting pass, because the slice ran on into the emit that
    followed it. Parse the tree."""
    tree = ast.parse(TEXT)
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        src = ast.get_source_segment(TEXT, node.test) or ""
        if '"force_final"' in src:
            return node
    raise AssertionError("no force_final branch found")


def _emits(node) -> bool:
    return any(isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "emit"
               for c in ast.walk(node))


def test_no_handler_can_leave_without_emitting():
    """Two shapes are safe and one is not.

    Safe: the handler emits itself; or it assigns a fallback and FALLS THROUGH to
    an emit below it — which is what the local branch does.

    Not safe: the handler raises, returns or exits, because then the emit below
    never runs. That is the shape being guarded against, and a plain "does this
    handler contain emit()" check rejects the safe fall-through case while a text
    search accepts the unsafe one."""
    node = _force_final_node()
    handlers = [h for h in ast.walk(node) if isinstance(h, ast.ExceptHandler)]
    assert len(handlers) >= 2, f"expected a handler on each branch, found {len(handlers)}"
    for h in handlers:
        which = ast.get_source_segment(TEXT, h.type) or "except"
        if _emits(h):
            continue
        terminators = [n for n in ast.walk(h)
                       if isinstance(n, (ast.Raise, ast.Return))
                       or (isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                           and n.func.attr == "exit")]
        assert not terminators, (
            f"the {which} handler neither emits nor falls through — it terminates, "
            f"so the salvage is lost")


def test_no_path_out_of_the_forced_final_skips_the_emit():
    """Both branches — local and cloud — must emit before exiting."""
    node = _force_final_node()
    exits = [n for n in ast.walk(node)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "exit"]
    assert len(exits) >= 2, f"expected an exit per branch, found {len(exits)}"
    assert _emits(node), "the forced-final branch never calls emit at all"


def test_transport_errors_are_caught_on_the_cloud_branch_too():
    """anthropic.APIError alone leaves an httpx transport failure silent."""
    block = _force_final_block()
    assert "httpx.HTTPError" in block, \
        "the cloud forced-final catches only anthropic errors"


def test_every_salvaged_final_says_what_the_run_managed_to_do():
    """An error string alone discards the fact that the run decompiled four
    functions — that is in the transcript already.

    Asserted PER HANDLER: checking the block as a whole let the cloud branch
    satisfy it while the local branch had been stripped."""
    node = _force_final_node()
    handlers = [h for h in ast.walk(node) if isinstance(h, ast.ExceptHandler)]
    for h in handlers:
        src = ast.get_source_segment(TEXT, h) or ""
        which = ast.get_source_segment(TEXT, h.type) or "except"
        assert "tools_invoked" in src, f"{which} handler drops the tools invoked"
        assert '"partial": True' in src, f"{which} handler does not mark the result partial"


def test_tool_names_are_read_out_of_the_transcript():
    """Exercised, not just present — it has to cope with both dict blocks and
    SDK objects, which is what the transcript actually holds."""
    spec = importlib.util.spec_from_file_location("_ig", SRC)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_ig"] = mod
    try:
        spec.loader.exec_module(mod)
    except Exception:
        import pytest
        pytest.skip("interpret-ghidra.py needs container-only deps to import")

    class _Block:
        def __init__(self, name):
            self.type, self.name = "tool_use", name

    messages = [
        {"role": "assistant", "content": [_Block("decompile_function"), _Block("list_functions")]},
        {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "x"}]},
        {"role": "assistant", "content": [{"type": "tool_use", "name": "get_strings_at"}]},
        {"role": "user", "content": "plain string, not a block list"},
    ]
    assert mod._tool_names_from(messages) == [
        "decompile_function", "list_functions", "get_strings_at"]
