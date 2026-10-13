# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Cloud agent loops cache the transcript, not only the system prompt (#727).

An Opus 4.8 probe cell (2026-10-13) billed 82% of its input at the full price
(54,654 fresh against 8,094 cache reads): every turn re-sent the whole growing
transcript. A breakpoint on the newest block lets each turn read the previous
ones from cache at 0.1x.
"""
import ast
import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "ansible/roles/interpret/files/interpret-ghidra.py"


@pytest.fixture(scope="module")
def ig():
    name = "_ig_cache_bp"
    try:
        spec = importlib.util.spec_from_file_location(name, SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    except ImportError as e:   # container-only deps
        pytest.skip(f"interpret-ghidra.py needs container deps: {e}")
    yield mod
    sys.modules.pop(name, None)


TRANSCRIPT = [
    {"role": "user", "content": "analyse this"},
    {"role": "assistant", "content": [{"type": "text", "text": "looking"},
                                      {"type": "tool_use", "id": "t1", "name": "x", "input": {}}]},
    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "r1"}]},
]


def _markers(messages):
    return sum(1 for m in messages if isinstance(m.get("content"), list)
               for b in m["content"] if isinstance(b, dict) and "cache_control" in b)


def test_exactly_one_breakpoint_on_the_newest_block(ig):
    out = ig.with_transcript_cache_breakpoint(TRANSCRIPT)
    assert _markers(out) == 1
    assert out[-1]["content"][-1]["cache_control"] == {"type": "ephemeral"}


def test_the_callers_transcript_is_never_modified(ig):
    """Markers left behind would pile up past the API's limit of four."""
    before = repr(TRANSCRIPT)
    ig.with_transcript_cache_breakpoint(TRANSCRIPT)
    assert repr(TRANSCRIPT) == before


def test_turn_after_turn_there_is_still_one_breakpoint(ig):
    msgs = list(TRANSCRIPT)
    for i in range(12):
        sent = ig.with_transcript_cache_breakpoint(msgs)
        assert _markers(sent) == 1, f"turn {i}"
        msgs += [{"role": "assistant", "content": [{"type": "text", "text": f"t{i}"}]},
                 {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                               "content": f"r{i}"}]}]


def test_string_content_becomes_one_marked_text_block(ig):
    out = ig.with_transcript_cache_breakpoint([{"role": "user", "content": "hi"}])
    assert out[-1]["content"] == [{"type": "text", "text": "hi",
                                   "cache_control": {"type": "ephemeral"}}]


def test_an_empty_transcript_is_returned_as_is(ig):
    assert ig.with_transcript_cache_breakpoint([]) == []


def _loop_call():
    tree = ast.parse(SCRIPT.read_text())
    for n in ast.walk(tree):
        if (isinstance(n, ast.Call) and getattr(n.func, "id", "") == "create_message_streaming"
                and any(k.arg == "tools" for k in n.keywords)):
            return tree, n
    raise AssertionError("the loop's create_message_streaming call was not found")


def test_the_loop_sends_the_cached_copy_on_the_cloud_path_only():
    """Structural: the loop is inside main() with a live client. The local backend
    (llama.cpp) keeps its own KV prefix and must get the transcript unmodified."""
    tree, call = _loop_call()
    sent = next(k.value for k in call.keywords if k.arg == "messages")
    assert isinstance(sent, ast.Name) and sent.id == "request_messages"
    assign = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                  and any(isinstance(t, ast.Name) and t.id == "request_messages" for t in n.targets))
    src = ast.unparse(assign.value)
    assert "with_transcript_cache_breakpoint(messages)" in src
    assert "re_backend" in src and "'local'" in src


def test_the_trail_fingerprints_the_content_not_the_marker():
    """The marker moves every turn; hashed in, every cloud turn would read as a
    prefix divergence (#262)."""
    tree = ast.parse(SCRIPT.read_text())
    loop_logs = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                 and getattr(n.func, "id", "") == "log_request_shape"
                 and n.args and isinstance(n.args[0], ast.Constant) and n.args[0].value == "loop"]
    assert loop_logs and all(isinstance(c.args[4], ast.Name) and c.args[4].id == "messages"
                             for c in loop_logs)
