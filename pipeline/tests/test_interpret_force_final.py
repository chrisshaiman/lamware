# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""force_final must close out EVERY tool_use block, not just the one it lands on.

The agentic loop's invariant is stated at the deferral branch: *every* tool_use
block must receive a tool_result, or the next request is malformed. Two of the
three early-exit branches honoured it. `force_final` did not — it appended a
tool_result for the block it happened to be on and then left the loop to build
the salvage request:

    if result_msg.get("type") == "force_final":
        tool_results_content.append({... "tool_use_id": block.id ...})   # only this one
        messages.append({"role": "user", "content": tool_results_content})

The assistant message appended earlier in the turn still carries every block's
tool_use id, so any block after the current one was left orphaned. The Messages
API rejects that transcript with a 400 (*"tool_use ids were found without
tool_result blocks immediately after"*), and the `except anthropic.APIError`
handler writes

    {"error": "Claude API error on forced final: ..."}

as the run's analysis. So the branch that exists to SALVAGE a timed-out run was
the branch that lost it.

Conditional, which is why it survived: it needs two or more tool_use blocks in
the turn AND the signal to arrive before the last one. force_final landing on
the final block of a batch produces a well-formed transcript, and a
one-tool-per-turn run never reproduces it at all.

This matters for #240. Reserving a synthesis window makes force_final fire more
reliably and earlier — straight into this path — so "a run that exhausts the
loop budget still emits a complete analysis" cannot hold while the salvage
request is itself malformed.

The tests drive the real `main()` with a scripted orchestrator and inspect the
transcript actually handed to the client. Asserting on the source text would not
distinguish "results for all blocks" from "a result for one block".
"""
import importlib.util
import io
import json
import sys
import types
from pathlib import Path

import anthropic
import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = (ROOT / "ansible" / "roles" / "interpret" / "files"
          / "interpret-ghidra.py")

pytest.importorskip("anthropic", reason="pip install './pipeline[test]'")


def _orphaned_ids(request):
    """tool_use ids in the transcript with no matching tool_result."""
    uses, results = set(), set()
    for message in request["messages"]:
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if part.get("type") == "tool_use":
                uses.add(part["id"])
            elif part.get("type") == "tool_result":
                results.add(part["tool_use_id"])
    return uses - results


class _MalformedTranscript(anthropic.APIError):
    """What the Messages API returns for an orphaned tool_use id: a 400.

    Subclasses the real APIError so the script's own `except anthropic.APIError`
    handler catches it, which is the path that turned a salvaged run into an
    error string.
    """

    def __init__(self, message):
        Exception.__init__(self, message)
        self.message = message


class _Block:
    def __init__(self, **kw):
        self.__dict__.update(kw)


class _Message:
    def __init__(self, content, stop_reason):
        self.content = content
        self.stop_reason = stop_reason
        self.model = "stub-model"
        self.usage = types.SimpleNamespace(input_tokens=10, output_tokens=5)


class _Stream:
    """Minimal stand-in for the SDK's streaming context manager."""

    def __init__(self, message):
        self._message = message

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        return iter(())          # no deltas; the loop only needs the final message

    def get_final_message(self):
        return self._message


class _Messages:
    """Stands in for the SDK, and enforces the one rule that matters here.

    The server-side check is the whole point of this issue, so the stub applies
    it: a transcript with a tool_use id and no matching tool_result is rejected,
    exactly as the Messages API rejects it. Without that, a stub would happily
    answer the malformed request and every assertion below would pass against
    the unfixed script.
    """

    def __init__(self, first_turn_blocks, recorder):
        self._blocks = first_turn_blocks
        self._recorder = recorder
        self.calls = 0

    def stream(self, **kwargs):
        self._recorder.append(kwargs)
        self.calls += 1
        orphaned = _orphaned_ids(kwargs)
        if orphaned:
            raise _MalformedTranscript(
                f"messages.{len(kwargs['messages'])}: `tool_use` ids were found "
                f"without `tool_result` blocks immediately after: {sorted(orphaned)}")
        if self.calls == 1:
            return _Stream(_Message(self._blocks, "tool_use"))
        return _Stream(_Message([_Block(type="text", text='{"summary": "salvaged"}')],
                                "end_turn"))


def _tool_use(block_id):
    return _Block(type="tool_use", id=block_id, name="decompile_function",
                  input={"name": block_id})


def _drive(monkeypatch, orchestrator_messages, first_turn_blocks):
    """Run the real main() against a scripted orchestrator.

    Returns (requests, emitted) — every kwargs dict passed to messages.stream,
    and every JSON line the script wrote back to the orchestrator.
    """
    requests: list[dict] = []

    name = "_interpret_force_final_under_test"
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    try:
        spec.loader.exec_module(mod)

        monkeypatch.setattr(
            mod.anthropic, "Anthropic",
            lambda **kw: types.SimpleNamespace(
                messages=_Messages(first_turn_blocks, requests)))
        monkeypatch.setenv("LITELLM_API_KEY", "test-key")
        monkeypatch.setattr(
            mod.sys, "stdin",
            io.StringIO("".join(json.dumps(m) + "\n" for m in orchestrator_messages)))
        out = io.StringIO()
        monkeypatch.setattr(mod.sys, "stdout", out)

        with pytest.raises(SystemExit):
            mod.main()

        emitted = [json.loads(ln) for ln in out.getvalue().splitlines()
                   if ln.strip().startswith("{")]
        return requests, emitted
    finally:
        sys.modules.pop(name, None)


INIT = {
    "type": "init",
    "ghidra_data": {"program": {"name": "sample.exe"}, "functions": [],
                    "strings": [], "imports": []},
    "config": {"re_backend": "cloud", "model": "stub-model",
               "max_tool_calls": 20, "max_tool_calls_per_turn": 3},
}
FORCE = {"type": "force_final", "reason": "interpret timeout"}


def test_force_final_on_an_early_block_leaves_no_orphaned_tool_use(monkeypatch):
    """THE bug. force_final arrives while the loop is on the FIRST of two blocks;
    the second was never dispatched and used to get no tool_result at all."""
    requests, _ = _drive(monkeypatch, [INIT, FORCE],
                         [_tool_use("tu_A"), _tool_use("tu_B")])
    assert len(requests) == 2, "expected the turn plus the salvage request"
    orphaned = _orphaned_ids(requests[-1])
    assert not orphaned, (
        f"tool_use ids with no tool_result in the salvage request: {sorted(orphaned)}. "
        f"The Messages API rejects this transcript with a 400, and the run's analysis "
        f"becomes the error string instead of the synthesis it timed out producing.")


def test_the_forced_run_still_produces_an_analysis(monkeypatch):
    """The point of the branch. A malformed salvage request turned every forced
    run into {"error": "Claude API error on forced final: ..."}."""
    _, emitted = _drive(monkeypatch, [INIT, FORCE],
                        [_tool_use("tu_A"), _tool_use("tu_B")])
    finals = [m for m in emitted if m.get("type") == "final"]
    assert finals, f"no final emitted: {emitted}"
    analysis = finals[-1]["analysis"]
    assert "error" not in analysis, f"forced run lost its analysis: {analysis}"


def test_every_abandoned_block_is_told_why(monkeypatch):
    """The skipped blocks are reported as errors carrying the orchestrator's
    reason, so the model can tell 'not run' from 'ran and returned nothing'."""
    requests, _ = _drive(monkeypatch, [INIT, FORCE],
                         [_tool_use("tu_A"), _tool_use("tu_B")])
    results = [part
               for message in requests[-1]["messages"]
               if isinstance(message.get("content"), list)
               for part in message["content"]
               if part.get("type") == "tool_result"]
    assert len(results) == 2, f"expected a result per block, got {results}"
    for part in results:
        assert part.get("is_error") is True
        assert "interpret timeout" in part["content"], (
            "the orchestrator's reason should reach the model, not a generic string")


def test_force_final_on_the_last_block_is_unaffected(monkeypatch):
    """The case that always worked, pinned so a fix cannot regress it — and the
    reason a one-tool-per-turn run never reproduced the bug."""
    requests, _ = _drive(monkeypatch, [INIT, FORCE], [_tool_use("tu_only")])
    assert not _orphaned_ids(requests[-1])


def test_the_branch_sweeps_the_remaining_blocks(monkeypatch):
    """Structural guard: the fix depends on indexing into tool_use_blocks from
    the current position. Reverting to `block.id` alone restores the bug for any
    turn the single-block test above cannot see."""
    source = SCRIPT.read_text(encoding="utf-8")
    branch_start = source.index('if result_msg.get("type") == "force_final":')
    branch = source[branch_start:branch_start + 1200]
    assert "tool_use_blocks[block_idx:]" in branch, (
        "force_final must close out every remaining block, not just the current one")
    assert "for block_idx, block in enumerate(tool_use_blocks):" in source, (
        "the loop must expose its index for the sweep above to be possible")
