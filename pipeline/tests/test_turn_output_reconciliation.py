# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A turn that records nothing must be distinguishable from one that returned nothing.

#283: LiteLLM's openai->anthropic conversion discards `reasoning_content`. llama.cpp
generates it and counts it in `output_tokens`; the Messages response arrives with an
empty thinking block, or no blocks at all. Every layer then behaves correctly on empty
input, and the trail reads as "the model was silent" on turns where it emitted over a
thousand tokens.

Measured on the same prompt, same model, 2026-08-03:

    /v1/chat/completions (OpenAI)     400 output tokens, reasoning_content 1,146 chars
    /v1/messages         (Anthropic)  400 output tokens, EMPTY content array

That gap misled a real analysis: reading the zeros as absence produced the conclusion
"the model contributes 0% of context, so prompt engineering has nothing to work on".

This cannot recover the reasoning — that needs the OpenAI route. It makes the loss
loud instead of silent, which is the difference between a known limitation and a
wrong conclusion.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from stages.interpret import TurnTrail  # noqa: E402


@pytest.fixture()
def trail(tmp_path):
    return TurnTrail(tmp_path / "t.trail.jsonl", started=0.0)


def _row(trail):
    return json.loads(trail.path.read_text(encoding="utf-8").splitlines()[0])


def test_dropped_reasoning_is_recorded_as_a_shortfall(trail):
    """The real shape: 1,255 output tokens, three small tool calls, no text."""
    trail.turn({"turn_index": 13, "stop_reason": "tool_use", "text": "", "thinking": "",
                "tool_calls": [{"name": "decompile_function", "input": '{"name":"FUN_1"}'}],
                "usage": {"output_tokens": 1255},
                "block_types": ["thinking", "tool_use"]})
    row = _row(trail)
    assert row["unaccounted_output_tokens"] > 1000, (
        "a turn billed 1,255 tokens that records ~60 chars must report the shortfall")
    assert row["block_types"] == ["thinking", "tool_use"], (
        "block shape must be recorded — an empty thinking block and no thinking block "
        "are different diagnoses")


def test_a_turn_that_really_was_short_reports_no_shortfall(trail):
    """Must not cry wolf, or the signal is worthless on normal turns."""
    trail.turn({"turn_index": 1, "stop_reason": "end_turn",
                "text": "The sample is a loader." * 20, "thinking": "",
                "tool_calls": [], "usage": {"output_tokens": 120},
                "block_types": ["text"]})
    assert _row(trail)["unaccounted_output_tokens"] == 0


def test_captured_reasoning_counts_as_accounted(trail):
    """Once the transport stops dropping it, the warning must go quiet by itself."""
    trail.turn({"turn_index": 2, "stop_reason": "tool_use", "text": "",
                "thinking": "x" * 2400, "tool_calls": [],
                "usage": {"output_tokens": 1150}, "block_types": ["thinking"]})
    assert _row(trail)["unaccounted_output_tokens"] == 0, (
        "1,150 tokens against 2,400 chars of captured thinking reconciles")


def test_missing_usage_does_not_produce_a_false_shortfall(trail):
    """Older containers send no usage; absence must not read as loss."""
    trail.turn({"turn_index": 3, "stop_reason": "tool_use", "text": "", "thinking": "",
                "tool_calls": [], "usage": {}})
    assert _row(trail)["unaccounted_output_tokens"] == 0


def test_unknown_block_types_are_surfaced(trail):
    """Same class as #280: a discarded block and a discarded message both vanish."""
    trail.turn({"turn_index": 4, "stop_reason": "tool_use", "text": "", "thinking": "",
                "tool_calls": [], "usage": {"output_tokens": 10},
                "block_types": ["reasoning"], "unknown_block_types": ["reasoning"]})
    assert _row(trail)["unknown_block_types"] == ["reasoning"]


def test_emit_turn_collects_block_types_and_flags_unknown_ones():
    """Container side: the shape must be captured where the response is parsed."""
    src = (ROOT / "ansible" / "roles" / "interpret" / "files"
           / "interpret-ghidra.py").read_text(encoding="utf-8")
    fn = src.split("def emit_turn", 1)[1].split("\ndef ", 1)[0]
    assert "block_types.append(btype)" in fn
    assert 'btype not in ("text", "thinking", "redacted_thinking", "tool_use")' in fn, (
        "unrecognised block types must be detected, not silently skipped")
