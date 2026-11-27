# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Stored assistant text keeps the breaks between tool rounds (2026-11-27).

The model writes text, calls tools, then writes more. The live panel shows each
stretch as its own block; the stored message concatenated them, so a reloaded
session read "simultaneously.Very revealing". join_segment is the rule the
event_stream applies per token.
"""
from app.routers.investigate import join_segment


def _store(events):
    stored, after_tool = "", False
    for kind, text in events:
        if kind == "token":
            stored, after_tool = join_segment(stored, text, after_tool), False
        else:
            after_tool = True
    return stored


def test_text_after_a_tool_call_starts_a_new_paragraph():
    events = [("token", "Let me gather data "), ("token", "simultaneously."), ("tool", ""),
              ("tool", ""), ("token", "Very revealing."), ("tool", ""), ("token", "Excellent.")]
    assert _store(events) == "Let me gather data simultaneously.\n\nVery revealing.\n\nExcellent."


def test_tokens_within_one_stretch_join_as_streamed():
    assert _store([("token", "in par"), ("token", "allel.")]) == "in parallel."


def test_no_leading_break_when_a_turn_starts_with_a_tool():
    assert _store([("tool", ""), ("token", "Result:")]) == "Result:"


def test_an_existing_paragraph_break_is_not_doubled():
    assert _store([("token", "Done.\n\n"), ("tool", ""), ("token", "Next.")]) == "Done.\n\nNext."
