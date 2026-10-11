# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Phase 2a stops once its reasoning has looped well past the salvage's cut point (#761).

Phorpiex 13464460 v0 (deterministic): ~5.5 KB of analysis, then 977 lines of
"- T#### (...) - Not seen" to the 16,384-token cap, about 38 of the cell's 47
minutes. #762 made the salvage discard everything after the loop starts, so
generating it bought nothing. Behavioural: a fake streaming client replays
event sequences into the real function.
"""
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "ansible/roles/interpret/files/interpret-ghidra.py"
ANALYSIS = ("The sample sends mail over raw sockets.\n"
            "- T1071.001 (Web Protocols) - HTTP fetch\n"
            "- T1105 (Ingress Tool Transfer) - download\n") * 20
NAMES = ["Data Encoding", "Rootkit", "BITS Jobs", "Native API", "Time Sources"]


@pytest.fixture(scope="module")
def ig():
    name = "_ig_stop_repetition"
    try:
        spec = importlib.util.spec_from_file_location(name, SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    except ImportError as e:   # container-only deps
        pytest.skip(f"interpret-ghidra.py needs container deps: {e}")
    yield mod
    sys.modules.pop(name, None)


class FakeStream:
    def __init__(self, events, final):
        self.events, self.final, self.consumed, self.closed = events, final, 0, False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True

    def __iter__(self):
        for e in self.events:
            self.consumed += 1
            yield e

    def get_final_message(self):
        return self.final


def _client(stream):
    return NS(messages=NS(stream=lambda **kw: stream))


def _events(chunks, text=None):
    start = NS(type="message_start",
               message=NS(usage=NS(input_tokens=10269, output_tokens=0,
                                   cache_creation_input_tokens=0, cache_read_input_tokens=1873)))
    ev = [start] + [NS(type="content_block_delta", delta=NS(type="thinking_delta", thinking=c))
                    for c in chunks]
    if text:
        ev.append(NS(type="content_block_delta", delta=NS(type="text_delta", text=text)))
    return ev


def _loop_lines(n):
    return [f"- T{1132 + i} ({NAMES[i % len(NAMES)]}) - Not seen\n" for i in range(n)]


def test_a_looping_2a_is_stopped_early(ig):
    chunks = [ANALYSIS] + _loop_lines(1000)
    s = FakeStream(_events(chunks), final=None)
    msg = ig.create_message_until_repetition(_client(s))
    assert msg.stop_reason == "repetition"
    assert s.closed
    assert s.consumed < 400, f"read {s.consumed} of {len(chunks) + 1} events before stopping"
    assert msg.content[0].thinking.startswith(ANALYSIS)
    assert msg.usage.input_tokens == 10269 and msg.usage.output_tokens == s.consumed - 1


def test_the_stopped_reasoning_salvages_to_the_analysis(ig):
    s = FakeStream(_events([ANALYSIS] + _loop_lines(1000)), final=None)
    out = ig.salvage_reasoning(ig.create_message_until_repetition(_client(s)))
    assert "Ingress Tool Transfer" in out and "Rootkit" not in out


def test_a_run_without_a_loop_returns_the_servers_message_unchanged(ig):
    final = NS(content=[NS(type="text", text="prose")], stop_reason="end_turn", usage=None)
    s = FakeStream(_events([ANALYSIS] * 5, text="prose"), final=final)
    assert ig.create_message_until_repetition(_client(s)) is final
    assert s.consumed == len(s.events)


def test_a_short_loop_below_the_stop_line_runs_to_completion(ig):
    """A run of 8+ lines that ends before REPETITION_STOP_LINES is not stopped:
    the salvage still cuts it, but the model may yet write prose."""
    final = NS(content=[], stop_reason="end_turn", usage=None)
    s = FakeStream(_events([ANALYSIS] + _loop_lines(40) + [ANALYSIS]), final=final)
    assert ig.create_message_until_repetition(_client(s)) is final


def test_once_prose_starts_nothing_is_stopped(ig):
    final = NS(content=[], stop_reason="max_tokens", usage=None)
    events = _events([ANALYSIS], text="The family is") + _events(_loop_lines(1000))[1:]
    s = FakeStream(events, final=final)
    assert ig.create_message_until_repetition(_client(s)) is final


def test_phase_2a_uses_the_repetition_aware_call():
    import ast
    tree = ast.parse(SCRIPT.read_text())
    fn = next(n for n in ast.walk(tree)
              if isinstance(n, ast.FunctionDef) and n.name == "local_synthesize")
    calls = {getattr(n.value.func, "id", None) for n in ast.walk(fn)
             if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call)
             and any(isinstance(t, ast.Name) and t.id == "concl" for t in n.targets)}
    assert calls == {"create_message_until_repetition"}, calls
