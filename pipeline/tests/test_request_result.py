# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Synthesis must record what it COST, not just what it sent (#299).

`request` records the shape of an outbound call — message count, prefix hashes, tools,
wire format (#262). Loop turns pair that with a `turn` event carrying usage, so their
cost is recoverable. Synthesis emits no turn event, so 2a and 2b were the only legs of
a run whose cost appeared nowhere in the trail.

The consequence was concrete: deciding whether synthesis had budget headroom for #298
meant running `journalctl -u llama-cpp` and hand-reading `eval time = ... / N tokens`,
out of a forensic artifact built precisely so that is unnecessary.

The tests below concentrate on the WIRE SPLIT, because that is where this silently
regresses. 2a receives an Anthropic SDK object (`usage.output_tokens`); 2b posts raw
httpx to /chat/completions and parses a dict (`usage.completion_tokens`). A reader that
only knows the first records 2b as zero tokens — which is the exact failure this issue
is about, reproduced one layer down and just as invisible.
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from stages.interpret import TurnTrail  # noqa: E402

CONTAINER = (ROOT / "ansible" / "roles" / "interpret" / "files"
             / "interpret-ghidra.py")


@pytest.fixture()
def trail(tmp_path):
    return TurnTrail(tmp_path / "t.trail.jsonl", started=0.0)


def _rows(trail) -> list[dict]:
    text = trail.path.read_text(encoding="utf-8") if trail.path.exists() else ""
    return [json.loads(x) for x in text.splitlines() if x.strip()]


# --- orchestrator side ------------------------------------------------------


def test_a_result_event_is_recorded(trail):
    trail.request_result({
        "request_phase": "synth_2a", "wire": "anthropic",
        "usage": {"input_tokens": 5354, "output_tokens": 2362},
        "elapsed_s": 794.9, "stop_reason": "end_turn"})
    rows = _rows(trail)
    assert len(rows) == 1
    r = rows[0]
    assert r["event"] == "request_result"
    assert r["request_phase"] == "synth_2a"
    assert r["usage"]["output_tokens"] == 2362
    assert r["elapsed_s"] == 794.9


def test_wire_is_carried_not_assumed(trail):
    """2a and 2b do not share a wire format, and their numbers are not comparable.

    A reader must be able to tell them apart without inferring it from the phase name
    — the same reason #262 made `wire` a first-class field on request events.
    """
    trail.request_result({"request_phase": "synth_2b", "wire": "openai",
                          "usage": {"input_tokens": 1448, "output_tokens": 584}})
    assert _rows(trail)[0]["wire"] == "openai"


def test_a_missing_usage_does_not_raise(trail):
    """Instrumentation must never break a run it is only observing."""
    trail.request_result({"request_phase": "synth_2a"})
    assert _rows(trail)[0]["usage"] == {}


# --- container side: the wire split ----------------------------------------


def _log_request_result():
    """Load the container's logger without importing the whole module.

    interpret-ghidra.py imports ghidra bindings at module scope and cannot be imported
    in CI, so the function is exec'd from source with a captured `emit`.
    """
    src = CONTAINER.read_text(encoding="utf-8")
    body = src.split("def log_request_result(", 1)[1]
    body = "def log_request_result(" + body.split("\n\ndef ", 1)[0]
    captured: list[dict] = []
    ns = {"Any": object, "emit": captured.append, "sys": sys,
          "print": lambda *a, **k: None}
    exec(compile(body, "<log_request_result>", "exec"), ns)  # noqa: S102
    return ns["log_request_result"], captured


def test_anthropic_response_usage_is_read():
    """2a's shape: an SDK object with input_tokens/output_tokens."""
    fn, captured = _log_request_result()
    resp = SimpleNamespace(
        usage=SimpleNamespace(input_tokens=5354, output_tokens=2362),
        stop_reason="end_turn")
    fn("synth_2a", resp, 794.9)
    assert captured[0]["usage"] == {"input_tokens": 5354, "output_tokens": 2362}
    assert captured[0]["wire"] == "anthropic"


def test_openai_body_usage_is_read():
    """2b's shape: a parsed JSON dict using completion_tokens/prompt_tokens.

    THE regression guard. Reading only the Anthropic shape records 2b at zero tokens
    — silently, and looking exactly like a cheap call.
    """
    fn, captured = _log_request_result()
    body = {"usage": {"prompt_tokens": 1448, "completion_tokens": 584},
            "choices": [{"message": {}}]}
    fn("synth_2b", body, 63.8, wire="openai")
    assert captured[0]["usage"] == {"input_tokens": 1448, "output_tokens": 584}, (
        "the OpenAI leg names its counts completion_tokens/prompt_tokens; reading "
        "only output_tokens/input_tokens records 2b as free")
    assert captured[0]["wire"] == "openai"


def test_a_broken_response_never_raises():
    """An instrument that can kill a 45-minute run is worse than no instrument."""
    fn, captured = _log_request_result()
    fn("synth_2a", object(), 1.0)
    assert captured and captured[0]["usage"] == {}


def test_synthesis_logs_a_result():
    """Guards the call site, not just the helper.

    A logger nothing calls is the failure this issue describes, so the wiring is
    asserted separately from the function.

    Only synth_2a now: #298 removed phase 2b, whose whole job was converting 2a's prose
    into the schema without ever seeing the tool output. The OpenAI-shape branch in
    log_request_result is kept and still tested, because the helper is the general one
    and a future OpenAI leg must not silently record zero.
    """
    src = CONTAINER.read_text(encoding="utf-8")
    assert 'log_request_result("synth_2a"' in src, (
        "synthesis emits a request shape but never its cost — the gap #299 is about")
