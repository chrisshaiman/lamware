# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Log what we SEND, not just what came back (#262).

The #197 trail recorded the model's replies and nothing about the requests, so
answering "does phase 2a's prompt match the loop's through message k?" meant reading
journalctl, backing a cache-hit count out of rounded progress checkpoints, and guessing
which phase issued which server request from token sizes. The attribution came out wrong
twice before it came out right — from information that existed at request-build time.

These are behavioural tests, not source assertions. The property that matters is what
the hashes DO: a rolling prefix that survives appends, breaks exactly where the prompt
breaks, and never carries prompt content into the trail.

`interpret-ghidra.py` cannot be imported (hyphen, plus module-level anthropic/httpx),
so the request-shape block is exec'd in isolation — which is also the point: these are
pure functions and should be reachable without the container.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ansible" / "roles" / "pipeline" / "files"))

from lamware_eval.trail import compare_requests, first_divergence  # noqa: E402
from stages.interpret import TurnTrail  # noqa: E402

SCRIPT = (ROOT / "ansible" / "roles" / "interpret" / "files" / "interpret-ghidra.py")

# Marker comments delimit the block. A character window would silently truncate the
# moment someone adds a comment above it — the failure mode called out in
# test_interpret_synthesis.py.
_START = "# Request-shape logging (#262)"
_END = "# One budget for every leg of an LLM call."


@pytest.fixture(scope="module")
def shape_ns() -> dict:
    """Exec just the request-shape helpers, with emit() captured rather than printed."""
    src = SCRIPT.read_text()
    assert _START in src and _END in src, "request-shape block markers moved"
    block = src.split(_START, 1)[1].split(_END, 1)[0]
    ns: dict = {"json": json, "hashlib": __import__("hashlib"), "sys": sys,
                "Any": object, "emitted": []}
    ns["emit"] = lambda obj: ns["emitted"].append(obj)
    exec(compile(block, str(SCRIPT), "exec"), ns)  # noqa: S102 - test harness
    return ns


def _msgs(n: int, salt: str = "") -> list[dict]:
    return [{"role": "user" if i % 2 == 0 else "assistant",
             "content": f"message {i}{salt}"} for i in range(n)]


TOOLS = [{"name": "decompile_function", "input_schema": {"type": "object"}}]
SYSTEM = "You are a malware analyst."


# ---------------------------------------------------------------------------
# The rolling-prefix property
# ---------------------------------------------------------------------------

def test_prefix_hashes_align_one_per_message(shape_ns):
    """prefix_hashes[i] must correspond to messages[i], so a diff reports a real index."""
    s = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS, _msgs(5))
    assert len(s["prefix_hashes"]) == 5
    assert len(s["prefix_chars"]) == 5
    assert s["n_messages"] == 5
    assert s["roles"] == "u,a,u,a,u"


def test_identical_requests_hash_identically(shape_ns):
    a = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS, _msgs(4))
    b = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS, _msgs(4))
    assert a["prefix_hashes"] == b["prefix_hashes"]
    assert first_divergence(a, b) is None


def test_appending_a_message_preserves_the_prefix(shape_ns):
    """The core property. Phase 2a appends to the loop's transcript, and #246 was about
    that append being forced to re-evaluate everything before it."""
    loop = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS, _msgs(6))
    a2 = shape_ns["request_shape"]("synth_2a", "m", SYSTEM, TOOLS,
                                   _msgs(6) + [{"role": "user", "content": "summarise"}])
    assert a2["prefix_hashes"][:6] == loop["prefix_hashes"]
    assert first_divergence(loop, a2) is None, (
        "appending must not read as a divergence — that is the healthy case")


def test_changing_message_k_diverges_at_exactly_k(shape_ns):
    base = _msgs(8)
    edited = _msgs(8)
    edited[5] = {"role": "assistant", "content": "DIFFERENT"}
    a = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS, base)
    b = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS, edited)
    assert a["prefix_hashes"][:5] == b["prefix_hashes"][:5]
    assert first_divergence(a, b) == 5


def test_prefix_chars_are_monotonic(shape_ns):
    s = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS, _msgs(6))
    assert s["prefix_chars"] == sorted(s["prefix_chars"])
    assert all(b > a for a, b in zip(s["prefix_chars"], s["prefix_chars"][1:]))


# ---------------------------------------------------------------------------
# The verification #262 asks for by name
# ---------------------------------------------------------------------------

def test_dropping_the_tools_block_diverges_at_message_zero(shape_ns):
    """The #246 shape, which is what this instrument exists to make visible.

    Phase 2a without `tools` changed the prompt at its FRONT — the chat template renders
    tool definitions near the start — so llama.cpp reused nothing after that point and
    re-evaluated the whole transcript: a 31,023-token prompt that reused THREE tokens,
    1,280s of prompt eval, 72% of the run's wall-clock.

    The issue asks for exactly this check: replay the broken shape and confirm the
    reader reports divergence at index 0, visible as a hash mismatch on the very first
    entry rather than something to be derived.
    """
    msgs = _msgs(10)
    good = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS, msgs)
    broken = shape_ns["request_shape"]("synth_2a", "m", SYSTEM, None, msgs)

    assert first_divergence(good, broken) == 0
    assert good["tools_hash"] != broken["tools_hash"]
    assert good["has_tools"] is True and broken["has_tools"] is False


def test_changing_the_system_prompt_also_diverges_at_zero(shape_ns):
    msgs = _msgs(4)
    a = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS, msgs)
    b = shape_ns["request_shape"]("loop", "m", "different system", TOOLS, msgs)
    assert first_divergence(a, b) == 0
    assert a["system_hash"] != b["system_hash"]


# ---------------------------------------------------------------------------
# Chain of custody: shape without content
# ---------------------------------------------------------------------------

def test_no_prompt_content_reaches_the_event(shape_ns):
    """Hashes, not content — the trail is a forensic artefact and prompts carry
    sample-derived data. Copying malware strings into a second file would be a
    regression in exactly the artefact meant to be safe to keep."""
    secret = "EVIL_C2_DOMAIN_do_not_copy_me.example"
    s = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS,
                                  [{"role": "user", "content": secret}])
    blob = json.dumps(s)
    assert secret not in blob
    assert "malware analyst" not in blob, "system prompt text must not be carried either"


def test_logging_never_raises_on_unserialisable_input(shape_ns):
    """Instrumentation must never break the run it instruments."""
    class Exploding:
        def __repr__(self):
            raise RuntimeError("boom")

    shape_ns["emitted"].clear()
    # default=str reaches __repr__ for unknown types; the helper must swallow whatever
    # happens rather than take the run down with it.
    shape_ns["log_request_shape"]("loop", "m", SYSTEM, TOOLS,
                                  [{"role": "user", "content": Exploding()}])
    # Either it emitted something or it logged a failure — what matters is no raise.


def test_emitted_event_is_typed_for_the_orchestrator(shape_ns):
    shape_ns["emitted"].clear()
    shape_ns["log_request_shape"]("loop", "m", SYSTEM, TOOLS, _msgs(3), turn_index=7)
    assert len(shape_ns["emitted"]) == 1
    ev = shape_ns["emitted"][0]
    assert ev["type"] == "request"
    assert ev["phase"] == "loop"
    assert ev["turn_index"] == 7
    assert ev["wire"] == "anthropic"


# ---------------------------------------------------------------------------
# Wire formats are not comparable
# ---------------------------------------------------------------------------

def test_openai_leg_is_tagged_and_not_diffed_against_anthropic(shape_ns):
    """Phase 2b serialises tools differently and sends no system message, so it
    diverges at message 0 against the loop by construction. A reader that compared
    across wire formats would manufacture a prefix bug that is not there — a false
    positive in the tool built to stop false conclusions."""
    msgs = _msgs(3)
    loop = shape_ns["request_shape"]("loop", "m", SYSTEM, TOOLS, msgs)
    b2 = shape_ns["request_shape"]("synth_2b", "m", None,
                                   [{"type": "function", "function": {"name": "x"}}],
                                   msgs, "openai")
    assert loop["wire"] == "anthropic"
    assert b2["wire"] == "openai"

    rows = [{"event": "request", "t": 1, "request_phase": "loop", "wire": "anthropic",
             **loop},
            {"event": "request", "t": 2, "request_phase": "synth_2b", "wire": "openai",
             **b2}]
    out = compare_requests(rows)
    # The 2b row is the first of its wire format, so it is not diffed at all.
    assert "first of this wire format" in out
    assert "diverges at message 0" not in out


# ---------------------------------------------------------------------------
# Orchestrator side
# ---------------------------------------------------------------------------

def test_trail_persists_the_request_event(tmp_path):
    trail = TurnTrail(tmp_path / "t.trail.jsonl", started=0.0)
    trail.request({"phase": "synth_2a", "model": "local-qwen", "wire": "anthropic",
                   "n_messages": 2, "roles": "u,a", "has_tools": True,
                   "system_hash": "aaa", "tools_hash": "bbb",
                   "prefix_hashes": ["h1", "h2"], "prefix_chars": [10, 20]})
    rows = [json.loads(x) for x in
            (tmp_path / "t.trail.jsonl").read_text().splitlines() if x.strip()]
    assert len(rows) == 1
    assert rows[0]["event"] == "request"
    assert rows[0]["request_phase"] == "synth_2a"
    assert rows[0]["prefix_hashes"] == ["h1", "h2"]
    assert rows[0]["wire"] == "anthropic"


def test_reader_reports_prefix_intact_for_an_append():
    """The headline output: 2a reusing the loop's prefix must read as healthy."""
    rows = [
        {"event": "request", "t": 60, "request_phase": "loop", "wire": "anthropic",
         "n_messages": 3, "has_tools": True, "system_hash": "s", "tools_hash": "t",
         "prefix_hashes": ["a", "b", "c"], "prefix_chars": [10, 20, 30]},
        {"event": "request", "t": 120, "request_phase": "synth_2a", "wire": "anthropic",
         "n_messages": 4, "has_tools": True, "system_hash": "s", "tools_hash": "t",
         "prefix_hashes": ["a", "b", "c", "d"], "prefix_chars": [10, 20, 30, 40]},
    ]
    out = compare_requests(rows)
    assert "prefix intact, extends by 1" in out


def test_reader_names_the_tools_block_when_it_is_the_cause():
    """"diverges at message 0" is not actionable on its own — #246 was specifically a
    missing tools block, and the reader should say so rather than leave it to be
    rediscovered."""
    rows = [
        {"event": "request", "t": 60, "request_phase": "loop", "wire": "anthropic",
         "n_messages": 2, "has_tools": True, "system_hash": "s", "tools_hash": "t",
         "prefix_hashes": ["a", "b"], "prefix_chars": [10, 20]},
        {"event": "request", "t": 120, "request_phase": "synth_2a", "wire": "anthropic",
         "n_messages": 2, "has_tools": False, "system_hash": "s", "tools_hash": None,
         "prefix_hashes": ["x", "y"], "prefix_chars": [8, 18]},
    ]
    out = compare_requests(rows)
    assert "diverges at message 0" in out
    assert "tools differ" in out


def test_reader_is_silent_when_the_container_predates_the_feature():
    out = compare_requests([{"event": "turn", "t": 1}])
    assert "predates #262" in out
