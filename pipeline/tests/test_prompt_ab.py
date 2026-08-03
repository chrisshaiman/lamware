# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The prompt A/B probe must produce a comparison that means something.

Built for #260, where the naive readings were all wrong in the same direction:

  - output tokens said "not empty" while the question was whether any of them were
    VISIBLE TEXT rather than an empty thinking block
  - wall-clock said one arm was 17% faster, when generation rate was identical to
    within 0.4% and the whole gap was one arm emitting 406 more tokens

So the properties worth guarding are not "it runs" but: arms differ by exactly the
suffix, the transcript is shared byte-for-byte between them, text and thinking are
reported separately, and rate is reported alongside wall-clock.

The probe imports `anthropic` and the container script, neither of which is importable
here, so the pure functions are exec'd out of the source in isolation.
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
PROBE = ROOT / "ansible" / "roles" / "interpret" / "files" / "prompt_ab.py"
WRAPPER = ROOT / "ansible" / "roles" / "interpret" / "templates" / "run-prompt-ab.sh.j2"


@pytest.fixture(scope="module")
def ns() -> dict:
    """Exec the probe's pure functions without its container-only imports."""
    src = PROBE.read_text()
    # From the first module constant, not from DEFAULT_INIT: load_container_module()
    # takes CONTAINER_SCRIPT as a default argument, which is evaluated at def time, so
    # a slice starting below it raises NameError before any test runs.
    start = src.index("CONTAINER_SCRIPT = ")
    end = src.index("def build_client")
    namespace: dict = {"json": json, "sys": sys, "Any": object,
                       "importlib": __import__("importlib.util").util}
    exec(compile(src[start:end], str(PROBE), "exec"), namespace)  # noqa: S102
    return namespace


class _Block:
    def __init__(self, type_, **kw):
        self.type = type_
        for k, v in kw.items():
            setattr(self, k, v)


class _Resp:
    def __init__(self, blocks, stop="end_turn", in_tok=100, out_tok=50):
        self.content = blocks
        self.stop_reason = stop
        self.usage = type("U", (), {"input_tokens": in_tok, "output_tokens": out_tok})()


AUDIT = [
    {"tool": "decompile_function", "args": {"address": "0x401000"}, "result": {"code": "int main(){}"}},
    {"tool": "get_strings_at", "args": {"address": "0x402000"}, "result": ["evil.example", "cmd.exe"]},
]


# ---------------------------------------------------------------------------
# Transcript rebuild
# ---------------------------------------------------------------------------

def test_every_tool_use_gets_a_matching_tool_result(ns):
    """An unanswered tool_use makes the NEXT request fail outright, not degrade."""
    msgs = ns["rebuild_transcript"](AUDIT)
    uses = [b["id"] for m in msgs if m["role"] == "assistant"
            for b in m["content"] if b["type"] == "tool_use"]
    results = [b["tool_use_id"] for m in msgs if m["role"] == "user"
               and isinstance(m["content"], list)
               for b in m["content"] if b["type"] == "tool_result"]
    assert uses == results, "each tool_use must be answered by its own tool_result id"
    assert len(uses) == len(AUDIT)


def test_transcript_alternates_and_starts_with_the_user(ns):
    msgs = ns["rebuild_transcript"](AUDIT)
    assert msgs[0]["role"] == "user"
    assert [m["role"] for m in msgs] == ["user"] + ["assistant", "user"] * len(AUDIT)


def test_tool_results_carry_the_real_payload(ns):
    """The point of using a real audit log is that the content is real."""
    msgs = ns["rebuild_transcript"](AUDIT)
    blob = json.dumps(msgs)
    assert "evil.example" in blob and "int main(){}" in blob


def test_rebuild_is_deterministic(ns):
    """Both arms must receive a byte-identical transcript or the pairing is void."""
    assert ns["rebuild_transcript"](AUDIT) == ns["rebuild_transcript"](AUDIT)


def test_an_errored_tool_call_still_produces_a_result_block(ns):
    msgs = ns["rebuild_transcript"]([{"tool": "decompile_function", "args": {},
                                      "error": "validation failed"}])
    assert any(b["type"] == "tool_result" for m in msgs if isinstance(m["content"], list)
               for b in m["content"]), "a failed call still needs its tool_result"


# ---------------------------------------------------------------------------
# The distinction #260 turned on
# ---------------------------------------------------------------------------

def test_text_and_thinking_are_counted_separately(ns):
    """The #260 failure was reasoning WITHOUT visible text. Summing them hides it."""
    resp = _Resp([_Block("thinking", thinking="x" * 1654)])
    d = ns["describe"](resp)
    assert d["text_chars"] == 0, "an all-thinking response must report zero TEXT"
    assert d["thinking_chars"] == 1654
    assert d["blocks"] == 1


def test_an_empty_response_is_visible_despite_a_healthy_stop_reason(ns):
    """stop_reason, blocks and tokens all looked fine in the failing case."""
    d = ns["describe"](_Resp([], stop="end_turn", out_tok=1979))
    assert d["text_chars"] == 0
    assert d["stop_reason"] == "end_turn"
    assert d["out_tok"] == 1979, "tokens can be nonzero while text is empty — the trap"


def test_describe_reports_a_real_answer(ns):
    d = ns["describe"](_Resp([_Block("text", text="This is a loader." * 10)]))
    assert d["text_chars"] > 0
    assert "text" in d["block_types"]
    assert d["text_head"].startswith("This is a loader.")


# ---------------------------------------------------------------------------
# Verdict must not repeat #260's original mistake
# ---------------------------------------------------------------------------

def test_verdict_reports_generation_rate_not_just_wall_clock(ns):
    """Wall-clock alone is what produced the bogus '154s -> 115s' reading.

    These two arms differ 20% in wall-clock and 0% in rate — the slower one simply
    emitted more. A verdict showing only wall-clock invites the same wrong conclusion.
    """
    rows = [
        {"arm": "bare", "rep": 1, "wall": 480.0, "text_chars": 4571, "out_tok": 2392},
        {"arm": "+/no_think", "rep": 1, "wall": 400.0, "text_chars": 5417, "out_tok": 1986},
    ]
    out = "\n".join(ns["summarise"](rows, ["bare", "+/no_think"]))
    assert "tok/s" in out, "the verdict must normalise for output length"
    assert "4.98 tok/s" in out and "4.96 tok/s" in out, (
        f"rates should come out near-identical, showing the wall-clock gap is length "
        f"rather than speed. Got:\n{out}")


def test_verdict_counts_empty_responses_per_arm(ns):
    rows = [
        {"arm": "bare", "rep": 1, "wall": 10.0, "text_chars": 0, "out_tok": 5},
        {"arm": "bare", "rep": 2, "wall": 10.0, "text_chars": 900, "out_tok": 300},
    ]
    out = "\n".join(ns["summarise"](rows, ["bare"]))
    assert "empty 1/2" in out


# ---------------------------------------------------------------------------
# Invocation safety and correctness
# ---------------------------------------------------------------------------

def test_wrapper_never_puts_the_key_in_argv():
    """/proc/<pid>/cmdline is world-readable — this is the #238 leak, and the #260
    measurement reintroduced it from an ad-hoc command line."""
    text = WRAPPER.read_text()
    assert "export LITELLM_API_KEY=" in text
    assert not [ln for ln in text.splitlines()
                if "-e LITELLM_API_KEY=" in ln], (
        "forward the key BY NAME (`-e LITELLM_API_KEY`), never inline")


def test_wrapper_targets_the_router_not_the_passthrough():
    """Local models 404 on /anthropic and 200 on the router (#273). Getting this wrong
    fails every arm identically, which reads like a result rather than a config error."""
    text = WRAPPER.read_text()
    assert 'LITELLM_BASE_URL="http://litellm.invalid"' in text
    assert "/anthropic" not in text.split("LITELLM_BASE_URL")[1][:80]


def test_probe_takes_system_and_tools_from_the_container_script():
    """Restating them here would drift, and a drifted prompt makes the arms
    incomparable to production without anything looking wrong."""
    src = PROBE.read_text()
    assert "module.CACHED_SYSTEM" in src and "module.TOOLS" in src
    assert "module.create_message" in src, (
        "use the container's own request path, not a reimplementation")


def test_arms_differ_only_by_the_suffix():
    src = PROBE.read_text()
    assert 'arms = [("bare", base_prompt),' in src, (
        "arm A must be the bare prompt and arm B the same string plus the suffix — "
        "any other construction reintroduces a second variable")
