# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""llama-server must be told how to surface reasoning, or the trail records none.

The unit never passed `--reasoning-format`, so the server ran at its default and
`/props` reported `reasoning_format: none`. Qwen3.6's chain-of-thought therefore never
reached the client as a separate field, and the #197 forensic trail recorded
`thinking=0c` on every turn — with no error anywhere. The capture mechanism was correct;
there was simply nothing to capture.

This is the second flag on this unit to fail that way, after `min_p` silently taking
llama.cpp's 0.05 over Qwen's recommended 0.0. Both were invisible because an unset flag
produces a working server with quietly different behaviour.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ROLE = ROOT / "ansible" / "roles" / "llama-cpp"
UNIT = (ROLE / "templates" / "llama-cpp.service.j2").read_text()
DEFAULTS = (ROLE / "defaults" / "main.yml").read_text()
TASKS = (ROLE / "tasks" / "main.yml").read_text()


def test_the_flag_is_passed_explicitly():
    assert "--reasoning-format {{ llamacpp_reasoning_format }}" in UNIT, (
        "reasoning_format must be passed explicitly; the default silently disables "
        "chain-of-thought capture")


def test_a_default_is_defined():
    match = re.search(r"^llamacpp_reasoning_format:\s*\"?([a-z-]+)\"?", DEFAULTS, re.MULTILINE)
    assert match, "llamacpp_reasoning_format missing from the role defaults"
    assert match.group(1) != "none", (
        "'none' is the value that produced thinking=0c on every turn")


def test_deploy_asserts_the_server_actually_applied_it():
    """Runtime assertion, not a static one — #218's lesson: a value can be in the file
    and never reach the process."""
    assert "reasoning_format" in TASKS
    assert "_llamacpp_props.json.default_generation_settings.params.reasoning_format" in TASKS


def test_the_failure_message_explains_the_silent_symptom():
    """A mismatch has no visible symptom except empty reasoning records, so the message
    has to say that outright or the next person will not connect the two."""
    block = TASKS[TASKS.find("Assert the server is surfacing reasoning"):][:800]
    assert "thinking=0" in block or "thinking = 0" in block, (
        "the fail_msg should name the symptom (empty reasoning) so it is diagnosable")


def test_every_sampling_flag_is_still_passed_explicitly():
    """Guards the whole class of bug, not just this instance."""
    for flag in ("--temp", "--top-p", "--top-k", "--min-p", "--presence-penalty",
                 "--seed", "--reasoning-format"):
        assert flag in UNIT, f"{flag} is not passed explicitly — it will take a default"
