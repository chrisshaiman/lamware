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


# The three values `llama-server --help` enumerates for this pinned image digest. `auto`
# is NOT among them: it is the help text's "(default: ...)" — what the server does when the
# flag is omitted — and passing it applies `none`.
ACCEPTED = {"none", "deepseek", "deepseek-legacy"}


def _configured_default() -> str:
    match = re.search(r"^llamacpp_reasoning_format:\s*\"?([a-z-]+)\"?", DEFAULTS, re.MULTILINE)
    assert match, "llamacpp_reasoning_format missing from the role defaults"
    return match.group(1)


def test_a_default_is_defined():
    assert _configured_default() != "none", (
        "'none' is the value that produced thinking=0c on every turn")


def test_the_default_is_a_value_the_build_actually_accepts():
    """The bug this file was written for, round two.

    The first version of the default was `auto`, taken from the help text's
    "(default: auto)". That is the unspecified-behaviour description, not an accepted
    value. llama-server DOES NOT REJECT IT — the unit, `podman inspect` and `ps` all
    showed `--reasoning-format auto` while /props reported `none`. Asserting merely
    'not none' passed the whole way through and the setting was silently off.
    """
    configured = _configured_default()
    assert configured in ACCEPTED, (
        f"{configured!r} is not accepted by this build ({sorted(ACCEPTED)}). "
        "llama-server will silently fall back to 'none' rather than failing.")


def test_the_accepted_set_is_declared_for_the_fail_fast_assertion():
    """The role must carry the choices itself, so a typo dies before the 10-minute mmap
    instead of only at the /props check after a full restart."""
    match = re.search(r"^llamacpp_reasoning_format_choices:\s*\[([^\]]+)\]",
                      DEFAULTS, re.MULTILINE)
    assert match, "llamacpp_reasoning_format_choices missing from the role defaults"
    declared = {v.strip().strip("\"'") for v in match.group(1).split(",")}
    assert declared == ACCEPTED, (
        f"declared choices {sorted(declared)} do not match what the build accepts "
        f"{sorted(ACCEPTED)} — the fail-fast guard would pass a value the server rejects, "
        "or reject one it supports")
    assert "llamacpp_reasoning_format_choices" in TASKS, (
        "the choices are declared but never asserted against in tasks/main.yml")


def test_deploy_verifies_reasoning_by_asking_the_model():
    """Runtime assertion, not a static one — #218's lesson: a value can be in the file
    and never reach the process. But it must probe the RIGHT thing (see below)."""
    assert "/v1/chat/completions" in TASKS, (
        "reasoning must be verified by a real request; nothing else distinguishes "
        "'configured' from 'working'")
    assert "reasoning_content" in TASKS


def test_props_is_not_used_as_the_reasoning_oracle():
    """The regression this file exists to prevent, round three.

    `default_generation_settings.params.reasoning_format` reports `none` even on a server
    where reasoning demonstrably works — it describes default PER-REQUEST settings, not
    the chat-time parser used by --jinja + /v1/chat/completions. An assertion reading it
    failed two consecutive CORRECT deploys on 2026-07-29. The obvious "simplification" is
    to put it back, so pin it shut.
    """
    assert "params.reasoning_format" not in TASKS, (
        "/props reasoning_format is not a valid oracle — it reads `none` on a working "
        "server. Verify reasoning with a real completion instead.")


def test_the_failure_message_explains_the_silent_symptom():
    """A mismatch has no visible symptom except empty reasoning records, so the message
    has to say that outright or the next person will not connect the two."""
    block = TASKS[TASKS.find("Assert the server actually surfaces chain-of-thought"):][:900]
    assert "thinking=0" in block or "thinking = 0" in block, (
        "the fail_msg should name the symptom (empty reasoning) so it is diagnosable")


def test_every_sampling_flag_is_still_passed_explicitly():
    """Guards the whole class of bug, not just this instance."""
    for flag in ("--temp", "--top-p", "--top-k", "--min-p", "--presence-penalty",
                 "--seed", "--reasoning-format"):
        assert flag in UNIT, f"{flag} is not passed explicitly — it will take a default"
