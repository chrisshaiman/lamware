# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Long-generation calls in the interpret template must stream.

The 2026-07-27 depth probe died at 22 tool calls with "Request timed out". Context was
NOT the limit — llama-server reached 47,596 tokens with truncated = 0. The cause was
latency: one turn spent 503s in prompt eval alone (14,512 tokens at ~29 tok/s), the
request totalled 550s, and the next crossed the SDK's 600s default. llama-server logged
`cancel task`.

interpret-ghidra.py.j2 is a Jinja template, so nothing can import or execute it (#205).
These are static assertions over its text — weaker than real tests, and the reason #205
matters, but they do catch a silent revert to a blocking call.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TMPL = (ROOT / "ansible" / "roles" / "interpret" / "templates"
        / "interpret-ghidra.py.j2").read_text()


def test_streaming_helper_exists():
    assert "def create_message(" in TMPL
    assert "cli.messages.stream(" in TMPL
    assert "get_final_message()" in TMPL


def test_agentic_loop_streams():
    """The loop call is the one that timed out; it must not go back to .create()."""
    assert re.search(r"response = create_message\(\s*client,\s*\n\s*model=current_model,"
                     r"\s*\n\s*max_tokens=max_output_tokens,\s*\n\s*system=CACHED_SYSTEM,"
                     r"\s*\n\s*tools=TOOLS,", TMPL), \
        "the agentic loop must call create_message(), not client.messages.create()"


def test_forced_final_and_conclusion_stream():
    """These run against the LARGEST transcript, so they are the most timeout-prone."""
    assert TMPL.count("final_response = create_message(") == 2, \
        "both forced-final calls must stream"
    assert "concl = create_message(" in TMPL, "phase 2a conclusion must stream"


def test_no_blocking_create_on_the_long_generation_paths():
    """Guard against a partial revert leaving one long path blocking."""
    for pattern in (
        "response = client.messages.create(\n                model=current_model,\n"
        "                max_tokens=max_output_tokens,\n                system=CACHED_SYSTEM,\n"
        "                tools=TOOLS,",
        "final_response = client.messages.create(",
        "concl = client.messages.create(",
    ):
        assert pattern not in TMPL, f"long-generation path still blocking: {pattern[:60]}"


def test_client_carries_an_explicit_timeout():
    """Streaming keeps the connection alive but does not raise the 600s SDK default."""
    assert '"timeout": 1800.0' in TMPL, (
        "the Anthropic client must set an explicit timeout; the 600s default is what "
        "killed the depth probe")


def test_single_shot_paths_are_left_alone():
    """Only the long agentic paths changed — single-shot analysis calls are short and
    were not implicated, so converting them would be unrequested scope."""
    assert "response = ss_client.messages.create(" in TMPL


# The 8 config scalars the template interpolates, all in one dict literal at lines 42-49.
_SUBS = {
    "interpret_model": "claude-sonnet-5",
    "interpret_escalation_threshold": "8",
    "interpret_escalation_model": "claude-opus-5",
    "interpret_max_output_tokens": "16384",
    "interpret_max_tool_calls": "10",
    "interpret_max_imports": "100",
    "interpret_max_strings": "150",
    "interpret_max_string_length": "200",
}


def test_rendered_template_is_valid_python():
    """Syntax gate for a 2,600-line file no test can import.

    Nothing else in CI would catch a syntax error here — it would surface as a failed
    detonation, minutes into a container run. Rendering the 8 scalars and compiling is
    the only executable check available until the file becomes plain Python (#205).
    """
    import py_compile
    import tempfile

    rendered = TMPL
    for key, value in _SUBS.items():
        rendered = rendered.replace(f"{{{{ {key} }}}}", value)

    leftover = re.findall(r"\{\{.*?\}\}|\{%.*?%\}", rendered)
    assert not leftover, f"unsubstituted Jinja — update _SUBS: {leftover[:5]}"

    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                     encoding="utf-8") as fh:
        fh.write(rendered)
        path = fh.name
    try:
        py_compile.compile(path, doraise=True)
    finally:
        Path(path).unlink(missing_ok=True)
