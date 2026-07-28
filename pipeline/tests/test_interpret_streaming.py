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


def test_agentic_loop_reports_unhandled_exceptions_instead_of_dying():
    """The protocol is the container's only channel; a silent death tells us nothing.

    The 2026-07-27 qwen@30 probe made 18 good tool calls, then the process exited with
    no final message. The host saw EOF on stdout and could only report "exited without
    final result", with tool_calls_used = 0 because that count rides on that message.
    anthropic.APIError alone does not cover transport errors raised during streaming.
    """
    assert "except Exception as e:  # noqa: BLE001" in TMPL
    assert "Unhandled {type(e).__name__} in agentic loop" in TMPL
    assert "import traceback" in TMPL
    assert 'traceback.format_exc()' in TMPL


def test_client_carries_an_explicit_timeout():
    """Streaming keeps the connection alive but does not raise the 600s SDK default."""
    assert '"timeout": LLM_TIMEOUT_S' in TMPL, (
        "the Anthropic client must set an explicit timeout; the 600s default is what "
        "killed the depth probe")


def _llm_timeout() -> float:
    m = re.search(r"^LLM_TIMEOUT_S\s*=\s*([0-9.]+)", TMPL, re.MULTILINE)
    assert m, "LLM_TIMEOUT_S not found"
    return float(m.group(1))


def _container_timeout() -> int:
    txt = (ROOT / "ansible" / "roles" / "interpret" / "defaults" / "main.yml").read_text()
    m = re.search(r'^interpret_container_timeout:\s*"?(\d+)"?', txt, re.MULTILINE)
    assert m, "interpret_container_timeout not found"
    return int(m.group(1))


def test_llm_timeout_exceeds_the_measured_silent_gap():
    """It must outlast the longest SILENT gap, not the longest request.

    llama-server emits nothing while evaluating a prompt, so the client sees a dead
    socket for the whole prompt-processing phase — and that phase grows with the
    transcript. Measured on probe6 (qwen@30, ~50k-token synthesis prompt): still
    processing at t=1741s with progress 0.73 and ZERO tokens generated, needing ~2500s
    total. The 1800s from #220 cancelled it at 73%.
    """
    assert _llm_timeout() >= 3000, (
        f"LLM_TIMEOUT_S={_llm_timeout()}s is below the measured ~2500s silent gap for a "
        f"50k-token prompt; synthesis will be cancelled mid-pass")


def test_llm_timeout_stays_under_the_container_reaper():
    """The container timeout is the designed reaper (test_eval_timeout_ordering).

    Keeping the client timeout below it means a genuine hang surfaces as a Python error
    with a traceback (#219) instead of an opaque SIGKILL — but it must not be so far
    below that it fires during legitimate work.
    """
    llm, container = _llm_timeout(), _container_timeout()
    assert llm < container, (
        f"LLM_TIMEOUT_S={llm}s must stay under interpret_container_timeout={container}s")
    assert container - llm >= 300, (
        f"only {container - llm}s between client timeout and container reap; leave "
        f"enough margin for the error to be emitted and read")


def test_no_bare_httpx_client_survives():
    """A bare httpx.Client() carries httpx's own default timeout, and when the SDK is
    given a custom http_client THAT client governs the stream read — so `timeout=` on the
    SDK never reaches it.

    This is what killed the qwen@30 probe after 30 successful tool calls:

        httpx.ReadTimeout: timed out   (anthropic/_streaming.py -> httpx iter_raw)

    llama-server sends zero bytes while evaluating a large prompt, which reads as an idle
    socket. Every client must therefore carry an explicit timeout.
    """
    assert "httpx.Client(transport=httpx.HTTPTransport(uds=uds))" not in TMPL, \
        "bare UDS client — must go through _uds_client() for the read timeout"
    # The only bare-looking construction left must carry an explicit Timeout.
    for match in re.finditer(r"httpx\.Client\(", TMPL):
        tail = TMPL[match.start():match.start() + 260]
        assert "timeout" in tail or "transport=httpx.HTTPTransport(uds=uds),\n" in tail, \
            f"httpx.Client without an explicit timeout: {tail[:120]!r}"


def test_read_timeout_is_generous_and_connect_is_not():
    """read covers the silent prompt-eval gap; connect should fail fast on a bad socket."""
    assert "httpx.Timeout(LLM_TIMEOUT_S, connect=30.0)" in TMPL


def test_synthesis_paths_share_the_same_budget():
    """Phase 2b runs on the largest transcript, so it cannot keep the old 600s."""
    assert "timeout=600.0" not in TMPL
    assert "timeout=LLM_TIMEOUT_S" in TMPL


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
    "interpret_max_tool_calls_per_turn": "3",
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
