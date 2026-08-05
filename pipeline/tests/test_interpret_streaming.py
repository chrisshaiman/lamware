# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Long-generation calls in the interpret template must stream.

The 2026-07-27 depth probe died at 22 tool calls with "Request timed out". Context was
NOT the limit — llama-server reached 47,596 tokens with truncated = 0. The cause was
latency: one turn spent 503s in prompt eval alone (14,512 tokens at ~29 tok/s), the
request totalled 550s, and the next crossed the SDK's 600s default. llama-server logged
`cancel task`.

These are static assertions over the script's text. They predate #205, when the file
was a Jinja template and could not be imported at all; it is now plain Python
(roles/interpret/files/interpret-ghidra.py). Kept as source assertions because what
they pin is the SHAPE of the call — that it streams — which importing would not check.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TMPL = (ROOT / "ansible" / "roles" / "interpret" / "files"
        / "interpret-ghidra.py").read_text()


def test_streaming_helper_exists():
    assert "def create_message(" in TMPL
    assert "cli.messages.stream(" in TMPL
    assert "get_final_message()" in TMPL


def test_agentic_loop_streams():
    """The loop call is the one that timed out; it must not go back to .create().

    Asserts the PROPERTY (it streams) rather than one spelling. #197 switched this call
    to create_message_streaming(), which streams identically and additionally emits a
    progress heartbeat — the original regex pinned the exact call text and failed on a
    change that preserved everything it was protecting.
    """
    assert re.search(r"response = create_message(_streaming)?\(\s*\n?\s*client,"
                     r"(\s*\n\s*turn_index=tool_calls_used,)?"
                     r"\s*\n\s*model=current_model,"
                     r"\s*\n\s*max_tokens=max_output_tokens,\s*\n\s*system=CACHED_SYSTEM,"
                     r"\s*\n\s*tools=TOOLS,", TMPL), \
        "the agentic loop must stream, not call client.messages.create()"


def test_the_loop_emits_a_progress_heartbeat():
    """llama-server emits nothing during prompt eval, so a long turn looks like a hang.

    The 2026-07-28 synthesis ran 90 minutes and was indistinguishable from a stall until
    the container log was parsed by hand.
    """
    assert "def create_message_streaming(" in TMPL
    assert '"type": "stream"' in TMPL
    assert "STREAM_HEARTBEAT_TOKENS" in TMPL


def test_a_wall_clock_heartbeat_covers_prompt_evaluation():
    """The token heartbeat covers only GENERATION — the wrong phase.

    Measured: a 62k synthesis spent ~83 of 90 minutes in prompt eval before emitting a
    token, and a qwen@10 cell left the trail silent for 20 of 33 minutes. A token-counted
    heartbeat cannot fire during either, so it did not solve the problem it was added for.
    """
    assert "class _WaitHeartbeat" in TMPL
    assert "WAIT_HEARTBEAT_SECONDS" in TMPL
    assert '"waiting": True' in TMPL, "waiting ticks must be distinguishable from generation"
    assert "with _WaitHeartbeat(turn_index)" in TMPL, \
        "the wait heartbeat must wrap the streaming call"


def test_the_wait_heartbeat_stops_once_tokens_arrive():
    """Otherwise the trail shows 'waiting' while the model is visibly generating."""
    assert "waiting.stop()" in TMPL


def test_concurrent_emits_are_serialised():
    """The heartbeat emits from a background thread while the main thread may also emit.

    The protocol has no framing beyond the newline, so two interleaved writes produce a
    corrupt line the orchestrator cannot parse.
    """
    assert "_EMIT_LOCK = threading.Lock()" in TMPL
    assert "with _EMIT_LOCK:" in TMPL


def test_the_heartbeat_thread_cannot_hold_the_process_open():
    assert "daemon=True" in TMPL


def test_the_loop_emits_the_models_reasoning():
    """#197: the orchestrator cannot see text or thinking — only the container can."""
    assert "def emit_turn(" in TMPL
    assert '"type": "turn"' in TMPL
    assert "emit_turn(response, turn_index=tool_calls_used)" in TMPL
    for field in ('"text"', '"thinking"', '"tool_calls"', '"stop_reason"'):
        assert field in TMPL, f"turn record missing {field}"


def test_redacted_thinking_is_recorded_as_having_existed():
    """Encrypted reasoning cannot be shown, but omitting it silently would imply the
    model reasoned less than it did — which is misleading in a chain-of-custody record."""
    assert "[redacted_thinking block]" in TMPL


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
    """Synthesis runs on the largest transcript of the run, so it cannot keep the old
    600s default — a bare client here dies mid-prompt-eval for the same reason the
    agentic client did.

    The check moved from `timeout=LLM_TIMEOUT_S` to the client kwarg because #298
    removed phase 2b and with it the separate httpx client that carried that exact
    string. The PROPERTY is unchanged — synthesis shares the agentic budget — but it is
    now inherited from the one Anthropic client rather than set on a second one. A
    literal-string assertion would have gone green by matching a line in an unrelated
    path, which is worse than failing.
    """
    assert "timeout=600.0" not in TMPL
    assert '"timeout": LLM_TIMEOUT_S' in TMPL, (
        "the Anthropic client must carry the long budget; synthesis now shares it "
        "rather than owning a second client (#298)")


def test_single_shot_paths_are_left_alone():
    """Only the long agentic paths changed — single-shot analysis calls are short and
    were not implicated, so converting them would be unrequested scope."""
    assert "response = ss_client.messages.create(" in TMPL


# The render-and-compile harness that used to live here has been REMOVED, not relocated
# wholesale.
#
# It substituted nine Jinja scalars into the template, asserted no `{{ }}` survived, and
# compiled the result — the only executable check possible on a file nothing could import.
# #205 made the file plain Python, at which point the substitution loop matched nothing,
# the leftover-Jinja assertion trivially held, and the test passed while checking nothing.
# A vacuous test is worse than a missing one: it reports green.
#
# The surviving obligation — "this file must compile" — is now a direct py_compile in
# test_interpret_config_defaults.py::test_the_script_compiles_standalone, which also pins
# that no Jinja marker has crept back in.
