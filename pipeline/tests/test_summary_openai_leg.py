# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Local summaries must take LiteLLM's OpenAI leg, not the /v1/messages router.

qwen3.6 is a thinking model and NOTHING disables that over /v1/messages. Measured
end to end 2026-08-19 against the deployed proxy, identical prompt, max_tokens=400:

    llama-server DIRECT  /v1/messages       + chat_template_kwargs   496 chars,  9.0s
    llama-server DIRECT  /chat/completions  + chat_template_kwargs   496 chars,  7.9s
    LiteLLM  /chat/completions  kwarg in litellm_params              436 chars,  7.1s
    LiteLLM  /v1/messages       kwarg in litellm_params                0 chars, 400 tok
    LiteLLM  /v1/messages       kwarg in extra_body                    0 chars, 400 tok
    LiteLLM  /v1/messages       kwarg in the request body              0 chars, 400 tok
    LiteLLM  /v1/messages       anthropic thinking:{type:disabled}     0 chars, 400 tok

llama.cpp honours the kwarg on BOTH its endpoints; LiteLLM's anthropic translator
drops it, correctly — `chat_template_kwargs` is not in the Anthropic schema, so the
mapping layer has nowhere to put it. No config change can fix that, which is why
this is a transport choice in code.

The failure it prevents is the silent kind: the model spent its whole budget
thinking, returned content carrying no text block, and the pipeline stored an EMPTY
executive summary after a 300s timeout — HTTP 200 throughout, so the Haiku fallback
never fired. Succeeds-and-produces-nothing, the same shape as #411.

Two earlier attempts at this were verified against `/v1/chat/completions`, which the
summary stage never calls, and both passed while production was broken. These tests
assert the ROUTE, because that was the thing being got wrong.
"""
import re
from pathlib import Path

SRC = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "interpret"
       / "files" / "interpret-ghidra.py").read_text(encoding="utf-8")


def _code_only(src: str) -> str:
    """Strip comments and docstring bodies.

    An absence assertion must not be satisfiable by the prose explaining the
    absence. The comment in summarize_via_openai_leg says a bare `httpx.Client()`
    would route nowhere — which made the very test asserting no bare client fail
    against correct code. Same trap test_dead_controls.py documents.
    """
    out, in_doc = [], False
    for ln in src.splitlines():
        s = ln.strip()
        if s.startswith(('"""', "r\"\"\"")) or s.endswith('"""'):
            if s.count('"""') == 1:
                in_doc = not in_doc
            continue
        if in_doc or s.startswith("#"):
            continue
        out.append(ln)
    return "\n".join(out)


def _func(name: str) -> str:
    m = re.search(rf"^def {re.escape(name)}\(.*?(?=^def |\Z)", SRC, re.S | re.M)
    assert m, f"{name} not found"
    return m.group(0)


def test_helper_posts_to_chat_completions_not_messages():
    body = _func("summarize_via_openai_leg")
    assert "/chat/completions" in body, "the OpenAI leg must POST /chat/completions"
    assert "/v1/messages" not in body, (
        "the summary helper must not use /v1/messages — that is the route that "
        "silently returns thinking and no text")


def test_helper_disables_thinking_in_the_request():
    body = _func("summarize_via_openai_leg")
    assert re.search(r'"chat_template_kwargs":\s*\{"enable_thinking":\s*False\}', body), (
        "the request must carry chat_template_kwargs enable_thinking False; the "
        "alias-level copy alone is one config edit away from a 300s timeout")


def test_both_prose_stages_route_local_models_to_the_openai_leg():
    """run_summarize and the plain_english branch both had the defect."""
    assert "summarize_via_openai_leg" in _func("run_summarize"), "run_summarize"
    assert SRC.count("summarize_via_openai_leg(") >= 3, (
        "expected the helper definition plus a call in each prose stage")


def test_local_alias_is_recognised_and_cloud_is_not():
    prefixes = re.search(r"_OPENAI_LEG_SUMMARY_PREFIXES\s*=\s*\(([^)]*)\)", SRC)
    assert prefixes, "_OPENAI_LEG_SUMMARY_PREFIXES not found"
    names = re.findall(r'"([^"]+)"', prefixes.group(1))
    assert "local-qwen-llamacpp" in names
    assert not any(n.startswith("claude") for n in names), (
        "cloud models must keep the anthropic client — they have no chat template "
        "to configure and the passthrough is where prompt caching lives")


def test_transport_failure_is_reported_not_swallowed():
    """An empty summary that reads as 'nothing to say' is the defect itself."""
    body = _func("run_summarize")
    assert "httpx.HTTPError" in body, (
        "run_summarize must catch the OpenAI leg's transport errors, or an httpx "
        "failure escapes past the anthropic-only handler")


def test_prose_stages_use_the_openai_base_not_the_router_base():
    """LITELLM_ROUTER_BASE_URL is `http://litellm.invalid` and serves /v1/messages;
    LITELLM_OPENAI_BASE_URL is `http://litellm.invalid/v1` and serves
    /chat/completions. The first draft passed the router base, which would have
    POSTed to `/chat/completions` on the messages root — the fix would have looked
    applied and changed nothing."""
    # Exclude the definition, whose own parameter list matches the call pattern.
    body = "\n".join(ln for ln in SRC.splitlines()
                     if not ln.lstrip().startswith("def summarize_via_openai_leg"))
    calls = re.findall(r"summarize_via_openai_leg\(\s*([^,]+),\s*([^,]+),", body)
    assert calls, "no calls to summarize_via_openai_leg found"
    for client_arg, base_arg in calls:
        assert "router_base" not in base_arg, (
            f"summary call passes {base_arg.strip()}; it must pass the OpenAI base")
        assert "synth_openai_base" in base_arg or "openai_base" in base_arg, base_arg


def test_helper_never_constructs_its_own_client():
    """--network=none: LiteLLM is reachable only over the Unix socket, so a client
    built here would route nowhere and carry httpx's default timeout."""
    body = _code_only(_func("summarize_via_openai_leg"))
    assert "httpx.Client(" not in body, (
        "the helper must take a caller-supplied UDS-aware client")
