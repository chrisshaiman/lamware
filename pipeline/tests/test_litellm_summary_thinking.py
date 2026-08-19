# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The llama.cpp summary alias must disable thinking, or it returns nothing (#429).

qwen3.6 is a thinking model. On llama.cpp's OpenAI leg the thinking is delivered as
`reasoning_content` and `content` comes back EMPTY. Measured against the deployed
proxy on 2026-08-19, identical prompt:

    without enable_thinking:false   content_len=0    finish=length  400 tokens  34.0s
    with    enable_thinking:false   content_len=436  finish=stop     86 tokens   7.1s

The failure mode is the dangerous one. The call returns HTTP 200 with no error, so
the Haiku fallback never fires and the pipeline writes an empty executive summary —
a stage that succeeds and produces nothing, indistinguishable from a sample with
nothing to say. Same class as #411.

Ollama's leg does not behave this way, which is why moving the summary stages onto
llama.cpp looked like a like-for-like swap and was not. It shipped, deployed, and
was caught only because the transport change was explicitly flagged as unverified.

`/no_think` in the prompt does NOT disable it; chat_template_kwargs is the switch
that actually works (#297).
"""
import re
from pathlib import Path

CFG = (Path(__file__).resolve().parents[2] / "ansible" / "roles" / "litellm"
       / "templates" / "config.yaml.j2").read_text(encoding="utf-8")

#: Aliases that answer with prose the pipeline stores verbatim. A thinking model
#: on the OpenAI leg returns empty content for these unless thinking is disabled.
PROSE_ALIASES = ("local-qwen-llamacpp",)


def _entry(alias: str) -> str:
    """The litellm_params for one alias — COMMENTS STRIPPED.

    The prose above an entry discusses the very setting these tests assert on, so a
    naive capture sweeps the next entry's explanatory comment into this one's body
    and reports enable_thinking on an alias that does not set it. Caught by
    test_the_re_alias_is_not_accidentally_silenced failing on a correct config.
    """
    m = re.search(rf'^  - model_name: "{re.escape(alias)}"\n(.*?)(?=^  - model_name:|^\S)',
                  CFG, re.S | re.M)
    assert m, f"{alias} not found in the litellm config template"
    return "\n".join(ln for ln in m.group(1).splitlines()
                     if not ln.lstrip().startswith("#"))


def test_summary_alias_disables_thinking():
    body = _entry("local-qwen-llamacpp")
    assert "chat_template_kwargs" in body, (
        "local-qwen-llamacpp must set chat_template_kwargs; without it llama.cpp "
        "returns empty content and the pipeline writes a blank summary")
    assert re.search(r"enable_thinking:\s*false", body), (
        "local-qwen-llamacpp must set enable_thinking: false")


def test_the_re_alias_is_not_accidentally_silenced():
    """The mirror. -re runs the agentic loop, where thinking is REQUIRED — #285 moved
    it to the anthropic leg precisely so thinking survives tool-calling turns.
    Copying enable_thinking:false onto it would undo that."""
    body = _entry("local-qwen-llamacpp-re")
    assert "enable_thinking" not in body, (
        "local-qwen-llamacpp-re must NOT disable thinking — #285 moved it to the "
        "anthropic leg so thinking survives tool-calling turns")


def test_every_prose_alias_is_covered():
    """A new prose alias added without the switch fails here rather than in production."""
    for alias in PROSE_ALIASES:
        assert re.search(r"enable_thinking:\s*false", _entry(alias)), alias
