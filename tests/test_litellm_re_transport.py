# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The local RE aliases must reach llama-server as ANTHROPIC, not OpenAI (#285).

llama-server implements `/v1/messages` natively and fills thinking blocks on it.
Routing through the OpenAI shape asked LiteLLM to translate a format the backend
already speaks, and that translation dropped the model's entire reasoning: the same
request returned `content: []` with `usage.output_tokens: 80` — eighty tokens
generated, none delivered. That empty array is what #283 recorded as "the trail
contains ZERO model output on tool-calling turns".

Measured 2026-08-04 against llama-server directly, no LiteLLM in the path:

    thinking    568 chars, returned alongside a tool_use block in one response
    tool calls  stop_reason=tool_use, correct name and arguments
    KV cache    second call on an identical prefix: input=4, cache_read=1220

Every failure this file guards is SILENT, which is the only reason static checks
earn their place here:

  - a `/v1` suffix on the anthropic base yields POST /v1/v1/messages -> 404, at
    request time, hours into a run
  - a `seed:` on an anthropic entry is swallowed by `drop_params: true` with no
    error, which is how #292 went unnoticed for a week
  - a provider reverted to `openai/` looks completely normal and silently resumes
    discarding the reasoning

None of these fail a deploy. They fail a measurement, later, invisibly.
"""
import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
CONFIG = _ROOT / "ansible" / "roles" / "litellm" / "templates" / "config.yaml.j2"
DEFAULTS = _ROOT / "ansible" / "roles" / "litellm" / "defaults" / "main.yml"

# Alias entries whose transport this file governs: the agentic RE model and its
# seed-named variants. The summary models on Ollama are deliberately out of scope.
#
# Split on `- model_name:` boundaries rather than matching a fixed indent run. The
# first draft used `(?:      .*\n)+` and matched NOTHING, because the line after
# model_name is `    litellm_params:` at four spaces — the same brittle-parsing trap
# test_interpret_synthesis.py records for fixed character windows. A guard that
# silently matches zero entries reports success while checking nothing, which is the
# exact failure this file exists to prevent.
def _re_entries() -> dict[str, str]:
    """Alias name -> its litellm_params lines ONLY.

    Comments are excluded deliberately. The first draft returned the whole chunk up
    to the next entry, which swept in the explanatory comment block below the base
    alias — so the `seed:` guard matched the prose EXPLAINING that no seed is set and
    failed on a correct config. A guard that reads comments is testing documentation
    while claiming to test configuration.
    """
    text = CONFIG.read_text(encoding="utf-8")
    entries: dict[str, str] = {}
    for chunk in text.split("- model_name:")[1:]:
        name = re.match(r'\s*"([^"]+)"', chunk)
        if not name or not name.group(1).startswith("local-qwen-llamacpp-re"):
            continue
        params: list[str] = []
        for line in chunk.splitlines()[1:]:
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("{%"):
                continue
            if not line.startswith("    "):  # dedented out of this entry
                break
            params.append(line)
        entries[name.group(1)] = "\n".join(params)
    return entries


def test_the_re_entries_are_still_there():
    entries = _re_entries()
    assert "local-qwen-llamacpp-re" in entries, (
        f"the base RE alias vanished; found {sorted(entries)}")
    assert len(entries) >= 2, "expected the base alias plus seed-named variants"


@pytest.mark.parametrize("alias", sorted(_re_entries()))
def test_every_re_alias_uses_the_anthropic_provider(alias):
    """An `openai/` provider here silently resumes dropping the reasoning."""
    body = _re_entries()[alias]
    assert 'model: "anthropic/' in body, (
        f"{alias} is not on the anthropic provider. llama-server speaks "
        f"/v1/messages natively; going via OpenAI makes LiteLLM translate a format "
        f"the backend already speaks and discard the thinking blocks (#285).")


@pytest.mark.parametrize("alias", sorted(_re_entries()))
def test_no_re_alias_carries_a_v1_suffix(alias):
    """`.../v1` + LiteLLM's own `/v1/messages` = `/v1/v1/messages` = 404.

    Not a deploy failure — a request-time one, hours into a run.
    """
    body = _re_entries()[alias]
    m = re.search(r"api_base: \"([^\"]+)\"", body)
    assert m, f"{alias} has no api_base"
    assert "/v1" not in m.group(1), (
        f"{alias} api_base is {m.group(1)!r}; LiteLLM appends /v1/messages for "
        f"anthropic providers, so a /v1 suffix produces /v1/v1/messages")


@pytest.mark.parametrize("alias", sorted(_re_entries()))
def test_no_re_alias_claims_a_seed_it_cannot_apply(alias):
    """`seed:` on an anthropic entry is discarded by `drop_params: true`, silently.

    llama-server ignores `seed` on /v1/messages outright — measured 2026-08-04,
    seeds 42 and 1337 produced identical output. Writing one here would restate the
    #292 bug in the config that documents it.
    """
    body = _re_entries()[alias]
    assert "seed:" not in body, (
        f"{alias} sets a seed. It cannot take effect: llama-server ignores seed on "
        f"/v1/messages and drop_params would swallow it anyway (#292). Remove it "
        f"rather than shipping a control that silently does nothing.")


def test_the_seeded_aliases_are_documented_as_unseeded():
    """The names say -s42. Anyone reading the config must learn they are not seeded
    without having to run the experiment again."""
    text = CONFIG.read_text(encoding="utf-8")
    assert "NOT SEEDED" in text.upper(), (
        "the seed-named aliases must carry a prominent note that they are not "
        "actually seeded (#292), or the next reader will trust the name")
    assert "#292" in text


def test_both_llamacpp_bases_are_defined_and_differ():
    """Two shapes, two bases. Collapsing them re-creates the /v1/v1 bug."""
    text = DEFAULTS.read_text(encoding="utf-8")
    openai = re.search(r'^litellm_llamacpp_api_base:\s*"([^"]+)"', text, re.M)
    anthropic = re.search(r'^litellm_llamacpp_anthropic_base:\s*"([^"]+)"', text, re.M)
    assert openai and anthropic, "both llama.cpp bases must be defined"
    assert openai.group(1).endswith("/v1"), "the OpenAI-shaped base needs its /v1"
    assert not anthropic.group(1).endswith("/v1"), (
        "the anthropic base must not end in /v1 — LiteLLM appends /v1/messages")
    assert openai.group(1) != anthropic.group(1)
