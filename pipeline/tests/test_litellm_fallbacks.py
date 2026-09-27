# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The agentic RE model must never fall back to a cloud provider.

Its context holds decompiled malware bodies, extracted strings and C2 indicators. A
cloud fallback would ship all of that to a third party at the exact moment the local
model failed — an availability feature that silently becomes a data-egress incident,
defeating the air-gap that is the whole reason RE runs locally.

This surfaced as a confusing error in the 2026-07-27 depth probe:

    No fallback model group found for original model_group=local-qwen-llamacpp-re
    Fallbacks=[{'local-qwen': ['haiku-fallback']}]

That message reads like a misconfiguration and invites a "fix" that adds the fallback.
The absence is correct. This test makes it explicit so nobody helpfully closes the gap.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CFG = (ROOT / "ansible" / "roles" / "litellm" / "templates"
       / "config.yaml.j2").read_text()

# Models whose context contains malware-derived content or which are explicitly offline.
NO_CLOUD_FALLBACK = ("local-qwen-llamacpp-re", "local-qwen-llamacpp-strict")


def _fallbacks_line() -> str:
    match = re.search(r"^\s*fallbacks:\s*(\[.*\])\s*$", CFG, re.MULTILINE)
    assert match, "could not find the fallbacks: line in the LiteLLM config"
    return match.group(1)


def test_re_model_has_no_fallback_configured():
    line = _fallbacks_line()
    for model in NO_CLOUD_FALLBACK:
        assert model not in line, (
            f"{model} must NOT have a fallback: its context carries malware-derived "
            f"decompilation, so falling back to a cloud provider is data egress, not "
            f"resilience. Let it fail loudly instead.")


def test_the_deliberate_absence_is_documented():
    """A bare omission is indistinguishable from an oversight — say why in the config."""
    assert "DELIBERATELY ABSENT" in CFG
    assert "local-qwen-llamacpp-re" in CFG.split("DELIBERATELY ABSENT")[1][:900]


def _production_summary_models() -> set[str]:
    """The aliases the summary stages actually request, read from the pipeline
    role's defaults rather than hard-coded here."""
    defaults = (ROOT / "ansible" / "roles" / "pipeline" / "defaults"
                / "main.yml").read_text()
    found = re.findall(r'^pipeline_(?:summary|plain_english)_model:\s*"([^"]+)"',
                       defaults, re.MULTILINE)
    assert found, "pipeline summary model defaults not found"
    return set(found)


def test_summary_model_fallback_is_still_intact():
    """The summary path is a different risk profile and SHOULD stay resilient.

    Asserted against whatever the pipeline ACTUALLY requests. This test used to
    name "local-qwen", the Ollama alias. When the summary stages moved to
    llama.cpp it kept passing while checking a fallback nothing used, and it only
    noticed anything when that alias was deleted.
    """
    line = _fallbacks_line()
    for model in _production_summary_models():
        assert f'"{model}": ["haiku-fallback"]' in line, (
            f"{model} is what the summary stages request, and has no fallback")


def test_re_model_is_still_registered_as_a_model():
    """No fallback is not the same as not existing — the arm must still route."""
    assert 'model_name: "local-qwen-llamacpp-re"' in CFG


def test_no_cloud_provider_sneaks_into_the_re_entry():
    """The RE entry must reach the LOCAL llama.cpp server — never a cloud endpoint.

    Malware decompilation goes over this route. Sending it to a third-party API is
    the single worst regression this config could suffer, so the guard is deliberately
    strict about the DESTINATION.

    It used to assert `"anthropic/" not in block`, which conflated two independent
    things: the provider prefix (the wire FORMAT LiteLLM speaks) and where the
    request actually goes. #285 moved the entry to `anthropic/qwen3.6` against
    `api_base: http://127.0.0.1:11435` — the Anthropic message shape, spoken to
    llama-server on loopback, because llama-server implements /v1/messages natively
    and the OpenAI translation was discarding the model's reasoning.

    So the check now pins the destination directly, which is both the real property
    and a stricter one: a prefix test would have passed `openai/gpt-4` with a cloud
    api_base.
    """
    block = CFG.split('model_name: "local-qwen-llamacpp-re"')[1].split("model_name:")[0]

    assert "qwen3.6" in block, "the RE entry must serve the local qwen model"

    api_base = re.search(r'api_base: "([^"]+)"', block)
    assert api_base, "the RE entry must pin an explicit api_base, never a provider default"
    target = api_base.group(1)
    assert ("127.0.0.1" in target or "localhost" in target
            or "llamacpp" in target), (
        f"RE api_base is {target!r} — it must resolve to the local llama.cpp server. "
        f"Malware decompilation travels this route.")

    # A cloud credential in this entry means the request can leave the host.
    assert "ANTHROPIC_API_KEY" not in block and "OPENAI_API_KEY" not in block, (
        "the RE entry must not reference a cloud API key; llama.cpp ignores api_key "
        "entirely, so a real one here can only mean the traffic is leaving")
    for cloud_model in ("claude-", "gpt-4", "gpt-5"):
        assert cloud_model not in block, (
            f"RE entry names {cloud_model!r} — that is a cloud model, not local qwen")


def test_the_offline_summary_mode_still_exists():
    """`local-qwen-strict` was the documented offline mode for the summary stages.
    Removing the Ollama aliases must not quietly remove the capability, so it moved
    to llama.cpp — registered, and deliberately absent from `fallbacks`."""
    assert 'model_name: "local-qwen-llamacpp-strict"' in CFG
    assert "local-qwen-llamacpp-strict" not in _fallbacks_line()


def test_no_model_routes_to_ollama():
    """Ollama served the same qwen3.6 weights as llama-server. A live route to it
    meant any caller loaded a second ~14GB copy next to ~23GB, which is the #403 OOM
    (#407). No production stage used it. The container is kept for #431, which
    reaches it directly on :11434, never through LiteLLM."""
    model_list = CFG.split("litellm_settings:")[0]
    entries = [e for e in model_list.split("- model_name:")[1:]]
    for e in entries:
        body = "\n".join(ln for ln in e.splitlines() if not ln.strip().startswith("#"))
        assert "ollama" not in body.lower(), f"an entry still routes to ollama: {e[:80]}"
        assert "11434" not in body, f"an entry still targets ollama's port: {e[:80]}"
