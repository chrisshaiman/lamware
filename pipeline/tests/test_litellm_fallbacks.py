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
NO_CLOUD_FALLBACK = ("local-qwen-llamacpp-re", "local-qwen-strict")


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


def test_summary_model_fallback_is_still_intact():
    """The summary path is a different risk profile and SHOULD stay resilient."""
    assert '"local-qwen": ["haiku-fallback"]' in _fallbacks_line()


def test_re_model_is_still_registered_as_a_model():
    """No fallback is not the same as not existing — the arm must still route."""
    assert 'model_name: "local-qwen-llamacpp-re"' in CFG


def test_no_cloud_provider_sneaks_into_the_re_entry():
    """The RE entry must point at the local llama.cpp server, not an anthropic/ model."""
    block = CFG.split('model_name: "local-qwen-llamacpp-re"')[1].split("model_name:")[0]
    assert "openai/qwen3.6" in block
    assert "anthropic/" not in block, "RE entry must not resolve to a cloud provider"
    assert "127.0.0.1" in block or "litellm_llamacpp_api_base" in block
