# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Automated runs use the local model; cloud is the analyst's choice, not the machine's.

Policy: the pipeline runs unattended against decompiled malware, so nothing
automated may reach a cloud model on its own. The Anthropic entries stay
deployed because an analyst selects them from the GUI.

The trap this guards is specific. The litellm model_list used to name its
Anthropic entries from `interpret_model` itself:

    - model_name: "{{ interpret_model }}"
      litellm_params:
        model: "anthropic/{{ interpret_model }}"

so pointing the pipeline at a local alias would have emitted

    - model_name: "local-qwen-llamacpp-re"
        model: "anthropic/local-qwen-llamacpp-re"

shadowing the real local alias of that name and sending decompiled malware to
the cloud — while every config file read "local".
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
INTERPRET = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "interpret" / "defaults" / "main.yml").read_text(encoding="utf-8"))
PIPELINE = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "pipeline" / "defaults" / "main.yml").read_text(encoding="utf-8"))
LITELLM = (ROOT / "ansible" / "roles" / "litellm" / "templates"
           / "config.yaml.j2").read_text(encoding="utf-8")

AUTOMATED_VARS = ("interpret_model", "interpret_summary_model", "interpret_escalation_model")


def test_no_automated_stage_names_a_cloud_model():
    """Including escalation. Escalating unattended would put decompiled malware
    in the cloud without an analyst ever choosing it."""
    for var in AUTOMATED_VARS:
        val = INTERPRET[var]
        assert not val.startswith("claude-"), f"{var} = {val!r} is a cloud model"
        assert val.startswith("local-"), f"{var} = {val!r} is not a local alias"


def test_the_pipeline_summary_is_local_too():
    assert PIPELINE["pipeline_summary_model"].startswith("local-")


def test_automated_models_use_the_llamacpp_backend_not_ollama():
    """ollama serves the SAME qwen3.6 weights; a second ~14GB copy alongside
    llama-server is what #407 exists to stop."""
    for var in AUTOMATED_VARS:
        assert "llamacpp" in INTERPRET[var], f"{var} = {INTERPRET[var]!r} is not the llama.cpp alias"


def test_the_agentic_stage_uses_an_alias_with_no_cloud_fallback():
    """-re carries no fallback by design because its context holds decompiled
    malware. A fallback would defeat the policy on the first local hiccup."""
    assert INTERPRET["interpret_model"].endswith("-re")
    # The WHOLE declaration. A non-greedy [.*?] stops at the first "]", which is
    # the one closing the nested ["haiku-fallback"] — so it only ever inspected
    # the first entry and a fallback added to any later one survived. Caught by
    # mutation, not by reading it.
    line = next((ln for ln in LITELLM.splitlines() if ln.strip().startswith("fallbacks:")), None)
    assert line, "no fallbacks declared"
    assert INTERPRET["interpret_model"] not in line, (
        f"{INTERPRET['interpret_model']} has a fallback; automated RE traffic "
        f"could escape to the cloud")


def test_cloud_entries_are_named_from_analyst_vars_not_the_pipeline_ones():
    """The whole trap. If these are named from interpret_model, repointing the
    pipeline at a local alias emits an Anthropic entry WITH THAT NAME."""
    for var in AUTOMATED_VARS:
        assert f"anthropic/{{{{ {var}" not in LITELLM, (
            f"litellm builds an anthropic backend from {var}; repointing it "
            f"locally would shadow the local alias with a cloud one")
        assert f'model_name: "{{{{ {var}' not in LITELLM, (
            f"litellm names a model_list entry from {var}")


def test_the_cloud_models_are_still_deployed_for_analysts():
    """Local-by-default must not remove the analyst's option."""
    for var in ("interpret_analyst_model", "interpret_analyst_summary_model",
                "interpret_analyst_escalation_model"):
        assert INTERPRET[var].startswith("claude-"), f"{var} is no longer a cloud model"
        assert f"{{{{ {var}" in LITELLM, f"{var} is not deployed to the litellm model_list"
