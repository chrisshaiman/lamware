# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A profile's `cloud: false` must mean its traffic stays on the host (ADR-036).

The pipeline's config model lets a non-cloud profile name only aliases matching
LOCAL_ALIAS_RE. This holds that pattern to the real routes: every alias in the
rendered LiteLLM config that matches it must have a loopback api_base. Rendered with
the role's defaults, as the other LiteLLM tests do.
"""
import re
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
# In pipeline/tests, not tests/: it imports the pipeline's config (pydantic), which
# the top-level test job does not install.
from lamware_pipeline.config import LOCAL_ALIAS_RE  # noqa: E402

LITELLM = ROOT / "ansible/roles/litellm"
DEFAULTS = yaml.safe_load((LITELLM / "defaults/main.yml").read_text())
INTERPRET = yaml.safe_load((ROOT / "ansible/roles/interpret/defaults/main.yml").read_text())
PIPELINE = yaml.safe_load((ROOT / "ansible/roles/pipeline/defaults/main.yml").read_text())
# The servers that run models ON this host. Not "any loopback address": the
# federated eval route (anthropic-wif) is loopback too, and forwards to the cloud.
# The OpenAI-shape base is not a role default; the template falls back to the same
# /v1 address as litellm_llamacpp_api_base.
LOCAL_BASES = {DEFAULTS["litellm_llamacpp_anthropic_base"], DEFAULTS["litellm_llamacpp_api_base"],
               DEFAULTS.get("litellm_llamacpp_openai_base", DEFAULTS["litellm_llamacpp_api_base"]),
               DEFAULTS["litellm_stub_base"]}
STUB = yaml.safe_load((ROOT / "ansible/roles/llm-stub/defaults/main.yml").read_text())


def _model_list(**extra):
    env = jinja2.Environment(undefined=jinja2.StrictUndefined)
    env.filters.setdefault("mandatory", lambda v: v)
    text = (LITELLM / "templates/config.yaml.j2").read_text()
    return yaml.safe_load(env.from_string(text).render(
        **{**INTERPRET, **DEFAULTS, "litellm_master_key": "k", **extra}))["model_list"]


def _local_named(entries):
    return [m for m in entries if re.fullmatch(LOCAL_ALIAS_RE, m["model_name"])]


@pytest.mark.parametrize("routes", [[], ["eval"], ["production", "eval"]])
def test_every_alias_the_pattern_calls_local_routes_to_loopback(routes):
    entries = _model_list(litellm_anthropic_wif_routes=routes)
    local = _local_named(entries)
    assert local, "no alias matches LOCAL_ALIAS_RE: the check would pass vacuously"
    for m in local:
        base = m["litellm_params"].get("api_base", "")
        assert base in LOCAL_BASES, f"{m['model_name']} matches the local pattern but routes to {base!r}"


@pytest.mark.parametrize("base", ["https://api.anthropic.com", "http://127.0.0.1:4012", ""])
def test_the_check_catches_a_local_looking_alias_on_a_cloud_route(base):
    """Guards the guard: a direct cloud route, the loopback WIF forwarder, and no
    api_base at all (a keyed Anthropic entry) are each refused."""
    bad = {"model_name": "local-qwen-llamacpp-x",
           "litellm_params": {"model": "anthropic/claude-haiku-4-5", "api_base": base}}
    assert _local_named([bad]) == [bad] and bad["litellm_params"]["api_base"] not in LOCAL_BASES


def test_the_deployed_defaults_define_no_cloud_profile():
    """Without local vars a deploy has "local" and the free, local "stub"; a cloud
    profile is always the operator's own addition."""
    assert PIPELINE["pipeline_llm_profiles"] == {}
    profiles = PIPELINE["pipeline_llm_profiles_builtin"]
    assert set(profiles) == {"stub"}
    assert profiles["stub"]["cloud"] is False
    assert {profiles["stub"][f] for f in ("model", "escalation_model", "summary_model",
                                          "plain_english_model")} == {"stub"}


def test_the_stub_alias_points_at_the_stub_service():
    (entry,) = [m for m in _model_list() if m["model_name"] == "stub"]
    assert entry["litellm_params"]["api_base"] == DEFAULTS["litellm_stub_base"]
    assert DEFAULTS["litellm_stub_base"] == f"http://{STUB['llm_stub_listen_host']}:{STUB['llm_stub_port']}"


def test_the_automated_defaults_are_local_aliases():
    for var in ("interpret_model", "interpret_summary_model", "interpret_escalation_model"):
        assert re.fullmatch(LOCAL_ALIAS_RE, INTERPRET[var]), var
    for var in ("pipeline_summary_model", "pipeline_plain_english_model"):
        assert re.fullmatch(LOCAL_ALIAS_RE, PIPELINE[var]), var
