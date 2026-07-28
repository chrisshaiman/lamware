# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The seed list is duplicated across a boundary, so it needs a drift guard.

`SEEDS` in lamware_eval/arms.py names the LiteLLM model aliases the harness will
request. `litellm_llamacpp_seeds` in the litellm role's defaults is what actually
generates those aliases. Nothing at import time connects the two.

If they drift, the failure is expensive and late: the harness resolves the arm fine,
starts the run, and only discovers the alias does not exist when the first request
returns model-not-found — potentially hours in, and per-cell, so a sweep can burn a
whole night before anyone notices.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
EVAL_PKG = ROOT / "ansible" / "roles" / "pipeline" / "files"
sys.path.insert(0, str(EVAL_PKG))

from lamware_eval import arms as arms_mod  # noqa: E402

LITELLM_DEFAULTS = (ROOT / "ansible" / "roles" / "litellm" / "defaults" / "main.yml").read_text()
LITELLM_CFG = (ROOT / "ansible" / "roles" / "litellm" / "templates" / "config.yaml.j2").read_text()


def _seeds_from_ansible_defaults() -> list[int]:
    match = re.search(r"^litellm_llamacpp_seeds:\s*\[([^\]]*)\]", LITELLM_DEFAULTS, re.MULTILINE)
    assert match, "litellm_llamacpp_seeds not found in the litellm role defaults"
    return [int(v) for v in match.group(1).split(",") if v.strip()]


def test_seed_lists_match_across_the_boundary():
    assert sorted(arms_mod.SEEDS) == sorted(_seeds_from_ansible_defaults()), (
        "lamware_eval.arms.SEEDS and litellm_llamacpp_seeds have drifted. Every seed the "
        "harness can request must have a model alias generated for it, or the run fails "
        "at request time rather than at deploy time.")


def test_the_template_actually_generates_an_alias_per_seed():
    """A matching list is worthless if the template stopped looping over it."""
    assert "{% for seed in litellm_llamacpp_seeds %}" in LITELLM_CFG
    assert 'model_name: "local-qwen-llamacpp-re-s{{ seed }}"' in LITELLM_CFG
    assert "seed: {{ seed }}" in LITELLM_CFG


def test_every_local_arm_has_a_seeded_variant():
    unseeded = [a for a in arms_mod._REGISTRY.values() if a.re_backend == "local" and a.seed is None]
    for base in unseeded:
        for seed in arms_mod.SEEDS:
            name = f"{base.name}:s{seed}"
            assert name in arms_mod._REGISTRY, f"missing seeded variant {name}"


def test_seeded_arms_route_to_the_matching_alias():
    for arm in arms_mod._REGISTRY.values():
        if arm.seed is None:
            continue
        assert arm.model == f"local-qwen-llamacpp-re-s{arm.seed}", (
            f"arm {arm.name} claims seed {arm.seed} but routes to {arm.model} — the "
            f"recorded seed would not be the seed actually used.")


def test_seeded_arms_inherit_the_base_depth():
    """A seed variant must differ from its base in ONE dimension, or it is not paired."""
    for arm in arms_mod._REGISTRY.values():
        if arm.seed is None:
            continue
        base = arms_mod._REGISTRY[arm.name.split(":s")[0]]
        assert arm.max_tool_calls == base.max_tool_calls
        assert arm.re_backend == base.re_backend


def test_unknown_seed_arm_fails_fast():
    with pytest.raises(KeyError):
        arms_mod.resolve_arm("qwen@30:s999999")


def test_cloud_arms_are_not_given_seed_variants():
    """Anthropic has no seed parameter; a seeded cloud arm would be a false promise."""
    for arm in arms_mod._REGISTRY.values():
        if arm.seed is not None:
            assert arm.re_backend == "local", (
                f"{arm.name} pins a seed but is not a local arm — the Anthropic Messages "
                f"API has no seed field, so the pin would be silently ignored.")
