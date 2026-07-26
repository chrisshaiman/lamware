# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _litellm_cfg() -> str:
    return (ROOT / "ansible" / "roles" / "litellm" / "templates"
            / "config.yaml.j2").read_text()


def test_litellm_has_cloud_eval_model_entries():
    cfg = _litellm_cfg()
    assert 'model_name: "claude-sonnet-5"' in cfg
    assert 'model_name: "claude-opus-5"' in cfg


def test_cloud_eval_models_use_undated_ids():
    """Dated snapshot ids 404 on the Anthropic API.

    Verified live 2026-07-24: GET /v1/models/claude-sonnet-5 -> 200, but
    /v1/models/claude-sonnet-5-20260630 -> 404 not_found_error. A dated pin
    fails the whole arm at benchmark time, so assert the resolved backend ids
    are the undated aliases.
    """
    cfg = _litellm_cfg()
    assert 'model: "anthropic/claude-sonnet-5"' in cfg
    assert 'model: "anthropic/claude-opus-5"' in cfg
    assert "claude-sonnet-5-20" not in cfg, "dated sonnet-5 id 404s"
    assert "claude-opus-5-20" not in cfg, "dated opus-5 id 404s"


def test_every_arm_model_has_a_litellm_entry():
    """Cross-copy drift guard: the arm registry and the LiteLLM model_list are two
    copies of the same contract on opposite sides of a deploy boundary.

    Without this, an arm can name a model that was never registered and the gap
    only surfaces mid-benchmark as a routing failure - which is exactly how
    `local-qwen-llamacpp-re` went missing while both qwen arms depended on it.
    """
    from lamware_eval.arms import _REGISTRY

    cfg = _litellm_cfg()
    missing = [a.model for a in _REGISTRY.values()
               if f'model_name: "{a.model}"' not in cfg]
    assert not missing, f"arms reference unregistered litellm models: {missing}"


def test_rejected_experiment_models_are_not_registered():
    """qwen3:32b and gpt-oss:20b were evaluated and rejected (2026-07-07/08).

    Leaving them in model_list is not inert: LiteLLM's /health fans out a live
    inference call to every entry, so each dormant entry is a multi-GB cold load
    waiting to happen. One of them drove the host to load 136 on 2026-07-24.
    """
    cfg = _litellm_cfg()
    for dead in ("qwen3:32b", "gpt-oss:20b"):
        assert dead not in cfg, f"rejected experiment model still registered: {dead}"


def test_pipeline_manifest_deploys_lamware_eval_and_ab_re():
    tasks = (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text()
    assert "lamware_eval" in tasks
    assert "llm_ab_re.py" in tasks  # runner imports it; must deploy


def test_every_lamware_eval_module_is_in_the_deploy_loop():
    """Cross-copy drift guard: the package directory and the Ansible copy loop are
    two copies of the same file list on opposite sides of the deploy boundary.

    The loop is enumerated, not a glob, so a new module is silently left behind on
    the host — the code merges, CI stays green, and the gap only surfaces as an
    ImportError mid-benchmark. `rebuild.py` shipped in #189 and was missed exactly
    this way; the previous assertion only checked that the string "lamware_eval"
    appeared somewhere in the tasks file, which no missing module can falsify.
    """
    pkg = ROOT / "ansible" / "roles" / "pipeline" / "files" / "lamware_eval"
    tasks = (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text()

    missing = [p.name for p in sorted(pkg.glob("*.py"))
               if f"- {p.name}" not in tasks]
    assert not missing, (
        f"lamware_eval modules exist but are never deployed: {missing}. "
        f"Add them to the copy loop in roles/pipeline/tasks/main.yml.")
