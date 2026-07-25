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


def test_pipeline_manifest_deploys_lamware_eval_and_ab_re():
    tasks = (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text()
    assert "lamware_eval" in tasks
    assert "llm_ab_re.py" in tasks  # runner imports it; must deploy
