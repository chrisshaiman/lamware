# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_litellm_has_sonnet5_entry():
    cfg = (ROOT / "ansible" / "roles" / "litellm" / "templates" / "config.yaml.j2").read_text()
    assert "claude-sonnet-5" in cfg


def test_pipeline_manifest_deploys_lamware_eval_and_ab_re():
    tasks = (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text()
    assert "lamware_eval" in tasks
    assert "llm_ab_re.py" in tasks  # runner imports it; must deploy
