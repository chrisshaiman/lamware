# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Guard: the two pilot local-model entries exist in the LiteLLM config template."""
from pathlib import Path

CONFIG = (Path(__file__).resolve().parents[2]
          / "ansible" / "roles" / "litellm" / "templates" / "config.yaml.j2")


def test_pilot_model_entries_present():
    text = CONFIG.read_text(encoding="utf-8")
    assert 'model_name: "local-qwen32-re"' in text
    assert 'model_name: "local-gptoss-re"' in text
    # reasoning-on for both
    assert text.count("think: true") >= 3  # local-qwen-re + the two new ones
