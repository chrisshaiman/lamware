# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Settings parses LAMWARE_INVESTIGATE_MODELS as the env file writes it (ADR-038).

The other half of tests/test_investigate_models.py, which renders the env template:
systemd strips the single quotes, and pydantic-settings parses the JSON list.
"""
import json

from app.config import DEFAULT_INVESTIGATE_MODELS, Settings


def test_the_rendered_json_becomes_the_models_in_order(monkeypatch):
    value = json.dumps([{"name": "claude-haiku-4-5", "label": "Fast"},
                        {"name": "local-qwen-llamacpp", "label": "Local"}])
    monkeypatch.setenv("LAMWARE_INVESTIGATE_MODELS", value)
    got = Settings().investigate_models
    assert [(m.name, m.label) for m in got] == [("claude-haiku-4-5", "Fast"), ("local-qwen-llamacpp", "Local")]


def test_without_the_variable_the_default_three(monkeypatch):
    monkeypatch.delenv("LAMWARE_INVESTIGATE_MODELS", raising=False)
    assert Settings().investigate_models == DEFAULT_INVESTIGATE_MODELS
