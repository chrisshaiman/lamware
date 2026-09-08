# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The agentic transport must agree with the model name (#582 follow-up).

interpret-ghidra.py has TWO transports and picks by config, not by model name:

    /anthropic passthrough  — cloud models only
    /v1/messages router     — local model_list aliases

Measured and recorded at the `client = summary_client` line in that file:

    local-qwen-llamacpp-re  /anthropic/v1/messages -> 404 not_found_error
    local-qwen-llamacpp-re  /v1/messages           -> 200

The switch is `config["re_backend"] == "local"`. config.json.j2 never set it, so
it was None and the agentic path stayed on the cloud passthrough regardless of
interpret_model. #582 changed the model to a local alias and left the transport
alone, so every interpret call 404'd — after sending the decompiled context to
the cloud endpoint. The stage recorded the error in the report and the pipeline
still exited 0.

Two settings that must agree, in two different files, with a failure that is
silent. That is what this test is for.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
INTERPRET = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "interpret" / "defaults" / "main.yml").read_text(encoding="utf-8"))
CONFIG_TEMPLATE = (ROOT / "ansible" / "roles" / "pipeline" / "templates"
                   / "config.json.j2").read_text(encoding="utf-8")


def test_the_rendered_config_carries_the_transport_switch():
    """Absent, it defaults to None inside interpret-ghidra.py and the agentic
    path silently uses the cloud passthrough."""
    assert '"re_backend"' in CONFIG_TEMPLATE, (
        "config.json.j2 does not ship re_backend, so the agentic path cannot "
        "reach a local model whatever interpret_model says")
    assert "interpret_re_backend" in CONFIG_TEMPLATE, \
        "re_backend is hardcoded rather than driven by the role variable"


def test_a_local_model_implies_the_local_transport():
    """The coupling that broke. A local alias on the cloud passthrough is a 404
    on every single call."""
    model = INTERPRET["interpret_model"]
    backend = INTERPRET["interpret_re_backend"]
    if model.startswith("local-"):
        assert backend == "local", (
            f"interpret_model={model} is local but interpret_re_backend={backend}; "
            f"the agentic path will 404 on the /anthropic passthrough")
    else:
        assert backend != "local", (
            f"interpret_model={model} is a cloud model but the transport is local")


def test_the_escalation_model_shares_the_transport():
    """Escalation runs on the same client. A cloud escalation model with a local
    transport, or the reverse, fails the same way."""
    esc = INTERPRET["interpret_escalation_model"]
    backend = INTERPRET["interpret_re_backend"]
    assert esc.startswith("local-") == (backend == "local"), (
        f"interpret_escalation_model={esc} does not match "
        f"interpret_re_backend={backend}")
