# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""config.json.j2 must render to something PipelineConfig accepts.

`PipelineConfig` sets `extra="forbid"`, so a key added to the template but not to the
model is a HARD FAILURE at pipeline start, not a warning. That is what adding
`summary_timeout` did on 2026-08-20:

    pydantic_core.ValidationError: 1 validation error for PipelineConfig
    interpret.summary_timeout
      Extra inputs are not permitted [type=extra_forbidden, input_value=900]

Every stage died before triage. The tests at the time asserted the key was present in
the template text and that the model had a matching default — both passed, because
neither rendered the template and fed it to the model.

test_config.py's `_FULL` fixture is a hand-written dict described as "mirroring what
config.json.j2 renders at deploy". A fixture written by hand cannot discover that the
template renders something the model rejects; it only proves the model accepts what
the fixture's author believed the template produces. Same defect class as #409.

This renders the ACTUAL template and validates the ACTUAL model against it.
"""
import json
from pathlib import Path

import jinja2
import pytest
import yaml
from lamware_pipeline.config import PipelineConfig

_ROLE = Path(__file__).resolve().parents[2] / "ansible" / "roles" / "pipeline"
TEMPLATE = _ROLE / "templates" / "config.json.j2"
DEFAULTS = _ROLE / "defaults" / "main.yml"


def _render() -> str:
    """Render the template with the role's ACTUAL defaults as context.

    Not hand-written stand-ins: `ansible/roles/pipeline/defaults/main.yml` is what
    Ansible supplies at deploy when a play sets nothing, so rendering against it is
    the closest reproduction of the deployed config available without a host. Keys
    the role does not default (`cape_api_url`, and paths from other roles) get
    placeholders, because their VALUES are irrelevant to whether the SHAPE validates.

    Ansible's `to_json` and `mandatory` filters are not in stock Jinja and are
    supplied here.
    """
    defaults = yaml.safe_load(DEFAULTS.read_text(encoding="utf-8")) or {}
    ctx = dict(defaults)
    # Cross-role and inventory-supplied values, none of which affect the shape.
    for k in ("cape_api_url", "pipeline_reports_dir", "volatility_install_dir",
              "ghidra_install_dir", "dotnet_analysis_install_dir",
              "go_analysis_install_dir", "pyinstaller_analysis_install_dir",
              "java_analysis_install_dir", "office_macro_analysis_install_dir",
              "powershell_analysis_install_dir", "screenshot_analysis_install_dir",
              "pdf_generation_install_dir", "interpret_install_dir",
              "pcap_analysis_install_dir", "triage_install_dir",
              "pipeline_db_host", "pipeline_db_name", "pipeline_db_user"):
        ctx.setdefault(k, "placeholder")

    def to_json(v):
        return json.dumps("placeholder" if isinstance(v, jinja2.Undefined) else v)

    env = jinja2.Environment(undefined=jinja2.ChainableUndefined, autoescape=False)
    env.filters["to_json"] = to_json
    env.filters["mandatory"] = lambda v: "placeholder" if isinstance(v, jinja2.Undefined) else v
    return env.from_string(TEMPLATE.read_text(encoding="utf-8")).render(**ctx)


def test_template_renders_to_valid_json():
    out = _render()
    try:
        json.loads(out)
    except json.JSONDecodeError as e:
        pytest.fail(f"config.json.j2 does not render to valid JSON: {e}")


def test_rendered_template_validates_against_the_model():
    """The assertion that would have caught the summary_timeout outage."""
    data = json.loads(_render())
    try:
        PipelineConfig.model_validate(data)
    except Exception as e:
        pytest.fail(
            "config.json.j2 renders a config PipelineConfig rejects — the pipeline "
            f"would die at startup before triage:\n{e}")


def test_summary_timeout_survives_the_round_trip():
    """Specific regression: the key that caused the outage."""
    cfg = PipelineConfig.model_validate(json.loads(_render()))
    assert cfg.interpret.summary_timeout > 340, (
        "summary_timeout must clear the slowest observed generation (340s)")


def test_a_key_the_model_does_not_know_is_rejected():
    """Proves the guard can fail — otherwise it is only asserting today's state."""
    data = json.loads(_render())
    data["interpret"]["zz_not_a_real_key"] = 1
    with pytest.raises(Exception):
        PipelineConfig.model_validate(data)
