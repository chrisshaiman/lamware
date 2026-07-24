# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Static guards: the two-phase RE synthesis (forced submit_analysis + think:false)."""
from pathlib import Path

TEMPLATE = (Path(__file__).resolve().parents[2]
            / "ansible" / "roles" / "interpret" / "templates" / "interpret-ghidra.py.j2")


def _t() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


def test_submit_analysis_schema_defined():
    t = _t()
    assert "SUBMIT_ANALYSIS_SCHEMA = {" in t
    block = t.split("SUBMIT_ANALYSIS_SCHEMA = {", 1)[1][:1500]
    for field in ("malware_family_guess", "capabilities", "attack_techniques",
                  "code_level_iocs", "narrative"):
        assert field in block, field


def test_synth_openai_base_read_from_env():
    t = _t()
    assert 'os.environ.get("LITELLM_OPENAI_BASE_URL"' in t
