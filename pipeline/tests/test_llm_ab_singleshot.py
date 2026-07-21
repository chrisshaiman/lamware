# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the single-shot local-vs-cloud A/B harness (pure functions)."""
from llm_ab_singleshot import build_singleshot_configs, init_for_report, source_text_for


def test_local_model_sets_backend_flag():
    cfgs = build_singleshot_configs(["local-qwen-re", "local-gptoss-re"])
    assert all(c["single_shot_backend"] == "local" for c in cfgs)
    assert [c["model"] for c in cfgs] == ["local-qwen-re", "local-gptoss-re"]
    assert all(c["max_output_tokens"] >= 8192 for c in cfgs)


def test_cloud_model_leaves_backend_unset():
    cfgs = build_singleshot_configs(["claude-sonnet-4-6"])
    assert "single_shot_backend" not in cfgs[0]
    assert cfgs[0]["model"] == "claude-sonnet-4-6"


def test_init_for_report_detects_powershell():
    report = {"powershell_analysis": {"analysis_success": True, "final_decoded": "iex(...)",
                                       "iocs_extracted": {"urls": ["http://evil.test/a"]}}}
    init = init_for_report(report)
    assert init["analysis_type"] == "powershell"


def test_init_for_report_detects_go_and_dotnet():
    assert init_for_report({"go_analysis": {"analysis_success": True}})["analysis_type"] == "go_goresym"
    assert init_for_report({"dotnet_analysis": {"analysis_success": True,
                                                "decompilation": {"source": "x"}}})["analysis_type"] == "dotnet"


def test_init_for_report_none_when_no_single_shot_stage():
    assert init_for_report({"ghidra": {"analyzed_files": []}}) is None


def test_source_text_contains_input_material():
    report = {"powershell_analysis": {"analysis_success": True,
                                      "final_decoded": "downloadstring http://evil.test/a",
                                      "iocs_extracted": {}}}
    init = init_for_report(report)
    text = source_text_for(init)
    assert "evil.test" in text.lower()
