# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for PipelineConfig (malfind + 2b-1 scalars/CMD paths + 2b-2 collections)."""

import json

import pytest
from lamware_pipeline.config import PipelineConfig
from pydantic import ValidationError

# A fully-populated config.json, mirroring what config.json.j2 renders at deploy.
# Values track ansible/roles/pipeline/defaults/main.yml (and cross-role install dirs).
_VALID = {
    # malfind (Phase 1)
    "malfind_enabled": True,
    "malfind_max_candidates": 5,
    "malfind_min_size": 256,
    "malfind_max_size": 10485760,
    "malfind_min_score": 2,
    "malfind_benign_processes": ["csrss.exe", "smss.exe"],
    # Phase 2b-1 — CMD paths
    "cape_api_url": "http://10.200.0.1:8000/apiv2",
    "triage_cmd": "/opt/triage/run-triage",
    "volatility_cmd": "/opt/volatility3/run-volatility",
    "ghidra_cmd": "/opt/ghidra/run-ghidra",
    "dotnet_cmd": "/opt/dotnet-analysis/run-dotnet-analysis",
    "go_cmd": "/opt/go-analysis/run-go-analysis",
    "pyinstaller_cmd": "/opt/pyinstaller-analysis/run-pyinstaller-analysis",
    "java_cmd": "/opt/java-analysis/run-java-analysis",
    "office_cmd": "/opt/office-macro-analysis/run-office-analysis",
    "powershell_cmd": "/opt/powershell-analysis/run-powershell-analysis",
    "screenshot_cmd": "/opt/screenshot-analysis/run-screenshot-analysis",
    "pdf_cmd": "/opt/pdf-generation/run-pdf-generation",
    "interpret_cmd": "/opt/interpret/run-interpret",
    "pcap_cmd": "/opt/pcap-analysis/run-pcap-analysis",
    # Phase 2b-1 — scalars
    "interpret_enabled": True,
    "interpret_timeout": 300,
    "reports_dir": "/opt/pipeline/reports",
    "cape_poll_interval": 30,
    "cape_timeout": 1200,
    "pcap_enabled": True,
    "pcap_timeout": 120,
    "evasion_hunter_enabled": True,
    "evasion_max_signatures": 10,
    "evasion_min_binary_size": 51200,
    "volatility_ramdisk": "/opt/pipeline/ramdisk",
    "volatility_parallel_workers": 7,
    # Phase 2b-2 — collections
    "interpret": {
        "model": "claude-sonnet-4-6",
        "escalation_threshold": 5,
        "escalation_model": "claude-opus-4-6",
        "max_output_tokens": 4096,
        "max_tool_calls": 10,
        "max_imports": 200,
        "max_strings": 100,
        "max_string_length": 500,
        "summary_model": "claude-haiku-4-5",
    },
    "volatility_triggers": [
        "injection_createremotethread",
        "process_hollowing",
        "packed_binary",
    ],
    "volatility_extra_plugins": {
        "injection": {
            "triggers": ["injection_createremotethread", "injection_rwx"],
            "plugins": ["windows.handles"],
        },
        "rootkit": {
            "triggers": ["rootkit_ssdt_hook"],
            "plugins": ["windows.ssdt", "windows.callbacks"],
        },
    },
    # Phase 3b — DB connection (non-secret; password is in pipeline.env)
    "db_host": "127.0.0.1",
    "db_port": 5432,
    "db_name": "malware_analysis",
    "db_user": "pipeline",
}


def test_loads_valid_config(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_VALID))
    cfg = PipelineConfig.load(str(p))
    # malfind (Phase 1)
    assert cfg.malfind_min_score == 2
    assert cfg.malfind_benign_processes == ["csrss.exe", "smss.exe"]
    # CMD paths
    assert cfg.ghidra_cmd == "/opt/ghidra/run-ghidra"
    assert cfg.volatility_cmd == "/opt/volatility3/run-volatility"
    assert cfg.triage_cmd == "/opt/triage/run-triage"
    assert cfg.cape_api_url == "http://10.200.0.1:8000/apiv2"
    # scalars
    assert cfg.cape_timeout == 1200
    assert cfg.cape_poll_interval == 30
    assert cfg.reports_dir == "/opt/pipeline/reports"
    assert cfg.interpret_enabled is True
    assert cfg.interpret_timeout == 300
    assert cfg.pcap_enabled is True


def test_stale_inline_defaults_preserve_effective_values(tmp_path):
    """The two .j2 inline defaults are dead (defaults/main.yml overrides them).
    Today's effective values are 7 and 10, not the inline 3 and 5."""
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_VALID))
    cfg = PipelineConfig.load(str(p))
    assert cfg.volatility_parallel_workers == 7
    assert cfg.evasion_max_signatures == 10


def test_rejects_wrong_type(tmp_path):
    bad = dict(_VALID, cape_timeout="twenty minutes")
    p = tmp_path / "config.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(ValidationError):
        PipelineConfig.load(str(p))


def test_rejects_missing_field(tmp_path):
    bad = {k: v for k, v in _VALID.items() if k != "ghidra_cmd"}
    p = tmp_path / "config.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(ValidationError):
        PipelineConfig.load(str(p))


def test_interpret_submodel(tmp_path):
    """INTERPRET_CONFIG is rebuilt from the nested submodel via model_dump();
    its keys must match what the orchestrator body indexes."""
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_VALID))
    cfg = PipelineConfig.load(str(p))
    dumped = cfg.interpret.model_dump()
    assert dumped == _VALID["interpret"]
    assert dumped["model"] == "claude-sonnet-4-6"
    assert dumped["summary_model"] == "claude-haiku-4-5"


def test_interpret_max_output_tokens_landmine(tmp_path):
    """interpret-role default (4096) overrides the dead inline default(2048).
    The deployed effective value is 4096."""
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_VALID))
    cfg = PipelineConfig.load(str(p))
    assert cfg.interpret.max_output_tokens == 4096


def test_volatility_collections_are_plain(tmp_path):
    """VOLATILITY_TRIGGERS stays a list; VOLATILITY_EXTRA_PLUGINS stays a plain
    nested dict (not a submodel) so the body iterates it unchanged."""
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_VALID))
    cfg = PipelineConfig.load(str(p))
    assert cfg.volatility_triggers == _VALID["volatility_triggers"]
    assert isinstance(cfg.volatility_extra_plugins, dict)
    assert cfg.volatility_extra_plugins["rootkit"]["plugins"] == [
        "windows.ssdt", "windows.callbacks",
    ]


def test_rejects_unknown_top_level_key(tmp_path):
    """extra='forbid' surfaces a config.json key the model doesn't know about —
    a dropped/renamed key is a deploy bug we want loud, not silently ignored."""
    bad = dict(_VALID, surprise_key="oops")
    p = tmp_path / "config.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(ValidationError):
        PipelineConfig.load(str(p))


def test_rejects_unknown_interpret_key(tmp_path):
    bad = json.loads(json.dumps(_VALID))
    bad["interpret"]["surprise_key"] = "oops"
    p = tmp_path / "config.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(ValidationError):
        PipelineConfig.load(str(p))


def test_db_connection_fields(tmp_path):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_VALID))
    cfg = PipelineConfig.load(str(p))
    assert cfg.db_host == "127.0.0.1"
    assert cfg.db_port == 5432
    assert cfg.db_name == "malware_analysis"
    assert cfg.db_user == "pipeline"


def test_fixture_config_loads():
    from pathlib import Path
    cfg_path = Path(__file__).parent / "fixtures" / "config.json"
    PipelineConfig.load(str(cfg_path))  # raises if the checked-in fixture drifts from the model
