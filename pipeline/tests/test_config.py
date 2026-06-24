# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for PipelineConfig (malfind slice + Phase 2b-1 scalars/CMD paths)."""

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
