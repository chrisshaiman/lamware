# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Tests for the shared single-shot init-payload builders."""
from stages.single_shot_init import build_dotnet_init, build_go_init, build_ps_init


def test_dotnet_init_original_binary():
    dotnet_data = {
        "decompilation": {"source": "class Loader { }"},
        "classes": [{"name": "Loader"}],
        "strings_of_interest": ["evil.example.com"],
    }
    out = build_dotnet_init(dotnet_data, {"bazaar_family": "agenttesla"}, ["InjectionCreateRemoteThread"])
    assert out["analysis_type"] == "dotnet"
    assert out["source_language"] == "csharp"
    assert out["decompiled_source"] == "class Loader { }"
    assert out["class_count"] == 1
    assert out["classes"] == [{"name": "Loader"}]
    assert out["strings_of_interest"] == ["evil.example.com"]
    assert out["origin"] == "original"
    assert out["extraction_context"] is None
    assert out["analysis_success"] is True
    assert out["bazaar_family"] == "agenttesla"  # llm_context merged in


def test_dotnet_init_extracted_payload_carries_context():
    dotnet_data = {
        "decompilation": {"source": "x"},
        "classes": [],
        "strings_of_interest": [],
        "extraction_source": {"source_dir": "/d", "sha256": "abc"},
    }
    out = build_dotnet_init(dotnet_data, {}, ["sig1", "sig2"])
    assert out["origin"] == "extraction"
    assert out["extraction_context"] == {"source_dir": "/d", "sha256": "abc", "cape_signatures": ["sig1", "sig2"]}


def test_dotnet_init_caps_source_at_50k():
    out = build_dotnet_init({"decompilation": {"source": "a" * 60000}, "classes": [], "strings_of_interest": []}, {}, [])
    assert len(out["decompiled_source"]) == 50000


def test_go_init_shape():
    go_data = {
        "build_info": {"go_version": "1.21"},
        "packages": [{"category": "user"}],
        "functions": {"user_count": 12},
        "types": [{"name": "T"}],
        "strings_of_interest": ["1.2.3.4"],
    }
    out = build_go_init(go_data, {})
    assert out["analysis_type"] == "go_goresym"
    assert out["build_info"] == {"go_version": "1.21"}
    assert out["packages"] == [{"category": "user"}]
    assert out["functions"] == {"user_count": 12}
    assert out["strings_of_interest"] == ["1.2.3.4"]
    assert out["analysis_success"] is True


def test_ps_init_shape_and_caps():
    ps_data = {
        "original_script": "o" * 40000,
        "final_decoded": "d" * 60000,
        "layer_count": 3,
        "obfuscation_techniques": ["base64"],
        "iocs_extracted": {"urls": ["http://evil.test/x"]},
        "strings_of_interest": ["evil.test"],
        "input_mode": "cape",
    }
    out = build_ps_init(ps_data, {}, ["PowershellDownload"])
    assert out["analysis_type"] == "powershell"
    assert out["source_language"] == "powershell"
    assert len(out["original_script"]) == 30000   # capped at 30k
    assert len(out["final_decoded"]) == 50000     # capped at 50k
    assert out["layer_count"] == 3
    assert out["iocs_extracted"] == {"urls": ["http://evil.test/x"]}
    assert out["cape_signatures"] == ["PowershellDownload"]
    assert out["input_mode"] == "cape"
    assert out["analysis_success"] is True
