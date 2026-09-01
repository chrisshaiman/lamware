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


def test_dotnet_init_does_not_cut_below_what_the_container_stored():
    """This used to slice to 50,000 — a second, silent cap below the container's
    own 100,000, which also sliced off the container's truncation marker. The
    model got a prefix ending mid-line that read as a whole program: on quasarrat,
    50,000 characters of a 4,468,045-character decompilation (#507)."""
    out = build_dotnet_init(
        {"decompilation": {"source": "a" * 60000}, "classes": [],
         "strings_of_interest": []}, {}, [])
    assert out["decompiled_source"] == "a" * 60000, "cut below the container cap"
    assert out["source_bytes_shown"] == 60000


def test_dotnet_init_marks_its_own_truncation():
    """If this layer ever does cut, it must say so. A prefix that does not say it
    is a prefix is the whole defect."""
    out = build_dotnet_init(
        {"decompilation": {"source": "a" * 150000}, "classes": [],
         "strings_of_interest": []}, {}, [])
    src = out["decompiled_source"]
    assert src.startswith("a" * 100000)
    assert "truncated" in src and "150,000" in src, src[-120:]
    assert out["source_bytes_shown"] == len(src)


def test_dotnet_init_carries_the_true_size_the_container_recorded():
    """`source_length` has always been in the report and nothing read it, so a
    report could say 4,468,045 while the model saw 50,000 and no consumer could
    tell."""
    out = build_dotnet_init(
        {"decompilation": {"source": "a" * 100041, "source_length": 4468045,
                           "truncated": True},
         "classes": [], "strings_of_interest": []}, {}, [])
    assert out["source_bytes_total"] == 4468045
    assert out["source_truncated_by_analyser"] is True


def test_an_untruncated_source_says_so():
    """Positive control: the flag is not unconditionally true."""
    out = build_dotnet_init(
        {"decompilation": {"source": "a" * 500, "source_length": 500,
                           "truncated": False},
         "classes": [], "strings_of_interest": []}, {}, [])
    assert out["source_truncated_by_analyser"] is False
    assert "truncated" not in out["decompiled_source"]


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
    # Cut at the limit and MARKED. A deobfuscated PowerShell payload is exactly
    # where a reader assumes they are seeing all of it (#507).
    assert out["original_script"].startswith("o" * 30000)
    assert "truncated" in out["original_script"]
    assert out["final_decoded"].startswith("d" * 50000)
    assert "truncated" in out["final_decoded"]
    assert out["layer_count"] == 3
    assert out["iocs_extracted"] == {"urls": ["http://evil.test/x"]}
    assert out["cape_signatures"] == ["PowershellDownload"]
    assert out["input_mode"] == "cape"
    assert out["analysis_success"] is True
