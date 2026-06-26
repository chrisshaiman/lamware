# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Per-rule unit tests + enrich safety tests for the correlation rule registry.

Rules are pure functions of the report dict, so each is tested with an inline
dict fixture (no filesystem). enrich (the only impure step) is tested separately
with tmp_path + a monkeypatched storage root.
"""
import pytest

import lamware_pipeline.correlation_rules as cr
from lamware_pipeline.correlation_rules import (
    enrich_correlation_inputs,
    evaluate_rules,
    rule_cmdline_spoofing,
    rule_dropped_file_loaded,
    rule_shellcode_self_modified,
)


# --- rule_dropped_file_loaded ---

def test_dropped_file_loaded_fires_when_dropped_name_loaded():
    report = {
        "_correlation_inputs": {"dropped_files": ["C:\\\\Temp\\\\evil.dll"], "buffer_samples": {}},
        "volatility": {"plugins": {"dlllist": [
            {"Process": "victim.exe", "PID": 42, "Path": "C:\\\\Temp\\\\evil.dll", "Name": "evil.dll"}
        ]}},
    }
    findings = rule_dropped_file_loaded(report)
    assert len(findings) == 1
    assert findings[0]["type"] == "dropped_file_loaded"
    assert findings[0]["severity"] == "high"
    assert findings[0]["sources"] == ["Cape", "Volatility"]


def test_dropped_file_loaded_silent_when_no_overlap():
    report = {
        "_correlation_inputs": {"dropped_files": ["evil.dll"], "buffer_samples": {}},
        "volatility": {"plugins": {"dlllist": [
            {"Process": "ok.exe", "PID": 1, "Path": "C:\\\\Windows\\\\System32\\\\ntdll.dll", "Name": "ntdll.dll"}
        ]}},
    }
    assert rule_dropped_file_loaded(report) == []


def test_dropped_file_loaded_silent_when_no_dropped_files():
    report = {
        "_correlation_inputs": {"dropped_files": [], "buffer_samples": {}},
        "volatility": {"plugins": {"dlllist": [
            {"Process": "svc.exe", "PID": 1, "Path": "C:\\\\Windows\\\\System32\\\\ntdll.dll", "Name": "ntdll.dll"}
        ]}},
    }
    assert rule_dropped_file_loaded(report) == []


# --- rule_shellcode_self_modified ---

def test_shellcode_self_modified_fires_when_bytes_differ():
    # Cape captured 'AAAA'; malfind shows 'BBBB' at the same pid+addr.
    report = {
        "_correlation_inputs": {"dropped_files": [], "buffer_samples": {"99:0x00410000": (b"AAAA").hex()}},
        "cape": {"injection_buffers": [{"target_pid": 99, "injection_address": "0x00410000", "path": "x"}]},
        "volatility": {"plugins": {"malfind": [
            {"PID": 99, "Start VPN": 0x00410000, "Hexdump": "42 42 42 42"}
        ]}},
    }
    findings = rule_shellcode_self_modified(report)
    assert len(findings) == 1
    assert findings[0]["type"] == "shellcode_self_modified"
    # before/after are capped at 64B in production; these 4-byte inputs are
    # always shorter, so the cap is a no-op here.
    assert findings[0]["before"] == (b"AAAA").hex()
    assert findings[0]["after"] == (b"BBBB").hex()


def test_shellcode_self_modified_silent_when_bytes_equal():
    report = {
        "_correlation_inputs": {"dropped_files": [], "buffer_samples": {"99:0x00410000": (b"BBBB").hex()}},
        "cape": {"injection_buffers": [{"target_pid": 99, "injection_address": "0x00410000", "path": "x"}]},
        "volatility": {"plugins": {"malfind": [
            {"PID": 99, "Start VPN": 0x00410000, "Hexdump": "42 42 42 42"}
        ]}},
    }
    assert rule_shellcode_self_modified(report) == []


# --- rule_cmdline_spoofing ---

def test_cmdline_spoofing_fires_when_cmdline_changed():
    report = {
        "cape": {"process_cmdlines": {4444: "C:\\\\real\\\\app.exe"}},
        "volatility": {"plugins": {"cmdline": [{"PID": 4444, "Args": "C:\\\\fake\\\\evil.exe"}]}},
    }
    findings = rule_cmdline_spoofing(report)
    assert len(findings) == 1
    assert findings[0]["type"] == "cmdline_spoofing"
    assert findings[0]["severity"] == "critical"


def test_cmdline_spoofing_silent_on_benign_embedding_flag():
    report = {
        "cape": {"process_cmdlines": {4444: "C:\\\\app.exe"}},
        "volatility": {"plugins": {"cmdline": [{"PID": 4444, "Args": "C:\\\\app.exe -Embedding"}]}},
    }
    assert rule_cmdline_spoofing(report) == []


# --- evaluate_rules + empty-report safety ---

def test_evaluate_rules_empty_report_is_safe():
    assert evaluate_rules({}) == []


def test_each_rule_empty_report_is_safe():
    for rule in cr._RULES:
        assert rule({}) == []


# --- enrich_correlation_inputs: safety properties ---

def test_enrich_rejects_path_outside_storage_root(tmp_path, monkeypatch):
    root = tmp_path / "storage"
    (root / "1" / "dropped").mkdir(parents=True)
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    # A buffer path OUTSIDE the storage root must be skipped (no sample produced).
    outside = tmp_path / "secret.bin"
    outside.write_bytes(b"TOPSECRET")
    report = {"cape": {"task_id": 1, "injection_buffers": [
        {"target_pid": 5, "injection_address": "0x1000", "path": str(outside)}
    ]}}
    enrich_correlation_inputs(report)
    assert report["_correlation_inputs"]["buffer_samples"] == {}


def test_enrich_rejects_symlink_outside_storage_root(tmp_path, monkeypatch):
    # A symlink INSIDE the storage root whose target is OUTSIDE must be rejected
    # (realpath resolves the link before the containment check).
    root = tmp_path / "storage"
    buf_dir = root / "1" / "dropped"
    buf_dir.mkdir(parents=True)
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    outside = tmp_path / "secret.bin"
    outside.write_bytes(b"TOPSECRET")
    link = buf_dir / "link.bin"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")
    report = {"cape": {"task_id": 1, "injection_buffers": [
        {"target_pid": 5, "injection_address": "0x1000", "path": str(link)}
    ]}}
    enrich_correlation_inputs(report)
    assert report["_correlation_inputs"]["buffer_samples"] == {}


def test_enrich_truncates_buffer_to_sample_size(tmp_path, monkeypatch):
    root = tmp_path / "storage"
    buf_dir = root / "1" / "dropped"
    buf_dir.mkdir(parents=True)
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    monkeypatch.setattr(cr, "_BUFFER_SAMPLE_BYTES", 4)
    buf = buf_dir / "buf.bin"
    buf.write_bytes(b"ABCDEFGH")  # 8 bytes, cap is 4
    report = {"cape": {"task_id": 1, "injection_buffers": [
        {"target_pid": 5, "injection_address": "0x1000", "path": str(buf)}
    ]}}
    enrich_correlation_inputs(report)
    assert report["_correlation_inputs"]["buffer_samples"]["5:0x1000"] == (b"ABCD").hex()


def test_enrich_is_idempotent(tmp_path, monkeypatch):
    root = tmp_path / "storage"
    (root / "1" / "dropped").mkdir(parents=True)
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    report = {"cape": {"task_id": 1, "injection_buffers": []}, "ghidra": {"analyzed_files": []}}
    enrich_correlation_inputs(report)
    first = dict(report["_correlation_inputs"])
    enrich_correlation_inputs(report)
    assert report["_correlation_inputs"] == first


def test_enrich_caps_dropped_file_count(tmp_path, monkeypatch):
    root = tmp_path / "storage"
    dropped = root / "1" / "dropped"
    dropped.mkdir(parents=True)
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    monkeypatch.setattr(cr, "_MAX_DROPPED_FILES", 3)
    for i in range(10):
        (dropped / f"f{i}.bin").write_bytes(b"x")
    report = {"cape": {"task_id": 1, "injection_buffers": []}, "ghidra": {"analyzed_files": []}}
    enrich_correlation_inputs(report)
    assert len(report["_correlation_inputs"]["dropped_files"]) == 3


def test_cross_correlate_pops_inputs_so_bytes_are_not_persisted(tmp_path, monkeypatch):
    root = tmp_path / "storage"
    buf_dir = root / "1" / "dropped"
    buf_dir.mkdir(parents=True)
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    buf = buf_dir / "buf.bin"
    buf.write_bytes(b"PAYLOAD")
    report = {"cape": {"task_id": 1, "injection_buffers": [
        {"target_pid": 5, "injection_address": "0x1000", "path": str(buf)}
    ]}}
    cr.cross_correlate(report)
    assert "_correlation_inputs" not in report  # gathered bytes must not persist


# --- rule_c2_live_in_memory ---

def test_c2_live_in_memory_fires_when_config_ip_in_netscan():
    from lamware_pipeline.correlation_rules import rule_c2_live_in_memory
    report = {
        "cape": {"extracted_configs": [{"C2": "203.0.113.7", "version": "1.2"}]},
        "volatility": {"plugins": {"netscan": [
            {"ForeignAddr": "203.0.113.7", "PID": 1337, "State": "ESTABLISHED"}
        ]}},
    }
    findings = rule_c2_live_in_memory(report)
    assert len(findings) == 1
    assert findings[0]["type"] == "c2_live_in_memory"
    assert findings[0]["severity"] == "high"
    assert findings[0]["indicator"] == "203.0.113.7"
    assert findings[0]["pid"] == 1337


def test_c2_live_in_memory_silent_when_ip_not_connected():
    from lamware_pipeline.correlation_rules import rule_c2_live_in_memory
    report = {
        "cape": {"extracted_configs": [{"C2": "203.0.113.7"}]},
        "volatility": {"plugins": {"netscan": [
            {"ForeignAddr": "127.0.0.1", "PID": 1, "State": "LISTENING"}
        ]}},
    }
    assert rule_c2_live_in_memory(report) == []


def test_c2_live_in_memory_silent_when_c2_ip_is_skipped_address():
    from lamware_pipeline.correlation_rules import rule_c2_live_in_memory
    report = {
        "cape": {"extracted_configs": [{"C2": "0.0.0.0"}]},
        "volatility": {"plugins": {"netscan": [
            {"ForeignAddr": "0.0.0.0", "PID": 1, "State": "ESTABLISHED"}
        ]}},
    }
    assert rule_c2_live_in_memory(report) == []


def test_c2_live_in_memory_dedups_multiple_connections_to_same_c2():
    from lamware_pipeline.correlation_rules import rule_c2_live_in_memory
    report = {
        "cape": {"extracted_configs": [{"C2": "203.0.113.7"}]},
        "volatility": {"plugins": {"netscan": [
            {"ForeignAddr": "203.0.113.7", "PID": 100, "State": "ESTABLISHED"},
            {"ForeignAddr": "203.0.113.7", "PID": 200, "State": "ESTABLISHED"},
        ]}},
    }
    findings = rule_c2_live_in_memory(report)
    assert len(findings) == 1


def test_c2_live_in_memory_fires_from_network_hosts_list():
    from lamware_pipeline.correlation_rules import rule_c2_live_in_memory
    report = {
        "cape": {"network": {"hosts": ["198.51.100.9", "8.8.8.8"]}},
        "volatility": {"plugins": {"netscan": [
            {"ForeignAddr": "198.51.100.9", "PID": 77, "State": "ESTABLISHED"}
        ]}},
    }
    findings = rule_c2_live_in_memory(report)
    assert len(findings) == 1
    assert findings[0]["indicator"] == "198.51.100.9"
