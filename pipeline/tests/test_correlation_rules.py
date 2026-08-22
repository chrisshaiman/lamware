# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Per-rule unit tests + enrich safety tests for the correlation rule registry.

Rules are pure functions of the report dict, so each is tested with an inline
dict fixture (no filesystem). enrich (the only impure step) is tested separately
with tmp_path + a monkeypatched storage root.
"""
import json

import lamware_pipeline.correlation_rules as cr
import pytest
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


def _loaded(*entries):
    return {"volatility": {"plugins": {"dlllist": list(entries)}}}


def _with_dropped(report, *dropped):
    report["_correlation_inputs"] = {"dropped_files": list(dropped), "buffer_samples": {}}
    return report


def test_a_dropped_ntdll_does_not_correlate_with_the_system_ntdll():
    """The rule reduced the dropped file to its basename and accepted a
    SUBSTRING match against any loaded module, so a sample dropping `ntdll.dll`
    into Temp reported HIGH against the real `system32\\ntdll.dll`. DLL
    side-loading is the most common reason a dropped name collides with a loaded
    one, so the rule misfired hardest on the samples it exists for — and the
    finding carried +5 on the deterministic severity score (ADR-017)."""
    report = _with_dropped(
        _loaded({"Process": "victim.exe", "PID": 42,
                 "Path": "C:\\Windows\\System32\\ntdll.dll", "Name": "ntdll.dll"}),
        "C:\\Users\\v\\AppData\\Local\\Temp\\ntdll.dll",
    )
    assert rule_dropped_file_loaded(report) == []


def test_the_same_dll_loaded_from_where_it_was_dropped_still_fires():
    """The mirror of the test above: side-loading is only distinguishable from
    the system copy by the path, so the path is what has to match."""
    report = _with_dropped(
        _loaded({"Process": "victim.exe", "PID": 42,
                 "Path": "C:\\Users\\v\\AppData\\Local\\Temp\\ntdll.dll", "Name": "ntdll.dll"}),
        "C:\\Users\\v\\AppData\\Local\\Temp\\ntdll.dll",
    )
    findings = rule_dropped_file_loaded(report)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high", "severity of a true positive is unchanged"


def test_an_empty_dropped_name_matches_nothing():
    """`loaded_dlls.add(dll_name.lower() if dll_name else "")` put "" in the match
    set, and a dropped path ending in a separator reduced to "" — which then
    matched via exact membership, unconditionally."""
    report = _with_dropped(
        _loaded({"Process": "svc.exe", "PID": 1,
                 "Path": "C:\\Windows\\System32\\ntdll.dll", "Name": ""}),
        "C:\\Temp\\",
        "",
    )
    assert rule_dropped_file_loaded(report) == []


def test_a_dlllist_entry_with_no_path_cannot_confirm_a_load():
    """Matching a dropped file against a bare module NAME is the basename join
    again, so an entry that carries no Path establishes nothing.

    Both sides are bare here on purpose. With a full dropped path the assertion
    holds whether or not the rule falls back to Name — `c:\\temp\\evil.dll` never
    equals `evil.dll` — so it would pass against a rule that had no such guard.
    The rule is a pure function of its inputs and is tested as one; the
    gatherer's own guarantee that dropped paths are absolute is asserted
    separately, and neither test should depend on the other holding."""
    report = _with_dropped(
        _loaded({"Process": "svc.exe", "PID": 1, "Path": "", "Name": "evil.dll"}),
        "evil.dll",
    )
    assert rule_dropped_file_loaded(report) == []

    with_full_path = _with_dropped(
        _loaded({"Process": "svc.exe", "PID": 1, "Path": "", "Name": "evil.dll"}),
        "C:\\Temp\\evil.dll",
    )
    assert rule_dropped_file_loaded(with_full_path) == []


def test_wow64_redirection_is_the_same_file():
    """Observed on task 1023: the sample dropped
    `System32\\config\\systemprofile\\...\\UltraSuiteSmartCoreware\\ffmpeg.dll` and
    Grape.exe loaded the SysWOW64 form of that exact path. A 32-bit process
    writing to System32 is redirected to SysWOW64, so Cape logs one end of the
    redirection and Volatility reads the other — the same recording difference
    as argv0 quoting in rule_cmdline_spoofing, not a different file."""
    report = _with_dropped(
        _loaded({"Process": "Grape.exe", "PID": 8652, "Name": "ffmpeg.dll",
                 "Path": "C:\\WINDOWS\\SysWOW64\\config\\systemprofile\\AppData\\Local\\Suite\\ffmpeg.dll"}),
        "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Suite\\ffmpeg.dll",
    )
    assert len(rule_dropped_file_loaded(report)) == 1


def test_wow64_folding_does_not_relax_the_rest_of_the_path():
    """The same run dropped d3dcompiler_47.dll under SystemTemp and under
    System32\\config\\systemprofile, while dwm.exe loaded the real
    system32\\D3DCOMPILER_47.dll. Everything below the redirected root still has
    to match, or folding SysWOW64 would hand back the basename join."""
    report = _with_dropped(
        _loaded({"Process": "dwm.exe", "PID": 1104, "Name": "D3DCOMPILER_47.dll",
                 "Path": "C:\\WINDOWS\\system32\\D3DCOMPILER_47.dll"}),
        "C:\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Suite\\d3dcompiler_47.dll",
        "C:\\Windows\\SystemTemp\\is-UH4P8TPWUR.tmp\\d3dcompiler_47.dll",
    )
    assert rule_dropped_file_loaded(report) == []


def test_path_separator_and_case_differences_still_correlate():
    """Normalisation is on the comparison, not the evidence: the same file
    written two ways is still the same file."""
    report = _with_dropped(
        _loaded({"Process": "victim.exe", "PID": 9,
                 "Path": "c:/temp/evil.dll", "Name": "evil.dll"}),
        "C:\\Temp\\Evil.dll",
    )
    assert len(rule_dropped_file_loaded(report)) == 1


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


def _cmdlines(cape_cmd, vol_cmd, pid=4444):
    return {
        "cape": {"process_cmdlines": {pid: cape_cmd}},
        "volatility": {"plugins": {"cmdline": [{"PID": pid, "Args": vol_cmd}]}},
    }


def test_argv0_quoting_is_not_command_line_spoofing():
    """Cape logs the launch command line; Volatility reads the PEB later. One
    quoting the image path and the other not is a recording difference, and the
    old rule called it CRITICAL — worth +10 on the deterministic severity score
    that GHSA-f5q8-v78c-mr55 exists to keep free of unreliable signal."""
    assert rule_cmdline_spoofing(_cmdlines('"C:\\x.exe" -a', "C:\\x.exe -a")) == []


def test_whitespace_runs_between_arguments_are_not_spoofing():
    assert rule_cmdline_spoofing(_cmdlines("C:\\x.exe -a  -b", "C:\\x.exe -a -b")) == []


def test_an_unresolvable_short_path_does_not_produce_a_critical_finding():
    """8.3 vs long form cannot be resolved without the guest filesystem, which is
    gone by the time correlation runs. For a rule feeding the deterministic
    score, missing a spoof that happens to involve PROGRA~1 is the cheaper error
    than calling an ordinary Windows abbreviation critical."""
    assert rule_cmdline_spoofing(
        _cmdlines("C:\\PROGRA~1\\app\\x.exe -a", "C:\\Program Files\\app\\x.exe -a")
    ) == []


def test_a_real_argument_change_is_still_critical():
    """The mirror: normalisation must not swallow a changed argument vector."""
    findings = rule_cmdline_spoofing(
        _cmdlines('"C:\\x.exe" -a', "C:\\x.exe -a --exfil http://evil.example")
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "critical", "severity of a true positive is unchanged"


def test_a_replaced_image_path_is_still_critical():
    findings = rule_cmdline_spoofing(_cmdlines('"C:\\real\\app.exe"', "C:\\fake\\evil.exe"))
    assert len(findings) == 1
    assert findings[0]["type"] == "cmdline_spoofing"


def test_quoted_arguments_containing_spaces_are_one_token():
    """The splitter has to respect quotes, or `-p "a b"` and `-p "a  b"` would
    normalise to the same thing and a changed argument would be lost."""
    assert cr._split_cmdline('x.exe -p "a b" -q') == ["x.exe", "-p", "a b", "-q"]
    assert rule_cmdline_spoofing(_cmdlines('x.exe -p "a b"', 'x.exe -p "a  b"')) != []


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


def _write_manifest(root, task_id, records):
    task_dir = root / str(task_id)
    task_dir.mkdir(parents=True, exist_ok=True)
    (task_dir / "files.json").write_text(
        "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
    )


def test_enrich_caps_dropped_file_count(tmp_path, monkeypatch):
    root = tmp_path / "storage"
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    monkeypatch.setattr(cr, "_MAX_DROPPED_FILES", 3)
    _write_manifest(root, 1, [
        {"filepath": f"C:\\Temp\\f{i}.bin", "category": "", "path": f"files/{i}"}
        for i in range(10)
    ])
    report = {"cape": {"task_id": 1, "injection_buffers": []}, "ghidra": {"analyzed_files": []}}
    enrich_correlation_inputs(report)
    assert len(report["_correlation_inputs"]["dropped_files"]) == 3


# --- _gather_dropped_files: the manifest, not a directory CAPEv2 never makes ---

def test_dropped_files_come_from_the_cape_manifest(tmp_path, monkeypatch):
    """The guest path is what the rule needs, and files.json is the only place
    that records it. Listing `<task>/dropped/` — the previous source — returned
    nothing on all 1024 analyses on the sandbox host, because that directory is
    Cuckoo's layout and CAPEv2 does not create it."""
    root = tmp_path / "storage"
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    _write_manifest(root, 7, [
        {"filepath": "C:\\WINDOWS\\TEMP\\KL-X86.msi", "category": "", "path": "files/aa"},
    ])
    paths, reason = cr._gather_dropped_files({"cape": {"task_id": 7}})
    assert paths == ["C:\\WINDOWS\\TEMP\\KL-X86.msi"]
    assert reason is None


def test_cape_internal_dump_artifacts_are_not_dropped_files(tmp_path, monkeypatch):
    """CAPE/procdump/memory records point into CAPE's own randomised staging
    directory. Treating them as files the sample wrote would correlate CAPE's
    instrumentation with the sample's behaviour."""
    root = tmp_path / "storage"
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    _write_manifest(root, 7, [
        {"filepath": "C:\\bAsEzF\\CAPE\\4336_2350668654", "category": "CAPE", "path": "CAPE/aa"},
        {"filepath": "C:\\bAsEzF\\memory\\4336.dmp", "category": "memory", "path": "memory/4336.dmp"},
        {"filepath": "C:\\x\\CAPE\\7836_2204900", "category": "procdump", "path": "procdump/bb"},
    ])
    paths, reason = cr._gather_dropped_files({"cape": {"task_id": 7}})
    assert paths == []
    assert reason is None


def test_hash_named_manifest_entries_without_a_guest_path_are_skipped(tmp_path, monkeypatch):
    """`category: files` entries whose filepath is just the sha256 again carry no
    origin, so there is nothing to compare against a loaded module path."""
    root = tmp_path / "storage"
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    _write_manifest(root, 7, [
        {"filepath": "8ebc92ac9ddf6b77", "category": "files", "path": "files/8ebc92ac9ddf6b77"},
    ])
    assert cr._gather_dropped_files({"cape": {"task_id": 7}})[0] == []


def test_a_missing_manifest_reports_a_reason_rather_than_an_empty_list(tmp_path, monkeypatch):
    """The bug this rule spent its life in: no dropped files and no way to tell
    that apart from having never looked."""
    root = tmp_path / "storage"
    (root / "7").mkdir(parents=True)
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    paths, reason = cr._gather_dropped_files({"cape": {"task_id": 7}})
    assert paths == []
    assert reason and "files.json" in reason


def test_no_cape_stage_is_not_reported_as_a_missing_manifest():
    """Cape not running is a reported pipeline state, like `triggered: False` on
    the Volatility side — not a degradation to warn about."""
    assert cr._gather_dropped_files({}) == ([], None)


def test_manifest_outside_the_storage_root_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(tmp_path / "storage"))
    paths, reason = cr._gather_dropped_files({"cape": {"task_id": "../../etc"}})
    assert paths == []
    assert reason == "manifest path outside the allowed storage root"


def test_a_dropped_file_reaches_a_finding_through_cross_correlate(tmp_path, monkeypatch):
    """End to end through the real entrypoint, because every part of this rule
    was individually defensible while the whole produced nothing: the manifest
    is read, a guest path comes out, and the path matches a loaded module.

    Written against the shape of a real files.json record from the sandbox host
    (JSON Lines; `filepath` is the guest path, `path` the storage location)."""
    root = tmp_path / "storage"
    monkeypatch.setattr(cr, "_CAPE_STORAGE_ROOT", str(root))
    _write_manifest(root, 104, [
        {"path": "files/8ebc92ac", "filepath": "C:\\WINDOWS\\TEMP\\svchost.dll",
         "pids": [4336], "ppids": [1796], "metadata": "", "category": ""},
        {"path": "memory/4336.dmp", "filepath": "C:\\bAsEzF\\memory\\4336.dmp",
         "pids": [4336], "ppids": [], "metadata": "", "category": "memory"},
    ])
    report = {
        "cape": {"task_id": 104},
        "volatility": {"plugins": {"dlllist": [
            {"Process": "explorer.exe", "PID": 1796,
             "Path": "C:\\Windows\\System32\\ntdll.dll", "Name": "ntdll.dll"},
            {"Process": "svchost.exe", "PID": 4336,
             "Path": "C:\\WINDOWS\\TEMP\\svchost.dll", "Name": "svchost.dll"},
        ]}},
    }
    findings = cr.cross_correlate(report)
    dropped = [f for f in findings if f["type"] == "dropped_file_loaded"]
    assert len(dropped) == 1
    assert "svchost.dll" in dropped[0]["title"]
    assert "pid 4336" in dropped[0]["detail"]
    assert not [w for w in report["correlation_warnings"] if "dropped-file manifest" in w]
    assert "_correlation_inputs" not in report


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


# --- rule_injection_corroborated ---

def test_injection_corroborated_fires_when_target_pid_has_malfind_region():
    from lamware_pipeline.correlation_rules import rule_injection_corroborated
    report = {
        "cape": {"injection_buffers": [{"target_pid": 1234, "injection_address": "0x1000", "path": ""}]},
        "volatility": {"plugins": {"malfind": [
            {"PID": 1234, "Start VPN": 0x1000, "Hexdump": "90 90"},
            {"PID": 1234, "Start VPN": 0x2000, "Hexdump": "cc cc"},
        ]}},
    }
    findings = rule_injection_corroborated(report)
    assert len(findings) == 1
    assert findings[0]["type"] == "injection_corroborated"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["pid"] == 1234
    assert "2 anomalous executable region(s)" in findings[0]["detail"]


def test_injection_corroborated_silent_when_malfind_in_other_pid():
    from lamware_pipeline.correlation_rules import rule_injection_corroborated
    report = {
        "cape": {"injection_buffers": [{"target_pid": 1234, "injection_address": "0x1000", "path": ""}]},
        "volatility": {"plugins": {"malfind": [{"PID": 9999, "Start VPN": 0x1000, "Hexdump": "90"}]}},
    }
    assert rule_injection_corroborated(report) == []


def test_injection_corroborated_silent_when_target_pid_is_none():
    from lamware_pipeline.correlation_rules import rule_injection_corroborated
    report = {
        "cape": {"injection_buffers": [{"injection_address": "0x1000", "path": ""}]},  # no target_pid
        "volatility": {"plugins": {"malfind": [{"PID": 1234, "Start VPN": 0x1000, "Hexdump": "90"}]}},
    }
    assert rule_injection_corroborated(report) == []


def test_enrich_reads_buffer_under_pipeline_reports_root(tmp_path, monkeypatch):
    # Injection buffers live under the pipeline reports tree (output_dir/cape_injections),
    # NOT the CAPE storage tree — enrich must read from there too (regression guard).
    reports = tmp_path / "reports"
    inj_dir = reports / "task1" / "cape_injections"
    inj_dir.mkdir(parents=True)
    monkeypatch.setattr(cr, "_PIPELINE_REPORTS_ROOT", str(reports))
    buf = inj_dir / "inject.bin"
    buf.write_bytes(b"SHELLCODE")
    report = {"cape": {"task_id": "task1", "injection_buffers": [
        {"target_pid": 5, "injection_address": "0x1000", "path": str(buf)}
    ]}}
    enrich_correlation_inputs(report)
    assert report["_correlation_inputs"]["buffer_samples"]["5:0x1000"] == (b"SHELLCODE").hex()


# ---------------------------------------------------------------------------
# Command-line spoofing must survive the JSON round-trip
# ---------------------------------------------------------------------------
#
# rule_cmdline_spoofing keyed its Volatility lookup by the cmdline plugin's PID
# (an int from the -r json renderer) and then iterated cape["process_cmdlines"],
# whose keys are ints ONLY while the report is in memory. stages/cape.py builds
# them from int process_id, json.dump writes them as JSON object keys — i.e.
# strings — and run_replay reloads the report with no coercion.
#
# So on the replay path every lookup missed and the rule returned [] no matter
# how badly a command line had been spoofed. The live path was unaffected, which
# is why the existing fixtures never caught it: they only ever construct the
# in-memory int-keyed shape.
#
# Replay is not read-only. run-pipeline's write_report() rewrites the SAME
# reports/<task>/report.json, so a re-run erased the original `critical` finding
# from the canonical artifact, and the degraded report is then what feeds
# ingest_to_db and the PDF generator.

def _spoofed_report():
    return {
        "cape": {"process_cmdlines": {1234: 'C:\\Windows\\System32\\svchost.exe -k netsvcs'}},
        "volatility": {"plugins": {"cmdline": [
            {"PID": 1234, "Args": 'C:\\Users\\v\\AppData\\Local\\Temp\\evil.exe --beacon'},
        ]}},
    }


def _round_trip(report):
    """What run_replay does: the report comes back off disk, so dict keys that
    were ints are now strings."""
    return json.loads(json.dumps(report))


def test_cmdline_spoofing_is_detected_in_memory():
    """Positive control. Without it, a rule that detects nothing at all would
    satisfy the replay assertion below."""
    findings = rule_cmdline_spoofing(_spoofed_report())
    assert len(findings) == 1, findings
    assert findings[0]["type"] == "cmdline_spoofing"
    assert findings[0]["severity"] == "critical"


def test_cmdline_spoofing_is_still_detected_after_a_json_round_trip():
    """THE bug. Same data, string PID keys, and the rule went silent."""
    findings = rule_cmdline_spoofing(_round_trip(_spoofed_report()))
    assert len(findings) == 1, (
        "spoofing went undetected on the replay path; a re-run then overwrites "
        "report.json and erases the original critical finding")
    assert findings[0]["severity"] == "critical"


def test_the_round_trip_really_does_change_the_key_type():
    """Guards the guard: if keys stayed ints, the test above would be a
    duplicate of the in-memory one and would prove nothing."""
    assert list(_round_trip(_spoofed_report())["cape"]["process_cmdlines"]) == ["1234"]


def test_a_matching_cmdline_is_not_flagged_either_way():
    """The rule must not start firing on every process now that keys agree."""
    same = {
        "cape": {"process_cmdlines": {1234: "C:\\Windows\\System32\\svchost.exe -k netsvcs"}},
        "volatility": {"plugins": {"cmdline": [
            {"PID": 1234, "Args": "C:\\Windows\\System32\\svchost.exe -k netsvcs"},
        ]}},
    }
    assert rule_cmdline_spoofing(same) == []
    assert rule_cmdline_spoofing(_round_trip(same)) == []
