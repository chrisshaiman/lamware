# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""PowerShell content detection read a key nothing ever wrote.

`is_powershell_script` has three tests: the filename extension, the MIME type,
and — for anything that merely looks like text — a content sniff of the sample's
first 2KB for PowerShell keywords.

That third branch resolved its path from `report["_sample_path"]`. Nothing in
the pipeline sets that key; a grep across `ansible/` finds no writer at all. So
the branch never ran, and a PowerShell payload delivered without a `.ps1`
extension and without a `powershell` MIME type was never routed to the
deobfuscation stage. Malware does not helpfully name its droppers `.ps1`, which
is precisely the case the content sniff existed to catch.

The path is now a parameter. That also keeps a host filesystem path out of
`report.json`, which is an evidentiary artifact.

Same bug class as #406 (`get_api_traces` reading `cape.behavior`): a consumer
reading a key with no producer, invisible because the fallback is silent.
"""
from stages.powershell import is_powershell_script

PS_BODY = (
    "param($x)\n"
    "$env:TEMP\n"
    "Invoke-Expression ([Convert]::FromBase64String($x))\n"
    "New-Object System.Net.WebClient\n"
)


def _text_report(name="invoice.txt"):
    return {"sample_name": name, "triage": {"file_type": "ASCII text", "file_mime": "text/plain"}}


def test_a_ps1_extension_is_still_detected():
    """Positive control for the branch that always worked."""
    assert is_powershell_script({"sample_name": "x.ps1", "triage": {}}) is True


def test_a_powershell_mime_is_still_detected():
    assert is_powershell_script(
        {"sample_name": "x.bin", "triage": {"file_mime": "text/x-powershell"}}) is True


def test_powershell_content_without_a_ps1_extension_is_detected(tmp_path):
    """THE bug. This is the case the content sniff exists for, and it never ran."""
    f = tmp_path / "invoice.txt"
    f.write_text(PS_BODY, encoding="utf-8")
    assert is_powershell_script(_text_report(), str(f)) is True, (
        "a PowerShell payload without a .ps1 extension was not detected")


def test_plain_text_is_not_misdetected(tmp_path):
    """The sniff needs two keyword hits; ordinary prose must not trip it."""
    f = tmp_path / "notes.txt"
    f.write_text("Dear customer, please find the invoice attached.\n", encoding="utf-8")
    assert is_powershell_script(_text_report(), str(f)) is False


def test_a_single_keyword_is_not_enough(tmp_path):
    """Guards the >= 2 threshold, so widening the keyword list cannot quietly
    turn every text file into a PowerShell script."""
    f = tmp_path / "readme.txt"
    f.write_text("Run powershell to continue.\n", encoding="utf-8")
    assert is_powershell_script(_text_report(), str(f)) is False


def test_a_missing_or_omitted_path_degrades_quietly(tmp_path):
    """Callers that cannot supply a path must not crash — the extension and MIME
    checks still have to work."""
    assert is_powershell_script(_text_report()) is False
    assert is_powershell_script(_text_report(), str(tmp_path / "gone.txt")) is False
    assert is_powershell_script({"sample_name": "x.ps1", "triage": {}}, "") is True


def test_the_dead_key_is_gone():
    """Structural guard: reinstating report["_sample_path"] restores a branch
    that cannot execute, and nothing would fail.

    Comments are stripped first. This assertion failed on its first run by
    matching the comment that explains the removal — the same trap
    tests/test_ntfy_alerting.py documents with its _code_only helper. Look at
    the code, not at the prose about the code.
    """
    import inspect
    src = "\n".join(
        line for line in inspect.getsource(is_powershell_script).splitlines()
        if not line.lstrip().startswith("#")
    )
    assert "_sample_path" not in src, (
        "is_powershell_script reads _sample_path again; nothing in the pipeline "
        "writes that key, so the content-detection branch would be dead")
