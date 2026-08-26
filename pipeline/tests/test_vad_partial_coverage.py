# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A partial read of injection memory must not report as a clean one.

`_gather_vad_samples` originally set a reason only when EVERY address failed
(`if unresolved and not samples`). Analysis 1072 compared 27 of 32 addresses and
emitted `correlation_warnings: []`, so the five it never read were
indistinguishable from five it read and found unmodified.

That is #452's argument at finer grain: "I could not look" is its own answer,
and it stays true when I looked at *most* of it. Every bail-out in the read loop
is therefore counted, and a non-zero count is reported even when other addresses
resolved fine.

These tests drive the real filesystem path — actual dump files under the
reports root — because the silent drops being closed here (a short dump, an
unreadable path) only exist on that path.
"""
import pytest
from lamware_pipeline import correlation_rules as cr

ADDR_BASE = 0x1000


def _report(buffers, vadinfo, dump_dir):
    return {
        "cape": {"injection_buffers": buffers},
        "volatility": {"plugins": {"vadinfo": vadinfo}, "vad_dump_dir": str(dump_dir)},
    }


def _vad(pid, start, name):
    return {"PID": pid, "Start VPN": start, "End VPN": start + 0xFFF, "File output": name}


@pytest.fixture
def dump_root(tmp_path, monkeypatch):
    """A dump dir that passes _within_allowed_root."""
    root = tmp_path / "reports"
    root.mkdir()
    monkeypatch.setattr(cr, "_PIPELINE_REPORTS_ROOT", str(root))
    d = root / "vol_vadinfo"
    d.mkdir()
    return d


def test_some_addresses_resolve_and_some_do_not(dump_root):
    """The case that shipped silent: 1 of 2 read, no warning at all."""
    (dump_root / "hit.dmp").write_bytes(b"\xcc" * 512)
    buffers = [
        {"target_pid": 100, "injection_address": f"{ADDR_BASE:x}"},
        {"target_pid": 100, "injection_address": f"{ADDR_BASE + 0x50000:x}"},  # no VAD
    ]
    report = _report(buffers, [_vad(100, ADDR_BASE, "hit.dmp")], dump_root)

    samples, reason, unresolved = cr._gather_vad_samples(report)

    assert len(samples) == 1, "the resolvable address should still be compared"
    assert reason is None, "a partial read is not a total failure"
    assert unresolved == 1

    cr.enrich_correlation_inputs(report)
    warnings = cr.correlation_warnings(report)
    partial = [w for w in warnings if "partially covered" in w]
    assert partial, f"a partial read must be reported, got {warnings!r}"
    assert "1 of 2" in partial[0], partial[0]


def test_full_coverage_stays_quiet(dump_root):
    """The zero must remain interpretable — no warning when nothing was missed."""
    (dump_root / "hit.dmp").write_bytes(b"\xcc" * 512)
    report = _report(
        [{"target_pid": 100, "injection_address": f"{ADDR_BASE:x}"}],
        [_vad(100, ADDR_BASE, "hit.dmp")],
        dump_root,
    )
    samples, reason, unresolved = cr._gather_vad_samples(report)
    assert len(samples) == 1 and reason is None and unresolved == 0

    cr.enrich_correlation_inputs(report)
    assert not [w for w in cr.correlation_warnings(report) if "partially covered" in w]


def test_a_short_dump_is_counted_not_dropped(dump_root):
    """Seeking past the end of a truncated dump reads b"" — previously silent."""
    (dump_root / "short.dmp").write_bytes(b"\xcc" * 4)  # offset 0x800 is past EOF
    addr = ADDR_BASE + 0x800
    report = _report(
        [{"target_pid": 100, "injection_address": f"{addr:x}"}],
        [_vad(100, ADDR_BASE, "short.dmp")],
        dump_root,
    )
    samples, reason, unresolved = cr._gather_vad_samples(report)
    assert samples == {}
    assert unresolved == 1, "an empty read is a buffer we did not compare"
    assert reason, "nothing resolved at all, so this is a total failure"


def test_an_unparseable_address_is_counted(dump_root):
    (dump_root / "hit.dmp").write_bytes(b"\xcc" * 512)
    buffers = [
        {"target_pid": 100, "injection_address": f"{ADDR_BASE:x}"},
        {"target_pid": 100, "injection_address": "not-hex"},
    ]
    report = _report(buffers, [_vad(100, ADDR_BASE, "hit.dmp")], dump_root)
    _, _, unresolved = cr._gather_vad_samples(report)
    assert unresolved == 1


def test_total_failure_still_reports_unavailable_not_partial(dump_root):
    """The two messages must stay distinct; a total failure is the louder one."""
    report = _report(
        [{"target_pid": 100, "injection_address": f"{ADDR_BASE:x}"}],
        [_vad(100, 0x999000, "other.dmp")],  # no VAD contains the address
        dump_root,
    )
    cr.enrich_correlation_inputs(report)
    warnings = cr.correlation_warnings(report)
    assert [w for w in warnings if "unavailable" in w], warnings
    assert not [w for w in warnings if "partially covered" in w], warnings


def test_no_injection_buffers_produces_no_vad_warning(dump_root):
    """The #453 constraint: this channel must stay quiet on ordinary samples."""
    report = _report([], [], dump_root)
    cr.enrich_correlation_inputs(report)
    assert not [
        w for w in cr.correlation_warnings(report)
        if "partially covered" in w or "Injection-address" in w
    ]


def test_maxsize_skipped_vads_are_recognised_not_guessed_at(dump_root):
    """A VAD over --maxsize reports File output = "Error outputting file".

    Observed on analysis 1072: one 184MB PAGE_EXECUTE_WRITECOPY VAD in pid 4500
    held 7 of the 32 injection addresses and was never dumped. Treating that
    status string as a filename builds `<dump_dir>/Error outputting file` and
    relies on the OSError to catch it. The count came out right by accident.
    """
    report = _report(
        [{"target_pid": 100, "injection_address": f"{ADDR_BASE:x}"}],
        [_vad(100, ADDR_BASE, "Error outputting file")],
        dump_root,
    )
    samples, reason, unresolved = cr._gather_vad_samples(report)
    assert samples == {} and unresolved == 1
    assert not (dump_root / "Error outputting file").exists(), "must not be probed as a path"


@pytest.mark.parametrize("name,is_dump", [
    ("proc.100.0x1000.dmp", True),
    ("Disabled", False),
    ("disabled", False),
    ("Error outputting file", False),
    ("  Error outputting file  ", False),
    ("", False),
])
def test_dump_filename_sentinels(name, is_dump):
    assert cr._is_dump_filename(name) is is_dump
