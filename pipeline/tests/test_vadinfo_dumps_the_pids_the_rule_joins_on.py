# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""vadinfo must dump the pids the correlation rule actually joins on (#614).

`rule_shellcode_self_modified` compares each injection buffer's captured bytes
against the VAD that was dumped at that buffer's address. It looks the VAD up by
`injection_buffers[].target_pid`. But `run_volatility` chose which pids to dump
from `cape.injection_pids` — a *different* CAPE source, derived from signature
data rather than from the API call trace.

Nothing makes the two agree. On verify_salat_20260919 they had no overlap at
all: vadinfo dumped 504 VADs for [972, 1852, 9100] while every buffer targeted
4192, so the rule resolved zero addresses and reported "(3 unresolved)".

The fix is a union, not a substitution — injection_pids still earns its place,
it just isn't the list the consumer keys on. Measured across the corpus the
union newly covers three pids (formbook 8588, unclassified_25d18a2b 8988,
unclassified_42b9c406 9560); quasarrat and warzonerat were already covered.

What this file pins down:
  - the union is what reaches vol's argv, from either source alone or both
  - neither source is silently dropped (the mutation that motivated the issue
    is exactly "use one of them")
  - the pids stay one argv token each, since vadinfo's --pid is nargs="*"
  - the `pslist --dump` loop further down is deliberately NOT unioned: its
    output feeds Ghidra's shellcode candidates, and widening what the agent
    sees would confound the #420 evidence comparison. That is a decision, so
    it is asserted rather than left to be "tidied up" later.
"""
from pathlib import Path

import pytest
from stages import volatility


@pytest.fixture
def vadinfo_pids(tmp_path, monkeypatch):
    """Run run_volatility far enough to build vadinfo's argv, and return the pids."""
    dump = tmp_path / "memory.dmp"
    dump.write_bytes(b"\x00")
    monkeypatch.setattr(volatility, "get_memory_dump_path", lambda _d: dump)

    calls = []

    def fake_plugin(_dump, plugin, _out, _cmd, extra_args=None, **_kw):
        calls.append((plugin, list(extra_args or [])))
        return []

    monkeypatch.setattr(volatility, "run_single_plugin", fake_plugin)

    def run(injection_pids, buffer_pids):
        volatility.run_volatility(
            cape_data={"id": 1}, output_dir=tmp_path / "out",
            volatility_cmd="vol", volatility_triggers=[],
            volatility_standard_plugins=[], volatility_extra_plugins={},
            malfind_enabled=False, malfind_min_size=0, malfind_max_size=0,
            malfind_min_score=0, malfind_max_candidates=0,
            malfind_benign_processes=[],
            get_cape_signatures_fn=lambda _d: [],
            memory_dump_requested=True,
            cape_injection_pids=injection_pids,
            cape_buffer_pids=buffer_pids,
        )
        vad = [args for plugin, args in calls if plugin == "windows.vadinfo"]
        if not vad:
            return None
        args = vad[0]
        return [int(tok) for tok in args[args.index("--pid") + 1:]]

    return run


def test_the_two_sources_are_unioned(vadinfo_pids):
    assert vadinfo_pids([972, 1852], [4192]) == [972, 1852, 4192]


def test_buffer_pids_alone_still_produce_a_dump(vadinfo_pids):
    """salat's shape: signature data named nobody, the call trace named the target.
    Dumping nothing here is what made the rule unresolvable."""
    assert vadinfo_pids([], [4192]) == [4192]


def test_injection_pids_alone_are_not_lost(vadinfo_pids):
    """The mutation to guard against is a substitution rather than a union."""
    assert vadinfo_pids([972, 1852], []) == [972, 1852]


def test_overlapping_sources_are_deduplicated(vadinfo_pids):
    assert vadinfo_pids([8588, 972], [8588]) == [972, 8588]


def test_no_pids_from_either_source_runs_no_vadinfo(vadinfo_pids):
    assert vadinfo_pids([], []) is None


def test_each_pid_is_its_own_argv_token(tmp_path, monkeypatch, vadinfo_pids):
    """vadinfo declares `--pid [PID ...]` (nargs="*"): `--pid 2768 8424` returned
    519 VADs where a comma-joined token is rejected by argparse outright."""
    assert vadinfo_pids([2768], [8424]) == [2768, 8424]


def test_pslist_procdump_is_deliberately_not_unioned():
    """A decision, not an oversight. The `windows.pslist --dump` loop reconstructs
    PE images that become Ghidra's shellcode candidates; unioning it would change
    what the agent sees mid-experiment and confound #420. Revisit after that
    comparison closes, not before."""
    src = (Path(volatility.__file__)).read_text()
    marker = "# Dump hollowed process images"
    tail = src[src.index(marker):]
    assert "if cape_injection_pids and active_dump.exists():" in tail.split("\n\n")[0] \
        or "if cape_injection_pids and active_dump.exists():" in tail[:400], \
        "the procdump gate changed; if that was intentional, update #420's notes"
    assert "cape_buffer_pids" not in tail[:800]
