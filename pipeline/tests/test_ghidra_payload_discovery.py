# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The Ghidra stage's view of what Cape extracted (#377).

get_dropped_pe_files() looked only in ``<task>/dropped``, which is empty in
1017 of 1017 analyses on this deployment. Every run therefore fell through to
``trigger_reason: original_sample_is_pe`` and decompiled the *packed* sample —
the unpacked payloads sitting in ``CAPE/`` were never touched.
"""

from lamware_shared.cape_payloads import MAX_ANALYSABLE_BYTES
from stages.ghidra import get_dropped_pe_files, should_run_ghidra

PE = b"MZ\x90\x00"


def write_pe(directory, name, size=8192, body=PE):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(body + b"\x00" * (size - len(body)))


def name_for(seed):
    return f"{seed:0>64}"[:64].replace(" ", "0")


def test_finds_unpacked_payloads_cape_extracted(tmp_path):
    """The regression: no dropped/ at all, payloads in CAPE/ and files/."""
    write_pe(tmp_path / "900" / "CAPE", name_for("a"))
    write_pe(tmp_path / "900" / "files", name_for("b"))

    found = get_dropped_pe_files({"id": 900}, storage=tmp_path)

    assert not (tmp_path / "900" / "dropped").exists()
    assert len(found) == 2


def test_cape_extractions_come_first(tmp_path):
    """run_ghidra analyses only pe_files[:5] — order decides what gets seen."""
    for i in range(6):
        write_pe(tmp_path / "900" / "procdump", name_for(f"p{i}"))
    write_pe(tmp_path / "900" / "CAPE", name_for("unpacked"))

    found = get_dropped_pe_files({"id": 900}, storage=tmp_path)

    assert found[0].parent.name == "CAPE"
    assert any(p.parent.name == "CAPE" for p in found[:5]), (
        "the unpacked payload must survive the caller's 5-file cap"
    )


def test_oversized_process_dumps_are_excluded(tmp_path):
    """Ghidra on a 78MB dump runs for hours; procdump routinely holds those."""
    write_pe(tmp_path / "900" / "procdump", name_for("huge"),
             size=MAX_ANALYSABLE_BYTES + 4096)
    write_pe(tmp_path / "900" / "procdump", name_for("ok"))

    found = get_dropped_pe_files({"id": 900}, storage=tmp_path)

    assert [p.name for p in found] == [name_for("ok")]


def test_non_pe_carves_are_not_handed_to_ghidra(tmp_path):
    """CAPE/ holds raw code regions with no PE header — not loadable images."""
    write_pe(tmp_path / "900" / "CAPE", name_for("raw"), body=b"\x55\x8b\xec\x00")
    write_pe(tmp_path / "900" / "CAPE", name_for("pe"))

    found = get_dropped_pe_files({"id": 900}, storage=tmp_path)

    assert [p.name for p in found] == [name_for("pe")]


def test_task_without_cape_id_is_empty(tmp_path):
    assert get_dropped_pe_files({}, storage=tmp_path) == []


def test_extracted_payloads_now_reach_the_ghidra_trigger(tmp_path):
    """should_run_ghidra's has_trigger-and-has_dropped_pes arm was unreachable.

    With dropped/ always empty, has_dropped_pes was always False, so the
    highest-value branch — packing signatures *plus* extracted payloads —
    could never be taken. Only the original-sample fallback ever fired.
    """
    ghidra_cmd = tmp_path / "run-ghidra"
    ghidra_cmd.write_text("#!/bin/sh\n")
    write_pe(tmp_path / "900" / "CAPE", name_for("unpacked"))
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"not-a-pe")  # so only the payload arm can trigger

    assert should_run_ghidra(
        {"id": 900, "status": "reported"},
        sample,
        str(ghidra_cmd),
        lambda _cape: ["packed_binary"],
        storage=tmp_path,
    ) is True


def test_no_payloads_and_no_pe_sample_does_not_trigger(tmp_path):
    """Positive control: the trigger above is not simply always True."""
    ghidra_cmd = tmp_path / "run-ghidra"
    ghidra_cmd.write_text("#!/bin/sh\n")
    (tmp_path / "900").mkdir()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"not-a-pe")

    assert should_run_ghidra(
        {"id": 900, "status": "reported"},
        sample,
        str(ghidra_cmd),
        lambda _cape: ["packed_binary"],
        storage=tmp_path,
    ) is False
