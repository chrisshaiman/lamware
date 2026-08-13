# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Cape payload discovery (#377).

The bug these cover: both callers looked only in ``dropped/``, which this
deployment never writes. So the load-bearing assertions here are the ones that
build a task with **no** ``dropped/`` directory at all and demand a non-empty
result — reintroducing the old behaviour makes them fail, which the old tests
could not do because they never described where CAPE actually writes.
"""

import hashlib

import pytest
from lamware_shared.cape_payloads import (
    MIN_PAYLOAD_BYTES,
    PAYLOAD_SUBDIRS,
    find_payloads,
    find_pe_payloads,
    payload_dirs,
)

PE = b"MZ\x90\x00"
NOT_PE = b"\x55\x8b\xec\x00"  # a raw code carve: push ebp; mov ebp,esp


def write(directory, name, body=PE, size=MIN_PAYLOAD_BYTES * 2):
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(body + b"\x00" * (size - len(body)))
    return path


def sha_name(seed: str) -> str:
    """A content-addressed filename, the form CAPE actually uses."""
    return hashlib.sha256(seed.encode()).hexdigest()


@pytest.fixture
def task(tmp_path):
    """A storage root plus the task id inside it."""
    return tmp_path, "4242"


def test_finds_payloads_when_dropped_does_not_exist(task):
    """The whole bug: dropped/ is absent, everything is in CAPE/ and files/."""
    storage, tid = task
    write(storage / tid / "CAPE", sha_name("a"))
    write(storage / tid / "files", sha_name("b"))

    found = find_payloads(tid, storage=storage)

    assert not (storage / tid / "dropped").exists()
    assert len(found) == 2, "payloads outside dropped/ must be discoverable"
    assert {p.source for p in found} == {"CAPE", "files"}


def test_searches_every_documented_subdir(task):
    """Each directory contributes independently — none is silently skipped."""
    storage, tid = task
    for sub in PAYLOAD_SUBDIRS:
        write(storage / tid / sub, sha_name(sub))

    by_source = {p.source: p for p in find_payloads(tid, storage=storage)}

    assert set(by_source) == set(PAYLOAD_SUBDIRS)


def test_cape_extractions_rank_above_disk_writes_and_memory_dumps(task):
    """Callers truncate to the first N, so the unpacked payloads must lead."""
    storage, tid = task
    for sub in ("procdump", "files", "CAPE", "dropped"):
        write(storage / tid / sub, sha_name(sub))

    assert [p.source for p in find_payloads(tid, storage=storage)] == [
        "CAPE", "files", "procdump", "dropped",
    ]


def test_ordering_is_stable_across_calls(task):
    """read_payload resolves an index handed out by an earlier call."""
    storage, tid = task
    for i in range(6):
        write(storage / tid / "files", sha_name(f"f{i}"))

    first = [p.path for p in find_payloads(tid, storage=storage)]
    second = [p.path for p in find_payloads(tid, storage=storage)]

    assert first == second
    assert len(first) == 6


def test_same_payload_in_two_dirs_is_deduplicated(task):
    """CAPE names files by SHA-256, so a shared name is the same bytes."""
    storage, tid = task
    name = sha_name("shared")
    write(storage / tid / "CAPE", name)
    write(storage / tid / "files", name)

    found = find_payloads(tid, storage=storage)

    assert len(found) == 1
    assert found[0].source == "CAPE", "the higher-priority copy survives"


def test_non_hash_names_are_never_deduplicated(task):
    """Only a content-addressed name proves two paths hold the same bytes."""
    storage, tid = task
    write(storage / tid / "CAPE", "payload.bin", size=MIN_PAYLOAD_BYTES * 2)
    write(storage / tid / "files", "payload.bin", size=MIN_PAYLOAD_BYTES * 3)

    found = find_payloads(tid, storage=storage)

    assert len(found) == 2
    assert {p.size for p in found} == {MIN_PAYLOAD_BYTES * 2, MIN_PAYLOAD_BYTES * 3}


def test_tiny_files_are_skipped(task):
    """Stub carves and config fragments are not payloads."""
    storage, tid = task
    (storage / tid / "CAPE").mkdir(parents=True)
    (storage / tid / "CAPE" / sha_name("stub")).write_bytes(b"MZ" + b"\x00" * 10)

    assert find_payloads(tid, storage=storage) == []


def test_max_bytes_excludes_dumps_too_large_to_decompile(task):
    """Ghidra on a 78MB process dump runs for hours and yields nothing."""
    storage, tid = task
    write(storage / tid / "procdump", sha_name("huge"), size=MIN_PAYLOAD_BYTES * 10)
    write(storage / tid / "procdump", sha_name("small"), size=MIN_PAYLOAD_BYTES * 2)

    found = find_payloads(tid, storage=storage, max_bytes=MIN_PAYLOAD_BYTES * 3)

    assert [p.size for p in found] == [MIN_PAYLOAD_BYTES * 2]


def test_pe_only_rejects_raw_code_carves(task):
    """CAPE/ holds unpacked code regions with no PE header — Ghidra can't load them."""
    storage, tid = task
    write(storage / tid / "CAPE", sha_name("pe"), body=PE)
    write(storage / tid / "CAPE", sha_name("raw"), body=NOT_PE)

    assert len(find_payloads(tid, storage=storage)) == 2
    pes = find_pe_payloads(tid, storage=storage)
    assert len(pes) == 1
    assert pes[0].path.read_bytes()[:2] == b"MZ"


def test_directories_inside_a_payload_dir_are_not_payloads(task):
    """A subdirectory used to shift every index that followed it."""
    storage, tid = task
    (storage / tid / "files" / "subdir").mkdir(parents=True)
    write(storage / tid / "files", sha_name("real"))

    found = find_payloads(tid, storage=storage)

    assert [p.path.name for p in found] == [sha_name("real")]


def test_missing_task_id_is_empty_not_an_error(task):
    storage, _ = task
    assert find_payloads(None, storage=storage) == []
    assert find_payloads("", storage=storage) == []
    assert payload_dirs(None, storage=storage) == []


def test_task_with_no_extraction_dirs_is_empty(task):
    storage, tid = task
    (storage / tid).mkdir(parents=True)
    assert payload_dirs(tid, storage=storage) == []
    assert find_payloads(tid, storage=storage) == []


def test_unreadable_payload_does_not_abort_the_scan(task):
    """One bad file must not hide the rest of the extraction."""
    storage, tid = task
    bad = write(storage / tid / "files", sha_name("bad"))
    write(storage / tid / "files", sha_name("good"))
    bad.chmod(0o000)
    try:
        found = find_pe_payloads(tid, storage=storage)
    finally:
        bad.chmod(0o644)

    assert [p.path.name for p in found] == [sha_name("good")]
