# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""safe_write refuses every way a planted link could redirect a report write."""
import os

import pytest
from lamware_shared import safe_write

pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX semantics")


@pytest.fixture
def report(tmp_path):
    d = tmp_path / "report"
    d.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    return d, victim, elsewhere


def test_writes_and_creates_missing_directories(report):
    root, _, _ = report
    safe_write.write_bytes(root / "a" / "b" / "x.bin", b"data", root=root)
    assert (root / "a" / "b" / "x.bin").read_bytes() == b"data"


def test_replaces_an_existing_file(report):
    root, _, _ = report
    (root / "x.json").write_text("old")
    safe_write.write_text(root / "x.json", "new", root=root)
    assert (root / "x.json").read_text() == "new"
    assert not [p for p in root.iterdir() if p.name.startswith(".")], "temp file left"


def test_a_link_at_the_file_is_replaced_not_followed(report):
    root, victim, _ = report
    (root / "report.json").symlink_to(victim)
    safe_write.write_text(root / "report.json", "mine", root=root)
    assert victim.read_text() == "untouched"
    assert not (root / "report.json").is_symlink()
    assert (root / "report.json").read_text() == "mine"


def test_a_link_at_the_parent_directory_is_refused(report):
    root, _, elsewhere = report
    (root / "cape_injections").symlink_to(elsewhere)
    with pytest.raises(OSError):
        safe_write.write_bytes(root / "cape_injections" / "inject.bin", b"x", root=root)
    assert list(elsewhere.iterdir()) == []


def test_a_link_at_an_intermediate_directory_is_refused(report):
    root, _, elsewhere = report
    (elsewhere / "results").mkdir()
    (root / "llm_audit").symlink_to(elsewhere)
    with pytest.raises(OSError):
        safe_write.write_text(root / "llm_audit" / "results" / "0001.json", "{}", root=root)
    assert list((elsewhere / "results").iterdir()) == []


def test_append_refuses_a_link_and_appends_to_a_file(report):
    root, victim, _ = report
    (root / "trail.jsonl").symlink_to(victim)
    with pytest.raises(OSError):
        safe_write.append_text(root / "trail.jsonl", "row\n", root=root)
    assert victim.read_text() == "untouched"
    (root / "trail.jsonl").unlink()
    safe_write.append_text(root / "trail.jsonl", "a\n", root=root)
    safe_write.append_text(root / "trail.jsonl", "b\n", root=root)
    assert (root / "trail.jsonl").read_text() == "a\nb\n"


def test_a_path_outside_the_root_is_refused(report, tmp_path):
    root, _, _ = report
    with pytest.raises(ValueError):
        safe_write.write_text(tmp_path / "outside.json", "x", root=root)
    with pytest.raises(ValueError):
        safe_write.write_text(root / ".." / "escape.json", "x", root=root)
