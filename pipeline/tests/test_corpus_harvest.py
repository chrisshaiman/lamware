# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The nightly keep-list names only real, young report directories (#420).

`select` decides which report directories the cleanup skips. Calls it on rows
shaped like KEEP_CANDIDATES' and on real directories; the database fetch is the
one part not exercised here (it is run on the host, see the PR).
"""
import datetime as dt

import pytest
from lamware_pipeline.corpus_harvest import Candidate, select, write

NOW = dt.datetime(2026, 10, 14, tzinfo=dt.UTC)


def _row(task_id, days_old=1, findings=1, rules=("shellcode_self_modified",)):
    return (task_id, "ab" * 32, NOW - dt.timedelta(days=days_old), 1295, "unknown",
            findings, list(rules))


@pytest.fixture
def reports(tmp_path):
    root = tmp_path / "reports"
    for name in ("c8138c80aa17", "v661_5b4f596d3cf5", "old0123456ab"):
        (root / name).mkdir(parents=True)
    return root


def test_a_young_report_that_exists_is_kept(reports):
    got = select([_row("c8138c80aa17"), _row("v661_5b4f596d3cf5")], reports, 60, NOW)
    assert [c.task_id for c in got] == ["c8138c80aa17", "v661_5b4f596d3cf5"]


@pytest.mark.parametrize("bad", ["..", ".", "../reports", "a/b", "", "/etc", ".hidden",
                                 "x" * 101, None])
def test_a_task_id_that_is_not_one_path_component_is_never_named(reports, bad):
    """keep.txt drives what the cleanup skips; a crafted value must not name
    anything outside, or above, the reports directory."""
    assert select([_row(bad)], reports, 60, NOW) == []


def test_a_name_ending_in_a_newline_is_never_named(reports):
    """keep.txt is one name per line, so an embedded newline would split one
    entry into two. The directory exists here, so only the pattern can refuse it
    (`$` would accept it; the anchor is \\Z)."""
    (reports / "c8138c80aa17\n").mkdir()
    assert select([_row("c8138c80aa17\n")], reports, 60, NOW) == []


def test_a_report_older_than_the_keep_window_goes_back_to_the_cleanup(reports):
    assert select([_row("old0123456ab", days_old=61)], reports, 60, NOW) == []


def test_a_report_already_deleted_is_not_listed(reports):
    assert select([_row("aaaaaaaaaaaa")], reports, 60, NOW) == []


def test_a_symlinked_report_dir_is_not_listed(reports, tmp_path):
    (tmp_path / "elsewhere").mkdir()
    (reports / "linked012345").symlink_to(tmp_path / "elsewhere")
    assert select([_row("linked012345")], reports, 60, NOW) == []


@pytest.mark.parametrize("findings,rules,priority", [
    (1, ("shellcode_self_modified",), False),
    (3, ("shellcode_self_modified",), True),
    (1, ("injection_corroborated",), True),
    (1, ("dropped_file_loaded",), True),
])
def test_priority_marks_rich_findings(findings, rules, priority):
    c = Candidate("t", "", NOW, None, "", findings, rules)
    assert c.priority is priority


def test_write_lists_exactly_the_kept_names_and_priority_first(reports, tmp_path):
    out = tmp_path / "harvest"
    out.mkdir()
    cands = select([_row("c8138c80aa17"),
                    _row("v661_5b4f596d3cf5", findings=16, rules=("injection_corroborated",))],
                   reports, 60, NOW)
    write(cands, out)
    assert (out / "keep.txt").read_text().split() == ["c8138c80aa17", "v661_5b4f596d3cf5"]
    rows = (out / "candidates.tsv").read_text().splitlines()
    assert rows[0].startswith("task_id\tpriority")
    assert rows[1].split("\t")[:3] == ["v661_5b4f596d3cf5", "yes", "16"]
    assert not list(out.glob(".*")), "a temp file was left behind"
