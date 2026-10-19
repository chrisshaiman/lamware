# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""CAPE's analysis store is bounded by its own cleaner, not by `find -delete` (#795).

Structural, a memory of two things read in the installed CAPE while writing the
retention cron: `--delete-older-than` is the only option that removes a task's
directory, Postgres row and Mongo report together, and the two sibling options
(`--delete-tmp-items-older-than`, `--delete-binaries-items-older-than`) compare
`ctime > cutoff` and so delete the NEWER items. Only a deploy observes the
retention itself (task count and directory count before and after the first
run); this keeps the job's shape from drifting back to either mistake.
"""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
CAPE = ROOT / "ansible" / "roles" / "cape"
TASKS = yaml.safe_load((CAPE / "tasks" / "main.yml").read_text(encoding="utf-8"))
DEFAULTS = yaml.safe_load((CAPE / "defaults" / "main.yml").read_text(encoding="utf-8"))


def _cron(name: str) -> dict:
    for task in TASKS:
        cron = task.get("ansible.builtin.cron") or task.get("cron")
        if isinstance(cron, dict) and cron.get("name") == name:
            return cron
    raise AssertionError(f"no cron task named {name!r} in the cape role")


def test_retention_runs_capes_cleaner_with_the_configured_period():
    job = _cron("cape-analysis-retention")["job"]
    assert "utils/cleaners.py" in job
    assert "--delete-older-than {{ cape_analysis_retention_days }}d" in job
    assert "--delete-mongo" in job, "a report left in Mongo outlives its task row"
    assert "find " not in job, "a bare find -delete leaves the task row and report behind"


def test_retention_does_not_use_the_inverted_upstream_options():
    job = _cron("cape-analysis-retention")["job"]
    assert "--delete-tmp-items-older-than" not in job
    assert "--delete-binaries-items-older-than" not in job


def test_retention_period_default_and_user():
    assert DEFAULTS["cape_analysis_retention_days"] == 60
    assert _cron("cape-analysis-retention")["user"] == "{{ cape_user }}"


def test_retention_is_tagged_with_the_cron_tag_that_restores_cron_allow():
    """The cron.allow task carries this tag so a tag-limited deploy cannot add
    the entry without first letting cape use crontab (see the role's comment)."""
    for task in TASKS:
        cron = task.get("ansible.builtin.cron") or task.get("cron")
        if isinstance(cron, dict) and cron.get("name") == "cape-analysis-retention":
            assert "cape-storage-perms" in task.get("tags", [])
            return
    raise AssertionError("retention cron task not found")
