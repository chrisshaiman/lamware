# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The deploy provenance marker must be written on TAGGED deploys (#151).

A provenance marker that only appears on full deploys is absent exactly when it is
needed. `make deploy TAGS=pipeline` is the common case here, and Ansible skips
pre_tasks entirely unless they carry the `always` tag — the same trap that let an
empty vault variable through in #238, documented a few lines above these tasks.

Measured 2026-08-03, which is why this exists: a `TAGS=pipeline` deploy ran from a
clean `main` while the change under test — the `qwen@15` arm — existed only on an
unmerged feature branch. The host silently reverted to main's copy of `arms.py`, and
the next eval would have run at depth 10 for fifty minutes while being recorded as
depth 15. It was caught by chance, by checking the arm registry before launching.

Note what a bare SHA would have shown: `main`, clean, current. Perfectly healthy. The
marker therefore records BRANCH and DIRTY as well, and `make provenance-has` answers
the question that actually catches this — "is THIS commit live?".

Parses the YAML and the Makefile rather than running a deploy, so it runs in CI with
no host.
"""
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "ansible" / "site.yml"
MAKEFILE = ROOT / "Makefile"

# Task-name fragments identifying the provenance block.
_PROVENANCE = ("git HEAD", "branch", "uncommitted", "provenance")


def _pre_tasks() -> list[dict]:
    play = yaml.safe_load(SITE.read_text(encoding="utf-8"))[0]
    return play.get("pre_tasks") or []


def _provenance_tasks() -> list[dict]:
    return [t for t in _pre_tasks()
            if any(f.lower() in (t.get("name") or "").lower() for f in _PROVENANCE)]


def test_the_provenance_block_exists():
    tasks = _provenance_tasks()
    assert len(tasks) >= 4, (
        f"expected the provenance capture/write tasks in site.yml pre_tasks, "
        f"found {[t.get('name') for t in tasks]}")


@pytest.mark.parametrize("task", _provenance_tasks(),
                         ids=lambda t: (t.get("name") or "?")[:45])
def test_every_provenance_task_runs_on_tagged_deploys(task):
    """THE property. Untagged, these are skipped by `make deploy TAGS=...` — which is
    precisely the deploy that drifts."""
    tags = task.get("tags") or []
    tags = [tags] if isinstance(tags, str) else tags
    assert "always" in tags, (
        f"pre_task {task.get('name')!r} is not tagged `always`, so it is SKIPPED on "
        f"every tagged deploy. A marker that only appears on full deploys is missing "
        f"exactly when drift happens (#151).")


def test_the_marker_records_more_than_a_sha():
    """A SHA alone would have looked healthy during the 2026-08-03 failure.

    The host was on clean, current `main`; the change was simply somewhere else. What
    distinguishes that from a good deploy is the branch, and whether the tree was
    dirty.
    """
    writer = next((t for t in _pre_tasks()
                   if "provenance marker" in (t.get("name") or "").lower()), None)
    assert writer is not None, "no task writes the provenance marker"
    content = yaml.dump(writer)
    for field in ("sha", "branch", "dirty", "tags", "deployed_at"):
        assert field in content, (
            f"the marker omits {field!r}; a SHA alone cannot distinguish "
            f"'deployed from another branch' from a healthy deploy")


def test_a_dirty_tree_is_recorded_not_blocked():
    """Deploying a work-in-progress deliberately is legitimate; an unexplained hard
    failure would just teach people to bypass the check. It must be loud, not fatal."""
    src = SITE.read_text(encoding="utf-8")
    block = src.split("Deploy provenance (#151)", 1)[1].split("\n  roles:", 1)[0]
    assert "failed_when: true" not in block, (
        "the provenance block must not fail the deploy on a dirty tree — record it")
    assert "dirty" in block


# --- the make targets ------------------------------------------------------


def test_provenance_targets_exist_and_are_phony():
    mk = MAKEFILE.read_text(encoding="utf-8")
    assert re.search(r"^provenance:", mk, re.M), "no `provenance` target"
    assert re.search(r"^provenance-has:", mk, re.M), "no `provenance-has` target"
    phony = next(ln for ln in mk.splitlines() if ln.startswith(".PHONY"))
    for t in ("provenance", "provenance-has"):
        assert t in phony, f"{t} missing from .PHONY"


def test_provenance_recipes_are_posix_sh():
    """make runs recipes under /bin/sh — no SHELL is set in this Makefile.

    `${VAR:0:12}` is a bashism and expands to nothing under dash, which would print
    truncated-looking output that is actually empty. Caught while writing this.
    """
    mk = MAKEFILE.read_text(encoding="utf-8")
    body = mk.split("provenance:", 1)[1].split("\nsmoke-setup:", 1)[0]
    assert not re.search(r"\$\$\{[A-Za-z_]+:\d+:\d+\}", body), (
        "bash substring expansion in a /bin/sh recipe — use `cut -c1-12`")


def test_provenance_distinguishes_stale_from_diverged():
    """Two different failures needing two different responses.

    STALE (host runs an ancestor) means 'you forgot to deploy'. DIVERGED (host runs
    something not in your history) means 'the host was deployed from a different
    branch' — the 2026-08-03 case, and the one a simple != check would misreport as
    merely out of date.
    """
    body = MAKEFILE.read_text(encoding="utf-8").split("provenance:", 1)[1]
    body = body.split("\nsmoke-setup:", 1)[0]
    assert "merge-base --is-ancestor" in body, (
        "distinguishing stale from diverged needs an ancestry test, not string "
        "inequality")
    assert "STALE" in body and "DIVERGED" in body
