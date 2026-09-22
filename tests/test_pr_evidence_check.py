# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The pre-merge deploy gate must refuse what it is meant to refuse.

These exercise the decision function directly rather than the workflow YAML:
the property that matters is what the check *decides* for a given body, head
and file list, and that is observable without GitHub.
"""
import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "pr_evidence_check.py"

_spec = importlib.util.spec_from_file_location("pr_evidence_check", SCRIPT)
check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(check)

HEAD = "33e3591c704a9e60c560b1cc01aea842b1c5a999"
CODE_FILES = ["ansible/roles/pipeline/tasks/main.yml", "tests/test_x.py"]


def test_docs_only_change_needs_no_evidence():
    ok, msg = check.evaluate("", HEAD, ["docs/DECISIONS.md", "README.md", "AUTHORS"])
    assert ok
    assert "docs-only" in msg


def test_empty_file_list_is_not_docs_only():
    """A diff that could not be computed must not pass as 'nothing changed'."""
    assert not check.is_docs_only([])
    ok, _ = check.evaluate("", HEAD, [])
    assert not ok


@pytest.mark.parametrize("path", [
    ".github/workflows/ci.yml", "Makefile", "VERSION", "tests/test_x.py",
    "ansible/roles/pipeline/files/run-pipeline.py", "frontend/package.json",
])
def test_build_and_deploy_affecting_paths_are_not_docs(path):
    assert not check.is_docs_only([path])


def test_one_code_file_among_docs_requires_evidence():
    ok, _ = check.evaluate("", HEAD, ["README.md", "Makefile"])
    assert not ok


def test_missing_line_fails_with_instructions():
    ok, msg = check.evaluate("## Summary\nfixed it\n", HEAD, CODE_FILES)
    assert not ok
    assert "make merge-check" in msg


def test_template_placeholder_fails():
    body = "Provenance commit: <paste the full 40-character SHA printed by `make merge-check`>"
    ok, msg = check.evaluate(body, HEAD, CODE_FILES)
    assert not ok
    assert "placeholder" in msg


def test_full_sha_matching_head_passes():
    ok, _ = check.evaluate(f"Host evidence\nProvenance commit: {HEAD}\n", HEAD, CODE_FILES)
    assert ok


def test_short_prefix_and_backticks_and_case_are_accepted():
    ok, _ = check.evaluate(f"provenance commit: `{HEAD[:12].upper()}`", HEAD, CODE_FILES)
    assert ok


def test_prefix_shorter_than_twelve_is_not_evidence():
    ok, _ = check.evaluate(f"Provenance commit: {HEAD[:7]}", HEAD, CODE_FILES)
    assert not ok


def test_stale_sha_after_a_push_fails():
    """The head moved after the deploy — the host is not running what would merge."""
    stale = "f4cb4908133548c8627d9261e08fc7e231eeddc7"
    ok, msg = check.evaluate(f"Provenance commit: {stale}", HEAD, CODE_FILES)
    assert not ok
    assert stale[:12] in msg and HEAD[:12] in msg


def test_none_body_is_handled():
    ok, _ = check.evaluate(None, HEAD, CODE_FILES)
    assert not ok


def test_cli_reads_body_from_environment_not_argv(tmp_path):
    """End to end through the entrypoint, the way the workflow calls it."""
    files = tmp_path / "changed.txt"
    files.write_text("\n".join(CODE_FILES) + "\n", encoding="utf-8")
    env = {"PATH": "/usr/bin:/bin", "PR_BODY": f"Provenance commit: {HEAD}"}
    ok = subprocess.run([sys.executable, str(SCRIPT), "--head-sha", HEAD,
                         "--changed-files", str(files)],
                        env=env, capture_output=True, text=True)
    assert ok.returncode == 0, ok.stdout + ok.stderr
    env["PR_BODY"] = "no evidence here"
    bad = subprocess.run([sys.executable, str(SCRIPT), "--head-sha", HEAD,
                          "--changed-files", str(files)],
                         env=env, capture_output=True, text=True)
    assert bad.returncode == 1
    assert "FAIL" in bad.stdout
