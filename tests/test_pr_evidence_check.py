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
    # The rule widened beyond documentation (tests/ qualifies on the same
    # grounds), so the message says what is actually being asserted.
    assert "no deployed files changed" in msg


def test_empty_file_list_is_not_docs_only():
    """A diff that could not be computed must not pass as 'nothing changed'."""
    assert not check.is_docs_only([])
    ok, _ = check.evaluate("", HEAD, [])
    assert not ok


@pytest.mark.parametrize("path", [
    ".github/workflows/ci.yml", "Makefile", "VERSION",
    "ansible/roles/pipeline/files/run-pipeline.py", "frontend/package.json",
])
def test_build_and_deploy_affecting_paths_are_not_docs(path):
    assert not check.is_docs_only([path])


@pytest.mark.parametrize("path", [
    "tests/test_x.py", "pipeline/tests/test_y.py", "api/tests/test_z.py",
])
def test_test_only_changes_need_no_host_evidence(path):
    """`tests/` is not deployed — the pipeline tarball is built with
    `--exclude=tests` — so the redeploy the gate would demand ships no changed
    byte and moves only the provenance marker.

    This assertion was inverted until 2026-09-26. The first real instance of the
    friction was #637's second commit: a tests-only change that required a full
    redeploy to alter nothing on the host. Pointless friction on every test-only
    PR is what trains people to route around a check.
    """
    assert check.is_docs_only([path])


@pytest.mark.parametrize("path", [
    "tests/smoke/test_nav_smoke.py", "tests/smoke/conftest.py",
    "tests/smoke/_redaction.py",
])
def test_the_smoke_gate_itself_is_never_exempt(path):
    """`make deploy` runs tests/smoke as the post-deploy gate, so it is not
    merely tested code — it IS the gate. A change that weakens it must go through
    the gate it implements.

    The specific pattern has to beat the general one, and this is the assertion
    that catches it if the ordering is ever lost."""
    assert not check.is_docs_only([path])


def test_a_smoke_change_is_not_laundered_by_other_test_files():
    """Every path must qualify, not just one. Bundling a smoke edit with ordinary
    test edits must not exempt the bundle."""
    assert not check.is_docs_only(["tests/test_x.py", "tests/smoke/conftest.py"])


def test_tests_plus_deployed_code_still_needs_evidence():
    """The common real shape: a fix plus its test. The fix is deployed, so the
    PR needs evidence — the test carve-out must not swallow it."""
    assert not check.is_docs_only(
        ["tests/test_x.py", "ansible/roles/pipeline/files/run-pipeline.py"])


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
