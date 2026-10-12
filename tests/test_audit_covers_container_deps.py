# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The dependency audit must point at the tree we actually ship.

Before #211 it did not. `pip-audit` read a root requirements.txt that named only
files from the decommissioned src/ Lambda handlers, and pinned `anthropic==0.102.0`
while the interpret container ships `0.52.0` — so the audit reported on a version
deployed nowhere while the deployed one went unchecked. The control was green and
aimed at the wrong target, which is worse than an absent control because it buys
false confidence.

These guards make the aim explicit, so the coverage cannot quietly narrow again.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
PRECOMMIT = (ROOT / ".pre-commit-config.yaml").read_text()

# Live Python trees. Anything scanning "our code" should cover all of these.
LIVE_TREES = ("api/", "shared/", "pipeline/")


def test_no_root_requirements_txt_returns():
    """It only ever described deleted code; a new one would re-point the audit at it."""
    assert not (ROOT / "requirements.txt").exists(), (
        "a root requirements.txt is back. Runtime deps belong in each package's "
        "pyproject.toml and each container's own requirements; a root file here "
        "becomes the thing pip-audit reads INSTEAD of the real trees.")


def test_audit_installs_the_real_packages_before_auditing():
    assert "pip install ./shared ./pipeline" in CI
    assert "api/pyproject.toml" in CI, (
        "the api dependency list must be read from its manifest, not hand-typed a "
        "second time — a copy drifts and the audit silently covers the stale one.")


def test_audit_covers_every_shipped_image_lock():
    """Each hermetic image installs exactly its hash lock (ADR-023), so the locks
    are the deployed versions. The audit must read all of them, by glob, so a
    newly migrated role is covered without editing CI."""
    assert 'for lock in ansible/roles/*/files/requirements.lock' in CI
    assert 'pip-audit --require-hashes --disable-pip -r "$lock"' in CI


def test_the_interpret_lock_carries_the_deployed_anthropic_pin():
    """The pin #211 was about: the version the container actually ships."""
    text = (ROOT / "ansible" / "roles" / "interpret" / "files" / "requirements.lock").read_text()
    assert re.search(r"^anthropic==0\.52\.0 ", text, re.M)


def test_scanners_cover_every_live_tree():
    """ruff and semgrep must not silently drop a tree the way `^src/` did."""
    for tool, line in (("ruff", "ruff check "), ("semgrep", "semgrep scan --config p/python ")):
        idx = CI.find(line)
        assert idx != -1, f"{tool} invocation not found in CI"
        invocation = CI[idx:CI.index("\n", idx)]
        missing = [t for t in LIVE_TREES if t not in invocation]
        assert not missing, f"{tool} does not cover {missing}: {invocation!r}"


def test_scanners_do_not_reference_deleted_trees():
    for dead in ("src/", "aws/"):
        assert f"ruff check {dead}" not in CI
        assert f"p/python {dead}" not in CI


def test_precommit_ruff_hook_matches_real_files():
    """A `files:` pattern matching nothing passes forever without scanning anything."""
    match = re.search(r"- id: ruff\b.*?files:\s*(\S+)", PRECOMMIT, re.DOTALL)
    assert match, "the pre-commit ruff hook lost its files: pattern"
    pattern = re.compile(match.group(1))
    tracked = [str(p.relative_to(ROOT)).replace("\\", "/")
               for tree in LIVE_TREES
               for p in (ROOT / tree.rstrip("/")).rglob("*.py")]
    assert tracked, "no live Python files found — the test itself is looking in the wrong place"
    assert any(pattern.match(p) for p in tracked), (
        f"the pre-commit ruff pattern {match.group(1)!r} matches none of the live "
        f"Python files, so the hook scans nothing and always passes.")


def test_terraform_matrix_has_no_deleted_root_modules():
    for dead in ("aws/bootstrap", "aws/envs/prod"):
        assert dead not in CI, f"CI still validates {dead}, which no longer exists"
    assert "- ovh" in CI, "the OVH root module must still be validated"
