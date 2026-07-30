# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""#206: ansible/ must stay inside the lint and SAST gates, and the G004 deferral must expire.

Before #206, `ruff check` and `semgrep scan` both ran against `api/ shared/ pipeline/`
only, and pre-commit was scoped `^(api|shared|pipeline)/`. That left 12,162 lines of
Python under ansible/ — the entire analysis pipeline, the interpret container script, the
Cape/Volatility/Ghidra stages — unlinted and unscanned.

The #205 refactor made the biggest of those files importable and testable, and its payoff
was still uncollected: the destination directory was the excluded one, so 2,980 lines moved
from "untestable and unlinted" to "testable and still unlinted".

These tests exist because a scope regression is invisible. Nothing fails, nothing warns —
findings simply stop being reported, exactly as they silently were for a year.
"""
import datetime as dt
import importlib.util
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
PRECOMMIT = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))

# The date the G004 deferral stops being acceptable. Kept here AND in the pyproject
# comment; the test below fails if they disagree, so neither can drift unnoticed.
G004_EXPIRY = dt.date(2026, 10, 31)


def test_ruff_covers_ansible():
    assert re.search(r"ruff check .*\bansible/", CI), (
        "ansible/ dropped out of the ruff gate — 12k lines silently stop being linted")


def test_semgrep_covers_ansible():
    assert re.search(r"semgrep scan .*\bansible/", CI), (
        "ansible/ dropped out of the SAST gate — the analysis pipeline stops being scanned")


def test_precommit_covers_ansible():
    assert "ansible" in PRECOMMIT, (
        "pre-commit no longer matches ansible/, so findings only appear in CI")


def test_the_g004_deferral_has_not_silently_become_permanent():
    """An ignore with no deadline is just a permanently lower standard.

    Mirrors frontend/audit-exceptions.json, which fails the build when its reviewBy
    passes rather than trusting anyone to remember.
    """
    ignores = PYPROJECT["tool"]["ruff"]["lint"]["per-file-ignores"]
    if "ansible/**" not in ignores:
        return  # already retired — nothing to police
    assert ignores["ansible/**"] == ["G004"], (
        "the ansible/ deferral must stay limited to G004; widening it turns a dated "
        "exception into a general exemption")
    assert dt.date.today() <= G004_EXPIRY, (
        f"the G004 deferral for ansible/ expired on {G004_EXPIRY}. Fix the remaining "
        f"logging f-strings, then delete both the per-file-ignore in pyproject.toml and "
        f"this test. Do NOT extend the date without deciding the work is not worth doing.")


def test_the_expiry_date_is_documented_where_the_ignore_lives():
    """A deadline only a test knows about is a deadline nobody sees while editing config."""
    raw = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert G004_EXPIRY.isoformat() in raw, (
        "pyproject.toml must state the same expiry date this test enforces")


@pytest.mark.skipif(not (ROOT / "ansible").is_dir(), reason="ansible/ not present")
def test_ansible_is_actually_clean_under_the_gate():
    """Local early warning: a finding under ansible/ fails here, not at push time.

    SKIPPED where ruff is absent, which is the `packages` CI job -- it installs
    `./shared ./pipeline[test] pytest hypothesis` and nothing else. Skipping is honest
    here ONLY because this test is not the gate: `ruff check ... ansible/` runs in the
    "Python lint & test" job and is authoritative. Duplicating it here would mean adding
    a lint dependency to a test job to re-run a check CI already performs.

    If that lint job ever stops covering ansible/, test_ruff_covers_ansible above fails —
    which is the guard that actually matters.
    """
    ruff = importlib.util.find_spec("ruff")
    if ruff is None:
        pytest.skip("ruff not installed in this job; the lint job is the real gate")
    r = subprocess.run([sys.executable, "-m", "ruff", "check", "ansible/"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, f"ruff findings under ansible/:\n{r.stdout[-2000:]}"
