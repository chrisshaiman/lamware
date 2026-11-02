# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""#206: ansible/ must stay inside the lint and SAST gates, with no rule exempted.

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

def test_ruff_covers_ansible():
    assert re.search(r"ruff check .*\bansible/", CI), (
        "ansible/ dropped out of the ruff gate — 12k lines silently stop being linted")


def test_semgrep_covers_ansible():
    assert re.search(r"semgrep scan .*\bansible/", CI), (
        "ansible/ dropped out of the SAST gate — the analysis pipeline stops being scanned")


def test_precommit_covers_ansible():
    assert "ansible" in PRECOMMIT, (
        "pre-commit no longer matches ansible/, so findings only appear in CI")


def test_ansible_has_no_rule_exemption():
    """#206 deferred G004 for ansible/ until 2026-10-31; it was retired by fixing all 174.

    An ignore with no deadline is just a permanently lower standard, so a new one for
    ansible/ should arrive with its own dated guard, not slip in as a config line.
    """
    ignores = PYPROJECT["tool"]["ruff"]["lint"].get("per-file-ignores", {})
    exempt = {k: v for k, v in ignores.items() if k.startswith("ansible")}
    assert not exempt, f"ansible/ is exempted from ruff rules again: {exempt}"


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
