# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Catch `yaml[line-length]` locally instead of in CI.

`ansible-lint ansible/site.yml` is the one CI check that cannot run on a
developer machine — it needs the vault password. So every formatting violation
costs a full push/wait/read-the-log round trip, and this rule in particular has
now caused three of them.

Reproducing ansible-lint is not the goal and would be a bad idea: it would drift
from the real linter and give false confidence. This reproduces exactly ONE rule,
the cheapest and most frequently tripped, and says so. CI remains authoritative.

The 160 default comes from ansible-lint's yamllint defaults; `.ansible-lint`
carries no `line-length` override, and this test asserts that — if someone
configures a different limit, this file must be updated rather than silently
checking the wrong number.
"""
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
ANSIBLE = ROOT / "ansible"
LIMIT = 160


def test_the_limit_matches_the_linter_config():
    """Guards the guard: a `line-length` override in .ansible-lint would make
    every assertion below check a number the real linter does not use."""
    cfg_path = ROOT / ".ansible-lint"
    assert cfg_path.exists(), "no .ansible-lint — the assumed default may not hold"
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    rules = (cfg.get("rules") or {}).get("line-length")
    yamllint = cfg.get("yamllint_file") or cfg.get("yaml")
    assert not rules and not yamllint, (
        f"{cfg_path.name} now configures line-length ({rules or yamllint}); "
        f"update LIMIT in this file to match")


def _yaml_files() -> list[Path]:
    return sorted(p for p in ANSIBLE.rglob("*.yml")
                  if ".venv" not in p.parts and "collections" not in p.parts)


def test_yaml_files_were_found():
    """An empty file list makes the check below vacuous."""
    files = _yaml_files()
    assert len(files) > 50, f"only found {len(files)} ansible YAML files"


def test_no_ansible_yaml_line_exceeds_the_lint_limit():
    """THE rule. A long URL or a `when:` that grew past the limit fails the
    deploy pipeline at the linting stage, not on the host — cheap to fix, and
    cheaper still to find here."""
    offenders = []
    for path in _yaml_files():
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if len(line) > LIMIT:
                rel = path.relative_to(ROOT)
                offenders.append(f"{rel}:{n} ({len(line)} > {LIMIT})")
    assert not offenders, (
        "ansible-lint yaml[line-length] will fail on:\n  " + "\n  ".join(offenders)
        + "\n\nNote a folded scalar (`>-`) does NOT fix a long URL: it joins its "
          "lines with spaces. Split the value into a variable instead.")
