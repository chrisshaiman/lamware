# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Two controls that reported healthy while measuring nothing.

Both surfaced in the 2026-08-08 threat-model verification pass (GHSA-f5q8-v78c-mr55),
and both are the same failure: an instrument watching a proxy rather than the thing
it protects.

  network-monitor  hardcoded `iface="eth0"` while the host's management interface
                   is `enp3s0f0`, so the awk match never matched a real rule. The
                   internet-egress counter was permanently 0 and the alarm branch
                   was unreachable. It also only diffed ACCEPT deltas and never
                   asserted the DROP rules exist — flush the FORWARD chain (default
                   policy ACCEPT) and it still reports `ok` with nothing blocked.

  CI gitleaks      the pre-commit hook's entry is `gitleaks git --staged`, which
                   scans the git INDEX. On a fresh actions/checkout nothing is
                   staged, so it scanned an empty diff and exited 0 every time. It
                   works locally, where a commit has staged content, which is
                   exactly why the difference went unnoticed.
"""
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MONITOR = (ROOT / "ansible" / "roles" / "network-monitor" / "templates"
           / "network-monitor.sh.j2")
CI = ROOT / ".github" / "workflows" / "ci.yml"
# The real vars file is gitignored (it carries the server IP), so the shipped
# contract is the example. Checked local-first so a developer with a real file
# gets the stronger assertion, without CI failing on a file it cannot have.
ANSIBLE_VARS = ROOT / "ansible" / "vars" / "main.yml"
ANSIBLE_VARS_EXAMPLE = ROOT / "ansible" / "vars" / "main.yml.example"

MONITOR_SRC = MONITOR.read_text(encoding="utf-8")
CI_SRC = CI.read_text(encoding="utf-8")

# Comment-free view: the rationale below quotes the removed constructs verbatim,
# and an absence check must not be satisfiable by the prose explaining the absence.
MONITOR_CODE = "\n".join(
    ln for ln in MONITOR_SRC.splitlines() if not ln.lstrip().startswith("#"))


def test_the_comment_stripper_works():
    """Guards the guard — negative and positive control."""
    assert "reported healthy while measuring" not in MONITOR_CODE
    assert "rule_survey()" in MONITOR_CODE


# ---------------------------------------------------------------------------
# network-monitor
# ---------------------------------------------------------------------------

def test_the_interface_is_templated_not_hardcoded():
    """THE bug. `eth0` is not this host's management interface and never was."""
    assert 'iface="eth0"' not in MONITOR_CODE, (
        "the management interface is hardcoded again — it is a variable whose live "
        "value is enp3s0f0, so a literal eth0 matches no rule and the egress alarm "
        "becomes unreachable")
    assert "{{ management_interface }}" in MONITOR_SRC


def test_the_interface_variable_actually_exists():
    """A template referencing an undefined var fails the play, and one that
    somehow rendered empty would match EVERY rule rather than none — failing open
    in the opposite direction.

    Asserted against `main.yml.example`, which ships. The live `main.yml` is
    gitignored because it carries the server IP, so CI cannot read it; when it is
    present locally it is checked too.
    """
    src = ANSIBLE_VARS if ANSIBLE_VARS.exists() else ANSIBLE_VARS_EXAMPLE
    variables = yaml.safe_load(src.read_text(encoding="utf-8"))
    assert variables.get("management_interface"), (
        f"management_interface must be defined in {src.name}")
    assert yaml.safe_load(
        ANSIBLE_VARS_EXAMPLE.read_text(encoding="utf-8")).get("management_interface"), (
        "the example must define it too — it is the only copy a fresh clone gets, "
        "and the network monitor's air-gap check renders from it")


def test_the_drop_rules_are_asserted_to_exist():
    """Counter deltas cannot see a flushed chain: no rules means no matches means
    no delta means `ok`, with nothing blocked."""
    assert "rule_survey" in MONITOR_CODE
    assert "MISSING: no $cmd DROP rule" in MONITOR_SRC
    assert "rules_problem" in MONITOR_CODE


def test_the_rule_checks_are_actually_CALLED():
    """Defining `check_rules` and never calling it leaves the script exactly as
    blind as before, with more code to suggest otherwise.

    This test exists because the first version of this file asserted only that the
    machinery was PRESENT. A mutation that deleted the call site — leaving every
    function definition intact — passed the whole suite. Presence is not wiring,
    which is the same mistake as the control being fixed here.

    It is a cheap structural check. What the checks actually REPORT is asserted in
    test_air_gap_rule_checks.py, which runs them against fake firewall tables — a
    check can be called and still be wrong, and no amount of grepping sees that.
    """
    driver = re.search(r"^for _fam in (.+?); do$(.*?)^done$",
                       MONITOR_CODE, re.M | re.S)
    assert driver, "the rule checks are no longer driven by a family loop"
    families, body = driver.group(1).split(), driver.group(2)
    assert {"iptables", "ip6tables"} <= set(families), (
        f"the survey covers {families} — an unsurveyed family can be flushed "
        f"silently, which is how the v6 air-gap rules went unwatched (#343)")
    assert "check_rules" in body, "the bridge rule survey runs into nothing"
    assert "check_egress" in body, "the pipeline egress allowlist is unchecked"
    assert "{{ management_interface }}" in body, "the internet path is unchecked"
    assert "wg0" in body, "the management path is unchecked"
    assert re.search(r"^\s*rules_problem=.*_check", body, re.M), (
        "the loop computes checks but never accumulates them into rules_problem")


def test_rule_ordering_is_checked():
    """A DROP below an ACCEPT for the same pair never sees the traffic, so mere
    presence is not enough."""
    assert "ORDERING:" in MONITOR_SRC


def test_a_missing_rule_alarms_on_its_own():
    """It must not depend on a counter threshold — the counters are exactly what a
    flushed chain stops producing."""
    idx = MONITOR_CODE.index('if [ -n "$rules_problem" ]')
    block = MONITOR_CODE[idx:idx + 600]
    assert 'status="alert"' in block
    assert "PAUSE_FILE" in block, "a containment failure must halt the pipeline"


def test_the_rule_state_reaches_the_status_file():
    """The dashboard reads status.json. A check whose result never leaves the
    script is a check nobody sees."""
    assert "air_gap_rules" in MONITOR_SRC


# ---------------------------------------------------------------------------
# CI gitleaks
# ---------------------------------------------------------------------------

def _ci_run_steps() -> list[str]:
    wf = yaml.safe_load(CI_SRC)
    out = []
    for job in wf.get("jobs", {}).values():
        for step in job.get("steps", []) or []:
            if isinstance(step, dict) and step.get("run"):
                out.append(step["run"])
    return out


def test_ci_scans_the_tree_not_the_index():
    """THE bug: `--staged` on a fresh checkout scans nothing."""
    runs = " ".join(_ci_run_steps())
    assert re.search(r"gitleaks\s+dir\s", runs), (
        "CI must invoke `gitleaks dir` against the working tree; the pre-commit "
        "hook's `gitleaks git --staged` scans an empty index on a fresh checkout")


def test_ci_does_not_rely_on_the_precommit_hook_for_secret_scanning():
    """`pre-commit run --all-files` may stay — it runs ruff and the rest. What must
    not happen is treating it as the secret scan."""
    runs = _ci_run_steps()
    assert any("pre-commit run" in r for r in runs), "pre-commit still runs"
    assert any("gitleaks dir" in r for r in runs), (
        "and secret scanning has its own step that actually reads files")


def test_the_download_is_checksum_verified():
    """A security control fetched over the network without verification is a
    supply-chain hole in the thing meant to close one."""
    runs = " ".join(_ci_run_steps())
    assert "sha256sum -c" in runs, "verify the archive against the release manifest"


def test_the_pinned_version_matches_pre_commit():
    """Local and CI must apply the same ruleset, or a secret caught on a laptop
    sails through CI and vice versa."""
    pc = yaml.safe_load((ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8"))
    rev = next(r["rev"] for r in pc["repos"] if "gitleaks" in r["repo"])
    runs = " ".join(_ci_run_steps())
    assert f"VERSION={rev.lstrip('v')}" in runs, (
        f"CI pins a different gitleaks than pre-commit ({rev}); they must agree")
