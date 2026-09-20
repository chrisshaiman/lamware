# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The air-gap check, run against REAL captured iptables output.

The first version used `iptables -L FORWARD -n --line-numbers` and matched the
outbound interface with a substring. Without `-v`, iptables omits the in/out
columns entirely, so nothing ever matched and `make security-test` reported:

    FAIL: AIR GAP: iptables has no rule for virbr-det -> internet (enp3s0f0);
    ... malware on the detonation network could reach the internet

The rules were present and correct. A false FAILURE on the most serious alarm
this project has is its own kind of dangerous -- it teaches the operator that
the air-gap alarm is noise.

It shipped because it was verified the wrong way: bash syntax checked, test
assertions written against the check's own source, never once run against what
iptables actually prints. `network-monitor`'s working `check_rules` had used
`-v -n -x --line-numbers` all along, one file away.

The fixtures here are the real thing, captured from the host on 2026-09-19.
They are what makes this a test of the PARSER rather than of my idea of the
format.
"""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SMOKE = (ROOT / "ansible" / "roles" / "security-test" / "templates"
         / "security-smoke-test.sh.j2").read_text()


def _awk_program() -> str:
    """The exact awk the shipped check runs — extracted, not retyped.

    A copy here would pass while the shipped script was broken, which is the
    failure this file exists to prevent.
    """
    m = re.search(r"awk -v o=\"\$oif\" '([^']+)'", SMOKE)
    assert m, "the air-gap check no longer uses the expected awk shape"
    return m.group(1)


def _run(fixture: str, oif: str) -> str:
    out = subprocess.run(
        ["awk", "-v", f"o={oif}", _awk_program(), str(FIXTURES / fixture)],
        capture_output=True, text=True, check=False)
    return out.stdout.strip()


@pytest.mark.parametrize("fixture,oif,expect_target", [
    ("iptables_forward_real.txt", "enp3s0f0", "DROP"),
    ("iptables_forward_real.txt", "wg0", "DROP"),
    ("ip6tables_forward_real.txt", "enp3s0f0", "DROP"),
    ("ip6tables_forward_real.txt", "wg0", "DROP"),
])
def test_the_airgap_rules_are_found_in_real_output(fixture, oif, expect_target):
    """All four must match. The shipped check matched none of them."""
    got = _run(fixture, oif)
    assert got, (
        f"{fixture}: no match for virbr-det -> {oif}. The rules ARE in this "
        f"fixture; the parser is wrong.")
    num, target = got.split()
    assert target == expect_target, f"first match is {target}, not {expect_target}"
    assert int(num) > 0


def test_the_check_reads_the_verbose_form():
    """Without -v there are no in/out columns to match on, and the check
    silently finds nothing."""
    start = SMOKE.index("CONTAINMENT: detonation network cannot leave the box")
    body = SMOKE[start:start + 2500]
    assert "-L FORWARD -v -n -x --line-numbers" in body, (
        "the air-gap check omits -v; iptables will not print the interfaces "
        "it matches on and every rule will read as missing")


def test_interfaces_are_matched_positionally_not_by_substring():
    """A rule comment mentioning an interface name must not satisfy the check.
    The original matched `$0 ~ o`, which any comment could have satisfied had
    the columns been present."""
    prog = _awk_program()
    assert '$7 == "virbr-det"' in prog, "the in-interface is not matched on its column"
    assert "$8 == o" in prog, "the out-interface is not matched on its column"
    assert "$0 ~" not in prog, "still matching the whole line by substring"


def test_a_missing_rule_really_does_produce_no_match(tmp_path):
    """The inverse. Without this, a parser that matched everything would pass
    every test above."""
    stripped = tmp_path / "no_airgap.txt"
    src = (FIXTURES / "iptables_forward_real.txt").read_text().splitlines()
    stripped.write_text("\n".join(
        ln for ln in src if "virbr-det" not in ln) + "\n")
    out = subprocess.run(["awk", "-v", "o=enp3s0f0", _awk_program(), str(stripped)],
                         capture_output=True, text=True, check=False)
    assert out.stdout.strip() == "", "matched a rule that is not there"


def test_an_accept_first_is_reported_as_the_first_match(tmp_path):
    """The property that matters: a DROP below an ACCEPT for the same pair
    never sees the traffic, so the check must surface whatever comes first."""
    src = (FIXTURES / "iptables_forward_real.txt").read_text().splitlines()
    hdr, rest = src[:2], src[2:]
    accept = ("1           0        0 ACCEPT     0    --  virbr-det enp3s0f0  "
              "0.0.0.0/0            0.0.0.0/0")
    f = tmp_path / "accept_first.txt"
    f.write_text("\n".join(hdr + [accept] + rest) + "\n")
    out = subprocess.run(["awk", "-v", "o=enp3s0f0", _awk_program(), str(f)],
                         capture_output=True, text=True, check=False)
    lines = [ln for ln in out.stdout.splitlines() if ln.strip()]

    # EXACTLY one line. The shell does `num="${line%% *}"; tgt="${line##* }"`,
    # so with two matches it takes num from the first and tgt from the LAST --
    # an ACCEPT at rule 1 followed by a DROP at rule 5 would report "rule 1,
    # DROP" and pass a check that should fail. A mutation removing `exit`
    # survived until this assertion existed.
    assert len(lines) == 1, (
        f"awk emitted {len(lines)} lines; the shell would mix the rule number "
        f"of the first with the target of the last: {lines}")
    assert lines[0].split()[1] == "ACCEPT", (
        "the check did not report the FIRST matching rule, so a DROP ordered "
        "below an ACCEPT would read as enforced")
