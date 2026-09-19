# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Run the network monitor's rule checks against fake firewall tables.

`test_dead_controls.py` asserts these checks EXIST and are WIRED, by reading the
template as text. That caught a mutation which deleted the call site, but it
cannot catch a check that is called and wrong — an awk field index off by one, a
comparison inverted, a family never surveyed. Every one of those leaves the
source looking exactly right.

So this file executes the checks. The rendered functions run against fake
`iptables`/`ip6tables` binaries on PATH, and each scenario asserts what the
checks SAY, not what they contain:

  healthy    -> no problem reported
  flushed    -> MISSING, in both families independently
  reordered  -> ORDERING, for the pair that is actually inverted

The IPv6 cases are the reason this exists. Until #343 the survey ran `iptables`
only; the v6 air-gap rules were real, deployed, and unwatched, and the v6
pipeline allowlist did not exist at all.
"""
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
MONITOR = (ROOT / "ansible" / "roles" / "network-monitor" / "templates"
           / "network-monitor.sh.j2")

BRIDGE = "virbr-det"
MGMT = "enp3s0f0"

TEMPLATE_VARS = {
    "management_interface": MGMT,
    "network_monitor_detonation_bridge": BRIDGE,
    "network_monitor_install_dir": "/opt/network-monitor",
    "network_monitor_pause_file": "/opt/network-monitor/paused",
}


def _render() -> str:
    return jinja2.Template(MONITOR.read_text(encoding="utf-8")).render(**TEMPLATE_VARS)


def _rule_check_section(rendered: str) -> str:
    """The survey/check functions plus the loop that drives them.

    Sliced rather than re-implemented: a copy of the logic in the test would pass
    while the shipped script was broken, which is the failure this whole file is
    about.
    """
    start = rendered.index("rule_survey()")
    end = rendered.index("# Current counters")
    section = rendered[start:end]
    assert "check_egress" in section, "the slice missed the pipeline egress check"
    assert "for _fam in" in section, "the slice missed the driver loop"
    assert "alert_subject()" in section, "the slice missed the alert classifier"
    return section


# `iptables -L <chain> -v -n -x --line-numbers` columns:
#   num pkts bytes target prot opt in out source destination
def _rule(num, target, in_if, out_if, comment=""):
    tail = f'/* {comment} */' if comment else ""
    return (f"{num} 0 0 {target} all -- {in_if} {out_if} "
            f"0.0.0.0/0 0.0.0.0/0 {tail}")


def _forward_table(*, drop=True, accept_first=False):
    rows = []
    n = 1
    if accept_first:
        rows.append(_rule(n, "ACCEPT", BRIDGE, MGMT)); n += 1
        rows.append(_rule(n, "ACCEPT", BRIDGE, "wg0")); n += 1
    if drop:
        rows.append(_rule(n, "DROP", BRIDGE, MGMT)); n += 1
        rows.append(_rule(n, "DROP", BRIDGE, "wg0")); n += 1
    header = ("Chain FORWARD (policy ACCEPT 0 packets, 0 bytes)\n"
              "num pkts bytes target prot opt in out source destination")
    return "\n".join([header, *rows])


def _output_table(*, drop=True, drop_first=False, preempt=False, chain="OUTPUT"):
    """The pipeline allowlist as it appears in ufw's before-output chain.

    It used to be surveyed in OUTPUT, where it was unreachable: ufw accepts all
    loopback and its own outgoing port list before OUTPUT's later rules run.
    `preempt=True` reproduces that — a terminating ACCEPT above the DROP, which
    is what defeated the real rules while every check stayed green.
    """
    rows = []
    n = 1
    if preempt:
        rows.append(_rule(n, "ACCEPT", "*", "lo")); n += 1
    allows = [("ACCEPT", "pipeline: PostgreSQL"), ("ACCEPT", "pipeline: CAPE API")]
    if drop_first and drop:
        rows.append(_rule(n, "DROP", "*", "*", "pipeline: block all other outbound")); n += 1
    for target, comment in allows:
        rows.append(_rule(n, target, "*", "lo", comment)); n += 1
    if drop and not drop_first:
        rows.append(_rule(n, "DROP", "*", "*", "pipeline: block all other outbound")); n += 1
    header = (f"Chain {chain} (policy ACCEPT 0 packets, 0 bytes)\n"
              "num pkts bytes target prot opt in out source destination")
    return "\n".join([header, *rows])


def _fake_binary(path: Path, forward: str, output: str) -> None:
    path.write_text(textwrap.dedent(f"""\
        #!/bin/bash
        # Fake firewall. Emits a canned table for `-L <chain> ...`.
        for a in "$@"; do
          case "$a" in
            FORWARD) cat <<'EOF'
{forward}
EOF
              exit 0 ;;
            OUTPUT) cat <<'EOF'
{output}
EOF
              exit 0 ;;
          esac
        done
        exit 0
        """), encoding="utf-8")
    path.chmod(0o755)


def _run(tmp_path, *, v4_forward, v4_output, v6_forward, v6_output) -> str:
    """Execute the rendered checks and return what they reported."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    _fake_binary(bindir / "iptables", v4_forward, v4_output)
    _fake_binary(bindir / "ip6tables", v6_forward, v6_output)

    script = tmp_path / "check.sh"
    script.write_text(
        f'BRIDGE="{BRIDGE}"\n'
        + _rule_check_section(_render())
        + '\nprintf "%s|%s" "$(alert_subject)" "$rules_problem"\n',
        encoding="utf-8")

    proc = subprocess.run(
        ["bash", str(script)],
        env={"PATH": f"{bindir}:{shutil.os.environ['PATH']}"},
        capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0, f"the check script itself failed: {proc.stderr}"
    return proc.stdout


def _subject(out: str) -> str:
    """The alert headline the operator actually sees."""
    return out.split("|", 1)[0]


def _problems(out: str) -> str:
    return out.split("|", 1)[1] if "|" in out else out


HEALTHY = dict(v4_forward=_forward_table(), v4_output=_output_table(),
               v6_forward=_forward_table(), v6_output=_output_table())


def test_a_healthy_rule_set_reports_no_problem(tmp_path):
    """The positive control. Without it, a check that reports a problem
    unconditionally would satisfy every other test in this file."""
    out = _run(tmp_path, **HEALTHY)
    assert _problems(out) == "", out
    assert _subject(out) == "", "a healthy host must not produce an alert headline"


def test_the_fake_binaries_are_actually_consulted(tmp_path):
    """Guards the guard: if the fakes were not on PATH, the real iptables (absent
    in CI, or present and unrelated) would decide these results."""
    out = _run(tmp_path, **{**HEALTHY, "v4_forward": _forward_table(drop=False)})
    assert out != "", "changing the fake table changed nothing — PATH is not wired"


@pytest.mark.parametrize("family", ["v4", "v6"])
def test_a_flushed_forward_chain_is_reported_per_family(tmp_path, family):
    """THE original bug (#336), now per family. A flushed chain has no rules, so
    no counter moves and the delta-based check reads `ok` forever."""
    out = _problems(_run(tmp_path, **{**HEALTHY, f"{family}_forward": _forward_table(drop=False)}))
    cmd = "iptables" if family == "v4" else "ip6tables"
    assert f"MISSING: no {cmd} DROP rule" in out, out
    other = "ip6tables" if family == "v4" else "iptables"
    assert f"MISSING: no {other} DROP rule" not in out, (
        f"a flushed {cmd} chain was blamed on {other} too — the families are not "
        f"surveyed independently")


@pytest.mark.parametrize("family", ["v4", "v6"])
def test_an_accept_above_the_drop_is_reported_per_family(tmp_path, family):
    """A DROP below an ACCEPT for the same pair never sees the traffic. Both rules
    are present, so every presence check passes."""
    out = _run(tmp_path,
               **{**HEALTHY, f"{family}_forward": _forward_table(accept_first=True)})
    cmd = "iptables" if family == "v4" else "ip6tables"
    assert f"ORDERING: {cmd} ACCEPT" in out, out


@pytest.mark.parametrize("family", ["v4", "v6"])
def test_a_missing_pipeline_drop_all_is_reported(tmp_path, family):
    """#343: the v6 allowlist did not exist at all, against an OUTPUT policy of
    ACCEPT, and nothing said so."""
    out = _problems(_run(tmp_path, **{**HEALTHY, f"{family}_output": _output_table(drop=False)}))
    cmd = "iptables" if family == "v4" else "ip6tables"
    assert f"MISSING: no {cmd} DROP-all for the pipeline user" in out, out


@pytest.mark.parametrize("family", ["v4", "v6"])
def test_a_pipeline_allow_below_the_drop_all_is_reported(tmp_path, family):
    """The specific hazard the Ansible tasks carry: `ansible.builtin.iptables`
    APPENDS, so an allow added in a later change lands below the DROP-all. It is
    present, it matches `iptables -C`, and it permits nothing."""
    out = _problems(_run(tmp_path, **{**HEALTHY, f"{family}_output": _output_table(drop_first=True)}))
    cmd = "iptables" if family == "v4" else "ip6tables"
    assert f"ORDERING: {cmd} pipeline ACCEPT" in out, out


@pytest.mark.parametrize("family", ["v4", "v6"])
def test_a_foreign_accept_above_the_drop_all_is_reported(tmp_path, family):
    """The failure that actually happened, and that nothing detected.

    On 2026-09-19 the allowlist was present, correctly ordered among itself, and
    completely ineffective: ufw's chains accepted all loopback and its own
    outgoing port list before OUTPUT's later rules were reached. The DROP-all
    sat at 0 packets while the pipeline user opened TCP to 1.1.1.1:443.

    The old survey read only rules commented `pipeline:`, so a terminating
    ACCEPT above them was invisible. Every check reported healthy throughout.
    """
    out = _run(tmp_path, **{**HEALTHY,
                            f"{family}_output": _output_table(preempt=True)})
    cmd = "iptables" if family == "v4" else "ip6tables"
    assert f"PREEMPTED: {cmd}" in out, out


def test_our_own_allows_above_the_drop_are_not_reported_as_preemption(tmp_path):
    """The allows are SUPPOSED to sit above the DROP. A preemption check that
    flags them fires on every healthy host, and a check that always fires is one
    the operator learns to ignore -- which is how the real thing gets missed.

    This is not hypothetical: the first version of the check did exactly that,
    and test_a_healthy_rule_set_reports_no_problem caught it.
    """
    out = _run(tmp_path, **HEALTHY)
    assert "PREEMPTED" not in _problems(out), out


def test_every_reported_problem_survives_into_one_string(tmp_path):
    """Several simultaneous failures must all be reported. An accumulator that
    overwrites instead of appending would pass every single-fault test above and
    hide everything but the last problem in a real incident."""
    out = _run(tmp_path,
               v4_forward=_forward_table(drop=False), v4_output=_output_table(drop=False),
               v6_forward=_forward_table(drop=False), v6_output=_output_table(drop=False))
    assert out.count("MISSING") == 6, (
        f"expected 6 problems (2 bridge paths + 1 egress, per family), got: {out}")


# --- the alert must name the control that actually failed --------------------
#
# On 2026-09-19 a pipeline-egress survey reading the wrong chain fired
# "AIR-GAP RULES NOT ENFORCED" at urgent/skull priority while the air-gap was
# perfectly intact — DROPs at FORWARD 4-5, above every ufw chain, in both
# families. An operator who sees that headline cry wolf learns to discount it,
# and the air-gap is the one alert that must never be discounted.

def test_a_real_air_gap_breach_still_fires(tmp_path):
    """THE test. Everything else here is in service of this one still working."""
    out = _run(tmp_path, **{**HEALTHY, "v4_forward": _forward_table(drop=False)})
    assert _subject(out) == "AIR-GAP RULES NOT ENFORCED", out
    assert "MISSING" in _problems(out), out


def test_a_real_air_gap_breach_fires_in_ipv6_too(tmp_path):
    out = _run(tmp_path, **{**HEALTHY, "v6_forward": _forward_table(drop=False)})
    assert _subject(out) == "AIR-GAP RULES NOT ENFORCED", out


def test_an_accept_above_the_air_gap_drop_still_fires(tmp_path):
    """A DROP that exists but sits below an ACCEPT for the same pair."""
    out = _run(tmp_path, **{**HEALTHY,
                            "v4_forward": _forward_table(accept_first=True)})
    assert _subject(out) == "AIR-GAP RULES NOT ENFORCED", out
    assert "ORDERING" in _problems(out), out


def test_an_egress_only_problem_does_not_claim_the_air_gap_is_open(tmp_path):
    """The 2026-09-19 false positive, reproduced.

    The egress DROP is absent; the air-gap is untouched. The alert must say so.
    """
    out = _run(tmp_path, **{**HEALTHY, "v4_output": _output_table(drop=False)})
    assert _subject(out) == "PIPELINE EGRESS NOT ENFORCED", out
    assert "AIR-GAP" not in _subject(out), out
    # Still an alert -- an unrestricted pipeline user is a real finding.
    assert _problems(out) != "", out


def test_both_failing_names_both(tmp_path):
    """Collapsing to one category would hide the air-gap behind an egress
    problem, which is the same mistake in the other direction."""
    out = _run(tmp_path, **{**HEALTHY,
                            "v4_forward": _forward_table(drop=False),
                            "v4_output": _output_table(drop=False)})
    assert _subject(out) == "AIR-GAP AND PIPELINE EGRESS NOT ENFORCED", out


def test_a_preempted_egress_is_reported_as_egress_not_air_gap(tmp_path):
    """The real-world defeat — a foreign ACCEPT above the DROP — is an egress
    finding, however alarming."""
    out = _run(tmp_path, **{**HEALTHY, "v4_output": _output_table(preempt=True)})
    assert _subject(out) == "PIPELINE EGRESS NOT ENFORCED", out
    assert "PREEMPTED" in _problems(out), out
