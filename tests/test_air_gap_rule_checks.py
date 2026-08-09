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


def _output_table(*, drop=True, drop_first=False):
    rows = []
    n = 1
    allows = [("ACCEPT", "pipeline: PostgreSQL"), ("ACCEPT", "pipeline: CAPE API")]
    if drop_first and drop:
        rows.append(_rule(n, "DROP", "*", "*", "pipeline: block all other outbound")); n += 1
    for target, comment in allows:
        rows.append(_rule(n, target, "*", "lo", comment)); n += 1
    if drop and not drop_first:
        rows.append(_rule(n, "DROP", "*", "*", "pipeline: block all other outbound")); n += 1
    header = ("Chain OUTPUT (policy ACCEPT 0 packets, 0 bytes)\n"
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
        + '\nprintf "%s" "$rules_problem"\n',
        encoding="utf-8")

    proc = subprocess.run(
        ["bash", str(script)],
        env={"PATH": f"{bindir}:{shutil.os.environ['PATH']}"},
        capture_output=True, text=True, timeout=60, check=False)
    assert proc.returncode == 0, f"the check script itself failed: {proc.stderr}"
    return proc.stdout


HEALTHY = dict(v4_forward=_forward_table(), v4_output=_output_table(),
               v6_forward=_forward_table(), v6_output=_output_table())


def test_a_healthy_rule_set_reports_no_problem(tmp_path):
    """The positive control. Without it, a check that reports a problem
    unconditionally would satisfy every other test in this file."""
    assert _run(tmp_path, **HEALTHY) == ""


def test_the_fake_binaries_are_actually_consulted(tmp_path):
    """Guards the guard: if the fakes were not on PATH, the real iptables (absent
    in CI, or present and unrelated) would decide these results."""
    out = _run(tmp_path, **{**HEALTHY, "v4_forward": _forward_table(drop=False)})
    assert out != "", "changing the fake table changed nothing — PATH is not wired"


@pytest.mark.parametrize("family", ["v4", "v6"])
def test_a_flushed_forward_chain_is_reported_per_family(tmp_path, family):
    """THE original bug (#336), now per family. A flushed chain has no rules, so
    no counter moves and the delta-based check reads `ok` forever."""
    out = _run(tmp_path, **{**HEALTHY, f"{family}_forward": _forward_table(drop=False)})
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
    out = _run(tmp_path, **{**HEALTHY, f"{family}_output": _output_table(drop=False)})
    cmd = "iptables" if family == "v4" else "ip6tables"
    assert f"MISSING: no {cmd} DROP-all for the pipeline user" in out, out


@pytest.mark.parametrize("family", ["v4", "v6"])
def test_a_pipeline_allow_below_the_drop_all_is_reported(tmp_path, family):
    """The specific hazard the Ansible tasks carry: `ansible.builtin.iptables`
    APPENDS, so an allow added in a later change lands below the DROP-all. It is
    present, it matches `iptables -C`, and it permits nothing."""
    out = _run(tmp_path, **{**HEALTHY, f"{family}_output": _output_table(drop_first=True)})
    cmd = "iptables" if family == "v4" else "ip6tables"
    assert f"ORDERING: {cmd} pipeline ACCEPT" in out, out


def test_every_reported_problem_survives_into_one_string(tmp_path):
    """Several simultaneous failures must all be reported. An accumulator that
    overwrites instead of appending would pass every single-fault test above and
    hide everything but the last problem in a real incident."""
    out = _run(tmp_path,
               v4_forward=_forward_table(drop=False), v4_output=_output_table(drop=False),
               v6_forward=_forward_table(drop=False), v6_output=_output_table(drop=False))
    assert out.count("MISSING") == 6, (
        f"expected 6 problems (2 bridge paths + 1 egress, per family), got: {out}")
