# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every container that touches a sample must carry the isolation flag set (#4).

From the threat-model verification pass (GHSA-f5q8-v78c-mr55): 11 of 15 wrappers
carried all five flags, and nothing asserted it. The only existing coverage was
`tests/test_interpret_network_isolation.py`, which checks one wrapper.

Two traps this test is built to avoid, both hit while writing it:

  1. A NAME glob is wrong. `run-pipeline-wrapper.sh.j2` matches `run-*wrapper*` and
     runs no container at all — it is a host-side orchestrator wrapper. Reporting
     it as missing all five flags is a false alarm that trains the reader to ignore
     the list. The wrapper set is DERIVED: a file is in scope iff it invokes
     `podman run`.

  2. Grepping the WHOLE FILE for a flag gives false passes. `run-sandbox.sh.j2`
     contains `systemd-run --user`, an unrelated flag on an unrelated command, so a
     naive `"--user" in text` reports the flag present when the podman invocation
     has no such option. Detection is scoped to the `podman run` invocation.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ROLES = ROOT / "ansible" / "roles"

REQUIRED_FLAGS = ("--network=none", "--read-only", "--user", "--cap-drop",
                  "--security-opt")

# Flags a wrapper deliberately omits, each with the reason it is safe here.
# A stale entry FAILS (see the last test) so it cannot outlive its justification —
# the same discipline as frontend/audit-exceptions.json.
EXCEPTIONS: dict[tuple[str, str], str] = {
    ("run-sandbox.sh.j2", "--user"): (
        "the Containerfile's USER directive already forces non-root, and the "
        "wrapper says so in a comment; adding --user here would be redundant"),
    ("run-volatility-wrapper.sh.j2", "--user"): (
        "runs image-default root inside the rootless userns. Volatility writes to "
        "/root and /home (both tmpfs, owned by root), so switching to 65534 needs a "
        "real memory-dump run to validate rather than a blind edit — tracked "
        "separately"),
}


# `podman run` in COMMAND position: at the start of a line, or after a pipe.
# Not inside quotes — network-monitor.sh.j2 carries the literal glob
# `'podman run --rm*'` in its process allowlist, which is a pattern it matches
# command lines against, not a container it starts. A plain substring search
# treats that script as a sample-processing container missing all five flags.
# Third false positive of this shape in one file; the fix each time is to match
# what the thing IS rather than text that resembles it.
_PODMAN_CMD = re.compile(r"^[ \t]*(?:[^#'\"\n]*\|[ \t]*)?podman[ \t]+run\b", re.M)


def _podman_invocation(text: str) -> str:
    """The `podman run` command only — flags elsewhere in the file do not count."""
    m = _PODMAN_CMD.search(text)
    if not m:
        return ""
    idx = m.start()
    out = []
    for line in text[idx:].splitlines():
        out.append(line)
        if not line.rstrip().endswith("\\"):
            break
    return "\n".join(out)


def _container_wrappers() -> dict[str, str]:
    """Every template that actually runs a container, keyed by filename."""
    found = {}
    for p in sorted(ROLES.glob("*/templates/*.sh.j2")):
        text = p.read_text(encoding="utf-8")
        invocation = _podman_invocation(text)
        if invocation:
            found[p.name] = invocation
    return found


WRAPPERS = _container_wrappers()


def test_the_wrapper_set_was_discovered():
    """Guards the guard: an empty or tiny set makes every assertion below vacuous."""
    assert len(WRAPPERS) >= 12, f"only found {sorted(WRAPPERS)}"
    for expected in ("run-ghidra-wrapper.sh.j2", "run-interpret-wrapper.sh.j2",
                     "run-volatility-wrapper.sh.j2", "run-sandbox.sh.j2"):
        assert expected in WRAPPERS, f"{expected} not discovered"


def test_a_non_container_wrapper_is_not_in_scope():
    """`run-pipeline-wrapper.sh.j2` matches the obvious name glob and runs nothing.
    Including it would report five phantom gaps forever."""
    assert "run-pipeline-wrapper.sh.j2" not in WRAPPERS


def test_flag_detection_is_scoped_to_the_podman_command():
    """`systemd-run --user` in run-sandbox.sh.j2 must not read as podman's --user.

    This is the difference between a test that measures the thing and one that
    measures a string that happens to appear nearby.
    """
    sandbox = WRAPPERS["run-sandbox.sh.j2"]
    assert "systemd-run" not in sandbox, "the invocation slice leaked other commands"
    assert "--user" not in sandbox, (
        "run-sandbox's podman invocation has no --user; if that changed, remove "
        "its entry from EXCEPTIONS")


def test_every_container_wrapper_carries_the_isolation_flags():
    """THE parity check the advisory asked for."""
    missing = []
    for name, invocation in sorted(WRAPPERS.items()):
        for flag in REQUIRED_FLAGS:
            if flag in invocation:
                continue
            if (name, flag) in EXCEPTIONS:
                continue
            missing.append(f"{name} lacks {flag}")
    assert not missing, (
        "container wrappers missing isolation flags: " + "; ".join(missing) +
        " — add the flag, or add a justified entry to EXCEPTIONS")


def test_network_isolation_has_no_exceptions():
    """Every other flag is arguable in some context. This one is the containment
    boundary itself: a sample-processing container must never reach a network."""
    for name, invocation in WRAPPERS.items():
        assert "--network=none" in invocation, f"{name} can reach the network"
    assert not any(f == "--network=none" for _, f in EXCEPTIONS), (
        "no exception may be granted for network isolation")


def test_exceptions_are_justified():
    for key, reason in EXCEPTIONS.items():
        assert len(reason) > 40, f"{key} needs a real reason, not a label"


def test_no_exception_is_stale():
    """An exception whose flag is now present has outlived its justification and
    must be deleted, or the list quietly grows into a way of hiding real gaps."""
    stale = []
    for (name, flag), _ in EXCEPTIONS.items():
        if name not in WRAPPERS:
            stale.append(f"{name} no longer exists")
        elif flag in WRAPPERS[name]:
            stale.append(f"{name} now has {flag}")
    assert not stale, f"remove these stale exceptions: {stale}"
