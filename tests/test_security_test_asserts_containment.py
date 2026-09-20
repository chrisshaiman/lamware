# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""`make security-test` must assert what is IMPOSSIBLE, not only what is up.

Before this, the suite ran nine checks and made exactly one negative assertion
(the public TLS listener). Six were health and auth, one was a scanner, and one
— which I added — was a functional reachability check. SECURITY_MODEL.md said
outright that the air gap was somebody else's job.

That is the wrong shape for a post-deploy security gate on a host that
detonates live malware. On 2026-09-19 the pipeline user's egress DROP sat at
0 packets for a day while uid 997 reached 1.1.1.1:443, and nothing in that file
would have noticed.

The properties this host actually rests on:

    the detonation network cannot leave the box
    the pipeline user cannot leave the box
    the pipeline user is held to its localhost allowlist

A negative assertion has to be made by ATTEMPTING the thing. A rule that exists
satisfied every structural check for the whole day it did nothing, which is why
these connect rather than grep.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = (ROOT / "ansible" / "roles" / "security-test" / "templates"
         / "security-smoke-test.sh.j2").read_text()


def _check(label: str) -> str:
    start = SMOKE.index(label)
    nxt = SMOKE.find('echo "[', start + len(label))
    return SMOKE[start:nxt if nxt > 0 else len(SMOKE)]


def test_pipeline_egress_is_asserted_by_attempting_it():
    body = _check("CONTAINMENT: pipeline user cannot reach the internet")
    assert "/dev/tcp/" in body, "egress containment is inferred, not attempted"
    assert body.count("/dev/tcp/") >= 1
    assert re.search(r"fail\s+\"pipeline user reached the internet", body), (
        "reaching the internet does not fail the check")


def test_pipeline_egress_tries_more_than_one_destination():
    """One unreachable host is indistinguishable from enforcement."""
    body = _check("CONTAINMENT: pipeline user cannot reach the internet")
    dsts = set(re.findall(r"for dst in ([^\n]+)", body))
    assert dsts, "no destination list"
    assert len(next(iter(dsts)).split()) >= 3, f"only {dsts} probed"


def test_the_localhost_allowlist_is_checked_in_both_directions():
    """Denied ports must refuse AND allowed ports must work. Without the second
    half, a host with no networking at all would pass as contained."""
    body = _check("CONTAINMENT: pipeline user is held to its localhost allowlist")
    assert "27017" in body and "4000" in body, "revoked ports not probed"
    assert "5432" in body, "the allowlist is never shown to still work"
    assert re.search(r"fail\s+\"pipeline user cannot reach PostgreSQL", body), (
        "a denied allowlist does not fail the check")


def test_the_air_gap_is_asserted():
    """SECURITY_MODEL.md used to say this suite did not check the air gap."""
    body = _check("CONTAINMENT: detonation network cannot leave the box")
    assert "FORWARD" in body
    assert "virbr-det" in body
    assert re.search(r"fail\s+\"AIR GAP:", body), "the air gap cannot fail this check"


def test_the_air_gap_check_covers_both_families_and_both_paths():
    """#343: the v6 half of a control existed and was unwatched for months."""
    body = _check("CONTAINMENT: detonation network cannot leave the box")
    assert "iptables ip6tables" in body, "only one address family is checked"
    assert "wg0" in body and "management_interface" in body, (
        "both escape paths — internet and management VPN — must be checked")


def test_the_air_gap_check_verifies_the_FIRST_match_is_a_drop():
    """Presence is not enough: a DROP below an ACCEPT for the same pair never
    sees the traffic. The check reads the first matching rule and requires it
    to be terminating."""
    body = _check("CONTAINMENT: detonation network cannot leave the box")
    assert "exit" in body, "the awk does not stop at the first match"
    assert re.search(r'!=\s*"DROP"', body), "a non-DROP first match is accepted"


def test_the_air_gap_check_states_it_is_structural():
    """It asserts rules and order, not a live packet — a host cannot originate
    a FORWARDed one. Overclaiming here would be worse than the weaker check."""
    body = _check("CONTAINMENT: detonation network cannot leave the box")
    assert "network-monitor" in body, (
        "the check does not say what does the continuous verification")


def test_containment_checks_come_after_the_service_checks_but_all_run():
    """Ordering is cosmetic; what matters is none of them are skipped."""
    for label in ("CONTAINMENT: pipeline user cannot reach the internet",
                  "CONTAINMENT: pipeline user is held to its localhost allowlist",
                  "CONTAINMENT: detonation network cannot leave the box"):
        assert SMOKE.count(label) == 1, f"{label!r} appears {SMOKE.count(label)} times"
