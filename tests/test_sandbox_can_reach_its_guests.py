# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The smoke test must check the INWARD path, not only the public surface.

This is the assertion #563 asked for on 2026-09-03 and nobody added. The gap
cost a working day twice:

  2026-09-03  A `TAGS=hardening,kvm,frontend` deploy left the host unable to
              reach its own guests. konstruktoid set `deny (outgoing)` with no
              rule for the detonation network, and roles/networking -- which
              owns those rules -- was not in the tag list. A freshly built guest
              booted, took a DHCP lease, reached the desktop, and answered
              nothing. Hours went into the image before the host was suspected.

  2026-09-19  Same mechanism, different route. CAPE could not reach the guest
              agent; every detonation returned 0 processes and 0 API calls.
              Finding it took three detonations and a packet-logging rule.
              #563 had already written down the symptom, the cause, the packet
              counters and the fix.

Prose did not prevent the second occurrence. A red check would have.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SMOKE = (ROOT / "ansible" / "roles" / "security-test" / "templates"
         / "security-smoke-test.sh.j2").read_text()
DECISIONS = (ROOT / "docs" / "DECISIONS.md").read_text()
SECURITY_MODEL = (ROOT / "docs" / "SECURITY_MODEL.md").read_text()


def _reachability_check() -> str:
    """The PREREQUISITE check — the host being able to reach its own guests.

    Deliberately not called a containment check: it asserts the sandbox WORKS,
    not that something is impossible. The containment assertions live in
    test_security_test_asserts_containment.py.
    """
    start = SMOKE.index("PREREQUISITE: sandbox can reach its own guests")
    nxt = SMOKE.find('echo "[', start + 10)
    return SMOKE[start:nxt if nxt > 0 else len(SMOKE)]


def test_the_reachability_check_exists():
    assert "sandbox can reach its own guests" in SMOKE, (
        "nothing asserts the host can reach the guests it analyses; that gap "
        "cost a day on 2026-09-03 and again on 2026-09-19")


def test_it_fails_when_output_drops_to_the_detonation_bridge():
    """The exact condition from #563: `deny (outgoing)` with no rule for the
    detonation network."""
    body = _reachability_check()
    assert "OUT_POLICY" in body and "DET_ACCEPT" in body, (
        "the check does not inspect the OUTPUT policy or an ACCEPT to the bridge")
    assert re.search(r"fail\s+\"OUTPUT policy is", body), (
        "a dropping OUTPUT policy does not fail the check")


def test_it_probes_a_live_guest_when_one_exists():
    """Inferring from rules is the fallback. When a guest is actually up, the
    connection is the better evidence — and it is what CAPE itself does."""
    body = _reachability_check()
    assert "virsh list --state-running" in body
    assert "/dev/tcp/" in body, "no live probe of the agent port"


def test_it_does_not_fail_merely_because_no_guest_is_running():
    """Guests are shut off between analyses. A check that fails then would fire
    on every healthy host, and a check that always fires gets ignored."""
    body = _reachability_check()
    assert re.search(r"pass\s+\"firewall path to", body), (
        "with no guest running the check must pass on the path, not fail")


def test_the_reachability_check_is_labelled_as_a_prerequisite():
    """It is a functional health check, not a containment property, and it sits
    in a suite whose job is asserting what must be impossible. Labelling it
    keeps the distinction visible to whoever reads the output."""
    assert "PREREQUISITE" in SMOKE, (
        "the reachability check reads like a security assertion; it is not one")


def test_the_numbering_is_consistent():
    """A renumbering miss reads as a silently skipped test."""
    totals = {int(t) for _, t in re.findall(r"\[(\d+)/(\d+)\]", SMOKE)}
    assert len(totals) == 1, f"mixed totals in step labels: {totals}"
    total = totals.pop()
    nums = sorted({int(n) for n, _ in re.findall(r"\[(\d+)/(\d+)\]", SMOKE)})
    assert nums == list(range(1, total + 1)), f"checks numbered {nums}, expected 1..{total}"


# --- the decision itself has to be findable --------------------------------

def test_the_firewall_decision_is_recorded_as_an_adr():
    """#563 recommended `manage_ufw: false` on 2026-09-03 and it was
    rediscovered from scratch sixteen days later. The reasoning belongs where
    someone looks for architectural decisions, not only in a closed issue."""
    assert "ADR-020" in DECISIONS
    assert "iptables-persistent" in DECISIONS
    assert "manage_ufw" in DECISIONS, "the ADR does not name the actual knob"


def test_the_adr_is_in_the_index():
    """An ADR nobody can find is a commit message with extra steps."""
    assert "adr-020-one-firewall-mechanism" in DECISIONS


def test_the_adr_records_what_the_choice_gives_up():
    """Dropping ufw gave up default-deny inbound and nothing replaced it. An
    ADR that lists only benefits is advocacy, not a record."""
    idx = DECISIONS.index("## ADR-020")
    body = DECISIONS[idx:]
    assert ":INPUT ACCEPT" in body
    assert "unpaid for" in body or "does not solve" in body


def test_the_security_model_does_not_describe_a_firewall_we_removed():
    """SECURITY_MODEL.md described `ufw-before-output` for two hours after ufw
    was purged. Stale security documentation is worse than none: it reads as
    current and was written to be authoritative."""
    assert "ufw-before-output" not in SECURITY_MODEL
    assert "ufw6-before-output" not in SECURITY_MODEL


def test_the_security_model_states_inbound_is_not_default_deny():
    """The property ufw provided and nothing replaced. It must not be possible
    to read the doc and assume inbound is handled."""
    assert ":INPUT ACCEPT" in SECURITY_MODEL
    assert "not default-deny" in SECURITY_MODEL.lower() or "NOT default-deny" in SECURITY_MODEL
