# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""SSH must offer a post-quantum key exchange, without narrowing what works.

konstruktoid v4.4.1 defaults sshd_kex_algorithms to five pre-PQ algorithms, so
every session to this host negotiated a classical KEX and OpenSSH 10 clients
warned about "store now, decrypt later". The banner blamed the server version.
That was wrong: sshd is OpenSSH 9.6p1 and its build supports
sntrup761x25519-sha512@openssh.com -- verified with

    sshd -T -o KexAlgorithms=sntrup761x25519-sha512@openssh.com

The algorithm was excluded by our own hardening baseline. We pin the role
deliberately, and upstream main carries the same list, so an override is the
mechanism either way.
"""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]

PQ_KEX = "sntrup761x25519-sha512@openssh.com"

# The upstream v4.4.1 defaults. Every one must survive the override: changing
# the KEX list on a host reachable only over SSH is not the place to also
# narrow it, and a client that can connect today must still connect after.
ROLE_DEFAULT_KEX = [
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "ecdh-sha2-nistp521",
    "ecdh-sha2-nistp384",
]


def _kex():
    tasks = yaml.safe_load(
        (ROOT / "ansible" / "roles" / "hardening" / "tasks" / "main.yml").read_text())
    for t in tasks:
        v = (t or {}).get("vars") or {}
        if "sshd_kex_algorithms" in v:
            return v["sshd_kex_algorithms"]
    return None


def test_a_post_quantum_kex_is_offered():
    kex = _kex()
    assert kex is not None, (
        "no sshd_kex_algorithms override; the role default is pre-PQ only")
    assert PQ_KEX in kex, f"{PQ_KEX} is not offered"


def test_the_pq_kex_is_preferred():
    """Order is preference. Offering it last means it is rarely negotiated."""
    assert _kex()[0] == PQ_KEX


def test_the_override_is_additive_and_locks_nobody_out():
    """Every upstream default must survive.

    This is the property that makes the change safe to deploy to a host whose
    only access path is the thing being reconfigured.
    """
    kex = _kex()
    missing = [a for a in ROLE_DEFAULT_KEX if a not in kex]
    assert not missing, (
        f"the override DROPS algorithms the role offered: {missing}. A client "
        f"that can connect today would stop being able to.")


def test_no_weak_kex_was_smuggled_in_alongside():
    """Additive must not mean indiscriminate."""
    banned = ("diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1",
              "diffie-hellman-group-exchange-sha1", "ecdh-sha2-nistp256")
    present = [a for a in _kex() if a in banned]
    assert not present, f"weak KEX algorithms added: {present}"


def test_mlkem_is_not_claimed_on_a_server_that_cannot_do_it():
    """mlkem768x25519-sha256 needs OpenSSH 9.9+; this host runs 9.6p1.

    Listing it would be silently inert -- sshd ignores unknown algorithms in
    some builds and refuses to start in others. Neither is a good outcome for
    a value nobody verified.
    """
    assert "mlkem768x25519-sha256" not in _kex(), (
        "mlkem requires OpenSSH 9.9+; verify the server version before adding it")
