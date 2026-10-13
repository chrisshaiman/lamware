# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The host's DNSSEC root trust anchors are managed and current (#769).

2026-10-11 11:44 PDT: the root zone began signing its DNSKEY set only with
KSK-2024 (tag 38696). systemd-resolved 255's built-in anchor lacks it, and with
DNSSEC=allow-downgrade (set by konstruktoid.hardening) every lookup on the host
failed with `missing-key`. The fix was a hand-placed anchors file; this keeps it
in the role, byte-identical to what fixed the host.
"""
import hashlib
from pathlib import Path

import jinja2
import yaml

ROLE = Path(__file__).resolve().parents[1] / "ansible" / "roles" / "hardening"
DEFAULTS = yaml.safe_load((ROLE / "defaults" / "main.yml").read_text())
TASKS = yaml.safe_load((ROLE / "tasks" / "resolver.yml").read_text())

# IANA root-anchors.xml, verified 2026-10-11 (see the role defaults).
IANA = {
    "20326": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
    "38696": "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16",
}
# sha256 of /etc/dnssec-trust-anchors.d/root.positive on the host, 2026-10-12.
HOST_SHA256_PREFIX = "9ecaa9e83ad7952e"


def _rendered(keep_trailing_newline: bool = False) -> str:
    task = next(t for t in TASKS if "ansible.builtin.copy" in t)
    env = jinja2.Environment(keep_trailing_newline=keep_trailing_newline)
    return env.from_string(task["ansible.builtin.copy"]["content"]).render(**DEFAULTS)


def test_the_file_renders_byte_identical_to_the_host():
    """A deploy of this role must change nothing on the host that DNS depends on."""
    for keep in (False, True):  # independent of how the renderer treats a trailing newline
        out = _rendered(keep_trailing_newline=keep)
        assert hashlib.sha256(out.encode()).hexdigest().startswith(HOST_SHA256_PREFIX), (keep, out[-20:])


def test_both_current_root_ksks_are_anchored_with_ianas_digests():
    lines = [ln for ln in _rendered().splitlines() if ln and not ln.startswith(";")]
    got = {}
    for ln in lines:
        owner, cls, typ, tag, alg, dtype, digest = ln.split()
        assert (owner, cls, typ, alg, dtype) == (".", "IN", "DS", "8", "2"), ln
        got[tag] = digest
    assert got == IANA


def test_the_deploy_fails_unless_the_root_zone_validates():
    """Presence is not the property; resolution is."""
    q = next(t for t in TASKS if "ansible.builtin.command" in t)
    assert q["ansible.builtin.command"]["cmd"].strip() == "resolvectl query -t SOA ."
    a = next(t for t in TASKS if "ansible.builtin.assert" in t)
    assert "authenticated: yes" in a["ansible.builtin.assert"]["that"]


def test_the_role_imports_the_resolver_tasks():
    main = yaml.safe_load((ROLE / "tasks" / "main.yml").read_text())
    assert any(t.get("ansible.builtin.import_tasks") == "resolver.yml" for t in main)
