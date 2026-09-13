# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The UI is served on WireGuard only; port 80 stays public for ACME alone (#600).

The UI was public so friends could see it. Nobody did, and it cannot be
discussed at work, so the public TLS listener was pure attack surface on a host
that also detonates live malware. Of the two directions that colocation exposes
— web compromise reaching the lab, and a guest escape reaching the app — web
compromise is far the likelier, because a public nginx with Keycloak auth is
probed continuously while a hypervisor escape is a sub-1% scenario.

Keycloak sharpens it: it is pinned at 26.1.5 with no upgrade path, because
26.7.2 fails its own migration on an open upstream defect (keycloak#51304,
reproduced against a copy of production in #457). An internet-facing service
that cannot be upgraded is a standing condition, not a patchable one.

Port 80 MUST stay publicly bound. certbot renews by webroot/HTTP-01, so
Let's Encrypt has to reach the public address on 80 or the certificate expires
and TLS breaks over WireGuard too. That asymmetry is the easy thing to "tidy up"
later, so it is asserted explicitly here rather than left to a comment.

These tests parse the `server` blocks and assert on their `listen` directives.
The template's comments name every address and port involved, so a grep would
pass whether or not the listeners were right.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TPL_PATH = (ROOT / "ansible" / "roles" / "frontend" / "templates"
            / "lamware-nginx.conf.j2")
TPL = TPL_PATH.read_text(encoding="utf-8")

PUBLIC = "{{ public_ip }}"
WIREGUARD = "{{ wireguard_address | ansible.utils.ipaddr('address') }}"


def _server_blocks() -> list[str]:
    """Brace-matched bodies of every top-level `server { ... }` block."""
    blocks = []
    for m in re.finditer(r"^server\s*\{", TPL, re.MULTILINE):
        i, depth = m.end(), 1
        while depth and i < len(TPL):
            if TPL[i] == "{":
                depth += 1
            elif TPL[i] == "}":
                depth -= 1
            i += 1
        blocks.append(TPL[m.end():i - 1])
    assert blocks, "no server blocks parsed — the template shape changed"
    return blocks


def _listens(body: str) -> list[str]:
    """`listen` directives in a block, comments stripped."""
    out = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = re.match(r"listen\s+([^;]+);", stripped)
        if m:
            out.append(m.group(1).strip())
    return out


def _tls_block() -> str:
    for b in _server_blocks():
        if any("ssl" in d for d in _listens(b)):
            return b
    raise AssertionError("no server block with a TLS listener")


def _plain_block() -> str:
    for b in _server_blocks():
        ds = _listens(b)
        if ds and not any("ssl" in d for d in ds):
            return b
    raise AssertionError("no plain-HTTP server block")


# --- the change itself -----------------------------------------------------

def test_tls_is_not_served_on_the_public_address():
    """The point of #600. If this fails, the UI is internet-facing again."""
    for directive in _listens(_tls_block()):
        assert PUBLIC not in directive, (
            f"public TLS listener is back: 'listen {directive};' — the UI is "
            f"internet-facing, on the host that detonates malware")


def test_tls_is_served_on_wireguard():
    """Removing the public listener must not have removed access entirely."""
    assert any(WIREGUARD in d for d in _listens(_tls_block())), \
        "no WireGuard TLS listener — the UI is unreachable from anywhere"


def test_the_tls_block_listens_on_exactly_one_address():
    listens = _listens(_tls_block())
    assert len(listens) == 1, \
        f"expected one TLS listener (WireGuard), found {len(listens)}: {listens}"


# --- the part that must NOT be tidied away ---------------------------------

def test_port_80_stays_publicly_bound_for_acme():
    """certbot uses webroot/HTTP-01. Drop this and the cert silently stops
    renewing; ~90 days later TLS fails over WireGuard too."""
    assert any(PUBLIC in d for d in _listens(_plain_block())), (
        "public port-80 listener removed — certbot renews by webroot/HTTP-01 "
        "and Let's Encrypt can no longer reach the challenge")


def test_the_acme_challenge_location_still_exists():
    assert "/.well-known/acme-challenge/" in _plain_block(), \
        "ACME challenge location gone; renewal will fail"


def test_the_public_http_listener_serves_nothing_but_acme_and_a_redirect():
    """Port 80 is the one remaining public surface, so what it serves is the
    whole of the public attack surface. It must stay trivial."""
    body = _plain_block()
    locations = re.findall(r"location\s+([^\s{]+)\s*\{", body)
    assert set(locations) <= {"/.well-known/acme-challenge/", "/"}, \
        f"public port 80 serves more than ACME and a redirect: {locations}"
    assert "proxy_pass" not in body, \
        "public port 80 proxies to a backend — it must only serve ACME"
