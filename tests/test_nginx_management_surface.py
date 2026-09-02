# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The admin console and OpenAPI docs were reachable from the internet (#529).

The public 443 listener is deliberate and serves the SPA, `/api/` and `/ws/`.
`/docs`, `/redoc` and `/openapi.json` were not part of that decision — they
enumerate every endpoint and its schema for an unauthenticated reader — and
`/auth/admin/` is the Keycloak admin console, the highest-value target on a host
that detonates live malware.

Both listeners share one `server` block, so the restriction is per-location on
`$remote_addr` rather than per-listener. These tests parse the location blocks
and assert on their contents; the file's own comments name every path involved,
so a grep for "deny all" would pass whether or not the guards survived.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TPL = (ROOT / "ansible" / "roles" / "frontend" / "templates"
       / "lamware-nginx.conf.j2").read_text(encoding="utf-8")


def _location_body(path: str) -> str:
    """Return the body of `location <path> { ... }`, brace-matched."""
    m = re.search(r"location\s+" + re.escape(path) + r"\s*\{", TPL)
    assert m, f"no location block for {path}"
    i, depth = m.end(), 1
    while depth:
        if TPL[i] == "{":
            depth += 1
        elif TPL[i] == "}":
            depth -= 1
        i += 1
    return TPL[m.end():i - 1]


RESTRICTED = ["/docs", "/redoc", "/openapi.json", "/auth/admin/"]
PUBLIC = ["/api/", "/ws/", "/auth/"]


@pytest.mark.parametrize("path", RESTRICTED)
def test_the_management_paths_are_wireguard_only(path):
    body = _location_body(path)
    assert "deny all;" in body, f"{path} is reachable from the public listener"
    allows = re.findall(r"allow\s+([^;]+);", body)
    assert allows, f"{path} denies everything, including WireGuard"
    assert any("wireguard_address" in a for a in allows), (
        f"{path} allows {allows} — not derived from wireguard_address")


@pytest.mark.parametrize("path", RESTRICTED)
def test_the_allow_uses_the_subnet_not_the_single_address(path):
    """`ipaddr('address')` yields 10.200.0.1 — the server's own end. Peers come
    from elsewhere in the subnet, so that spelling would lock everyone out."""
    body = _location_body(path)
    allow = next(a for a in re.findall(r"allow\s+([^;]+);", body)
                 if "wireguard_address" in a)
    assert "subnet" in allow, f"{path}: {allow.strip()} is the host address, not the subnet"


@pytest.mark.parametrize("path", PUBLIC)
def test_the_deliberately_public_paths_are_not_restricted(path):
    """The 443 listener is intentional. A blanket deny would be a regression in
    the other direction, and this is the assertion that keeps the test honest."""
    assert "deny all;" not in _location_body(path), (
        f"{path} is meant to be publicly reachable")


def test_admin_keeps_its_rate_limit_as_well_as_the_allowlist():
    """#209 gave /auth/admin/ its own limit_req zone. Network restriction must
    not quietly replace brute-force control — a WireGuard peer can still guess
    passwords."""
    assert "limit_req zone=admin" in _location_body("/auth/admin/")


def test_the_redirect_does_not_reflect_the_host_header():
    """#536: `return 301 https://$host$request_uri` sends a client wherever the
    Host header says."""
    # [^;]+ not \S+: the target contains a Jinja expression with spaces
    # ("{{ frontend_server_name }}"), so \S+ matches nothing and the test
    # would fail on "no redirect found" instead of on the thing it guards.
    redirects = re.findall(r"return\s+301\s+([^;]+);", TPL)
    assert redirects, "no redirect found"
    assert not any("$host" in r for r in redirects), redirects
