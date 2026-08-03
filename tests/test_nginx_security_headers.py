# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every location that sets a header must set them ALL (#209).

nginx `add_header` does not merge. A single `add_header` anywhere in a `location`
block **replaces every header inherited from the server block** — silently, with no
warning at config test or reload. So a block that adds one cache header drops all six
security headers, and a block that overrides `X-Frame-Options` drops the other five.

That is exactly what had happened:

- `location /assets/` added `Cache-Control` and therefore served every static asset
  with no HSTS, no CSP, and no nosniff
- both `/auth/` blocks overrode `X-Frame-Options` deliberately — the comments explain
  why — and lost `Strict-Transport-Security` and `Content-Security-Policy` as
  collateral

The override was understood. The consequence was not, and nothing in the config or the
deploy would ever say so. This test is the only place that can.

It parses the template rather than a rendered file so it runs in CI with no host, and
because the Jinja scalars here do not affect header structure.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONF = (ROOT / "ansible" / "roles" / "frontend" / "templates"
        / "lamware-nginx.conf.j2")

# The security headers the server block establishes. Any location that adds ANY header
# must restate all of these or it silently serves responses without them.
REQUIRED = (
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Strict-Transport-Security",
    "Content-Security-Policy",
)


def _text() -> str:
    return CONF.read_text(encoding="utf-8")


def _location_blocks() -> dict[str, str]:
    """Map of "path #n" -> block body, by brace matching.

    Keyed with an index because this config has TWO `location /` blocks — one in the
    HTTP->HTTPS redirect server, one in the TLS server. A plain path key collides and
    silently drops one from the parametrised test, which is the sort of gap this file
    exists to prevent.

    Brace matching rather than regex-to-`}`: these blocks contain nested braces in
    Jinja expressions and proxy directives.
    """
    text = _text()
    blocks: dict[str, str] = {}
    for n, match in enumerate(re.finditer(r"^\s*location\s+([^\s{]+)\s*\{", text, re.M)):
        path = f"{match.group(1)} #{n}"
        depth, i = 0, match.end() - 1
        while i < len(text):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        blocks[path] = text[match.end():i]
    return blocks


def test_server_block_still_sets_the_full_header_set():
    """If the server block loses one, the per-location expectation below is wrong.

    Detected by INDENTATION, not by splitting on the first `location`: there are two
    server blocks, and the first is the ACME/HTTP redirect which has locations but no
    headers. Splitting naively tested the wrong block and reported all six missing.
    """
    text = _text()
    missing = [h for h in REQUIRED
               if not re.search(rf"^    add_header {h}", text, re.M)]
    assert not missing, f"server block no longer sets {missing}"


@pytest.mark.parametrize("path", sorted(_location_blocks()))
def test_location_that_adds_any_header_restates_all_of_them(path):
    """The core guard. Adding one header silently drops the inherited six."""
    body = _location_blocks()[path]
    if "add_header" not in body:
        return  # inherits cleanly — nothing to check
    missing = [h for h in REQUIRED if f"add_header {h}" not in body]
    assert not missing, (
        f"location {path} calls add_header, which REPLACES all inherited headers, "
        f"but does not restate {missing}. Responses from this location are served "
        f"without them. Restate every header in REQUIRED, or remove add_header "
        f"from the block entirely so the server-level set is inherited.")


def test_every_proxied_auth_path_is_rate_limited():
    """The admin console was the one auth path with no brute-force control."""
    unlimited = [p for p, body in _location_blocks().items()
                 if p.startswith("/auth") and "limit_req" not in body]
    assert not unlimited, (
        f"auth paths without limit_req: {unlimited}. The Keycloak admin console is "
        f"the highest-value target on the host; exempting it while /auth/ below it "
        f"is limited inverts the priority (#209).")


def test_declared_zones_match_the_zones_actually_used():
    """A typo'd zone name is an nginx startup failure, not a silent no-op — but a
    declared-and-unused zone is dead config that invites the opposite mistake."""
    text = _text()
    declared = set(re.findall(r"limit_req_zone[^;]*zone=(\w+):", text))
    used = set(re.findall(r"limit_req\s+zone=(\w+)", text))
    assert used <= declared, f"limit_req references undeclared zone(s): {used - declared}"
    assert declared <= used, f"declared but unused zone(s): {declared - used}"


def test_rate_limit_comment_matches_the_configured_bursts():
    """The header comment claimed auth burst 10 while the config used 50.

    Documentation drift on a security control is how the next person 'fixes' the
    config to match a comment that was never true.
    """
    text = _text()
    header = text.split("limit_req_zone", 1)[0]
    for zone, burst in re.findall(r"limit_req\s+zone=(\w+)\s+burst=(\d+)", text):
        claimed = re.search(rf"(?im)^#\s*{zone}\b.*burst\s+(\d+)", header)
        if claimed:
            assert claimed.group(1) == burst, (
                f"zone '{zone}': comment documents burst {claimed.group(1)} but the "
                f"config uses burst={burst}")
