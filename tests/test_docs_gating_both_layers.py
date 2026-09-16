# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The docs smoke test asserted one gate and broke when a second was added.

#529 put an nginx `allow`/`deny` in front of `/docs`. The smoke test asserted
the response was exactly 404 — the code the *application* returns when
`LAMWARE_ENABLE_DOCS` is false — so a correctly-hardened host started failing
its own security test with:

    FAIL: /docs returned 403 (expected 404 - docs should be gated)

403 is the stronger answer: refused at the edge before the request reaches the
app. Measured on the live host after deploying #542:

    public IP      -> 403   (nginx denied)
    10.200.0.1     -> 404   (allowed through, then gated by the API)

The test now checks both layers, and asserts the invariant that matters — /docs
is never 200 from either source — rather than pinning one status code.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TPL = (ROOT / "ansible" / "roles" / "security-test" / "templates"
       / "security-smoke-test.sh.j2").read_text(encoding="utf-8")
# Located by NAME, not by step number. This previously split on the literal
# "[4/7] Docs endpoint gated", so adding an eighth check to the suite renumbered
# the label and broke collection with an IndexError — the locator was pinned to
# a count that has nothing to do with what this file tests.
_start = re.search(r"\[\d+/\d+\]\s*Docs endpoint gated", TPL)
assert _start, "no 'Docs endpoint gated' step in the smoke test template"
_end = re.search(r"#\s*Test \d+:", TPL[_start.end():])
assert _end, "no following '# Test N:' header to bound the docs section"
SECTION = TPL[_start.end():_start.end() + _end.start()]


def test_both_sources_are_probed():
    """Checking only the public URL would pass on a host where the app gate had
    been switched off, because nginx answers 403 before the app is consulted."""
    assert "DOCS_PUBLIC=" in SECTION and "DOCS_WG=" in SECTION
    assert "$WG_URL" in SECTION, "the WireGuard probe must use the real address"


@pytest.mark.parametrize("var", ["DOCS_PUBLIC", "DOCS_WG"])
def test_a_200_from_either_source_fails(var):
    """The actual invariant. Everything else is a detail of which layer caught it."""
    assert re.search(rf'\[ "\${var}" = "200" \]', SECTION), (
        f"{var} is probed but a 200 from it is not treated as failure")


def test_the_network_layer_is_asserted_not_just_the_app_layer():
    """If the network layer stopped being applied, the app gate alone would
    still return 404, and a test that only checked for "not 200" would pass
    while the defence added in #529 was silently gone.

    The acceptable public answers changed with #604 — there is no public TLS
    listener any more, so a refused connection (000) is the network layer
    working, and is strictly stronger than the 403 that #529 produced. What must
    not change is that some OTHER code still fails the suite."""
    accepted = re.findall(r'"\$DOCS_PUBLIC" = "(\d{3})"', SECTION)
    assert "000" in accepted or "403" in accepted, (
        "no network-layer answer is accepted, so the public probe is no longer "
        "distinguishing 'blocked' from anything else")
    assert re.search(r'fail "/docs returned \$DOCS_PUBLIC publicly', SECTION), (
        "an unexpected public response no longer fails the suite — the network "
        "layer could vanish silently (#529)")


def test_it_no_longer_demands_exactly_404():
    """The specific brittleness that caused the failure."""
    assert 'expected 404' not in SECTION, "still pinning the app-layer code"


def test_the_nginx_rule_this_relies_on_still_exists():
    """Cross-check: the smoke test expects 403 publicly, which is only true
    while the nginx template carries the allow/deny. If someone removes that,
    this points at the reason rather than leaving a mystery 404."""
    conf = (ROOT / "ansible" / "roles" / "frontend" / "templates"
            / "lamware-nginx.conf.j2").read_text(encoding="utf-8")
    # Brace-match: the block body contains a Jinja expression, so splitting on
    # the first "}" stops inside `{{ wireguard_address | ... }}` and finds
    # nothing -- the test would fail for a reason unrelated to its subject.
    m = re.search(r"location\s+/docs\s*\{", conf)
    assert m, "no /docs location block"
    i, depth = m.end(), 1
    while depth:
        if conf[i] == "{":
            depth += 1
        elif conf[i] == "}":
            depth -= 1
        i += 1
    assert "deny all;" in conf[m.end():i - 1]
