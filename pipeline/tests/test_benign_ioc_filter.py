# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The benign filter must not let a sample suppress its own C2 indicator.

`is_benign_indicator` dropped a resolved IP whenever the context string merely
CONTAINED a benign domain:

    for benign in BENIGN_DOMAINS:
        if benign in ctx_lower:      # unbounded substring test
            return True

The context is built as `f"Resolved from {domain}"` from sample-derived DNS
data, so the test was effectively applied to an attacker-chosen string. A C2 at
`login.live.com.attacker-cdn.net` — a subdomain of a domain the attacker owns,
prefixed with a benign name — had its resolved IP removed from the IOC set,
silently. Coincidence sufficed too: `notlogin.live.command-and-control.ru`
contains `login.live.com`.

That is an evasion primitive, not a false positive: it is cheap to trigger
deliberately and leaves no trace, and the IOC set is what feeds the database,
the report and any downstream hunting.

`is_benign_domain` in the same module already does this correctly — exact match
or a TRUE subdomain suffix — so the fix is to parse the domain out and call it,
rather than keep a second, weaker copy of the check. Same shape as the two
delimiter implementations in #361.
"""
import pytest

# conftest.py puts ansible/roles/pipeline/files on sys.path — the modules deploy
# flat to /opt/pipeline/, so `ioc_extract` is only importable via that hook.
from ioc_extract import is_benign_domain, is_benign_indicator

IP = "198.51.100.7"


def _dropped(context: str) -> bool:
    return is_benign_indicator("ipv4-addr", IP, context)


@pytest.mark.parametrize("domain", [
    "login.live.com",
    "www.msftconnecttest.com",
    "time.windows.com",
])
def test_a_genuinely_benign_domain_is_still_filtered(domain):
    """Positive control. Without it, a filter that suppresses nothing would
    satisfy every assertion below and re-flood the IOC set with sandbox noise."""
    assert _dropped(f"Resolved from {domain}") is True


def test_a_true_subdomain_is_still_filtered():
    """`is_benign_domain` accepts real subdomains, and that behaviour is kept."""
    assert _dropped("Resolved from edge-a.login.live.com") is True


@pytest.mark.parametrize("hostile", [
    "login.live.com.attacker-cdn.net",       # benign name as a LEFT label
    "evil-login.live.com.badguy.ru",         # embedded mid-string
    "notlogin.live.command-and-control.ru",  # coincidental substring
    "time.windows.com.evil.example",
])
def test_a_lookalike_domain_does_not_suppress_the_ioc(hostile):
    """THE bug. Each of these is a domain an attacker can register."""
    assert _dropped(f"Resolved from {hostile}") is False, (
        f"C2 IP suppressed because its context contains a benign name: {hostile}")


def test_an_unrelated_c2_is_untouched():
    assert _dropped("Resolved from c2.evil.example") is False


def test_the_filter_still_applies_to_the_domain_itself():
    """The domain-name path was already correct; guard it against drift."""
    assert is_benign_indicator("domain-name", "login.live.com") is True
    assert is_benign_indicator("domain-name", "login.live.com.attacker-cdn.net") is False
    assert is_benign_domain("login.live.com.attacker-cdn.net") is False


def test_a_context_without_the_marker_is_ignored():
    """Only 'resolved from' contexts carry a domain; anything else must not be
    parsed as one."""
    assert _dropped("Seen in login.live.com traffic") is False
    assert _dropped("") is False


def test_a_truncated_context_does_not_raise():
    """The marker with nothing after it used to be impossible; now it is parsed,
    so it must degrade rather than IndexError."""
    assert _dropped("Resolved from ") is False
    assert _dropped("resolved from") is False
