# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The Keycloak fail2ban filter must actually match Keycloak's log lines (#435).

The shipped failregex was:

    LOGIN_ERROR.*ipAddress=<HOST>

Keycloak 26 quotes its event values, so `ipAddress=<HOST>` cannot match a leading
quote. Measured with fail2ban-regex against a real journal line from the deployed
host:

    Failregex: 0 total
    Lines: 1 lines, 0 ignored, 0 matched, 1 missed

The jail was enabled the whole time — `enabled = true`, `maxretry = 10`, port
http,https — reporting zero failures, which is indistinguishable from nobody
attacking Keycloak. Same shape as the dead controls in test_dead_controls.py, and the
same shape as the nginx rate-limit filter whose sibling test this is modelled on.

There is a second property worth pinning, because fixing only the quoting would leave
it. `.*` is greedy and the old pattern was unanchored. In Keycloak's event format
`username` comes AFTER `ipAddress`, so under an unquoted format the greedy match
binds to the LAST `ipAddress=` on the line — letting an unauthenticated attacker
submit a username of the form `ipAddress=<victim>` and ban an arbitrary IP through
iptables-multiport. That is why test_a_crafted_username_cannot_choose_the_banned_ip
exists.

These tests EXECUTE fail2ban-regex rather than reading the pattern. This class of bug
looks correct when read — the line really does contain LOGIN_ERROR and an ipAddress —
and only the tool knows about the quotes.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
FILTER = (ROOT / "ansible" / "roles" / "fail2ban" / "templates"
          / "filter-keycloak-auth.conf.j2")
SRC = FILTER.read_text(encoding="utf-8")

# Captured verbatim from `journalctl -u keycloak` on the deployed host, with the
# systemd prefix stripped the way fail2ban's systemd backend delivers it.
QUOTED_REAL = (
    '2026-08-20 15:26:01,464 WARN  [org.keycloak.events] (executor-thread-34) '
    'type="LOGIN_ERROR", realmId="0286a739-9bd1-4521-a4df-e45686d94d88", '
    'realmName="lamware", clientId="lamware-web", userId="null", '
    'ipAddress="34.29.229.177", error="user_not_found", username="admin"'
)
# The format the original pattern was written for. Kept so a Keycloak change that
# drops the quoting degrades to "still works" rather than back to "silently dead".
UNQUOTED = (
    '2026-08-20 15:26:01,464 WARN  [org.keycloak.events] (executor-thread-34) '
    'type=LOGIN_ERROR, realmName=lamware, clientId=lamware-web, '
    'ipAddress=34.29.229.177, error=user_not_found, username=admin'
)
IPV6 = QUOTED_REAL.replace('"34.29.229.177"', '"2001:db8::dead:beef"')
# username comes AFTER ipAddress in Keycloak's event order, so a greedy .* binds to
# the attacker's string rather than the real client.
CRAFTED_USERNAME = (
    '2026-08-20 15:26:01,464 WARN  [org.keycloak.events] (executor-thread-34) '
    'type="LOGIN_ERROR", realmName="lamware", ipAddress="203.0.113.9", '
    'error="user_not_found", username="ipAddress=198.51.100.7"'
)
# A successful login must never ban anyone.
LOGIN_OK = (
    '2026-08-20 15:27:11,001 INFO  [org.keycloak.events] (executor-thread-35) '
    'type="LOGIN", realmName="lamware", clientId="lamware-web", '
    'ipAddress="34.29.229.177", username="analyst"'
)

needs_fail2ban = pytest.mark.skipif(
    shutil.which("fail2ban-regex") is None,
    reason="fail2ban-regex not installed")


def _render(tmp_path: Path) -> Path:
    out = tmp_path / "keycloak-auth.conf"
    out.write_text(jinja2.Template(SRC).render(), encoding="utf-8")
    return out


def _run(tmp_path: Path, lines: list[str]) -> tuple[int, int, list[str]]:
    """Run fail2ban-regex; return (matched, missed, ips_that_would_be_banned)."""
    log = tmp_path / "keycloak.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    proc = subprocess.run(
        ["fail2ban-regex", str(log), str(_render(tmp_path))],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    summary = re.search(r"Lines: \d+ lines, \d+ ignored, (\d+) matched, (\d+) missed",
                        proc.stdout)
    assert summary, f"could not parse fail2ban-regex output:\n{proc.stdout[-2000:]}"
    ips = re.findall(r"^\s+(\S+)\s+\(", proc.stdout, re.M)
    return int(summary.group(1)), int(summary.group(2)), ips


@needs_fail2ban
def test_a_real_quoted_login_error_is_matched(tmp_path):
    """THE bug: this returned 0 matched, so the jail never banned anything."""
    matched, missed, _ = _run(tmp_path, [QUOTED_REAL])
    assert (matched, missed) == (1, 0), (
        "the filter does not match Keycloak 26's own log line — it quotes event "
        "values and the pattern expected them bare")


@needs_fail2ban
def test_the_unquoted_format_still_matches(tmp_path):
    """A Keycloak change that drops quoting must not silently kill the jail again."""
    matched, missed, _ = _run(tmp_path, [UNQUOTED])
    assert (matched, missed) == (1, 0)


@needs_fail2ban
def test_an_ipv6_client_is_matched(tmp_path):
    matched, _, _ = _run(tmp_path, [IPV6])
    assert matched == 1


@needs_fail2ban
def test_a_successful_login_is_not_matched(tmp_path):
    """The other half. A filter loose enough to match any event line bans analysts."""
    matched, missed, _ = _run(tmp_path, [LOGIN_OK])
    assert (matched, missed) == (0, 1), "a successful LOGIN matched the failure filter"


@needs_fail2ban
def test_a_crafted_username_line_still_matches(tmp_path):
    """It should match — it IS a login failure. Which IP it bans is the next test."""
    matched, missed, _ = _run(tmp_path, [CRAFTED_USERNAME])
    assert (matched, missed) == (1, 0)


def test_a_crafted_username_cannot_choose_the_banned_ip():
    """The greedy-match hazard, which fixing the quoting alone would leave.

    username comes AFTER ipAddress in Keycloak's event order, so `.*ipAddress=<HOST>`
    binds to the last occurrence — the attacker's. That turns an unauthenticated login
    attempt into an arbitrary-IP ban on http,https via iptables-multiport.

    Asserted on the CAPTURE, not the match count: both patterns match this line, and
    only the captured host differs. Measured with fail2ban's <HOST> expansion:

        OLD  captures 198.51.100.7   the attacker's crafted username
        NEW  captures 203.0.113.9    the real client

    This test needs no fail2ban binary, so unlike its siblings it runs everywhere —
    which matters, because it is the security-relevant assertion of the file.
    """
    failregex = re.search(r"^failregex\s*=\s*(.+)$", jinja2.Template(SRC).render(),
                          re.M).group(1).strip()
    # fail2ban's <HOST>, approximated closely enough to compare binding behaviour.
    host = r"(?P<host>[\w\-.^_]*\w|[0-9a-fA-F:]+)"
    pattern = failregex.replace("<HOST>", host)
    body = CRAFTED_USERNAME.split(") ", 1)[1]
    m = re.search(pattern, body)
    assert m, "the filter no longer matches a crafted-username login failure"
    assert m.group("host") == "203.0.113.9", (
        f"the pattern captured {m.group('host')!r} — a crafted username selected the "
        f"banned IP, because the match is binding to the last ipAddress= on the line "
        f"rather than the event's own field")
