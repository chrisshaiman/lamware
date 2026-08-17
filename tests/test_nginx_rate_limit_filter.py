# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The nginx rate-limit fail2ban filter must actually match nginx's log lines.

The shipped failregex opened with a date prefix:

    ^\\s*\\S+ \\S+ \\[error\\] \\d+#\\d+: \\*\\d+ limiting requests, ...

fail2ban matches its **datepattern first** and hands failregex the line with the
timestamp already stripped, so those two leading `\\S+` tokens had nothing left to
match. The filter could never fire. nginx logged every rate-limit event, fail2ban
read them, and nothing was ever banned — a control that reported healthy while
measuring nothing, which is the same shape as #336 and #343.

Measured with fail2ban-regex on a real nginx error.log line:

    with the date prefix:     Lines: 1 lines, 0 ignored, 0 matched, 1 missed
    without it:               Lines: 1 lines, 0 ignored, 1 matched, 0 missed

These tests EXECUTE fail2ban-regex rather than eyeballing the pattern. A regex
this class of bug lives in looks correct when read — the log line really does
start with a date — and only the tool knows the date is gone by then.
"""
import re
import shutil
import subprocess
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
FILTER = (ROOT / "ansible" / "roles" / "fail2ban" / "templates"
          / "filter-nginx-rate-limit.conf.j2")
SRC = FILTER.read_text(encoding="utf-8")

# Real nginx error.log lines. limit_req emits the first two; the third is an
# unrelated error that must NOT ban a legitimate client.
RATE_LIMITED_V4 = (
    '2026/08/17 05:14:22 [error] 1234#1234: *5678 limiting requests, excess: '
    '50.123 by zone "api", client: 203.0.113.9, server: lamware.example, '
    'request: "GET /api/analyses HTTP/1.1", host: "lamware.example"'
)
RATE_LIMITED_V6 = (
    '2026/08/17 05:14:23 [error] 1234#1234: *5679 limiting requests, excess: '
    '0.700 by zone "general", client: 2001:db8::dead:beef, server: '
    'lamware.example, request: "POST /api/submit HTTP/1.1", host: "lamware.example"'
)
UNRELATED_ERROR = (
    '2026/08/17 05:15:01 [error] 1234#1234: *5700 open() "/var/www/x" failed '
    '(2: No such file or directory), client: 198.51.100.4, server: lamware.example'
)

needs_fail2ban = pytest.mark.skipif(
    shutil.which("fail2ban-regex") is None,
    reason="fail2ban-regex not installed")


def _render(tmp_path: Path) -> Path:
    out = tmp_path / "nginx-rate-limit.conf"
    out.write_text(jinja2.Template(SRC).render(), encoding="utf-8")
    return out


def _run(tmp_path: Path, lines: list[str]) -> tuple[int, int]:
    """Run fail2ban-regex; return (matched, missed)."""
    log = tmp_path / "nginx-error.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    proc = subprocess.run(
        ["fail2ban-regex", str(log), str(_render(tmp_path))],
        capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
    summary = re.search(r"Lines: \d+ lines, \d+ ignored, (\d+) matched, (\d+) missed",
                        proc.stdout)
    assert summary, f"could not parse fail2ban-regex output:\n{proc.stdout[-2000:]}"
    return int(summary.group(1)), int(summary.group(2))


@needs_fail2ban
def test_a_rate_limited_request_is_matched(tmp_path):
    """THE bug: this returned 0 matched, so nothing was ever banned."""
    matched, missed = _run(tmp_path, [RATE_LIMITED_V4])
    assert (matched, missed) == (1, 0), (
        "the nginx rate-limit filter does not match nginx's own log line; "
        "fail2ban strips the timestamp before applying failregex")


@needs_fail2ban
def test_an_ipv6_client_is_matched(tmp_path):
    """<HOST> covers both families; the surrounding pattern must not assume v4."""
    matched, _ = _run(tmp_path, [RATE_LIMITED_V6])
    assert matched == 1


@needs_fail2ban
def test_an_unrelated_nginx_error_is_not_matched(tmp_path):
    """The other half. A filter loose enough to match any [error] line would
    ban clients for requesting a missing file."""
    matched, missed = _run(tmp_path, [UNRELATED_ERROR])
    assert (matched, missed) == (0, 1), (
        "an unrelated nginx error matched the rate-limit filter — this bans "
        "legitimate clients")


@needs_fail2ban
def test_mixed_traffic_matches_only_the_rate_limited_lines(tmp_path):
    matched, missed = _run(
        tmp_path, [RATE_LIMITED_V4, UNRELATED_ERROR, RATE_LIMITED_V6])
    assert (matched, missed) == (2, 1)


def test_the_pattern_carries_no_date_prefix():
    """Structural guard, and the one assertion that runs without fail2ban
    installed. Re-adding a leading date token silently disables the filter."""
    failregex = next(ln for ln in SRC.splitlines() if ln.startswith("failregex"))
    body = failregex.split("=", 1)[1].strip()
    assert body.startswith(r"^\s*\[error\]"), (
        f"failregex must start at [error]; fail2ban has already removed the "
        f"timestamp by the time this pattern runs. Got: {body[:60]!r}")
    assert "<HOST>" in body, "no <HOST> group means fail2ban has nothing to ban"
