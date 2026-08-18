# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""TLS-expiry alerts must authenticate, or a protected topic drops them.

#352 (2c9b89f) gave the main alert path a bearer token. The certbot expiry
checker was not part of that change and kept publishing with a bare
`curl -s ... "$NTFY_URL"`. On a token-protected topic ntfy answers 403, `-s`
swallows it, and the script exits 0 — so "certificate expired" was reported
healthy while delivering nothing. Same shape as #336 and #343: a control that
measures nothing and says so to no one.

These tests RENDER the template and EXECUTE it against a stub curl, asserting
on what it actually sends. A string match for "Authorization" would pass
against a script that never reaches the call.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = (ROOT / "ansible" / "roles" / "certbot" / "templates"
            / "check-cert-expiry.sh.j2")
SRC = TEMPLATE.read_text(encoding="utf-8")

needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="bash required")


def _render(tmp_path: Path, token: str) -> Path:
    out = tmp_path / "check.sh"
    out.write_text(jinja2.Template(SRC).render(
        certbot_domain="lamware.example", certbot_expiry_warn_days=21,
        ntfy_url="https://ntfy.example", ntfy_topic="alerts", ntfy_token=token),
        encoding="utf-8")
    return out


def _run(tmp_path: Path, token: str) -> list[str]:
    """Execute the script with a stub curl; return the argv of each publish."""
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    log = tmp_path / "calls.jsonl"
    (bindir / "curl").write_text(
        "#!/usr/bin/env python3\n"
        "import sys, json\n"
        f"open({str(log)!r}, 'a').write(json.dumps(sys.argv[1:]) + '\\n')\n",
        encoding="utf-8")
    (bindir / "curl").chmod(0o755)

    script = _render(tmp_path, token)
    env = {"PATH": f"{bindir}:/usr/bin:/bin"}
    subprocess.run(["bash", str(script)], capture_output=True, text=True,
                   timeout=60, env=env)
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text().splitlines()]


@needs_bash
def test_an_alert_carries_a_bearer_token(tmp_path):
    """THE bug. The missing-certificate path fires on a fresh host."""
    calls = _run(tmp_path, "sekrit-token")
    assert calls, "the script published nothing at all"
    argv = " ".join(calls[0])
    assert "Authorization: Bearer sekrit-token" in argv, (
        f"publish is unauthenticated; a protected topic drops it. argv: {argv}")


@needs_bash
def test_an_unset_token_still_publishes(tmp_path):
    """An empty ntfy_token is a supported deployment (#398 tracks setting it).
    The header must be omitted rather than sent empty, and the alert must still
    go out."""
    calls = _run(tmp_path, "")
    assert calls, "an unauthenticated deployment stopped alerting entirely"
    argv = " ".join(calls[0])
    assert "Authorization" not in argv, f"empty bearer header sent: {argv}"


@needs_bash
def test_the_alert_still_carries_its_title_and_body(tmp_path):
    """Guards the refactor into a helper: the three call sites must keep their
    distinct titles, priorities and bodies."""
    argv = " ".join(_run(tmp_path, "t")[0])
    assert "Title: lamware TLS cert missing" in argv
    assert "Priority: urgent" in argv
    assert "Certificate file not found" in argv
    assert "https://ntfy.example/alerts" in argv


def test_every_publish_goes_through_the_authenticated_helper():
    """Structural: a new bare-curl call site would silently reintroduce this."""
    code = "\n".join(ln for ln in SRC.splitlines() if not ln.lstrip().startswith("#"))
    assert "curl -s -H" not in code, "a publish bypasses the notify helper"
    assert code.count("notify ") >= 3, "expected all three alert sites to use notify"


def test_failures_are_not_swallowed():
    """`-s` alone hid the 403 that caused this. The helper must surface it."""
    assert "--fail-with-body" in SRC or "-sS" in SRC, (
        "a rejected publish must not look like a successful one")
