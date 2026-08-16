# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Live C2 must not reach a phone in tappable form (#352).

The daily digest builds its LLM context from real IOC values and then tells the
model *"Be specific — name the families, techniques, and IOCs"*. Those
highlights become the notification body, pushed to `https://ntfy.sh` by default.

Two consequences, and they need different fixes:

  Confidentiality  the topic string is the entire access control on a public
                   relay. A topic is a routing key, not a secret. Fixed by
                   supporting a bearer token (or a self-hosted ntfy).
  Tappable C2      Android linkifies notification text. One mis-tap from a lock
                   screen is an outbound connection to attacker infrastructure
                   from a personal device — no sandbox, no proxy, attributable.

These tests RENDER and EXECUTE the template rather than grepping it, so they
assert what the module does, not what it appears to say.
"""
import re
from pathlib import Path

import pytest

jinja2 = pytest.importorskip("jinja2")

ROOT = Path(__file__).resolve().parents[1]
NTFY = ROOT / "ansible" / "roles" / "ntfy-alerts"
TEMPLATE = (NTFY / "templates" / "ntfy_notify.py.j2").read_text(encoding="utf-8")
DIGEST = (NTFY / "templates" / "daily-digest.py.j2").read_text(encoding="utf-8")


def _ansible_bool(v):
    """`bool` is an Ansible filter, not a stock Jinja2 one (see #349)."""
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("true", "yes", "on", "1")


def load(token="", url="https://ntfy.sh", topic="t", enabled=True):
    """Render the module and exec it, returning its namespace."""
    env = jinja2.Environment()  # noqa: S701 — rendering Python, not HTML
    env.filters["bool"] = _ansible_bool
    src = env.from_string(TEMPLATE).render(
        ntfy_url=url, ntfy_topic=topic, ntfy_token=token, ntfy_enabled=enabled)
    ns: dict = {}
    exec(compile(src, "ntfy_notify.py", "exec"), ns)  # noqa: S102
    return ns


MOD = load()
defang_text = MOD["defang_text"]
defang_ioc = MOD["defang_ioc"]


# ---------------------------------------------------------------------------
# Nothing tappable survives
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw", [
    "http://evil.example.com/gate.php",
    "https://c2.example.net:8443/beacon",
    "Contact http://malware.test/x now",
])
def test_urls_lose_their_scheme_and_dots(raw):
    out = defang_text(raw)
    assert "http://" not in out and "https://" not in out, out
    assert "hxxp" in out
    # A BARE dot between word characters is what linkifies; `[.]` contains a
    # literal '.', so `"." not in out` would be trivially false on correct
    # output — that was the first version of this assertion.
    assert not re.search(r"\w\.\w", out), out


def test_bare_ipv4_is_defanged():
    assert defang_text("beacon to 203.0.113.42 hourly") == "beacon to 203[.]0[.]113[.]42 hourly"


def test_ordinary_prose_is_left_alone():
    """Over-defanging makes the channel look broken and trains people to ignore it.

    `.py` and `.sh` are real ccTLDs, so a general hostname pattern would mangle
    these — which is why defang_text covers schemes and IPv4 only.
    """
    for s in ("run-pipeline.py failed", "see daily-digest.sh", "Keep each bullet to 1-2 sentences."):
        assert defang_text(s) == s, s


def test_defang_is_idempotent():
    once = defang_text("http://evil.example.com")
    assert defang_text(once) == once


def test_empty_input_is_safe():
    assert defang_text("") == ""
    assert defang_ioc("", "domain-name") == ""


# ---------------------------------------------------------------------------
# Typed defanging, for values known to be indicators
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,ioc_type", [
    ("evil.example.com", "domain-name"),
    ("203.0.113.42", "ipv4-addr"),
    ("bad.example.org", "hostname"),
])
def test_typed_indicators_are_fully_defanged(value, ioc_type):
    """The digest knows the type from the DB row, so no guessing is needed."""
    out = defang_ioc(value, ioc_type)
    assert "[.]" in out
    assert not re.search(r"\w\.\w", out), out


def test_a_hash_is_not_mangled_into_nonsense():
    """Not every IOC is a network indicator."""
    sha = "a" * 64
    assert defang_ioc(sha, "file:hashes.SHA-256") == sha


# ---------------------------------------------------------------------------
# The choke point
# ---------------------------------------------------------------------------

def test_send_alert_defangs_before_sending(monkeypatch):
    """Applied in send_alert so no caller can forget."""
    ns = load()
    sent = {}

    class _Resp:
        status_code = 200

    def fake_post(url, data=None, headers=None, timeout=None):
        sent["url"], sent["data"], sent["headers"] = url, data, headers
        return _Resp()

    ns["requests"].post = fake_post
    ok = ns["send_alert"]("C2 at http://evil.example.com",
                          "beacon 203.0.113.42 -> http://evil.example.com/gate")

    assert ok is True
    body = sent["data"].decode()
    assert "http://" not in body and "203.0.113.42" not in body, body
    assert "hxxp" in body and "203[.]0[.]113[.]42" in body
    assert "http://" not in sent["headers"]["Title"]


def test_the_click_url_stays_tappable(monkeypatch):
    """The dashboard link is operator-supplied and is the one link we WANT live."""
    ns = load()

    class _Resp:
        status_code = 200

    captured = {}
    ns["requests"].post = lambda url, data=None, headers=None, timeout=None: (
        captured.update(headers=headers) or _Resp())
    ns["send_alert"]("t", "m", click="https://lamware.example.com/analyses/1")

    assert captured["headers"]["Click"] == "https://lamware.example.com/analyses/1"


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def test_a_token_becomes_a_bearer_header():
    ns = load(token="tk_secret")

    class _Resp:
        status_code = 200

    captured = {}
    ns["requests"].post = lambda url, data=None, headers=None, timeout=None: (
        captured.update(headers=headers) or _Resp())
    ns["send_alert"]("t", "m")

    assert captured["headers"]["Authorization"] == "Bearer tk_secret"


def test_no_token_sends_no_authorization_header():
    """Positive control: the header is conditional, not always present."""
    ns = load(token="")

    class _Resp:
        status_code = 200

    captured = {}
    ns["requests"].post = lambda url, data=None, headers=None, timeout=None: (
        captured.update(headers=headers) or _Resp())
    ns["send_alert"]("t", "m")

    assert "Authorization" not in captured["headers"]


def test_the_token_default_exists_so_the_template_renders_without_vault():
    defaults = (NTFY / "defaults" / "main.yml").read_text(encoding="utf-8")
    assert "ntfy_token:" in defaults


# ---------------------------------------------------------------------------
# The digest defangs before the MODEL sees the value
# ---------------------------------------------------------------------------

def _shared_ioc_context() -> str:
    """The block that builds the shared-IOC line of the LLM context.

    Located by the literal the block emits, not by a positional split on
    "shared_iocs" — that name appears several times and the index picked the
    wrong segment, failing against correct code.
    """
    marker = 'Shared IOCs (today\'s samples matching previous)'
    assert marker in DIGEST, "digest no longer emits the shared-IOC line"
    head = DIGEST.split(marker)[0]
    return head[head.rindex('if stats["shared_iocs"]'):]


def test_the_context_locator_works():
    """Guards the guard below."""
    ctx = _shared_ioc_context()
    assert "ioc['value']" in ctx and "context_parts" in ctx
    assert "top_techniques" not in ctx, "locator ran past the block"


def test_the_digest_defangs_iocs_into_the_prompt_context():
    """send_alert's backstop is not enough on its own.

    The prompt asks the model to name IOCs. A fanged value in the context comes
    back fanged in the generated highlights, and only then hits the backstop —
    so the value must be defanged before it is ever shown to the model.
    """
    ctx = _shared_ioc_context()
    assert "defang_ioc(" in ctx, "raw ioc['value'] still reaches the LLM context"
    assert "from ntfy_notify import defang_ioc" in DIGEST


def test_no_raw_ioc_value_interpolation_remains():
    """Drift guard: any new f-string putting a bare value into the digest fails."""
    bad = [ln.strip() for ln in DIGEST.splitlines()
           if "ioc['value']" in ln and "defang_ioc" not in ln]
    assert not bad, f"undefanged IOC interpolation: {bad}"
