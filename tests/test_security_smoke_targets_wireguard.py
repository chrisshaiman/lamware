# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The security smoke tests must probe where the app is, not where it used to be.

#604 removed the public TLS listener. The smoke suite still aimed four of its
seven checks at `https://lamware.shaiman.net`, which resolves to the public
address, so every one returned `000` and the post-deploy gate failed on a host
that was **more** secure than the one the assertions were written for:

    FAIL: API health endpoint returned 000 (expected 200)
    FAIL: Unauthenticated /api/analyses returned 000 (expected 401/403)
    FAIL: /docs returned 000 publicly, expected 403
    FAIL: Could not read TLS certificate

The dangerous one was quieter. Nuclei was pointed at the same dead address, and
a scanner that reaches nothing reports zero findings — a PASS indistinguishable
from a clean scan. That is the "enforcement that stops enforcing" shape: the
suite would have kept reporting 'no high/critical findings' forever while
scanning an address that serves nothing.

So the probes move to WireGuard, and the public side gets a POSITIVE assertion
that TLS is refused, because every other check now passes whether or not the
public listener comes back.
"""
from pathlib import Path

import pytest
import yaml
from jinja2 import Environment

ROOT = Path(__file__).resolve().parents[1]
TPL = (ROOT / "ansible" / "roles" / "security-test" / "templates"
       / "security-smoke-test.sh.j2").read_text(encoding="utf-8")
DEFAULTS = yaml.safe_load(
    (ROOT / "ansible" / "roles" / "security-test" / "defaults"
     / "main.yml").read_text(encoding="utf-8"))

PUBLIC_IP = "203.0.113.9"
WG_IP = "10.200.0.1"


def _ipaddr(value, _what="address"):
    return str(value).split("/")[0]


def _bool(value):
    """Ansible's `| bool`. Present because #349 was a Jinja truthiness bug in
    exactly this template family, so the filter is load-bearing here."""
    return str(value).strip().lower() in ("true", "yes", "on", "1")


def _render() -> str:
    env = Environment()
    env.filters["ansible.utils.ipaddr"] = _ipaddr
    env.filters["bool"] = _bool
    return env.from_string(TPL).render(
        public_ip=PUBLIC_IP,
        wireguard_address="10.200.0.1/24",
        ntfy_url="https://ntfy.example", ntfy_topic="lamware", ntfy_token="tok",
        security_test_domain="lamware.example",
        security_test_api_url="https://lamware.example",
        security_test_wg_url=f"https://{WG_IP}",
        security_test_wg_address=WG_IP,
        security_test_keycloak_url="http://127.0.0.1:8080/auth",
        security_test_install_dir="/opt/security-test",
        keycloak_port=8080,
    )


RENDERED = _render()


def test_the_template_renders_as_valid_shell():
    import subprocess
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
        f.write(RENDERED)
        path = f.name
    r = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def _probe_line(fragment: str) -> str:
    for line in RENDERED.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if fragment in stripped:
            return stripped
    raise AssertionError(f"no probe line containing {fragment!r}")


# --- the app probes must reach the app --------------------------------------

@pytest.mark.parametrize("path", ["/health", "/api/analyses"])
def test_app_probes_target_wireguard_not_the_public_domain(path):
    line = _probe_line(f'"$WG_URL{path}"')
    assert "$API_URL" not in line, (
        f"{path} is probed via $API_URL, which no longer serves TLS — this "
        f"returns 000 and fails a correctly-hardened host")


def test_nuclei_scans_the_wireguard_address():
    """The false-pass one. A scanner aimed at a dead address finds nothing and
    reports success, which looks exactly like a clean scan."""
    line = _probe_line('"$NUCLEI" -u')
    assert '-u "$WG_URL"' in line, (
        "nuclei still scans $API_URL — after #604 nothing listens there, so it "
        "would report 'no findings' forever while scanning nothing")


def test_tls_certificate_is_read_from_the_wireguard_listener():
    line = _probe_line("s_client")
    assert f"-connect {WG_IP}:443" in line, \
        "cert is read from the public address, where TLS is no longer served"
    assert '-servername "$DOMAIN"' in line, \
        "SNI must stay the real domain — that is what the cert is issued for"


# --- the public side is asserted, not assumed -------------------------------

def test_public_tls_refusal_is_positively_asserted():
    """Without this, every other check passes whether or not the public
    listener returns, so #604 could regress in silence."""
    assert 'PUB_TLS=' in RENDERED, "no probe of the public TLS address"
    assert 'fail "public TLS listener is back' in RENDERED, \
        "a returning public TLS listener does not fail the suite"


def test_acme_reachability_is_asserted_so_renewal_cannot_break_silently():
    """certbot renews by webroot/HTTP-01. Losing the public port-80 listener
    breaks renewal and shows no symptom for ~90 days."""
    assert 'PUB_ACME=' in RENDERED
    assert 'fail "public port 80 is not answering ACME' in RENDERED, \
        "losing the ACME listener would not fail the suite"


def test_docs_accepts_refused_as_well_as_denied():
    """000 (no listener) is strictly stronger than 403 (denied). Demanding 403
    fails the safer host — the exact bug this file exists for."""
    block = RENDERED[RENDERED.index("DOCS_PUBLIC="):RENDERED.index("Test 5")]
    assert '"$DOCS_PUBLIC" = "000"' in block, \
        "a refused public probe is not accepted, so no-listener reads as failure"
    assert '"$DOCS_PUBLIC" = "200"' in block, \
        "the real invariant — /docs must never be 200 publicly — is not checked"


# --- the counter stayed honest ----------------------------------------------

def test_the_step_labels_are_consecutive_and_match_the_total():
    import re
    labels = re.findall(r"\[(\d+)/(\d+)\]", RENDERED)
    assert labels, "no step labels found"
    totals = {t for _, t in labels}
    assert len(totals) == 1, f"mixed totals in step labels: {totals}"
    total = int(totals.pop())
    assert [int(n) for n, _ in labels] == list(range(1, total + 1)), \
        f"step numbers are not 1..{total}: {[n for n, _ in labels]}"


def test_wg_url_default_points_at_the_wireguard_address():
    assert "wireguard_address" in DEFAULTS["security_test_wg_url"], \
        "security_test_wg_url no longer derives from the WireGuard address"


# --- the probe must yield a code, not a concatenation -----------------------

def test_public_probes_yield_exactly_one_status_code():
    """Executed, not inspected. The first live run of test 7 printed `000000`:
    curl's -w prints 000 on a refused connection AND exits non-zero, so a
    `|| echo 000` fallback appends a second one. The result matched neither
    branch and reported a returning public TLS listener on a host where TLS was
    correctly refused — a false alarm from the guard itself.

    203.0.113.0/24 is TEST-NET-3 (RFC 5737), reserved and unroutable, so this
    exercises the refused path without touching anything real.
    """
    import re
    import subprocess

    # Contiguous block, not filtered lines: the PUB_ACME probe is split across
    # two lines with a backslash continuation, and picking out only the lines
    # that START with PUB_ dropped it, producing a snippet bash could not parse.
    start = RENDERED.index("PUB_TLS=$(")
    end = RENDERED.index("PUB_ACME=${PUB_ACME:-000}") + len("PUB_ACME=${PUB_ACME:-000}")
    block = RENDERED[start:end]
    assert block.count("curl") == 2, f"expected two probes, got: {block!r}"

    script = block + '\necho "$PUB_TLS|$PUB_ACME"\n'
    script = script.replace(PUBLIC_IP, "203.0.113.1").replace("--max-time 5", "--max-time 2")
    script = 'DOMAIN=lamware.example\n' + script

    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    tls, acme = r.stdout.strip().split("|")
    assert re.fullmatch(r"\d{3}", tls), f"PUB_TLS is not one status code: {tls!r}"
    assert re.fullmatch(r"\d{3}", acme), f"PUB_ACME is not one status code: {acme!r}"
