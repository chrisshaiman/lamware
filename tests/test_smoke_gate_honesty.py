# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The smoke gate must not claim readiness it has not proven (#269).

`playwright install chromium` exits 0 when the host is missing the browser's shared
libraries — it prints a banner and carries on. So `make smoke-setup` announced
"Smoke gate ready" in a state where the browser could never launch, and the `make smoke`
failure that followed was indistinguishable from "the deploy broke the site". It also
fired the ntfy alert, which then cried wolf about a site that was fine.

That mattered because the gate is the last step of `make deploy`: it is the signal the
deploy is good. A control node that cannot run it produces the same red as a broken
deployment.

These are source assertions rather than behavioural ones because the behaviour needs a
real browser and a real host. What they defend is the ORDER: proof before the claim.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text()
VERIFIER = ROOT / "tests" / "smoke" / "verify_browser.py"


def _target(name: str) -> str:
    """Executable body of one Makefile target — recipe lines only, comments stripped.

    Comments must go before any ordering assertion. These targets carry prose explaining
    the #269 failure, and that prose necessarily quotes the very strings under test
    ("Smoke gate ready", "ntfy"). Searching the raw text found the comment rather than
    the command and reported the order backwards on code that was correct.
    """
    body = MAKEFILE.split(f"\n{name}:", 1)[1]
    body = re.split(r"\n(?=[A-Za-z0-9_.-]+:)", body)[0]
    return "\n".join(line for line in body.splitlines()
                     if not line.strip().lstrip("@").startswith("#"))


def test_verifier_exists_and_actually_launches_a_browser():
    """The check has to start a browser. Anything less is what we already had."""
    assert VERIFIER.exists(), "tests/smoke/verify_browser.py is the readiness proof"
    src = VERIFIER.read_text()
    assert "chromium.launch" in src, (
        "the verifier must LAUNCH a browser — checking that the binary exists is the "
        "same mistake, since a downloadable browser can still be unrunnable")
    assert "sys.exit" in src or "return 1" in src, "it must fail nonzero"


def test_smoke_setup_proves_readiness_before_announcing_it():
    body = _target("smoke-setup")
    assert "smoke-verify" in body, (
        "smoke-setup must run smoke-verify — without it the target reports success "
        "in a state where the browser cannot launch (#269)")
    verify_at = body.index("smoke-verify")
    ready_at = body.index("Smoke gate ready")
    assert verify_at < ready_at, (
        "the readiness claim must come AFTER the proof, not before it")


def test_smoke_checks_the_control_node_before_blaming_the_site():
    """A workstation missing apt packages must not fire the site-down alert."""
    body = _target("smoke")
    assert "smoke-verify" in body, (
        "make smoke must verify the control node first, so 'my machine cannot run the "
        "gate' does not surface as 'the deploy broke the site'")
    verify_at = body.index("smoke-verify")
    # The ntfy alert lives in the pytest failure path; it must be unreachable when the
    # control node is the problem.
    if "ntfy" in body:
        assert verify_at < body.index("ntfy"), (
            "the control-node check must run before the alert that blames the site")


def test_the_verifier_names_the_fix():
    """A failure the operator cannot act on just moves the confusion."""
    src = VERIFIER.read_text()
    assert "libnss3" in src and "install-deps" in src, (
        "the failure message should carry the apt command — it is the whole remedy")
    assert "CONTROL NODE" in src, (
        "the message must say which side is broken; that ambiguity is the bug")
