# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Security-boundary roles must prompt, even when a vault password file exists.

A vault password file makes routine deploys non-interactive. That is a
convenience for `pipeline`, `ghidra`, `api`, `postgres` — roles whose failure
mode is a bad result. It is NOT authorisation to change the security boundary
unattended, where the failure mode is different in kind:

  * #563 — a `TAGS=hardening` deploy left the host unable to reach its own
    guests. It cost a working day to find, because everything reported healthy.
  * `wireguard` is the management VPN. A mistake there is a drive to a console.

So `hardening`, `networking`, `wireguard`, `keycloak`, `kvm` and `all` force
`--ask-vault-pass` regardless of VAULT_ARGS.

WHY THIS IS A MECHANISM AND NOT A POLICY NOTE: an automated caller — a CI job, a
script, an AI agent — has no TTY. `--ask-vault-pass` then fails immediately with

    [ERROR]: EOFError (ctrl-d) on prompt for (default)

verified against this repo's own vault. Typing the password is the proof a human
is present, and it cannot be faked by something that cannot type.

There is deliberately NO override flag. An override is the thing that gets set
once, works, and then lives in a shell profile forever — at which point the
mechanism is back to being a promise.
"""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text()

PROTECTED = ["hardening", "networking", "wireguard", "keycloak", "kvm", "all"]
ROUTINE = ["ghidra", "postgres", "pipeline", "api", "frontend", "interpret"]


def _deploy_recipe(tags: str, pass_file: Path) -> str:
    """What `make deploy` would actually run, with a password file present."""
    out = subprocess.run(
        ["make", "-n", "deploy", f"TAGS={tags}", f"VAULT_PASS_FILE={pass_file}"],
        cwd=ROOT, capture_output=True, text=True, timeout=120)
    return out.stdout


@pytest.fixture(scope="module")
def pass_file(tmp_path_factory):
    p = tmp_path_factory.mktemp("vault") / "pass"
    p.write_text("not-a-real-password")
    return p


@pytest.mark.parametrize("tag", PROTECTED)
def test_a_protected_role_prompts_despite_a_password_file(tag, pass_file):
    """The property, asserted by expanding the real recipe rather than by reading
    the variable — a variable can be right while the recipe uses another one."""
    recipe = _deploy_recipe(f"api,{tag}" if tag != "all" else "all", pass_file)
    site = next((ln for ln in recipe.splitlines() if "site.yml" in ln), None)
    block = recipe[recipe.index("site.yml"):][:400] if site else recipe
    assert "--ask-vault-pass" in block, (
        f"TAGS containing {tag!r} would deploy non-interactively: {block[:200]}")


@pytest.mark.parametrize("tag", ROUTINE)
def test_a_routine_role_stays_non_interactive(tag, pass_file):
    """The convenience has to survive, or the password file is pointless and
    someone will route around the whole thing."""
    recipe = _deploy_recipe(tag, pass_file)
    block = recipe[recipe.index("site.yml"):][:400]
    assert "--vault-password-file" in block, block[:200]
    assert "--ask-vault-pass" not in block, (
        f"{tag} should not require a console: {block[:200]}")


def test_one_protected_tag_protects_the_whole_deploy(pass_file):
    """`--tags a,b` runs both, so a protected tag anywhere in the list must gate
    the run. Checking only the first tag would miss `TAGS=api,hardening`."""
    block = _deploy_recipe("api,frontend,hardening", pass_file)
    block = block[block.index("site.yml"):][:400]
    assert "--ask-vault-pass" in block, block[:200]


def test_the_protected_list_covers_the_documented_categories():
    """Named in the Makefile so a reader sees the rule where the rule lives."""
    defn = next(ln for ln in MAKEFILE.splitlines()
                if ln.startswith("VAULT_CONSOLE_TAGS"))
    for tag in PROTECTED:
        assert re.search(rf"\b{tag}\b", defn), f"{tag} missing from {defn}"


def test_there_is_no_override_flag():
    """An override becomes a shell-profile export, and then this is a promise
    again. If one is ever added, this test should be deleted deliberately rather
    than quietly loosened."""
    gate = MAKEFILE[MAKEFILE.index("VAULT_CONSOLE_TAGS"):]
    gate = gate[:gate.index("deploy:") + 1200]
    for escape in ("FORCE", "SKIP_", "I_AM_", "NO_PROMPT", "YES=", "ALLOW_"):
        assert escape not in gate, f"an override ({escape}) defeats the mechanism"
