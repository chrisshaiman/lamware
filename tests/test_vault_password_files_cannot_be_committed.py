# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A vault password file must not be committable.

Both supported locations are OUTSIDE the repo — `/dev/shm/lamware-vault-<uid>`
for a boot-scoped session and `~/.vault_pass` for the permanent form — so these
patterns should never match anything in a healthy tree.

They exist because `VAULT_PASS_FILE` is overridable and conventions drift. A
plaintext password file is one `git add -A` from a public repo, and the
pre-commit secret scanner does not reliably flag a file whose entire content is a
single unlabelled word: there is no key name, no assignment, no recognisable
prefix for it to match. `.gitignore` is the control that does not depend on
pattern recognition.

Asserted via `git check-ignore`, which consults the real ignore rules rather than
a text search of `.gitignore` — an entry can be present and still be overridden
by a later negation, and grepping the file would not notice.
"""
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

WOULD_BE_A_SECRET = [
    ".vault_pass", ".vault-pass", ".vault_password", ".vault-password",
    "vault_pass", "vault-pass", "my.vaultpass",
    "ansible/.vault_pass", "tests/smoke/.vault_pass", "docs/vault_pass",
]

MUST_STAY_TRACKABLE = [
    "Makefile",
    "ansible/vars/secrets.yml.example",
    "docs/RUNBOOK_VAULT_SESSION.md",
    "scripts/pr_evidence_check.py",
]


def _ignored(path: str) -> bool:
    """Would the ignore RULES match this path?

    `--no-index` is load-bearing. Without it `git check-ignore` never reports a
    TRACKED file as ignored, so every "must stay trackable" assertion below
    passed trivially and could not fail: appending `docs/` to .gitignore left
    the tracked runbook reported as not-ignored. Verified — with `--no-index`
    that same mutation is caught.

    This is the vacuous-guard shape again, and the mutation harness is what
    exposed it: three mutations "survived", and the survival was the finding.
    """
    return subprocess.run(["git", "check-ignore", "--no-index", "-q", path],
                          cwd=ROOT, capture_output=True).returncode == 0


@pytest.mark.parametrize("path", WOULD_BE_A_SECRET)
def test_a_vault_password_file_is_ignored(path):
    assert _ignored(path), (
        f"{path} would be committable — a plaintext vault password is one "
        "`git add -A` from a public repo")


@pytest.mark.parametrize("path", MUST_STAY_TRACKABLE)
def test_the_patterns_do_not_swallow_real_files(path):
    """An over-broad pattern that hides the Makefile or the runbook would be a
    worse bug than the one being prevented, and would be found late."""
    assert not _ignored(path), f"{path} is ignored and must not be"


def test_the_encrypted_vault_itself_stays_untracked():
    """Deliberate in this repo: even the encrypted form is local-only, with an
    .example committed. Not a general Ansible convention, so it is pinned here
    rather than left to be 'corrected' by someone who knows the usual practice."""
    assert _ignored("ansible/vars/secrets.yml")
    assert not _ignored("ansible/vars/secrets.yml.example")


def test_the_smoke_artifacts_stay_untracked():
    """Failure captures include the HTML of an AUTHENTICATED page, which can carry
    session material. They are debugging output, not evidence to keep."""
    assert _ignored("tests/smoke/.artifacts/anything.html")
    assert _ignored("tests/smoke/.artifacts/anything.png")


def test_nothing_secret_shaped_is_untracked_in_the_tree_now():
    """The patterns above are prevention. This is detection: if something already
    sits in the working tree awaiting a careless `git add`, fail now."""
    out = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT, capture_output=True, text=True).stdout
    # Matched on the BASENAME against exact names, not as a substring of the path.
    # A substring check flagged this very file, whose name contains
    # "vault_password" — the detector's own name tripping it, which is the
    # false-positive shape that gets a check disabled rather than fixed.
    secret_names = {
        ".vault_pass", ".vault-pass", ".vault_password", ".vault-password",
        "vault_pass", "vault-pass", "secrets.txt", "id_rsa",
    }
    suspicious = []
    for ln in out.splitlines():
        name = Path(ln[3:].strip().strip('"')).name
        if name in secret_names or name.endswith((".vaultpass", ".pem")):
            suspicious.append(ln)
    assert not suspicious, f"secret-shaped files present and not ignored: {suspicious}"
