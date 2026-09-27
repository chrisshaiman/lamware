# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The vault-session procedure must stay documented, and match the Makefile.

The tmpfs password dies on every reboot, so the setup step recurs forever and
will be forgotten by both the human and the agent. Three places carry it and all
three can rot independently:

    make help                    where a human looks
    .claude/CLAUDE.md            where an agent looks, every session
    docs/RUNBOOK_VAULT_SESSION.md  where the reasoning lives

#563 is the precedent for why this matters more than tidiness: that diagnosis was
written up well, and was missed anyway sixteen days later, because nothing
executable enforced it. Prose is not a control — but prose that contradicts the
code is worse than none, because it is trusted.

So these assertions pin the FACTS that would diverge: the target names, and the
protected role list. If VAULT_CONSOLE_TAGS changes, the docs fail until updated.
"""
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text()
CLAUDE_MD = (ROOT / ".claude" / "CLAUDE.md").read_text()
RUNBOOK = (ROOT / "docs" / "RUNBOOK_VAULT_SESSION.md").read_text()

TARGETS = ["vault-session", "vault-session-clear", "vault-session-status"]


def _console_tags() -> list[str]:
    """The protected roles, read from the Makefile — the single source of truth."""
    line = next(ln for ln in MAKEFILE.splitlines()
                if ln.startswith("VAULT_CONSOLE_TAGS"))
    return line.split("=", 1)[1].split()


def test_the_targets_exist():
    """Guards the guard: docs referencing a missing target are worse than no docs."""
    for t in TARGETS:
        assert re.search(rf"^{re.escape(t)}:", MAKEFILE, re.M), f"{t} is not a target"


@pytest.mark.parametrize("doc,name", [(CLAUDE_MD, "CLAUDE.md"), (RUNBOOK, "runbook")])
def test_the_reboot_step_is_documented(doc, name):
    assert "make vault-session" in doc, f"{name} does not name the command"
    assert re.search(r"reboot|restart|boot", doc, re.I), f"{name} omits WHEN to run it"


@pytest.mark.parametrize("doc,name", [(CLAUDE_MD, "CLAUDE.md"), (RUNBOOK, "runbook")])
def test_every_protected_role_is_named_in_the_docs(doc, name):
    """The list that must not silently diverge. An agent reading CLAUDE.md needs to
    know which roles it cannot deploy; a human needs to know which will prompt."""
    missing = [t for t in _console_tags() if not re.search(rf"\b{re.escape(t)}\b", doc)]
    assert not missing, f"{name} does not mention protected role(s): {missing}"


def test_no_doc_references_a_target_that_does_not_exist():
    """A `make vault-session-help` reference survived in a comment for one commit
    before being caught by hand. This catches the next one."""
    for doc, name in [(CLAUDE_MD, "CLAUDE.md"), (RUNBOOK, "runbook"), (MAKEFILE, "Makefile")]:
        for ref in set(re.findall(r"make (vault-session[a-z-]*)", doc)):
            assert re.search(rf"^{re.escape(ref)}:", MAKEFILE, re.M), \
                f"{name} references `make {ref}`, which is not a target"


def test_make_help_advertises_the_session():
    """Discoverable at the point of need, not only in a file nobody opens."""
    # Bounded to the help RECIPE. Slicing to end-of-file matched the
    # vault-session targets themselves, so deleting the help lines changed
    # nothing and the mutation survived.
    start = MAKEFILE.index("help:")
    body = MAKEFILE[start:]
    end = next((i for i, ln in enumerate(body.splitlines()[1:], 1)
                if ln and not ln.startswith(("\t", " ", "#"))), None)
    help_block = "\n".join(body.splitlines()[:end])
    assert "vault-session" in help_block, "make help does not advertise the session"
    assert re.search(r"reboot|restart|boot", help_block, re.I), \
        "help does not say when to run it"


def test_the_docs_do_not_promise_an_override():
    """There is deliberately no escape hatch. Documenting one that does not exist
    would send someone hunting for it; documenting one that does would defeat the
    mechanism."""
    for doc, name in [(CLAUDE_MD, "CLAUDE.md"), (RUNBOOK, "runbook")]:
        for escape in ("FORCE=", "SKIP_", "ALLOW_", "--force"):
            assert escape not in doc, f"{name} advertises an override: {escape}"


def test_the_runbook_states_the_tmpfs_property():
    """The reason this is acceptable at all: RAM-only, gone on reboot. If someone
    later moves the file to a real filesystem, this assertion should stop them."""
    assert "/dev/shm" in RUNBOOK
    assert re.search(r"tmpfs|RAM", RUNBOOK, re.I)
    assert "/dev/shm" in MAKEFILE, "the Makefile no longer uses tmpfs"


def test_the_vault_session_recipe_actually_runs():
    """EXECUTED, not expanded. `make -n` prints a recipe without running it, so
    every structural test here passed while the target was broken:

        $ make vault-session
        Vault password (not echoed): /bin/sh: 3: read: Illegal option -s
            REFUSED: empty password.

    `read -s` is a bashism and make runs recipes under /bin/sh, which is dash on
    this platform. Worse than failing: the failed read left PW empty, so the empty
    guard fired and the error read as a bad password rather than a broken recipe.

    Running with empty stdin cannot supply a password, so this asserts on the
    SHELL accepting the syntax — which is the part that was wrong — and on the
    empty-input guard still firing.
    """
    out = subprocess.run(["make", "vault-session"], cwd=ROOT, stdin=subprocess.DEVNULL,
                         capture_output=True, text=True, timeout=120)
    combined = out.stdout + out.stderr
    for bad in ("Illegal option", "not found", "Syntax error", "unexpected"):
        assert bad not in combined, f"recipe is not valid in this shell: {combined[:300]}"
    assert "REFUSED: empty password" in combined, combined[:300]
    assert out.returncode != 0, "empty input must fail, not silently store nothing"


def _recipe_blocks() -> list[str]:
    """Recipe lines, with backslash continuations JOINED.

    A block has to be the unit of analysis: `bash -c '...'` opens on one line and
    the bash-only syntax appears on a continuation, so checking lines in isolation
    reported my own correctly-wrapped `read -rs` as an offender.
    """
    blocks, current = [], ""
    for ln in MAKEFILE.splitlines():
        if not ln.startswith("\t"):
            if current:
                blocks.append(current)
                current = ""
            continue
        body = ln.lstrip("\t")
        if body.lstrip("@").startswith("#"):
            continue
        current += body
        if body.rstrip().endswith("\\"):
            current = current.rstrip()[:-1] + " "
        else:
            blocks.append(current)
            current = ""
    if current:
        blocks.append(current)
    return blocks


# `[[:space:]]` is a POSIX character class in awk and sed, not a bash test.
# Requiring a space or dollar after `[[` distinguishes them; without that the
# check flagged two legitimate awk one-liners.
BASHISMS = (
    (re.compile(r"\bread\b[^|;&]*\s-\w*s"), "read -s"),
    (re.compile(r"\[\[[\s$]"), "[[ ]] test"),
    (re.compile(r"\$'"), "$'...' quoting"),
    (re.compile(r"<<<"), "here-string"),
)


def test_no_recipe_uses_a_bash_only_builtin_under_sh():
    """The class, not the instance. Make runs recipes under /bin/sh — dash on this
    platform — and these fail at RUN time, which no structural test observes.

    This found a pre-existing instance in `packer-setup`, which had the same
    `read -s` defect as vault-session and would have failed identically. Both are
    fixed by wrapping the recipe in an explicit `bash -c`.
    """
    offenders = []
    for block in _recipe_blocks():
        if "bash -c" in block or block.lstrip("@").startswith("bash "):
            continue                       # explicitly bash: allowed
        for pattern, label in BASHISMS:
            if pattern.search(block):
                offenders.append(f"{label}: {block.strip()[:90]}")
    assert not offenders, (
        "bash-only syntax in a /bin/sh recipe — it fails only when the target is "
        "actually run: " + "; ".join(offenders))


def _session_file() -> Path:
    """The path the Makefile would write, read from the Makefile."""
    import os
    line = next(ln for ln in MAKEFILE.splitlines()
                if ln.startswith("VAULT_SESSION_FILE"))
    raw = line.split("=", 1)[1].strip()
    return Path(raw.replace("$(shell id -u)", str(os.getuid())))


def test_a_wrong_password_is_refused_and_stores_nothing():
    """The feature's most valuable property, and it was unguarded — a mutation that
    stored the password WITHOUT verifying it survived the whole suite.

    Testable without the real password: a deliberately wrong one must fail the
    decrypt check. Without this step the first symptom of a typo is a failed deploy
    ten minutes later, with the password looking configured the whole time — this
    repo's recurring shape, not a hypothetical.

    Skips if a real session is active rather than clobbering it.
    """
    target = _session_file()
    if target.exists():
        pytest.skip(f"a real vault session is active at {target}; not disturbing it")

    out = subprocess.run(["make", "vault-session"], cwd=ROOT,
                         input="definitely-not-the-vault-password\n",
                         capture_output=True, text=True, timeout=180)
    combined = out.stdout + out.stderr
    assert out.returncode != 0, f"a wrong password was accepted: {combined[:300]}"
    assert "does not decrypt" in combined, combined[:300]
    assert not target.exists(), (
        f"{target} was left on disk after a failed verification — a wrong password "
        "must store nothing, or the next deploy fails with a file that looks valid")
