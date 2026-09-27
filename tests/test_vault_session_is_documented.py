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
