# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Every vault-touching target must route through VAULT_ARGS.

A `make deploy && make merge-check` cycle prompted for the vault password FOUR
times:

    deploy       -> site.yml                        --ask-vault-pass
    deploy       -> smoke -> ansible-vault view     (no vault flag at all)
    deploy       -> security-test.yml               --ask-vault-pass
    merge-check  -> security-test.yml               --ask-vault-pass

`VAULT_ARGS` was added in #231 for `make validate`, and it already falls back to
`--ask-vault-pass` when no password file exists. The targets above predate it and
were never migrated, so they hardcoded the prompt and ignored the variable —
which meant creating `~/.vault_pass` fixed none of them, and the documented
escape hatch (`make validate VAULT_ARGS=...`) silently did not apply to a deploy.

With everything routed through VAULT_ARGS: 4 prompts with no password file
(unchanged), 0 with one.

The assertion is on RECIPE lines only. `--ask-vault-pass` legitimately appears in
this Makefile's comments and in an error message that names the flag, so matching
the string anywhere would fail for the wrong reason.
"""
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MAKEFILE = (ROOT / "Makefile").read_text()

# A recipe line is tab-indented. Comments inside recipes start with @# or #.
RECIPE = [ln for ln in MAKEFILE.splitlines()
          if ln.startswith("\t") and not ln.lstrip("\t@").startswith("#")]


def test_there_are_recipe_lines_to_check():
    """Guards the guard: if tab detection breaks, everything below is vacuous."""
    assert len(RECIPE) > 50, f"only {len(RECIPE)} recipe lines found"


def _passes_flag_to_a_command(line: str) -> bool:
    """True when the line supplies the flag as an ARGUMENT, not as printed text.

    `make validate` echoes an error naming the flag ("ansible-playbook would block
    on --ask-vault-pass indefinitely"), which is documentation and must not count.
    Matching the bare string flagged that line and cost a real assertion its
    meaning, so the check looks at how the flag is used.
    """
    if "--ask-vault-pass" not in line:
        return False
    return not re.search(r'\b(echo|printf)\b', line)


def test_no_recipe_hardcodes_the_vault_prompt():
    offenders = [ln.strip() for ln in RECIPE if _passes_flag_to_a_command(ln)]
    assert not offenders, (
        "these recipe lines prompt for the vault password directly instead of "
        f"using $(VAULT_ARGS), so a password file cannot suppress them: {offenders}")


def test_the_fallback_still_prompts_when_there_is_no_password_file():
    """The point is to make ONE password serve the cycle, not to require a file.
    Without one, VAULT_ARGS must still expand to a prompt rather than to nothing —
    expanding to empty would make ansible fail to decrypt instead of asking."""
    defn = next(ln for ln in MAKEFILE.splitlines() if ln.startswith("VAULT_ARGS"))
    assert "--ask-vault-pass" in defn, defn
    assert "--vault-password-file" in defn, defn


@pytest.mark.parametrize("cmd", ["ansible-playbook", "ansible-vault"])
def test_every_vault_touching_command_passes_vault_args(cmd):
    """Any invocation that reads the encrypted vars needs the flag. `--syntax-check`
    counts: it loads vars_files, which is why #231 existed."""
    using = [ln.strip() for ln in RECIPE if cmd in ln]
    assert using, f"no {cmd} invocations found — has the Makefile been restructured?"
    # The flag may sit on a continuation line, so check each invocation's block.
    text = "\n".join(RECIPE)
    for inv in using:
        idx = text.index(inv)
        block = text[idx: idx + 400]
        # Either the shared variable, or an explicit password file. The second is
        # correct in `vault-session`, which verifies the password it has just
        # written and must not consult VAULT_ARGS (that would read the OLD
        # source). The property under test is "supplies a password source
        # non-interactively", not "mentions one particular variable".
        assert "VAULT_ARGS" in block or "--vault-password-file" in block, (
            f"{cmd} invocation with no vault password source: {inv}")


def test_the_password_file_path_is_outside_the_repo():
    """It must not be committable. $(HOME) keeps it out of the working tree
    entirely, which is stronger than a .gitignore entry."""
    defn = next(ln for ln in MAKEFILE.splitlines() if ln.startswith("VAULT_PASS_FILE"))
    assert "$(HOME)" in defn, defn
    assert "$(ANSIBLE_DIR)" not in defn and "./" not in defn
