# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Package staging must not ship the whole working tree file-by-file.

`ansible.builtin.copy` pointed at a directory recurses and checksums EVERY file on both
ends to decide what to transfer, so the cost is file COUNT against SSH latency rather than
bytes. Staging `shared` + `pipeline` that way walked 700 files — and the very next task
(`file: recurse=true`, fixing group traversal) walked them all again.

Of those 700, thirteen are needed to pip install both packages. The rest were
`.hypothesis` fuzzing state, `tests/`, `__pycache__`, `build/` and egg-info. `copy:` has
no exclude option, which is why the fix is a tarball — the same shape the api role already
uses.

__pycache__ is excluded for correctness as much as speed: a stale `.pyc` shadowing
deployed source is a failure this project has already hit.
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TASKS = (ROOT / "ansible" / "roles" / "pipeline" / "tasks" / "main.yml").read_text(encoding="utf-8")

# The staging block, isolated so assertions cannot accidentally be satisfied by an
# unrelated task elsewhere in the role.
_START = "Create package staging directory"
_END = "Ensure staged package source is traversable"
BLOCK = TASKS[TASKS.index(_START):TASKS.index(_END)]


def test_staging_does_not_copy_source_directories_file_by_file():
    """The regression: a `copy:` whose src is one of the package source trees."""
    for src in ("/../shared", "/../pipeline"):
        assert f"src: \"{{{{ playbook_dir }}}}{src}\"" not in BLOCK, (
            f"package staging is copying {src} as a directory again — that walks and "
            "checksums the whole tree, including caches and tests")


def test_staging_uses_an_archive():
    assert "tar czf" in BLOCK, "staging should build one archive, not transfer a tree"
    assert "ansible.builtin.unarchive" in BLOCK, "the archive must be unpacked on the host"


def test_the_expensive_and_dangerous_paths_are_excluded():
    """.hypothesis was 564K of local fuzzing state; __pycache__ can shadow real source."""
    for excl in ("--exclude=__pycache__", "--exclude=.hypothesis", "--exclude=tests",
                 "--exclude=.venv", "--exclude=.pytest_cache", "--exclude=build",
                 "--exclude='*.egg-info'", "--exclude='*.pyc'"):
        assert excl in BLOCK, f"{excl} missing — staging will ship it again"


def test_both_packages_are_still_staged():
    """Excluding too much is the opposite failure: pip install must still work."""
    assert re.search(r"-C \{\{ playbook_dir \}\}/\.\. shared pipeline", BLOCK), (
        "both package roots must be in the archive")


def test_the_archive_is_not_stripped_into_the_wrong_layout():
    """`copy: src=../shared dest=pkg/` produced pkg/shared. The tar must too.

    The api role uses --strip-components=1 because it extracts a single package INTO its
    install dir. Here two packages extract side by side and the prefix is load-bearing:
    the venv installs from pkg/shared and pkg/pipeline by path.
    """
    assert "--strip-components" not in BLOCK, (
        "stripping the leading component would flatten shared/ and pipeline/ into pkg/ "
        "and break the two `pip install` paths below")


def test_ownership_is_still_applied():
    assert "owner: pipeline" in BLOCK and "group: lamware" in BLOCK, (
        "the api venv reads this tree as group lamware; unarchive must set ownership")


def test_stale_staged_source_is_cleared_before_extracting():
    """`unarchive` overwrites but never deletes.

    Without an explicit clear, every file ever staged survives forever regardless of the
    excludes. Observed on the live host before this was added: `.pyc` from 2026-07-01 and
    `.hypothesis` state from 07-21 still present, oldest file 06-22. The tarball would
    have made deploys fast while preserving exactly the caches the excludes exist to
    remove — including bytecode that can shadow deployed source.
    """
    clear_idx = BLOCK.find("Clear previously staged package source")
    extract_idx = BLOCK.find("Extract package source on server")
    assert clear_idx != -1, (
        "nothing clears the staging dir, so excluded files persist from earlier deploys")
    assert clear_idx < extract_idx, "the clear must happen BEFORE the extract"
    assert "state: absent" in BLOCK[clear_idx:extract_idx]
    tail = BLOCK[clear_idx:extract_idx]
    assert "shared" in tail and "pipeline" in tail, (
        "both staged package roots must be cleared, or one keeps its stale tree")
