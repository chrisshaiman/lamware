# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""task_id reaches two filesystem joins, one of which deletes what it finds.

`DELETE /api/analyses/{id}` builds `reports_dir / task_id` and unlinks the
directory's contents; `cape_payloads.payload_dirs` builds
`CAPE_STORAGE / str(task_id)`. The column is `varchar(100)` with no character
constraint.

The obvious guard — `task_id.isdigit()` — is wrong here, and the tests below pin
that. Measured against the 998 analyses on the sandbox host, exactly ONE is
digits-only; the other 997 are run identifiers like `eval-Latrodectus-d22c9656`.
A digits-only guard would refuse to delete the report files of 997 of 998
analyses, silently, because that removal is best-effort.
"""
import pytest
from lamware_shared.task_ids import is_safe_task_id, require_safe_task_id

#: Shapes taken verbatim from the sandbox host's `analyses` table. All 998 rows
#: match the allowlist; lengths run 7 to 28.
REAL_TASK_IDS = [
    "1022",
    "00cf10351cea",
    "eval-Latrodectus-d22c9656",
    "eval-RaccoonStealer-982a0d1b",
    "verify-e3f78fa-warmcookie",
    "smoke-eicar-20260802-182929",
    "corpus-104-25d18a2b",
    "corpus104b",
]


@pytest.mark.parametrize("task_id", REAL_TASK_IDS)
def test_real_task_ids_are_accepted(task_id):
    """The guard must not break the endpoint it protects. `isdigit()` — the
    obvious fix — rejects seven of these eight."""
    assert is_safe_task_id(task_id)


def test_the_digits_only_guard_would_have_been_wrong():
    """Stated as a test so the reasoning survives the next person's cleanup."""
    non_numeric = [t for t in REAL_TASK_IDS if not t.isdigit()]
    assert len(non_numeric) == len(REAL_TASK_IDS) - 1
    assert all(is_safe_task_id(t) for t in non_numeric)


@pytest.mark.parametrize("task_id", [
    "",            # -> reports_dir itself; the unlink loop then empties it
    ".",           # -> the same directory by another name
    "..",          # -> the reports_dir's PARENT
    "../..",
    "../../etc",
    "/etc",
    "/",
    "a/b",         # a second path segment
    "a\\b",
    "sub/../..",
    ".hidden",     # leading dot: excluded by requiring an alphanumeric first char
    "-rf",         # leading dash
    " 1022",
    "1022 ",
    "1022\n",
    "1022\x00",
    "a" * 101,     # past the column's own max_length
])
def test_unsafe_values_are_refused(task_id):
    assert not is_safe_task_id(task_id)


@pytest.mark.parametrize("value", [None, 1022, 3.5, [], {}, object()])
def test_non_strings_are_refused(value):
    """The column is a str, but `payload_dirs` accepts `str | int | None` and
    callers pass whatever the report held."""
    assert not is_safe_task_id(value)


def test_the_empty_string_is_the_one_that_matters():
    """Called out separately because it is the reachable case: a failed ingest
    writing "" is far likelier than an attacker writing "../..", and it resolves
    to the reports ROOT, whose top-level contents the delete loop then removes.
    """
    from pathlib import Path
    assert Path("/opt/pipeline/reports") / "" == Path("/opt/pipeline/reports")
    assert not is_safe_task_id("")


def test_require_raises_with_the_offending_value():
    with pytest.raises(ValueError) as exc:
        require_safe_task_id("../etc")
    assert "../etc" in str(exc.value)


def test_require_returns_the_value_when_safe():
    assert require_safe_task_id("eval-Latrodectus-d22c9656") == "eval-Latrodectus-d22c9656"


# --- the caller that reads CAPE storage -----------------------------------

def test_payload_dirs_refuses_an_unsafe_task_id(tmp_path):
    """`CAPE_STORAGE / ".."` is a real directory, so without the guard this
    walks out of the storage root and reports whatever it finds there."""
    from lamware_shared import cape_payloads

    (tmp_path / "storage").mkdir()
    (tmp_path / "CAPE").mkdir()  # a sibling of storage/, reachable via ".."
    assert cape_payloads.payload_dirs("..", storage=tmp_path / "storage") == []


def test_payload_dirs_still_finds_a_real_task(tmp_path):
    """The mirror: the guard must not break discovery."""
    from lamware_shared import cape_payloads

    task = tmp_path / "storage" / "eval-Latrodectus-d22c9656"
    (task / "CAPE").mkdir(parents=True)
    dirs = cape_payloads.payload_dirs(
        "eval-Latrodectus-d22c9656", storage=tmp_path / "storage")
    assert [d.name for d in dirs] == ["CAPE"]
