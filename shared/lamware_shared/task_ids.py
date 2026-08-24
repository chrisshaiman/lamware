# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""One rule for whether a task ID may be joined onto a path.

`task_id` is a `str(max_length=100)` database column with no character
constraint, and two places interpolate it straight into a filesystem path:
`DELETE /api/analyses/{id}` builds `reports_dir / task_id` and then unlinks the
directory's contents, and `cape_payloads.payload_dirs` builds
`CAPE_STORAGE / str(task_id)`. The delete path is the one with teeth — an empty
value resolves to the reports ROOT, whose top-level contents the loop then
removes one by one.

Not `task_id.isdigit()`, which is the obvious guard and would be wrong here.
Measured against the 998 rows on the sandbox host: exactly ONE is digits-only.
The other 997 are run identifiers like `eval-Latrodectus-d22c9656`,
`verify-e3f78fa-warmcookie` and `smoke-eicar-20260802-182929`, 7 to 28
characters. A digits-only guard would refuse to delete the report files of 997
of 998 analyses, and quietly — the endpoint's file removal is best-effort.

What the data does support is a single safe path segment. All 998 match, none
contains `/` or `..`.
"""
import re

#: A single safe path segment. The first character must be alphanumeric, which
#: is what excludes the empty string, `.`, `..`, and a leading `-`.
#:
#: `\Z`, not `$`: Python's `$` also matches immediately BEFORE a trailing
#: newline, so `"1022\n"` satisfied the pattern and reached the path join. Found
#: by the test rather than by reading the regex.
_TASK_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,99}\Z")


def is_safe_task_id(task_id: object) -> bool:
    """True if `task_id` may be joined onto a path as one directory name."""
    return isinstance(task_id, str) and bool(_TASK_ID_RE.match(task_id))


def require_safe_task_id(task_id: object) -> str:
    """Return `task_id`, or raise ValueError. Call before any path join."""
    if not is_safe_task_id(task_id):
        raise ValueError(
            f"unsafe task_id {task_id!r}: must be 1-100 characters of "
            f"[A-Za-z0-9._-] beginning with a letter or digit"
        )
    return task_id  # type: ignore[return-value]
