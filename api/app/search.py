# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Substring search over user text, with LIKE's wildcards taken literally (#730).

`ilike(f"%{q}%")` treats `%` and `_` in the user's text as wildcards, so a search
for `a_b` also matched `axb`, and `%` alone matched everything. That is match
semantics, not injection (the value is bound), but a search box should find
what was typed.
"""

#: The escape character passed to ilike(..., escape=ESCAPE). Backslash, escaped
#: first so an escape the user typed stays literal too.
ESCAPE = "\\"


def contains(text: str) -> str:
    """`%text%` with LIKE's metacharacters in `text` escaped. Pair with escape=ESCAPE."""
    escaped = (text.replace(ESCAPE, ESCAPE * 2)
                   .replace("%", ESCAPE + "%")
                   .replace("_", ESCAPE + "_"))
    return f"%{escaped}%"
