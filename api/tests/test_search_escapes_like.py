# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Search boxes match what was typed: LIKE's `%` and `_` are taken literally (#730).

`contains` is called directly. The second test is structural, because the
behaviour (a search for `a_b` not matching `axb`) needs Postgres to observe: it
parses every router and asserts each `.ilike(...)` call passes `escape=`, which
is what stops a new search from reintroducing the bare f"%{q}%" form.
"""
import ast
from pathlib import Path

import pytest
from app.search import ESCAPE, contains

ROUTERS = Path(__file__).resolve().parents[1] / "app" / "routers"


@pytest.mark.parametrize("typed,pattern", [
    ("abc", "%abc%"),
    ("a_b", "%a\\_b%"),
    ("100%", "%100\\%%"),
    ("c:\\x", "%c:\\\\x%"),
])
def test_contains_escapes_like_metacharacters(typed, pattern):
    assert contains(typed) == pattern
    assert ESCAPE == "\\"


def test_every_ilike_in_the_routers_passes_escape():
    calls, bare = 0, []
    for f in sorted(ROUTERS.glob("*.py")):
        for node in ast.walk(ast.parse(f.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("ilike", "like")):
                calls += 1
                if not any(k.arg == "escape" for k in node.keywords):
                    bare.append(f"{f.name}:{node.lineno}")
    assert calls >= 7, f"found only {calls} like/ilike calls; the scan is not seeing the routers"
    assert not bare, f"ilike without escape= (wildcards in user text stay live): {bare}"
