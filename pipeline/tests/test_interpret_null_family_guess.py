# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A null malware_family_guess must not kill the interpret container.

`_promote_nested_analysis` opened with:

    if result.get("malware_family_guess", "").lower() not in ("unknown", ""):

The `""` default applies only when the key is ABSENT. The model routinely emits
`{"malware_family_guess": null}`, which `.get()` returns as `None`, and
`None.lower()` raises `AttributeError`.

Every call site wraps this in `except (json.JSONDecodeError, TypeError)`, so the
AttributeError was not caught: it escaped the entire parse chain, skipping the
remaining extraction strategies (markdown fences, free-text JSON) that exist
precisely to salvage a sloppy response. A run was lost over a null field the
function was about to treat as "unknown" anyway.

The value is now coerced by type rather than by `.get()`'s default, which also
covers the dict/list/number shapes an LLM can emit for the same key.
"""
import ast
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "ansible" / "roles" / "interpret" / "files"
       / "interpret-ghidra.py").read_text(encoding="utf-8")

# Load just the helper — importing the module pulls in anthropic/httpx.
# `Any` appears in the annotations; supply it rather than strip them.
_NS: dict = {"json": json, "re": __import__("re"), "Any": object}
for _node in ast.parse(SRC).body:
    if isinstance(_node, ast.FunctionDef) and _node.name == "_promote_nested_analysis":
        exec(compile(ast.Module([_node], []), "<helper>", "exec"), _NS)  # noqa: S102
promote = _NS["_promote_nested_analysis"]

NESTED = json.dumps({"malware_family_guess": "agenttesla", "narrative": "real analysis"})


def test_the_helper_loaded():
    """Guards the guard: a failed exec makes every test below vacuous."""
    assert callable(promote)


@pytest.mark.parametrize("guess", [None, 0, 1, [], {}, ["agenttesla"], {"name": "x"}])
def test_a_non_string_family_guess_does_not_raise(guess):
    """THE bug. None is the realistic one; the rest are the same class."""
    result = {"malware_family_guess": guess, "narrative": "nothing to promote"}
    assert promote(result) is result


def test_a_null_guess_still_allows_promotion():
    """null means 'unknown', so the nested analysis must still be promoted —
    the point is to treat it as unknown, not to bail out."""
    out = promote({"malware_family_guess": None, "narrative": f"```json\n{NESTED}\n```"})
    assert out["malware_family_guess"] == "agenttesla"


def test_an_absent_guess_still_allows_promotion():
    """The case the "" default was written for; unchanged."""
    out = promote({"narrative": f"```json\n{NESTED}\n```"})
    assert out["malware_family_guess"] == "agenttesla"


def test_a_real_family_guess_is_left_alone():
    """Positive control: a wrapper that already names a family is not a wrapper."""
    result = {"malware_family_guess": "remcos", "narrative": f"```json\n{NESTED}\n```"}
    assert promote(result) is result


def test_the_callers_still_cannot_catch_an_attributeerror():
    """Why this had to be fixed at the source rather than by widening the
    except clauses: the parse chain deliberately catches only parse errors."""
    assert "except (json.JSONDecodeError, TypeError)" in SRC
    assert "except (json.JSONDecodeError, TypeError, AttributeError)" not in SRC, (
        "widening the except would hide this class of bug rather than fix it")
