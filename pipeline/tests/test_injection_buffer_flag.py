# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""cape_has_injection_buffers must count injection buffers, not payloads.

`cape_injection_candidates` is a mixed list. It collects two different things:

  * `"source": "cape_injection"` — real WriteProcessMemory injection buffers,
    from `report["cape"]["injection_buffers"]`
  * `"source": "cape_payload"`   — Cape's extracted large payloads, appended
    afterwards from `report["cape"]["large_payloads"]`

The flag was `len(cape_injection_candidates) > 0`, so ANY extracted payload
claimed injection buffers existed. That flag decides whether the Volatility
stage trusts Cape's buffers or falls back to a malfind scan, so a sample that
dropped a payload but performed no injection had its malfind fallback
suppressed — and malfind is what finds injected code Cape did not capture.

Directly relevant to #402's `a71de2c`, which repaired the targeted-malfind dump
in that same fallback branch: this bug determines how often that branch is
reached at all.

Asserted on the expression rather than by running the whole stage, which needs
CAPE, a memory dump and Volatility.
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "ansible" / "roles" / "pipeline" / "files" / "run-pipeline.py").read_text(
    encoding="utf-8")


def _flag_expression() -> str:
    """The expression assigned to cape_has_injection_buffers at the call site."""
    tree = ast.parse(SRC)
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "cape_has_injection_buffers":
            return ast.unparse(node.value)
    raise AssertionError("cape_has_injection_buffers is no longer passed to the stage")


def test_the_flag_is_not_a_bare_length_of_the_mixed_list():
    """THE bug. len(...) > 0 counts cape_payload entries as injection buffers."""
    expr = _flag_expression()
    assert "len(cape_injection_candidates) > 0" not in expr, (
        "the flag counts the whole mixed list again, so any extracted payload "
        "suppresses the malfind fallback")


def test_the_flag_discriminates_on_source():
    expr = _flag_expression()
    assert "cape_injection" in expr, (
        f"the flag must select injection-sourced entries; got: {expr}")


def test_both_sources_still_populate_the_shared_list():
    """The premise. If the list stopped carrying both kinds, this guard would be
    protecting a distinction that no longer exists."""
    assert '"source": "cape_injection"' in SRC
    assert '"source": "cape_payload"' in SRC


def test_the_flag_semantics_hold_on_representative_lists():
    """Evaluate the real expression against each list shape."""
    expr = _flag_expression()
    inj = {"source": "cape_injection"}
    pay = {"source": "cape_payload"}
    cases = {
        "empty": ([], False),
        "payloads only": ([pay, pay], False),
        "injection only": ([inj], True),
        "both": ([pay, inj], True),
    }
    for label, (candidates, expected) in cases.items():
        got = eval(expr, {}, {"cape_injection_candidates": candidates})  # noqa: S307
        assert got is expected, f"{label}: expected {expected}, got {got}"
