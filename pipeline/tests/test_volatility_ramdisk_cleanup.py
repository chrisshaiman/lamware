# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The ramdisk copy of the memory dump must be freed on every exit path.

`run_volatility` optionally copies the memory dump to a ramdisk for faster I/O
across all plugins, then unlinks it when done. The unlink used to sit inline
near the end of the function body, so it only ran when the body ran to
completion. Any raise above it — a plugin crash, an unreadable dump, the
45-minute container timeout that kills this stage — left the copy behind.

That copy is the whole memory dump, routinely multiple GB, and a ramdisk is
tmpfs: it is RAM. Leaking it is the memory-exhaustion shape #200 is about,
reached by a different route, and the leak survives the run that caused it.

The cleanup now lives in a `finally`, which is asserted structurally: a
behavioural test would need a real dump and a working Volatility, and the
property at issue is exactly "does this run when the body raises".
"""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC_PATH = (ROOT / "ansible" / "roles" / "pipeline" / "files" / "stages"
            / "volatility.py")
SRC = SRC_PATH.read_text(encoding="utf-8")


def _run_volatility() -> ast.FunctionDef:
    for node in ast.walk(ast.parse(SRC)):
        if isinstance(node, ast.FunctionDef) and node.name == "run_volatility":
            return node
    raise AssertionError("run_volatility not found")


def _unlink_calls_in(nodes) -> list:
    found = []
    for n in nodes:
        for sub in ast.walk(n):
            if (isinstance(sub, ast.Call)
                    and isinstance(sub.func, ast.Attribute)
                    and sub.func.attr == "unlink"
                    and ast.unparse(sub.func.value) == "ramdisk_dump"):
                found.append(sub)
    return found


def test_the_ramdisk_unlink_is_in_a_finally():
    """THE bug. Inline at the end of the body means 'only on the happy path'."""
    fn = _run_volatility()
    tries = [n for n in ast.walk(fn) if isinstance(n, ast.Try) and n.finalbody]
    in_finally = [c for t in tries for c in _unlink_calls_in(t.finalbody)]
    assert in_finally, (
        "ramdisk_dump.unlink() is not inside a finally block; a plugin crash or "
        "the 45-minute stage timeout leaks a multi-GB copy in tmpfs")


def test_no_unlink_is_left_on_the_happy_path_only():
    """A second copy outside the finally would run twice on success and still
    be skipped on failure — worse than either alternative."""
    fn = _run_volatility()
    tries = [n for n in ast.walk(fn) if isinstance(n, ast.Try) and n.finalbody]
    finally_calls = {id(c) for t in tries for c in _unlink_calls_in(t.finalbody)}
    all_calls = {id(c) for c in _unlink_calls_in([fn])}
    assert all_calls == finally_calls, (
        "a ramdisk unlink exists outside the finally block")


def test_the_copy_is_still_created_before_the_guard():
    """The premise: if the copy stopped being made, this guard would be
    protecting a variable that is always None."""
    assert "ramdisk_dump = copy_to_ramdisk(dump_path, ramdisk_path)" in SRC


def test_the_module_still_compiles():
    """The fix re-indented the whole function body; a broken indent would be a
    syntax error, and this catches it independently of the assertions above."""
    compile(SRC, str(SRC_PATH), "exec")
