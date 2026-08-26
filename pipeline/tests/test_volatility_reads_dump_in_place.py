# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Volatility reads the Cape dump in place — no tmpfs copy.

`run_volatility` used to copy the whole memory dump to a ramdisk "for faster
I/O". Measured on this host with the page cache dropped before each arm, the
plugins run in parallel to give the ramdisk its best case, and the copy counted
as part of its cost:

    ramdisk   copy 4s + plugins 126s = 130s   [8 GiB RAM pinned]
    disk      no copy,  plugins 129s = 129s   [0 RAM pinned]

/opt is NVMe. The disk was never the bottleneck.

The copy was not merely useless, it was harmful in a specific way:

    active_dump = ramdisk_dump if ramdisk_dump else dump_path

`copy_to_ramdisk` returned None whenever the dump did not fit, and two
concurrent analyses never fit in a 12g ramdisk. The fallback was a path the
rootless container could not read at all, so the second analysis lost its ENTIRE
Volatility stage — every plugin, not just one (#470).

These tests exist so the copy cannot come back without someone re-running the
measurement, and so the conditional-fallback shape cannot return with it.
"""
import ast
from pathlib import Path

import pytest

SRC_PATH = Path(__file__).resolve().parents[2] / "ansible/roles/pipeline/files/stages/volatility.py"
SRC = SRC_PATH.read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _func(name: str) -> ast.FunctionDef:
    for node in ast.walk(TREE):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node
    raise AssertionError(f"{name} not found")


def test_no_ramdisk_copy_helper():
    names = [n.name for n in ast.walk(TREE) if isinstance(n, ast.FunctionDef)]
    assert "copy_to_ramdisk" not in names


def test_run_volatility_takes_no_ramdisk_argument():
    args = _func("run_volatility").args
    every = [a.arg for a in args.args + args.kwonlyargs]
    assert not [a for a in every if "ramdisk" in a], every


def test_the_dump_is_used_directly_not_via_a_fallback():
    """The specific shape that made the copy load-bearing.

    `active_dump = ramdisk_dump if ramdisk_dump else dump_path` reads as a
    harmless optimisation with a safe fallback. It was neither: the fallback was
    unreadable, so "the copy did not happen" silently became "no memory analysis
    at all". Assert the assignment is a plain Name, so a conditional cannot
    reappear without failing here.
    """
    fn = _func("run_volatility")
    assigns = [n for n in ast.walk(fn)
               if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "active_dump" for t in n.targets)]
    assert len(assigns) == 1, f"expected one active_dump assignment, got {len(assigns)}"
    value = assigns[0].value
    assert isinstance(value, ast.Name), (
        f"active_dump is assigned from {type(value).__name__}, not a plain name — "
        "a conditional fallback here is what turned a missing copy into a silent "
        "loss of the whole stage")
    assert value.id == "dump_path"


@pytest.mark.parametrize("token", ["ramdisk", "copy_to_ramdisk", "tmpfs"])
def test_run_volatility_body_mentions_no_ramdisk(token):
    """Docstring and comments are excluded: the code explains why the ramdisk
    was removed, and that explanation must not read as a dependency."""
    fn = _func("run_volatility")
    body = fn.body[1:] if (isinstance(fn.body[0], ast.Expr)
                           and isinstance(fn.body[0].value, ast.Constant)) else fn.body
    code = "\n".join(ast.unparse(n) for n in body)
    assert token not in code
