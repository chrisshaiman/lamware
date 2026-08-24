# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""DELETE /api/analyses/{id} unlinks what it finds, so the path it builds matters.

The endpoint removes the analysis's report directory with
`Path(settings.reports_dir) / task_id` followed by an `iterdir()` unlink loop.
`task_id` is a free-form `varchar(100)`, and an empty value resolves that join
to the reports ROOT — whose top-level contents the loop then removes one by one.

The value comes from the database row, not from the request, and the endpoint
requires the admin role. So this guards against a bad write upstream rather than
against this caller — which on a delete path is exactly the case worth guarding.

Asserted against the parsed AST: the fix is a branch that must sit BEFORE the
join, and "the file contains is_safe_task_id" would be satisfied by a call
placed after it.
"""
import ast
from pathlib import Path

import app.routers.analyses as analyses

SRC = Path(analyses.__file__).read_text(encoding="utf-8")
TREE = ast.parse(SRC)


def _delete_fn() -> ast.FunctionDef:
    fn = next((n for n in ast.walk(TREE)
               if isinstance(n, ast.FunctionDef) and n.name == "delete_analysis"), None)
    assert fn is not None, "delete_analysis not found — update this test with it"
    return fn


def test_the_guard_is_imported_from_the_shared_rule():
    """One rule, shared with cape_payloads — not a second copy that can drift."""
    imported = {
        alias.name
        for n in ast.walk(TREE) if isinstance(n, ast.ImportFrom)
        and n.module == "lamware_shared.task_ids"
        for alias in n.names
    }
    assert "is_safe_task_id" in imported


def test_the_guard_runs_before_the_path_is_built():
    """Order is the whole fix. A check after the join is decoration."""
    fn = _delete_fn()
    guards = [
        n.lineno for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        and n.func.id == "is_safe_task_id"
    ]
    assert guards, "delete_analysis does not validate task_id before joining it"

    joins = [
        n.lineno for n in ast.walk(fn)
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div)
        and isinstance(n.left, ast.Call) and isinstance(n.left.func, ast.Name)
        and n.left.func.id == "Path"
    ]
    assert joins, "expected a Path(...) / task_id join in delete_analysis"
    assert min(guards) < min(joins), (
        f"is_safe_task_id runs at line {min(guards)} but the path is built at "
        f"{min(joins)} — the guard is after the thing it guards")


def test_an_unsafe_task_id_returns_before_any_unlink():
    """The guarded branch must leave the filesystem alone entirely."""
    fn = _delete_fn()
    guarded = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.If) and isinstance(n.test, ast.UnaryOp)
        and isinstance(n.test.op, ast.Not)
        and isinstance(n.test.operand, ast.Call)
        and isinstance(n.test.operand.func, ast.Name)
        and n.test.operand.func.id == "is_safe_task_id"
    ]
    assert guarded, "no `if not is_safe_task_id(...)` branch"
    body = ast.dump(ast.Module(body=guarded[0].body, type_ignores=[]))
    assert "unlink" not in body and "rmdir" not in body
    assert any(isinstance(n, ast.Return) for n in ast.walk(guarded[0])), (
        "the branch must return, or execution falls through to the unlink loop")


def test_the_refusal_is_reported_to_the_caller_and_logged():
    """The database rows ARE deleted before this point, so silently skipping the
    files would leave orphans nobody knows about. Same principle as the stats
    `errors` field: the shape stays, the reason rides along."""
    fn = _delete_fn()
    guarded = next(
        n for n in ast.walk(fn)
        if isinstance(n, ast.If) and isinstance(n.test, ast.UnaryOp)
        and isinstance(n.test.operand, ast.Call)
        and getattr(n.test.operand.func, "id", None) == "is_safe_task_id"
    )
    body = ast.dump(ast.Module(body=guarded.body, type_ignores=[]))
    assert "files_error" in body, "the response must say the files were left in place"
    assert "log" in body and "error" in body, "and the refusal must be logged"


def test_the_happy_path_still_deletes_files():
    """The guard must not have made the removal unreachable."""
    fn = _delete_fn()
    unlinks = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "unlink"
    ]
    assert unlinks, "delete_analysis no longer removes report files at all"
