# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A test module that stubs sys.modules must put it back.

pytest imports test modules during collection, in order, into one interpreter. A
stub left in `sys.modules` is therefore visible to every module collected after it.
That is not a hypothetical: five test modules installed `ModuleType` fakes for
`fastapi`, `sqlmodel`, `sqlalchemy` and `httpx` at import time and never removed
them, so `test_ws_endpoint.py` and `test_ws_manager.py` died at collection with
`cannot import name 'WebSocket' from 'fastapi' (unknown location)`.

Both files were then **excluded from CI** rather than fixed — leaving the WebSocket
endpoint, which has the weakest auth in the codebase, with no CI coverage at all.
That is the failure this guard exists to prevent recurring: the cost of the leak was
not a flaky test, it was a silently untested security surface.

The check is static rather than runtime because a runtime check would have to run
*after* the offending module, and pytest's collection order is alphabetical — this
file sorts before `test_orchestrator.py`, so it could not observe that leak.
"""
import ast
from pathlib import Path

TESTS_DIR = Path(__file__).resolve().parent

# Files that legitimately DELETE entries to defend themselves against leaks, rather
# than installing stubs of their own. They pre-date the fix and are harmless.
_DELETE_ONLY = {"test_auth_aud.py", "test_feeder_state.py"}


def _assigns_sys_modules(tree: ast.AST) -> bool:
    """True if the module assigns into sys.modules (rather than only deleting)."""
    for node in ast.walk(tree):
        # sys.modules["x"] = ...
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Attribute)
                    and target.value.attr == "modules"
                ):
                    return True
        # sys.modules.setdefault("x", ...)
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "setdefault"
            and isinstance(node.func.value, ast.Attribute)
            and node.func.value.attr == "modules"
        ):
            return True
    return False


def _calls_restore(tree: ast.AST) -> bool:
    return any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "restore"
        for node in ast.walk(tree)
    )


def test_every_stubbing_test_module_restores_sys_modules():
    offenders = []
    for path in sorted(TESTS_DIR.glob("test_*.py")):
        if path.name in _DELETE_ONLY or path.name == Path(__file__).name:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if _assigns_sys_modules(tree) and not _calls_restore(tree):
            offenders.append(path.name)

    assert not offenders, (
        "These test modules install sys.modules stubs but never restore them: "
        f"{offenders}. A leaked stub breaks every test module collected afterwards "
        "— which is how the WebSocket tests came to be excluded from CI. Use "
        "tests/_module_stubs.py: snapshot() before stubbing, restore() once the "
        "module under test has been exec'd."
    )


def test_the_ws_tests_are_not_excluded_from_ci():
    """The exclusions were the symptom. If they come back, so has the disease."""
    ci = (TESTS_DIR.parents[1] / ".github" / "workflows" / "ci.yml").read_text()
    for excluded in ("test_ws_endpoint.py", "test_ws_manager.py"):
        assert f"--ignore=tests/{excluded}" not in ci, (
            f"{excluded} is excluded from CI again. If it is failing, fix the cause "
            f"— excluding it leaves the WebSocket auth path with no coverage."
        )
