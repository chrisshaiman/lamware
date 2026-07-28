# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Snapshot/restore helper for test modules that stub `sys.modules` at import time.

Several unit tests load a module under test by exec'ing its source with every
external dependency replaced by a `ModuleType` stub. That is a reasonable way to
test a router without a database — but the stubs were installed at IMPORT time and
never removed.

pytest imports test modules during collection, one after another, so a leaked stub
is visible to every module collected later. `test_ws_endpoint.py` and
`test_ws_manager.py` sort after `test_investigate_*` and `test_orchestrator`, import
the real `app.main`, and died at collection with:

    ImportError: cannot import name 'WebSocket' from 'fastapi' (unknown location)

"unknown location" is the tell: `fastapi` was a bare ModuleType, not the package.
Both files were excluded from CI rather than fixed, so the WebSocket endpoint — the
one with the weakest auth in the codebase — had no CI coverage at all.

Usage: snapshot BEFORE installing stubs, restore AFTER the module under test has
been exec'd. The exec'd module keeps its own references to the stub objects, so
restoring `sys.modules` afterwards does not affect it.

    _saved = snapshot(STUBBED_NAMES)
    ...install stubs, exec the module under test...
    restore(_saved)
"""
import sys


def snapshot(names: tuple[str, ...] | list[str]) -> dict[str, object | None]:
    """Record the current sys.modules entry for each name (None if absent)."""
    return {name: sys.modules.get(name) for name in names}


def restore(saved: dict[str, object | None]) -> None:
    """Put sys.modules back exactly as `snapshot` found it.

    Names absent beforehand are removed rather than left pointing at a stub — that
    distinction is the whole point, since a leaked stub under a real package's name
    is what breaks later imports.
    """
    for name, original in saved.items():
        if original is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = original
