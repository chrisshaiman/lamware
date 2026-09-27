# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The smoke gate must not print the smoke user's password.

`config` is a fixture ARGUMENT of every smoke test, and pytest prints each
argument in the failure header:

    page = <Page ...>, config = {'password': '...', 'user': 'smoke-test'}

So any failing smoke test published a live credential into the deploy output,
which is then pasted into terminals, issues and chat. Found on 2026-09-24 when
a /evasions failure did exactly that.

These tests import the config type directly rather than running the gate, which
needs Playwright and a live host. That keeps the guard in the normal suite,
where it runs on every commit.
"""
import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "tests" / "smoke" / "_redaction.py"


def _load():
    """Import the redaction helpers WITHOUT importing playwright.

    They live in their own module for exactly this reason: when these guards
    imported conftest they skipped wherever playwright was absent, which
    includes CI, and a guard that skips in CI guards nothing.
    """
    spec = importlib.util.spec_from_file_location("_smoke_redaction", MODULE)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_smoke_redaction"] = mod
    spec.loader.exec_module(mod)
    return mod


SECRET = "hunter2-do-not-print-me"


@pytest.mark.parametrize("render", [repr, str, "fstring"])
def test_the_password_never_renders(render):
    """Every path pytest could use to display the fixture."""
    cfg = _load().SmokeConfig(base_url="https://x", user="smoke-test", password=SECRET)
    text = f"{cfg}" if render == "fstring" else render(cfg)
    assert SECRET not in text
    assert "<redacted>" in text


def test_the_value_is_still_readable():
    """Redaction must not break the login that needs it."""
    cfg = _load().SmokeConfig(base_url="https://x", user="smoke-test", password=SECRET)
    assert cfg["password"] == SECRET
    assert cfg["base_url"] == "https://x"


def test_non_secret_fields_stay_visible():
    """A failure header that hides the base URL is harder to debug for no gain."""
    cfg = _load().SmokeConfig(base_url="https://x", user="smoke-test", password=SECRET)
    assert "https://x" in repr(cfg) and "smoke-test" in repr(cfg)


@pytest.mark.parametrize("key", ["password", "api_token", "CLIENT_SECRET"])
def test_other_secret_shaped_keys_are_redacted_too(key):
    cfg = _load().SmokeConfig(base_url="https://x", **{key: SECRET})
    assert SECRET not in repr(cfg)


@pytest.mark.parametrize("text,leaks", [
    ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1g", True),
    ("Bearer abcdefghijklmnopqrstuvwxyz012345", True),
    ("TypeError: Cannot read properties of undefined (reading 'techniques')", False),
])
def test_console_capture_redacts_tokens_but_keeps_errors(text, leaks):
    """The console is captured to diagnose blank pages, and a failed XHR can put a
    bearer token in it. The React error must survive — redacting everything would
    defeat the reason for capturing at all."""
    out = _load().redact(text)
    assert ("<redacted-token>" in out) is leaks
    if not leaks:
        assert out == text


def test_the_smoke_conftest_actually_imports_its_helpers():
    """The split that made these guards runnable also broke the gate.

    `tests/smoke` has no `__init__.py`, so pytest imports conftest.py as the
    top-level module `conftest`. `from ._redaction import ...` therefore raised

        ImportError: attempted relative import with no known parent package

    and the whole gate failed at collection — after the deploy had already run.
    Nothing caught it: these guards import `_redaction.py` directly, so they
    passed while the file that USES it could not load.

    Asserted by compiling conftest.py the way pytest does — as a module with no
    package — which fails on a relative import without needing playwright.
    """
    import ast

    src = (ROOT / "tests" / "smoke" / "conftest.py").read_text()
    tree = ast.parse(src)
    relative = [n for n in ast.walk(tree)
                if isinstance(n, ast.ImportFrom) and n.level and n.level > 0]
    assert not relative, (
        "conftest.py uses a relative import; it is loaded as a top-level module "
        f"and will fail at collection: {[n.module for n in relative]}")


def test_the_helper_directory_is_on_the_path_before_it_is_imported():
    """An absolute `from _redaction import ...` only resolves because conftest puts
    its own directory on sys.path first. Order matters, so it is asserted."""
    src = (ROOT / "tests" / "smoke" / "conftest.py").read_text()
    lines = src.splitlines()
    path_line = next(i for i, ln in enumerate(lines) if "sys.path.insert" in ln)
    import_line = next(i for i, ln in enumerate(lines) if "from _redaction import" in ln)
    assert path_line < import_line, "sys.path is extended after the import that needs it"
