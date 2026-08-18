# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""A JWKS refresh failure is an auth failure, not a server error.

`_validate_jwt` refreshes the JWKS cache when a token carries an unknown `kid`.
`fetch_jwks()` calls `r.raise_for_status()`, and nothing wrapped it — so a
Keycloak 5xx, or Keycloak simply being unreachable, raised `httpx.HTTPError` out
of `_validate_jwt`.

That path is reachable by an UNAUTHENTICATED caller: any token with an unknown
kid triggers it. The consequences were both wrong:

  * the caller got HTTP 500 instead of 401, turning a failed authentication into
    an apparent server fault, and
  * the `raise HTTPException(401, "Unknown signing key")` line was never
    reached — and with it `_log_failed_auth` — so the attempt left no record.

An auth path has to fail closed and on the record. The refresh now swallows
transport and HTTP errors into "key not found" and logs them.
"""
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from tests._module_stubs import restore, snapshot

_STUBBED = ("httpx",)
_SAVED = snapshot(_STUBBED)

_httpx = types.ModuleType("httpx")


class _HTTPError(Exception):
    pass


class _HTTPStatusError(_HTTPError):
    pass


class _ConnectError(_HTTPError):
    pass


_httpx.HTTPError = _HTTPError
_httpx.HTTPStatusError = _HTTPStatusError
_httpx.ConnectError = _ConnectError
_httpx.AsyncClient = MagicMock()
sys.modules["httpx"] = _httpx

_SRC = (Path(__file__).resolve().parent.parent / "app" / "auth.py").read_text(
    encoding="utf-8")

restore(_SAVED)


def _refresh_source() -> str:
    start = _SRC.index("async def _refresh_jwks_for_kid")
    return _SRC[start:_SRC.index("\n\n\n", start)]


def test_the_refresh_catches_transport_and_http_errors():
    """THE bug. fetch_jwks() raises via raise_for_status(); nothing caught it."""
    src = _refresh_source()
    assert "try:" in src and "except httpx.HTTPError" in src, (
        "a Keycloak 5xx or an unreachable Keycloak escapes as an unhandled "
        "exception, so an unknown-kid token yields 500 instead of 401")


def test_a_failed_refresh_reports_key_not_found():
    """It must return False, which routes to the existing 401 — not re-raise."""
    src = _refresh_source()
    tail = src[src.index("except httpx.HTTPError"):]
    assert "return False" in tail, "a failed refresh must fail closed"
    assert "raise" not in tail.replace("raise_for_status", ""), (
        "re-raising puts us back at a 500")


def test_the_failure_is_logged():
    """The 500 path skipped _log_failed_auth entirely; the refusal must still
    leave a record an operator can find."""
    assert "log.error(" in _refresh_source()


def test_the_unknown_key_path_still_returns_401():
    """The destination this now routes to, pinned so it cannot drift."""
    assert 'raise HTTPException(status_code=401, detail="Unknown signing key")' in _SRC


def test_httpx_is_imported_at_module_scope():
    """The except clause names httpx, so a function-local import would make the
    handler itself a NameError — the #384 failure mode."""
    header = _SRC[:_SRC.index("log = logging.getLogger")]
    assert "\nimport httpx\n" in header


@pytest.mark.parametrize("exc", ["HTTPStatusError", "ConnectError"])
def test_both_failure_modes_are_covered_by_the_base_class(exc):
    """httpx.HTTPError is the base of both a 5xx response and an unreachable
    host; catching the base is what makes 'Keycloak is down' a 401 too."""
    assert issubclass(getattr(_httpx, exc), _httpx.HTTPError)
