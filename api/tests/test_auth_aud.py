# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0

"""Deterministic unit tests for JWT audience validation in app.auth._validate_jwt.

We mint RSA-signed tokens in-process and pre-populate the JWKS cache, so no
network or live Keycloak is needed. This proves the audience allowlist actually
rejects tokens whose aud is outside it — the core of the confused-deputy fix.

Import strategy: app.auth must be the REAL module. Sibling test modules
(test_investigate_tools / test_orchestrator) force-assign stub app.config /
sqlalchemy / sqlmodel into sys.modules at import time. To stay independent of
pytest collection order, we purge any cached app* modules and import the real
package here before binding our references. Do NOT remove the purge block.
"""

import asyncio
import sys
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

# --- Import the REAL app.auth, order-independently --------------------------
for _name in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
    del sys.modules[_name]

import app.auth as app_auth  # noqa: E402


def test_default_allowlist_is_transitional():
    """Shipped default accepts the dedicated audience plus transitional account."""
    assert app_auth.settings.jwt_allowed_audiences == ["lamware-api", "account"]


# --- Test key + token helpers ----------------------------------------------
_KID = "test-key-1"
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(autouse=True)
def _populate_jwks():
    """Insert our test public key into the JWKS cache for every test."""
    app_auth._jwks_cache.clear()
    app_auth._jwks_cache[_KID] = _PRIVATE_KEY.public_key()
    yield
    app_auth._jwks_cache.clear()


def _expected_issuer() -> str:
    s = app_auth.settings
    return f"{s.keycloak_issuer_url}/realms/{s.keycloak_realm}"


def _mint(aud=None) -> str:
    """Mint an RS256 token signed by the test key, optionally with an aud claim."""
    now = int(time.time())
    payload = {
        "sub": "user-123",
        "email": "user@lamware.test",
        "name": "Test User",
        "iss": _expected_issuer(),
        "iat": now,
        "exp": now + 3600,
        "realm_access": {"roles": ["viewer"]},
    }
    if aud is not None:
        payload["aud"] = aud
    return jwt.encode(payload, _PRIVATE_KEY, algorithm="RS256", headers={"kid": _KID})


def _validate(token: str):
    return asyncio.run(app_auth._validate_jwt(token))


# --- Acceptance -------------------------------------------------------------
def test_string_aud_in_allowlist_accepted(monkeypatch):
    monkeypatch.setattr(app_auth.settings, "jwt_allowed_audiences", ["lamware-api"])
    ctx = _validate(_mint(aud="lamware-api"))
    assert ctx.user_id == "user-123"
    assert ctx.roles == ["viewer"]


def test_list_aud_intersecting_allowlist_accepted(monkeypatch):
    monkeypatch.setattr(app_auth.settings, "jwt_allowed_audiences", ["lamware-api"])
    ctx = _validate(_mint(aud=["lamware-api", "account"]))
    assert ctx.user_id == "user-123"


def test_account_accepted_under_transitional_default(monkeypatch):
    monkeypatch.setattr(
        app_auth.settings, "jwt_allowed_audiences", ["lamware-api", "account"]
    )
    ctx = _validate(_mint(aud="account"))
    assert ctx.user_id == "user-123"


# --- Rejection (the actual fix) --------------------------------------------
def test_account_only_rejected_when_strict(monkeypatch):
    monkeypatch.setattr(app_auth.settings, "jwt_allowed_audiences", ["lamware-api"])
    with pytest.raises(HTTPException) as exc:
        _validate(_mint(aud="account"))
    assert exc.value.status_code == 401


def test_foreign_audience_rejected(monkeypatch):
    monkeypatch.setattr(app_auth.settings, "jwt_allowed_audiences", ["lamware-api"])
    with pytest.raises(HTTPException) as exc:
        _validate(_mint(aud="some-other-client"))
    assert exc.value.status_code == 401


def test_missing_aud_rejected(monkeypatch):
    monkeypatch.setattr(app_auth.settings, "jwt_allowed_audiences", ["lamware-api"])
    with pytest.raises(HTTPException) as exc:
        _validate(_mint(aud=None))
    assert exc.value.status_code == 401
