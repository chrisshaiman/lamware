# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Only RSA signing keys from the JWKS become verifiers, and a bad key is skipped (#730).

`fetch_jwks` ran `RSAAlgorithm.from_jwk` on every key in the set. A non-RSA key
raised InvalidKeyError, which the refresh path did not catch, so an unknown-kid
token got a 500 instead of a 401; a `use: enc` key was cached as a verifier. It
also cleared the cache before loading, so one bad key left no keys at all.

Calls the real fetch_jwks against a key set served by a fake HTTP client.
"""
import asyncio
import json

import app.auth as app_auth
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa


def _rsa_jwk(kid: str, use: str | None = "sig") -> dict:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    d = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key))
    d["kid"] = kid
    if use is not None:
        d["use"] = use
    return d


def _ec_jwk(kid: str) -> dict:
    key = ec.generate_private_key(ec.SECP256R1()).public_key()
    d = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(key))
    d.update(kid=kid, use="sig")
    return d


class _Resp:
    def __init__(self, body):
        self._body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self._body


class _Client:
    body: dict = {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def get(self, url):
        return _Resp(_Client.body)


@pytest.fixture
def serve(monkeypatch):
    monkeypatch.setattr(app_auth.httpx, "AsyncClient", lambda *a, **k: _Client())
    monkeypatch.setattr(app_auth, "_jwks_cache", {})

    def _serve(keys):
        _Client.body = {"keys": keys}
        asyncio.run(app_auth.fetch_jwks())
        return dict(app_auth._jwks_cache)
    return _serve


def test_only_rsa_signing_keys_are_loaded(serve):
    broken = _rsa_jwk("rsa-broken")
    del broken["n"]
    cache = serve([_rsa_jwk("rsa-sig"), _rsa_jwk("rsa-nouse", use=None),
                   _rsa_jwk("rsa-enc", use="enc"), _ec_jwk("ec-sig"), broken])
    assert sorted(cache) == ["rsa-nouse", "rsa-sig"]


def test_a_bad_key_does_not_raise_or_empty_the_cache(serve):
    """The 500: an EC key in the set used to raise out of fetch_jwks."""
    serve([_rsa_jwk("old")])
    cache = serve([_ec_jwk("ec"), _rsa_jwk("new")])
    assert list(cache) == ["new"]
