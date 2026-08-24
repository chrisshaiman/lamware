# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""An unauthenticated caller must not be able to aim the API at Keycloak.

`_refresh_jwks_for_kid` runs for any token carrying an unknown `kid`, which is
the point of it — a key rotation has to be picked up without a restart. It is
therefore reachable BEFORE authentication succeeds, and it had no rate limit and
no negative cache. A loop of junk tokens with random `kid` values became one
outbound request to Keycloak per token, from a caller who had proved nothing.

The fix is a single global timestamp rather than a per-kid negative cache,
because the attacker chooses the kids: a dict keyed on them is unbounded memory
under the same attack it is meant to stop.

These tests call the real coroutine and count fetches. Counting is the whole
point — a test that only asserted "returns False" would pass against the
unlimited version too.
"""
import asyncio

import app.auth as app_auth
import pytest


@pytest.fixture
def jwks(monkeypatch):
    """Real _refresh_jwks_for_kid, with fetch_jwks counted instead of performed."""
    calls: list[int] = []

    async def _fake_fetch():
        calls.append(1)

    monkeypatch.setattr(app_auth, "fetch_jwks", _fake_fetch)
    monkeypatch.setattr(app_auth, "_jwks_cache", {})
    monkeypatch.setattr(app_auth, "_last_jwks_refresh", float("-inf"))
    monkeypatch.setattr(app_auth, "_jwks_refresh_lock", asyncio.Lock())
    return calls


def test_a_flood_of_distinct_unknown_kids_causes_one_fetch(jwks):
    """THE bug. 500 junk tokens, 500 outbound requests to the IdP."""
    async def run():
        return [await app_auth._refresh_jwks_for_kid(f"kid-{i}") for i in range(500)]

    results = asyncio.run(run())
    assert results == [False] * 500, "every unknown kid must still fail closed"
    assert len(jwks) == 1, (
        f"{len(jwks)} JWKS fetches for 500 junk tokens — an unauthenticated "
        f"caller can amplify against Keycloak")


def test_concurrent_unknown_kids_do_not_stampede(jwks):
    """50 at once, still one fetch. The timestamp is written BEFORE the await,
    so this holds on the rate limit alone — the lock is not what does it here."""
    async def _slow_fetch():
        jwks.append(1)
        await asyncio.sleep(0)  # a real fetch suspends; a synchronous stub hides races

    app_auth.fetch_jwks = _slow_fetch  # type: ignore[assignment]

    async def run():
        return await asyncio.gather(
            *(app_auth._refresh_jwks_for_kid(f"kid-{i}") for i in range(50)))

    asyncio.run(run())
    assert len(jwks) == 1, f"{len(jwks)} concurrent fetches for 50 junk kids"


def test_a_rotation_racing_with_itself_is_not_reported_as_unknown(jwks, monkeypatch):
    """What the lock is actually for, which the rate limit alone gets wrong.

    Two requests arrive together bearing a genuinely rotated kid. The first
    starts a fetch and suspends. Without the lock, the second reads the
    just-written timestamp, finds itself inside the window, and returns False —
    a 401 for a valid token, because a refresh that was already in flight and
    about to succeed had not finished yet.

    With the lock the second waits, re-checks the cache, and finds the key.
    """
    async def _slow_fetch():
        jwks.append(1)
        await asyncio.sleep(0)
        app_auth._jwks_cache["rotated"] = object()

    monkeypatch.setattr(app_auth, "fetch_jwks", _slow_fetch)

    async def run():
        return await asyncio.gather(
            app_auth._refresh_jwks_for_kid("rotated"),
            app_auth._refresh_jwks_for_kid("rotated"),
        )

    results = asyncio.run(run())
    assert results == [True, True], (
        f"{results} — a valid token was refused because another request was "
        f"already refreshing for the same key")
    assert len(jwks) == 1, "and it must still be one fetch, not two"


def test_the_first_refresh_is_never_suppressed(jwks):
    """A legitimate rotation on a freshly started process must be picked up."""
    asyncio.run(app_auth._refresh_jwks_for_kid("kid-1"))
    assert len(jwks) == 1


def test_a_refresh_is_allowed_again_once_the_window_passes(jwks, monkeypatch):
    """Rate-limited, not disabled — key rotation still works within one window."""
    asyncio.run(app_auth._refresh_jwks_for_kid("kid-1"))
    assert len(jwks) == 1

    import time
    real = time.monotonic()
    monkeypatch.setattr(
        app_auth.time, "monotonic",
        lambda: real + app_auth._JWKS_MIN_REFRESH_INTERVAL_S + 1)
    asyncio.run(app_auth._refresh_jwks_for_kid("kid-2"))
    assert len(jwks) == 2, "the limiter must expire, or rotation needs a restart"


def test_a_kid_the_fetch_finds_is_reported_found(jwks, monkeypatch):
    """The success path still works: refresh, then the kid is present."""
    async def _fetch_that_adds():
        jwks.append(1)
        app_auth._jwks_cache["rotated"] = object()

    monkeypatch.setattr(app_auth, "fetch_jwks", _fetch_that_adds)
    assert asyncio.run(app_auth._refresh_jwks_for_kid("rotated")) is True


def test_a_kid_already_cached_needs_no_fetch_at_all(jwks):
    """The re-check under the lock. Two callers race on the same unknown kid;
    the second must see the first one's result, not fetch again."""
    app_auth._jwks_cache["known"] = object()
    assert asyncio.run(app_auth._refresh_jwks_for_kid("known")) is True
    assert len(jwks) == 0


def test_a_keycloak_outage_is_still_a_closed_failure(jwks, monkeypatch):
    """The pre-existing contract (#404 lead 2) must survive the rate limit:
    an HTTP error becomes False, not an exception, so the caller returns 401."""
    import httpx

    async def _boom():
        jwks.append(1)
        raise httpx.ConnectError("keycloak unreachable")

    monkeypatch.setattr(app_auth, "fetch_jwks", _boom)
    assert asyncio.run(app_auth._refresh_jwks_for_kid("kid-1")) is False


def test_a_failed_fetch_still_consumes_the_window(jwks, monkeypatch):
    """Otherwise the limiter has a hole exactly when Keycloak is struggling:
    every failing attempt would leave the timestamp unmoved and let the next
    junk token try again immediately."""
    import httpx

    async def _boom():
        jwks.append(1)
        raise httpx.ConnectError("keycloak unreachable")

    monkeypatch.setattr(app_auth, "fetch_jwks", _boom)

    async def run():
        for i in range(20):
            await app_auth._refresh_jwks_for_kid(f"kid-{i}")

    asyncio.run(run())
    assert len(jwks) == 1, (
        f"{len(jwks)} fetches against an already-failing IdP — a Keycloak "
        f"outage becomes the moment the amplification works best")
