"""Fixtures for the lamware post-deploy Playwright smoke gate.

Logs into the live Keycloak-gated React SPA once per session via the real login form,
caches Playwright storage_state (Keycloak SSO cookies, same-origin at /auth), and hands
each test a fresh authenticated page. Read-only; no writes, no LLM.

Author: Christopher Shaiman
License: Apache 2.0
"""

import os
from pathlib import Path

import pytest
from playwright.sync_api import expect, sync_playwright

# expect() assertions use their own 5s default; raise to match the suite's 15s intent.
expect.set_options(timeout=15_000)

ARTIFACTS_DIR = Path(__file__).parent / ".artifacts"


def _config() -> dict:
    """Read smoke config from the environment."""
    base_url = os.environ.get("SMOKE_BASE_URL", "https://lamware.shaiman.net").rstrip("/")
    user = os.environ.get("SMOKE_TEST_USER", "smoke-test")
    password = os.environ.get("SMOKE_TEST_PASSWORD", "")
    return {"base_url": base_url, "user": user, "password": password}


@pytest.fixture(scope="session")
def config() -> dict:
    cfg = _config()
    if not cfg["password"]:
        pytest.fail("SMOKE_TEST_PASSWORD is not set — the gate cannot authenticate.")
    return cfg


@pytest.fixture(scope="session")
def _playwright():
    with sync_playwright() as pw:
        yield pw


@pytest.fixture(scope="session")
def browser(_playwright):
    browser = _playwright.chromium.launch(headless=True)
    yield browser
    browser.close()


@pytest.fixture(scope="session")
def auth_state(browser, config) -> dict:
    """Log in once via the Keycloak form and return cached storage_state.

    The SPA uses keycloak-js with onLoad: "login-required", so navigating to the base URL
    auto-redirects to the Keycloak login form. Keycloak is proxied same-origin at /auth, so
    the resulting SSO cookies are captured by storage_state and reused by every test.
    """
    context = browser.new_context()
    context.set_default_timeout(15000)
    page = context.new_page()

    # Auto-redirects to the Keycloak login form.
    page.goto(config["base_url"])

    # Standard Keycloak login form element IDs (default + custom theme keep these).
    page.fill("#username", config["user"])
    page.fill("#password", config["password"])
    page.click("#kc-login")
    try:
        # The app shell (<aside>) only mounts after a successful auth round-trip.
        page.wait_for_selector("aside", timeout=15_000)
    except Exception as exc:
        ARTIFACTS_DIR.mkdir(exist_ok=True)
        shot = ARTIFACTS_DIR / "login-failure.png"
        page.screenshot(path=str(shot))
        on_keycloak = "/auth/" in page.url or page.locator("#kc-login").count() > 0
        hint = (
            "still on the Keycloak login page — bad credentials, an unverified email, "
            "or a required user action (e.g. temporary password)"
            if on_keycloak
            else "reached the app origin but the <aside> app shell never rendered"
        )
        context.close()
        raise RuntimeError(
            f"Smoke login failed: {hint}. Landing URL: {page.url}. "
            f"Screenshot: {shot}"
        ) from exc
    state = context.storage_state()
    context.close()
    return state


@pytest.fixture()
def page(browser, auth_state, request):
    """A fresh authenticated page per test (reuses the cached Keycloak SSO cookies)."""
    context = browser.new_context(
        storage_state=auth_state,
        viewport={"width": 1400, "height": 900},
    )
    context.set_default_timeout(15000)
    page = context.new_page()
    request.node._smoke_page = page
    yield page
    context.close()


@pytest.fixture(scope="session")
def viewer_token(browser, auth_state, config) -> str:
    """Capture the live viewer Bearer token off a real /api/* request.

    keycloak-js holds the token in memory; the SPA's axios interceptor stamps
    'Authorization: Bearer <jwt>' on every /api/* call. We navigate to /analyses (which
    triggers GET /api/analyses) and lift the header — the only PKCE-compatible way to get a
    raw viewer JWT (direct-access-grants are disabled).
    """
    context = browser.new_context(storage_state=auth_state)
    context.set_default_timeout(15000)
    page = context.new_page()
    try:
        with page.expect_request(
            lambda r: "/api/" in r.url and bool(r.headers.get("authorization"))
        ) as info:
            page.goto(config["base_url"] + "/analyses")
        header = info.value.headers.get("authorization", "")
    except Exception as exc:
        context.close()
        raise RuntimeError(
            "Could not capture a viewer Bearer token: no authenticated /api/* request "
            "was observed on /analyses."
        ) from exc
    context.close()
    if not header.lower().startswith("bearer "):
        raise RuntimeError(
            f"Captured /api/* request had no Bearer Authorization header (got: {header!r})."
        )
    return header.split(" ", 1)[1]


@pytest.fixture(scope="session")
def viewer_api(_playwright, config, viewer_token):
    """A raw HTTP client carrying the viewer's Bearer token (no browser)."""
    ctx = _playwright.request.new_context(
        base_url=config["base_url"],
        extra_http_headers={"Authorization": f"Bearer {viewer_token}"},
    )
    yield ctx
    ctx.dispose()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """On a failed test, dump a screenshot + page HTML for post-mortem."""
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and report.failed:
        page = getattr(item, "_smoke_page", None)
        if page is not None:
            ARTIFACTS_DIR.mkdir(exist_ok=True)
            safe = item.name.replace("/", "_").replace("[", "_").replace("]", "_")
            try:
                page.screenshot(path=str(ARTIFACTS_DIR / f"{safe}.png"))
                (ARTIFACTS_DIR / f"{safe}.html").write_text(
                    page.content(), encoding="utf-8"
                )
            except Exception:
                pass  # best-effort post-mortem; never mask the real failure
