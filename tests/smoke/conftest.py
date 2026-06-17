"""Fixtures for the lamware post-deploy Playwright smoke gate.

Logs into the live Keycloak-gated React SPA once per session via the real login form,
caches Playwright storage_state (Keycloak SSO cookies, same-origin at /auth), and hands
each test a fresh authenticated page. Read-only; no writes, no LLM.

Author: Christopher Shaiman
License: Apache 2.0
"""

import os
import re

import pytest
from playwright.sync_api import sync_playwright


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
    page = context.new_page()
    page.set_default_timeout(15000)

    # Auto-redirects to the Keycloak login form.
    page.goto(config["base_url"])

    # Standard Keycloak login form element IDs (default + custom theme keep these).
    page.fill("#username", config["user"])
    page.fill("#password", config["password"])
    page.click("#kc-login")

    # Land back on the app shell at an authed route (default redirect -> /analyses).
    page.wait_for_url(re.compile(re.escape(config["base_url"]) + r"/.*"))
    page.wait_for_selector("aside")

    state = context.storage_state()
    context.close()
    return state


@pytest.fixture()
def page(browser, auth_state):
    """A fresh authenticated page per test (reuses the cached Keycloak SSO cookies)."""
    context = browser.new_context(
        storage_state=auth_state,
        viewport={"width": 1400, "height": 900},
    )
    context.set_default_timeout(15000)
    page = context.new_page()
    yield page
    context.close()
