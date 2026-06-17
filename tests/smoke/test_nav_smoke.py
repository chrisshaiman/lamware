"""Post-deploy smoke checks: login + all 8 nav pages render.

Heading text is taken verbatim from the current React app. Each route asserts the
accessible heading plus one key widget (an accessible anchor where one exists, otherwise a
data-testid added to the page root). Deterministic: Playwright auto-waiting, no retries.

Author: Christopher Shaiman
License: Apache 2.0
"""

import re

import pytest
from playwright.sync_api import expect

# (path, heading text, key-widget selector)
ROUTES = [
    ("/analyses", "Analyses", "input[placeholder*='Search']"),
    ("/iocs", "IOC Browser", "[data-testid='iocs-content']"),
    ("/techniques", "MITRE ATT&CK", "[data-testid='techniques-content']"),
    ("/stats", "Statistics", "[data-testid='stats-content']"),
    ("/pipeline", "Pipeline Status", "[data-testid='pipeline-content']"),
    ("/alerts", "Operational Health", "[data-testid='alerts-content']"),
    ("/evasions", "Evasion Dashboard", "[data-testid='evasions-content']"),
    ("/submit", "Submit Sample", "text=Drag and drop"),
]


def test_login_succeeded(page, config):
    """The cached session authenticates and the app shell renders on the default route."""
    page.goto(config["base_url"])
    expect(page.locator("aside")).to_be_visible()
    assert "/analyses" in page.url


@pytest.mark.parametrize("path,heading,widget", ROUTES, ids=[r[0] for r in ROUTES])
def test_nav_page_renders(page, config, path, heading, widget):
    """Each nav page loads with its heading and key widget visible."""
    page.goto(config["base_url"] + path)
    # Auto-wait for the SPA route to settle (keycloak-js may bounce a deep link through
    # /auth before React mounts); a redirect-to-default then fails here as a clear URL
    # mismatch rather than an opaque widget timeout.
    expect(page).to_have_url(re.compile(re.escape(path)))
    expect(page.get_by_role("heading", name=heading, exact=True).first).to_be_visible()
    expect(page.locator(widget).first).to_be_visible()
