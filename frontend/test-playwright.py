#!/usr/bin/env python3
"""
Playwright smoke test for the Lamware React frontend.
Tests navigation, layout, security cat, and page rendering.
Run: python3 test-playwright.py

Author: Christopher Shaiman
License: Apache 2.0
"""

import sys
from playwright.sync_api import sync_playwright

BASE_URL = "http://localhost:3000"
PASSED = 0
FAILED = 0
SCREENSHOTS = []


def check(name, condition, page=None):
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  PASS: {name}")
    else:
        FAILED += 1
        print(f"  FAIL: {name}")
        if page:
            fname = f"/tmp/fail-{name.replace(' ', '-')}.png"
            page.screenshot(path=fname)
            SCREENSHOTS.append(fname)


def test_layout_and_navigation(page):
    """Test the app shell renders with sidebar and navigation."""
    print("\n--- Layout & Navigation ---")
    page.goto(BASE_URL)
    page.wait_for_load_state("networkidle")

    # Should redirect to /analyses
    check("redirects to /analyses", "/analyses" in page.url, page)

    # Sidebar exists
    sidebar = page.locator("aside")
    check("sidebar is visible", sidebar.is_visible(), page)

    # Logo text
    check("lamware logo visible", page.locator("text=lamware").first.is_visible(), page)
    check("subtitle visible", page.locator("text=Malware Analysis Platform").is_visible(), page)

    # Navigation links
    nav_items = ["Analyses", "IOCs", "Techniques", "Statistics", "Pipeline", "Alerts", "Evasions", "Submit"]
    for item in nav_items:
        link = page.locator(f"nav >> text={item}")
        check(f"nav link '{item}' visible", link.is_visible(), page)


def test_security_cat(page):
    """Test security cat is visible and interactive."""
    print("\n--- Security Cat ---")
    page.goto(BASE_URL)
    page.wait_for_load_state("networkidle")

    # Cat ASCII art
    cat_pre = page.locator("pre").filter(has_text="/\\_/\\")
    check("security cat ASCII art visible", cat_pre.is_visible(), page)

    # Cat label
    cat_label = page.locator("text=security cat is")
    check("security cat label visible", cat_label.first.is_visible(), page)

    # Click for popover
    cat_button = page.locator("[data-testid='security-cat']")
    check("cat is clickable", cat_button.is_visible(), page)
    if cat_button.is_visible():
        cat_button.click()
        page.wait_for_timeout(500)
        # Popover should appear (absolute positioned div above cat)
        popover_visible = page.locator(".absolute.bottom-full").is_visible()
        check("click popover appears", popover_visible, page)


def test_analyses_page(page):
    """Test the analyses list page."""
    print("\n--- Analyses Page ---")
    page.goto(f"{BASE_URL}/analyses")
    page.wait_for_load_state("networkidle")

    # Page header
    check("analyses heading visible", page.locator("text=Analyses").first.is_visible(), page)

    # Search input
    search = page.locator("input[placeholder*='Search']")
    check("search input visible", search.is_visible(), page)

    # Severity dropdown
    severity_select = page.locator("select").first
    check("severity filter visible", severity_select.is_visible(), page)

    # Wait for data to load or error to appear (API may be unreachable)
    page.wait_for_timeout(5000)  # allow TanStack Query retry to complete
    has_table = page.locator("table").is_visible()
    has_empty = page.locator("text=No analyses found").is_visible()
    has_error = page.locator("text=Failed to load").is_visible()
    has_skeleton = page.locator("div.animate-pulse").first.is_visible()
    check("table, empty state, error, or loading skeleton rendered",
          has_table or has_empty or has_error or has_skeleton,
          page)


def test_page_navigation(page):
    """Test clicking through all nav links."""
    print("\n--- Page Navigation ---")

    pages = [
        ("/analyses", "Analyses"),
        ("/iocs", "IOC Browser"),
        ("/techniques", "MITRE ATT"),
        ("/stats", "Statistics"),
        ("/pipeline", "Pipeline Status"),
        ("/alerts", "Operational Health"),
        ("/evasions", "Evasion Dashboard"),
        ("/submit", "Submit Sample"),
    ]

    for path, expected_text in pages:
        page.goto(f"{BASE_URL}{path}")
        page.wait_for_load_state("networkidle")
        check(f"{path} loads and shows '{expected_text}'",
              page.locator(f"text={expected_text}").first.is_visible(),
              page)


def test_submit_page(page):
    """Test the sample submission page."""
    print("\n--- Submit Page ---")
    page.goto(f"{BASE_URL}/submit")
    page.wait_for_load_state("networkidle")

    # Drop zone
    check("drop zone visible",
          page.locator("text=Drag and drop").is_visible(), page)

    # Browse button
    check("browse button visible",
          page.locator("text=Browse files").is_visible(), page)

    # Max size note
    check("max size note visible",
          page.locator("text=Max 100 MB").is_visible(), page)


def test_analysis_detail_page(page):
    """Test analysis detail page renders (even without API data)."""
    print("\n--- Analysis Detail Page ---")
    page.goto(f"{BASE_URL}/analyses/1")
    page.wait_for_load_state("networkidle")

    # Wait for data or error (API may be unreachable)
    page.wait_for_timeout(5000)
    has_detail = page.locator("text=Back to analyses").is_visible()
    has_error = page.locator("text=Failed to load").is_visible()
    has_skeleton = page.locator("div.animate-pulse").first.is_visible()
    check("detail page renders (content, error, or loading)",
          has_detail or has_error or has_skeleton,
          page)


def test_top_bar(page):
    """Test the top bar renders."""
    print("\n--- Top Bar ---")
    page.goto(f"{BASE_URL}/analyses")
    page.wait_for_load_state("networkidle")

    # Health indicator dot
    health_dot = page.locator("header div[class*='rounded-full']")
    check("health indicator dot visible", health_dot.first.is_visible(), page)


def test_dark_theme(page):
    """Test the dark theme is applied."""
    print("\n--- Dark Theme ---")
    page.goto(BASE_URL)
    page.wait_for_load_state("networkidle")

    # Check body background color
    bg_color = page.evaluate("getComputedStyle(document.body).backgroundColor")
    # #0d1117 = rgb(13, 17, 23)
    check("dark background applied", "13" in bg_color and "17" in bg_color, page)


def main():
    global PASSED, FAILED

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1400, "height": 900})
        page = context.new_page()

        print("Lamware React Frontend — Playwright Smoke Tests")
        print(f"Testing against: {BASE_URL}")

        test_layout_and_navigation(page)
        test_security_cat(page)
        test_analyses_page(page)
        test_page_navigation(page)
        test_submit_page(page)
        test_analysis_detail_page(page)
        test_top_bar(page)
        test_dark_theme(page)

        # Take a final screenshot of the landing page
        page.goto(BASE_URL)
        page.wait_for_load_state("networkidle")
        page.screenshot(path="/tmp/lamware-react-landing.png")

        # Take screenshots of key pages
        for path in ["/techniques", "/stats", "/submit"]:
            page.goto(f"{BASE_URL}{path}")
            page.wait_for_load_state("networkidle")
            page.screenshot(path=f"/tmp/lamware-react{path.replace('/', '-')}.png")

        browser.close()

    print(f"\n{'='*50}")
    print(f"Results: {PASSED} passed, {FAILED} failed")
    if SCREENSHOTS:
        print(f"Failure screenshots: {', '.join(SCREENSHOTS)}")
    print(f"Page screenshots saved to /tmp/lamware-react-*.png")

    return 0 if FAILED == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
