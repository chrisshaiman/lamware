"""Test configuration and fixtures.

Integration tests run against the deployed API via WireGuard.
Set environment variables to configure:

    LAMWARE_TEST_URL=http://10.200.0.1:8001
    LAMWARE_TEST_API_KEY=your-api-key

Author: Christopher Shaiman
License: Apache 2.0
"""
import os

import httpx
import pytest


@pytest.fixture(scope="session")
def base_url():
    """API base URL."""
    url = os.environ.get("LAMWARE_TEST_URL", "http://10.200.0.1:8001")
    return url.rstrip("/")


@pytest.fixture(scope="session")
def api_key():
    """API key for authenticated requests."""
    key = os.environ.get("LAMWARE_TEST_API_KEY", "")
    if not key:
        pytest.skip("LAMWARE_TEST_API_KEY not set")
    return key


@pytest.fixture(scope="session")
def client(base_url):
    """HTTP client for the API."""
    return httpx.Client(base_url=base_url, timeout=30)


@pytest.fixture(scope="session")
def auth_headers(api_key):
    """Headers with API key."""
    return {"X-API-Key": api_key}
