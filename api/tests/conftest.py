"""Test configuration and fixtures.

Integration tests run against the deployed API via WireGuard.
Set environment variables to configure:

    LAMWARE_TEST_URL=http://10.200.0.1:8001
    LAMWARE_TEST_JWT=<keycloak-jwt-token>

Author: Christopher Shaiman
License: Apache 2.0
"""
import os

import httpx
import pytest


@pytest.fixture(scope="session")
def base_url():
    """API base URL for integration tests.

    Integration tests hit the live deployed API. Skip them (rather than ConnectError)
    when LAMWARE_TEST_URL is unset — mirrors the jwt_token fixture below. Set
    LAMWARE_TEST_URL=http://10.200.0.1:8001 to run them locally against the sandbox.
    """
    url = os.environ.get("LAMWARE_TEST_URL", "")
    if not url:
        pytest.skip("LAMWARE_TEST_URL not set")
    return url.rstrip("/")


@pytest.fixture(scope="session")
def client(base_url):
    """HTTP client for the API."""
    return httpx.Client(base_url=base_url, timeout=30)


@pytest.fixture(scope="session")
def jwt_token():
    """JWT token for authenticated requests. Requires Keycloak to be running."""
    token = os.environ.get("LAMWARE_TEST_JWT", "")
    if not token:
        pytest.skip("LAMWARE_TEST_JWT not set")
    return token


@pytest.fixture(scope="session")
def jwt_headers(jwt_token):
    """Headers with Bearer JWT."""
    return {"Authorization": f"Bearer {jwt_token}"}
