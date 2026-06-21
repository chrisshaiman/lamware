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

import sys

# --- Import the REAL app.auth, order-independently --------------------------
for _name in [m for m in sys.modules if m == "app" or m.startswith("app.")]:
    del sys.modules[_name]

import app.auth as app_auth  # noqa: E402


def test_default_allowlist_is_transitional():
    """Shipped default accepts the dedicated audience plus transitional account."""
    assert app_auth.settings.jwt_allowed_audiences == ["lamware-api", "account"]
