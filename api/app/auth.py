# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Authentication — JWT validation against Keycloak + API key fallback.
#
# require_auth: FastAPI dependency returning AuthContext. Checks Bearer JWT
# first, then X-API-Key header as a fallback (with deprecation warning).
#
# require_role: Factory returning a dependency that enforces a realm role.

import logging
from dataclasses import dataclass, field

import jwt
from fastapi import Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

log = logging.getLogger(__name__)

# --- JWKS cache -----------------------------------------------------------

_jwks_cache: dict[str, object] = {}
_jwks_url: str = ""


async def fetch_jwks() -> None:
    """Fetch JWKS from Keycloak and populate the cache. Call on startup."""
    import httpx

    global _jwks_url
    _jwks_url = (
        f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"
        "/protocol/openid-connect/certs"
    )
    async with httpx.AsyncClient() as client:
        r = await client.get(_jwks_url)
        r.raise_for_status()
        jwks = r.json()

    _jwks_cache.clear()
    for key_data in jwks.get("keys", []):
        kid = key_data.get("kid")
        if kid:
            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)
            _jwks_cache[kid] = public_key

    log.info("JWKS loaded: %d keys from %s", len(_jwks_cache), _jwks_url)


async def _refresh_jwks_for_kid(kid: str) -> bool:
    """Re-fetch JWKS if a token has an unknown kid. Returns True if found."""
    await fetch_jwks()
    return kid in _jwks_cache


# --- AuthContext -----------------------------------------------------------


@dataclass
class AuthContext:
    """Authenticated user context returned by all auth dependencies."""

    user_id: str
    email: str
    name: str
    roles: list[str] = field(default_factory=list)
    auth_method: str = "jwt"


# --- Security schemes (auto_error=False for manual handling) ---------------

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# --- require_auth ----------------------------------------------------------


async def require_auth(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
    api_key: str | None = Security(api_key_header),
) -> AuthContext:
    """
    FastAPI dependency: authenticate via JWT (preferred) or API key (fallback).

    JWT: Validates signature against Keycloak JWKS, extracts user info + roles.
    API key: Returns AuthContext with configurable role + deprecation header.
    """
    # --- Try JWT first ---
    if credentials and credentials.credentials:
        return await _validate_jwt(credentials.credentials)

    # --- Fall back to API key ---
    if api_key and settings.api_key:
        if api_key == settings.api_key:
            request.state.auth_deprecated = True
            return AuthContext(
                user_id="api-key",
                email="api-key@legacy",
                name="API Key User",
                roles=[settings.api_key_role],
                auth_method="api_key",
            )

    # --- Dev mode: no key configured, allow all ---
    if not settings.api_key:
        return AuthContext(
            user_id="dev",
            email="dev@localhost",
            name="Dev Mode",
            roles=["admin", "analyst", "viewer"],
            auth_method="dev",
        )

    raise HTTPException(status_code=401, detail="Invalid or missing authentication")


async def _validate_jwt(token: str) -> AuthContext:
    """Decode and validate a JWT against cached Keycloak JWKS keys."""
    try:
        header = jwt.get_unverified_header(token)
    except jwt.DecodeError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}") from e

    kid = header.get("kid")
    if not kid:
        raise HTTPException(status_code=401, detail="Token missing kid header")

    # Look up signing key, refresh if unknown
    public_key = _jwks_cache.get(kid)
    if public_key is None:
        if not await _refresh_jwks_for_kid(kid):
            raise HTTPException(status_code=401, detail="Unknown signing key")
        public_key = _jwks_cache[kid]

    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            options={"verify_aud": False},
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {e}")

    # Extract realm roles from Keycloak token structure
    realm_access = payload.get("realm_access", {})
    roles = realm_access.get("roles", [])

    return AuthContext(
        user_id=payload.get("sub", ""),
        email=payload.get("email", ""),
        name=payload.get("name", payload.get("preferred_username", "")),
        roles=roles,
        auth_method="jwt",
    )


# --- require_role ----------------------------------------------------------


def require_role(role: str):
    """Factory: returns a FastAPI dependency that enforces a realm role."""

    async def _check_role(
        auth: AuthContext = Depends(require_auth),
    ) -> AuthContext:
        if role not in auth.roles:
            raise HTTPException(
                status_code=403,
                detail=f"Role '{role}' required",
            )
        return auth

    return _check_role
