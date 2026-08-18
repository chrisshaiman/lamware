# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Authentication — JWT validation against Keycloak JWKS.
#
# require_auth: FastAPI dependency returning AuthContext.
# require_role: Factory returning a dependency that enforces a realm role.

import logging
from dataclasses import dataclass, field

import httpx
import jwt
from fastapi import Depends, HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.requests import HTTPConnection

from app.config import settings

log = logging.getLogger(__name__)

# --- JWKS cache -----------------------------------------------------------

_jwks_cache: dict[str, object] = {}
_jwks_url: str = ""


async def fetch_jwks() -> None:
    """Fetch JWKS from Keycloak and populate the cache. Call on startup."""
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
    """Re-fetch JWKS if a token has an unknown kid. Returns True if found.

    Transport and HTTP errors are swallowed into False rather than propagated.
    This runs for any token carrying an unknown kid, i.e. it is reachable by an
    UNAUTHENTICATED caller, and fetch_jwks() calls raise_for_status(). Letting
    httpx's exception escape turned a Keycloak 5xx or an unreachable Keycloak
    into an HTTP 500 for what is really a failed authentication — bypassing the
    401 below and, with it, _log_failed_auth. An auth path must fail closed and
    on the record.
    """
    try:
        await fetch_jwks()
    except httpx.HTTPError as exc:
        log.error("JWKS refresh failed for kid %s: %s", kid, exc)
        return False
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
    # Unix expiry from the token's `exp`. REST re-validates on every request so it has
    # never needed this; a WebSocket validates ONCE and then holds the socket open, so
    # it is the only path that must enforce expiry itself (#208). None means the token
    # carried no exp — treated as immediately stale rather than eternal.
    exp: int | None = None


# --- Security scheme -------------------------------------------------------

bearer_scheme = HTTPBearer(auto_error=False)


# --- require_auth ----------------------------------------------------------


async def require_auth(
    request: HTTPConnection,
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> AuthContext:
    """
    FastAPI dependency: authenticate via JWT Bearer token.

    Validates signature against Keycloak JWKS, extracts user info + roles.
    Returns 401 if no token or invalid token. Logs failed attempts.
    """
    if credentials and credentials.credentials:
        try:
            return await _validate_jwt(credentials.credentials)
        except HTTPException as e:
            _log_failed_auth(request, e.detail)
            raise

    _log_failed_auth(request, "No credentials provided")
    raise HTTPException(status_code=401, detail="Authentication required")


def _log_failed_auth(request: HTTPConnection, reason: str) -> None:
    """Log failed authentication attempts for security monitoring.

    Typed on HTTPConnection, the Starlette base of BOTH Request and WebSocket, so the
    WebSocket path logs through this exact function rather than a parallel copy. Every
    attribute used below is defined on the base, so the two paths cannot drift in what
    they record — which is the failure #208 documents: REST logged failed auth and the
    three WebSocket rejection paths logged nothing, making credential stuffing on /ws/
    invisible.
    """
    client_ip = request.headers.get("x-real-ip", request.client.host if request.client else "unknown")
    user_agent = request.headers.get("user-agent", "unknown")
    log.warning(
        "Auth failed: %s | IP: %s | UA: %s | Path: %s",
        reason, client_ip, user_agent, request.url.path,
    )


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

    expected_issuer = f"{settings.keycloak_issuer_url}/realms/{settings.keycloak_realm}"

    try:
        payload = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            issuer=expected_issuer,
            audience=settings.jwt_allowed_audiences,
            # Accept a token only if its aud intersects the allowlist. lamware-web
            # stamps "lamware-api" via a Keycloak audience mapper. Prevents a
            # second realm client's token from being replayed against this API
            # (confused-deputy).
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidIssuerError:
        raise HTTPException(status_code=401, detail="Invalid token issuer")
    except jwt.InvalidAudienceError:
        raise HTTPException(status_code=401, detail="Invalid token audience")
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
        exp=payload.get("exp"),
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
