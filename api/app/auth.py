# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Authentication — API key via X-API-Key header.
#
# Dev mode: if settings.api_key is empty (default), all requests are allowed
# through without a key. This lets you run locally without configuring auth.
#
# Production: set LAMWARE_API_KEY in the environment file. Any request that
# sends the wrong key or omits the header gets a 401.
#
# Future upgrade: replace require_api_key with JWT/OIDC validation.
# All routers use Depends(require_api_key) so the callsite stays the same.

from fastapi import Depends, HTTPException, Security
from fastapi.security import APIKeyHeader

from app.config import settings

# auto_error=False lets us handle the missing-header case ourselves so we can
# return a clear 401 instead of FastAPI's default 403.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(api_key: str = Security(api_key_header)) -> dict:
    """
    FastAPI dependency enforcing API key authentication.

    Returns a dict with authenticated=True on success.
    Raises HTTP 401 on failure.
    """
    # Dev mode: no key configured — allow all traffic
    if not settings.api_key:
        return {"authenticated": True, "dev_mode": True}

    if not api_key or api_key != settings.api_key:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")

    return {"authenticated": True}
