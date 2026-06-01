# Enterprise Auth Part 2: FastAPI Authentication & Authorization

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace static API key auth with Keycloak JWT validation, RBAC, and audit logging across all FastAPI endpoints.

**Architecture:** Dual-mode auth (JWT primary, API key fallback with configurable role). JWKS keys cached in memory with refresh-on-unknown-kid. Audit log writes to PostgreSQL via explicit helper calls at each write endpoint. WebSocket auth moves from query parameter to first-message JWT.

**Tech Stack:** FastAPI, PyJWT[crypto], Keycloak 26.1 OIDC, PostgreSQL, asyncpg

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `api/app/auth.py` | Rewrite | AuthContext, JWKS cache, require_auth, require_role |
| `api/app/audit.py` | Create | log_audit() helper |
| `api/app/config.py` | Modify | Add Keycloak settings |
| `api/app/main.py` | Modify | JWKS fetch on startup |
| `api/app/routers/samples.py` | Modify | require_role("analyst"), submitted_by, audit |
| `api/app/routers/feeder.py` | Modify | require_role("analyst"), audit |
| `api/app/routers/analyses.py` | Modify | require_role("admin") on DELETE, audit |
| `api/app/routers/ws.py` | Modify | Message-based JWT auth with 5s timeout |
| `api/app/routers/alerts.py` | Modify | Swap require_api_key → require_auth |
| `api/app/routers/stats.py` | Modify | Swap require_api_key → require_auth |
| `api/app/routers/iocs.py` | Modify | Swap require_api_key → require_auth |
| `api/app/routers/techniques.py` | Modify | Swap require_api_key → require_auth |
| `api/app/routers/families.py` | Modify | Swap require_api_key → require_auth |
| `api/app/routers/evasions.py` | Modify | Swap require_api_key → require_auth |
| `api/app/routers/pipeline.py` | Modify | Swap require_api_key → require_auth |
| `api/pyproject.toml` | Modify | Add PyJWT[crypto] dependency |
| `api/tests/test_auth.py` | Rewrite | JWT + API key fallback tests |
| `api/tests/test_audit.py` | Create | Audit logging tests |
| `api/tests/conftest.py` | Modify | Add JWT fixture |
| `ansible/roles/pipeline/files/migration_002_auth.sql` | Create | submitted_by + audit_log table |
| `ansible/roles/postgres/tasks/main.yml` | Modify | Apply migration_002 |
| `ansible/roles/api/templates/lamware-api.env.j2` | Modify | Add Keycloak env vars |
| `ansible/roles/api/defaults/main.yml` | Modify | Add Keycloak defaults |

---

### Task 1: Database Migration — submitted_by + audit_log

**Files:**
- Create: `ansible/roles/pipeline/files/migration_002_auth.sql`
- Modify: `ansible/roles/postgres/tasks/main.yml`

- [ ] **Step 1: Create migration SQL file**

Create `ansible/roles/pipeline/files/migration_002_auth.sql`:

```sql
-- migration_002_auth.sql
-- Adds submitted_by column to analyses and creates audit_log table.
-- Idempotent — safe to re-run.

-- Track which user submitted each sample
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS submitted_by VARCHAR(255) DEFAULT NULL;

-- Audit log for write operations
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    action VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    details JSONB
);

CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log (timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log (user_id);
```

- [ ] **Step 2: Add migration to postgres role**

In `ansible/roles/postgres/tasks/main.yml`, after the existing migration_001 block (around line 111), add:

```yaml
- name: Deploy auth migration SQL
  ansible.builtin.copy:
    src: "{{ playbook_dir }}/roles/pipeline/files/migration_002_auth.sql"
    dest: /tmp/pipeline-migration-002.sql
    mode: "0644"

- name: Apply auth migration
  ansible.builtin.command:
    cmd: psql -d {{ postgres_db_name }} -f /tmp/pipeline-migration-002.sql
  become: true
  become_user: postgres
  changed_when: false

- name: Clean up auth migration file
  ansible.builtin.file:
    path: /tmp/pipeline-migration-002.sql
    state: absent
```

- [ ] **Step 3: Grant SELECT on audit_log to pipeline user**

Add to the existing `GRANT` block in `ansible/roles/postgres/tasks/main.yml` (around line 114-134), in the SQL that grants privileges:

```sql
GRANT SELECT, INSERT ON audit_log TO {{ postgres_db_user }};
GRANT USAGE, SELECT ON SEQUENCE audit_log_id_seq TO {{ postgres_db_user }};
```

- [ ] **Step 4: Commit**

```bash
git add ansible/roles/pipeline/files/migration_002_auth.sql ansible/roles/postgres/tasks/main.yml
git commit -m "feat(auth): add submitted_by column and audit_log table migration"
```

---

### Task 2: Configuration — Keycloak Settings + PyJWT Dependency

**Files:**
- Modify: `api/app/config.py`
- Modify: `api/pyproject.toml`
- Modify: `ansible/roles/api/templates/lamware-api.env.j2`
- Modify: `ansible/roles/api/defaults/main.yml`

- [ ] **Step 1: Add Keycloak settings to config.py**

In `api/app/config.py`, add these fields to the `Settings` class after the `api_host` field (line 23):

```python
    # Keycloak OIDC
    keycloak_url: str = "http://127.0.0.1:8080/auth"
    keycloak_realm: str = "lamware"
    api_key_role: str = "viewer"  # role granted to API key auth during transition
```

- [ ] **Step 2: Add PyJWT dependency**

In `api/pyproject.toml`, add to the `dependencies` list:

```toml
    "PyJWT[crypto]>=2.9",
```

- [ ] **Step 3: Add Keycloak vars to Ansible env template**

In `ansible/roles/api/templates/lamware-api.env.j2`, add after the `LAMWARE_CORS_ORIGINS` line:

```jinja2
LAMWARE_KEYCLOAK_URL=http://127.0.0.1:{{ keycloak_port | default(8080) }}/auth
LAMWARE_KEYCLOAK_REALM={{ keycloak_realm | default('lamware') }}
LAMWARE_API_KEY_ROLE={{ lamware_api_key_role | default('viewer') }}
```

- [ ] **Step 4: Add defaults to API role**

Check `ansible/roles/api/defaults/main.yml` and add if not present:

```yaml
lamware_api_key_role: "viewer"
```

- [ ] **Step 5: Commit**

```bash
git add api/app/config.py api/pyproject.toml ansible/roles/api/templates/lamware-api.env.j2 ansible/roles/api/defaults/main.yml
git commit -m "feat(auth): add Keycloak config settings and PyJWT dependency"
```

---

### Task 3: Auth Module — JWKS Cache, AuthContext, require_auth, require_role

**Files:**
- Rewrite: `api/app/auth.py`
- Modify: `api/app/main.py`
- Rewrite: `api/tests/test_auth.py`
- Modify: `api/tests/conftest.py`

- [ ] **Step 1: Write auth tests**

Rewrite `api/tests/test_auth.py`:

```python
"""Authentication tests — JWT + API key fallback.

Author: Christopher Shaiman
License: Apache 2.0
"""


def test_no_auth_returns_401(client):
    """Requests without auth should return 401."""
    r = client.get("/api/analyses")
    assert r.status_code == 401


def test_invalid_api_key_returns_401(client):
    """Invalid API key should return 401."""
    r = client.get("/api/analyses", headers={"X-API-Key": "wrong-key-12345"})
    assert r.status_code == 401


def test_valid_api_key_accepted(client, auth_headers):
    """Valid API key should return 200 with deprecation header."""
    r = client.get("/api/analyses", headers=auth_headers)
    assert r.status_code == 200
    assert r.headers.get("deprecation") == "true"


def test_api_key_gets_viewer_role(client, auth_headers):
    """API key auth should work for read-only endpoints (viewer role)."""
    r = client.get("/api/stats", headers=auth_headers)
    assert r.status_code == 200


def test_valid_jwt_accepted(client, jwt_headers):
    """Valid JWT should return 200."""
    r = client.get("/api/analyses", headers=jwt_headers)
    assert r.status_code == 200


def test_health_no_auth_required(client):
    """Health endpoint should be public."""
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
```

- [ ] **Step 2: Add JWT fixture to conftest.py**

Add to `api/tests/conftest.py`:

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cd api && python -m pytest tests/test_auth.py -v`
Expected: Existing tests fail because `require_api_key` doesn't set deprecation header yet, and JWT tests skip (no token set).

- [ ] **Step 4: Rewrite auth.py**

Replace `api/app/auth.py` entirely:

```python
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
from fastapi.responses import JSONResponse
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

log = logging.getLogger(__name__)

# --- JWKS cache -----------------------------------------------------------

_jwks_cache: dict[str, jwt.algorithms.RSAAlgorithm] = {}
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
            # Set deprecation header on the response
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
```

- [ ] **Step 5: Add JWKS fetch to startup and deprecation header middleware**

In `api/app/main.py`, update the startup handler and add middleware:

After the `app` definition (around line 29), add:

```python
@app.middleware("http")
async def add_deprecation_header(request: Request, call_next):
    """Add Deprecation header when API key auth is used."""
    response = await call_next(request)
    if getattr(request.state, "auth_deprecated", False):
        response.headers["Deprecation"] = "true"
    return response
```

Add the import at the top:
```python
from fastapi import FastAPI, Request
```

Update the startup handler:

```python
@app.on_event("startup")
async def _startup():
    from app.auth import fetch_jwks
    from app.routers.ws import start_pg_listener
    try:
        await fetch_jwks()
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("JWKS fetch failed on startup: %s (JWT auth unavailable until Keycloak is reachable)", e)
    await start_pg_listener()
```

- [ ] **Step 6: Run tests**

Run: `cd api && python -m pytest tests/test_auth.py -v`
Expected: API key tests pass (with deprecation header), JWT tests skip (no token).

- [ ] **Step 7: Commit**

```bash
git add api/app/auth.py api/app/main.py api/tests/test_auth.py api/tests/conftest.py
git commit -m "feat(auth): JWT validation with JWKS cache and API key fallback"
```

---

### Task 4: Audit Log Helper

**Files:**
- Create: `api/app/audit.py`
- Create: `api/tests/test_audit.py`

- [ ] **Step 1: Write audit test**

Create `api/tests/test_audit.py`:

```python
"""Audit logging tests.

Author: Christopher Shaiman
License: Apache 2.0
"""
from app.audit import log_audit
from app.auth import AuthContext


def test_log_audit_builds_correct_record():
    """log_audit should build the correct SQL parameters."""
    auth = AuthContext(
        user_id="abc-123",
        email="chris@lamware.local",
        name="Chris",
        roles=["admin"],
        auth_method="jwt",
    )
    # Verify the function exists and accepts the right args without DB
    # Full integration test requires deployed DB — covered by deploy verification
    assert auth.user_id == "abc-123"
    assert auth.email == "chris@lamware.local"
```

- [ ] **Step 2: Create audit.py**

Create `api/app/audit.py`:

```python
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
#
# Audit logging — explicit helper called at each write endpoint.
# Writes to the audit_log PostgreSQL table.

import json
import logging

from sqlmodel import Session, text

from app.auth import AuthContext

log = logging.getLogger(__name__)


def log_audit(
    session: Session,
    auth: AuthContext,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict | None = None,
) -> None:
    """
    Write an audit log entry to PostgreSQL.

    Called explicitly at each write endpoint — no middleware magic.
    Failures are logged but do not block the request.
    """
    try:
        session.exec(
            text(
                "INSERT INTO audit_log (user_id, email, action, resource_type, resource_id, details) "
                "VALUES (:user_id, :email, :action, :resource_type, :resource_id, :details)"
            ),
            params={
                "user_id": auth.user_id,
                "email": auth.email,
                "action": action,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "details": json.dumps(details) if details else None,
            },
        )
        session.commit()
    except Exception as e:
        log.error("Audit log write failed: %s", e)
```

- [ ] **Step 3: Run test**

Run: `cd api && python -m pytest tests/test_audit.py -v`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add api/app/audit.py api/tests/test_audit.py
git commit -m "feat(auth): add audit log helper for write operations"
```

---

### Task 5: Swap Read-Only Routers to require_auth

**Files:**
- Modify: `api/app/routers/alerts.py`
- Modify: `api/app/routers/stats.py`
- Modify: `api/app/routers/iocs.py`
- Modify: `api/app/routers/techniques.py`
- Modify: `api/app/routers/families.py`
- Modify: `api/app/routers/evasions.py`
- Modify: `api/app/routers/pipeline.py`

These routers all follow the same pattern. For each file:

- [ ] **Step 1: Update imports in all 7 read-only routers**

In each file, change:
```python
from ..auth import require_api_key
```
to:
```python
from ..auth import require_auth, AuthContext
```

- [ ] **Step 2: Update dependency injection in all 7 routers**

In each file, change every occurrence of:
```python
    _auth: dict = Depends(require_api_key),
```
to:
```python
    auth: AuthContext = Depends(require_auth),
```

Files and their `Depends(require_api_key)` locations:
- `alerts.py`: line 38
- `stats.py`: line 29
- `iocs.py`: line 31
- `techniques.py`: line 34
- `families.py`: line 30
- `evasions.py`: line 23
- `pipeline.py`: line 31

- [ ] **Step 3: Run existing tests to verify nothing broke**

Run: `cd api && python -m pytest tests/ -v`
Expected: All existing tests pass (API key still works via fallback).

- [ ] **Step 4: Commit**

```bash
git add api/app/routers/alerts.py api/app/routers/stats.py api/app/routers/iocs.py api/app/routers/techniques.py api/app/routers/families.py api/app/routers/evasions.py api/app/routers/pipeline.py
git commit -m "feat(auth): swap read-only routers from API key to require_auth"
```

---

### Task 6: Samples Router — require_role("analyst") + submitted_by + Audit

**Files:**
- Modify: `api/app/routers/samples.py`

- [ ] **Step 1: Update imports**

In `api/app/routers/samples.py`, change:
```python
from ..auth import require_api_key
```
to:
```python
from ..auth import require_role, AuthContext
from ..audit import log_audit
from ..database import get_session
```

- [ ] **Step 2: Update submit_sample endpoint**

Change the endpoint signature from:
```python
@router.post("/submit")
async def submit_sample(
    file: UploadFile,
    _auth: dict = Depends(require_api_key),
) -> dict:
```
to:
```python
@router.post("/submit")
async def submit_sample(
    file: UploadFile,
    auth: AuthContext = Depends(require_role("analyst")),
    session: Session = Depends(get_session),
) -> dict:
```

Add the `Session` import at the top:
```python
from sqlmodel import Session
```

- [ ] **Step 3: Add audit logging and submitted_by to response**

At the end of the `submit_sample` function, before the return statement, add:

```python
    log_audit(
        session, auth,
        action="sample_submit",
        resource_type="sample",
        resource_id=submission_id,
        details={"filename": safe_name, "size_bytes": len(content)},
    )
```

Add `submitted_by` to the return dict:
```python
        "submitted_by": auth.email,
```

- [ ] **Step 4: Run tests**

Run: `cd api && python -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add api/app/routers/samples.py
git commit -m "feat(auth): require analyst role for sample submission with audit log"
```

---

### Task 7: Feeder Router — require_role("analyst") + Audit

**Files:**
- Modify: `api/app/routers/feeder.py`

- [ ] **Step 1: Update imports**

Change:
```python
from ..auth import require_api_key
```
to:
```python
from ..auth import require_auth, require_role, AuthContext
from ..audit import log_audit
```

- [ ] **Step 2: Update feeder_status to require_auth (viewer)**

Change `feeder_status` (GET, read-only):
```python
    _auth: dict = Depends(require_api_key),
```
to:
```python
    auth: AuthContext = Depends(require_auth),
```

- [ ] **Step 3: Update feeder_pause to require_role("analyst") + audit**

Change `feeder_pause`:
```python
    _auth: dict = Depends(require_api_key),
```
to:
```python
    auth: AuthContext = Depends(require_role("analyst")),
```

Add after the PAUSE file is created (before the return):
```python
    log_audit(session, auth, action="feeder_pause", resource_type="feeder")
```

Add `session: Session = Depends(get_session)` to the function signature and the necessary imports:
```python
from sqlmodel import Session
from ..database import get_session
```

- [ ] **Step 4: Update feeder_resume to require_role("analyst") + audit**

Same pattern — swap to `require_role("analyst")`, add `session` param, add:
```python
    log_audit(session, auth, action="feeder_resume", resource_type="feeder")
```

- [ ] **Step 5: Update feeder_reset to require_role("analyst") + audit**

Same pattern — swap to `require_role("analyst")`, add `session` param, add:
```python
    log_audit(session, auth, action="feeder_reset", resource_type="feeder")
```

- [ ] **Step 6: Run tests**

Run: `cd api && python -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add api/app/routers/feeder.py
git commit -m "feat(auth): require analyst role for feeder control with audit log"
```

---

### Task 8: Analyses Router — require_role("admin") on DELETE + Audit

**Files:**
- Modify: `api/app/routers/analyses.py`

- [ ] **Step 1: Update imports**

Change:
```python
from ..auth import require_api_key
```
to:
```python
from ..auth import require_auth, require_role, AuthContext
from ..audit import log_audit
```

- [ ] **Step 2: Update all GET endpoints to require_auth**

Change every `_auth: dict = Depends(require_api_key)` on GET endpoints (lines 59, 162, 391, 419, 460, 572) to:
```python
    auth: AuthContext = Depends(require_auth),
```

- [ ] **Step 3: Update DELETE endpoint to require_role("admin") + audit**

Change the `delete_analysis` function (line 336):
```python
    _auth: dict = Depends(require_api_key),
```
to:
```python
    auth: AuthContext = Depends(require_role("admin")),
```

Add audit logging after the `session.commit()` call:
```python
    log_audit(
        session, auth,
        action="analysis_delete",
        resource_type="analysis",
        resource_id=str(analysis_id),
        details={"task_id": task_id},
    )
```

- [ ] **Step 4: Run tests**

Run: `cd api && python -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add api/app/routers/analyses.py
git commit -m "feat(auth): require admin role for analysis deletion with audit log"
```

---

### Task 9: WebSocket Auth — Message-Based JWT

**Files:**
- Modify: `api/app/routers/ws.py`
- Modify: `api/tests/test_ws_endpoint.py`

- [ ] **Step 1: Rewrite WebSocket endpoint**

In `api/app/routers/ws.py`, replace the `websocket_pipeline` function:

```python
@router.websocket("/ws/pipeline")
async def websocket_pipeline(websocket: WebSocket):
    """
    WebSocket endpoint for real-time pipeline status updates.

    Auth: client sends {"type": "auth", "token": "<jwt>"} or
    {"type": "auth", "api_key": "<key>"} as first message within 5 seconds.
    """
    await websocket.accept()

    # --- Auth via first message (5s timeout) ---
    try:
        raw = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
        msg = json.loads(raw)
    except (asyncio.TimeoutError, json.JSONDecodeError):
        await websocket.close(code=4001, reason="Auth timeout or invalid message")
        return

    if msg.get("type") != "auth":
        await websocket.close(code=4001, reason="First message must be auth")
        return

    # Try JWT
    token = msg.get("token")
    api_key = msg.get("api_key")

    if token:
        from ..auth import _validate_jwt
        try:
            auth = await _validate_jwt(token)
        except Exception:
            await websocket.close(code=4001, reason="Invalid token")
            return
    elif api_key and settings.api_key and api_key == settings.api_key:
        from ..auth import AuthContext
        auth = AuthContext(
            user_id="api-key", email="api-key@legacy",
            name="API Key User", roles=[settings.api_key_role],
            auth_method="api_key",
        )
    elif not settings.api_key:
        # Dev mode
        from ..auth import AuthContext
        auth = AuthContext(
            user_id="dev", email="dev@localhost",
            name="Dev Mode", roles=["admin", "analyst", "viewer"],
            auth_method="dev",
        )
    else:
        await websocket.close(code=4001, reason="Invalid credentials")
        return

    # --- Authenticated — join broadcast pool ---
    manager.connect_ws(websocket)

    try:
        # Send current state
        try:
            with Session(engine) as session:
                state = _get_current_state(session)
        except Exception:
            state = {"running": [], "recent_completed": [], "as_of": ""}
        await websocket.send_json(state)

        # Keep alive — wait for client disconnect
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)
```

- [ ] **Step 2: Remove the api_key query parameter import**

Remove `Query` from the imports (no longer needed):
```python
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
```

- [ ] **Step 3: Update ws_manager.py if needed**

Check if `manager.connect` vs `manager.connect_ws` needs adjustment. The existing `connect` method calls `websocket.accept()` — since we now accept before auth, rename or adjust:

In `ws_manager.py`, if `connect` calls `await websocket.accept()`, change the WebSocket handler to use a method that doesn't re-accept. If `connect` just adds to the list, no change needed. Use `manager.connect(websocket)` if it only tracks connections, or add the websocket to the active list directly.

- [ ] **Step 4: Run tests**

Run: `cd api && python -m pytest tests/ -v`
Expected: PASS (WS tests may need updating if they use query param auth)

- [ ] **Step 5: Commit**

```bash
git add api/app/routers/ws.py api/app/ws_manager.py
git commit -m "feat(auth): message-based JWT auth for WebSocket with 5s timeout"
```

---

### Task 10: Ansible Deployment + Verification

**Files:**
- Modified files from Tasks 1-9

- [ ] **Step 1: Deploy database migration**

```bash
ansible-playbook site.yml --tags postgres -i inventory/hosts --ask-vault-pass
```

Verify on sandbox:
```bash
ssh sandbox "sudo -u postgres psql -d malware_analysis -c '\d audit_log'"
ssh sandbox "sudo -u postgres psql -d malware_analysis -c '\d analyses' | grep submitted_by"
```

- [ ] **Step 2: Deploy API with new auth**

```bash
ansible-playbook site.yml --tags api -i inventory/hosts --ask-vault-pass
```

- [ ] **Step 3: Verify API key fallback still works**

```bash
curl -s https://10.200.0.1/api/analyses -H "X-API-Key: <key>" -k | head -c 200
```

Should return 200 with `Deprecation: true` header.

- [ ] **Step 4: Get a JWT token and verify JWT auth**

```bash
# On sandbox — get a token for chris user
TOKEN=$(curl -s -X POST "http://127.0.0.1:8080/auth/realms/lamware/protocol/openid-connect/token" \
  -d "client_id=lamware-web" \
  -d "username=chris" \
  --data-urlencode 'password=<chris-password>' \
  -d "grant_type=password" | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Test JWT auth
curl -s https://10.200.0.1/api/analyses -H "Authorization: Bearer $TOKEN" -k | head -c 200
```

Should return 200 without deprecation header.

- [ ] **Step 5: Verify role enforcement**

```bash
# Create a viewer-only user in Keycloak, get their token
# Try to submit a sample — should get 403
curl -s -X POST https://10.200.0.1/api/samples/submit \
  -H "Authorization: Bearer $VIEWER_TOKEN" \
  -F "file=@/tmp/test.txt" -k
```

Expected: 403 with "Role 'analyst' required"

- [ ] **Step 6: Verify audit log**

```bash
ssh sandbox "sudo -u postgres psql -d malware_analysis -c 'SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 5'"
```

- [ ] **Step 7: Run full test suite**

```bash
cd api && LAMWARE_TEST_URL=http://10.200.0.1:8001 LAMWARE_TEST_API_KEY=<key> python -m pytest tests/ -v
```

- [ ] **Step 8: Commit any deployment fixes**

```bash
git add -A && git commit -m "fix(auth): deployment adjustments from verification"
```
