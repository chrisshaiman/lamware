# Enterprise Auth Part 2: FastAPI Authentication & Authorization

**Date:** 2026-05-31
**Author:** Christopher Shaiman
**Status:** Approved
**Depends on:** Part 1 (Keycloak infrastructure) — merged PR #80

---

## Overview

Replace the static API key authentication in the FastAPI backend with JWT-based
authentication validated against Keycloak, role-based access control (RBAC), and
audit logging for write operations. Maintain backwards compatibility with the
existing API key during the transition period.

## Auth Module (`api/app/auth.py`)

### AuthContext

All auth dependencies return an `AuthContext` dataclass:

```python
@dataclass
class AuthContext:
    user_id: str        # Keycloak 'sub' claim (UUID)
    email: str          # From JWT
    name: str           # From JWT
    roles: list[str]    # Realm roles from JWT
    auth_method: str    # "jwt" or "api_key"
```

### Dual-Mode Authentication (`require_auth`)

The `require_auth` FastAPI dependency checks in order:

1. **`Authorization: Bearer <jwt>`** — Validate JWT signature against Keycloak
   JWKS endpoint. Extract user info and realm roles from claims. Return
   `AuthContext` with `auth_method="jwt"`.
2. **`X-API-Key` header** — Validate against configured key. Return `AuthContext`
   with a configurable role (default: `viewer`, controlled via
   `LAMWARE_API_KEY_ROLE` env var). Add `Deprecation: true` response header.
3. **Neither present** — Return 401 Unauthorized.

### JWKS Caching

- Fetch Keycloak's JWKS on FastAPI startup
- Cache keys in memory keyed by `kid`
- Re-fetch only when a JWT arrives with an unknown `kid` (handles key rotation)
- JWKS URL: `http://127.0.0.1:{keycloak_port}/auth/realms/lamware/protocol/openid-connect/certs`

### Role Enforcement (`require_role`)

Factory function returning a FastAPI dependency:

```python
def require_role(role: str) -> Callable:
    """Returns a dependency that enforces the given role."""
```

Wraps `require_auth`, checks `role in auth_context.roles`, returns 403 Forbidden
if the role is missing.

## Route Protection Map

| Route | Method | Minimum Role | Rationale |
|---|---|---|---|
| `/health` | GET | **public** | Systemd health checks, returns only `{"status": "ok"}` |
| `/api/analyses/*` | GET | viewer | Read-only |
| `/api/iocs/*` | GET | viewer | Read-only |
| `/api/techniques/*` | GET | viewer | Read-only |
| `/api/families/*` | GET | viewer | Read-only |
| `/api/stats/*` | GET | viewer | Read-only |
| `/api/evasions/*` | GET | viewer | Read-only |
| `/api/alerts/*` | GET | viewer | Read-only |
| `/api/pipeline/status` | GET | viewer | Read-only |
| `/api/samples/submit` | POST | analyst | Write operation |
| `/api/feeder/*` | POST | analyst | Feeder control |
| `/api/analyses/*` | DELETE | admin | Destructive |
| `/ws/pipeline` | WS | viewer | Real-time updates |

**Pattern:** Viewers read, analysts write, admins delete.

## WebSocket Auth

Replace query parameter auth (`?api_key=<key>`) with message-based JWT auth:

1. Client connects to `/ws/pipeline` — no auth required on connect
2. Client sends `{"type": "auth", "token": "<jwt>"}` as first message
3. Server validates JWT, assigns roles from token
4. **Timeout:** If no auth message within 5 seconds, close with code 4001
5. **Invalid token:** Close with code 4001
6. **Transition fallback:** `{"type": "auth", "api_key": "<key>"}` also accepted,
   grants configurable role (same as HTTP fallback)

This avoids putting tokens in URLs (logged in access logs and browser history).

## Database Changes

Applied via raw SQL in the postgres Ansible role (Alembic migration framework
is a backlog item for future schema changes).

### `submitted_by` column on `analyses` table

```sql
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS submitted_by VARCHAR(255) DEFAULT NULL;
```

- Populated on new sample submissions from `AuthContext.email`
- Existing rows remain NULL (pre-auth submissions)
- Not a foreign key — decoupled from Keycloak user store

### `audit_log` table

```sql
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

### Audit Logging

A `log_audit()` helper function called explicitly at each write endpoint:

```python
async def log_audit(
    db: AsyncSession,
    auth: AuthContext,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict | None = None,
) -> None:
```

**Logged actions:**

| Action | Resource Type | When |
|---|---|---|
| `sample_submit` | `sample` | POST `/api/samples/submit` |
| `feeder_pause` | `feeder` | POST feeder pause |
| `feeder_resume` | `feeder` | POST feeder resume |
| `feeder_reset` | `feeder` | POST feeder reset |
| `analysis_delete` | `analysis` | DELETE `/api/analyses/{id}` |

**Not logged:** Read-only operations, WebSocket connections, health checks.

The `details` JSONB field captures context (e.g., filename, SHA-256 hash,
analysis ID).

## Configuration

New environment variables in `lamware-api.env`:

| Variable | Purpose | Default |
|---|---|---|
| `KEYCLOAK_URL` | Keycloak base URL | `http://127.0.0.1:8080/auth` |
| `KEYCLOAK_REALM` | Realm name | `lamware` |
| `LAMWARE_API_KEY_ROLE` | Role granted to API key auth | `viewer` |

Existing `LAMWARE_API_KEY` remains — empty string disables API key auth entirely.

## Dependencies

New Python package: `PyJWT[crypto]` (for RS256 JWT validation + JWKS fetching).

## Files Changed

| File | Change |
|---|---|
| `api/app/auth.py` | Rewrite: JWT validation, JWKS cache, `AuthContext`, `require_role` |
| `api/app/main.py` | Add JWKS fetch on startup |
| `api/app/routers/*.py` | Swap `require_api_key` → `require_auth` / `require_role` |
| `api/app/routers/ws.py` | Message-based auth with 5s timeout |
| `api/app/routers/samples.py` | Add `submitted_by` to analysis creation |
| `api/app/audit.py` | New: `log_audit()` helper |
| `ansible/roles/postgres/tasks/main.yml` | Add `submitted_by` column + `audit_log` table |
| `ansible/roles/api/templates/lamware-api.env.j2` | Add Keycloak config vars |
| `api/requirements.txt` | Add `PyJWT[crypto]` |
