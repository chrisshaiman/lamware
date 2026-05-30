# Enterprise Authentication Design

## Overview

Replace lamware's static API key authentication with enterprise-grade SSO using a self-hosted Keycloak identity broker. Supports OIDC and SAML from any IdP (Entra ID, Okta, etc.) plus local user accounts. Three-tier RBAC (admin, analyst, viewer) with admin-invite provisioning.

## Architecture

```
Browser -> nginx (443)
  |-- /auth/*  -> Keycloak (8080) -- login, token exchange, SAML endpoints
  |-- /api/*   -> FastAPI (8001)  -- validates JWT from Keycloak
  |-- /ws/*    -> FastAPI (8001)  -- validates JWT from Keycloak
  \-- /*       -> React SPA      -- stores JWT in memory, sends as Bearer token
```

### Auth Flow

1. User visits lamware dashboard
2. React auth guard detects no valid token
3. Redirect to Keycloak login page (hosted at `/auth/`)
4. User authenticates (local credentials or SSO via Entra ID/other IdP)
5. Keycloak issues JWT access token + refresh token via authorization code flow with PKCE
6. React stores tokens in memory (not localStorage)
7. All API calls include `Authorization: Bearer <token>`
8. FastAPI validates JWT signature against Keycloak's JWKS endpoint
9. Token refresh handled silently by keycloak-js library

### Components

**Keycloak (new)**
- Root Podman container managed by systemd (same pattern as LiteLLM)
- Image: `quay.io/keycloak/keycloak:26.1` (pinned version)
- Dedicated PostgreSQL database: `keycloak` on existing instance
- Listens on `127.0.0.1:8080`, proxied by nginx at `/auth/*`
- Production mode with `--optimized`
- ~512MB RAM

**Keycloak Realm Configuration**
- Realm: `lamware`
- Client: `lamware-web` (public client, authorization code + PKCE)
- Roles: `admin`, `analyst`, `viewer`
- Default role for new users: `viewer`
- Identity providers: Entra ID (OIDC), extensible to any OIDC/SAML IdP
- Local user store: admin accounts, service accounts, guest analysts

## FastAPI Changes

### Auth Dependency

Replace `require_api_key` with `require_auth`:

```python
@dataclass
class AuthContext:
    user_id: str        # Keycloak subject
    email: str
    name: str
    roles: list[str]    # ["admin", "analyst", "viewer"]

async def require_auth(authorization: str = Header(...)) -> AuthContext:
    """Validate JWT from Keycloak, extract user identity and roles."""
    token = authorization.removeprefix("Bearer ")
    claims = validate_jwt(token, jwks_url=settings.keycloak_jwks_url)
    return AuthContext(
        user_id=claims["sub"],
        email=claims.get("email", ""),
        name=claims.get("preferred_username", ""),
        roles=claims.get("realm_access", {}).get("roles", []),
    )

def require_role(role: str):
    """Factory for role-specific auth dependencies."""
    async def check(auth: AuthContext = Depends(require_auth)) -> AuthContext:
        if role not in auth.roles:
            raise HTTPException(403, f"Role '{role}' required")
        return auth
    return check
```

All existing `Depends(require_api_key)` callsites change to `Depends(require_auth)` or `Depends(require_role("analyst"))`.

### Endpoint Permissions

| Role | Permissions |
|------|------------|
| viewer | Read analyses, IOCs, techniques, stats, pipeline status, download reports |
| analyst | Everything viewer + submit samples, control auto-feeder (pause/resume/reset) |
| admin | Everything analyst + delete analyses, user management (via Keycloak admin) |

### WebSocket Auth

Switch from query parameter to first-message authentication:

1. Client connects to `/ws/pipeline` (no query parameter)
2. Client sends `{"type": "auth", "token": "<jwt>"}` as first message
3. Server validates JWT, accepts or closes connection
4. Subsequent messages flow normally

### Static API Key Deprecation (Phase 1)

During transition period, `X-API-Key` header is still accepted as fallback:
- Logged as warning: "Static API key auth is deprecated"
- Gets `viewer` role only (no submit, no feeder control, no delete)
- Phase 2 (backlogged): Remove static key entirely, replace with Keycloak service accounts (client credentials grant)

## React Frontend Changes

### Auth Provider

- Library: `keycloak-js` (official Keycloak adapter)
- `AuthProvider` context wraps entire app in `main.tsx`
- Tokens stored in memory only (not localStorage — XSS mitigation)
- Silent token refresh via iframe (keycloak-js handles automatically)
- Short-lived access tokens: 5 minutes (configurable in Keycloak)
- Refresh tokens: 30 minutes

### Protected Routes

All routes wrapped in auth guard:
- No valid token: redirect to Keycloak login
- Valid token: render page
- No custom login page — Keycloak provides themed login UI

### API Client Update

`api-client.ts` changes:
- Remove `VITE_API_KEY` env var usage
- Read token from auth context
- Interceptor adds `Authorization: Bearer <token>`
- 401 response triggers token refresh or re-login

### Role-Aware UI

Components check user roles:
- `/submit` page: hidden for viewers
- Auto-feeder controls (pause/resume/reset): hidden for viewers
- Delete buttons: hidden for non-admins
- All read-only pages: visible to everyone

### User Indicator

Top bar shows:
- Logged-in user name or email
- Role badge
- Logout button

## nginx Changes

Add Keycloak proxy:

```nginx
location /auth/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_buffer_size 128k;
    proxy_buffers 4 256k;
    proxy_busy_buffers_size 256k;
}
```

Larger buffers needed for Keycloak's SAML responses and token exchanges.

## Database Changes

### New Tables (Keycloak-managed)

Keycloak manages its own schema in the `keycloak` PostgreSQL database. No changes to lamware's `malware_analysis` database schema for auth.

### Audit Trail

Add `submitted_by` column to `analyses` table:

```sql
ALTER TABLE analyses ADD COLUMN submitted_by TEXT;
```

Populated from `AuthContext.email` when a sample is submitted. NULL for auto-feeder submissions. Enables "who submitted what" queries.

## Ansible Implementation

### New Role: `keycloak`

```
roles/keycloak/
  defaults/main.yml         # keycloak_image, port, admin creds
  tasks/main.yml             # pull image, deploy config, systemd
  templates/
    keycloak.service.j2      # systemd unit (root Podman)
    keycloak.env.j2          # DB connection, admin creds
  handlers/main.yml          # restart handler
```

### Modified Roles

- `postgres` — create `keycloak` database + user
- `frontend` — nginx config adds `/auth/` proxy, rebuild with keycloak-js dependency
- `api` — deploy updated auth.py with JWT validation

### Site.yml Ordering

Keycloak after PostgreSQL, before API:

```yaml
- role: keycloak
  tags: [keycloak]
```

## Security Properties

- **Authorization code flow with PKCE** — browser never sees client secret
- **Tokens in memory only** — XSS can't steal persisted tokens
- **JWT signature validation** — FastAPI validates against Keycloak JWKS endpoint
- **Short-lived access tokens** — 5 min default, limits exposure window
- **WireGuard remains** — network-level access control stays as defense in depth
- **Keycloak handles credentials** — lamware never touches passwords
- **rehype-sanitize** — existing XSS protection on LLM narratives preserved
- **Keycloak admin console** — user management without lamware code changes

## Deployment Order

1. Deploy PostgreSQL changes (create keycloak database)
2. Deploy Keycloak (new role)
3. Configure Keycloak realm, client, roles (manual via admin console or import JSON)
4. Deploy updated nginx (add /auth/ proxy)
5. Deploy updated API (JWT validation)
6. Deploy updated frontend (keycloak-js, auth provider, protected routes)
7. Create initial admin user in Keycloak
8. Test SSO with Entra ID
9. Deprecation: static API key demoted to viewer-only

## Backlog (Phase 2)

- Remove static API key fallback entirely
- Keycloak service accounts for programmatic API access (client credentials grant)
- Audit log table for all state-changing operations
- Per-user API rate limiting
- Keycloak theme customization (lamware branding on login page)
