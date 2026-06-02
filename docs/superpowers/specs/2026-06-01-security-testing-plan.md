# Security Testing Plan — lamware Platform

**Date:** 2026-06-01
**Author:** Christopher Shaiman
**Status:** Approved
**Scope:** Auth stack, API, WebSocket, Keycloak, nginx — everything behind WireGuard

---

## Threat Model

### In Scope

**Threat A — Authenticated analyst gone rogue:** Valid JWT with analyst role,
attempting privilege escalation, data exfiltration, or destructive actions
beyond their role.

**Threat B — Stolen WireGuard key:** Attacker has network access to the
management plane but no Keycloak credentials. Attempting to bypass auth,
exploit unauthenticated endpoints, or abuse the OIDC flow.

### Out of Scope

**Threat C — Compromised Keycloak:** Supply chain attack on Keycloak container
image. Mitigation is operational (pinned image versions, security advisories,
kill server and wait for patch). Not testable via pentest.

### Current Architecture Assumptions

- Single-tenant shared analyst platform (IDOR is acceptable — all analysts
  see all analyses)
- All access via WireGuard VPN (no public-facing services)
- JWT-only auth (static API key removed)
- Three roles: admin > analyst > viewer (composite hierarchy)

---

## Attack Surface Summary

| # | Finding | Severity | Surface | Test Phase |
|---|---|---|---|---|
| 1 | IDOR on analysis endpoints | Low (single-tenant) | API | Phase 1 (document) |
| 2 | `verify_aud` disabled | Medium | Auth | Phase 2 (JWT tamper) |
| 3 | No `iss` claim validation | Medium | Auth | Phase 2 (JWT tamper) |
| 4 | `/docs` `/redoc` unauthenticated | Medium | API | Phase 3 (Nuclei) |
| 5 | No rate limiting | Medium | API | Phase 2 (manual) |
| 6 | No failed auth auditing | Medium | Audit | Phase 1 (RBAC tests) |
| 7 | CORS `allow_credentials=True` | Medium | API | Phase 3 (Nuclei) |
| 8 | No file type validation on upload | Medium | Upload | Phase 1 (Schemathesis) |
| 9 | Redirect URI wildcards | Low | Keycloak | Phase 2 (manual) |
| 10 | 24-hour WebSocket idle timeout | Low | WebSocket | Phase 2 (manual) |

---

## Phase 1: Manual Pentest — Find Vulnerabilities

Hands-on testing to understand the real attack surface. Document every
finding with evidence (curl commands, responses, screenshots). This drives
what gets fixed and what gets automated.

### 1.1 JWT Tampering

**Tests:**

| Test | Expected | How |
|---|---|---|
| Expired token | 401 | Get token, wait 5+ min, replay |
| Modified role claims | 401 | Decode JWT, change roles, re-encode (signature breaks) |
| Algorithm confusion (`alg: none`) | 401 | Set header alg to "none", strip signature |
| Algorithm confusion (`alg: HS256`) | 401 | Re-sign with HS256 using public key as secret |
| Wrong `kid` header | 401 (after JWKS refresh) | Use non-existent kid value |
| Token from different issuer | 401 | Create self-signed JWT with different iss |
| Missing `kid` header | 401 | Strip kid from JWT header |
| Token without `realm_access` | 200 but empty roles | Valid token, no roles claim |
| Token with extra roles | roles from token accepted | Valid token, add fake roles (shouldn't work — Keycloak controls claims) |

**Tools:** jwt.io for decoding, PyJWT for crafting tokens, curl for requests.

### 1.2 WebSocket Auth Testing

**Tests:**

| Test | Expected | How |
|---|---|---|
| No auth message | 4001 close after 5s | Connect, send nothing |
| Invalid JSON as first message | 4001 close | Send garbage bytes |
| Wrong message type | 4001 close | Send `{"type": "subscribe"}` |
| Auth without token field | 4001 close | Send `{"type": "auth"}` |
| Invalid JWT token | 4001 close | Send `{"type": "auth", "token": "invalid"}` |
| Expired JWT | 4001 close | Send expired token |
| Valid auth then malformed messages | Connection survives | Normal auth, then send random data |
| Multiple simultaneous connections | All receive events | Open 10 connections, verify broadcast |
| Auth message after 4.9 seconds | Should succeed | Test timing boundary |

**Tools:** websocat or Python websockets library.

### 1.3 Keycloak OIDC Hardening

**Tests:**

| Test | Expected | How |
|---|---|---|
| Redirect URI manipulation | Rejected | Login with `redirect_uri=https://evil.com/callback` |
| PKCE downgrade | Rejected | Start auth flow without `code_challenge` |
| Direct access grants | Rejected | POST to token endpoint with `grant_type=password` |
| Brute force lockout | Account locked after 5 failures | Send 6 wrong passwords |
| Client secret extraction | N/A (public client) | Verify no client_secret in any response |
| Token endpoint abuse | Rate limited | Rapid token requests |
| Open redirect via login | Rejected | Manipulate post-login redirect |

**Tools:** curl, browser dev tools.

### 1.4 Input Validation

**Tests:**

| Test | Target | Expected |
|---|---|---|
| SQL injection in search `q` param | `/api/analyses?q='OR 1=1--` | Normal response (parameterized) |
| XSS in search param | `/api/analyses?q=<script>alert(1)</script>` | Escaped in response |
| Path traversal in upload filename | `../../etc/passwd` as filename | Sanitized to `passwd` |
| Oversized upload (>100MB) | `/api/samples/submit` | 413 response |
| Zero-byte upload | `/api/samples/submit` | 400 response |
| Upload with no filename | `/api/samples/submit` | 400 response |
| Integer overflow on analysis_id | `/api/analyses/99999999999` | 404, not 500 |
| Negative offset | `/api/analyses?offset=-1` | 422 validation error |
| Limit > 500 | `/api/analyses?limit=9999` | 422 validation error |

**Tools:** curl, Burp Suite Community (optional).

### 1.5 RBAC Manual Verification

Manually test every endpoint with each role to verify enforcement:

| Endpoint | Method | viewer | analyst | admin |
|---|---|---|---|---|
| `/api/analyses` | GET | 200 | 200 | 200 |
| `/api/analyses/{id}` | GET | 200 | 200 | 200 |
| `/api/iocs` | GET | 200 | 200 | 200 |
| `/api/techniques` | GET | 200 | 200 | 200 |
| `/api/families` | GET | 200 | 200 | 200 |
| `/api/stats` | GET | 200 | 200 | 200 |
| `/api/pipeline/status` | GET | 200 | 200 | 200 |
| `/api/alerts` | GET | 200 | 200 | 200 |
| `/api/evasions` | GET | 200 | 200 | 200 |
| `/api/feeder/status` | GET | 200 | 200 | 200 |
| `/api/samples/submit` | POST | 403 | 200 | 200 |
| `/api/feeder/pause` | POST | 403 | 200 | 200 |
| `/api/feeder/resume` | POST | 403 | 200 | 200 |
| `/api/feeder/reset` | POST | 403 | 200 | 200 |
| `/api/analyses/{id}` | DELETE | 403 | 403 | 200 |
| `/health` | GET | 200 (no auth) | 200 (no auth) | 200 (no auth) |

Also test:
- No auth → 401 on all protected endpoints
- Invalid Bearer token → 401
- `X-API-Key` header → 401 (no longer accepted)

### 1.6 Failed Auth Auditing Gap

**Test:** Send 10 invalid auth requests, then check audit_log table.

**Expected:** Currently nothing logged (known gap).

**Remediation:** Add failed auth attempt logging to `require_auth` — log
user-agent, source IP, and failure reason.

---

## Phase 2: Fix Vulnerabilities + Schemathesis Discovery

Fix issues found in Phase 1, then run Schemathesis to catch edge cases
manual testing missed.

### 2.1 Implement Fixes

Based on Phase 1 findings. Known issues to fix:

1. **Add `iss` claim validation** to JWT decode (`auth.py`)
2. **Add failed auth logging** — log 401/403 with user-agent and IP
3. **Gate `/docs` and `/redoc`** behind auth or environment flag
4. **Tighten redirect URIs** — replace `/*` with specific paths
5. **Add `Content-Security-Policy` header** to nginx
6. **Add `Strict-Transport-Security` header** to nginx

Plus any new findings from Phase 1.

### 2.2 Schemathesis API Fuzzing

**Tool:** Schemathesis (Python, runs against OpenAPI schema)

**What it tests:**
- Every endpoint with malformed inputs, boundary values, unexpected types
- Response codes match schema definitions
- Content-type enforcement
- Parameter type coercion attacks
- Large payloads and edge cases

**Configuration:**
- Schema URL: `http://127.0.0.1:8001/openapi.json`
- Auth: Bearer JWT token from Keycloak service account (admin role)
- Priority targets: `/api/samples/submit` (file upload), `/api/feeder/*` (write ops)
- Stateful testing: link-based (follows schema relationships)
- Output: JUnit XML report

---

## Phase 3: Automate — CI/CD Post-Deploy

Convert Phase 1 manual tests + Phase 2 fixes into a repeatable
`security-test` Ansible role. All tools produce machine-readable reports
saved to `/opt/pipeline/reports/security/`.

### 3.1 RBAC Enforcement Tests (Automated)

**Tool:** Custom Python script using httpx

Convert the Phase 1.5 RBAC matrix into an automated script that:
- Gets JWT tokens for each role via Keycloak service accounts
- Hits every endpoint with each role
- Verifies correct HTTP status codes
- Runs as Ansible task — any unexpected status code fails deploy

### 3.2 JWT Security Tests (Automated)

Convert Phase 1.1 JWT tampering tests into `api/tests/test_jwt_security.py`:
- Expired token, algorithm confusion, wrong kid, missing kid
- Runs as part of the test suite

### 3.3 WebSocket Security Tests (Automated)

Convert Phase 1.2 WebSocket tests into `api/tests/test_ws_security.py`:
- No auth, invalid token, timeout, malformed messages
- Runs as part of the test suite

### 3.4 Nuclei Misconfig Sweep

**Tool:** Nuclei with custom + community templates

**What it tests:**
- Exposed `/docs` and `/redoc` (Swagger/ReDoc)
- Exposed `/openapi.json`
- CORS misconfiguration (test with spoofed Origin headers)
- Missing security headers (CSP, HSTS)
- Debug mode indicators
- Keycloak well-known endpoints information disclosure
- SSL/TLS configuration (cipher strength, protocol versions)

**Custom templates for lamware:**
- Verify `X-Frame-Options: DENY` on all non-Keycloak paths
- Verify `X-Frame-Options: SAMEORIGIN` on `/auth/*` paths only
- Verify no `Server` version disclosure in responses
- Verify health endpoint returns only `{"status":"ok","service":"lamware-api"}`

**CI/CD integration:** Runs as Ansible task. Critical/high findings fail deploy.

### 3.5 Schemathesis in CI/CD

Move the Phase 2.2 Schemathesis config into the Ansible role for
regression testing on every deploy.

---

## Phase 4: Pentest Report

Generate a formal report as PDF using WeasyPrint (existing pipeline).

### Report Structure

1. **Executive Summary** — scope, methodology, overall risk rating, key findings
2. **Methodology** — tools used, threat model, testing dates
3. **Findings** — each finding with:
   - Title and severity (Critical/High/Medium/Low/Info)
   - Description
   - Evidence (screenshots, curl commands, responses)
   - Impact
   - Remediation recommendation
   - Remediation status (Fixed/Accepted Risk/Deferred)
4. **RBAC Matrix** — verified role-endpoint matrix
5. **Remediation Summary** — table of all findings with status
6. **Appendix** — raw Schemathesis output, Nuclei findings, RBAC test results

### Severity Rating

| Rating | Definition |
|---|---|
| Critical | Auth bypass, RCE, data exfiltration without auth |
| High | Privilege escalation, IDOR with sensitive data |
| Medium | Missing hardening, information disclosure, no rate limiting |
| Low | Best practice gaps, defense-in-depth recommendations |
| Info | Observations, accepted risks, documentation items |

---

## Deliverables

| Deliverable | Location | CI/CD? |
|---|---|---|
| Schemathesis config + runner | `ansible/roles/security-test/` | Yes — post-deploy |
| RBAC test script | `ansible/roles/security-test/files/test_rbac.py` | Yes — post-deploy |
| Nuclei custom templates | `ansible/roles/security-test/files/nuclei/` | Yes — post-deploy |
| JWT tamper test script | `api/tests/test_jwt_security.py` | Convert to CI after manual run |
| WebSocket auth test script | `api/tests/test_ws_security.py` | Convert to CI after manual run |
| Pentest report (PDF) | `docs/security/2026-06-pentest-report.pdf` | No — one-time document |
| Pentest report (markdown) | `docs/security/2026-06-pentest-report.md` | No — one-time document |

---

## Execution Order

1. **Manual JWT tampering** — test all token attack vectors, document findings
2. **Manual WebSocket testing** — test auth bypass, timeouts, edge cases
3. **Manual Keycloak hardening** — redirect URI, PKCE, brute force, direct grants
4. **Manual input validation** — SQL injection, XSS, path traversal, upload abuse
5. **Manual RBAC verification** — every endpoint, every role, document matrix
6. **Audit gap testing** — verify failed auth logging (known gap)
7. **Implement fixes** for all vulnerabilities found in steps 1-6
8. **Run Schemathesis fuzzing** — catch edge cases manual testing missed
9. **Fix any Schemathesis findings**
10. **Build CI/CD security-test Ansible role** — convert manual tests to automated
11. **Run full automated suite** to verify everything passes
12. **Generate pentest report PDF**

---

## Known Issues to Fix (Phase 2)

Identified from attack surface exploration. Additional findings from Phase 1
manual testing will be added here.

1. **Add `iss` claim validation** to JWT decode (`auth.py`)
2. **Add failed auth logging** — log 401/403 with user-agent and IP
3. **Gate `/docs` and `/redoc`** behind auth or environment flag
4. **Tighten redirect URIs** — replace `/*` with specific paths
5. **Add `Content-Security-Policy` header** to nginx
6. **Add `Strict-Transport-Security` header** to nginx
