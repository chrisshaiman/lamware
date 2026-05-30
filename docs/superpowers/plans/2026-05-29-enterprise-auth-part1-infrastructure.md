# Enterprise Auth Part 1: Infrastructure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deploy Keycloak identity broker as a root Podman container with PostgreSQL backend, nginx proxy, security cat theme, and realm configuration. At the end of this plan, the Keycloak login page is accessible at `/auth/` with lamware branding.

**Architecture:** Keycloak runs as a root Podman container managed by systemd (same pattern as LiteLLM). Uses a dedicated PostgreSQL database on the existing instance. nginx proxies `/auth/*` to Keycloak on port 8080. A realm export JSON pre-configures the `lamware` realm, client, and roles.

**Tech Stack:** Keycloak 26.1, Podman (root), systemd, PostgreSQL 16, nginx, Ansible

**Spec:** [docs/superpowers/specs/2026-05-29-enterprise-auth-design.md](../specs/2026-05-29-enterprise-auth-design.md)

**Sub-plans:**
- Part 1: Infrastructure (this plan)
- Part 2: Backend (FastAPI auth rewrite, audit logging)
- Part 3: Frontend (React auth integration, role-aware UI)

---

## File Structure

```
ansible/roles/keycloak/
  defaults/main.yml                    # keycloak_image, port, realm settings
  tasks/main.yml                       # pull image, deploy config, systemd, realm import
  templates/
    keycloak.service.j2                # systemd unit (root Podman)
    keycloak.env.j2                    # DB connection, admin creds (0600)
  handlers/main.yml                    # restart handler
  files/
    lamware-realm.json                 # realm export with client, roles, defaults
    theme/                             # security cat login theme
      login/
        theme.properties               # parent=keycloak, import=common/keycloak
        login.ftl                       # custom login template
        resources/css/login.css         # dark theme CSS
        resources/img/security-cat.svg  # favicon/logo

ansible/roles/postgres/tasks/main.yml  # add keycloak DB + user (modify)
ansible/roles/frontend/templates/
  lamware-nginx.conf.j2                # add /auth/ proxy block (modify)
ansible/site.yml                       # add keycloak role (modify)
ansible/vars/secrets.yml               # add keycloak_db_password, keycloak_admin_password (modify, vault-encrypted)
```

---

### Task 1: PostgreSQL — Create Keycloak Database

**Files:**
- Modify: `ansible/roles/postgres/tasks/main.yml`
- Modify: `ansible/vars/secrets.yml` (vault-encrypted)

- [ ] **Step 1: Add keycloak_db_password to Ansible vault**

Run from WSL:
```bash
cd /mnt/c/Users/djtod/codingProjects/ReverseEngineeringMalware/malware-sandbox-infra/ansible
ansible-vault edit vars/secrets.yml
```

Add these two lines alongside existing secrets:
```yaml
keycloak_db_password: "<generate-a-strong-password>"
keycloak_admin_password: "<generate-a-strong-password>"
```

Save and close.

- [ ] **Step 2: Add Keycloak database tasks to postgres role**

Add after the LiteLLM database tasks in `ansible/roles/postgres/tasks/main.yml`:

```yaml
- name: Create Keycloak database user
  become: true
  become_user: postgres
  community.postgresql.postgresql_user:
    name: "{{ keycloak_db_user | default('keycloak') }}"
    password: "{{ keycloak_db_password }}"
    role_attr_flags: NOSUPERUSER,NOCREATEDB,NOCREATEROLE

- name: Create Keycloak database
  become: true
  become_user: postgres
  community.postgresql.postgresql_db:
    name: "{{ keycloak_db_name | default('keycloak') }}"
    owner: "{{ keycloak_db_user | default('keycloak') }}"
    encoding: UTF-8
```

- [ ] **Step 3: Deploy and verify**

```bash
ansible-playbook site.yml --tags postgres -i inventory/hosts --ask-vault-pass
```

Verify:
```bash
ssh sandbox "sudo -u postgres psql -c '\l' | grep keycloak"
```

Expected: `keycloak | keycloak | UTF8 | ...`

- [ ] **Step 4: Commit**

```bash
git add ansible/roles/postgres/tasks/main.yml
git commit -m "feat(auth): create Keycloak PostgreSQL database + user"
```

---

### Task 2: Keycloak Ansible Role — Defaults and Handlers

**Files:**
- Create: `ansible/roles/keycloak/defaults/main.yml`
- Create: `ansible/roles/keycloak/handlers/main.yml`

- [ ] **Step 1: Create defaults**

```yaml
---
# =============================================================================
# Keycloak identity broker defaults
# =============================================================================

keycloak_enabled: true
keycloak_install_dir: /opt/keycloak
keycloak_image: "quay.io/keycloak/keycloak:26.1"
keycloak_port: 8080
keycloak_listen_address: "127.0.0.1"
keycloak_db_user: "keycloak"
keycloak_db_name: "keycloak"
keycloak_admin_user: "admin"
keycloak_realm: "lamware"
keycloak_client_id: "lamware-web"
```

- [ ] **Step 2: Create handlers**

```yaml
---
- name: Restart Keycloak
  ansible.builtin.systemd:
    name: keycloak
    state: restarted
    daemon_reload: true
```

- [ ] **Step 3: Commit**

```bash
git add ansible/roles/keycloak/defaults/main.yml ansible/roles/keycloak/handlers/main.yml
git commit -m "feat(auth): keycloak role defaults and handlers"
```

---

### Task 3: Keycloak Ansible Role — Service Templates

**Files:**
- Create: `ansible/roles/keycloak/templates/keycloak.env.j2`
- Create: `ansible/roles/keycloak/templates/keycloak.service.j2`

- [ ] **Step 1: Create environment file template**

`ansible/roles/keycloak/templates/keycloak.env.j2`:
```
KC_DB=postgres
KC_DB_URL=jdbc:postgresql://127.0.0.1:5432/{{ keycloak_db_name }}
KC_DB_USERNAME={{ keycloak_db_user }}
KC_DB_PASSWORD={{ keycloak_db_password }}
KC_HOSTNAME_STRICT=false
KC_PROXY_HEADERS=xforwarded
KC_HTTP_ENABLED=true
KC_HTTP_HOST={{ keycloak_listen_address }}
KC_HTTP_PORT={{ keycloak_port }}
KC_HEALTH_ENABLED=true
KEYCLOAK_ADMIN={{ keycloak_admin_user }}
KEYCLOAK_ADMIN_PASSWORD={{ keycloak_admin_password }}
```

- [ ] **Step 2: Create systemd service template**

`ansible/roles/keycloak/templates/keycloak.service.j2`:
```ini
# /etc/systemd/system/keycloak.service — managed by Ansible
# Keycloak identity broker — enterprise SSO for lamware.
# Runs as a root Podman container.

[Unit]
Description=Keycloak identity broker
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
ExecStartPre=-/usr/bin/podman rm -f keycloak
ExecStart=/usr/bin/podman run --rm --name keycloak \
    --network=host \
    --env-file {{ keycloak_install_dir }}/keycloak.env \
    -v {{ keycloak_install_dir }}/themes/lamware:/opt/keycloak/themes/lamware:ro \
    {{ keycloak_image }} \
    start
ExecStop=/usr/bin/podman stop keycloak
Restart=always
RestartSec=5
TimeoutStartSec=180

[Install]
WantedBy=multi-user.target
```

Note: Keycloak container runs as UID 1000 internally. `--read-only` is NOT used because Keycloak needs to write to its internal data directory during startup. The container itself provides isolation.

- [ ] **Step 3: Commit**

```bash
git add ansible/roles/keycloak/templates/
git commit -m "feat(auth): keycloak service and env templates"
```

---

### Task 4: Security Cat Login Theme

**Files:**
- Create: `ansible/roles/keycloak/files/theme/login/theme.properties`
- Create: `ansible/roles/keycloak/files/theme/login/login.ftl`
- Create: `ansible/roles/keycloak/files/theme/login/resources/css/login.css`
- Create: `ansible/roles/keycloak/files/theme/login/resources/img/security-cat.svg`

- [ ] **Step 1: Create theme.properties**

`ansible/roles/keycloak/files/theme/login/theme.properties`:
```properties
parent=keycloak
import=common/keycloak
styles=css/login.css
```

- [ ] **Step 2: Create login.ftl**

`ansible/roles/keycloak/files/theme/login/login.ftl`:
```html
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=realm.password && realm.registrationAllowed && !registrationDisabled??; section>
    <#if section = "header">
        <div class="lamware-header">
            <img src="${url.resourcesPath}/img/security-cat.svg" alt="lamware" class="lamware-logo" />
            <h1 class="lamware-title">lamware</h1>
            <p class="lamware-subtitle">Malware Analysis Platform</p>
        </div>
    <#elseif section = "form">
        <div id="kc-form">
            <div id="kc-form-wrapper">
                <#if realm.password>
                    <form id="kc-form-login" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
                        <div class="form-group">
                            <label for="username" class="control-label">${msg("loginAccountTitle")}</label>
                            <input tabindex="1" id="username" class="form-control" name="username" value="${(login.username!'')}" type="text" autofocus autocomplete="off" placeholder="${msg('usernameOrEmail')}" />
                        </div>
                        <div class="form-group">
                            <label for="password" class="control-label">${msg("password")}</label>
                            <input tabindex="2" id="password" class="form-control" name="password" type="password" autocomplete="off" placeholder="${msg('password')}" />
                        </div>
                        <div id="kc-form-buttons" class="form-group">
                            <input type="hidden" id="id-hidden-input" name="credentialId" />
                            <input tabindex="4" class="btn btn-primary btn-block btn-lg" name="login" id="kc-login" type="submit" value="${msg('doLogIn')}" />
                        </div>
                    </form>
                </#if>
            </div>
        </div>
    </#if>
</@layout.registrationLayout>
```

- [ ] **Step 3: Create login.css**

`ansible/roles/keycloak/files/theme/login/resources/css/login.css`:
```css
/* lamware dark theme — matches dashboard palette */
body {
    background-color: #0d1117 !important;
}

#kc-header-wrapper,
#kc-locale {
    display: none;
}

.login-pf body,
#kc-login {
    background-color: #0d1117;
}

#kc-form-login {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 24px;
}

.form-control {
    background-color: #0d1117 !important;
    border: 1px solid #30363d !important;
    color: #e6edf3 !important;
    border-radius: 6px !important;
    padding: 10px 12px !important;
}

.form-control:focus {
    border-color: #58a6ff !important;
    box-shadow: 0 0 0 3px rgba(88, 166, 255, 0.15) !important;
}

.control-label {
    color: #8b949e !important;
    font-size: 12px !important;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.btn-primary {
    background-color: #58a6ff !important;
    border-color: #58a6ff !important;
    color: #0d1117 !important;
    font-weight: 600 !important;
    border-radius: 6px !important;
    padding: 10px !important;
    margin-top: 8px;
}

.btn-primary:hover {
    background-color: #79c0ff !important;
    border-color: #79c0ff !important;
}

.lamware-header {
    text-align: center;
    margin-bottom: 24px;
}

.lamware-logo {
    width: 64px;
    height: 64px;
    margin-bottom: 12px;
}

.lamware-title {
    color: #e6edf3;
    font-size: 24px;
    font-weight: 700;
    margin: 0;
    letter-spacing: -0.5px;
}

.lamware-subtitle {
    color: #8b949e;
    font-size: 12px;
    margin: 4px 0 0 0;
}

#kc-content-wrapper {
    max-width: 400px;
    margin: 0 auto;
    padding-top: 10vh;
}

/* Error messages */
.alert-error {
    background-color: #3d1a1a !important;
    border-color: #ff6b6b !important;
    color: #ff6b6b !important;
    border-radius: 6px !important;
}

/* Social/IdP login buttons */
#kc-social-providers .zocial {
    background-color: #161b22 !important;
    border: 1px solid #30363d !important;
    color: #e6edf3 !important;
    border-radius: 6px !important;
}

#kc-social-providers .zocial:hover {
    background-color: #1c2128 !important;
}
```

- [ ] **Step 4: Copy security cat SVG**

Copy the existing favicon SVG to the theme:
```bash
cp frontend/public/favicon.svg ansible/roles/keycloak/files/theme/login/resources/img/security-cat.svg
```

- [ ] **Step 5: Commit**

```bash
git add ansible/roles/keycloak/files/
git commit -m "feat(auth): security cat Keycloak login theme"
```

---

### Task 5: Keycloak Realm Configuration

**Files:**
- Create: `ansible/roles/keycloak/files/lamware-realm.json`

- [ ] **Step 1: Create realm export JSON**

`ansible/roles/keycloak/files/lamware-realm.json`:
```json
{
  "realm": "lamware",
  "enabled": true,
  "sslRequired": "none",
  "registrationAllowed": false,
  "loginWithEmailAllowed": true,
  "duplicateEmailsAllowed": false,
  "resetPasswordAllowed": false,
  "editUsernameAllowed": false,
  "bruteForceProtected": true,
  "permanentLockout": false,
  "maxFailureWaitSeconds": 900,
  "minimumQuickLoginWaitSeconds": 60,
  "waitIncrementSeconds": 60,
  "quickLoginCheckMilliSeconds": 1000,
  "maxDeltaTimeSeconds": 43200,
  "failureFactor": 5,
  "defaultRoles": ["viewer"],
  "roles": {
    "realm": [
      {"name": "admin", "description": "Full access — user management, delete analyses, all operations"},
      {"name": "analyst", "description": "Submit samples, control auto-feeder, view all data"},
      {"name": "viewer", "description": "Read-only dashboard access"}
    ]
  },
  "clients": [
    {
      "clientId": "lamware-web",
      "name": "lamware Dashboard",
      "enabled": true,
      "publicClient": true,
      "standardFlowEnabled": true,
      "directAccessGrantsEnabled": false,
      "implicitFlowEnabled": false,
      "serviceAccountsEnabled": false,
      "protocol": "openid-connect",
      "redirectUris": ["https://10.200.0.1/*", "https://localhost:8443/*"],
      "webOrigins": ["https://10.200.0.1", "https://localhost:8443"],
      "attributes": {
        "pkce.code.challenge.method": "S256",
        "post.logout.redirect.uris": "https://10.200.0.1/*##https://localhost:8443/*"
      },
      "defaultClientScopes": ["openid", "profile", "email", "roles"],
      "protocolMappers": [
        {
          "name": "realm-roles",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-usermodel-realm-role-mapper",
          "config": {
            "claim.name": "realm_access.roles",
            "jsonType.label": "String",
            "multivalued": "true",
            "id.token.claim": "true",
            "access.token.claim": "true",
            "userinfo.token.claim": "true"
          }
        }
      ]
    }
  ],
  "loginTheme": "lamware",
  "accessTokenLifespan": 300,
  "ssoSessionIdleTimeout": 1800,
  "ssoSessionMaxLifespan": 36000
}
```

- [ ] **Step 2: Commit**

```bash
git add ansible/roles/keycloak/files/lamware-realm.json
git commit -m "feat(auth): keycloak realm config with roles and PKCE client"
```

---

### Task 6: Keycloak Ansible Role — Main Tasks

**Files:**
- Create: `ansible/roles/keycloak/tasks/main.yml`

- [ ] **Step 1: Create tasks/main.yml**

```yaml
---
# =============================================================================
# roles/keycloak/tasks/main.yml
# Deploys Keycloak identity broker as a root Podman container managed by
# systemd. Imports the lamware realm on first run.
#
# Author: Christopher Shaiman
# License: Apache 2.0
# =============================================================================

- name: Create Keycloak directories
  ansible.builtin.file:
    path: "{{ item }}"
    state: directory
    owner: root
    group: root
    mode: "0700"
  loop:
    - "{{ keycloak_install_dir }}"
    - "{{ keycloak_install_dir }}/themes"
    - "{{ keycloak_install_dir }}/import"

- name: Deploy Keycloak environment file (contains DB password + admin creds)
  ansible.builtin.template:
    src: keycloak.env.j2
    dest: "{{ keycloak_install_dir }}/keycloak.env"
    owner: root
    group: root
    mode: "0600"
  no_log: true
  notify: Restart Keycloak

- name: Deploy lamware login theme
  ansible.builtin.copy:
    src: theme/
    dest: "{{ keycloak_install_dir }}/themes/lamware/"
    owner: root
    group: root
    mode: "0644"
    directory_mode: "0755"

- name: Deploy realm import file
  ansible.builtin.copy:
    src: lamware-realm.json
    dest: "{{ keycloak_install_dir }}/import/lamware-realm.json"
    owner: root
    group: root
    mode: "0600"

- name: Pull Keycloak container image
  ansible.builtin.command:
    cmd: "podman pull {{ keycloak_image }}"
  register: keycloak_pull
  changed_when: "'Pulling' in keycloak_pull.stdout or 'Writing' in keycloak_pull.stderr"

- name: Deploy Keycloak systemd service
  ansible.builtin.template:
    src: keycloak.service.j2
    dest: /etc/systemd/system/keycloak.service
    owner: root
    group: root
    mode: "0644"
  notify: Restart Keycloak

- name: Enable and start Keycloak
  ansible.builtin.systemd:
    name: keycloak
    state: started
    enabled: true
    daemon_reload: true

- name: Wait for Keycloak to be ready
  ansible.builtin.uri:
    url: "http://{{ keycloak_listen_address }}:{{ keycloak_port }}/health/ready"
    method: GET
    status_code: 200
  register: keycloak_health
  retries: 20
  delay: 5
  until: keycloak_health.status == 200
```

- [ ] **Step 2: Update keycloak.service.j2 to include realm import on first start**

Update the ExecStart in `ansible/roles/keycloak/templates/keycloak.service.j2`:

```ini
ExecStart=/usr/bin/podman run --rm --name keycloak \
    --network=host \
    --env-file {{ keycloak_install_dir }}/keycloak.env \
    -v {{ keycloak_install_dir }}/themes/lamware:/opt/keycloak/themes/lamware:ro \
    -v {{ keycloak_install_dir }}/import:/opt/keycloak/data/import:ro \
    {{ keycloak_image }} \
    start --import-realm
```

The `--import-realm` flag imports JSON files from `/opt/keycloak/data/import/` on startup. If the realm already exists, it skips the import (idempotent).

- [ ] **Step 3: Commit**

```bash
git add ansible/roles/keycloak/tasks/main.yml ansible/roles/keycloak/templates/keycloak.service.j2
git commit -m "feat(auth): keycloak main tasks with realm import and health check"
```

---

### Task 7: Wire Keycloak into Site.yml and nginx

**Files:**
- Modify: `ansible/site.yml`
- Modify: `ansible/roles/frontend/templates/lamware-nginx.conf.j2`

- [ ] **Step 1: Add keycloak role to site.yml**

Insert after the `litellm` role block:

```yaml
    # 10c. Keycloak — identity broker for enterprise SSO
    - role: keycloak
      tags: [keycloak]
```

- [ ] **Step 2: Add /auth/ proxy to nginx config**

Add before the `# Gzip compression` section in `ansible/roles/frontend/templates/lamware-nginx.conf.j2`:

```nginx
    # Keycloak identity broker proxy
    location /auth/ {
        proxy_pass http://127.0.0.1:{{ keycloak_port | default(8080) }}/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffer_size 128k;
        proxy_buffers 4 256k;
        proxy_busy_buffers_size 256k;
    }
```

- [ ] **Step 3: Commit**

```bash
git add ansible/site.yml ansible/roles/frontend/templates/lamware-nginx.conf.j2
git commit -m "feat(auth): wire keycloak into site.yml and nginx proxy"
```

---

### Task 8: Deploy and Verify

- [ ] **Step 1: Deploy all infrastructure**

```bash
cd /mnt/c/Users/djtod/codingProjects/ReverseEngineeringMalware/malware-sandbox-infra/ansible
ansible-playbook site.yml --tags postgres,keycloak,frontend -i inventory/hosts --ask-vault-pass
```

- [ ] **Step 2: Verify Keycloak is running**

```bash
ssh sandbox "curl -s http://127.0.0.1:8080/health/ready"
```

Expected: `{"status":"UP","checks":[]}`

- [ ] **Step 3: Verify nginx proxy works**

```bash
ssh sandbox "curl -sk https://10.200.0.1/auth/realms/lamware/.well-known/openid-configuration | python3 -m json.tool | head -10"
```

Expected: JSON with `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`

- [ ] **Step 4: Verify login page loads in browser**

Visit `https://localhost:8443/auth/realms/lamware/account/` — should show the security cat themed login page.

- [ ] **Step 5: Log in as admin**

Use the credentials from `keycloak_admin_user` / `keycloak_admin_password` in the vault. Verify admin console is accessible at `https://localhost:8443/auth/admin/`.

- [ ] **Step 6: Verify realm, client, and roles exist**

In the Keycloak admin console:
1. Select realm "lamware" (top left dropdown)
2. Clients → `lamware-web` exists with PKCE enabled
3. Realm roles → `admin`, `analyst`, `viewer` exist
4. Realm settings → Login theme = `lamware`

- [ ] **Step 7: Create your first admin user**

In Keycloak admin console:
1. Users → Add user
2. Username: your email, Email verified: ON
3. Credentials → Set password
4. Role Mapping → Assign `admin` role

- [ ] **Step 8: Final commit and push**

```bash
git push origin main
```
