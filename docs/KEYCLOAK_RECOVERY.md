# Keycloak recovery

Written as prerequisite work for #457 (upgrade off 26.1 for CVE-2026-18963).
Every command here was **run against the live host**, not written from
documentation — three of them failed the first time, for reasons that only
executing them revealed.

## Why this exists before the upgrade

Keycloak migrates its database schema on startup after an upgrade and does not
support downgrade. Reverting the pinned image tag alone will not roll back a
failed upgrade: 26.7.2 will have already migrated the schema, and 26.1 will
refuse it.

There are four accounts, and password reset is disabled across both realms (it
is the CVE mitigation). So a failed upgrade has **no self-service way back in**.
Recovery is a database restore, and it has to be known-good beforehand.

## What actually recovers, and what does not

| Situation | Recovery |
|---|---|
| Upgrade fails, Keycloak will not start | Restore DB + revert image tag |
| Admin account lost or password unknown | Restore DB |
| Realm/client config damaged | Restore DB |

**The bootstrap admin does not help.** `--bootstrap-admin-*` is, per its own
help text, *"used only when the master realm is created"*. On an existing
database the master realm already exists, so the option is inert. It is not an
admin-lockout recovery mechanism for this deployment.

The database restore is the recovery path. There is no second one.

## Deployment facts

```
image      quay.io/keycloak/keycloak:26.1   (pinned, roles/keycloak/defaults/main.yml)
database   postgres, db "keycloak" on 127.0.0.1:5432
size       12 MB — 87 tables, 4 users, 2 realms (lamware, master), 15 clients, 6 credentials
service    systemd unit "keycloak", podman container
```

## Backup

`pg_dump` runs as the `postgres` user, so the destination must be readable and
writable by `postgres` — **including every parent directory**. Both halves of
that bit us:

```bash
sudo mkdir -p /opt/backups/keycloak
sudo chmod 711 /opt/backups              # traversal for postgres; listing still root-only
sudo chown postgres:postgres /opt/backups/keycloak
sudo chmod 700 /opt/backups/keycloak

sudo -u postgres pg_dump -Fc -d keycloak \
     -f /opt/backups/keycloak/keycloak-$(date -u +%Y%m%dT%H%M%SZ).dump
```

`-Fc` (custom format) rather than plain SQL, so a restore can be selective and
does not depend on statement ordering.

A dump of this database is ~210 KB.

### The failures worth knowing about

1. Destination `root:root 700` — `pg_dump` runs as `postgres` and cannot write.
2. Ownership fixed on the leaf, still failed: `/opt/backups` was `drwx------
   root root`, so `postgres` could not **traverse** into a directory it owned.
   The error is `could not open output file ... Permission denied`, which reads
   like a problem with the file rather than with its parent.

Neither is visible from reading the command. Both are why this was tested.

## Verify a backup before relying on it

A dump that has never been restored is an assumption. Restore into a scratch
database and compare — this touches nothing live:

```bash
sudo -u postgres psql -c 'CREATE DATABASE keycloak_restoretest OWNER keycloak;'
sudo -u postgres pg_restore -d keycloak_restoretest --no-owner --role=keycloak \
     /opt/backups/keycloak/<dump>

# compare against the source
cat > /tmp/cmp.sql <<'SQL'
SELECT 'tables='||count(*) FROM information_schema.tables WHERE table_schema='public';
SELECT 'users='||count(*) FROM user_entity;
SELECT 'realms='||string_agg(name,',' ORDER BY name) FROM realm;
SELECT 'clients='||count(*) FROM client;
SELECT 'credentials='||count(*) FROM credential;
SQL
chmod a+r /tmp/cmp.sql
sudo -u postgres psql -tA -d keycloak             -f /tmp/cmp.sql
sudo -u postgres psql -tA -d keycloak_restoretest -f /tmp/cmp.sql

sudo -u postgres psql -c 'DROP DATABASE keycloak_restoretest;'
```

Verified output, both sides identical:

```
tables=87 users=4 realms=lamware,master clients=15 credentials=6
```

Note `psql -f` reads the file **as the postgres user**, so a script in `/tmp`
written by another account needs `chmod a+r`. Otherwise it fails with
`Permission denied` and the comparison silently has nothing to compare.

## Restore for real

```bash
sudo systemctl stop keycloak
sudo -u postgres psql -c 'DROP DATABASE keycloak;'
sudo -u postgres psql -c 'CREATE DATABASE keycloak OWNER keycloak;'
sudo -u postgres pg_restore -d keycloak --no-owner --role=keycloak <dump>

# revert the pinned tag in roles/keycloak/defaults/main.yml, then
make deploy TAGS=keycloak
sudo systemctl status keycloak
```

Then confirm auth actually works — the service being "active" is not the same
as logins succeeding:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  https://lamware.shaiman.net/auth/realms/lamware/.well-known/openid-configuration
```

## Upgrade prerequisites

- [ ] Fresh dump taken **and** restore-verified on the day of the upgrade
- [ ] `keycloak.env` still sets `KEYCLOAK_ADMIN` / `KEYCLOAK_ADMIN_PASSWORD`,
      which 26.x deprecated in favour of `KC_BOOTSTRAP_ADMIN_USERNAME` /
      `KC_BOOTSTRAP_ADMIN_PASSWORD`. Inert here because the master realm
      already exists, but it should move to the current names during the
      upgrade rather than being found later
- [ ] A second admin session already open in another browser, so a failed login
      after the upgrade is not the first time anyone notices
- [ ] Confirm the CVE probe returns something other than a processing 400
      afterwards (see #457)
