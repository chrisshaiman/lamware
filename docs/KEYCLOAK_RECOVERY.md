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
| Upgrade fails, Keycloak will not start | Revert image tag, then restore DB |
| Admin password lost or account locked | `kc.sh bootstrap-admin user` |
| Realm/client config damaged | Restore DB |

### Two different "bootstrap admin" things — do not confuse them

An earlier version of this document said the database restore was the only
recovery path. That was **wrong**, and it was wrong in the way that matters:
it would have sent someone to a destructive procedure when a non-destructive
one exists.

**The env vars are inert here.** `KC_BOOTSTRAP_ADMIN_USERNAME` /
`KC_BOOTSTRAP_ADMIN_PASSWORD` (and the older `KEYCLOAK_ADMIN*`) are, per
Keycloak's own help, *"used only when the master realm is created"*. Master
already exists on this deployment, so setting them changes nothing.

**The CLI command is not.** `kc.sh bootstrap-admin` works against an existing
database:

```
kc.sh bootstrap-admin user      Add an admin user with a password
kc.sh bootstrap-admin service   Add an admin service account
```

So an admin lockout does **not** require a restore. Add a temporary admin,
log in, fix the real account, then remove the temporary one.

This distinction was found while actually locked out — the earlier claim came
from reading the env-var help and generalising from it.

### Before assuming a lockout, read the error

Keycloak names the failure precisely, and the names mean different things:

| `error=` in the journal | Meaning |
|---|---|
| `user_not_found` | The username does not exist **in that realm** |
| `invalid_user_credentials` | Right user, wrong password |
| `user_temporarily_disabled` | Brute-force lock (in-memory under `KC_CACHE=local`; a restart clears it) |

```bash
sudo journalctl -u keycloak --since '30 min ago' -o cat \
  | grep LOGIN_ERROR | tail -3 | tr ',' '\n' | grep -E 'error=|username=|realmId='
```

Check fail2ban too — repeated failures ban the source IP, which looks like a
Keycloak problem but is not:

```bash
sudo fail2ban-client status keycloak-auth          # 10 retries / 600s / 3600s ban
sudo fail2ban-client set keycloak-auth unbanip <ip>
```

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

- [ ] **Rehearse the upgrade against a copy of the production database.** This
      is the step whose absence caused an outage on 2026-08-29: 26.7.2 deployed,
      crash-looped on `RealmEntity.components` in the master realm, and returned
      502 on every endpoint including the admin console. Every piece needed to
      catch it beforehand already existed — a verified dump, a tested restore, a
      scratch database — and was never assembled. Preparedness is not assurance;
      none of the other prerequisites say anything about whether the new version
      can *start* on this data.

      ```bash
      sudo -u postgres psql -c 'CREATE DATABASE keycloak_upgradetest OWNER keycloak;'
      sudo -u postgres pg_restore -d keycloak_upgradetest --no-owner --role=keycloak <dump>
      # start the NEW image against keycloak_upgradetest, not the live database
      # only schedule the real upgrade if it starts clean
      ```
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

## A schema note, learned the hard way

26.7.2's migration was **purely additive** — 13 tables added, none removed
(`auth_session`, `root_auth_session`, `login_failure`, `single_use_object`,
`cluster_event`, `server_config`, `outbox_entry`, `org_invitation`,
`workflow_state`, and four verifiable-credential tables). Several are state
26.1 keeps in Infinispan that later versions moved into the database.

Consequently **26.1.5 started cleanly against the migrated 100-table schema**
after the tag was reverted — auth and admin console both returned 200 with no
errors. That was not expected; the assumption going in was that an old version
could not read a newer schema at all.

Do not read that as permission to stay on a hybrid schema. The additive check
rules out *dropped* tables; it says nothing about *altered columns* on the
tables that remain. "No symptoms" is not "supported". Restore to the matching
baseline.

It does mean a failed upgrade is less catastrophic than assumed: the service
may come back on the old image before the restore, which buys time to do the
restore carefully rather than under pressure.
