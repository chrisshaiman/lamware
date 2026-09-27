<!-- Copyright 2026 Christopher Shaiman / SPDX-License-Identifier: Apache-2.0 -->
# After a restart: re-arm the vault password

One command, once per boot:

```
make vault-session
```

That is the whole procedure. The rest of this page is why, and what to do when
something looks wrong.

## What it does

Prompts once, writes the password to `/dev/shm/lamware-vault-$UID` (mode 600),
and **verifies it decrypts `ansible/vars/secrets.yml` before reporting success**.
A typo is rejected on the spot and nothing is stored — otherwise the first
symptom would be a failed deploy several minutes later, with the password
looking configured the whole time.

`/dev/shm` is tmpfs: RAM-backed, wiped on reboot, never written to the SSD. The
convenience is opt-in per boot rather than a secret living on disk indefinitely.

## Checking and clearing

```
make vault-session-status    # which source is in use, if any
make vault-session-clear     # forget it now, without rebooting
```

## What it changes

| target | before a session | with one |
|---|---|---|
| `make deploy TAGS=ghidra,postgres` | prompts | silent |
| `make merge-check` | prompts | silent |
| `make smoke` | prompts | silent |
| `make deploy TAGS=api,hardening` | prompts | **still prompts** |

The last row is deliberate. See below.

## Roles that always prompt

```
hardening  networking  wireguard  keycloak  kvm  all
```

A mistake in these does not produce a wrong number — it produces a host you
cannot reach. #563 is the precedent: a `TAGS=hardening` deploy left the sandbox
unable to reach its own guests, every service reported healthy, and it cost a
working day. `wireguard` is the management VPN, so a mistake there means a drive
to a console.

Typing the password is proof a human is present. An automated caller — CI, a
script, an AI agent — has no TTY, so the prompt fails immediately:

```
[ERROR]: EOFError (ctrl-d) on prompt for (default)
```

There is no override flag, on purpose. An override gets set once, works, and
then lives in a shell profile — at which point this is a convention rather than
a mechanism.

## The permanent alternative

`~/.vault_pass` still works and takes precedence only when no session file
exists. It survives reboots, which is the trade-off: less typing, a plaintext
secret on disk indefinitely, and the console-role gate above still applies.

## If a target prompts unexpectedly

1. `make vault-session-status` — the session probably expired with a reboot.
2. Check the tags. A console role in the list prompts by design, even mid-list:
   `TAGS=api,hardening` prompts because of `hardening`.
3. `make -n deploy TAGS=...` shows which flag a run would actually use.
