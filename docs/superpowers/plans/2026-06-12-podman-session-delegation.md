# Podman Session Delegation Fix — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the investigation agent's sandbox and Ghidra tools work under the API's non-login `sudo -u pipeline` delegation, by having the wrappers re-enter pipeline's lingering systemd user session before running rootless podman.

**Architecture:** Add a small re-exec preamble to two wrapper templates. When invoked outside pipeline's user session, the wrapper re-execs itself via `systemd-run --user --pipe --quiet --wait --collect`, which runs it inside the lingering user manager where rootless podman's pause process is valid. No API change, no sudoers change, no new service, no storage reset. Full rationale: `docs/superpowers/specs/2026-06-12-podman-session-delegation-design.md`.

**Tech Stack:** Bash (Jinja2-templated `.j2` wrappers), Ansible (deploy), rootless Podman, systemd user instance (linger).

**Testing note:** These wrappers are `.j2` shell templates rendered at deploy time — they cannot be unit-tested locally (the de-templating limitation tracked separately). The authoritative verification is a **post-deploy functional smoke on the live host, exercising the exact non-login API path** (`sudo -u pipeline ...`) — NOT a login shell. This is the explicit lesson from the earlier Ghidra fix, whose login-shell "verification" masked this very bug. All "test" steps below run on the sandbox host over SSH.

**Branch:** `fix/podman-session-delegation` (already created; spec already committed on it).

---

### Task 1: Re-exec preamble in run-sandbox.sh.j2

run-sandbox is only ever invoked by the API (`sudo -u pipeline /usr/local/bin/run-sandbox [--data <dir>]`, script on stdin), so the preamble goes at the very top.

**Files:**
- Modify: `ansible/roles/python-sandbox/templates/run-sandbox.sh.j2` (insert after `set -uo pipefail`, line 17)

- [ ] **Step 1: Insert the preamble**

Insert this block immediately after the `set -uo pipefail` line and its following blank line, before `VOLUME_ARGS=()`:

```sh
# Re-enter pipeline's lingering systemd user session before touching podman.
# The API delegates via `sudo -u pipeline` (a non-login shell) where rootless
# podman cannot attach to its pause process (holds the user namespace) and
# fails with "image not found". systemd-run --user runs us inside the
# persistent user manager where podman works. The guard var prevents an
# infinite re-exec; the bus-socket check falls through to current behavior if
# no user session is reachable. See the design spec for full rationale.
_uid="$(id -u)"
if [ -z "${LAMWARE_IN_USER_SESSION:-}" ] && [ -S "/run/user/${_uid}/bus" ]; then
    export LAMWARE_IN_USER_SESSION=1
    exec env XDG_RUNTIME_DIR="/run/user/${_uid}" \
             DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${_uid}/bus" \
             systemd-run --user --pipe --quiet --wait --collect -- "$0" "$@"
fi
```

- [ ] **Step 2: Sanity-check the rendered shell is valid**

The template has no Jinja in the inserted block, so a direct bash parse check is valid:

Run: `bash -n ansible/roles/python-sandbox/templates/run-sandbox.sh.j2`
Expected: no output, exit 0 (syntax OK). (Jinja `{{ ... }}` tokens elsewhere are quoted/standalone and do not break `bash -n`; if they do, skip this and rely on the post-deploy smoke.)

- [ ] **Step 3: Commit**

```bash
git add ansible/roles/python-sandbox/templates/run-sandbox.sh.j2
git commit -m "fix(sandbox): re-enter pipeline user session so podman works under sudo -u

Investigation API delegates via 'sudo -u pipeline' (non-login); rootless
podman can't attach its pause process there -> 'image not found'. Re-exec via
systemd-run --user into pipeline's lingering session. Guard + bus-check keep
the non-session path unchanged when no session exists."
```

---

### Task 2: Re-exec preamble in run-ghidra-wrapper.sh.j2 (tool mode only)

The Ghidra wrapper serves three modes; only `--tool` is API-delegated. Analysis and shellcode modes are pipeline-native and already work, so the preamble goes **inside the `--tool` branch only**, leaving those modes untouched.

**Files:**
- Modify: `ansible/roles/ghidra/templates/run-ghidra-wrapper.sh.j2` (insert as the first statement inside `if [ "$1" = "--tool" ]; then`, line 28, before the arg-count check at line 32)

- [ ] **Step 1: Insert the preamble**

Change:

```sh
if [ "$1" = "--tool" ]; then
    # SECURITY: this arg-count check is load-bearing — the lamware-api sudoers
```

to:

```sh
if [ "$1" = "--tool" ]; then
    # Re-enter pipeline's lingering systemd user session before touching podman
    # (tool mode is API-delegated via non-login `sudo -u pipeline`, where
    # rootless podman cannot attach its pause process). Analysis/shellcode modes
    # are pipeline-native and intentionally NOT wrapped. Guard prevents an
    # infinite re-exec; bus-socket check falls through if no session exists.
    # See the design spec for full rationale.
    _uid="$(id -u)"
    if [ -z "${LAMWARE_IN_USER_SESSION:-}" ] && [ -S "/run/user/${_uid}/bus" ]; then
        export LAMWARE_IN_USER_SESSION=1
        exec env XDG_RUNTIME_DIR="/run/user/${_uid}" \
                 DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${_uid}/bus" \
                 systemd-run --user --pipe --quiet --wait --collect -- "$0" "$@"
    fi

    # SECURITY: this arg-count check is load-bearing — the lamware-api sudoers
```

(The re-exec replays `--tool <args>` so the re-execed process re-enters this same branch with the guard set, then proceeds to the arg-count check and body.)

- [ ] **Step 2: Sanity-check the rendered shell is valid**

Run: `bash -n ansible/roles/ghidra/templates/run-ghidra-wrapper.sh.j2`
Expected: exit 0. (If Jinja tokens break `bash -n`, skip and rely on the post-deploy smoke.)

- [ ] **Step 3: Confirm analysis/shellcode modes are untouched**

Run: `git diff ansible/roles/ghidra/templates/run-ghidra-wrapper.sh.j2`
Expected: the only change is the added block inside the `--tool` branch; no lines in the analysis-mode or shellcode-mode sections change.

- [ ] **Step 4: Commit**

```bash
git add ansible/roles/ghidra/templates/run-ghidra-wrapper.sh.j2
git commit -m "fix(ghidra): re-enter pipeline user session in tool mode so podman works under sudo -u

Tool mode is API-delegated via 'sudo -u pipeline' (non-login) where rootless
podman can't attach its pause process. Re-exec via systemd-run --user into
pipeline's lingering session. Scoped to the --tool branch so the pipeline-native
analysis/shellcode modes are unchanged. Guard + bus-check preserve fallback."
```

---

### Task 3: Deploy and verify on the exact non-login API path

This is the real test. Deploy re-renders both wrappers; verification uses `sudo -u pipeline` (non-login) — the path the API actually uses.

**Files:** none (deploy + verification only)

- [ ] **Step 1: Push the branch**

```bash
git push -u origin fix/podman-session-delegation
```

- [ ] **Step 2: Deploy (requires Ansible Vault password — operator runs this)**

```bash
cd ansible
ansible-playbook site.yml --tags python-sandbox,ghidra -i inventory/hosts --ask-vault-pass
```
Expected: the "deploy run-sandbox" and "deploy run-ghidra wrapper" tasks show `changed`. Image-build tasks no-op (templates only changed).

- [ ] **Step 3: Verify the wrappers carry the fix**

Run (on the host):
```bash
sudo grep -c "systemd-run --user" /usr/local/bin/run-sandbox /usr/local/bin/run-ghidra
```
Expected: `1` for each.

- [ ] **Step 4: TEST — sandbox via the exact non-login API path (expect 42)**

```bash
echo 'print(6*7)' | sudo -u pipeline /usr/local/bin/run-sandbox
```
Expected: `42` (the previous failure was `Error: image ... not found`).

- [ ] **Step 5: TEST — Ghidra tool mode via the exact non-login API path (expect count 200)**

```bash
sudo -u pipeline /usr/local/bin/run-ghidra --tool \
  /opt/pipeline/reports/19e0b62abee9/project \
  6570890558b0fe7fd8903349ade634a47a61d3b9f7bf7c224826567d42b623fe \
  list_functions '{}'
```
Expected: JSON containing `"count": 200`.

- [ ] **Step 6: TEST — security: confirm no host session env leaks into the container (expect empty list)**

```bash
echo 'import os; print(sorted(k for k in os.environ if "XDG" in k or "DBUS" in k))' \
  | sudo -u pipeline /usr/local/bin/run-sandbox
```
Expected: `[]` (the transient unit's XDG/DBUS env must not propagate into the analysis container; podman only forwards explicit `--env`).

- [ ] **Step 7: TEST — end-to-end through the investigation agent UI**

On analysis 827 in the UI: ask the agent to run a Python snippet (run_python) and to list functions / decompile (Ghidra). Both should return results, not "image not found" / "project unavailable".

- [ ] **Step 8: Regression check — pipeline-native Ghidra still works**

The ghidra diff is confined to the `--tool` branch (Task 2 Step 3), so analysis mode is unchanged. Optional gold-standard confirmation: submit one fresh PE sample through the pipeline and confirm it completes and persists a populated Ghidra project (a `db.1.gbf` under `reports/<task>/project/analysis.rep/idata`).

---

### Task 4: Open the PR

**Files:** none

- [ ] **Step 1: Create the PR**

```bash
gh pr create --base main --head fix/podman-session-delegation \
  --title "fix(investigate): wrappers re-enter pipeline user session for podman (sandbox + ghidra tools)" \
  --body-file <(cat <<'EOF'
Fixes the investigation-agent sandbox + Ghidra tools failing under the API's
non-login `sudo -u pipeline` delegation (rootless podman pause process can't
init outside pipeline's user session).

Wrappers re-exec into pipeline's lingering systemd user session via
`systemd-run --user`. No API change, no sudoers change, no new service, no
storage reset. Ghidra change scoped to the `--tool` branch so pipeline-native
analysis/shellcode modes are untouched.

Design: docs/superpowers/specs/2026-06-12-podman-session-delegation-design.md

Verified on the exact non-login API path: sandbox `print(6*7)`→42; Ghidra
`list_functions`→count 200; no XDG/DBUS env leak into the container.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)
```

- [ ] **Step 2: Confirm CI is green, then merge (operator decision — merge commit, like prior PRs)**

```bash
gh pr checks <PR#>
gh pr merge <PR#> --merge --delete-branch
```
