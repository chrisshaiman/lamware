# Podman Session Delegation Fix — Design

**Goal:** Make the investigation agent's sandbox and Ghidra tools work when invoked through the API, by having the tool wrappers re-enter pipeline's systemd user session before running rootless podman — without changing the API or relaxing the scoped sudoers rule.

**Status:** Designed 2026-06-12. Supersedes the "stable runroot" direction in the runroot investigation notes.

---

## Problem

The investigation API (running as `lamware-api`) delegates tool execution to the `pipeline` user via a scoped sudoers rule (ADR-017):

```
lamware-api ALL=(pipeline) NOPASSWD: /usr/local/bin/run-sandbox, /usr/local/bin/run-sandbox *, /usr/local/bin/run-ghidra --tool *
```

The API invokes these as `sudo -u pipeline /usr/local/bin/run-{sandbox,ghidra} ...` (a **non-login** shell). In that context rootless podman **fails to initialize at all** — it cannot find pipeline's image storage and reports "image not found" for the sandbox, and Ghidra tool calls fail. As a result, both tools are unusable through the agent UI even though the images are present and (after the empty-project fix, PR #102) Ghidra projects persist correctly.

### Root cause

The blocker is rootless podman's **pause process** — the long-lived helper (catatonit) that holds pipeline's user namespace open — together with a runroot baked into the storage DB. The pause process is anchored to pipeline's running user-manager runtime; a non-login `sudo -u pipeline` context cannot attach to it. (NB: this is *not* simply "podman needs a login session." Podman in principle only needs `XDG_RUNTIME_DIR` (or a `/tmp/containers-user-$UID` fallback) + `HOME` + subuid/subgid mappings. The failure here is the *namespace/pause-process state*, which env vars cannot reconstitute from outside the session.)

Evidence gathered 2026-06-12:

- `sudo -iu pipeline` (real login session) → podman works; `list_functions` returns 200, `decompile_function` parses its JSON arg.
- `sudo -u pipeline` (non-login) → `podman info` produces **zero output**; image "not found".
- Env-var replication does **not** work — tried `HOME`, `XDG_RUNTIME_DIR=/run/user/997`, `DBUS_SESSION_BUS_ADDRESS`, clean `env -i`, matching `TMPDIR`, explicit `--root`/`--runroot`, pinning `runroot` in `storage.conf`, and setting `XDG_RUNTIME_DIR` to the DB's exact runroot. The last surfaced the real error: `invalid internal status, try resetting the pause process with "podman system migrate": setting up the process`. So the runroot path is not the issue; the namespace/pause-process state is.
- `systemd-run --user` works because it executes the command *inside* pipeline's lingering user manager, where the pause process is valid and the runtime matches the DB — verified end-to-end.
- `podman system reset` (or `podman system migrate`, which resets the pause process) is not an option: pipeline's rootless storage holds ~12 GB across ~15 images (the entire analysis pipeline), and resetting would force a full rebuild and risk disrupting in-flight pipeline state.

### The constraint conflict

`sudo -iu` provides the needed session but requires the sudoers rule to permit a login **shell**, which would grant `lamware-api` arbitrary command execution as `pipeline` — defeating the scoped-sudo security model that is central to this project. Confirmed: lamware-api's current rule rejects `sudo -iu` ("a password is required"). So the fix must bridge to a session **without** loosening sudo.

---

## Design

### Architecture

`pipeline` has **lingering enabled** (`loginctl Linger=yes`), so its systemd **user manager** runs persistently with a live bus at `/run/user/997/bus`, independent of any interactive login. A non-login `pipeline` process can therefore submit work into that running session via `systemd-run --user`.

Each tool wrapper gains a **re-exec preamble** at the top. When invoked outside the user session (the API's `sudo -u pipeline` case), it re-execs *itself* into the session:

```sh
# Re-enter pipeline's lingering systemd user session so rootless podman can
# initialize. The scoped sudoers invocation (sudo -u pipeline) is a non-login
# shell where podman cannot resolve its per-user runtime; systemd-run --user
# runs us inside the persistent user manager where it can. Guard prevents an
# infinite re-exec loop; the bus-socket check keeps the pipeline-native path
# (which already works) unchanged when no user session is reachable.
_uid="$(id -u)"
if [ -z "${LAMWARE_IN_USER_SESSION:-}" ] && [ -S "/run/user/${_uid}/bus" ]; then
    export LAMWARE_IN_USER_SESSION=1
    exec env XDG_RUNTIME_DIR="/run/user/${_uid}" \
             DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${_uid}/bus" \
             systemd-run --user --pipe --quiet --wait --collect -- "$0" "$@"
fi
```

The wrapper **body is unchanged** — the existing lock-fix copy, the `podman unshare chown` empty-project fix, and the exit-code handling all run as before, just now inside the session where podman works. The **API call and the sudoers rule are not touched**: the entire fix lives in the two wrapper templates.

### Why `--pipe --quiet --wait --collect`

Verified 2026-06-12 that this combination passes everything cleanly through `systemd-run --user`:

- `--pipe` connects the transient unit's stdin/stdout/stderr to the wrapper's (so the sandbox script arrives on stdin and the tool's JSON result returns on stdout).
- `--quiet` suppresses systemd-run's own resource-summary output, so only the tool's stdout flows back (without it, the summary pollutes stdout).
- `--wait` runs synchronously and **propagates the unit's exit code** (verified: a script doing `sys.exit(3)` yields rc=3; the API's `_ghidra_tool` returncode check then behaves correctly).
- `--collect` garbage-collects the transient unit after it exits.

Verified results through the exact pattern: run-sandbox stdin→`42` rc=0; failing script→rc=3; run-ghidra `--tool ... list_functions '{}'`→`"count": 200`.

### Components

Two wrapper templates, each gaining the same preamble:

1. `ansible/roles/python-sandbox/templates/run-sandbox.sh.j2`
2. `ansible/roles/ghidra/templates/run-ghidra-wrapper.sh.j2`

**Decision — duplicate the preamble in both wrappers rather than factor into a shared sourced snippet.** It is ~8 lines, the two roles are independently deployed, and a shared file would add a cross-role dependency and another deploy ordering concern. Duplication is the simpler, more isolated choice here. (If a third consumer appears, revisit.)

### Data flow

```
API (lamware-api)
  → sudo -u pipeline /usr/local/bin/run-X [args]   (stdin: script, for sandbox)   [UNCHANGED]
    → wrapper preamble: not in session + bus present
      → exec systemd-run --user --pipe --quiet --wait --collect -- run-X [args]
        → wrapper body runs INSIDE pipeline's user session
          → podman initializes correctly → tool runs
        ← stdout (JSON result) + exit code flow back through --pipe
  ← API captures stdout / returncode   [UNCHANGED]
```

### Backward compatibility (key safety property)

The Ghidra `run-ghidra` wrapper is also called by the **pipeline itself** (analysis mode, shellcode mode) in a context where podman already works (analysis 827 persisted a 28 MB project correctly). The design must not regress that.

- The **guard var** (`LAMWARE_IN_USER_SESSION`) prevents infinite re-exec.
- The **bus-socket check** (`-S /run/user/$uid/bus`) means: if a user session is not reachable, the wrapper proceeds **without** re-exec — exactly today's behavior. The change only *adds* a working path for the non-login API delegation; it never removes the existing one.
- If the pipeline-native context *does* have the bus (likely, since pipeline runs as pipeline with linger), the re-exec simply normalizes it into the session, which also works.

Implementation must verify a full fresh pipeline analysis still completes after the change.

### Error handling

- Re-exec loop is impossible (guard var).
- If `systemd-run` or the user bus is genuinely unavailable, the wrapper falls through to the non-session path and, on podman failure, emits the existing JSON error — the agent receives a real message, never a silent hang. No new failure modes versus today.
- `~300ms` transient-unit spawn overhead per call — acceptable for interactive agent tools.

### Testing / verification

The verification **must exercise the exact non-login API path** (`sudo -u pipeline ...`), not a login shell — the lesson from the earlier Ghidra fix, whose "end-to-end" check used a login shell and masked this very bug.

1. `sudo -u pipeline /usr/local/bin/run-sandbox <<< 'print(6*7)'` → `42`, rc 0.
2. `sudo -u pipeline /usr/local/bin/run-ghidra --tool /opt/pipeline/reports/19e0b62abee9/project 6570890558b0fe7fd8903349ade634a47a61d3b9f7bf7c224826567d42b623fe list_functions '{}'` → `"count": 200`.
3. End-to-end through the investigation agent UI on analysis 827: run_python and a Ghidra tool both return results.
4. Regression: a full fresh pipeline analysis on a PE completes and persists a populated Ghidra project (native path intact).

### Scope

- **Files:** the two wrapper templates only.
- **No** API change, **no** sudoers change, **no** new service, **no** image rebuild, **no** storage reset.
- Preserves the ADR-017 scoped-sudo security model in full.

### Security analysis

Approach A introduces no new privilege escalation or attack surface, and is the most least-privilege of the viable options.

**Trust boundary (lamware-api → pipeline) — unchanged.** The scoped sudoers rule is untouched: `lamware-api` may still run only `run-sandbox` and `run-ghidra --tool *` as `pipeline`. The `systemd-run --user` call is *inside* the wrapper, after sudo has already dropped to `pipeline`, so the API gains no new capability. This is why `sudo -iu` was rejected — it would require granting a login *shell* (arbitrary execution as pipeline); Approach A gets the session without that, so it is strictly better than `-iu` here.

**Privilege model — no crossing.** `systemd-run --user` is pipeline asking its *own* user-systemd manager to run a transient unit, as pipeline (same UID, no setuid). It is the user instance, not `--system` (which would need root).

**Malware-containment boundary — unchanged (the one that matters most on this platform).** The boundary protecting the host from the *sample* is the container, and none of its constraints change: the wrapper body still runs podman `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --user 65534`, rootless (UID-mapped). Approach A only changes how the host-side wrapper reaches podman, not how the malware-running container is confined. A hypothetical container escape would land at `pipeline`-uid either way.

**Versus alternatives.** `sudo -iu` grants shell access (worse); a podman API socket (B) exposes a surface that can do anything podman can (worse). A adds no socket, no shell, no new sudo scope.

**Minor caveats (not vulnerabilities, recorded for completeness):**
1. Pipeline's user bus socket `/run/user/997/bus` is `srw-rw-rw-`, but its parent `/run/user/997` is `0700 pipeline`, so no other user can traverse to it. Pre-existing systemd default, not introduced here.
2. Relies on `Linger=yes` — pre-existing, standard for rootless-podman service accounts, not network-facing.
3. The guard var `LAMWARE_IN_USER_SESSION` is at most a denial lever (if set, the wrapper skips re-exec and the tool fails — no escalation); it is caller-controlled (lamware-api), not reachable by malware inside a container.
4. Transient-unit churn per tool call is bounded by the existing per-turn tool-call cap (the real flood control); minor upside is each call leaves a journald audit trail.
5. The `--` in `systemd-run ... -- "$0" "$@"` is load-bearing — it prevents a tool argument from being parsed as a systemd-run option. Required.

**Verification to include in the plan:** confirm the container's environment is clean — i.e., the transient unit does not leak host `XDG_RUNTIME_DIR`/`DBUS_SESSION_BUS_ADDRESS` into the analysis container (podman should only pass env via explicit `--env`; verify by inspecting the container env during a tool run).
