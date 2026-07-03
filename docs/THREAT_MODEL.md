# Threat Model

lamware executes and dissects live, adversary-controlled malware. Its entire
job is to process hostile input safely. This document states what it protects,
what it assumes an adversary can do, how the design contains that adversary,
and — most importantly — **what it does not protect against**.

It is a design artifact, not a certification. If you find a way to bypass a
mitigation described here, that is a vulnerability; see [SECURITY.md](../SECURITY.md).

---

## 1. Assets

In rough priority order, what an attacker gains by breaking a boundary:

1. **The management plane** — the operator's laptop, the WireGuard network, SSH
   to the host. Compromise here is game over.
2. **The host control plane** — the FastAPI backend, PostgreSQL, the pipeline
   orchestrator, Keycloak, and the secrets they hold (CAPE key, LLM key, DB
   credentials). Grants control over analysis and stored results.
3. **Outbound network reachability** — the ability to send *any* packet to the
   internet from inside the platform. For malware, egress is the objective:
   C2, exfiltration, propagation.
4. **Analysis integrity** — the correctness of verdicts, IOCs, and reports.
   Silently corrupted output is worse than no output.
5. **Stored corpus** — sample binaries and historical reports.

## 2. Trust zones

```
  ┌─ Management plane (TRUSTED) ───────────────────────────────┐
  │  operator laptop ── WireGuard (wg0) ──► host mgmt, Cape UI  │
  └────────────────────────────────────────────────────────────┘
                              │  authenticated VPN peer only
  ┌─ Host control plane (SEMI-TRUSTED) ────────────────────────┐
  │  FastAPI + Keycloak (PKCE) · PostgreSQL · pipeline          │
  │  orchestrator · LiteLLM proxy · analysis-tool containers    │
  └────────────────────────────────────────────────────────────┘
        │  brokers data to           │  processes sample-derived
        ▼  analysis containers       ▼  bytes and strings
  ┌─ Analysis sandbox (UNTRUSTED INPUT) ───────────────────────┐
  │  Ghidra / Volatility / interpret / … containers:           │
  │  --network=none --read-only --cap-drop=ALL                 │
  │  --security-opt=no-new-privileges --user 65534             │
  └────────────────────────────────────────────────────────────┘
  ┌─ Detonation VLAN (HOSTILE / AIR-GAPPED) ───────────────────┐
  │  KVM guest VMs running live malware on virbr-det           │
  │  iptables DROP: virbr-det ─X► eth0   virbr-det ─X► wg0     │
  └────────────────────────────────────────────────────────────┘
```

The two boundaries that carry the design are: **detonation VLAN → everything
else** (a live-malware boundary) and **sample-derived data → the control plane
and the LLM** (an untrusted-data boundary). Everything below is organized
around those.

## 3. Adversary model

We assume the sample is fully adversary-controlled and specifically built to
attack an analysis environment. Concretely, the adversary can:

- **Execute arbitrary code** in a detonation guest VM, including kernel-mode
  code, and attempt guest→host escape (VM breakout, QEMU/KVM exploits).
- **Detect virtualization/analysis** and alter behavior (evasion), including
  probing ACPI/SMBIOS firmware strings.
- **Embed prompt-injection payloads** in strings, filenames, decompiled code,
  and any other text that reaches the LLM interpretation layer.
- **Emit malformed/hostile data structures** designed to crash or exploit the
  parsers that ingest CAPE/Volatility/Ghidra output.
- **Attempt to beacon or exfiltrate** the moment it gets any network reach.

We assume the adversary **cannot**: reach the host before the OVH robot
firewall and iptables rules are active (provisioning is gated on it), obtain a
WireGuard private key, or authenticate to Keycloak.

## 4. Boundaries and mitigations

### 4.1 Detonation VLAN → internet / management plane

*Threat:* malware beacons out, or escapes the guest and pivots to the operator.

- The detonation bridge `virbr-det` has **no route** to `eth0` (internet) or
  `wg0` (management VPN), enforced by iptables `FORWARD … -j DROP` rules at the
  hypervisor, set before any ACCEPT rule. Guest-level containment is *not*
  relied upon.
- INetSim answers guest network requests locally, so C2 callbacks are logged
  without any real outbound packet.
- A successful guest escape lands on a stripped-down host with no cloud
  credentials and, critically, still no route off `virbr-det`.
- DSDT/ACPI tables are patched with host-specific values (`kvm-qemu.sh`) so
  firmware-string evasion is harder — the reason bare metal is required.

### 4.2 Analysis-tool containers → host

*Threat:* a malformed sample exploits Ghidra/Volatility/etc. and pivots to the
pipeline user or host.

- Every analysis container runs `--network=none --read-only --cap-drop=ALL
  --security-opt=no-new-privileges --user 65534:65534`, mounting only the one
  file it needs. No network namespace, no writable root, no capabilities, no
  privilege escalation.
- Containers are rootless Podman under a dedicated `pipeline` service user,
  separate from `cape`, the API user, and root.
- Tool arguments the LLM requests are validated against a regex whitelist
  (`shared/lamware_shared/tool_validators.py`) before any tool runs.

### 4.3 Sample-derived data → the LLM (prompt injection)

*Threat:* strings/decompiled code instruct the model to lie ("this is benign"),
exfiltrate, or misuse tools.

- All sample-derived content is wrapped in `UNTRUSTED_DATA` / `UNTRUSTED_CODE`
  delimiters with a standing instruction to treat it as hostile and ignore any
  instructions inside it.
- **LLM output never sets verdicts or triggers pipeline actions.** Maliciousness
  is decided by triage/CAPE/Volatility signals; the LLM is used only for
  *understanding* (narrative, hypotheses). A model that is fully deceived
  degrades the narrative, not the verdict.
- A post-hoc `possible_prompt_influence` heuristic flags narratives that echo
  injection keywords ("benign", "false positive", …) for operator attention.

### 4.4 LLM container → internet (egress containment)

*Threat:* injection or a tool bug turns the LLM container into an exfil path.

- The interpret container runs `--network=none`. It reaches the LLM **only**
  through a bind-mounted Unix domain socket to a host-side LiteLLM proxy.
- The configured base URL host is `litellm.invalid` — non-resolvable by design;
  all traffic rides the UDS, so any attempt to reach a real host **fails
  closed** rather than egressing.

### 4.5 Public edge → control plane

*Threat:* an unauthenticated party submits samples, reads results, or exploits
the API.

- Cape's UI/API bind to `wg0` only — reachable solely by authenticated
  WireGuard peers.
- The web app authenticates via Keycloak using the OAuth2 **PKCE** flow.
- Secrets live only in Ansible Vault (AES-256 at rest); none are committed.
  gitleaks runs in CI and pre-commit.

## 5. Residual risk — what this does NOT protect against

This is the honest part. These are **accepted** risks, not oversights. A report
that one of these *mitigations can be bypassed* is in scope; the residual itself
is known.

- **Guest → hypervisor escape is mitigated, not eliminated.** A working
  QEMU/KVM 0-day gets code execution on the host. Containment relies on the
  air-gap *after* escape (no route off `virbr-det`), not on the guest being
  unbreakable. Patch cadence for QEMU/KVM is an operational control, not a
  guarantee.
- **Prompt-injection defense is best-effort.** The delimiter + "ignore
  instructions" approach and the keyword heuristic reduce but do not eliminate
  injection. The load-bearing control is architectural: the LLM cannot change a
  verdict or take a privileged action, so a fully-deceived model corrupts a
  narrative, not a decision.
- **Analysis-tool 0-days are possible.** Ghidra/Volatility/CAPE parse hostile
  input; the container flags contain a compromise to a `--network=none`,
  capability-stripped, rootless namespace, but a container-escape 0-day chained
  with a tool 0-day is out of the model's protection.
- **The control plane trusts its operators.** Any authenticated WireGuard peer
  with API access is inside the trust boundary. There is no defense against a
  malicious or compromised operator account beyond Keycloak authentication.
- **Availability is not a goal.** A sample that wedges an analysis or fills disk
  is a nuisance, not a modeled threat; retention and guardrails handle it
  operationally, not as a security control.
- **History is not rewritten.** Anything ever committed (including pre-policy
  planning docs) remains in git history.

## 6. Reporting

Found a bypass of any mitigation above, or a boundary this document missed? Use
[private vulnerability reporting](https://github.com/chrisshaiman/lamware/security/advisories/new).
See [SECURITY.md](../SECURITY.md) for scope and expectations.
