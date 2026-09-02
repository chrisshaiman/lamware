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
  │  iptables DROP: virbr-det ─X► mgmt   virbr-det ─X► wg0     │
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

- The detonation bridge `virbr-det` has **no route** to the management interface (internet, named
  by `management_interface` — `enp3s0f0` here, not literally `eth0`) or
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
- That separation is a *privilege* boundary, not a data one. `pipeline` and
  `lamware-api` are members of the `lamware` group, which holds **read** access
  to CAPE's detonation output — extracted payloads, pcaps, process dumps. The
  analysis stages and the investigation agent exist to read that output, so
  this is deliberate; the grant is `rx` on `/opt/CAPEv2/storage` and neither
  user can write into CAPE's tree or act as `cape` (#385). A reader should not
  infer from "separate service users" that a compromised pipeline process
  cannot see other samples' results — it can.
- Tool arguments the LLM requests are validated against a regex whitelist
  (`shared/lamware_shared/tool_validators.py`) before any tool runs — **for the six
  Ghidra tools it covers**. `validate_ghidra_args()` returns "valid" for any tool
  absent from `GHIDRA_ARG_VALIDATORS`, and skips argument names it has no pattern
  for; its own docstring says callers layer generic validation on top. So this is a
  targeted allowlist on the tools that reach a decompiler, not blanket coverage of
  every tool argument.

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

  This is enforced by **dual scoring**, not by convention. `calculate_severity()`
  keeps two totals: `_severity_score` from deterministic evidence, which decides
  the band, and `_severity_score_llm_context` from model-asserted signals
  (capability count, the evasion hunter's self-reported confidence, and a family
  whose `_family_source` is model-derived), which is recorded and never decisive.
  `_severity_band_with_llm` shows what the band would be including it.

  A gap between the two bands is itself a signal worth an analyst's attention: the
  evidence and the model disagree, which is either a real finding or an injection
  attempt. `db_ingest` likewise refuses to fall back to the model's
  `risk_assessment` for the severity column — an absent verdict stays absent,
  because a missing one is a visible gap while a model-supplied one is
  indistinguishable from a real one.

  Until 2026-08-08 this bullet was aspirational: model-derived inputs contributed
  up to +30 against a `critical` threshold of 30, so a sample that reached the
  context could set or suppress its own verdict.
- A post-hoc `possible_prompt_influence` heuristic flags narratives that echo
  injection keywords ("benign", "false positive", …) for operator attention.

> **Not in the §2 diagram, and it should be:** the interpret *container* is
> egress-contained (§4.4), but the host-side LiteLLM proxy forwards sample-derived
> text — hostile strings, decompiled code — to the LLM provider. That is a real
> data flow out of the boundary. It is accepted rather than mitigated: the whole
> design depends on reaching a model, and cloud interpretation is the default
> backend. Recorded here so it is a decision rather than an oversight.

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

The edge is deliberately split. Stating it plainly, because the previous wording
implied the whole control plane was WireGuard-only and it is not (#529):

| Path | Public 443 | WireGuard |
|---|---|---|
| SPA, `/api/`, `/ws/` | yes — **intentional** | yes |
| `/auth/` (Keycloak login) | yes | yes |
| `/auth/admin/` (Keycloak admin console) | **no** | yes |
| `/docs`, `/redoc`, `/openapi.json` | **no** | yes |
| Cape UI/API (`:8000`) | never bound publicly | yes |

- Cape's UI/API bind to the WireGuard address only. This is the load-bearing
  reason WireGuard still exists: Cape v2's web interface is not a hardened
  internet-facing application, and it can submit samples, read every analysis,
  and reach the detonation infrastructure. Nothing else stands in front of it.
- The admin console and the OpenAPI documents are restricted to the WireGuard
  subnet by `allow`/`deny` in the nginx site config. Both listeners share one
  `server` block, so the split is per-location on `$remote_addr`.
- The public SPA is protected by Keycloak (PKCE S256, brute-force lockout after
  5 failures with a 900 s cap), nginx `limit_req`, and the `keycloak-auth`
  fail2ban jail. Those are all **in the request path**; WireGuard is not, which
  is what makes it worth keeping as a second, independent layer on the paths
  above.
- SSH does not depend on WireGuard — it listens on `0.0.0.0:22` and is
  restricted to `admin_cidrs` at the OVH robot firewall.
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
- **Detonation output is readable across samples.** A compromised `pipeline` or
  `lamware-api` process can read every analysis in CAPE storage, not just the
  one it is working on — payloads, pcaps, memory dumps. Per-analysis isolation
  of results is not modeled: the pipeline correlates across samples by design,
  and the investigation agent answers "have we seen this before". Write access
  is withheld, so results cannot be forged through this path.
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
