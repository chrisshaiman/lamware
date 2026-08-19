# lamware

> **Drop a sample. Get a correlated investigation.**

[![Release](https://img.shields.io/github/v/release/chrisshaiman/lamware?sort=semver)](https://github.com/chrisshaiman/lamware/releases)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.12%2B-blue)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-bare%20metal%20%7C%20KVM-lightgrey)]()
[![IaC](https://img.shields.io/badge/IaC-Terraform%20%2B%20Ansible-purple)]()
[![Sandbox](https://img.shields.io/badge/sandbox-CAPEv2-orange)]()
[![Status](https://img.shields.io/badge/status-v0.x%20research-yellow)]()

lamware is an end-to-end malware analysis platform combining dynamic execution, memory forensics, static analysis, and evidence-based LLM investigation in a single pipeline.

The thesis: **malware analysis tools are most useful when their observations are correlated, not when they are read as independent reports.** lamware runs CAPEv2, Volatility 3, Ghidra and language-specific analyzers, applies deterministic cross-tool correlation, and only then gives an LLM access to the resulting evidence.

> **Triage, CAPE and Volatility determine maliciousness. The AI explains the evidence; it does not decide whether a sample is malicious.**

> [!WARNING]
> **Status: v0.x research and engineering project. It executes hostile code.**
> Functional end to end, but not a hardened commercial appliance. Deploy only on
> dedicated infrastructure, and only after verifying containment. See
> [Current limitations](#current-limitations) and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Why lamware?

A conventional workflow leaves the hardest part — deciding which observations corroborate each other — to the analyst:

```
     sample                                    sample
        │                                         │
  ┌─────┼─────┐                        ┌──────────┼──────────┐
  ▼     ▼     ▼                        ▼          ▼          ▼
CAPE  Volat. Ghidra                  CAPE     Volatility   Static
  │     │     │                        └──────────┼──────────┘
  ▼     ▼     ▼                                   ▼
report report report                       deterministic
  │     │     │                            cross-correlation
  └─────┼─────┘                                   ▼
        ▼                                   evidence graph
     analyst                                      ▼
                                           LLM investigation
                                                  ▼
                                     grounded analyst narrative

   conventional                              lamware
```

The LLM sits **downstream of the evidence**. It is never asked to decide maliciousness from a blob of text.

---

## What the AI does — and does not do

| The AI does | The AI does not |
|---|---|
| Investigate decompiled code and follow cross-references | Determine whether a sample is malicious |
| Explain observed behavior, connect static to dynamic findings | Modify the maliciousness verdict |
| Identify plausible attack techniques | Write arbitrary files to the analysis host |
| Produce analyst-oriented narratives | Access another analysis by changing an `analysis_id` |
| Propose findings for human confirmation | Receive the Anthropic API key |
| Help navigate large volumes of analysis output | Reach the network from an analysis container |

LLM output is **interpretation of evidence, not evidence itself**. Findings the agent proposes are held as proposals until an analyst confirms them.

These are capability boundaries rather than input filters: `read_payload` takes an index into a resolved list rather than a path, tool arguments reach subprocesses as `argv` rather than a shell string, sandbox scripts arrive on stdin, and `pin_finding` returns a proposal instead of writing. See [ADR-017](docs/DECISIONS.md) for the architecture and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for what remains unmitigated.

---

## What it does

```
                         sample
                            │
        ┌──────────┬────────┴────────┬──────────┐
        ▼          ▼                 ▼          ▼
    dynamic     memory            static     network
   detonation  forensics         analysis    analysis
    (CAPEv2)  (Volatility 3)  (Ghidra, ILSpy, (Zeek,
        │          │           GoReSym, …)   Suricata)
        └──────────┴────────┬────────┴──────────┘
                            ▼
                     deterministic
                   cross-correlation
                            ▼
                    LLM investigation
                            ▼
                 grounded analyst report
```

| Stage | What it produces |
|---|---|
| **Triage** | YARA, ssdeep, FLOSS, entropy, PE metadata — and the routing decision |
| **Dynamic** | CAPEv2 detonation in Windows guests: behavioral signatures, API traces, memory dump, dropped files, network capture, injection traces |
| **Memory** | Volatility 3 over the dump — 6 standard plugins plus trigger-gated extras: injected regions, command lines, connections, mutexes, anomalous parents |
| **Static** | Routed by binary type across 8 analyzers (see below) |
| **Correlation** | Deterministic rules joining observations no single tool produces alone |
| **Investigation** | LLM reads the static analysis through bounded tools and explains the evidence |
| **Reporting** | IOCs, ATT&CK candidates, kill-chain narrative, PDF, dashboard |

Every analysis container runs `--network=none`. The full stage-by-stage pipeline, the
host topology and the database schema are in [ARCHITECTURE.md](ARCHITECTURE.md).

---

## What you get back

| Output | Description |
|---|---|
| **Structured IOCs** | STIX 2.1 types, source attribution, context — ready for SIEM and block lists |
| **ATT&CK technique candidates** | From CAPE behavioral signatures and analysis, with IOC-to-technique evidence. Candidates for analyst confirmation — accuracy is not established by a dedicated evaluation |
| **Cross-tool findings** | Dropped files confirmed loaded, shellcode self-modification, cmdline spoofing — with the tools that corroborated each |
| **Analyst narrative** | What the malware does and how, traced through decompiled code and grounded in the evidence shown |
| **Kill chain summary** | Briefing organized by attack phase rather than by tool |
| **Memory forensics** | Suspicious cmdlines, mutex IOCs, DLLs from unusual paths, process anomalies |
| **PDF report** | Source attribution badges showing which stage surfaced each finding |
| **PostgreSQL** | Normalized schema for cross-sample correlation and family tracking |
| **Web dashboard** | Analyses, IOCs, techniques, evasion view, live pipeline status |

---

## What we've demonstrated

### Cross-tool correlation

Findings that no single tool produces alone:

| Correlation | What it detects | Tools |
|---|---|---|
| Dropped file in `dlllist` | Payload was loaded and executed, not just written | Cape + Volatility |
| `WriteProcessMemory` vs `malfind` | Shellcode decrypted itself after injection | Cape + Volatility |
| Cape cmdline vs PEB cmdline | Process overwrote its own command line to hide | Cape + Volatility |
| Cape DNS vs shellcode APIs | DGA domains + networking APIs = confirmed C2 | Cape + Volatility artifacts |
| YARA family + Cape config | Family-specific config extraction guided by signature | Triage + Cape |

### Trace-derived injection extraction

Rather than scanning 17,000+ memory regions heuristically, lamware extracts the bytes written into remote processes directly from CAPE's `WriteProcessMemory` observations, preserving source process, target process, address and API-trace provenance.

The bytes are what CAPE recorded being written, which is a stronger starting point than a heuristic memory scan — but it is an observation, not a guarantee that those bytes are the final executable payload in every case. Whether the region changed after injection is a separate question, and it is exactly what the `WriteProcessMemory` vs `malfind` correlation above tests.

### Language-aware routing

lamware detects the binary type and routes to the analyzer that can actually read it —
Ghidra, ILSpy, GoReSym, pycdc, CFR, olevba or PSDecode across 8 binary types, each with a
prompt written for that language's patterns. The routing table is in
[ARCHITECTURE.md](ARCHITECTURE.md#language-routing).

### AI-driven investigation

**On the native PE path**, the interpret stage uses an LLM's tool-use API with 6 Ghidra query tools. The other language paths (.NET, Go, PyInstaller, Java, Office, PowerShell) receive single-shot interpretation over their decompiler output. The agent autonomously lists functions, decompiles suspicious ones, traces cross-references, and reads data — producing a structured analysis of capabilities and candidate ATT&CK techniques, with every concrete claim checked against the evidence it was shown. It follows leads iteratively rather than making a single pass.

The agent does not attribute a malware family, and it does not decide maliciousness. Family labels come from CAPE signatures or MalwareBazaar metadata and are presented as provenance; the verdict comes from triage, CAPE, and Volatility. See [Evaluation](#evaluation) for why, and what the stage *is* measured on.

| Tool | Description |
|---|---|
| `decompile_function` | Decompile a function by name or address |
| `get_xrefs_to` | What calls this function? |
| `get_xrefs_from` | What does this function call? |
| `get_strings_at` | Defined strings near an address |
| `list_functions` | List/search functions with xref counts |
| `get_data_at` | Read raw bytes at an address |

Single-shot is a deliberate choice there, not a gap: GoReSym and ILSpy already recover named functions, types and packages, so there is little for an agent to navigate toward.

Model routing and cost mechanics are in [ARCHITECTURE.md](ARCHITECTURE.md); the load-bearing property is that the Anthropic key lives only in the LiteLLM proxy and never reaches an analysis container.

### Kill chain narrative

The executive summary organizes findings by behavior — injection, persistence, C2, evasion — not by tool. Each claim cites which tools corroborated it:

> *"The malware injected identical 235-byte shellcode stubs into 59 system processes (Cape API traces), resolving `LoadLibraryA`, `CreateRemoteThread`, and `WSAStartup` at runtime (Volatility memory artifacts), confirming both process injection and C2 communication capability."*

---

## Evaluation

**The most useful result so far is a negative one.** We measured whether the model could
name a malware family from decompiled code. It scored **0/14** locally and **0/7** on the
frontier reference, on samples whose MalwareBazaar labels disagreed with the reference on
every one. Rather than tune prompts until the number improved, we retired family
attribution as a capability metric for this stage and reframed the column as a
contamination probe — near-zero is the expected result, and an unexpectedly *high* score
would be evidence of memorised published analyses rather than analysis of the binary.
Full reasoning, with the outside literature that narrowed our own argument, is in
[ADR-019](docs/DECISIONS.md).

The harness that produced it measures grounding rather than plausibility, and records
per-cell sampling configuration so a result is reproducible. Details below; the code is
in `ansible/roles/pipeline/files/lamware_eval/`.

A capability claim without its evaluation is marketing, so the rest of this section is
what the stage *is* held to.

**What the stage is scored on.** Not "did it name the family" but **"is every concrete claim supported by the evidence the model was shown"**. `grounding_check.py` extracts each concrete IOC value the model asserts — domains, IPs, URLs, registry keys, mutexes — and cross-references it against the source text it was given, after defang normalization. A value whose artifacts do not appear in the source is a fabrication flag. The harness reports `grounded_ratio` and a fabrication count per cell.

This exists because it was needed: a local model produced fluent, well-structured analysis containing an invented C2 domain and an invented registry GUID.

| Metric | What it answers |
|---|---|
| `grounded_ratio` | Did the model make this up? |
| fabrication count | Which specific claims are unsupported |
| `tool_call_error_rate` | Was the model driving the tools, or fighting them |
| `tool_layer_broken` | Was this cell measuring the model or the infrastructure |
| `parse_failed` | Finished but unparseable — neither success nor error |
| `family_guess` | **Contamination probe — not a capability metric** |

**Why the family result is about the metric, not the models.** When a 35B local model and a frontier reference both score zero, the metric is the suspect. The published literature agrees: the [MOTIF paper](https://arxiv.org/abs/2111.15031) measures AVClass at **46.78%** and AV majority voting at **62.10%** against expert ground truth, so the label itself is under 50% reliable.

The naive conclusion — "packing destroys family ID" — is **too strong and is not the claim here**. Supervised byte-level classifiers reach 91.66% on real packed malware. The distinction is what is being classified and how: byte histograms, entropy, and section characteristics over a *closed* family set is a different task from an LLM reading *decompiled code* over an open set of 454+. A packer stub is generic as source while staying statistically distinctive as bytes.

So `family_guess` stays in the scorecard **inverted**: near-zero is correct, and an unexpectedly *high* score is evidence of memorized published analyses rather than analysis of the binary. Prompts are not tuned against it.

The same structure explains why published threat-report IOCs cannot ground this stage: **0 of 9** icedid samples and **0 of 2** azorult samples contained any literal from their own linked reports. The reports describe runtime behaviour; static analysis sees the packer. Ground truth for recall therefore comes from CAPE detonation, which is independent of the model's evidence — and is treated as a **lower bound**, since one execution means evasion or a dead C2 under-reports.

**Reproducibility.** Each scorecard cell records the seed *requested* and the sampling configuration the inference server *reported applying* — per cell, not per sweep, because a server can be restarted mid-run and a result whose sampling config is known only by recollection is not reproducible.

**A metric that is implemented and deliberately refused.** Cross-run consensus — keeping only claims that independent runs agree on — is fully implemented and **disabled at the CLI**. The method rests entirely on the runs being independent, and no currently available axis supplies that: seeds are inert on the transport the RE stage uses, and a shallower depth produces a literal prefix of a deeper one, so agreement would be guaranteed by construction. The harness refuses the flag rather than print a table reporting 100% agreement for free.

**Known hazard, recorded because it is one refactor away.** The prompt builder injects the MalwareBazaar family verbatim when present. It does not contaminate the benchmark only because the eval passes the Ghidra sub-report while that field sits at report top level; passing the whole report would silently turn the benchmark into an answer key. The production .NET, PowerShell, and Go paths *do* receive that hint — so a family "identified" on those paths was supplied, not derived.

---

## Current limitations

Stated here rather than left to be discovered, because the distinction that matters most
in this project is **implemented ≠ demonstrated ≠ production-hardened**.

**Correlation runs after the investigator, not before it.** `run_pipeline` computes
cross-correlation at line 1152; the agentic investigation runs at line 997. Correlation
findings therefore reach severity scoring, IOC extraction, the executive summary and the
PDF — but **not** the agent, which sees only its decompiler output. The "correlation
before generation" principle below is currently implemented for the summary writer and
not for the investigator. Closing that loop, and measuring whether it actually helps, is
[#420](https://github.com/chrisshaiman/lamware/issues/420) — the project's central open
research question.

**ATT&CK mapping is implemented, not validated.** Technique candidates come from CAPE
behavioral signatures and from the LLM's reading of decompiled code. No dedicated
evaluation establishes their accuracy, so they carry exactly the same status family
attribution did before ADR-019 measured it. Treat them as candidates for an analyst to
confirm.

**Family attribution is not a validated capability.** Measured at 0/14 locally and 0/7 on
the frontier reference; retired as a capability metric rather than tuned against
([ADR-019](docs/DECISIONS.md)). Family labels shown in reports come from CAPE signatures
or MalwareBazaar metadata and are provenance, not analysis.

**Agent false-positive rate is unmeasurable today.** Dismissed pin proposals are not
recorded, so precision on the analyst-facing surface cannot be computed
([#312](https://github.com/chrisshaiman/lamware/issues/312)).

**Recall ground truth is a lower bound.** It comes from a single detonation, so evasion
or a dead C2 under-reports ([#314](https://github.com/chrisshaiman/lamware/issues/314)).

**Only the native PE path is agentic.** The .NET, Go, PyInstaller, Java, Office and
PowerShell paths use single-shot interpretation.

**Hypervisor escape remains residual risk.** Containment is layered and tested, but a
guest-to-host escape is not mitigated away — see
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

**Single maintainer, large operational surface.** Not suitable for unattended production
use.

---

## Security model

lamware executes hostile code, so containment is part of the product rather than an operational footnote.

**The detonation network is air-gapped. The analysis host is not.** Those are different
statements and conflating them gets people hurt:

- **Detonation network** — isolated KVM bridge, no NAT, iptables DROP toward the
  management interface, INetSim answering callbacks so malware sees a plausible internet
  that does not exist. Windows guests reach nothing real.
- **Analysis host** — has one tightly controlled outbound path: the LiteLLM gateway's
  HTTPS connection to the Anthropic API. Nothing else egresses, and the Anthropic key
  lives only in LiteLLM's environment.
- **Analysis containers** — every one runs `--network=none --read-only --cap-drop=ALL
  --security-opt=no-new-privileges` under rootless Podman with dedicated service
  identities. The container handling malware-derived LLM I/O reaches LiteLLM through a
  bind-mounted Unix socket, not the network.

Prompt injection is treated as a real attack surface — malware-derived text is wrapped in untrusted-data delimiters with escaping and argument validation — but **containment is the primary boundary**. Prompt-injection defense is defense in depth, not a claim that an LLM can safely process adversarial instructions.

> [!CAUTION]
> **Do not detonate malware until you have independently verified your deployment's containment.** A hypervisor escape or a misconfigured detonation route turns the analysis host into a live-malware host.

**Full detail:** [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) · [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) · [docs/SECURITY_CONSTRAINTS.md](docs/SECURITY_CONSTRAINTS.md)

---

## Design principles

**1. Correlation before generation.** The LLM investigates evidence the system has already collected and correlated. It is not asked to discover facts deterministic tooling establishes more reliably.

**2. Evidence and interpretation are different objects.** A CAPE observation is evidence. A Volatility observation is evidence. An LLM's explanation of them is interpretation. These must never silently merge — which is why LLM-derived signal is scored separately from deterministic signal and cannot move the verdict band ([ADR-017](docs/DECISIONS.md), GHSA-f5q8-v78c-mr55).

**3. Failure is not "nothing found".** Every stage must distinguish success+empty, success+findings, partial, timeout, error, and not-run. A failed analyzer must never masquerade as a clean result. This is enforced, not aspirational: `correlation_warnings` reports rules that could not run, `PayloadAccessError` separates "could not look" from "nothing there", and Ghidra `analysis_warnings` separates "could not read the sample" from "nothing to say".

**4. LLMs get capabilities, not trust.** Tools are narrow and purpose-built. The agent receives an analysis capability, never a shell.

**5. Security controls must be executable.** A security property that exists only in documentation is not a control. Container isolation flags, air-gap rules and previously-discovered dead controls all carry regression tests.

**6. Bad metrics should be deleted.** A benchmark that rewards memorization or correlated runs instead of the capability under test is a liability. See [ADR-019](docs/DECISIONS.md).

---

## Tested Malware Families

| Family | Type | Coverage |
|--------|------|----------|
| Emotet | VB6 packer/loader | Full pipeline, 130+ IOCs, cross-correlation findings |
| CobaltStrike/DidYouRansome | Native C beacon + ransomware | Full pipeline, 174 IOCs, 43 MITRE techniques |
| NanoCore | .NET RAT | ILSpy decompiled, 15 capabilities recovered (family supplied to the prompt as provenance — not an attribution result) |
| AsyncRAT | .NET RAT | de4dotEx deobfuscation + ILSpy, 23 classes extracted |
| BianLian | Go ransomware | GoReSym: 138 functions, 98 packages, SOCKS5 proxy architecture |
| Sliver | Go C2 (garble-obfuscated) | GoReSym partial + evasion hunter: 7 anti-sandbox techniques |
| ExelaStealer | PyInstaller stealer | pycdc: 100K chars Python, Discord/browser credential stealer |
| jRAT/Jacksbot | Java RAT | java-deobfuscator + CFR: 2.1M chars Java, 70 classes |
| LodaRAT | Office macro dropper | olevba: VBA deobfuscation, mshta download cradle recovered |
| SnappyClient | PowerShell stager | PSDecode: CobaltStrike-like shellcode stager, ntdll unhooking |

---

## Deployment

lamware runs on **dedicated bare metal**, not a development laptop. The process is
deliberately explicit, and containment verification comes before anything is detonated.

### Prerequisites

- Terraform >= 1.6, Packer >= 1.10, Ansible >= 2.14
  (plus `pip install -r ansible/requirements-python.txt` into the same environment
  as ansible — the `ipaddr` filter needs `netaddr`)
- OVHcloud API credentials
- WireGuard keypair
- Anthropic API key
- WSL2 if on Windows

### 1 — Provision and configure

```bash
# Provision bare metal
cd ovh && terraform init && terraform apply

# Build Windows guest images locally, then upload them
cd ../packer && make image
scp output-guest/windows11-guest.qcow2 sandbox:/home/ubuntu/
scp output/windows11-office.qcow2 sandbox:/home/ubuntu/

# Configure the host and pipeline
cd ../ansible
ansible-galaxy install -r requirements.yml
pip install -r requirements-python.txt
ansible-vault create vars/secrets.yml   # cape_api_key, anthropic_api_key, etc.
ansible-playbook -i inventory/hosts site.yml --ask-vault-pass
```

### 2 — Verify containment

```bash
make security-test
```

This is not optional and it is not a formality. It checks that the detonation bridge
cannot route to the management interface, that the DROP rules exist rather than merely
that no traffic happened to flow, and that every analysis container carries its
isolation flags. Read [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) before running it,
and do not proceed past this step until it passes.

### 3 — Detonate

> [!CAUTION]
> Everything past this point executes live malware.

Submission is operator-driven through `sample-feeder` on the analysis host, either from a
local file or from MalwareBazaar. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the
submission workflow and its options.

Results land at:

```
Dashboard   https://10.200.0.1        (via WireGuard)
CAPE UI     http://10.200.0.1:8000    (via WireGuard)
API docs    https://10.200.0.1/docs   (Swagger UI)
Reports     /opt/pipeline/reports/<task_id>/report.pdf
```

---

## Project structure

```
lamware/
├── api/         FastAPI backend + investigation agent (app/investigate/)
├── frontend/    React dashboard
├── pipeline/    Correlation rules + shared pipeline package
├── shared/      Cross-package utilities (payload discovery, tool validators)
├── tests/       Host, infrastructure and security regression tests
├── ansible/     Host/service configuration — also holds the analysis stages
│                (roles/pipeline/files/stages/) and the eval harness
│                (roles/pipeline/files/lamware_eval/)
├── packer/      Windows guest image builds
├── ovh/         Bare-metal infrastructure (Terraform)
├── scripts/     Operational tooling
└── docs/        Architecture, threat model, ADRs, deployment
```

Tests live beside what they cover: `tests/` (host + security), `api/tests/`, `pipeline/tests/`, `shared/tests/`.

---

## Why this project exists

The interesting question is not *"can an LLM read malware?"* — it obviously can.

The interesting question is: **can an LLM become more useful when given independently collected, correlated evidence and constrained investigation capabilities?**

lamware is an attempt to answer that without giving the model authority over the system it is investigating. That means being willing to find that a capability does not work, delete a misleading metric, fix a security assumption, and publish the result — rather than tuning the story until the benchmark looks good.

If that sounds more interesting than another "AI malware scanner", you are in the right place.

---

## Documentation

| Doc | Description |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | System design, provider rationale, deployment topology |
| [docs/DECISIONS.md](docs/DECISIONS.md) | **Architecture decision records** — why things are the way they are, including retired capabilities |
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) | Containment, isolation and key-handling detail |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Trust boundaries, adversary model, and residual risk |
| [docs/SECURITY_CONSTRAINTS.md](docs/SECURITY_CONSTRAINTS.md) | Non-negotiable security rules with rationale |
| [ROADMAP.md](ROADMAP.md) | Roadmap — themes + pointers to GitHub Issues/Milestones |
| [docs/archive/STATUS.md](docs/archive/STATUS.md) | Historical build journal (through v0.1.0) |
| [docs/COST_ESTIMATE.md](docs/COST_ESTIMATE.md) | Monthly cost breakdown |

---

## Disclaimer

> [!CAUTION]
> **This platform detonates live malware.** By deploying and using this software, you acknowledge and accept the following:
>
> - **Authorized use only.** This tool is intended for security research, malware analysis, incident response, and educational purposes by authorized professionals. You are solely responsible for ensuring your use complies with all applicable laws, regulations, and organizational policies in your jurisdiction.
> - **Inherent risk.** Executing malware — even in a sandboxed environment — carries inherent risks including but not limited to: unintended network exposure, data loss, system compromise, and lateral movement if containment fails. No sandbox provides absolute isolation.
> - **No warranty.** This software is provided "as is" without warranty of any kind. The author makes no guarantees regarding the completeness, accuracy, or reliability of analysis results. Do not rely solely on automated analysis for security decisions.
> - **Network isolation is your responsibility.** The detonation network must be properly air-gapped before executing samples. Verify iptables rules, bridge isolation, and WireGuard configuration before first use. See [docs/SECURITY_CONSTRAINTS.md](docs/SECURITY_CONSTRAINTS.md).
> - **AI-generated analysis is informational only.** LLM-produced findings (family identification, capability assessment, MITRE mapping) are analytical aids, not definitive verdicts. Human analyst review is required for actionable intelligence.
> - **Sample handling.** You are responsible for the legal and safe acquisition, storage, and disposal of malware samples. Ensure your sample sources (MalwareBazaar, VirusTotal, etc.) are used in accordance with their terms of service.
> - **Not for production security.** This platform is a research tool. It is not a substitute for enterprise security products, EDR solutions, or professional incident response services.

## Author

Christopher Shaiman

## License

Apache 2.0 — see [LICENSE](LICENSE). Third-party component licenses: [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md).
