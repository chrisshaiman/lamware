# Roadmap

Active, planned work is tracked in
**[GitHub Issues](https://github.com/chrisshaiman/lamware/issues)** and grouped
into **[Milestones](https://github.com/chrisshaiman/lamware/milestones)**. This
file is the map; the Issues are the source of truth.

For the historical build journal (what shipped and when, through v0.1.0), see
[docs/archive/STATUS.md](docs/archive/STATUS.md) and the git log / CHANGELOG.

## Milestones

| Milestone | Focus |
|---|---|
| [0.2.0](https://github.com/chrisshaiman/lamware/milestones) | Correlation/orchestrator depth, detection engineering, agent polish |
| [Hardening & Provenance](https://github.com/chrisshaiman/lamware/milestones) | Supply-chain, deploy provenance, fuzzing, operability |
| [Backlog](https://github.com/chrisshaiman/lamware/milestones) | Tracked but unscheduled |

## Themes

- **Correlation as the thesis** — grow the cross-tool rule registry and layer an
  agentic orchestrator on top (correlation/hypothesis first, not tool-routing).
- **Analysis → defense loop** — auto-draft Sigma/YARA/Suricata from findings,
  analyst-confirmed via pin→promote.
- **Threat intel from the corpus** — campaign graph (imphash + read API/UI) turns
  a per-sample tool into a platform.
- **Earn trust as a security tool** — parser fuzzing, SBOM/provenance, a deploy
  provenance gate, and operability signals.

## Ideas / someday

Not yet issues — promote to an Issue when picked up. Kept here so nothing is
lost from the pre-v0.1.0 backlog.

**New analyzers & formats:** ELF/Linux binary support (+ Linux guest VMs),
AutoIt (Exe2Aut), NSIS extraction, RTF exploit extraction (rtfobj), DDE
injection detection, embedded OLE extraction, XLM macro deobfuscation, VBA
p-code disassembly, Office-macro extraction from CAPE drops, PowerShell in
batch/VBS wrappers, Rust binary analysis, a headless garble string decryptor.

**Analysis depth:** dynamic-trace + LLM devirtualization (VMProtect/Themida),
network baseline diffing (subtract clean-guest noise), selective/rerun stage
execution.

**Evasion & guest realism (Packer):** VM user artifacts, uptime spoofing,
PowerShell ScriptBlock logging, an evasion→hardening aggregation agent.

**Infra & scaling:** OVH server migration, containerize FastAPI + React/nginx,
horizontal scaling, multi-user platform (per-user audit + tenant WS filtering),
systemd credentials, HashiCorp Vault, self-hosted ntfy.

**Security hardening:** file-permissions audit, pattern-based process allowlist,
WireGuard per-peer port ACLs, host file-integrity monitoring, randomized
UNTRUSTED_CODE delimiters, a PII scrubber for shared reports, LiteLLM
multi-provider fallback, threat-intel enrichment (VT/AbuseIPDB/Shodan).

**Developer experience & UI:** Nivo trend charts, React code-splitting,
shellcheck + PSScriptAnalyzer, eslint-plugin-security, container temp-dir
cleanup + output-dir pattern for the remaining wrappers, auto-feeder
retry-on-download-failure.

## Recently shipped

Through **v0.1.0** (see [CHANGELOG.md](CHANGELOG.md)): the seven-stage pipeline,
cross-tool correlation rule registry, cross-sample campaign graph (v1),
investigation agent, web platform (FastAPI + React + Keycloak PKCE), full
containment posture, Alembic schema management, post-deploy Playwright smoke
gate, LiteLLM Unix-socket egress isolation, and the project's security docs
(threat model, security policy).
