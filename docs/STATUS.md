# STATUS.md — Build Status (Living Document)

Update this file as components are built, stubbed, or descoped.
For design rationale see ARCHITECTURE.md. For decisions see docs/DECISIONS.md.

---

## Platform Status (2026-05-05)

**Fully operational.** Seven-stage malware analysis pipeline with AI-assisted reverse
engineering, cross-tool correlation, and web dashboard. Tested on Emotet (VB6 packer),
CobaltStrike (native C beacon + ransomware), and NanoCore (.NET RAT).

### Analysis Pipeline — 7 stages

| Stage | Tool | Container | Status |
|-------|------|-----------|--------|
| 1. Triage | YARA, ssdeep, FLOSS | Podman (--network=none) | Complete |
| 2. Dynamic | CAPEv2 (Win11 guest) | KVM/QEMU | Complete |
| 2.5 Injection buffers | Cape API trace extraction | Host-side | Complete |
| 2.7 PCAP | Zeek + Suricata | Podman (--network=none) | Complete |
| 3. Memory forensics | Volatility 3 | Podman (--network=none) | Complete |
| 4. Static analysis | Ghidra headless (native PE) | Podman (--network=none) | Complete |
| 4. Static analysis | de4dotEx + ILSpy (.NET) | Podman (--network=none) | Complete |
| 4. Static analysis | GoReSym (Go binaries) | Podman (--network=none) | Complete |
| 4. Static analysis | pyinstxtractor + pycdc (PyInstaller) | Podman (--network=none) | Complete |
| 4. Static analysis | java-deobfuscator + CFR (Java JAR) | Podman (--network=none) | Complete |
| 4. Static analysis | olevba macro extraction (Office docs) | Podman (--network=none) | Complete |
| 4. Static analysis | pwsh + PSDecode (PowerShell) | Podman (--network=none) | Complete |
| 4.5 AI RE | Claude tool_use (agentic for native PE, single-shot for .NET/Go/Python/Java/VBA/PS) | Podman (--network=host) | Complete |
| 4.7 Evasion hunter | Claude (single-shot) — triggers on low-activity samples | Podman (--network=host) | Complete |
| 5.5 Screenshot analysis | Perceptual dedup + QR detection | Podman (--network=none) | Complete |
| 5.7 Visual analysis | Claude multimodal (screenshot interpretation) | Podman (--network=host) | Complete |
| 5. Executive summary | Claude Haiku (single-shot) | Podman (--network=host) | Complete |
| 6. PDF report | WeasyPrint | Podman (--network=none) | Complete |

### Supporting Infrastructure — 20 Ansible roles

| Role | Purpose | Status |
|------|---------|--------|
| hardening | CIS-aligned OS baseline | Complete |
| kvm | libvirt, hugepages, QEMU | Complete |
| networking | Detonation bridge, iptables air-gap | Complete |
| inetsim | Network simulation (DNS/HTTP/SMTP) | Complete |
| wireguard | VPN for admin access | Complete |
| qemu-patched | DSDT-patched QEMU (anti-evasion) | Complete |
| mongodb | Cape dependency | Complete |
| cape | CAPEv2 installer + config | Complete |
| cape-guests | Win11 guest VMs + snapshots | Complete |
| podman | Container runtime | Complete |
| pcap-analysis | Zeek + Suricata container | Complete |
| triage | YARA/ssdeep/FLOSS container | Complete |
| volatility | Volatility 3 container + ISF cache | Complete |
| dotnet-analysis | de4dotEx deobfuscation + ILSpy decompiler | Complete |
| go-analysis | GoReSym Go binary metadata extraction | Complete |
| pyinstaller-analysis | pyinstxtractor + pycdc decompilation (Python 3.11/3.12) | Complete |
| java-analysis | java-deobfuscator + CFR decompiler | Complete |
| office-macro-analysis | olevba VBA extraction + mraptor classification | Complete |
| powershell-analysis | pwsh + PSDecode multi-layer deobfuscation | Complete |
| screenshot-analysis | Perceptual dedup + QR detection | Complete |
| pdf-generation | Containerized WeasyPrint rendering | Complete |
| ghidra | Ghidra headless container | Complete |
| interpret | Claude LLM container (agentic + summary) | Complete |
| postgres | Analysis database | Complete |
| pipeline | Orchestrator + modules | Complete |
| dashboard | Flask web UI | Complete |
| sample-feeder | MalwareBazaar CLI | Complete |
| auto-feeder | Unattended MalwareBazaar ingestion with 6 guardrails | Complete |

### Database Features

| Feature | Status |
|---------|--------|
| IOC storage (STIX 2.1 types) | Complete |
| MITRE ATT&CK technique tracking | Complete |
| IOC-to-MITRE mapping (programmatic + LLM) | Complete |
| Pipeline status tracking (real-time) | Complete |
| Cross-sample IOC correlation | Complete |
| MITRE tactics populated | Complete |
| Sample relationship lineage | Schema ready, not populated |

### Dashboard Pages

| Page | Status |
|------|--------|
| / (analysis list) | Complete |
| /analysis/<id> (detail view) | Complete |
| /status (pipeline progress) | Complete |
| /iocs (IOC browser) | Complete |
| /techniques (ATT&CK browser) | Complete |
| /pdf/<task_id> (PDF download) | Complete |
| /logs/<task_id> (pipeline log viewer) | Complete |

### Performance Optimizations

- Volatility ramdisk (tmpfs) — 4GB dump copied in 1.0s
- Parallel plugin execution — 7 plugins with 7 workers, all run concurrently
- Pre-built Volatility ISF cache — mounted :ro, eliminates 210s cache rebuild
- Pipeline replay mode — re-run post-collection stages in <10s
- Per-stage timing instrumentation with per-task log files
- Prompt caching on Claude API calls
- Haiku for executive summaries (3x cheaper, ~30s faster than Sonnet)

### Logging

- Unified Python logging module (replaced 106 print() calls)
- Per-task log files at `reports/<task_id>/pipeline.log`
- `--verbose` flag for debug-level output
- Flask `/logs/<task_id>` route with links on status + detail pages

---

## Backlog — Prioritized

### High Priority

No items — all resolved.

### Medium Priority

| Item | Effort | Notes |
|------|--------|-------|
| OVH server migration | Research + deploy | Sys-1 Xeon E-2136 $44/mo vs current $92/mo |
| VM user artifacts | 1-2 hrs (Packer) | Browser history, documents, installed software — defeats liveness heuristics. Requires Packer image rebuild. |
| VM uptime spoofing | 30 min (Packer) | System uptime > 72 hours. Requires Packer image rebuild. |
| PowerShell ScriptBlock logging | 15 min (Packer) | Enable `EnableScriptBlockLogging` registry key in guest. Captures decoded PS blocks in CAPE logs. Requires Packer image rebuild. |
| AutoIt support (Exe2Aut) | 1-2 hrs | Same container pattern. Common in commodity malware. ~2-3% of samples. |
| NSIS installer extraction | 1-2 hrs | 7zip extraction + script analysis. Common dropper packaging. ~2% of samples. |
| ELF/Linux binary support | 1 session | Ghidra + Linux Volatility symbols. Needs Linux guest VM in CAPE. ~5% of samples. |

### Future — React/FastAPI Rebuild

| Item | Effort | Notes |
|------|--------|-------|
| FastAPI backend | 1-2 sessions | Replace Flask, REST + WebSocket |
| React frontend | 2-3 sessions | SPA, interactive MITRE map, real-time status |
| Convert .j2 to plain Python | 3-4 hrs | config.json pattern, do during rebuild. Also fix inline imports at this time. |
| Selective stage execution | Design + build | --skip, --only, --rerun flags with dependency tracking. Avoids re-running Cape/Volatility when only static analysis changed. |
| WebSocket real-time updates | 1 session | Builds on pipeline_stage_events table |
| Multi-sample job queue | Design + build | Concurrent pipeline runs |
| Horizontal scaling | When needed | Split analysis from dashboard to second server |
| Systemd credentials | 2-3 hrs | Move secrets from config files to /etc/credstore/, injected via LoadCredential=. No new dependencies. Single-server upgrade. |
| HashiCorp Vault | 1-2 sessions | Central secrets management with rotation, audit, policies. Needed for multi-operator deployment. |
| Multi-user platform | Design + build | SSO integration (SAML/OIDC), RBAC (analyst/admin/viewer roles), per-user audit trail. Enterprise readiness. Depends on FastAPI + React rebuild. |

### Low Priority / Ideas

| Item | Effort | Notes |
|------|--------|-------|
| Remove AWS references | 1 hr | Clean up leftover AWS and Shared folder references from early design. Platform is OVH-only — no AWS dependency. Grep for AWS, S3, shared references across all files. |
| PowerShell in batch/VBS wrappers | 1-2 hrs | Extract PowerShell commands from .bat/.vbs wrapper scripts that call powershell. Rare as initial payload. |
| Randomize UNTRUSTED_CODE delimiters | 15 min | Per-request random suffix on UNTRUSTED_CODE tags to prevent delimiter escape from malicious content. Low risk but easy hardening. |
| Garble string decryptor | 1-2 weeks | Custom tool: Capstone + Unicorn + LIEF. No existing OSS tool works headless. Novel community contribution. GoReSym handles non-literal-obfuscated garble already. |
| Interactive investigation agent | 1-2 weeks | Conversational analyst workbench with Ghidra MCP. Full design needed. |
| Rust binary analysis | 2-3 weeks | Demangle names, identify stdlib functions, reconstruct common types. Research project. |
| Linux guest VMs | 1-2 sessions | ELF binary analysis, different Volatility symbols. New Packer build + CAPE guest config. |
| Threat intel enrichment | 2-3 hrs | VirusTotal, AbuseIPDB, Shodan lookups. API integrations per provider. |
| Dashboard honeypot | 1-2 hrs | Canary, decoy endpoint, fake analysis results. |
| Automated tests | 2-3 hrs | Pure functions in ioc_extract, cross_correlate are trivially testable. |
| YARA rule auto-update | 1-2 hrs | Cron job for community rule repos. ansible-pull or scheduled task. |
| AutoIt script support | 1-2 hrs | Exe2Aut decompiler. Same container pattern as ILSpy/GoReSym. |
| Configurable dump cleanup | 1 hr | Make memory dump retention configurable instead of always deleted. |
| RTF exploit extraction | 2-3 hrs | rtfobj for CVE-2017-11882/CVE-2018-0802 shellcode extraction. Different from macro analysis — parser exploits, not code. |
| DDE injection detection | 1-2 hrs | Pattern matching for DDE/DDEAUTO fields in OOXML/OLE. Not macros — formula abuse. |
| Embedded OLE object extraction | 1-2 hrs | Packager object extraction from Office docs. File dropping, not code execution. |
| XLM macro deobfuscation | 1-2 hrs | XLMMacroDeobfuscator (Apache 2.0) for Excel 4.0 macros. Complements olevba which only detects XLM presence. Unmaintained since Sep 2022 but stable. |
| VBA p-code disassembly | 1-2 hrs | pcodedmp (GPL v3, subprocess only) catches VBA stomping where source is wiped but bytecode remains. Unmaintained since 2019 but stable. |
| Office macro extraction from CAPE drops | 1-2 hrs | Detect Office docs in CAPE dropped/extracted files and route to olevba. Currently only handles submitted samples. |
| PII scrubber for DB/reports | 3-4 hrs | Strip stolen credentials, emails, PII from IOCs/strings/LLM narratives before DB ingestion. Needed if dashboard or reports are ever shared publicly. Tricky: distinguishing PII from IOCs (e.g., attacker email vs victim email). |

---

## Deployment

### Quick deploy (existing host)

```bash
cd ansible
ansible-galaxy install -r requirements.yml
ansible-playbook -i inventory/hosts site.yml --ask-vault-pass
```

### Full setup (new host)

See deployment phases below.

### Phase 1 — OVH bare metal provisioning

```bash
cd ovh
cp terraform.tfvars.example terraform.tfvars  # fill in OVH API creds
terraform init && terraform apply
```

### Phase 2 — Secrets setup (one-time)

```bash
wg genkey | tee ~/wg-private.key | wg pubkey > ~/wg-public.key
cp ansible/vars/secrets.yml.example ansible/vars/secrets.yml
ansible-vault encrypt ansible/vars/secrets.yml
```

### Phase 3 — Packer guest images

```bash
cd packer && make image  # ~2-3 hours
scp output-guest/windows11-guest.qcow2 sandbox:/home/ubuntu/
scp output/windows11-office.qcow2 sandbox:/home/ubuntu/
```

### Phase 4 — Ansible configuration

```bash
cd ansible
ansible-playbook -i inventory/hosts site.yml --ask-vault-pass
```

### Phase 5 — Smoke test

```bash
ssh sandbox
sudo -u cape python3 /opt/sample-feeder/sample_feeder.py --recent 24 --limit 1 --yes
```

---

## Tested Malware Families

| Family | Type | Pipeline Coverage | Notes |
|--------|------|-------------------|-------|
| Emotet | VB6 packer/loader | Full (all stages) | 130+ IOCs, cross-correlation findings |
| CobaltStrike/DidYouRansome | Native C beacon + ransomware | Full (all stages) | 174 IOCs, 43 MITRE techniques, LLM identified family |
| NanoCore | .NET RAT (clean sample) | Full (all stages) | ILSpy decompiled 324K chars C#, LLM identified NanoCore, 10 MITRE techniques |
| NanoCore | .NET RAT (VB6 dropper) | Partial (no .NET extraction) | Dropper analyzed by Ghidra, .NET payload not extracted — CAPE procdump investigation needed |
| BianLian | Go ransomware | Full (GoReSym + LLM) | 138 user functions, 98 packages recovered. LLM identified SOCKS5 proxy architecture. |
| Sliver | Go C2 implant (garble-obfuscated) | Full (GoReSym + LLM) | 8,708 user functions, 282 packages recovered despite garble. LLM identified Sliver from function patterns. Evasion hunter identified 7 anti-sandbox techniques. |
| ExelaStealer | PyInstaller stealer | Full (pycdc + LLM) | 100K chars Python source decompiled, LLM identified Discord/browser credential stealer |
| jRAT/Jacksbot | Java RAT | Full (java-deobfuscator + CFR + LLM) | 2.1M chars Java source, 70 classes, LLM identified Ratty variant |
| LodaRAT | Office macro dropper | Full (olevba + LLM) | 2 VBA modules, LLM deobfuscated Chr() cipher to reveal `mshta` download cradle. 7 evasion techniques detected. Macro evaded CAPE but static analysis recovered full payload. |
| SnappyClient | PowerShell stager | Full (PSDecode + LLM) | 4.4MB hex blob script, LLM identified CobaltStrike-like shellcode stager with ntdll unhooking. 12 MITRE techniques. |

---

## Architecture Review Findings (remaining)

- Inline imports in cape.py.j2 and run-pipeline.py.j2 — move to module level
- Make memory dump cleanup configurable (currently always deleted)
- Add automated tests — pure functions in ioc_extract, cross_correlate are trivially testable
