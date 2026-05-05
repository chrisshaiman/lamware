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
| 4.5 AI RE | Claude tool_use (agentic for native PE, single-shot for .NET/Go) | Podman (--network=host) | Complete |
| 5. Executive summary | Claude Haiku (single-shot) | Podman (--network=host) | Complete |
| 6. PDF report | WeasyPrint | Host-side | Complete |

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
| ghidra | Ghidra headless container | Complete |
| interpret | Claude LLM container (agentic + summary) | Complete |
| postgres | Analysis database | Complete |
| pipeline | Orchestrator + modules | Complete |
| dashboard | Flask web UI | Complete |
| sample-feeder | MalwareBazaar CLI | Complete |

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
| Cape screenshots in report | 1-2 hrs | Fix guest VM screenshot capture first (Pillow/display issue). Then: Flask endpoint, PDF embed, diff detection (identical screenshots = evasion signal). Most valuable for ransomware (ransom notes), banking trojans (form overlays), and evasion detection (static desktop = sandbox-aware sample). |
| Mutex IOCs from Cape API traces | 1 hr | CreateMutexA/W with timestamps |

| Evasion hunter mode | Design + 2 hrs | Second LLM prompt for sandbox evasion detection |
| Java JAR support (CFR) | 1-2 hrs | Same container pattern as ILSpy |
| OVH server migration | Research + deploy | Sys-1 Xeon E-2136 $44/mo vs current $92/mo |
| PyInstaller support | 1-2 hrs | pyinstxtractor + decompile |

### Future — React/FastAPI Rebuild

| Item | Effort | Notes |
|------|--------|-------|
| FastAPI backend | 1-2 sessions | Replace Flask, REST + WebSocket |
| React frontend | 2-3 sessions | SPA, interactive MITRE map, real-time status |
| Convert .j2 to plain Python | 3-4 hrs | config.json pattern, do during rebuild |
| WebSocket real-time updates | 1 session | Builds on pipeline_stage_events table |
| Multi-sample job queue | Design + build | Concurrent pipeline runs |
| Horizontal scaling | When needed | Split analysis from dashboard to second server |

### Low Priority / Ideas

| Item | Effort | Notes |
|------|--------|-------|
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
| Inline imports cleanup | 1 hr | Move to module level in .j2 templates. Do during FastAPI rebuild. |

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
| Sliver | Go C2 implant (garble-obfuscated) | Full (GoReSym + LLM) | 8,708 user functions, 282 packages recovered despite garble. LLM identified Sliver from function patterns. CAPE upload limit fixed (was 30MB, now 100MB). |

---

## Architecture Review Findings (remaining)

- Inline imports in cape.py.j2 and run-pipeline.py.j2 — move to module level
- Make memory dump cleanup configurable (currently always deleted)
- Add automated tests — pure functions in ioc_extract, cross_correlate are trivially testable
