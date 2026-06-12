# STATUS.md — Build Status (Living Document)

Update this file as components are built, stubbed, or descoped.
For design rationale see ARCHITECTURE.md. For decisions see docs/DECISIONS.md.

---

## Platform Status (2026-06-06)

**Public and operational.** Seven-stage malware analysis pipeline with AI-assisted reverse
engineering, cross-tool correlation, and web dashboard. Public at lamware.shaiman.net
(SSL Labs A+, Security Headers A). Tested on 10+ malware families including Emotet,
CobaltStrike, NanoCore, Sliver, AsyncRAT, and BianLian.

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
| 5.1 Plain English | Claude Haiku (non-technical explanation) | Podman (--network=host) | Complete |
| 6. PDF report | WeasyPrint | Podman (--network=none) | Complete |

### Supporting Infrastructure — 24 Ansible roles

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
| sample-feeder | MalwareBazaar CLI | Complete |
| auto-feeder | Unattended MalwareBazaar ingestion with 6 guardrails | Complete |
| network-monitor | Air-gap + QEMU breakout + process allowlist monitoring | Complete |
| ntfy-alerts | Push notifications + daily digest with LLM highlights | Complete |
| litellm | Claude API proxy — spend tracking, rate limiting | Complete |
| keycloak | Enterprise SSO — PKCE S256, Podman container, OTP | Complete |
| api | FastAPI REST backend — JWT/RBAC, audit logging | Complete |
| frontend | React SPA + nginx — public-facing on lamware.shaiman.net | Complete |
| fail2ban | SSH, nginx rate-limit, Keycloak auth jails | Complete |
| certbot | Let's Encrypt auto-renewal, cert expiry monitoring | Complete |

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
| Per-analysis LLM cost tracking | Complete |

### React Frontend (public at lamware.shaiman.net, PR #57 + #58 + #97)

| Page | Status |
|------|--------|
| /analyses (analysis list) | Complete — paginated, search, severity/family filters |
| /analyses/:id (detail view) | Complete — all sections, markdown narratives, downloads, Related Analyses overlap detection |
| /iocs (IOC browser) | Complete — campaign detection cards, pivot-to-analyses, family filter, noise filtering |
| /techniques (ATT&CK matrix) | Complete — Navigator-style 14-column grid, family filter, pivot-to-analyses |
| /stats (statistics) | Complete — KPI cards, top families chart |
| /pipeline (pipeline status) | Complete — running/completed cards, stage progress, 10s polling |
| /alerts (operational health) | Complete — network monitor, disk, feeder controls |
| /evasions (evasion dashboard) | Complete — technique frequency, recommendations |
| /submit (sample upload) | Complete — drag-and-drop, progress, success/error states |

Tech stack: Vite 8, React 19, TypeScript 6, Tailwind v4, Shadcn/ui, Nivo, TanStack Query/Table.
Deployment: nginx reverse proxy on public IP + WireGuard, Let's Encrypt TLS (A+), proxies to FastAPI on 127.0.0.1:8001.
Security cat mascot: 5 mood states, click for analysis facts, Konami code easter egg.
34 Playwright smoke tests passing.

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

### Current Priority Order (reprioritized 2026-06-11, post architecture review)

This is the curated current working order. The tier tables further below retain
detailed notes and the (mostly DONE) historical backlog.

**Tonight / Top**

| Item | Notes |
|------|-------|
| Ghidra empty-project fix | Pipeline persists empty Ghidra projects (`.rep` has no `data/`) → investigation-agent tool-mode fails with "Project data directory not found". Lock-permission layer already fixed (commit 541ec3f). Look at `roles/ghidra/templates/run-ghidra.py.j2` `analyze_with_headless()`; debug by comparing `ls -laR /output/project` in-container vs post-`cp -a`. |

**High**

| Item | Effort | Notes |
|------|--------|-------|
| De-template run-pipeline.py.j2 + decompose orchestrator | 1-2 sessions | 2050-line Jinja template; `run_pipeline()` ~1184 lines (698–1882); can't import/test/run locally. Root cause of: no pipeline unit tests, deploy-required iteration (how the get_session bug survived 120 green tests), and no seam to insert the agentic orchestrator. **Not a rewrite or language change** — Python stays Python; replace Jinja render with a runtime `config.json`, extract the pure helpers (`cross_correlate`, `determine_family`, `calculate_severity`, `build_mitre_mapping`) first. Incremental, behavior-preserving. (Elevated from "Convert .j2 to plain Python".) |
| Correlation engine — tested rule registry | 1 session | `cross_correlate` (the platform's thesis) is a ~170-line inline if-pile, Cape×Volatility only, zero tests, `import os` inside loops. Turn into a registry of pure-function rules, each `(report) -> finding \| None` with a fixture test. De-risks the thesis and lets it grow (PCAP×IOC, static-imports×dynamic-calls, etc.). |
| Agentic orchestrator — correlation/hypothesis first | Design + build | LLM loop reusing the investigation-agent engine. **First use = "what corroborates/contradicts across tools, and what one thing confirms it?"** (augments coverage — low risk), NOT tool-routing (a wrong skip = silent coverage gap). Graduate to routing only after the deterministic baseline + correlation engine are solid and A/B data backs it. |
| Alembic migrations | 1-2 hrs | Replace raw SQL + hand-numbered migrations (just added 3 investigation tables that way) before the next schema change. Schemas always change — do it sooner. Scaffold `alembic init`, configure for SQLModel, convert existing schema to initial migration. (Elevated from Future.) |
| Post-deploy Playwright smoke gate | 1 session | **Deterministic** browser smoke run against the LIVE site automatically after every `ansible-playbook` (home: `security-test` role); pass/fail gate. Would have caught this session's 422 / SSE / empty-Ghidra bugs in <1 min instead of hours of hand-debugging. 34 Playwright tests + `playwright_*.py` scripts already exist — wire them to the live deploy, extend to the investigation chat / pins / spend surfaces, use a dedicated Keycloak test account + read-mostly checks so runs don't pollute prod data. A gate must be deterministic — no LLM in this path. |
| Merge PR #101 (investigation agent) | DONE | Merged to main 2026-06-12 (merge commit 7f2e369). 6/7 capabilities live; Ghidra agentic tools still blocked on the separate empty-project pipeline bug. |

**Medium**

| Item | Effort | Notes |
|------|--------|-------|
| Cleanup trio | 2-3 hrs | (1) WebSocket events broadcast to ALL authenticated users — multi-operator landmine; add per-user/tenant filtering. (2) Delete `aws/` dead code (ADR-016 greenlit). (3) Move inline imports to module level (cape.py.j2, run-pipeline.py.j2). Supersedes the old "Remove AWS references" item. |
| Campaign graph from corpus | Design + build | Populate `sample_relationships` (schema-ready, never used) via shared IOCs / imphash / ssdeep / TLS JA3 → emergent threat intel from the corpus ("shares 18 IOCs + same C2 JA3 with 3 prior BianLian runs"). Per-sample tool → threat-intel platform. |
| Detection engineering output | Design + build | Auto-draft Sigma / YARA / Suricata from each analysis; analyst confirms via the investigation agent's pin→promote flow. Closes the analysis→defense loop; strong blue-team + OSS value. |
| Separate manual-analysis cost category | 2-3 hrs | Split investigation-agent (analyst-driven, ad-hoc) spend into its own category, distinct from automated pipeline (per-sample) spend, in cost tracking + the spend page. Investigation cost is already captured per session (`investigation_sessions.total_cost_usd`, ADR-017); pipeline cost is per-analysis via `_calculate_llm_cost()`. Work = tag/categorize the two sources and separate them in aggregation + the spend UI. |
| App-boot integration tests (TestClient) | 1 session | Boot the real FastAPI app via `TestClient` + ephemeral sqlite/pg + seeded JWT; assert the OpenAPI schema and hit endpoints. Catches the wiring/route-construction class (e.g. get_session) faster than the browser but covers less surface — complements the HIGH post-deploy smoke gate. Supersedes "Automated tests". |

**Low**

| Item | Effort | Notes |
|------|--------|-------|
| Job queue / spool-based auto-feeder | Design + build | Single-sample sequential today; the queue is the natural next architectural unit and dissolves the auto-feeder sudo-subprocess wart. Combines "Multi-sample job queue" + "Refactor auto-feeder to spool-based". |
| MCP server wrapping the corpus | 1-2 hrs | Expose IOC/technique/correlation/analysis queries as MCP — the investigation agent's 20-tool registry already exists. Reusable intelligence backend any LLM client can pivot through. |
| Exploratory LLM Playwright agent | 1-2 hrs | Free-roaming agent that drives the browser and reports UI anomalies (started as `playwright_bug_hunt.py`). Good for unknown-unknowns; non-deterministic + token-costly — run on-demand/nightly, NEVER in the deploy gate path. |

### High Priority

| Item | Effort | Notes |
|------|--------|-------|
| LiteLLM proxy | DONE | Root Podman container on localhost:4000. Anthropic passthrough endpoint. API key isolated to LiteLLM env file. All Claude calls routed through proxy (PR #74). |
| LiteLLM network lockdown | DONE | iptables OUTPUT rules restrict pipeline user to localhost only (LiteLLM:4000, PostgreSQL:5432, CAPE:8000, MongoDB:27017). All other outbound blocked. PR #79. |
| LiteLLM PostgreSQL spend tracking | DONE | LiteLLM connected to dedicated PostgreSQL database for native per-request spend tracking. PR #79. |
| Enterprise authentication (OAuth/SAML) | DONE | Keycloak SSO with PKCE, FastAPI JWT + RBAC + audit log, React keycloak-js. PRs #80-85. Pentested: 24 tests, 12 findings, 9 fixed. |
| Security testing — pentest complete | DONE | Phase 1 manual (24 tests), Phase 2 Schemathesis (2007 cases), port audit, alert tuning. PRs #84-89. Formal report pending. |
| Domain + TLS setup (lamware.shaiman.net) | DONE | Let's Encrypt via DNS-01, auto-renewal via certbot HTTP-01, cert expiry monitoring via ntfy. Public-facing on 15.204.64.8. PRs #91-96. |
| PKCE server-side enforcement | DONE | Verified S256 required in Keycloak admin console. |
| API rate limiting | DONE | Three nginx limit_req zones: API 30r/s, auth 5r/s (burst 50), upload 2r/s. PR #91. |
| OVH robot firewall | DONE | Enabled with deny-all rule. SSH (admin CIDR), WireGuard (0.0.0.0/0), HTTPS, HTTP, TCP established. Critical fix — was never enforcing since April 2026. PRs #93-94. |
| fail2ban | DONE | SSH brute force, nginx rate-limit recidivist, Keycloak auth failure jails. PR #92. |
| Keycloak production mode | DONE | Switched from start-dev to start. OTP enabled on admin account. PR #92. |
| IOC/technique correlation | DONE | Campaign detection, pivot-to-analyses, family filter, Related Analyses section, noise filtering. PR #97. |
| Domain parameterization | DONE | Replaced hardcoded lamware.shaiman.net with lamware_domain variable. PR #91. |
| Pentest report PDF | 1-2 hrs | Formal report: findings, methodology, evidence, remediation status. WeasyPrint. Portfolio deliverable. Missing Phase 1 details from compacted context. |
| CI/CD security-test Ansible role | 1 session | Automate RBAC tests, Schemathesis, Nuclei into post-deploy verification. |
| Family name normalization | 1-2 hrs | LLM generates verbose family names ("vb6 downloader/dropper (likely guloader)"). Normalize to canonical names. |
| Interactive investigation agent | DONE | Conversational analyst workbench on the analysis detail page. 20 tools (search IOCs/techniques, run Ghidra/sandbox, Python sandbox, pin findings). SSE streaming chat panel, session model, cost tracking, markdown report export. Deploy requires postgres + python-sandbox + api + frontend tags. ADR-017. |

### Medium Priority

| Item | Effort | Notes |
|------|--------|-------|
| OVH server migration | Research + deploy | Sys-1 Xeon E-2136 $44/mo vs current $92/mo |
| VM user artifacts | 1-2 hrs (Packer) | Browser history, documents, installed software — defeats liveness heuristics. Requires Packer image rebuild. |
| VM uptime spoofing | 30 min (Packer) | System uptime > 72 hours. Requires Packer image rebuild. |
| Dynamic guest clock from PE timestamp | DONE | Implemented — triage extracts PE timestamp, pipeline passes clock param to CAPE |
| PowerShell ScriptBlock logging | 15 min (Packer) | Enable `EnableScriptBlockLogging` registry key in guest. Captures decoded PS blocks in CAPE logs. Requires Packer image rebuild. |
| Actual LLM cost tracking | DONE | Implemented — usage_from_response() captures tokens on all Claude calls |
| Skip CAPE for non-Windows binaries | DONE | Detects ELF/Mach-O via file_mime and magic bytes, skips CAPE. Ghidra handles all three natively (PR #75). |
| Network baseline diffing | 1 session | Capture clean guest VM network traffic baseline (DNS, HTTP, telemetry). Subtract from analysis PCAP results before passing to LLM and IOC extraction. Eliminates false positives from Win11 noise (BitLocker attestation, Defender, Office telemetry, NCSI). Only filter exact matches to avoid masking malware that mimics Microsoft domains. |
| AutoIt support (Exe2Aut) | 1-2 hrs | Same container pattern. Common in commodity malware. ~2-3% of samples. |
| NSIS installer extraction | 1-2 hrs | 7zip extraction + script analysis. Common dropper packaging. ~2% of samples. |
| ELF/Linux binary support | 1 session | Ghidra + Linux Volatility symbols. Needs Linux guest VM in CAPE. ~5% of samples. |
| Batch/JS/VBS/HTA script analysis | DONE | Generic text/script catch-all handler (PR #77). Detects language, reads source, sends to LLM. Covers .bat, .cmd, .js, .jse, .wsf, .vbs, .vbe, .hta, .py, and any readable text. |
| shellcheck + PSScriptAnalyzer | 1 hr | Shell (1 file) and PowerShell (9 files) linting. Low ROI — stable Packer provisioning scripts, rarely change. |
| DAST: Schemathesis API fuzzing | DONE | 2007 fuzz cases, found integer overflow on offset params. PRs #84-89. |
| DAST: Nuclei misconfig sweep | DONE | 6,522 templates, 1 low finding (Keycloak admin config — accepted). Run against public endpoint. |
| DAST: ZAP Ajax Spider | 1 session | Headless browser crawl of React frontend + active scan. |
| /docs /redoc env-gating | DONE | Gated behind LAMWARE_ENABLE_DOCS=false in production. PR #84. |
| Remove static API key auth | DONE | Removed VITE_API_KEY from frontend build, X-API-Key fallback from FastAPI, API key from WebSocket auth. JWT-only auth path. |
| Refactor auto-feeder to spool-based | 1 session | Replace direct `sudo -u pipeline run-pipeline` with spool drop pattern (same as UI submit). Eliminates sudo/NoNewPrivileges tradeoff. Requires reworking cost tracking, failure counting, and sequential processing — currently coupled to subprocess.run(). |
| Test process alerting for all users | 1-2 hrs | Verify network-monitor process allowlists for all monitored users (cape, pipeline, auto-feeder, lamware-api). Simulate unexpected processes for each user and confirm alerts fire. Verify no remaining false positives after allowlist tuning. |
| eslint-plugin-security | 30 min | Frontend JS security patterns (unsafe innerHTML, regex DoS). Low priority — rehype-sanitize covers primary risk. |

### Future — Platform Enhancements

| Item | Effort | Notes |
|------|--------|-------|
| FastAPI backend | DONE | PR #55 — 10 routers (incl. evasions), 28+ tests, port 8001 |
| React frontend | DONE | PR #57, #58 — 10 pages, MITRE matrix, evasion dashboard, nginx deployment |
| WebSocket real-time updates | DONE | PR #64 — PG LISTEN/NOTIFY → FastAPI → browser, TanStack cache invalidation |
| Dynamic trace + LLM devirtualization | Design + build | Feed CAPE's runtime API trace alongside Ghidra's static decompilation to the LLM. For VM-protected binaries (VMProtect, Themida), Ghidra only sees the VM dispatcher loop — but CAPE captured what the code *actually did*. The LLM correlates "this VM bytecode sequence resulted in these API calls" to reconstruct behavior that no single tool can reverse. Novel cross-tool correlation — core to lamware's thesis. |
| LiteLLM multi-provider fallback | 1 hr | Add fallback models (e.g., OpenAI GPT-4o) via LiteLLM model_list with fallback groups. Resilience if Anthropic API is down. |
| Nivo trend charts | 2-3 hrs | Analysis-over-time line chart, severity breakdown pie chart on stats page |
| Code splitting | 1 hr | React.lazy() per page to reduce initial bundle (currently 560KB) |
| Containerize FastAPI + React/nginx | 1 session | Root Podman + systemd pattern (same as LiteLLM). Improves portability for host migration. FastAPI: Python slim + uvicorn. React: nginx + Vite build output. Touches API and frontend Ansible roles, SSL cert mounts, volume config. |
| Selective stage execution | Design + build | --skip, --only, --rerun flags with dependency tracking. Avoids re-running Cape/Volatility when only static analysis changed. |
| Multi-sample job queue | Design + build | Concurrent pipeline runs |
| Horizontal scaling | When needed | Split analysis from dashboard to second server |
| Systemd credentials | 2-3 hrs | Move secrets from config files to /etc/credstore/, injected via LoadCredential=. No new dependencies. Single-server upgrade. |
| HashiCorp Vault | 1-2 sessions | Central secrets management with rotation, audit, policies. Needed for multi-operator deployment. |
| Multi-user platform | Design + build | Per-user audit trail, team workspaces. Depends on enterprise auth (high priority). Enterprise readiness. WebSocket events currently broadcast to all authenticated users — add per-user/tenant filtering before exposing beyond trusted team. |

### Low Priority / Ideas

| Item | Effort | Notes |
|------|--------|-------|
| File permissions audit | 2-3 hrs | Audit all deployed files for over-permissioning (chmod 777 work dirs, 755 vs 750, world-readable status files). Establish consistent permission model: what runs as root vs cape, what needs cross-user read access, whether a shared group would be cleaner than world-readable files. |
| Process allowlist to pattern-based | 1-2 hrs | Replace exact-match CAPE_ALLOWLIST with regex/pattern matching. Current approach requires a commit for every new process. Pattern-based (e.g., match /home/cape paths, known prefixes) would be maintenance-free. |
| WireGuard phone peer | DONE | Phone peer at 10.200.0.3, QR code config via qrencode. |
| WireGuard port restrictions | 1 hr | iptables rules on wg0 limiting access to SSH/dashboard/CAPE ports only. Per-peer ACLs (laptop=full, phone=dashboard only). |
| Self-hosted ntfy | 1 hr | Replace public ntfy.sh with self-hosted instance on sandbox. Podman container, traffic stays on WireGuard. |
| Host file integrity monitoring | 1-2 hrs | SHA256 baseline of iptables rules + QEMU binary. Low value for single-operator setup — only 2 files worth watching, and an attacker with root could disable the checker. |
| Evasion-to-hardening agent | Design + build | Aggregate evasion hunter recommendations across all samples, rank by frequency, categorize by fix type (Packer/CAPE/QEMU). Near-term: dashboard view of outstanding evasion techniques. Long-term: autonomous agent that generates Packer scripts and Ansible tasks from evasion findings. |
| PowerShell in batch/VBS wrappers | 1-2 hrs | Extract PowerShell commands from .bat/.vbs wrapper scripts that call powershell. Rare as initial payload. |
| Randomize UNTRUSTED_CODE delimiters | 15 min | Per-request random suffix on UNTRUSTED_CODE tags to prevent delimiter escape from malicious content. Low risk but easy hardening. |
| Garble string decryptor | 1-2 weeks | Custom tool: Capstone + Unicorn + LIEF. No existing OSS tool works headless. Novel community contribution. GoReSym handles non-literal-obfuscated garble already. |
| Rust binary analysis | 2-3 weeks | Demangle names, identify stdlib functions, reconstruct common types. Research project. |
| Linux guest VMs | 1-2 sessions | ELF binary analysis, different Volatility symbols. New Packer build + CAPE guest config. |
| Threat intel enrichment | 2-3 hrs | VirusTotal, AbuseIPDB, Shodan lookups. API integrations per provider. |
| Dashboard honeypot | 1-2 hrs | Canary, decoy endpoint, fake analysis results. |
| YARA rule auto-update | 1-2 hrs | Cron job for community rule repos. ansible-pull or scheduled task. |
| AutoIt script support | 1-2 hrs | Exe2Aut decompiler. Same container pattern as ILSpy/GoReSym. |
| Configurable dump cleanup | 1 hr | Make memory dump retention configurable instead of always deleted. |
| Container temp dir cleanup errors | 30 min | Podman rootless UID mapping creates files the pipeline user can't delete in trap cleanup. Wrapper scripts log `rm: cannot remove` on exit. Fix with `podman unshare rm -rf` or `chmod -R` before cleanup. |
| Container output dir temp pattern for remaining wrappers | 1-2 hrs | 7 wrappers still mount $OUTPUT_DIR directly (screenshot, volatility, dotnet, go, pyinstaller, java, office, powershell). Apply same temp dir + copy-back pattern used in Ghidra and PCAP wrappers. May not surface as errors if containers write to stdout, but preemptive fix. |
| Auto-feeder retry on download failure | 1 hr | When a sample download fails (e.g., delisted, non-zip response), try a different sample within the same cycle instead of waiting 15 minutes. Currently only attempts one sample per cycle. |
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

- Make memory dump cleanup configurable (currently always deleted)
- (Inline imports + automated tests moved to "Current Priority Order" above: cleanup trio / test harness.)
