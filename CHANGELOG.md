# Changelog

All notable changes to this project are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The canonical version is the root [`VERSION`](VERSION) file; package manifests
are kept in sync (enforced by `tests/test_version_consistency.py`).

## [Unreleased]

## [0.1.0] - 2026-07-03

First tagged release. Consolidates the platform built since April 2026 into a
single versioned baseline. Pre-`0.1.0` history lives in the git log.

### Added

- **Analysis pipeline** — seven-stage flow: triage (YARA/ssdeep/FLOSS/entropy),
  dynamic analysis (CAPEv2 on KVM), PCAP (Zeek + Suricata), memory forensics
  (Volatility 3), language-aware static analysis (Ghidra for native PE, ILSpy
  for .NET, GoReSym, and more), agentic LLM interpretation, and executive
  summaries.
- **Cross-tool correlation** — a tested pure-function rule registry that
  surfaces findings no single tool produces (e.g. dropped-file-loaded,
  shellcode self-modification, cmdline spoofing, C2-live-in-memory).
- **Cross-sample campaign graph** — materializes typed relationships between
  samples (shared network IOCs, JA3, ssdeep similarity) into
  `sample_relationships`.
- **Investigation agent** — conversational analyst workbench with database,
  Python-sandbox, and agentic Ghidra tools, streamed over SSE.
- **Web platform** — FastAPI backend (port 8001) + React 19 SPA, Keycloak
  (PKCE) authentication, real-time pipeline updates via PostgreSQL
  LISTEN/NOTIFY.
- **Containment** — every analysis tool runs in a rootless Podman container
  with `--network=none`, `--read-only`, `--cap-drop=ALL`, and
  `--security-opt=no-new-privileges`; the detonation network is air-gapped at
  the hypervisor; the LLM-broker container reaches LiteLLM only over a
  bind-mounted Unix socket.
- **Infrastructure as code** — Packer image build, Terraform provisioning, and
  21 Ansible roles; secrets in Ansible Vault; schema managed by Alembic.
- **Project documentation** — threat model, security policy with private
  vulnerability reporting, contributor scaffolding, and SHA-pinned CI.

[Unreleased]: https://github.com/chrisshaiman/lamware/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/chrisshaiman/lamware/releases/tag/v0.1.0
