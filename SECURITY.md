# Security Policy

lamware is a malware-analysis platform: it detonates and dissects live,
adversary-controlled samples by design. Security reports are taken seriously
and handled by the maintainer directly.

## Supported versions

lamware is a rolling project: only the current `main` branch receives
security fixes. If you found an issue in an older checkout, please confirm
it still reproduces on `main` before reporting.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/chrisshaiman/lamware/security/advisories/new)
(Security tab → "Report a vulnerability"). This keeps the report private
while it is triaged and fixed, and threads all follow-up discussion in one
place.

Please include: affected component (API, pipeline, frontend, an Ansible
role), reproduction steps or a proof of concept, and the impact you believe
it has. **Do not attach malware samples** — describe them by SHA-256 and
source (e.g., a MalwareBazaar link) instead.

Please do not open public issues for suspected vulnerabilities.

Test only against deployments you operate yourself; never probe someone
else's lamware instance without their permission.

## What to expect

This is a solo-maintained open-source project. Realistic expectations:

- **Acknowledgement** usually within 72 hours.
- **Triage verdict** (accepted / not a vulnerability / out of scope) within
  1 week.
- **Fixes** land as ordinary pull requests once a fix is ready; there is no
  formal embargo process. If you need coordinated disclosure for a serious
  issue, say so in the report and we will agree on a timeline.
- Credit is given in the fix PR/changelog unless you ask otherwise.

## Scope

In scope:

- Code in this repository: the FastAPI backend (`api/`), pipeline
  (`pipeline/`, `ansible/roles/pipeline/files/`), React frontend
  (`frontend/`), shared libraries (`shared/`), and the Ansible roles that
  configure the platform.
- Containment regressions: anything that lets sample-derived data or code
  escape the isolation described in
  [docs/SECURITY_CONSTRAINTS.md](docs/SECURITY_CONSTRAINTS.md)
  (container flags, detonation-VLAN isolation, prompt-injection handling in
  the LLM interpretation layer, tool-argument validation).
- Resource exhaustion a *sample* can trigger: a sample that can wedge or
  exhaust the analysis host is a containment problem, not a denial of
  service.

Out of scope (report upstream instead):

- CAPEv2, Ghidra, Volatility, Suricata/Zeek, and other bundled analysis
  tools themselves.
- The vendored `konstruktoid.hardening` role.
- Volumetric denial of service against someone's self-hosted deployment,
  or overloading your own instance.

## Known, accepted residual risk

lamware assumes a hostile input set. Some risks are explicitly accepted and
documented rather than treated as vulnerabilities — for example, guest →
hypervisor escape in the detonation VMs is mitigated by network isolation,
not eliminated, and LLM prompt-injection detection is best-effort. The full
trust-boundary analysis and the complete residual-risk list are in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). A report that one of these
mitigations can be *bypassed* is absolutely in scope.

## Reporting misuse

lamware is intended for defensive security work. The Apache 2.0 license
does not restrict what it may be used for, but if you believe a public
deployment of lamware is being used to develop or distribute malware
rather than analyze it, report it through the same channels above.
