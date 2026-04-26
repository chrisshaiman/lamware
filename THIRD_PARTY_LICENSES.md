# Third-Party Licenses

This project uses the following third-party components. All are compatible
with the project's Apache 2.0 license for personal, research, and
open-source use.

## Analysis Tools

| Component | License | Usage | Notes |
|---|---|---|---|
| [CAPEv2](https://github.com/kevoreilly/CAPEv2) | MIT-like (custom) | Dynamic malware analysis sandbox | Core analysis engine |
| [YARA](https://github.com/VirusTotal/yara) | BSD 3-Clause | Pattern matching for malware signatures | Used via yara-python |
| [yara-python](https://github.com/VirusTotal/yara-python) | Apache 2.0 | Python bindings for YARA | Container dependency |
| [FLOSS (flare-floss)](https://github.com/mandiant/flare-floss) | Apache 2.0 | Obfuscated string extraction | Container dependency |
| [ppdeep](https://pypi.org/project/ppdeep/) | Apache 2.0 | Fuzzy hashing (ssdeep-compatible) | Container dependency |
| [pefile](https://github.com/erocarrera/pefile) | MIT | PE file parsing | Container dependency |
| [python-magic](https://github.com/ahupp/python-magic) | MIT | File type detection | Container dependency |
| [Volatility 3](https://github.com/volatilityfoundation/volatility3) | **Volatility Software License (VSL)** | Memory forensics | See note below |
| [Ghidra](https://ghidra-sre.org/) | Apache 2.0 | Static analysis / disassembly | Not yet deployed |

## YARA Rule Sets

| Rule Set | License | Usage | Notes |
|---|---|---|---|
| [Yara-Rules/rules](https://github.com/Yara-Rules/rules) | GPL v2 | Community malware detection rules | Cloned at deploy time, not bundled |
| [ReversingLabs YARA](https://github.com/reversinglabs/reversinglabs-yara-rules) | MIT | Malware family detection rules | Cloned at deploy time, not bundled |

## Infrastructure

| Component | License | Usage | Notes |
|---|---|---|---|
| [Podman](https://podman.io/) | Apache 2.0 | Rootless container runtime | Isolates analysis tools |
| [konstruktoid/hardening](https://github.com/konstruktoid/ansible-role-hardening) | MIT | CIS-aligned OS hardening | Ansible role |
| [Ansible](https://www.ansible.com/) | GPL v3 | Configuration management | Build tool, not bundled |
| [Terraform](https://www.terraform.io/) | BSL 1.1 | Infrastructure provisioning | Build tool, not bundled |
| [Packer](https://www.packer.io/) | BSL 1.1 | Image building | Build tool, not bundled |

## License Notes

### Volatility 3 — Volatility Software License (VSL)

The Volatility Software License permits free use for non-commercial purposes
including personal research, academic work, and open-source security tools.
**Commercial use requires a separate license** from the Volatility Foundation.

This project uses Volatility 3 for automated memory forensics of malware
samples — a non-commercial research use case. If this project is ever
commercialized, a commercial Volatility license must be obtained.

Reference: https://github.com/volatilityfoundation/volatility3/blob/develop/LICENSE.txt

### YARA-Rules/rules — GPL v2

The YARA-Rules community rule set is licensed under GPL v2. These rules are
**not bundled** with this project — they are cloned from GitHub at deploy
time by Ansible. The rules are loaded as data files by the YARA engine at
runtime, not linked into the project's code. This usage pattern (an
Apache 2.0 program loading GPL data files at runtime) is generally
considered compatible with both licenses.

### Terraform and Packer — BSL 1.1

HashiCorp Terraform and Packer use the Business Source License 1.1. These
are build/deploy tools only — they are not distributed with this project
and do not affect the project's license. The BSL allows free use for
non-competitive purposes.
