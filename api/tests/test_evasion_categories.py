# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0

"""Tests for evasion technique categorization logic.

The _categorize function and _CATEGORY_RULES are pure regex logic with no
app dependencies. We load just those symbols from the module source to
avoid importing the full FastAPI app stack.
"""

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Load _CATEGORY_RULES and _categorize without importing the router module
# (which pulls in FastAPI, SQLModel, jwt, etc.)
# ---------------------------------------------------------------------------
_SRC = Path(__file__).resolve().parent.parent / "app" / "routers" / "evasions.py"
_source = _SRC.read_text()

# Extract everything between the first `_CATEGORY_RULES` definition and the
# `def _categorize` function — then exec both into a private namespace.
_ns: dict = {"re": re}
# Grab from the _CATEGORY_RULES assignment through end of _categorize
_start = _source.index("_CATEGORY_RULES")
_end = _source.index("\n\n\n@router", _start)  # stop before the route decorator
exec(_source[_start:_end], _ns)  # noqa: S102

_categorize = _ns["_categorize"]
_mitigation_status = _ns["_mitigation_status"]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_qemu_categories():
    assert _categorize("Virtual Network Adapter Detection") == "qemu"
    assert _categorize("Storage Device Enumeration (VM Disk Detection)") == "qemu"
    assert _categorize("Virtual Machine Detection via Display Device Query") == "qemu"
    assert _categorize("Storage Device / Mount Point Enumeration for VM Detection") == "qemu"
    assert _categorize("VM/Sandbox Environment Detection via Static PE Anomaly") == "qemu"


def test_registry_vm_detection_is_guest_image():
    """Registry-based VM checks are fixed in Packer (guest image), not QEMU."""
    assert _categorize("Registry-Based VM/Environment Detection") == "guest_image"
    assert _categorize("Registry Artifact Checks (VM/Environment Detection)") == "guest_image"


def test_guest_image_categories():
    assert _categorize("Hardware ID / Volume Serial Number Profiling") == "guest_image"
    assert _categorize("Computer Name / Hostname Enumeration") == "guest_image"
    assert _categorize("System Fingerprinting / Environment Enumeration") == "guest_image"
    assert _categorize("Environment / Victim Profiling via Hardware ID and Volume Serial Number") == "guest_image"
    assert _categorize("Large File Size Evasion") == "guest_image"
    assert _categorize("Large Binary Size as Anti-Analysis Mechanism") == "guest_image"
    assert _categorize("Suspicious PDB Path (Development Artifact / Targeted Build Indicator)") == "guest_image"
    assert _categorize("Environment/VM Detection via Username Query") == "guest_image"
    assert _categorize("Hostname Enumeration for Environment Fingerprinting") == "guest_image"


def test_cape_config_categories():
    assert _categorize("Date/Time Expiration Check") == "cape_config"
    assert _categorize("Timing Evasion — Extended Sleep / Delayed Execution") == "cape_config"
    assert _categorize("DNS/Network Connectivity Verification") == "cape_config"
    assert _categorize("Dead C2 / Network Connectivity Probe") == "cape_config"
    assert _categorize("Date/Time Expiration Check (Kill Date)") == "cape_config"
    assert _categorize("Timing / Sleep-Based Evasion (Inferred from CAPE Duration Gap)") == "cape_config"
    assert _categorize("Sandbox Clock Manipulation Detection / Stale Snapshot Detection") == "cape_config"
    assert _categorize("Kill Switch Domain Check (Network Connectivity / Sinkhole Detection)") == "cape_config"
    assert _categorize("Stealth Network Communication / Protocol Not Simulated by INetSim") == "cape_config"
    assert _categorize("External IP / Connectivity Verification") == "cape_config"
    assert _categorize("Timing / Uptime / Recently Booted System Detection") == "cape_config"


def test_automation_categories():
    assert _categorize("User Interaction / Human Presence Check") == "automation"
    assert _categorize("Process Enumeration for Analysis Tools") == "automation"
    assert _categorize("Analysis Tool Detection via Process Enumeration") == "automation"
    assert _categorize("Parent Process / Execution Context Check") == "automation"
    assert _categorize("User Interaction Requirement — Social Engineering Gate (Enable Content Button)") == "automation"
    assert _categorize("Cross-Process Memory Reading for Analysis Tool Detection") == "automation"


def test_detection_engineering_fallback():
    """Techniques that can't be fixed in the sandbox fall to detection."""
    assert _categorize("Anti-Debug via SetUnhandledExceptionFilter") == "detection"
    assert _categorize("EDR/Hook Evasion via ntdll Unhooking") == "detection"
    assert _categorize("Language/Locale Geofencing") == "detection"
    assert _categorize("Encrypted/Packed Payload with Conditional Decryption") == "detection"
    assert _categorize("Vectored Exception Handler (VEH) Abuse for Control Flow Obfuscation") == "detection"
    assert _categorize("Privilege/UAC Elevation Check") == "detection"
    assert _categorize("TLS Callback Execution (Pre-EntryPoint Code)") == "detection"
    assert _categorize("PE Overlay Payload Concealment") == "detection"
    assert _categorize("SEH-Based Anti-Debug / Anti-Analysis") == "detection"
    assert _categorize("In-Memory Payload Staging (Process Memory Injection)") == "detection"
    assert _categorize("DLL Side-Loading / Unusual Extension DLL Load") == "detection"
    assert _categorize("UPX Packing with Modified Headers (Anti-Unpacking)") == "detection"


def test_empty_and_unknown():
    assert _categorize("") == "detection"
    assert _categorize("Some Unknown Technique") == "detection"


# ---------------------------------------------------------------------------
# Mitigation status tests
# ---------------------------------------------------------------------------


def test_mitigated_techniques():
    """Techniques defeated by deployed hardening."""
    # CPUID / hypervisor bit — host-passthrough + feature disable
    assert _mitigation_status("CPUID-based hypervisor detection", "qemu") == "mitigated"
    # Hostname — Packer randomized DESKTOP-XXXXXXX
    assert _mitigation_status("Computer Name / Hostname Enumeration", "guest_image") == "mitigated"
    assert _mitigation_status("Environment/VM Detection via Username Query", "guest_image") == "mitigated"
    # Screen resolution — 1920x1080
    assert _mitigation_status("Screen Resolution Check", "automation") == "mitigated"
    # Memory/disk — 4GB/60GB
    assert _mitigation_status("Memory Size Check", "guest_image") == "mitigated"
    # Hardware ID — real hardware passthrough
    assert _mitigation_status("Hardware ID / Volume Serial Number Profiling", "guest_image") == "mitigated"
    # DNS connectivity — INetSim
    assert _mitigation_status("DNS/Network Connectivity Verification", "cape_config") == "mitigated"
    # Clock — localtime + native TSC
    assert _mitigation_status("Sandbox Clock Manipulation Detection / Stale Snapshot Detection", "cape_config") == "mitigated"
    # System fingerprinting — decoy files + realistic profile
    assert _mitigation_status("System Fingerprinting / Environment Enumeration", "guest_image") == "mitigated"


def test_partial_techniques():
    """Techniques partially addressed by hardening."""
    # Storage device — DSDT patched but disk IDs may leak
    assert _mitigation_status("Storage Device Enumeration (VM Disk Detection)", "qemu") == "partial"
    # Virtual network — e1000 but MAC OUI 52:54:00
    assert _mitigation_status("Virtual Network Adapter Detection", "qemu") == "partial"
    # Timing/sleep — native TSC but no sleep skipping
    assert _mitigation_status("Timing Evasion — Extended Sleep / Delayed Execution", "cape_config") == "partial"
    # Date expiration — clock realistic but real date checked
    assert _mitigation_status("Date/Time Expiration Check (Kill Date)", "cape_config") == "partial"
    # Dead C2 — INetSim responds but protocol may not match
    assert _mitigation_status("Dead C2 / Network Connectivity Probe", "cape_config") == "partial"
    # Registry VM — some keys but not exhaustive
    assert _mitigation_status("Registry-Based VM/Environment Detection", "guest_image") == "partial"


def test_open_techniques():
    """Techniques not yet addressed."""
    # Human interaction — deferred
    assert _mitigation_status("User Interaction / Human Presence Check", "automation") == "open"
    # Parent process — not spoofed
    assert _mitigation_status("Parent Process / Execution Context Check", "automation") == "open"
    # Analysis tool detection
    assert _mitigation_status("Process Enumeration for Analysis Tools", "automation") == "open"


def test_na_for_detection_category():
    """Detection engineering techniques are always N/A."""
    assert _mitigation_status("Anti-Debug via SetUnhandledExceptionFilter", "detection") == "na"
    assert _mitigation_status("EDR/Hook Evasion via ntdll Unhooking", "detection") == "na"
    assert _mitigation_status("Language/Locale Geofencing", "detection") == "na"
