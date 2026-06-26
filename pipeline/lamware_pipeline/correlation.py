# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Family/severity/MITRE helpers (pure functions of the report dict).

cross_correlate() now lives in correlation_rules.py and is re-exported here
for backward compatibility. This module retains determine_family(),
calculate_severity(), and build_mitre_mapping() — the family-detection
priority chain, severity scoring, and MITRE ATT&CK mapping helpers.
"""
import re

from .correlation_rules import cross_correlate  # noqa: F401  (back-compat public re-export)

__all__ = [
    "determine_family",
    "calculate_severity",
    "build_mitre_mapping",
    "cross_correlate",
]


def determine_family(report: dict) -> str:
    """Determine malware family using a priority chain of signals.

    Priority order (highest confidence first):
    0. MalwareBazaar signature — threat intel community consensus
    1. Cape extracted configs — curated family tag from config extraction
    2. Cape malfamily — CAPE's own signature-based family detection
    3. Go offensive module match — definitive build provenance
    4. .NET namespace match — distinctive namespace patterns
    5. LLM family guess — highest intelligence, full context analysis
    6. YARA rule-derived — broadest match, most false positives

    Each level is tried in order. If a high-confidence signal exists,
    lower signals are ignored to avoid false positives from generic
    YARA rules overriding accurate LLM or Cape detection.
    """
    cape = report.get("cape", {})
    triage = report.get("triage", {})

    def _result(family: str, source: str) -> str:
        """Tag the report with the detection source for logging."""
        report["_family_source"] = source
        return family

    # --- Priority 0: MalwareBazaar signature (community consensus) ---
    bazaar_family = report.get("bazaar_family", "")
    if bazaar_family and bazaar_family.lower() not in ("", "unknown", "n/a", "none"):
        return _result(bazaar_family.lower(), "bazaar")

    # --- Priority 1: Cape extracted configs (highest confidence) ---
    for cfg in cape.get("extracted_configs", []):
        if isinstance(cfg, dict):
            family = cfg.get("family", "") or cfg.get("malware", "")
            if family:
                return _result(family.lower(), "cape_config")

    # --- Priority 2: Cape signature families ---
    cape_families = {}
    for sig in cape.get("signatures", []):
        families = sig.get("families", [])
        if isinstance(families, list):
            for fam in families:
                if fam:
                    cape_families[fam.lower()] = cape_families.get(fam.lower(), 0) + 1
    if cape_families:
        return _result(max(cape_families, key=cape_families.get), "cape_signatures")

    # --- Priority 3: Go offensive module/function match ---
    go_data = report.get("go_analysis", {})
    if go_data.get("analysis_success"):
        for s in go_data.get("strings_of_interest", []):
            if not isinstance(s, dict):
                continue
            if s.get("type") == "offensive_tool":
                # Extract family name from the description
                context = s.get("context", "")
                if "sliver" in context.lower():
                    return _result("sliver", "go_module")
                if "merlin" in context.lower():
                    return _result("merlin", "go_module")
                if "geacon" in context.lower():
                    return _result("cobaltstrike (geacon)", "go_module")
                if "chisel" in context.lower():
                    return _result("chisel", "go_module")
                if "prince" in context.lower():
                    return _result("prince ransomware", "go_module")
                if "skuld" in context.lower():
                    return _result("skuld stealer", "go_module")
                # Generic offensive tool
                return _result(s.get("value", "unknown go tool").split("/")[-1].lower(), "go_module")

    # --- Priority 3b: Evasion hunter likely behavior ---
    evasion = report.get("evasion_analysis", {})
    if evasion.get("enabled") and evasion.get("analysis"):
        likely = evasion["analysis"].get("likely_behavior_if_not_evading", "").lower()
        if likely:
            known_names = [
                "sliver", "merlin", "cobaltstrike", "cobalt strike",
                "emotet", "asyncrat", "nanocore", "remcos",
                "bianlian", "lockbit", "blackcat",
            ]
            for name in known_names:
                if name in likely:
                    return _result(name.replace(" ", ""), "evasion_analysis")

    # --- Priority 4: .NET namespace match ---
    dotnet_data = report.get("dotnet_analysis", {})
    if dotnet_data.get("analysis_success"):
        source = dotnet_data.get("decompilation", {}).get("source", "")
        dotnet_families = {
            "nanocore": ["NanoCore", "NanoCore.ClientPlugin"],
            "asyncrat": ["AsyncRAT", "AsyncClient"],
            "quasar": ["Quasar.Client", "Quasar.Common"],
            "njrat": ["njRAT", "njRat"],
            "darkcomet": ["DarkComet"],
            "agenttesla": ["AgentTesla"],
            "remcos": ["Remcos"],
            "warzone": ["Warzone", "Ave_Maria"],
            "orcus": ["Orcus"],
        }
        for family, patterns in dotnet_families.items():
            for pattern in patterns:
                if pattern in source:
                    return _result(family, "dotnet_namespace")

    # --- Priority 5: LLM family guess ---
    llm_family = (report.get("llm_interpretation", {})
                  .get("analysis", {})
                  .get("malware_family_guess", ""))
    if llm_family and llm_family.lower() not in ("unknown", ""):
        # Normalize long LLM descriptions to a short family name
        llm_lower = llm_family.lower()
        # Check for known families in the LLM's verbose description
        known_names = [
            # C2 frameworks
            "sliver", "merlin", "cobaltstrike", "cobalt strike",
            "meterpreter", "metasploit", "havoc", "brute ratel",
            "bruteratel", "mythic", "poshc2",
            # Banking/loader
            "emotet", "trickbot", "qakbot", "qbot", "icedid",
            "dridex", "pikabot", "smokeloader", "guloader",
            "bumblebee", "darkgate",
            # RATs
            "asyncrat", "nanocore", "remcos", "agenttesla",
            "njrat", "darkcomet", "quasar", "warzone", "netwire",
            "orcus", "xworm", "dcrat", "venom rat", "venomrat",
            "lime rat", "limerat",
            # Stealers
            "formbook", "lokibot", "raccoon", "redline", "vidar",
            "lumma", "stealc", "rhadamanthys", "mystic stealer",
            # Ransomware
            "lockbit", "blackcat", "alphv", "conti", "ryuk",
            "royal", "akira", "play", "medusa", "clop",
            "bianlian", "rhysida", "blackbasta",
            # Other
            "amadey", "systembc", "socks5systemz",
        ]
        for name in known_names:
            if name in llm_lower:
                return _result(name.replace(" ", ""), "llm_interpretation")

        # Fallback: extract a clean short name from the LLM description.
        # LLM often produces "VB6 dropper/downloader (likely guloader...)"
        # Strip parenthetical qualifiers and take the first meaningful phrase.
        # Remove parenthetical notes like "(likely ...)" or "(possibly ...)"
        cleaned = re.sub(r"\s*\(.*?\)", "", llm_family).strip()
        # Remove common filler words
        cleaned = re.sub(r"(?i)\b(likely|possibly|probably|variant of|appears to be|based on)\b", "", cleaned).strip()
        # Collapse whitespace and truncate
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        if cleaned:
            return _result(cleaned[:50].lower(), "llm_interpretation")
        return _result(llm_family[:50].lower(), "llm_interpretation")

    # --- Priority 6: YARA rule-derived (last resort) ---
    yara_families = {}
    known_yara_families = [
        "emotet", "trickbot", "qakbot", "qbot", "icedid", "dridex",
        "cobalt", "cobaltstrike", "agenttesla", "formbook",
        "lokibot", "remcos", "njrat", "asyncrat", "nanocore",
        "darkcomet", "quasar", "warzone", "netwire", "orcus",
        "raccoon", "redline", "vidar", "lumma", "stealc",
        "lockbit", "blackcat", "alphv", "conti", "ryuk", "revil",
        "guloader", "smokeloader", "amadey", "systembc",
        "bianlian", "sliver",
    ]
    # Exclude overly generic rules that cause false positives
    generic_rules = ["meterpreter", "metasploit", "hacktool", "generic", "suspicious"]
    for match in triage.get("yara_matches", []):
        rule = match.get("rule", "").lower()
        # Skip generic rules
        if any(g in rule for g in generic_rules):
            continue
        for family in known_yara_families:
            if family in rule:
                yara_families[family] = yara_families.get(family, 0) + 1
    if yara_families:
        return _result(max(yara_families, key=yara_families.get), "yara_rules")

    return _result("unknown", "none")


def calculate_severity(report: dict) -> str:
    """Calculate severity from all pipeline stages.

    Scoring sources:
    - Cape malscore and behavioral signatures
    - YARA match count and rule severity
    - Known malware family identification
    - Evasion detection (evasive = likely sophisticated)
    - LLM capabilities assessment
    - Go offensive module detection
    """
    score = 0
    cape = report.get("cape", {})

    # Cape malscore (0-10)
    malscore = cape.get("malscore", 0)
    if isinstance(malscore, (int, float)):
        score += malscore * 3  # 0-30 points

    # High-severity Cape signatures
    for sig in cape.get("signatures", []):
        sev = sig.get("severity", 0)
        if sev >= 3:
            score += 3
        elif sev >= 2:
            score += 1

    # Injection behavior
    injection_bufs = cape.get("injection_buffers", [])
    if injection_bufs:
        score += 10

    # Network C2
    network = cape.get("network", {})
    dns = network.get("dns_queries", [])
    if dns:
        score += 5

    # Cross-correlations
    for finding in report.get("cross_correlations", []):
        if finding.get("severity") == "critical":
            score += 10
        elif finding.get("severity") == "high":
            score += 5

    # --- Additional signals beyond Cape ---

    # Known malware family = at least medium severity
    family = report.get("family", "unknown")
    if family != "unknown":
        score += 10

    # YARA match count — many matches = well-known malicious
    triage = report.get("triage", {})
    yara_count = len(triage.get("yara_matches", []))
    if yara_count >= 10:
        score += 5
    elif yara_count >= 5:
        score += 3

    # Evasion detected — sandbox-aware samples are typically sophisticated
    evasion = report.get("evasion_analysis", {})
    if evasion.get("enabled") and evasion.get("analysis"):
        confidence = evasion["analysis"].get("confidence", "")
        if confidence == "high":
            score += 15  # confirmed evasion = at least high severity
        elif confidence == "medium":
            score += 10

    # Office macro mraptor flags — auto_exec + write + execute = high confidence
    office_data = report.get("office_analysis", {})
    if office_data.get("has_macros"):
        mraptor = office_data.get("mraptor_flags", {})
        if mraptor.get("auto_exec") and mraptor.get("execute"):
            score += 10  # auto-exec + execute = likely malicious
        if mraptor.get("write"):
            score += 3  # file write capability
        if office_data.get("obfuscation_indicators"):
            score += 5  # legitimate macros are rarely obfuscated
        if office_data.get("xlm_detected"):
            score += 5  # XLM macros are almost exclusively malicious

    # PowerShell obfuscation and offensive tool indicators
    ps_data = report.get("powershell_analysis", {})
    if ps_data.get("analysis_success"):
        # Encoded command from CAPE = suspicious
        if ps_data.get("cape_extracted") or ps_data.get("input_mode") == "encoded_command":
            score += 5
        # Heavy obfuscation
        if ps_data.get("layer_count", 0) > 2:
            score += 5
        # Offensive tool patterns
        for s in ps_data.get("strings_of_interest", []):
            if isinstance(s, dict) and s.get("type") in ("offensive_tool", "credential_access"):
                score += 10
                break
        # Download cradle
        for s in ps_data.get("strings_of_interest", []):
            if isinstance(s, dict) and s.get("type") == "download_cradle":
                score += 5
                break

    # Go offensive tool module detected (Sliver, Merlin, etc.)
    go_data = report.get("go_analysis", {})
    for s in go_data.get("strings_of_interest", []):
        if isinstance(s, dict) and s.get("type") == "offensive_tool":
            score += 15
            break

    # LLM identified capabilities
    llm = report.get("llm_interpretation", {}).get("analysis", {})
    capabilities = llm.get("capabilities", [])
    if len(capabilities) >= 10:
        score += 5
    elif len(capabilities) >= 5:
        score += 3

    report["_severity_score"] = score

    if score >= 30:
        return "critical"
    elif score >= 20:
        return "high"
    elif score >= 10:
        return "medium"
    return "low"


def build_mitre_mapping(report: dict) -> list[dict]:
    """Build MITRE ATT&CK mapping from Cape TTPs — no LLM needed.

    Cape already maps its behavioral signatures to MITRE technique IDs.
    The LLM can add techniques it discovers in code, but the Cape mapping
    is the authoritative source.
    """
    techniques = {}
    cape = report.get("cape", {})

    for ttp in cape.get("mitre_ttps", []):
        tid = ttp.get("id", "")
        if tid and tid not in techniques:
            techniques[tid] = {
                "id": tid,
                "source_signature": ttp.get("source_signature", ""),
                "sources": ["Cape"],
            }

    # Add any from LLM interpretation (supplementary)
    llm = report.get("llm_interpretation", {})
    analysis = llm.get("analysis", {})
    for t in analysis.get("attack_techniques", []):
        tid = t.get("id", "")
        if tid:
            if tid in techniques:
                if "AI Reverse Engineering" not in techniques[tid]["sources"]:
                    techniques[tid]["sources"].append("AI Reverse Engineering")
            else:
                techniques[tid] = {
                    "id": tid,
                    "name": t.get("name", ""),
                    "sources": ["AI Reverse Engineering"],
                }

    return list(techniques.values())
