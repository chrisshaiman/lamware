// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Shared constants — colors, MITRE taxonomy, badge mappings.

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

export const SEVERITY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "bg-red-900/50", text: "text-red-400", border: "border-red-800" },
  high:     { bg: "bg-orange-900/50", text: "text-orange-400", border: "border-orange-800" },
  medium:   { bg: "bg-yellow-900/50", text: "text-yellow-400", border: "border-yellow-800" },
  low:      { bg: "bg-blue-900/50", text: "text-blue-400", border: "border-blue-800" },
};

// ---------------------------------------------------------------------------
// Pipeline source stages
// ---------------------------------------------------------------------------

export const SOURCE_STAGE_COLORS: Record<string, { bg: string; text: string }> = {
  "Triage":                 { bg: "bg-gray-700/50", text: "text-gray-300" },
  "Cape":                   { bg: "bg-orange-900/50", text: "text-orange-300" },
  "Volatility":             { bg: "bg-purple-900/50", text: "text-purple-300" },
  "Ghidra":                 { bg: "bg-green-900/50", text: "text-green-300" },
  "AI Reverse Engineering":  { bg: "bg-blue-900/50", text: "text-blue-300" },
  "Summary":                { bg: "bg-violet-900/50", text: "text-violet-300" },
};

// ---------------------------------------------------------------------------
// MITRE ATT&CK — canonical tactic order (Enterprise matrix)
// ---------------------------------------------------------------------------

export const MITRE_TACTICS = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
] as const;

export type MitreTactic = (typeof MITRE_TACTICS)[number];

/** Human-readable tactic labels. */
export const TACTIC_LABELS: Record<MitreTactic, string> = {
  "reconnaissance": "Reconnaissance",
  "resource-development": "Resource Dev",
  "initial-access": "Initial Access",
  "execution": "Execution",
  "persistence": "Persistence",
  "privilege-escalation": "Priv Esc",
  "defense-evasion": "Defense Evasion",
  "credential-access": "Credential Access",
  "discovery": "Discovery",
  "lateral-movement": "Lateral Movement",
  "collection": "Collection",
  "command-and-control": "C2",
  "exfiltration": "Exfiltration",
  "impact": "Impact",
};

// ---------------------------------------------------------------------------
// Pipeline stages (for progress indicators)
// ---------------------------------------------------------------------------

export const PIPELINE_STAGES = [
  "triage",
  "cape",
  "pcap",
  "volatility",
  "ghidra",
  "interpret",
  "summary",
  "pdf",
] as const;

export const STAGE_LABELS: Record<string, string> = {
  triage: "Triage",
  cape: "Dynamic",
  pcap: "PCAP",
  volatility: "Memory",
  ghidra: "Static",
  interpret: "AI RE",
  summary: "Summary",
  pdf: "Report",
};

// ---------------------------------------------------------------------------
// IOC types
// ---------------------------------------------------------------------------

export const IOC_TYPES = [
  "ipv4-addr",
  "ipv6-addr",
  "domain-name",
  "url",
  "email-addr",
  "file:hashes.SHA-256",
  "file:hashes.MD5",
  "file:name",
  "windows-registry-key",
  "mutex",
  "user-agent",
  "network-traffic",
  "yara-rule",
] as const;
