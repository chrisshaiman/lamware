// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// One tool invocation in the investigation chat. Collapsed by default to a
// single row (chevron, family icon, tool name, short arg summary, result
// hint); click to expand the full args/result JSON. Color accent indicates
// the tool family. While the result is still undefined (call in flight) the
// row pulses subtly.

import { useState } from "react";
import { ChevronDown, ChevronRight, Search, Wrench } from "lucide-react";
import { MonoText } from "#components/shared/mono-text";
import { cn, truncate } from "#lib/utils";

interface InvestigationToolCallProps {
  tool: string;
  args: Record<string, unknown>;
  /**
   * undefined = call still in flight (pulse animation);
   * null = no result recorded (e.g. orphaned persisted row);
   * object = completed result.
   */
  result?: Record<string, unknown> | null;
}

// ---------------------------------------------------------------------------
// Tool family → color accent
// ---------------------------------------------------------------------------

type ToolFamily = "db" | "ghidra" | "python" | "pin" | "cape" | "other";

const GHIDRA_TOOLS = new Set([
  "decompile_function",
  "get_xrefs_to",
  "get_xrefs_from",
  "get_strings_at",
  "list_functions",
  "get_data_at",
]);

const CAPE_PCAP_TOOLS = new Set([
  "get_cape_payloads",
  "read_payload",
  "get_pcap_summary",
  "get_api_traces",
]);

function toolFamily(tool: string): ToolFamily {
  // Specific tool sets first — several also match the generic get_ prefix.
  if (GHIDRA_TOOLS.has(tool)) return "ghidra";
  if (CAPE_PCAP_TOOLS.has(tool)) return "cape";
  if (tool === "run_python") return "python";
  if (tool === "pin_finding") return "pin";
  if (tool.startsWith("search_") || tool.startsWith("get_")) return "db";
  return "other";
}

const FAMILY_ACCENT: Record<ToolFamily, string> = {
  db: "text-blue-400",
  ghidra: "text-purple-400",
  python: "text-green-400",
  pin: "text-amber-400",
  cape: "text-cyan-400",
  other: "text-gray-400",
};

// ---------------------------------------------------------------------------
// Collapsed-row summaries
// ---------------------------------------------------------------------------

/** Most informative arg value for the collapsed summary — first defined wins. */
const SUMMARY_KEYS = ["value", "technique_id", "name", "query", "analysis_id"] as const;

function argsSummary(args: Record<string, unknown>): string {
  for (const key of SUMMARY_KEYS) {
    const v = args[key];
    if (v !== undefined && v !== null) return truncate(String(v), 60);
  }
  return "";
}

function ResultHint({ result }: { result: Record<string, unknown> }) {
  if (result.error !== undefined && result.error !== null) {
    return (
      <span className="rounded border border-red-800 bg-red-900/30 px-1.5 py-0.5 text-[10px] font-medium text-red-400">
        error
      </span>
    );
  }
  if (result.count !== undefined) {
    return (
      <span className="text-[10px] tabular-nums text-[var(--color-text-muted)]">
        {String(result.count)} results
      </span>
    );
  }
  return <span className="text-[10px] text-[var(--color-text-muted)]">done</span>;
}

function JsonBlock({ label, value }: { label: string; value: Record<string, unknown> }) {
  return (
    <div>
      <div className="mb-1 text-[10px] font-medium uppercase tracking-wide text-[var(--color-text-muted)]">
        {label}
      </div>
      <pre className="max-h-64 overflow-x-auto overflow-y-auto rounded border border-[var(--color-border-light)] bg-[var(--color-background)] p-2 font-mono text-[10px] text-[var(--color-text-secondary)]">
        {JSON.stringify(value, null, 2)}
      </pre>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function InvestigationToolCall({ tool, args, result }: InvestigationToolCallProps) {
  const [expanded, setExpanded] = useState(false);

  const family = toolFamily(tool);
  const accent = FAMILY_ACCENT[family];
  const Icon = family === "db" ? Search : Wrench;
  const inFlight = result === undefined;
  const summary = argsSummary(args);

  return (
    <div
      className={cn(
        "rounded-md border border-[var(--color-border-light)] bg-[var(--color-surface)] text-xs",
        inFlight && "animate-pulse",
      )}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center gap-2 px-2 py-1.5 text-left"
      >
        {expanded ? (
          <ChevronDown className="h-3 w-3 shrink-0 text-[var(--color-text-muted)]" />
        ) : (
          <ChevronRight className="h-3 w-3 shrink-0 text-[var(--color-text-muted)]" />
        )}
        <Icon className={cn("h-3.5 w-3.5 shrink-0", accent)} />
        <MonoText className={cn("shrink-0 font-medium", accent)}>{tool}</MonoText>
        {summary && (
          <span className="min-w-0 flex-1 truncate font-mono text-[var(--color-text-muted)]">
            {summary}
          </span>
        )}
        {result != null && (
          <span className="ml-auto shrink-0">
            <ResultHint result={result} />
          </span>
        )}
      </button>

      {expanded && (
        <div className="space-y-2 border-t border-[var(--color-border-light)] p-2">
          <JsonBlock label="Input" value={args} />
          {result != null && <JsonBlock label="Output" value={result} />}
          {inFlight && (
            <div className="text-[var(--color-text-muted)]">Waiting for result&hellip;</div>
          )}
          {result === null && (
            <div className="text-[var(--color-text-muted)]">No result recorded.</div>
          )}
        </div>
      )}
    </div>
  );
}
