// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

/**
 * Which pipeline component fed which, for one analysis (#653).
 *
 * Four bugs in one week were a component silently not feeding the next
 * (#644, #648, #646, #647), each visible only in report.json. This card draws
 * what the report recorded: every hand-off with ok / skipped / failed / absent.
 *
 * Two rules:
 *  - `absent` is not zero. An edge whose count the report never recorded shows
 *    "not recorded", never "0 items" — that reading is the failure this exists
 *    to expose.
 *  - Every string here comes from a report, and payload labels and filenames
 *    are attacker-controlled. They are rendered as React text children only.
 */

import { useState } from "react";
import { ArrowRight, ChevronDown, ChevronRight } from "lucide-react";
import { useAnalysisFlow } from "#hooks/use-analyses";
import { cn } from "#lib/utils";
import type { FlowEdge, FlowItem, FlowNode, FlowStatus, PipelineFlow } from "#lib/types";

const STAGE_COLOR: Record<string, string> = {
  sample: "var(--color-text-secondary)",
  triage: "var(--color-stage-triage)",
  cape: "var(--color-stage-cape)",
  volatility: "var(--color-stage-volatility)",
  ghidra: "var(--color-stage-ghidra)",
  re_agent: "var(--color-stage-ai-re)",
  correlation: "var(--color-stage-summary)",
};

const STATUS_STYLE: Record<FlowStatus, { box: string; text: string; badge: string }> = {
  ok: {
    box: "border-[var(--color-border)]",
    text: "text-[var(--color-text-secondary)]",
    badge: "bg-green-900/40 text-green-300",
  },
  skipped: {
    box: "border-amber-700/70 bg-amber-950/20",
    text: "text-amber-300",
    badge: "bg-amber-900/50 text-amber-300",
  },
  failed: {
    box: "border-red-800 bg-red-950/30",
    text: "text-red-300",
    badge: "bg-red-900/50 text-red-300",
  },
  absent: {
    box: "border-dashed border-[var(--color-border)] opacity-70",
    text: "text-[var(--color-text-muted)]",
    badge: "bg-[var(--color-border-light)] text-[var(--color-text-muted)]",
  },
};

const ITEM_TEXT: Record<string, string> = {
  loaded: "text-green-300",
  read: "text-blue-300",
  empty: "text-[var(--color-text-secondary)]",
  skipped: "text-amber-300",
  lost: "text-red-300",
  failed: "text-red-300",
  missing: "text-red-300",
};

// Left-to-right order of the node strip. Routed analysers (ILSpy, olevba, …)
// sit between CAPE and Ghidra with Volatility.
const COLUMN: Record<string, number> = {
  sample: 0,
  triage: 1,
  cape: 1,
  volatility: 2,
  ghidra: 3,
  re_agent: 4,
  correlation: 4,
};

function styleFor(status: string) {
  return STATUS_STYLE[status as FlowStatus] ?? STATUS_STYLE.absent;
}

function StatusBadge({ status }: { status: string }) {
  return (
    <span
      data-testid="flow-status"
      className={cn("rounded px-1.5 py-0.5 text-[10px] font-medium uppercase", styleFor(status).badge)}
    >
      {status}
    </span>
  );
}

/**
 * "3 of 5 carried", "0 carried", "not recorded", or nothing for a hand-off
 * that is not counted (sample → triage). Never a zero the report did not state.
 */
function carriedText(edge: FlowEdge): string | null {
  if (edge.status === "absent") return "not recorded";
  if (edge.carried === null) return null;
  if (edge.expected !== null) return `${edge.carried} of ${edge.expected} carried`;
  return `${edge.carried} carried`;
}

function NodeBox({ node }: { node: FlowNode }) {
  const s = styleFor(node.status);
  return (
    <div
      data-testid={`flow-node-${node.id}`}
      data-status={node.status}
      className={cn("rounded-md border border-l-4 px-3 py-2 text-xs", s.box)}
      style={{ borderLeftColor: STAGE_COLOR[node.id] ?? "var(--color-accent)" }}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-semibold text-[var(--color-text-primary)]" title={node.label}>
          {node.label}
        </span>
        <StatusBadge status={node.status} />
      </div>
      {node.role && (
        <div className="mt-0.5 text-[10px] text-[var(--color-text-muted)]">{node.role}</div>
      )}
      {node.detail && (
        <div className="mt-1 break-words text-[var(--color-text-secondary)]">{node.detail}</div>
      )}
      {node.reason && <div className={cn("mt-1 break-words", s.text)}>{node.reason}</div>}
      {node.warnings && node.warnings.length > 0 && (
        <div className="mt-1 text-amber-300">
          {node.warnings.length} warning{node.warnings.length === 1 ? "" : "s"}
        </div>
      )}
    </div>
  );
}

function ItemRow({ item }: { item: FlowItem }) {
  return (
    <li className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 px-3 py-1.5 text-xs">
      <span className={cn("w-16 shrink-0 font-medium", ITEM_TEXT[item.status] ?? "")}>
        {item.status}
      </span>
      <span className="min-w-0 break-all text-[var(--color-text-primary)]">{item.label}</span>
      {item.functions != null && (
        <span className="text-[var(--color-text-muted)]">{item.functions} functions</span>
      )}
      {item.sha256 && (
        <span className="font-mono text-[var(--color-text-muted)]">{item.sha256}</span>
      )}
      {item.size != null && (
        <span className="text-[var(--color-text-muted)]">{item.size.toLocaleString()} B</span>
      )}
      {item.detail && (
        <span className="basis-full break-words pl-[4.75rem] text-[var(--color-text-secondary)]">
          {item.detail}
        </span>
      )}
    </li>
  );
}

function EdgeRow({ edge, nodes }: { edge: FlowEdge; nodes: Map<string, FlowNode> }) {
  const [open, setOpen] = useState(false);
  const s = styleFor(edge.status);
  const expandable = (edge.items?.length ?? 0) > 0;
  const fromLabel = nodes.get(edge.from)?.label ?? edge.from;
  const toLabel = nodes.get(edge.to)?.label ?? edge.to;

  return (
    <li data-testid={`flow-edge-${edge.id}`} data-status={edge.status} className={cn("rounded-md border", s.box)}>
      <button
        type="button"
        onClick={() => expandable && setOpen(!open)}
        aria-expanded={expandable ? open : undefined}
        disabled={!expandable}
        className="flex w-full flex-wrap items-center gap-x-2 gap-y-1 px-3 py-2 text-left text-xs disabled:cursor-default"
      >
        <span className="w-3.5 shrink-0">
          {expandable &&
            (open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />)}
        </span>
        <span className="max-w-[12rem] truncate text-[var(--color-text-primary)]" title={fromLabel}>
          {fromLabel}
        </span>
        <ArrowRight
          className={cn("h-3.5 w-3.5 shrink-0", s.text)}
          strokeDasharray={edge.status === "absent" ? "3 3" : undefined}
        />
        <span className="max-w-[12rem] truncate text-[var(--color-text-primary)]" title={toLabel}>
          {toLabel}
        </span>
        <span className="text-[var(--color-text-muted)]">{edge.label}</span>
        <StatusBadge status={edge.status} />
        {carriedText(edge) !== null && (
          <span data-testid="flow-carried" className={cn("tabular-nums", s.text)}>
            {carriedText(edge)}
          </span>
        )}
        {edge.inferred && <span className="text-[10px] text-[var(--color-text-muted)]">(inferred)</span>}
      </button>
      {(edge.reason || edge.note || edge.not_forwarded) && (
        <div className="space-y-0.5 px-3 pb-2 pl-9 text-xs">
          {edge.reason && <div className={cn("break-words", s.text)}>{edge.reason}</div>}
          {edge.not_forwarded ? (
            <div className="text-amber-300">
              {edge.not_forwarded} of {edge.extracted} not forwarded
              {edge.not_forwarded_reason ? `: ${edge.not_forwarded_reason}` : ""}
            </div>
          ) : null}
          {edge.note && <div className="break-words text-[var(--color-text-secondary)]">{edge.note}</div>}
        </div>
      )}
      {open && edge.items && (
        <ul className="divide-y divide-[var(--color-border-light)] border-t border-[var(--color-border-light)]">
          {edge.items.map((item, i) => (
            <ItemRow key={i} item={item} />
          ))}
          {edge.items_truncated > 0 && (
            <li className="px-3 py-1.5 text-xs text-[var(--color-text-muted)]">
              … {edge.items_truncated} more not shown
            </li>
          )}
        </ul>
      )}
    </li>
  );
}

/** The graph itself, from an already-fetched flow. Exported for tests. */
export function PipelineFlowView({ flow }: { flow: PipelineFlow }) {
  const byId = new Map(flow.nodes.map((n) => [n.id, n]));
  const columns: FlowNode[][] = [[], [], [], [], []];
  for (const n of flow.nodes) columns[COLUMN[n.id] ?? 2].push(n);
  const warnings = flow.nodes.flatMap((n) => (n.warnings ?? []).map((w) => ({ node: n.label, w })));

  return (
    <div className="space-y-4 border-t border-[var(--color-border)] px-4 py-3">
      {!flow.has_report && (
        <div className="text-xs text-[var(--color-text-muted)]">
          No report is stored for this analysis; every hand-off is absent.
        </div>
      )}
      <div className="flex flex-col gap-2 lg:flex-row lg:items-stretch">
        {columns.map((col, i) =>
          col.length === 0 ? null : (
            <div key={i} className="flex items-center gap-2 lg:flex-1">
              <div className="flex flex-1 flex-col gap-2">
                {col.map((n) => (
                  <NodeBox key={n.id} node={n} />
                ))}
              </div>
              {i < columns.length - 1 && (
                <ArrowRight className="hidden h-4 w-4 shrink-0 text-[var(--color-text-muted)] lg:block" />
              )}
            </div>
          ),
        )}
      </div>
      <ul className="space-y-1.5">
        {flow.edges.map((e) => (
          <EdgeRow key={e.id} edge={e} nodes={byId} />
        ))}
      </ul>
      {warnings.length > 0 && (
        <ul className="space-y-0.5 text-xs text-amber-300">
          {warnings.map(({ node, w }, i) => (
            <li key={i} className="break-words">
              <span className="text-[var(--color-text-muted)]">{node}: </span>
              {w}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function PipelineFlowSection({ analysisId }: { analysisId: number }) {
  const [expanded, setExpanded] = useState(true);
  const { data: flow, isLoading, isError } = useAnalysisFlow(analysisId);

  const tally = (status: FlowStatus) => flow?.edges.filter((e) => e.status === status).length ?? 0;
  const failed = tally("failed");
  const skipped = tally("skipped");
  const absent = tally("absent");

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between px-4 py-3 text-left"
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">Pipeline Flow</h3>
          {flow && (
            <span className="text-xs text-[var(--color-text-muted)]">
              {failed > 0 && <span className="text-red-300">{failed} failed · </span>}
              {skipped > 0 && <span className="text-amber-300">{skipped} skipped · </span>}
              {absent} absent
            </span>
          )}
        </div>
      </button>

      {expanded && isLoading && (
        <div className="mx-4 mb-3 h-16 animate-pulse rounded bg-[var(--color-background)]" />
      )}
      {expanded && isError && (
        // Say it failed. Hiding the card would read as "nothing to show".
        <div className="border-t border-[var(--color-border)] px-4 py-3 text-xs text-red-400">
          Failed to load the pipeline flow.
        </div>
      )}
      {expanded && flow && <PipelineFlowView flow={flow} />}
    </div>
  );
}
