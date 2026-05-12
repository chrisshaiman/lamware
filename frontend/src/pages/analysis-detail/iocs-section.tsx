// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { MonoText } from "#components/shared/mono-text";
import { SourceBadge } from "#components/shared/source-badge";
import type { AnalysisIoc } from "#lib/types";

export function IocsSection({ iocs }: { iocs: AnalysisIoc[] }) {
  const [expanded, setExpanded] = useState(true);
  const [showAll, setShowAll] = useState(false);

  if (iocs.length === 0) return null;

  const displayed = showAll ? iocs : iocs.slice(0, 20);

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between px-4 py-3 text-left"
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
            IOCs
          </h3>
          <span className="text-xs text-[var(--color-text-muted)]">({iocs.length})</span>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[var(--color-border)]">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[var(--color-border-light)] bg-[var(--color-background)]">
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Type</th>
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Value</th>
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Source</th>
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Confidence</th>
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Context</th>
              </tr>
            </thead>
            <tbody>
              {displayed.map((ioc) => (
                <tr key={ioc.id} className="border-b border-[var(--color-border-light)]">
                  <td className="px-4 py-2 text-[var(--color-text-secondary)]">{ioc.type}</td>
                  <td className="max-w-xs px-4 py-2">
                    <MonoText className="break-all">{ioc.value}</MonoText>
                  </td>
                  <td className="px-4 py-2">
                    <SourceBadge stage={ioc.source_stage} />
                  </td>
                  <td className="px-4 py-2 text-[var(--color-text-secondary)]">{ioc.confidence ?? "\u2014"}</td>
                  <td className="max-w-xs px-4 py-2 text-[var(--color-text-muted)]">{ioc.context ?? ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {iocs.length > 20 && (
            <div className="border-t border-[var(--color-border)] px-4 py-2 text-center">
              <button
                onClick={() => setShowAll(!showAll)}
                className="text-xs text-[var(--color-accent)] hover:underline"
              >
                {showAll ? "Show less" : `Show all ${iocs.length} IOCs`}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
