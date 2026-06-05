// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { Link } from "react-router-dom";
import { ChevronDown, ChevronRight } from "lucide-react";
import { MonoText } from "#components/shared/mono-text";
import type { OverlappingIoc, OverlappingTechnique } from "#lib/types";

interface RelatedAnalysesProps {
  overlappingIocs: OverlappingIoc[];
  overlappingTechniques: OverlappingTechnique[];
}

/** Renders a list of linked analyses that share an IOC or technique. */
function AnalysisLinks({ analyses }: { analyses: { analysis_id: number; sha256: string; family: string | null }[] }) {
  return (
    <div className="mt-1.5 flex flex-wrap gap-2">
      {analyses.map((a) => (
        <Link
          key={a.analysis_id}
          to={`/analyses/${a.analysis_id}`}
          className="inline-flex items-center gap-1.5 rounded bg-[var(--color-background)] px-2 py-1 text-[11px] text-[var(--color-accent)] hover:underline"
        >
          <MonoText className="text-[11px]">{a.sha256.slice(0, 12)}</MonoText>
          {a.family && (
            <span className="rounded bg-[var(--color-border)] px-1.5 py-0.5 text-[10px] text-[var(--color-text-muted)]">
              {a.family}
            </span>
          )}
        </Link>
      ))}
    </div>
  );
}

export function RelatedAnalyses({ overlappingIocs, overlappingTechniques }: RelatedAnalysesProps) {
  const [expanded, setExpanded] = useState(true);

  if (overlappingIocs.length === 0 && overlappingTechniques.length === 0) return null;

  // Count unique related analysis IDs across both sets
  const uniqueIds = new Set<number>();
  for (const ioc of overlappingIocs) {
    for (const a of ioc.other_analyses) uniqueIds.add(a.analysis_id);
  }
  for (const tech of overlappingTechniques) {
    for (const a of tech.other_analyses) uniqueIds.add(a.analysis_id);
  }

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between px-4 py-3 text-left"
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
            Related Analyses
          </h3>
          <span className="rounded-full bg-[var(--color-accent)] px-2 py-0.5 text-[10px] font-medium text-white">
            {uniqueIds.size}
          </span>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[var(--color-border)] px-4 py-3 space-y-4">
          {/* Shared IOCs */}
          {overlappingIocs.length > 0 && (
            <div>
              <h4 className="mb-2 text-xs font-medium text-[var(--color-text-muted)]">
                Shared IOCs ({overlappingIocs.length})
              </h4>
              <div className="space-y-3">
                {overlappingIocs.map((ioc) => (
                  <div
                    key={ioc.ioc_id}
                    className="rounded border border-[var(--color-border-light)] bg-[var(--color-background)] px-3 py-2"
                  >
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-[var(--color-border)] px-1.5 py-0.5 text-[10px] font-medium text-[var(--color-text-muted)]">
                        {ioc.type}
                      </span>
                      <MonoText className="break-all text-xs">{ioc.value}</MonoText>
                    </div>
                    <AnalysisLinks analyses={ioc.other_analyses} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Shared Techniques */}
          {overlappingTechniques.length > 0 && (
            <div>
              <h4 className="mb-2 text-xs font-medium text-[var(--color-text-muted)]">
                Shared Techniques ({overlappingTechniques.length})
              </h4>
              <div className="space-y-3">
                {overlappingTechniques.map((tech) => (
                  <div
                    key={tech.technique_id}
                    className="rounded border border-[var(--color-border-light)] bg-[var(--color-background)] px-3 py-2"
                  >
                    <div className="flex items-center gap-2">
                      <MonoText className="text-xs">{tech.technique_id}</MonoText>
                      <span className="text-xs text-[var(--color-text-secondary)]">{tech.technique_name}</span>
                    </div>
                    <AnalysisLinks analyses={tech.other_analyses} />
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
