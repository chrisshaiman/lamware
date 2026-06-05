// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { SourceBadge } from "#components/shared/source-badge";
import { formatRelativeTime } from "#lib/utils";

interface AnalysisLink {
  analysis_id: number;
  sha256: string;
  family: string | null;
  submitted_at: string;
  source_stage?: string;
}

interface AnalysisListPanelProps {
  analyses: AnalysisLink[];
  isLoading: boolean;
}

/**
 * Inline expandable panel showing analyses linked to an IOC or technique.
 * Renders a compact list with hash links, family badges, and relative time.
 */
export function AnalysisListPanel({ analyses, isLoading }: AnalysisListPanelProps) {
  if (isLoading) {
    return <div className="p-3 text-sm text-muted-foreground">Loading...</div>;
  }
  if (analyses.length === 0) {
    return <div className="p-3 text-sm text-muted-foreground">No linked analyses</div>;
  }
  return (
    <div className="border-t border-border bg-muted/30 p-3 space-y-1">
      {analyses.map((a) => (
        <div key={a.analysis_id} className="flex items-center gap-2 text-sm">
          <Link
            to={`/analyses/${a.analysis_id}`}
            className="font-mono text-xs text-primary hover:underline"
          >
            {a.sha256.slice(0, 12)}...
          </Link>
          {a.family && (
            <span className="rounded border border-border px-1.5 py-0.5 text-xs font-medium text-foreground/80">
              {a.family}
            </span>
          )}
          {a.source_stage && <SourceBadge stage={a.source_stage} />}
          <span className="text-xs text-muted-foreground ml-auto">
            {formatRelativeTime(a.submitted_at)}
          </span>
        </div>
      ))}
    </div>
  );
}
