// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { MonoText } from "#components/shared/mono-text";
import { SourceBadge } from "#components/shared/source-badge";
import type { AnalysisTechnique } from "#lib/types";
import { TACTIC_LABELS, type MitreTactic } from "#lib/constants";

export function TechniquesSection({ techniques }: { techniques: AnalysisTechnique[] }) {
  const [expanded, setExpanded] = useState(true);

  if (techniques.length === 0) return null;

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between px-4 py-3 text-left"
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
            MITRE Techniques
          </h3>
          <span className="text-xs text-[var(--color-text-muted)]">({techniques.length})</span>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[var(--color-border)]">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[var(--color-border-light)] bg-[var(--color-background)]">
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">ID</th>
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Name</th>
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Tactics</th>
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Source</th>
              </tr>
            </thead>
            <tbody>
              {techniques.map((t) => (
                <tr key={t.id} className="border-b border-[var(--color-border-light)]">
                  <td className="px-4 py-2">
                    <MonoText>{t.technique_id}</MonoText>
                  </td>
                  <td className="px-4 py-2 text-[var(--color-text-secondary)]">{t.technique_name}</td>
                  <td className="px-4 py-2">
                    <div className="flex flex-wrap gap-1">
                      {t.tactics.map((tactic) => (
                        <span
                          key={tactic}
                          className="rounded bg-[var(--color-background)] px-1.5 py-0.5 text-[10px] text-[var(--color-text-muted)]"
                        >
                          {TACTIC_LABELS[tactic as MitreTactic] ?? tactic}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <SourceBadge stage={t.source_stage} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
