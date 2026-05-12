// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { Shield } from "lucide-react";
import { useTechniquesList } from "#hooks/use-techniques";
import { SearchInput } from "#components/shared/search-input";
import { MonoText } from "#components/shared/mono-text";
import { formatRelativeTime } from "#lib/utils";
import { MITRE_TACTICS, TACTIC_LABELS, type MitreTactic } from "#lib/constants";
import { MitreHeatmap } from "./mitre-heatmap";

const PAGE_SIZE = 50;

export function TechniquesPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const q = searchParams.get("q") ?? "";
  const tactic = searchParams.get("tactic") ?? "";
  const offset = parseInt(searchParams.get("offset") ?? "0", 10);

  const { data: techniques, isLoading, isError } = useTechniquesList({
    q: q || undefined,
    tactic: tactic || undefined,
    limit: PAGE_SIZE,
    offset,
  });

  // Fetch ALL techniques for the heatmap (unfiltered)
  const { data: allTechniques } = useTechniquesList({ limit: 500 });

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) next.set(key, value);
        else next.delete(key);
        if (key !== "offset") next.delete("offset");
        return next;
      });
    },
    [setSearchParams],
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <Shield className="h-5 w-5 text-[var(--color-text-secondary)]" />
        <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">MITRE ATT&CK</h1>
      </div>

      {/* MITRE ATT&CK Heatmap */}
      {allTechniques && allTechniques.length > 0 && (
        <MitreHeatmap
          techniques={allTechniques}
          onTacticClick={(t) => setParam("tactic", t)}
          onTechniqueClick={(id) => setParam("q", id)}
        />
      )}

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <SearchInput
          value={q}
          onChange={(v) => setParam("q", v)}
          placeholder="Search technique ID or name..."
          className="w-80"
        />
        <select
          value={tactic}
          onChange={(e) => setParam("tactic", e.target.value)}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
        >
          <option value="">All tactics</option>
          {MITRE_TACTICS.map((t) => (
            <option key={t} value={t}>{TACTIC_LABELS[t]}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 10 }).map((_, i) => (
            <div key={i} className="h-10 animate-pulse rounded bg-[var(--color-surface)]" />
          ))}
        </div>
      ) : isError ? (
        <div className="rounded-md border border-red-800 bg-red-900/20 p-4 text-sm text-red-400">
          Failed to load techniques.
        </div>
      ) : !techniques || techniques.length === 0 ? (
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-secondary)]">
          No techniques found.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-md border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)]">
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">ID</th>
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">Name</th>
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">Tactics</th>
                <th className="px-4 py-3 text-right font-medium text-[var(--color-text-secondary)]">Samples</th>
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">First Seen</th>
              </tr>
            </thead>
            <tbody>
              {techniques.map((t) => (
                <tr key={t.id} className="border-b border-[var(--color-border-light)] transition-colors hover:bg-[var(--color-surface-hover)]">
                  <td className="px-4 py-2.5">
                    <MonoText>{t.technique_id}</MonoText>
                  </td>
                  <td className="px-4 py-2.5 text-[var(--color-text-secondary)]">
                    {t.technique_name}
                  </td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {t.tactics.map((tac) => (
                        <button
                          key={tac}
                          onClick={() => setParam("tactic", tac)}
                          className="rounded bg-[var(--color-surface)] px-1.5 py-0.5 text-[10px] text-[var(--color-text-muted)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-secondary)]"
                        >
                          {TACTIC_LABELS[tac as MitreTactic] ?? tac}
                        </button>
                      ))}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 text-right">
                    <span className={`tabular-nums ${t.analysis_count > 1 ? "font-medium text-[var(--color-accent)]" : "text-[var(--color-text-secondary)]"}`}>
                      {t.analysis_count}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-[var(--color-text-muted)]">
                    {t.first_seen ? formatRelativeTime(t.first_seen) : "\u2014"}
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
