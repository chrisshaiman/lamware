// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useCallback, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { Network, X } from "lucide-react";
import { useIocsList } from "#hooks/use-iocs";
import { useIocClusters } from "#hooks/use-ioc-clusters";
import { useIocAnalyses } from "#hooks/use-ioc-analyses";
import { CampaignCards } from "#components/shared/campaign-cards";
import { FamilyFilter } from "#components/shared/family-filter";
import { AnalysisListPanel } from "#components/shared/analysis-list-panel";
import { SearchInput } from "#components/shared/search-input";
import { MonoText } from "#components/shared/mono-text";
import { formatRelativeTime } from "#lib/utils";
import { IOC_TYPES } from "#lib/constants";
import type { IocCluster } from "#lib/types";

const PAGE_SIZE = 50;

export function IocsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const q = searchParams.get("q") ?? "";
  const type = searchParams.get("type") ?? "";
  const offset = parseInt(searchParams.get("offset") ?? "0", 10);

  // Family filter — "all" means no filter
  const [family, setFamily] = useState("all");

  // Row expand — which IOC is expanded to show linked analyses
  const [expandedIocId, setExpandedIocId] = useState<number | null>(null);

  // Campaign cluster filter — show the selected cluster's IOCs directly
  const [selectedCluster, setSelectedCluster] = useState<IocCluster | null>(null);

  const { data: iocs, isLoading, isError } = useIocsList({
    q: q || undefined,
    type: type || undefined,
    family: family !== "all" ? family : undefined,
    limit: PAGE_SIZE,
    offset,
  });

  const { data: clusters = [] } = useIocClusters();
  const { data: iocAnalyses = [], isLoading: analysesLoading } = useIocAnalyses(expandedIocId);

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

  /** When a campaign card is clicked, show that cluster's IOCs directly. */
  const handleClusterClick = useCallback((cluster: IocCluster) => {
    setSelectedCluster(cluster);
    setExpandedIocId(null);
  }, []);

  const clearClusterFilter = useCallback(() => {
    setSelectedCluster(null);
  }, []);

  // When a cluster is selected, show its IOCs directly instead of the browse results
  const displayedIocs = selectedCluster
    ? selectedCluster.shared_iocs.map((ioc) => ({
        id: ioc.id,
        type: ioc.type,
        value: ioc.value,
        first_seen: "",
        last_seen: "",
        analysis_count: selectedCluster.analyses.length,
      }))
    : iocs;

  return (
    <div className="space-y-4" data-testid="iocs-content">
      <div className="flex items-center gap-2">
        <Network className="h-5 w-5 text-[var(--color-text-secondary)]" />
        <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">IOC Browser</h1>
      </div>

      {/* Campaign cards */}
      <CampaignCards clusters={clusters} onClusterClick={handleClusterClick} />

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <SearchInput
          value={q}
          onChange={(v) => setParam("q", v)}
          placeholder="Search IOC values..."
          className="w-80"
        />
        <select
          value={type}
          onChange={(e) => setParam("type", e.target.value)}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
        >
          <option value="">All types</option>
          {IOC_TYPES.map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <FamilyFilter value={family} onChange={setFamily} />

        {selectedCluster && (
          <button
            type="button"
            onClick={clearClusterFilter}
            className="inline-flex items-center gap-1 rounded-md border border-orange-700 bg-orange-900/30 px-2.5 py-1.5 text-xs font-medium text-orange-300 hover:bg-orange-900/50"
          >
            Campaign filter active
            <X className="h-3 w-3" />
          </button>
        )}
      </div>

      {/* Campaign sample list — shown when a cluster is selected */}
      {selectedCluster && (
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
          <h3 className="mb-2 text-sm font-medium text-[var(--color-text-secondary)]">
            Campaign Samples ({selectedCluster.analyses.length})
          </h3>
          <div className="space-y-1">
            {selectedCluster.analyses.map((a) => (
              <div key={a.analysis_id} className="flex items-center gap-2 text-sm">
                <Link
                  to={`/analyses/${a.analysis_id}`}
                  className="font-mono text-xs text-[var(--color-accent)] hover:underline"
                >
                  {a.sha256.slice(0, 16)}...
                </Link>
                {a.family && (
                  <span className="rounded border border-[var(--color-border)] bg-[var(--color-background)] px-1.5 py-0.5 text-xs text-[var(--color-text-secondary)]">
                    {a.family}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 10 }).map((_, i) => (
            <div key={i} className="h-10 animate-pulse rounded bg-[var(--color-surface)]" />
          ))}
        </div>
      ) : isError ? (
        <div className="rounded-md border border-red-800 bg-red-900/20 p-4 text-sm text-red-400">
          Failed to load IOCs.
        </div>
      ) : !displayedIocs || displayedIocs.length === 0 ? (
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-secondary)]">
          No IOCs found.
        </div>
      ) : (
        <div className="overflow-x-auto rounded-md border border-[var(--color-border)]">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)]">
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">Type</th>
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">Value</th>
                <th className="px-4 py-3 text-right font-medium text-[var(--color-text-secondary)]">Samples</th>
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">First Seen</th>
                <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {displayedIocs.map((ioc) => (
                <IocRow
                  key={ioc.id}
                  ioc={ioc}
                  isExpanded={expandedIocId === ioc.id}
                  onToggle={() =>
                    setExpandedIocId(expandedIocId === ioc.id ? null : ioc.id)
                  }
                  analyses={expandedIocId === ioc.id ? iocAnalyses : []}
                  analysesLoading={expandedIocId === ioc.id && analysesLoading}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Simple offset-based pagination */}
      {iocs && iocs.length >= PAGE_SIZE && (
        <div className="flex justify-center gap-2 text-sm">
          {offset > 0 && (
            <button
              onClick={() => setParam("offset", String(Math.max(0, offset - PAGE_SIZE)))}
              className="rounded border border-[var(--color-border)] px-3 py-1 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface)]"
            >
              Previous
            </button>
          )}
          <button
            onClick={() => setParam("offset", String(offset + PAGE_SIZE))}
            className="rounded border border-[var(--color-border)] px-3 py-1 text-[var(--color-text-secondary)] hover:bg-[var(--color-surface)]"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// IOC row with expandable analysis panel
// ---------------------------------------------------------------------------

interface IocRowProps {
  ioc: { id: number; type: string; value: string; first_seen: string | null; last_seen: string | null; analysis_count: number };
  isExpanded: boolean;
  onToggle: () => void;
  analyses: { analysis_id: number; sha256: string; family: string | null; submitted_at: string; source_stage?: string }[];
  analysesLoading: boolean;
}

function IocRow({ ioc, isExpanded, onToggle, analyses, analysesLoading }: IocRowProps) {
  return (
    <>
      <tr className="border-b border-[var(--color-border-light)] transition-colors hover:bg-[var(--color-surface-hover)]">
        <td className="px-4 py-2.5">
          <span className="rounded bg-[var(--color-surface)] px-1.5 py-0.5 text-xs text-[var(--color-text-muted)]">
            {ioc.type}
          </span>
        </td>
        <td className="max-w-md px-4 py-2.5">
          <button
            type="button"
            onClick={onToggle}
            className="cursor-pointer text-left hover:underline"
          >
            <MonoText className="break-all">{ioc.value}</MonoText>
          </button>
        </td>
        <td className="px-4 py-2.5 text-right">
          <span className={`tabular-nums ${ioc.analysis_count > 1 ? "font-medium text-[var(--color-accent)]" : "text-[var(--color-text-secondary)]"}`}>
            {ioc.analysis_count}
          </span>
        </td>
        <td className="px-4 py-2.5 text-xs text-[var(--color-text-muted)]">
          {ioc.first_seen ? formatRelativeTime(ioc.first_seen) : "\u2014"}
        </td>
        <td className="px-4 py-2.5 text-xs text-[var(--color-text-muted)]">
          {ioc.last_seen ? formatRelativeTime(ioc.last_seen) : "\u2014"}
        </td>
      </tr>
      {isExpanded && (
        <tr>
          <td colSpan={5}>
            <AnalysisListPanel analyses={analyses} isLoading={analysesLoading} />
          </td>
        </tr>
      )}
    </>
  );
}
