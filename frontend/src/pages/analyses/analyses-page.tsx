// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useCallback } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { FileSearch, ChevronLeft, ChevronRight } from "lucide-react";
import { useAnalysesList } from "#hooks/use-analyses";
import { SearchInput } from "#components/shared/search-input";
import { SeverityBadge } from "#components/shared/severity-badge";
import { MonoText } from "#components/shared/mono-text";
import { formatBytes, formatRelativeTime } from "#lib/utils";

const PAGE_SIZE = 25;

export function AnalysesPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const q = searchParams.get("q") ?? "";
  const severity = searchParams.get("severity") ?? "";
  const family = searchParams.get("family") ?? "";
  const page = parseInt(searchParams.get("page") ?? "1", 10);
  const offset = (page - 1) * PAGE_SIZE;

  const { data, isLoading, isError } = useAnalysesList({
    q: q || undefined,
    severity: severity || undefined,
    family: family || undefined,
    limit: PAGE_SIZE,
    offset,
  });

  const setParam = useCallback(
    (key: string, value: string) => {
      setSearchParams((prev) => {
        const next = new URLSearchParams(prev);
        if (value) {
          next.set(key, value);
        } else {
          next.delete(key);
        }
        // Reset to page 1 on filter change
        if (key !== "page") next.delete("page");
        return next;
      });
    },
    [setSearchParams],
  );

  const totalPages = data ? Math.ceil(data.total / PAGE_SIZE) : 0;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileSearch className="h-5 w-5 text-[var(--color-text-secondary)]" />
          <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">
            Analyses
          </h1>
          {data && (
            <span className="text-sm text-[var(--color-text-muted)]">
              ({data.total})
            </span>
          )}
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <SearchInput
          value={q}
          onChange={(v) => setParam("q", v)}
          placeholder="Search SHA256, filename, or family..."
          className="w-80"
        />
        <select
          value={severity}
          onChange={(e) => setParam("severity", e.target.value)}
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <input
          type="text"
          value={family}
          onChange={(e) => setParam("family", e.target.value)}
          placeholder="Family filter..."
          className="rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] outline-none focus:border-[var(--color-accent)]"
        />
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="space-y-2">
          {Array.from({ length: 10 }).map((_, i) => (
            <div
              key={i}
              className="h-12 animate-pulse rounded bg-[var(--color-surface)]"
            />
          ))}
        </div>
      ) : isError ? (
        <div className="rounded-md border border-red-800 bg-red-900/20 p-4 text-sm text-red-400">
          Failed to load analyses. Is the API running?
        </div>
      ) : !data || data.analyses.length === 0 ? (
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-secondary)]">
          No analyses found.
        </div>
      ) : (
        <>
          <div className="overflow-x-auto rounded-md border border-[var(--color-border)]">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--color-border)] bg-[var(--color-surface)]">
                  <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">
                    Sample
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">
                    Severity
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">
                    Family
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">
                    Status
                  </th>
                  <th className="px-4 py-3 text-right font-medium text-[var(--color-text-secondary)]">
                    IOCs
                  </th>
                  <th className="px-4 py-3 text-right font-medium text-[var(--color-text-secondary)]">
                    Techniques
                  </th>
                  <th className="px-4 py-3 text-right font-medium text-[var(--color-text-secondary)]">
                    Sigs
                  </th>
                  <th className="px-4 py-3 text-left font-medium text-[var(--color-text-secondary)]">
                    When
                  </th>
                </tr>
              </thead>
              <tbody>
                {data.analyses.map((a) => (
                  <tr
                    key={a.id}
                    className="border-b border-[var(--color-border-light)] transition-colors hover:bg-[var(--color-surface-hover)]"
                  >
                    <td className="px-4 py-3">
                      <Link
                        to={`/analyses/${a.id}`}
                        className="block text-[var(--color-accent)] hover:underline"
                      >
                        {a.sample.filename ?? (
                          <MonoText truncate={16}>{a.sample.sha256}</MonoText>
                        )}
                      </Link>
                      <div className="mt-0.5 flex items-center gap-2">
                        <MonoText truncate={16}>{a.sample.sha256}</MonoText>
                        {a.sample.file_size && (
                          <span className="text-xs text-[var(--color-text-muted)]">
                            {formatBytes(a.sample.file_size)}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={a.severity} />
                    </td>
                    <td className="px-4 py-3 text-[var(--color-text-secondary)]">
                      {a.malware_family_guess ?? "\u2014"}
                    </td>
                    <td className="px-4 py-3">
                      <StatusPill status={a.pipeline_status} />
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-[var(--color-text-secondary)]">
                      {a.ioc_count}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-[var(--color-text-secondary)]">
                      {a.technique_count}
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-[var(--color-text-secondary)]">
                      {a.signature_count}
                    </td>
                    <td className="px-4 py-3 text-xs text-[var(--color-text-muted)]">
                      {a.started_at ? formatRelativeTime(a.started_at) : "\u2014"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between text-sm text-[var(--color-text-secondary)]">
              <span>
                Showing {offset + 1}\u2013{Math.min(offset + PAGE_SIZE, data.total)} of{" "}
                {data.total}
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setParam("page", String(page - 1))}
                  disabled={page <= 1}
                  className="rounded p-1 hover:bg-[var(--color-surface-hover)] disabled:opacity-30"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <span className="px-2">
                  Page {page} of {totalPages}
                </span>
                <button
                  onClick={() => setParam("page", String(page + 1))}
                  disabled={page >= totalPages}
                  className="rounded p-1 hover:bg-[var(--color-surface-hover)] disabled:opacity-30"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function StatusPill({ status }: { status: string | null }) {
  if (!status) return <span className="text-[var(--color-text-muted)]">\u2014</span>;

  const colors: Record<string, string> = {
    completed: "bg-green-900/50 text-green-400",
    running: "bg-blue-900/50 text-blue-400",
    pending: "bg-yellow-900/50 text-yellow-400",
    failed: "bg-red-900/50 text-red-400",
  };

  return (
    <span
      className={`rounded px-1.5 py-0.5 text-xs font-medium ${colors[status] ?? "bg-gray-800 text-gray-400"}`}
    >
      {status}
    </span>
  );
}
