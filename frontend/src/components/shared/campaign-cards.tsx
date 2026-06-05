// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import type { IocCluster } from "#lib/types";

interface CampaignCardsProps {
  clusters: IocCluster[];
  onClusterClick: (cluster: IocCluster) => void;
}

/**
 * Row of cards representing detected clusters of analyses that share IOCs.
 * Each card summarizes the cluster's size, families, shared IOCs, and techniques.
 */
export function CampaignCards({ clusters, onClusterClick }: CampaignCardsProps) {
  if (clusters.length === 0) return null;

  return (
    <div className="space-y-3">
      <h2 className="text-sm font-semibold text-[var(--color-text-secondary)]">
        Detected Campaigns ({clusters.length})
      </h2>

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
        {clusters.map((cluster) => (
          <ClusterCard
            key={cluster.cluster_id}
            cluster={cluster}
            onClick={() => onClusterClick(cluster)}
          />
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Internal card component
// ---------------------------------------------------------------------------

function ClusterCard({
  cluster,
  onClick,
}: {
  cluster: IocCluster;
  onClick: () => void;
}) {
  // Count families across analyses in this cluster
  const familyCounts = new Map<string, number>();
  for (const a of cluster.analyses) {
    const fam = a.family ?? "unknown";
    familyCounts.set(fam, (familyCounts.get(fam) ?? 0) + 1);
  }

  const iocLimit = 3;
  const techLimit = 4;
  const extraIocs = Math.max(0, cluster.shared_iocs.length - iocLimit);
  const extraTechs = Math.max(0, cluster.shared_techniques.length - techLimit);

  return (
    <button
      type="button"
      onClick={onClick}
      className="cursor-pointer rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3 text-left transition-colors hover:border-[var(--color-accent)] hover:bg-[var(--color-surface-hover)]"
    >
      {/* Header: sample count */}
      <p className="text-sm font-medium text-[var(--color-text-primary)]">
        {cluster.analyses.length} sample{cluster.analyses.length !== 1 ? "s" : ""}
      </p>

      {/* Family badges */}
      <div className="mt-1.5 flex flex-wrap gap-1">
        {[...familyCounts.entries()].map(([fam, count]) => (
          <span
            key={fam}
            className="rounded border border-[var(--color-border)] bg-[var(--color-background)] px-1.5 py-0.5 text-xs text-[var(--color-text-secondary)]"
          >
            {fam} ({count})
          </span>
        ))}
      </div>

      {/* Shared IOCs (truncated) */}
      {cluster.shared_iocs.length > 0 && (
        <div className="mt-2 space-y-0.5">
          {cluster.shared_iocs.slice(0, iocLimit).map((ioc) => (
            <p
              key={ioc.id}
              className="truncate font-mono text-xs text-[var(--color-text-muted)]"
              title={ioc.value}
            >
              {ioc.value}
            </p>
          ))}
          {extraIocs > 0 && (
            <p className="text-xs text-[var(--color-text-muted)]">
              +{extraIocs} more
            </p>
          )}
        </div>
      )}

      {/* Shared techniques (truncated) */}
      {cluster.shared_techniques.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {cluster.shared_techniques.slice(0, techLimit).map((t) => (
            <span
              key={t.id}
              className="rounded bg-blue-900/40 px-1.5 py-0.5 text-xs text-blue-300"
              title={t.technique_name}
            >
              {t.technique_id}
            </span>
          ))}
          {extraTechs > 0 && (
            <span className="px-1 text-xs text-[var(--color-text-muted)]">
              +{extraTechs} more
            </span>
          )}
        </div>
      )}
    </button>
  );
}
