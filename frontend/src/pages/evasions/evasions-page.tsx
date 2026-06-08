// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import {
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  Monitor,
  Cpu,
  Settings2,
  MousePointerClick,
  Search,
} from "lucide-react";
import {
  useEvasions,
  type EvasionCategory,
  type EvasionTechnique,
  type MitigationStatus,
} from "#hooks/use-evasions";
import { MonoText } from "#components/shared/mono-text";

/** Metadata for each fix-type category. */
const CATEGORY_META: Record<
  EvasionCategory,
  { label: string; icon: typeof Monitor; description: string; color: string }
> = {
  guest_image: {
    label: "Guest Image (Packer)",
    icon: Monitor,
    description:
      "Fix in your Packer template — registry keys, filenames, hardware IDs, disk/memory sizes.",
    color: "text-blue-400",
  },
  qemu: {
    label: "QEMU / Hypervisor",
    icon: Cpu,
    description:
      "Fix via QEMU patches — CPUID leaves, ACPI tables, storage device names, virtual adapters.",
    color: "text-purple-400",
  },
  cape_config: {
    label: "CAPE Config",
    icon: Settings2,
    description:
      "Fix in CAPE configuration — analysis timeouts, sleep skipping, clock spoofing, network simulation.",
    color: "text-yellow-400",
  },
  automation: {
    label: "Automation",
    icon: MousePointerClick,
    description:
      "Fix via agentic automation — mouse movement, keyboard activity, process naming, parent spoofing.",
    color: "text-green-400",
  },
  detection: {
    label: "Detection Engineering",
    icon: Search,
    description:
      "Can't fix in sandbox — write YARA/Sigma rules, improve analysis coverage. Anti-debug, EDR unhooking, packing, geofencing.",
    color: "text-orange-400",
  },
};

const STATUS_META: Record<
  MitigationStatus,
  { label: string; className: string; description: string }
> = {
  mitigated: {
    label: "Mitigated",
    className: "bg-green-900/50 text-green-400",
    description: "Hardening deployed — this technique is defeated",
  },
  partial: {
    label: "Partial",
    className: "bg-yellow-900/50 text-yellow-400",
    description: "Partially addressed — residual risk remains",
  },
  open: {
    label: "Open",
    className: "bg-red-900/50 text-red-400",
    description: "Not yet addressed — could be fixed",
  },
  na: {
    label: "N/A",
    className: "bg-gray-800/50 text-gray-400",
    description: "Detection engineering — not fixable in sandbox",
  },
};

/** Display order for categories — actionable fixes first. */
const CATEGORY_ORDER: EvasionCategory[] = [
  "guest_image",
  "qemu",
  "cape_config",
  "automation",
  "detection",
];

function StatusBadge({ status }: { status: MitigationStatus }) {
  const meta = STATUS_META[status];
  return (
    <span
      className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${meta.className}`}
      title={meta.description}
    >
      {meta.label}
    </span>
  );
}

function CategorySection({
  category,
  techniques,
  maxCount,
  defaultOpen,
}: {
  category: EvasionCategory;
  techniques: EvasionTechnique[];
  maxCount: number;
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const meta = CATEGORY_META[category];
  const Icon = meta.icon;
  const totalSamples = techniques.reduce((sum, t) => sum + t.sample_count, 0);

  // Count statuses within this category
  const statusCounts = { mitigated: 0, partial: 0, open: 0, na: 0 };
  for (const t of techniques) {
    statusCounts[t.status]++;
  }

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
      <button
        onClick={() => setOpen(!open)}
        className="flex w-full items-center gap-3 p-4 text-left hover:bg-[var(--color-background)] transition-colors"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-[var(--color-text-muted)]" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-[var(--color-text-muted)]" />
        )}
        <Icon className={`h-4 w-4 shrink-0 ${meta.color}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold text-[var(--color-text-primary)]">
              {meta.label}
            </span>
            <span className="rounded bg-[var(--color-background)] px-1.5 py-0.5 text-[10px] font-medium tabular-nums text-[var(--color-text-muted)]">
              {techniques.length} technique{techniques.length !== 1 ? "s" : ""} · {totalSamples} hit{totalSamples !== 1 ? "s" : ""}
            </span>
            {/* Status summary chips */}
            {statusCounts.mitigated > 0 && (
              <span className="rounded bg-green-900/30 px-1.5 py-0.5 text-[10px] font-medium text-green-400">
                {statusCounts.mitigated} mitigated
              </span>
            )}
            {statusCounts.partial > 0 && (
              <span className="rounded bg-yellow-900/30 px-1.5 py-0.5 text-[10px] font-medium text-yellow-400">
                {statusCounts.partial} partial
              </span>
            )}
            {statusCounts.open > 0 && (
              <span className="rounded bg-red-900/30 px-1.5 py-0.5 text-[10px] font-medium text-red-400">
                {statusCounts.open} open
              </span>
            )}
          </div>
          <p className="text-[11px] text-[var(--color-text-muted)] mt-0.5">
            {meta.description}
          </p>
        </div>
      </button>

      {open && (
        <div className="border-t border-[var(--color-border)] p-4 space-y-3">
          {techniques.map((t, i) => (
            <div key={i} className="space-y-1">
              <div className="flex items-center justify-between text-xs gap-2">
                <div className="flex items-center gap-2 min-w-0 flex-1">
                  <StatusBadge status={t.status} />
                  <span className="text-[var(--color-text-secondary)] truncate">
                    {t.technique}
                  </span>
                  {t.mitre_id && (
                    <MonoText className="text-[10px] shrink-0">{t.mitre_id}</MonoText>
                  )}
                </div>
                <span className="tabular-nums text-[var(--color-text-muted)] shrink-0">
                  {t.sample_count} sample{t.sample_count !== 1 ? "s" : ""}
                </span>
              </div>
              <div className="h-3 rounded bg-[var(--color-background)]">
                <div
                  className={`h-3 rounded ${
                    category === "detection"
                      ? "bg-orange-500/40"
                      : category === "automation"
                        ? "bg-green-500/40"
                        : category === "cape_config"
                          ? "bg-yellow-500/40"
                          : category === "qemu"
                            ? "bg-purple-500/40"
                            : "bg-blue-500/40"
                  }`}
                  style={{
                    width: `${(t.sample_count / maxCount) * 100}%`,
                  }}
                />
              </div>
              {t.evidence && (
                <div className="text-[10px] text-[var(--color-text-muted)]">
                  Evidence: {t.evidence}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function EvasionsPage() {
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [categoryFilter, setCategoryFilter] = useState<string>("");
  const [sortBy, setSortBy] = useState<"sample_count" | "status" | "category">("sample_count");

  const { data, isLoading, isError } = useEvasions({
    status: (statusFilter || undefined) as MitigationStatus | undefined,
    category: (categoryFilter || undefined) as EvasionCategory | undefined,
    sort: sortBy,
  });

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="h-20 animate-pulse rounded-md bg-[var(--color-surface)]"
          />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="rounded-md border border-red-800 bg-red-900/20 p-4 text-sm text-red-400">
        Failed to load evasion data.
      </div>
    );
  }

  if (!data) return null;

  // Group techniques by category
  const grouped = new Map<EvasionCategory, EvasionTechnique[]>();
  for (const cat of CATEGORY_ORDER) {
    grouped.set(cat, []);
  }
  for (const t of data.techniques) {
    const list = grouped.get(t.category) ?? [];
    list.push(t);
    grouped.set(t.category, list);
  }

  const maxCount =
    data.techniques.length > 0
      ? Math.max(...data.techniques.map((t) => t.sample_count))
      : 1;

  const nonEmptyCategories = CATEGORY_ORDER.filter(
    (cat) => (grouped.get(cat) ?? []).length > 0,
  );

  // Overall status counts
  const allStatusCounts = { mitigated: 0, partial: 0, open: 0, na: 0 };
  for (const t of data.techniques) {
    allStatusCounts[t.status]++;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-2">
        <ShieldAlert className="h-5 w-5 text-[var(--color-text-secondary)]" />
        <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">
          Evasion Dashboard
        </h1>
        <span className="text-sm text-[var(--color-text-muted)]">
          ({data.total_analyses_with_evasion} analyses with evasion data)
        </span>
      </div>

      {data.techniques.length === 0 && !statusFilter && !categoryFilter ? (
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-secondary)]">
          No evasion techniques detected across your samples yet.
        </div>
      ) : (
        <>
          {/* Status summary + filter/sort controls */}
          <div className="flex flex-wrap items-center gap-3">
            {/* Status summary chips (clickable as filters) */}
            <button
              onClick={() => setStatusFilter(statusFilter === "open" ? "" : "open")}
              className={`flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs transition-colors ${
                statusFilter === "open"
                  ? "border-red-700 bg-red-900/30 text-red-400"
                  : "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]"
              }`}
            >
              <span className="h-2 w-2 rounded-full bg-red-500" />
              Open
              <span className="font-medium tabular-nums">{allStatusCounts.open}</span>
            </button>
            <button
              onClick={() => setStatusFilter(statusFilter === "partial" ? "" : "partial")}
              className={`flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs transition-colors ${
                statusFilter === "partial"
                  ? "border-yellow-700 bg-yellow-900/30 text-yellow-400"
                  : "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]"
              }`}
            >
              <span className="h-2 w-2 rounded-full bg-yellow-500" />
              Partial
              <span className="font-medium tabular-nums">{allStatusCounts.partial}</span>
            </button>
            <button
              onClick={() => setStatusFilter(statusFilter === "mitigated" ? "" : "mitigated")}
              className={`flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs transition-colors ${
                statusFilter === "mitigated"
                  ? "border-green-700 bg-green-900/30 text-green-400"
                  : "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]"
              }`}
            >
              <span className="h-2 w-2 rounded-full bg-green-500" />
              Mitigated
              <span className="font-medium tabular-nums">{allStatusCounts.mitigated}</span>
            </button>
            <button
              onClick={() => setStatusFilter(statusFilter === "na" ? "" : "na")}
              className={`flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-xs transition-colors ${
                statusFilter === "na"
                  ? "border-gray-600 bg-gray-800/30 text-gray-400"
                  : "border-[var(--color-border)] bg-[var(--color-surface)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)]"
              }`}
            >
              <span className="h-2 w-2 rounded-full bg-gray-500" />
              N/A
              <span className="font-medium tabular-nums">{allStatusCounts.na}</span>
            </button>

            <div className="ml-auto flex items-center gap-2">
              {/* Category filter */}
              <select
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
                className="rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-2 py-1.5 text-xs text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
              >
                <option value="">All categories</option>
                {CATEGORY_ORDER.map((cat) => (
                  <option key={cat} value={cat}>
                    {CATEGORY_META[cat].label}
                  </option>
                ))}
              </select>

              {/* Sort */}
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
                className="rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-2 py-1.5 text-xs text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
              >
                <option value="sample_count">Sort: Frequency</option>
                <option value="status">Sort: Status</option>
                <option value="category">Sort: Category</option>
              </select>
            </div>
          </div>

          {/* Grouped technique sections */}
          {nonEmptyCategories.length === 0 ? (
            <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-secondary)]">
              No techniques match the current filters.
            </div>
          ) : (
            nonEmptyCategories.map((cat, i) => (
              <CategorySection
                key={cat}
                category={cat}
                techniques={grouped.get(cat) ?? []}
                maxCount={maxCount}
                defaultOpen={i === 0}
              />
            ))
          )}

          {/* Recommendations */}
          {data.recommendations.length > 0 && (
            <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
              <h3 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">
                Sandbox Hardening Recommendations
              </h3>
              <div className="space-y-2">
                {data.recommendations.map((rec, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-3 rounded border border-[var(--color-border-light)] bg-[var(--color-background)] p-3"
                  >
                    <span className="shrink-0 rounded bg-orange-900/50 px-1.5 py-0.5 text-[10px] font-medium tabular-nums text-orange-400">
                      {rec.frequency}x
                    </span>
                    <span className="text-xs text-[var(--color-text-secondary)]">
                      {rec.recommendation}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
