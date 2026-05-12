// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { ShieldAlert } from "lucide-react";
import { useEvasions } from "#hooks/use-evasions";
import { MonoText } from "#components/shared/mono-text";

export function EvasionsPage() {
  const { data, isLoading, isError } = useEvasions();

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-20 animate-pulse rounded-md bg-[var(--color-surface)]" />
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

  const maxCount = data.techniques.length > 0 ? data.techniques[0].sample_count : 1;

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

      {data.techniques.length === 0 ? (
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-secondary)]">
          No evasion techniques detected across your samples yet.
        </div>
      ) : (
        <>
          {/* Frequency chart — horizontal bars */}
          <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
            <h3 className="mb-4 text-sm font-semibold text-[var(--color-text-primary)]">
              Most Common Evasion Techniques
            </h3>
            <div className="space-y-3">
              {data.techniques.map((t, i) => (
                <div key={i} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <span className="text-[var(--color-text-secondary)]">{t.technique}</span>
                      {t.mitre_id && <MonoText className="text-[10px]">{t.mitre_id}</MonoText>}
                    </div>
                    <span className="tabular-nums text-[var(--color-text-muted)]">
                      {t.sample_count} sample{t.sample_count !== 1 ? "s" : ""}
                    </span>
                  </div>
                  <div className="h-3 rounded bg-[var(--color-background)]">
                    <div
                      className="h-3 rounded bg-orange-500/40"
                      style={{ width: `${(t.sample_count / maxCount) * 100}%` }}
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
          </div>

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
