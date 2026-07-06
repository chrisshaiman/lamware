// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { AlertTriangle, Pause, Play, RotateCcw } from "lucide-react";
import { useAlerts } from "#hooks/use-alerts";
import { useFeederStatus, useFeederPause, useFeederResume, useFeederReset } from "#hooks/use-feeder";
import { formatCost } from "#lib/utils";
import { RequireRole } from "#components/require-role";

export function AlertsPage() {
  const { data: alerts, isLoading: alertsLoading } = useAlerts();
  const { data: feeder, isFetching: feederFetching } = useFeederStatus();
  const pauseMutation = useFeederPause();
  const resumeMutation = useFeederResume();
  const resetMutation = useFeederReset();

  if (alertsLoading) {
    return (
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-32 animate-pulse rounded-md bg-[var(--color-surface)]" />
        ))}
      </div>
    );
  }

  const handlePause = () => {
    if (confirm("Pause the auto-feeder?")) pauseMutation.mutate();
  };
  // Resume is confirmed too (symmetric with Pause/Reset). Without it, a stray
  // click landing on the in-place Pause->Resume toggle — right as the status
  // refetch swaps the button — could silently undo a deliberate pause.
  const handleResume = () => {
    if (confirm("Resume the auto-feeder?")) resumeMutation.mutate();
  };
  const handleReset = () => {
    if (confirm("Reset the failure counter?")) resetMutation.mutate();
  };

  return (
    <div className="space-y-6" data-testid="alerts-content">
      <div className="flex items-center gap-2">
        <AlertTriangle className="h-5 w-5 text-[var(--color-text-secondary)]" />
        <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">
          Operational Health
        </h1>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {/* Network Monitor */}
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <h3 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">
            Network Monitor
          </h3>
          {alerts?.network_monitor ? (
            <div className="space-y-2 text-xs">
              {Object.entries(alerts.network_monitor)
                .filter(([, val]) => typeof val !== "object" || val === null)
                .map(([key, val]) => (
                <div key={key} className="flex justify-between">
                  <span className="text-[var(--color-text-muted)]">{key}</span>
                  <span className={`text-[var(--color-text-secondary)] ${val === "alert" ? "font-bold text-red-400" : ""}`}>
                    {String(val ?? "\u2014")}
                  </span>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-xs text-[var(--color-text-muted)]">No data available</p>
          )}
        </div>

        {/* Disk Usage */}
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <h3 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">
            Disk Usage
          </h3>
          {alerts?.disk ? (
            <div className="space-y-2">
              <div className="h-4 rounded-full bg-[var(--color-background)]">
                <div
                  className={`h-4 rounded-full ${alerts.disk.used_pct > 80 ? "bg-red-500" : alerts.disk.used_pct > 60 ? "bg-yellow-500" : "bg-green-500"}`}
                  style={{ width: `${alerts.disk.used_pct}%` }}
                />
              </div>
              <div className="flex justify-between text-xs text-[var(--color-text-muted)]">
                <span>{alerts.disk.used_gb.toFixed(1)} GB used</span>
                <span>{alerts.disk.free_gb.toFixed(1)} GB free</span>
                <span>{alerts.disk.used_pct.toFixed(1)}%</span>
              </div>
            </div>
          ) : (
            <p className="text-xs text-[var(--color-text-muted)]">No data available</p>
          )}
        </div>

        {/* Auto-feeder Controls */}
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <h3 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">
            Auto-feeder
          </h3>
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <div
                className={`h-2.5 w-2.5 rounded-full ${
                  feeder?.paused ? "bg-yellow-500" : feeder?.status === "running" ? "bg-green-500" : "bg-gray-500"
                }`}
              />
              <span className="text-sm text-[var(--color-text-secondary)]">
                {feeder?.paused ? "Paused" : feeder?.status ?? "Unknown"}
              </span>
            </div>
            {feeder?.state && (
              <div className="space-y-1 text-xs text-[var(--color-text-muted)]">
                {Object.entries(feeder.state).map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span>{k}</span>
                    <span className="text-[var(--color-text-secondary)]">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}
            <RequireRole role="analyst">
              <div className="flex gap-2">
                {feeder?.paused ? (
                  <button
                    onClick={handleResume}
                    disabled={resumeMutation.isPending || feederFetching}
                    className="flex items-center gap-1 rounded border border-green-800 bg-green-900/20 px-3 py-1.5 text-xs text-green-400 hover:bg-green-900/40 disabled:opacity-50"
                  >
                    <Play className="h-3 w-3" /> Resume
                  </button>
                ) : (
                  <button
                    onClick={handlePause}
                    disabled={pauseMutation.isPending || feederFetching}
                    className="flex items-center gap-1 rounded border border-yellow-800 bg-yellow-900/20 px-3 py-1.5 text-xs text-yellow-400 hover:bg-yellow-900/40 disabled:opacity-50"
                  >
                    <Pause className="h-3 w-3" /> Pause
                  </button>
                )}
                <button
                  onClick={handleReset}
                  disabled={resetMutation.isPending || feederFetching}
                  className="flex items-center gap-1 rounded border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-1.5 text-xs text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] disabled:opacity-50"
                >
                  <RotateCcw className="h-3 w-3" /> Reset Failures
                </button>
              </div>
            </RequireRole>
          </div>
        </div>

        {/* Cost */}
        <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
          <h3 className="mb-3 text-sm font-semibold text-[var(--color-text-primary)]">
            LLM Cost
          </h3>
          {alerts?.cost_today_usd != null ? (
            <div className="text-2xl font-bold tabular-nums text-[var(--color-text-primary)]">
              {formatCost(alerts.cost_today_usd)}
              <span className="ml-1 text-sm font-normal text-[var(--color-text-muted)]">today</span>
            </div>
          ) : (
            <p className="text-xs text-[var(--color-text-muted)]">No cost data</p>
          )}
        </div>
      </div>
    </div>
  );
}
