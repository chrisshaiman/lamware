// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { Link } from "react-router-dom";
import { Activity } from "lucide-react";
import { usePipelineStatus } from "#hooks/use-pipeline";
import { useWsStatus } from "#hooks/use-ws-context";
import { SeverityBadge } from "#components/shared/severity-badge";
import { MonoText } from "#components/shared/mono-text";
import { formatDuration, formatRelativeTime } from "#lib/utils";
import { PIPELINE_STAGES, STAGE_LABELS } from "#lib/constants";
import type { PipelineItem } from "#lib/types";

function PipelineCard({ item }: { item: PipelineItem }) {
  const isRunning = item.pipeline_status === "running" || item.pipeline_status === "pending";

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <div className="flex items-start justify-between">
        <div>
          <Link
            to={`/analyses/${item.id}`}
            className="text-sm font-medium text-[var(--color-accent)] hover:underline"
          >
            {item.sample.filename ?? <MonoText truncate={16}>{item.sample.sha256}</MonoText>}
          </Link>
          <div className="mt-0.5 flex items-center gap-2 text-xs text-[var(--color-text-muted)]">
            <MonoText truncate={12}>{item.sample.sha256}</MonoText>
            {item.sample.file_type && <span>{item.sample.file_type}</span>}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <SeverityBadge severity={item.severity} />
          {item.malware_family_guess && (
            <span className="text-xs text-[var(--color-text-secondary)]">{item.malware_family_guess}</span>
          )}
        </div>
      </div>

      {/* Stage progress */}
      <div className="mt-3 flex items-center gap-1">
        {PIPELINE_STAGES.map((stage) => {
          const timing = item.stage_timings[stage];
          const hasCompleted = timing != null;
          const isCurrent = item.current_stage === stage;
          return (
            <div key={stage} className="flex flex-1 flex-col items-center gap-1">
              <div
                className={`h-1.5 w-full rounded-full ${
                  hasCompleted
                    ? "bg-green-500"
                    : isCurrent
                      ? "bg-blue-500 animate-pulse"
                      : "bg-[var(--color-border)]"
                }`}
              />
              <span className="text-[9px] text-[var(--color-text-muted)]">
                {STAGE_LABELS[stage]}
              </span>
            </div>
          );
        })}
      </div>

      {/* Timing */}
      <div className="mt-2 flex items-center justify-between text-xs text-[var(--color-text-muted)]">
        <span>
          {isRunning ? "Running" : "Completed"}{" "}
          {item.started_at && formatRelativeTime(item.started_at)}
        </span>
        {item.stage_timings && (
          <span>
            {Object.values(item.stage_timings).reduce((a, b) => a + b, 0) > 0 &&
              formatDuration(Object.values(item.stage_timings).reduce((a, b) => a + b, 0))}
          </span>
        )}
      </div>
    </div>
  );
}

export function PipelinePage() {
  const { data, isLoading, isError } = usePipelineStatus();
  const { isConnected, isReconnecting } = useWsStatus();

  return (
    <div className="space-y-6" data-testid="pipeline-content">
      <div className="flex items-center gap-2">
        <Activity className="h-5 w-5 text-[var(--color-text-secondary)]" />
        <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">Pipeline Status</h1>
        {data && (
          <span className="text-xs text-[var(--color-text-muted)]">
            {data.running.length > 0
              ? `${data.running.length} running`
              : "idle"}
          </span>
        )}
        <span className="ml-auto flex items-center gap-1.5 text-xs">
          <span
            className={`inline-block h-2 w-2 rounded-full ${
              isConnected
                ? "bg-green-500"
                : isReconnecting
                  ? "bg-yellow-500 animate-pulse"
                  : "bg-gray-500"
            }`}
          />
          <span className="text-[var(--color-text-muted)]">
            {isConnected ? "Live" : isReconnecting ? "Reconnecting" : "Polling"}
          </span>
        </span>
      </div>

      {isLoading ? (
        <div className="space-y-3">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="h-28 animate-pulse rounded-md bg-[var(--color-surface)]" />
          ))}
        </div>
      ) : isError ? (
        <div className="rounded-md border border-red-800 bg-red-900/20 p-4 text-sm text-red-400">
          Failed to load pipeline status.
        </div>
      ) : !data ? null : (
        <>
          {/* Running */}
          {data.running.length > 0 && (
            <div className="space-y-3">
              <h2 className="text-sm font-medium text-[var(--color-text-secondary)]">Running</h2>
              {data.running.map((item) => (
                <PipelineCard key={item.id} item={item} />
              ))}
            </div>
          )}

          {/* Recently completed */}
          {data.recent_completed.length > 0 && (
            <div className="space-y-3">
              <h2 className="text-sm font-medium text-[var(--color-text-secondary)]">
                Recently Completed
              </h2>
              {data.recent_completed.map((item) => (
                <PipelineCard key={item.id} item={item} />
              ))}
            </div>
          )}

          {data.running.length === 0 && data.recent_completed.length === 0 && (
            <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-8 text-center text-sm text-[var(--color-text-secondary)]">
              No pipeline activity in the last 24 hours.
            </div>
          )}
        </>
      )}
    </div>
  );
}
