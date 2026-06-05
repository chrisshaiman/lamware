// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useParams, useNavigate, Link } from "react-router-dom";
import { ArrowLeft, Trash2 } from "lucide-react";
import { useAnalysisDetail, useDeleteAnalysis } from "#hooks/use-analyses";
import { SeverityBadge } from "#components/shared/severity-badge";
import { formatTimestamp, formatCost, formatDuration } from "#lib/utils";
import { PIPELINE_STAGES, STAGE_LABELS } from "#lib/constants";
import { SampleInfoCard } from "./sample-info-card";
import { RequireRole } from "#components/require-role";
import { NarrativeSection } from "./narrative-section";
import { IocsSection } from "./iocs-section";
import { TechniquesSection } from "./techniques-section";
import { SignaturesSection } from "./signatures-section";
import { CapabilitiesSection } from "./capabilities-section";
import { NetworkEventsSection } from "./network-events-section";
import { RelatedAnalyses } from "./related-analyses";
import { StageTimingsCard } from "./stage-timings-card";
import { DownloadBar } from "./download-bar";

export function AnalysisDetailPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const analysisId = id ? parseInt(id, 10) : undefined;
  const { data: analysis, isLoading, isError } = useAnalysisDetail(analysisId);
  const deleteMutation = useDeleteAnalysis();

  if (isLoading) {
    return (
      <div className="space-y-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="h-24 animate-pulse rounded-md bg-[var(--color-surface)]" />
        ))}
      </div>
    );
  }

  if (isError || !analysis) {
    return (
      <div className="rounded-md border border-red-800 bg-red-900/20 p-4 text-sm text-red-400">
        Failed to load analysis detail.
      </div>
    );
  }

  const handleDelete = async () => {
    if (!confirm(`Delete analysis ${analysis.task_id}? This cannot be undone.`)) return;
    await deleteMutation.mutateAsync(analysis.id);
    navigate("/analyses");
  };

  // Stage completion for the progress bar
  const stageFlags: Record<string, boolean | null> = {
    triage: analysis.triage_completed,
    cape: analysis.cape_completed,
    volatility: analysis.volatility_completed,
    ghidra: analysis.ghidra_completed,
    interpret: analysis.interpret_completed,
    summary: analysis.summary_completed,
    pdf: analysis.pdf_generated,
  };

  // Total duration
  const totalDuration =
    analysis.started_at && analysis.completed_at
      ? (new Date(analysis.completed_at).getTime() - new Date(analysis.started_at).getTime()) / 1000
      : null;

  return (
    <div className="space-y-5">
      {/* Back link */}
      <Link
        to="/analyses"
        className="inline-flex items-center gap-1 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"
      >
        <ArrowLeft className="h-3.5 w-3.5" />
        Back to analyses
      </Link>

      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-xl font-semibold text-[var(--color-text-primary)]">
              {analysis.sample?.filename ?? analysis.task_id}
            </h1>
            <SeverityBadge severity={analysis.severity} />
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-3 text-xs text-[var(--color-text-muted)]">
            {analysis.malware_family_guess && (
              <span className="font-medium text-[var(--color-text-secondary)]">
                {analysis.malware_family_guess}
              </span>
            )}
            {analysis.malscore != null && <span>Score: {analysis.malscore}</span>}
            {analysis.started_at && <span>{formatTimestamp(analysis.started_at)}</span>}
            {totalDuration != null && <span>{formatDuration(totalDuration)}</span>}
            {analysis.llm_cost_usd != null && <span>{formatCost(analysis.llm_cost_usd)}</span>}
          </div>
        </div>
        <RequireRole role="admin">
          <button
            onClick={handleDelete}
            disabled={deleteMutation.isPending}
            className="flex items-center gap-1.5 rounded-md border border-red-800 bg-red-900/20 px-3 py-1.5 text-xs font-medium text-red-400 transition-colors hover:bg-red-900/40 disabled:opacity-50"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Delete
          </button>
        </RequireRole>
      </div>

      {/* Stage progress bar */}
      <div className="flex items-center gap-1">
        {PIPELINE_STAGES.map((stage) => {
          const completed = stageFlags[stage];
          const isCurrent = analysis.current_stage === stage;
          return (
            <div
              key={stage}
              className="flex flex-1 flex-col items-center gap-1"
              title={`${STAGE_LABELS[stage]}: ${completed ? "completed" : isCurrent ? "running" : "pending"}`}
            >
              <div
                className={`h-1.5 w-full rounded-full ${
                  completed
                    ? "bg-green-500"
                    : isCurrent
                      ? "bg-blue-500 animate-pulse"
                      : "bg-[var(--color-border)]"
                }`}
              />
              <span className="text-[10px] text-[var(--color-text-muted)]">
                {STAGE_LABELS[stage]}
              </span>
            </div>
          );
        })}
      </div>

      {/* Downloads */}
      <DownloadBar
        analysisId={analysis.id}
        taskId={analysis.task_id}
        pdfGenerated={analysis.pdf_generated}
      />

      {/* Two-column layout: sample info + timings | narratives */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="space-y-5">
          <SampleInfoCard analysis={analysis} />
          <StageTimingsCard timings={analysis.stage_timings} />
        </div>
        <div className="lg:col-span-2">
          <NarrativeSection analysis={analysis} />
        </div>
      </div>

      {/* Data sections */}
      <IocsSection iocs={analysis.iocs} />
      <TechniquesSection techniques={analysis.techniques} />
      <RelatedAnalyses
        overlappingIocs={analysis.overlapping_iocs ?? []}
        overlappingTechniques={analysis.overlapping_techniques ?? []}
      />
      <SignaturesSection signatures={analysis.signatures} />
      <CapabilitiesSection capabilities={analysis.capabilities} />
      <NetworkEventsSection events={analysis.network_events} />
    </div>
  );
}
