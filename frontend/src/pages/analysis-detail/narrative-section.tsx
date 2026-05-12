// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { MarkdownProse } from "#components/shared/markdown-prose";
import { cn } from "#lib/utils";
import type { AnalysisDetail } from "#lib/types";

const TABS = [
  { key: "executive_summary", label: "Executive Summary" },
  { key: "plain_english_summary", label: "Plain English" },
  { key: "narrative", label: "AI RE Narrative" },
  { key: "working_notes", label: "Working Notes" },
] as const;

type TabKey = (typeof TABS)[number]["key"];

export function NarrativeSection({ analysis }: { analysis: AnalysisDetail }) {
  const [activeTab, setActiveTab] = useState<TabKey>("executive_summary");
  const content = analysis[activeTab];

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
      {/* Tab bar */}
      <div className="flex border-b border-[var(--color-border)]">
        {TABS.map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={cn(
              "px-4 py-2.5 text-xs font-medium transition-colors",
              activeTab === key
                ? "border-b-2 border-[var(--color-accent)] text-[var(--color-text-primary)]"
                : "text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]",
            )}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="p-4">
        {content ? (
          <MarkdownProse>{content}</MarkdownProse>
        ) : (
          <p className="text-sm text-[var(--color-text-muted)]">
            Not available for this analysis.
          </p>
        )}
      </div>

      {/* AI RE metadata (only on narrative tab) */}
      {activeTab === "narrative" && analysis.interpret_model && (
        <div className="border-t border-[var(--color-border)] px-4 py-2.5 text-xs text-[var(--color-text-muted)]">
          Model: {analysis.interpret_model}
          {analysis.interpret_tool_calls != null && ` | ${analysis.interpret_tool_calls} tool calls`}
          {analysis.interpret_duration_secs != null && ` | ${analysis.interpret_duration_secs.toFixed(0)}s`}
          {analysis.interpret_escalated && " | Escalated"}
          {analysis.possible_prompt_influence && (
            <span className="ml-2 text-yellow-400">Possible prompt influence</span>
          )}
        </div>
      )}
    </div>
  );
}
