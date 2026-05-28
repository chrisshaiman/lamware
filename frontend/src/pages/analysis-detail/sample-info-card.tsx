// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { Copy, Check } from "lucide-react";
import { useState } from "react";
import { MonoText } from "#components/shared/mono-text";
import { formatBytes } from "#lib/utils";
import type { AnalysisDetail } from "#lib/types";

function CopyableHash({ label, value }: { label: string; value: string | null }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;

  const handleCopy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div className="flex items-start justify-between gap-2">
      <span className="shrink-0 text-xs text-[var(--color-text-muted)]">{label}</span>
      <div className="flex items-start gap-1.5 min-w-0">
        <MonoText className="break-all">{value}</MonoText>
        <button
          onClick={handleCopy}
          className="rounded p-0.5 text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"
          title={`Copy ${label}`}
        >
          {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
        </button>
      </div>
    </div>
  );
}

export function SampleInfoCard({ analysis }: { analysis: AnalysisDetail }) {
  const s = analysis.sample;
  if (!s) return null;

  return (
    <div className="space-y-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
        Sample Info
      </h3>
      <div className="space-y-1.5">
        <CopyableHash label="SHA-256" value={s.sha256} />
        <CopyableHash label="MD5" value={s.md5} />
        <CopyableHash label="SHA-1" value={s.sha1} />
        <CopyableHash label="ssdeep" value={s.ssdeep} />
        {s.filename && (
          <div className="flex items-start justify-between gap-2">
            <span className="shrink-0 text-xs text-[var(--color-text-muted)]">Filename</span>
            <span className="break-all text-right text-xs text-[var(--color-text-secondary)]">{s.filename}</span>
          </div>
        )}
        {s.file_type && (
          <div className="flex items-start justify-between gap-2">
            <span className="shrink-0 text-xs text-[var(--color-text-muted)]">Type</span>
            <span className="break-all text-right text-xs text-[var(--color-text-secondary)]">{s.file_type}</span>
          </div>
        )}
        {s.file_size != null && (
          <div className="flex items-center justify-between">
            <span className="text-xs text-[var(--color-text-muted)]">Size</span>
            <span className="text-xs text-[var(--color-text-secondary)]">{formatBytes(s.file_size)}</span>
          </div>
        )}
        {s.entropy != null && (
          <div className="flex items-center justify-between">
            <span className="text-xs text-[var(--color-text-muted)]">Entropy</span>
            <span className="text-xs text-[var(--color-text-secondary)]">{s.entropy.toFixed(3)}</span>
          </div>
        )}
      </div>
    </div>
  );
}
