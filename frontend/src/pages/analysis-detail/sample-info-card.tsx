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
    <div className="space-y-0.5">
      <div className="flex items-center justify-between">
        <span className="text-xs text-[var(--color-text-muted)]">{label}</span>
        <button
          onClick={handleCopy}
          className="rounded p-0.5 text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]"
          title={`Copy ${label}`}
        >
          {copied ? <Check className="h-3 w-3 text-green-400" /> : <Copy className="h-3 w-3" />}
        </button>
      </div>
      <MonoText className="block break-all">{value}</MonoText>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-0.5">
      <span className="text-xs text-[var(--color-text-muted)]">{label}</span>
      <div className="break-all text-xs text-[var(--color-text-secondary)]">{value}</div>
    </div>
  );
}

export function SampleInfoCard({ analysis }: { analysis: AnalysisDetail }) {
  const s = analysis.sample;
  if (!s) return null;

  return (
    <div className="min-w-0 space-y-2 overflow-hidden rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-4">
      <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
        Sample Info
      </h3>
      <div className="space-y-2">
        <CopyableHash label="SHA-256" value={s.sha256} />
        <CopyableHash label="MD5" value={s.md5} />
        <CopyableHash label="SHA-1" value={s.sha1} />
        <CopyableHash label="ssdeep" value={s.ssdeep} />
        {s.filename && <InfoRow label="Filename" value={s.filename} />}
        {s.file_type && <InfoRow label="Type" value={s.file_type} />}
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
