// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { Signature } from "#lib/types";

const SEV_LABELS: Record<number, { label: string; color: string }> = {
  3: { label: "High", color: "text-orange-400" },
  2: { label: "Medium", color: "text-yellow-400" },
  1: { label: "Low", color: "text-blue-400" },
  0: { label: "Info", color: "text-gray-400" },
};

export function SignaturesSection({ signatures }: { signatures: Signature[] }) {
  const [expanded, setExpanded] = useState(true);

  if (signatures.length === 0) return null;

  const sorted = [...signatures].sort((a, b) => (b.severity ?? 0) - (a.severity ?? 0));

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between px-4 py-3 text-left"
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
            Signatures
          </h3>
          <span className="text-xs text-[var(--color-text-muted)]">({signatures.length})</span>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[var(--color-border)]">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-[var(--color-border-light)] bg-[var(--color-background)]">
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Severity</th>
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Name</th>
                <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Description</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((sig) => {
                const sev = SEV_LABELS[sig.severity ?? 0] ?? SEV_LABELS[0];
                return (
                  <tr key={sig.id} className="border-b border-[var(--color-border-light)]">
                    <td className={`px-4 py-2 font-medium ${sev.color}`}>{sev.label}</td>
                    <td className="px-4 py-2 text-[var(--color-text-secondary)]">{sig.name}</td>
                    <td className="max-w-md px-4 py-2 text-[var(--color-text-muted)]">
                      {sig.description ?? ""}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
