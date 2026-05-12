// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { SourceBadge } from "#components/shared/source-badge";
import type { Capability } from "#lib/types";

export function CapabilitiesSection({ capabilities }: { capabilities: Capability[] }) {
  const [expanded, setExpanded] = useState(true);

  if (capabilities.length === 0) return null;

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between px-4 py-3 text-left"
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
            Capabilities
          </h3>
          <span className="text-xs text-[var(--color-text-muted)]">({capabilities.length})</span>
        </div>
      </button>

      {expanded && (
        <ul className="border-t border-[var(--color-border)] divide-y divide-[var(--color-border-light)]">
          {capabilities.map((cap) => (
            <li key={cap.id} className="flex items-start gap-3 px-4 py-2.5">
              <SourceBadge stage={cap.source_stage} className="mt-0.5 shrink-0" />
              <span className="text-xs text-[var(--color-text-secondary)]">{cap.description}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
