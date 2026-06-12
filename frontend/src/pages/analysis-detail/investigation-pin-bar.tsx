// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Strip of pinned findings between the conversation and the input. Confirmed
// pins render as solid chips colored by pin type, with an inline Promote
// button for unpromoted ioc/technique pins. Agent proposals render as dashed
// amber chips with accept/dismiss controls — nothing is saved without the
// analyst's explicit confirmation.

import { ArrowUp, Check, Loader2, Pin, X } from "lucide-react";
import { cn, truncate } from "#lib/utils";
import type { InvestigationPin, PinProposal } from "#lib/types";

interface InvestigationPinBarProps {
  pins: InvestigationPin[];
  proposals: PinProposal[];
  onConfirm: (p: PinProposal) => void;
  onDismiss: (p: PinProposal) => void;
  onPromote: (pinId: number) => void;
  /** Pin id currently being promoted (disables its button, shows spinner). */
  promotingPinId?: number | null;
}

const PIN_STYLES: Record<InvestigationPin["pin_type"], string> = {
  ioc: "border-blue-800 bg-blue-900/30 text-blue-400",
  technique: "border-purple-800 bg-purple-900/30 text-purple-400",
  note: "border-gray-700 bg-gray-800/30 text-gray-400",
};

export function InvestigationPinBar({
  pins,
  proposals,
  onConfirm,
  onDismiss,
  onPromote,
  promotingPinId,
}: InvestigationPinBarProps) {
  if (pins.length === 0 && proposals.length === 0) return null;

  return (
    <div className="flex flex-wrap items-center gap-1.5 border-b border-[var(--color-border)] px-3 py-2">
      {/* Confirmed pins */}
      {pins.map((pin) => (
        <span
          key={pin.id}
          title={pin.context ? `${pin.value}\n${pin.context}` : pin.value}
          className={cn(
            "flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[11px]",
            PIN_STYLES[pin.pin_type],
          )}
        >
          <Pin className="h-3 w-3 shrink-0" />
          <span>{truncate(pin.value, 40)}</span>
          {pin.promoted && (
            <span className="flex items-center gap-0.5 text-green-400">
              <Check className="h-3 w-3 shrink-0" />
              promoted
            </span>
          )}
          {!pin.promoted && pin.pin_type !== "note" && (
            <button
              onClick={() => onPromote(pin.id)}
              disabled={promotingPinId === pin.id}
              title="Promote to the analysis record"
              className="ml-0.5 flex items-center gap-0.5 rounded border border-current px-1 py-px text-[10px] font-sans font-medium transition-opacity hover:opacity-80 disabled:opacity-50"
            >
              {promotingPinId === pin.id ? (
                <Loader2 className="h-2.5 w-2.5 animate-spin" />
              ) : (
                <ArrowUp className="h-2.5 w-2.5" />
              )}
              Promote
            </button>
          )}
        </span>
      ))}

      {/* Pending proposals awaiting analyst confirmation */}
      {proposals.map((proposal, i) => (
        <span
          key={`${proposal.type}-${proposal.value}-${i}`}
          title={proposal.context || proposal.value}
          className="flex max-w-full items-center gap-1.5 rounded-full border border-dashed border-amber-700 bg-amber-900/20 px-2 py-0.5 text-[11px] text-amber-400"
        >
          <span className="rounded bg-amber-900/40 px-1 py-px text-[10px] font-medium uppercase">
            {proposal.type}
          </span>
          <span className="font-mono">{truncate(proposal.value, 40)}</span>
          {proposal.context && (
            <span className="min-w-0 truncate text-[10px] text-[var(--color-text-muted)]">
              {truncate(proposal.context, 60)}
            </span>
          )}
          <button
            onClick={() => onConfirm(proposal)}
            title="Accept pin"
            aria-label={`Accept pin: ${proposal.value}`}
            className="shrink-0 hover:text-green-400"
          >
            <Check className="h-3 w-3" />
          </button>
          <button
            onClick={() => onDismiss(proposal)}
            title="Dismiss proposal"
            aria-label={`Dismiss pin: ${proposal.value}`}
            className="shrink-0 hover:text-red-400"
          >
            <X className="h-3 w-3" />
          </button>
        </span>
      ))}
    </div>
  );
}
