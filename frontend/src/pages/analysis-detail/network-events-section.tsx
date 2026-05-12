// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { MonoText } from "#components/shared/mono-text";
import { cn } from "#lib/utils";
import type { NetworkEvent } from "#lib/types";

const EVENT_TABS = ["dns", "http", "tcp", "udp", "smtp"] as const;

export function NetworkEventsSection({ events }: { events: NetworkEvent[] }) {
  const [expanded, setExpanded] = useState(true);
  const [activeTab, setActiveTab] = useState<string>("dns");

  if (events.length === 0) return null;

  // Group by event_type
  const grouped = events.reduce<Record<string, NetworkEvent[]>>((acc, ev) => {
    const key = ev.event_type || "other";
    if (!acc[key]) acc[key] = [];
    acc[key].push(ev);
    return acc;
  }, {});

  const availableTabs = EVENT_TABS.filter((tab) => grouped[tab]?.length);
  const currentEvents = grouped[activeTab] ?? [];

  return (
    <div className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)]">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between px-4 py-3 text-left"
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          <h3 className="text-sm font-semibold text-[var(--color-text-primary)]">
            Network Events
          </h3>
          <span className="text-xs text-[var(--color-text-muted)]">({events.length})</span>
        </div>
      </button>

      {expanded && (
        <>
          {/* Type tabs */}
          <div className="flex border-y border-[var(--color-border)]">
            {availableTabs.map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={cn(
                  "px-4 py-2 text-xs font-medium uppercase transition-colors",
                  activeTab === tab
                    ? "border-b-2 border-[var(--color-accent)] text-[var(--color-text-primary)]"
                    : "text-[var(--color-text-muted)] hover:text-[var(--color-text-secondary)]",
                )}
              >
                {tab} ({grouped[tab]?.length ?? 0})
              </button>
            ))}
          </div>

          {/* Event table */}
          <div className="overflow-x-auto">
            {activeTab === "dns" && <DnsTable events={currentEvents} />}
            {activeTab === "http" && <HttpTable events={currentEvents} />}
            {(activeTab === "tcp" || activeTab === "udp") && (
              <ConnectionTable events={currentEvents} />
            )}
            {activeTab === "smtp" && <ConnectionTable events={currentEvents} />}
          </div>
        </>
      )}
    </div>
  );
}

function DnsTable({ events }: { events: NetworkEvent[] }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="border-b border-[var(--color-border-light)] bg-[var(--color-background)]">
          <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Query</th>
          <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Type</th>
          <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Answers</th>
        </tr>
      </thead>
      <tbody>
        {events.map((ev) => (
          <tr key={ev.id} className="border-b border-[var(--color-border-light)]">
            <td className="px-4 py-2"><MonoText>{ev.dns_query ?? ""}</MonoText></td>
            <td className="px-4 py-2 text-[var(--color-text-muted)]">{ev.dns_type ?? ""}</td>
            <td className="px-4 py-2 text-[var(--color-text-muted)]">
              {ev.dns_answers?.map((a: unknown, i: number) => {
                const answer = a as Record<string, unknown>;
                return <span key={i}>{i > 0 && ", "}{String(answer.value ?? answer.data ?? "")}</span>;
              })}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function HttpTable({ events }: { events: NetworkEvent[] }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="border-b border-[var(--color-border-light)] bg-[var(--color-background)]">
          <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Method</th>
          <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">URL</th>
          <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Host</th>
          <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Status</th>
        </tr>
      </thead>
      <tbody>
        {events.map((ev) => (
          <tr key={ev.id} className="border-b border-[var(--color-border-light)]">
            <td className="px-4 py-2 font-medium text-[var(--color-text-secondary)]">{ev.http_method ?? ""}</td>
            <td className="max-w-md px-4 py-2"><MonoText className="break-all">{ev.http_url ?? ""}</MonoText></td>
            <td className="px-4 py-2 text-[var(--color-text-muted)]">{ev.http_host ?? ""}</td>
            <td className="px-4 py-2 text-[var(--color-text-muted)]">{ev.http_status ?? ""}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ConnectionTable({ events }: { events: NetworkEvent[] }) {
  return (
    <table className="w-full text-xs">
      <thead>
        <tr className="border-b border-[var(--color-border-light)] bg-[var(--color-background)]">
          <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Source</th>
          <th className="px-4 py-2 text-left font-medium text-[var(--color-text-muted)]">Destination</th>
        </tr>
      </thead>
      <tbody>
        {events.map((ev) => (
          <tr key={ev.id} className="border-b border-[var(--color-border-light)]">
            <td className="px-4 py-2">
              <MonoText>{ev.src_ip ?? ""}:{ev.src_port ?? ""}</MonoText>
            </td>
            <td className="px-4 py-2">
              <MonoText>{ev.dst_ip ?? ""}:{ev.dst_port ?? ""}</MonoText>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
