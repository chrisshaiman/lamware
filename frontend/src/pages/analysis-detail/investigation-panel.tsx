// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Investigation agent chat panel — the single entry point the analysis detail
// page mounts as a slide-out column. Orchestrates session bootstrap, message
// history rendering, live SSE streaming state, pin confirmation/promotion,
// model switching, cost display, and report export.
//
// Message state model: persisted history comes from the session detail query
// (tool_call/tool_result rows are paired into single tool renders); the
// in-flight exchange lives in a local liveEntries array (interleaved
// assistant text chunks and tool calls, in arrival order) rendered below the
// history until the "done" event triggers a refetch, after which live state
// is cleared — the persisted rows now include what just streamed.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, FileText, Loader2, Plus, Send, Square, X } from "lucide-react";
import {
  fetchInvestigationReport,
  useCompleteSession,
  useConfirmPin,
  useCreateSession,
  useInvestigationSession,
  useInvestigationSessions,
  useInvestigationStream,
  usePromotePin,
  useSwitchModel,
} from "#hooks/use-investigation";
import { cn, formatCost, formatRelativeTime } from "#lib/utils";
import type {
  InvestigationMessage as InvestigationMessageRow,
  InvestigationModel,
  InvestigationSSEEvent,
  PinProposal,
} from "#lib/types";
import { InvestigationMessage } from "./investigation-message";
import { InvestigationPinBar } from "./investigation-pin-bar";
import { InvestigationToolCall } from "./investigation-tool-call";

interface InvestigationPanelProps {
  analysisId: number;
  /** When provided, renders an X close button in the header. */
  onClose?: () => void;
}

// ---------------------------------------------------------------------------
// Live streaming state — the in-flight exchange only
// ---------------------------------------------------------------------------

type LiveEntry =
  | { kind: "assistant_chunk"; text: string }
  | {
      kind: "tool";
      tool: string;
      args: Record<string, unknown>;
      result?: Record<string, unknown>;
    };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// History pairing — persisted tool_call/tool_result rows become one render
// ---------------------------------------------------------------------------

type HistoryItem =
  | { kind: "chat"; key: string; role: "user" | "assistant"; content: string }
  | {
      kind: "tool";
      key: string;
      tool: string;
      args: Record<string, unknown>;
      result: Record<string, unknown> | null;
    };

/** Parse persisted message content JSON; returns null on malformed input. */
function parseRecord(raw: string): Record<string, unknown> | null {
  try {
    const value: unknown = JSON.parse(raw);
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

/**
 * Pair tool_result rows with their preceding tool_call (a result follows its
 * call; both carry the tool name). Malformed JSON payloads are skipped rather
 * than crashing the render.
 */
function buildHistory(messages: InvestigationMessageRow[]): HistoryItem[] {
  const items: HistoryItem[] = [];

  for (const msg of messages) {
    if (msg.role === "user" || msg.role === "assistant") {
      items.push({ kind: "chat", key: `m-${msg.id}`, role: msg.role, content: msg.content });
      continue;
    }

    const payload = parseRecord(msg.content);
    const tool =
      msg.tool_name ?? (payload && typeof payload.tool === "string" ? payload.tool : "unknown_tool");

    if (msg.role === "tool_call") {
      // Persisted as {"tool": ..., "args": {...}}
      items.push({
        kind: "tool",
        key: `t-${msg.id}`,
        tool,
        args: payload && isRecord(payload.args) ? payload.args : {},
        result: null,
      });
    } else if (msg.role === "tool_result") {
      // Persisted as {"tool": ..., "result": {...}} — attach to the most
      // recent call for this tool that doesn't have a result yet.
      if (!payload) continue;
      const result = isRecord(payload.result) ? payload.result : payload;
      const target = [...items]
        .reverse()
        .find((it) => it.kind === "tool" && it.tool === tool && it.result === null);
      if (target && target.kind === "tool") {
        target.result = result;
      } else {
        // Orphan result (no matching call) — render standalone rather than drop.
        items.push({ kind: "tool", key: `t-${msg.id}`, tool, args: {}, result });
      }
    }
  }

  return items;
}

// ---------------------------------------------------------------------------
// Model selector (header control)
// ---------------------------------------------------------------------------

const MODEL_OPTIONS: Array<{ value: InvestigationModel; label: string }> = [
  { value: "claude-sonnet-4-6", label: "Sonnet" },
  { value: "claude-opus-4-6", label: "Opus" },
  { value: "claude-haiku-4-5", label: "Haiku" },
];

function ModelSelect({
  value,
  onChange,
  disabled,
}: {
  value: string;
  onChange: (model: string) => void;
  disabled?: boolean;
}) {
  const known = MODEL_OPTIONS.some((o) => o.value === value);
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      disabled={disabled}
      title="Switch model for subsequent turns"
      className="rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-2 py-1 text-xs text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)] disabled:opacity-50"
    >
      {!known && <option value={value}>{value}</option>}
      {MODEL_OPTIONS.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

// ---------------------------------------------------------------------------
// Shared bits
// ---------------------------------------------------------------------------

const TEXT_BUTTON =
  "rounded border border-[var(--color-border)] px-2 py-1 text-xs text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] disabled:opacity-50";

function PanelSkeleton() {
  return (
    <div className="flex-1 space-y-3 p-3">
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="h-16 animate-pulse rounded-md bg-[var(--color-background)]" />
      ))}
    </div>
  );
}

function ErrorBox({ children }: { children: React.ReactNode }) {
  return (
    <div className="m-3 rounded-md border border-red-800 bg-red-900/20 p-4 text-sm text-red-400">
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Panel
// ---------------------------------------------------------------------------

export function InvestigationPanel({ analysisId, onClose }: InvestigationPanelProps) {
  const queryClient = useQueryClient();

  // --- Session bootstrap ---
  const sessionsQuery = useInvestigationSessions(analysisId);
  const [selectedSessionId, setSelectedSessionId] = useState<number | null>(null);

  const sessions = useMemo(() => sessionsQuery.data ?? [], [sessionsQuery.data]);
  const newestActive = useMemo(
    () =>
      [...sessions]
        .filter((s) => s.status === "active")
        .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())[0],
    [sessions],
  );
  const previousSessions = useMemo(
    () =>
      [...sessions]
        .filter((s) => s.status !== "active")
        .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()),
    [sessions],
  );

  // Explicit selection wins; otherwise auto-select the most recent active session.
  const sessionId = selectedSessionId ?? newestActive?.id;
  const sessionQuery = useInvestigationSession(sessionId);
  const session = sessionQuery.data;
  const isActive = session?.status === "active";

  const createSession = useCreateSession(analysisId);
  const confirmPin = useConfirmPin(sessionId ?? 0);
  const promotePin = usePromotePin(sessionId ?? 0);
  const switchModel = useSwitchModel(sessionId ?? 0);
  const completeSession = useCompleteSession(sessionId ?? 0, analysisId);

  // --- Live streaming state for the in-flight exchange ---
  const [liveUserMsg, setLiveUserMsg] = useState<string | null>(null);
  const [liveEntries, setLiveEntries] = useState<LiveEntry[]>([]);
  const [proposals, setProposals] = useState<PinProposal[]>([]);
  const [errorBanner, setErrorBanner] = useState<string | null>(null);
  const [costAlert, setCostAlert] = useState(false);
  const [promotingPinId, setPromotingPinId] = useState<number | null>(null);
  const [exporting, setExporting] = useState(false);
  const [input, setInput] = useState("");

  const clearLiveExchange = useCallback(() => {
    setLiveUserMsg(null);
    setLiveEntries([]);
    // proposals intentionally NOT cleared — they persist until the analyst
    // accepts or dismisses them.
  }, []);

  const finaliseExchange = useCallback(
    (alsoInvalidateList: boolean) => {
      // Refetch first, THEN clear live state — the persisted rows now include
      // everything that just streamed, so there's no gap.
      if (sessionId !== undefined) {
        void queryClient
          .invalidateQueries({ queryKey: ["investigation", "session", sessionId] })
          .then(() => clearLiveExchange());
        if (alsoInvalidateList) {
          void queryClient.invalidateQueries({
            queryKey: ["investigation", "sessions", analysisId],
          });
        }
      } else {
        clearLiveExchange();
      }
    },
    [analysisId, sessionId, queryClient, clearLiveExchange],
  );

  // Reset per-session state when switching sessions — the React-recommended
  // "adjust state during render" pattern (avoids an extra effect pass).
  const [prevSessionId, setPrevSessionId] = useState(sessionId);
  if (prevSessionId !== sessionId) {
    setPrevSessionId(sessionId);
    setLiveUserMsg(null);
    setLiveEntries([]);
    setProposals([]);
    setErrorBanner(null);
    setCostAlert(false);
  }

  const handleEvent = useCallback(
    (event: InvestigationSSEEvent) => {
      const data = event.data;
      switch (event.event) {
        case "token": {
          if (typeof data.content !== "string") break;
          const text = data.content;
          setLiveEntries((prev) => {
            const last = prev[prev.length - 1];
            // Extend the trailing assistant chunk; start a new one after tools.
            if (last?.kind === "assistant_chunk") {
              return [...prev.slice(0, -1), { kind: "assistant_chunk", text: last.text + text }];
            }
            return [...prev, { kind: "assistant_chunk", text }];
          });
          break;
        }
        case "tool_call": {
          if (typeof data.tool !== "string") break;
          const tool = data.tool;
          const args = isRecord(data.args) ? data.args : {};
          setLiveEntries((prev) => [...prev, { kind: "tool", tool, args }]);
          break;
        }
        case "tool_result": {
          if (typeof data.tool !== "string") break;
          const tool = data.tool;
          const result = isRecord(data.result) ? data.result : {};
          setLiveEntries((prev) => {
            const next = [...prev];
            // Attach to the LAST call for this tool without a result yet.
            for (let i = next.length - 1; i >= 0; i--) {
              const entry = next[i];
              if (entry.kind === "tool" && entry.tool === tool && entry.result === undefined) {
                next[i] = { ...entry, result };
                return next;
              }
            }
            return next;
          });
          break;
        }
        case "pin_proposal": {
          const p = isRecord(data.proposal) ? data.proposal : data;
          if (
            typeof p.value === "string" &&
            (p.type === "ioc" || p.type === "technique" || p.type === "note")
          ) {
            const proposal: PinProposal = {
              type: p.type,
              value: p.value,
              ioc_type: typeof p.ioc_type === "string" ? p.ioc_type : undefined,
              context: typeof p.context === "string" ? p.context : "",
            };
            setProposals((prev) => [...prev, proposal]);
          }
          break;
        }
        case "error": {
          setErrorBanner(
            typeof data.message === "string" ? data.message : "Investigation stream error.",
          );
          break;
        }
        case "done": {
          if (data.cost_alert === true) setCostAlert(true);
          // Invalidate the sessions list to refresh cost totals — session
          // status changes only via the Complete button, not on done events.
          finaliseExchange(true);
          break;
        }
      }
    },
    [finaliseExchange],
  );

  const { sendMessage, isStreaming, abort } = useInvestigationStream(
    analysisId,
    sessionId,
    handleEvent,
  );

  // --- Derived history + turn accounting ---
  const historyItems = useMemo(() => buildHistory(session?.messages ?? []), [session?.messages]);
  const userTurnCount = useMemo(
    () => (session?.messages ?? []).filter((m) => m.role === "user").length,
    [session?.messages],
  );
  const turnLimitReached =
    session !== undefined && userTurnCount + (liveUserMsg !== null ? 1 : 0) >= session.max_turns;
  const canSend = isActive && !isStreaming && !turnLimitReached;

  // --- Auto-scroll: follow the bottom only if the user is already there ---
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const nearBottomRef = useRef(true);

  const handleScroll = useCallback(() => {
    const el = scrollRef.current;
    if (el) nearBottomRef.current = el.scrollHeight - el.scrollTop - el.clientHeight < 100;
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (el && nearBottomRef.current) el.scrollTop = el.scrollHeight;
  }, [historyItems.length, liveEntries, liveUserMsg]);

  // --- Actions ---
  const handleNewSession = () => {
    createSession.mutate(undefined, {
      onSuccess: (s) => setSelectedSessionId(s.id),
      onError: () => setErrorBanner("Failed to create session."),
    });
  };

  const handleSend = () => {
    const text = input.trim();
    if (!text || !canSend) return;
    setErrorBanner(null);
    setLiveUserMsg(text);
    setLiveEntries([]);
    setInput("");
    void sendMessage(text);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleAbort = () => {
    abort();
    // The backend persists whatever completed before the abort — refetch and
    // fold the partial exchange into history. Don't invalidate sessions list
    // because abort doesn't change session status or final cost (cost updates
    // are server-side only on completion).
    finaliseExchange(false);
  };

  const handleModelChange = (model: string) => {
    if (sessionId === undefined) return;
    switchModel.mutate(model, {
      onError: () => setErrorBanner("Failed to switch model."),
    });
  };

  const handleExport = async () => {
    if (sessionId === undefined) return;
    setExporting(true);
    try {
      const markdown = await fetchInvestigationReport(sessionId);
      const blob = new Blob([markdown], { type: "text/markdown" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.target = "_blank";
      link.download = `investigation-${sessionId}.md`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      // Give the browser time to start the download before revoking.
      setTimeout(() => URL.revokeObjectURL(url), 30_000);
    } catch {
      setErrorBanner("Failed to export investigation report.");
    } finally {
      setExporting(false);
    }
  };

  const handleComplete = () => {
    if (sessionId === undefined) return;
    if (!window.confirm("Complete this investigation session? You won't be able to send more messages.")) {
      return;
    }
    completeSession.mutate(undefined, {
      onError: () => setErrorBanner("Failed to complete session."),
    });
  };

  const removeProposal = (proposal: PinProposal) =>
    setProposals((prev) =>
      prev.filter((p) => !(p.type === proposal.type && p.value === proposal.value)),
    );

  const handleConfirmPin = (proposal: PinProposal) => {
    confirmPin.mutate(
      {
        type: proposal.type,
        value: proposal.value,
        ioc_type: proposal.ioc_type,
        context: proposal.context,
      },
      {
        onSuccess: () => removeProposal(proposal),
        onError: () => setErrorBanner("Failed to confirm pin."),
      },
    );
  };

  const handlePromotePin = (pinId: number) => {
    setPromotingPinId(pinId);
    promotePin.mutate(pinId, {
      onSettled: () => setPromotingPinId(null),
      onSuccess: (data) => {
        if (data.status === "promotion_not_supported") {
          setErrorBanner(data.reason ?? "Promotion not supported for this pin.");
        }
      },
      onError: () => setErrorBanner("Failed to promote pin."),
    });
  };

  // --- Streaming cursor handling for live entries ---
  const lastLive = liveEntries[liveEntries.length - 1];
  const trailingChunkStreaming = isStreaming && lastLive?.kind === "assistant_chunk";
  // While streaming with no trailing text (e.g. a tool is running), show a
  // bare cursor so the analyst sees the turn is still in progress.
  const showBareCursor = isStreaming && lastLive?.kind !== "assistant_chunk";

  const totalTokens =
    session !== undefined ? session.total_input_tokens + session.total_output_tokens : 0;

  // --- Render ---
  return (
    <div className="flex h-full flex-col border-l border-[var(--color-border)] bg-[var(--color-surface)]">
      {/* Header */}
      <div className="flex flex-wrap items-center gap-2 border-b border-[var(--color-border)] px-3 py-2">
        <h2 className="shrink-0 text-sm font-semibold text-[var(--color-text-primary)]">
          Investigation
        </h2>
        {session && (
          <>
            <ModelSelect
              value={session.model}
              onChange={handleModelChange}
              disabled={isStreaming || switchModel.isPending || !isActive}
            />
            <span
              className="text-xs tabular-nums text-[var(--color-text-muted)]"
              title={`${totalTokens.toLocaleString()} tokens`}
            >
              {formatCost(session.total_cost_usd)}
              <span className="ml-1.5">{totalTokens.toLocaleString()} tok</span>
              {session.max_turns > 0 && (
                <span className="ml-1.5">
                  {userTurnCount}/{session.max_turns} turns
                </span>
              )}
            </span>
            {costAlert && (
              <span
                title="Cost alert: this session crossed the configured cost threshold"
                className="flex items-center gap-1 rounded border border-yellow-800 bg-yellow-900/30 px-1.5 py-0.5 text-[10px] font-medium text-yellow-400"
              >
                <AlertTriangle className="h-3 w-3" />
                cost
              </span>
            )}
          </>
        )}
        <div className="ml-auto flex items-center gap-1">
          {session && (
            <>
              <button
                onClick={() => void handleExport()}
                disabled={exporting}
                title="Export report as markdown"
                className={cn(TEXT_BUTTON, "flex items-center gap-1")}
              >
                {exporting ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <FileText className="h-3.5 w-3.5" />
                )}
                Report
              </button>
              {isActive && (
                <button
                  onClick={handleComplete}
                  disabled={completeSession.isPending || isStreaming}
                  className={TEXT_BUTTON}
                >
                  Complete
                </button>
              )}
            </>
          )}
          {onClose && (
            <button
              onClick={onClose}
              title="Close panel"
              aria-label="Close panel"
              className="rounded p-1.5 text-[var(--color-text-muted)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)]"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>

      {/* Cost alert banner (dismissible) */}
      {costAlert && (
        <div className="flex items-start justify-between gap-2 border-b border-yellow-800 bg-yellow-900/20 px-3 py-2 text-xs text-yellow-400">
          <span className="flex min-w-0 items-center gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
            This session has crossed the cost alert threshold. Consider switching to a cheaper
            model or completing the session.
          </span>
          <button onClick={() => setCostAlert(false)} title="Dismiss" aria-label="Dismiss" className="shrink-0">
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {/* Body */}
      {sessionsQuery.isLoading ? (
        <PanelSkeleton />
      ) : sessionsQuery.isError ? (
        <ErrorBox>Failed to load investigation sessions.</ErrorBox>
      ) : sessionId === undefined ? (
        // No session selected and none active — offer to start one.
        <div className="flex flex-1 flex-col overflow-y-auto p-6">
          <div className="flex flex-col items-center gap-3 pt-8">
            <p className="text-center text-sm text-[var(--color-text-muted)]">
              Start a conversational investigation of this sample. The agent can search the
              analysis database, decompile with Ghidra, and run Python.
            </p>
            <button
              onClick={handleNewSession}
              disabled={createSession.isPending}
              className="flex items-center gap-2 rounded-md border border-[var(--color-accent)] px-4 py-2 text-sm font-medium text-[var(--color-accent)] transition-colors hover:bg-[var(--color-surface-hover)] disabled:opacity-50"
            >
              {createSession.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
              Start Investigation
            </button>
            {createSession.isError && (
              <p className="text-xs text-red-400">Failed to create session. Try again.</p>
            )}
          </div>

          {previousSessions.length > 0 && (
            <div className="mt-10">
              <h3 className="mb-2 text-xs font-medium uppercase tracking-wide text-[var(--color-text-muted)]">
                Previous sessions
              </h3>
              <ul className="space-y-1">
                {previousSessions.map((s) => (
                  <li key={s.id}>
                    <button
                      onClick={() => setSelectedSessionId(s.id)}
                      className="flex w-full items-center justify-between gap-2 rounded-md border border-[var(--color-border-light)] bg-[var(--color-background)] px-3 py-2 text-left text-xs transition-colors hover:bg-[var(--color-surface-hover)]"
                    >
                      <span className="text-[var(--color-text-secondary)]">
                        Session #{s.id}
                        <span className="ml-2 text-[var(--color-text-muted)]">
                          {formatRelativeTime(s.created_at)} · {s.status}
                        </span>
                      </span>
                      <span className="tabular-nums text-[var(--color-text-muted)]">
                        {formatCost(s.total_cost_usd)}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      ) : sessionQuery.isLoading ? (
        <PanelSkeleton />
      ) : sessionQuery.isError || !session ? (
        <ErrorBox>Failed to load investigation session.</ErrorBox>
      ) : (
        <>
          {/* Message history + live exchange */}
          <div
            ref={scrollRef}
            onScroll={handleScroll}
            className="flex-1 space-y-3 overflow-y-auto px-3 py-3"
          >
            {historyItems.length === 0 && liveUserMsg === null && (
              <p className="pt-8 text-center text-sm text-[var(--color-text-muted)]">
                Ask a question about this sample to begin.
              </p>
            )}

            {historyItems.map((item) =>
              item.kind === "chat" ? (
                <InvestigationMessage key={item.key} role={item.role} content={item.content} />
              ) : (
                <InvestigationToolCall
                  key={item.key}
                  tool={item.tool}
                  args={item.args}
                  result={item.result}
                />
              ),
            )}

            {/* In-flight exchange (cleared once persisted history refetches) */}
            {liveUserMsg !== null && <InvestigationMessage role="user" content={liveUserMsg} />}
            {liveEntries.map((entry, i) =>
              entry.kind === "assistant_chunk" ? (
                <InvestigationMessage
                  key={`live-${i}`}
                  role="assistant"
                  content={entry.text}
                  streaming={trailingChunkStreaming && i === liveEntries.length - 1}
                />
              ) : (
                <InvestigationToolCall
                  key={`live-${i}`}
                  tool={entry.tool}
                  args={entry.args}
                  result={entry.result ?? (isStreaming ? undefined : null)}
                />
              ),
            )}
            {showBareCursor && <InvestigationMessage role="assistant" content="" streaming />}
          </div>

          {/* Pins + proposals */}
          <InvestigationPinBar
            pins={session.pins}
            proposals={proposals}
            onConfirm={handleConfirmPin}
            onDismiss={removeProposal}
            onPromote={handlePromotePin}
            promotingPinId={promotingPinId}
          />

          {/* Error banner */}
          {errorBanner && (
            <div className="mx-3 mt-2 flex items-start justify-between gap-2 rounded-md border border-red-800 bg-red-900/20 px-3 py-2 text-xs text-red-400">
              <span className="min-w-0 break-words">{errorBanner}</span>
              <button onClick={() => setErrorBanner(null)} title="Dismiss" aria-label="Dismiss" className="shrink-0">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          )}

          {/* Input */}
          <div className="border-t border-[var(--color-border)] p-3">
            {!isActive && (
              <div className="mb-2 flex items-center justify-between gap-2">
                <p className="text-xs text-[var(--color-text-muted)]">
                  Session {session.status} — read-only.
                </p>
                <button
                  onClick={handleNewSession}
                  disabled={createSession.isPending}
                  className={cn(TEXT_BUTTON, "flex shrink-0 items-center gap-1")}
                >
                  {createSession.isPending ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <Plus className="h-3 w-3" />
                  )}
                  New Session
                </button>
              </div>
            )}
            {isActive && turnLimitReached && (
              <p className="mb-2 text-xs text-yellow-400">
                Turn limit reached ({session.max_turns} turns). Complete the session or export the
                report.
              </p>
            )}
            <div className="flex items-end gap-2">
              <textarea
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                rows={2}
                disabled={!isActive || turnLimitReached}
                placeholder={
                  !isActive
                    ? "Session is read-only"
                    : turnLimitReached
                      ? "Turn limit reached"
                      : "Ask about this sample… (Enter to send, Shift+Enter for newline)"
                }
                className="flex-1 resize-none rounded-md border border-[var(--color-border)] bg-[var(--color-background)] px-3 py-2 text-sm text-[var(--color-text-primary)] outline-none placeholder:text-[var(--color-text-muted)] focus:border-[var(--color-accent)] disabled:opacity-50"
              />
              {isStreaming ? (
                <button
                  onClick={handleAbort}
                  title="Stop response"
                  className="rounded-md border border-red-800 bg-[var(--color-background)] p-2 text-red-400 transition-colors hover:bg-red-900/20"
                >
                  <Square className="h-4 w-4" />
                </button>
              ) : (
                <button
                  onClick={handleSend}
                  disabled={!canSend || input.trim() === ""}
                  title="Send message"
                  className="rounded-md border border-[var(--color-border)] bg-[var(--color-background)] p-2 text-[var(--color-accent)] transition-colors hover:bg-[var(--color-surface-hover)] disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Send className="h-4 w-4" />
                </button>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
