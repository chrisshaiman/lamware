// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// TanStack Query hooks and SSE streaming for investigation agent sessions.
// Mirrors /api/investigate/* endpoints in api/app/routers/investigate.py.

import { useCallback, useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import keycloak from "#lib/keycloak";
import type {
  InvestigationSession,
  InvestigationSessionDetail,
  InvestigationSSEEvent,
  InvestigationSSEEventType,
} from "#lib/types";

// ---------------------------------------------------------------------------
// Query key helpers
// ---------------------------------------------------------------------------

const investigationKeys = {
  sessions: (analysisId: number) => ["investigation", "sessions", analysisId] as const,
  session: (sessionId: number) => ["investigation", "session", sessionId] as const,
};

// ---------------------------------------------------------------------------
// Session list — GET /api/investigate/{analysisId}/sessions
// ---------------------------------------------------------------------------

export function useInvestigationSessions(analysisId: number | undefined) {
  return useQuery({
    queryKey: investigationKeys.sessions(analysisId ?? 0),
    queryFn: async () => {
      const { data } = await apiClient.get<{ sessions: InvestigationSession[] }>(
        `/api/investigate/${analysisId}/sessions`,
      );
      return data.sessions;
    },
    enabled: analysisId !== undefined,
  });
}

// ---------------------------------------------------------------------------
// Session detail — GET /api/investigate/sessions/{sessionId}
// ---------------------------------------------------------------------------

export function useInvestigationSession(sessionId: number | undefined) {
  return useQuery({
    queryKey: investigationKeys.session(sessionId ?? 0),
    queryFn: async () => {
      const { data } = await apiClient.get<InvestigationSessionDetail>(
        `/api/investigate/sessions/${sessionId}`,
      );
      return data;
    },
    enabled: sessionId !== undefined,
  });
}

// ---------------------------------------------------------------------------
// Create session — POST /api/investigate/{analysisId}/sessions
// Invalidates the sessions list for this analysis on success.
// ---------------------------------------------------------------------------

export function useCreateSession(analysisId: number) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (model?: string) => {
      const { data } = await apiClient.post<InvestigationSession>(
        `/api/investigate/${analysisId}/sessions`,
        model ? { model } : undefined,
      );
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: investigationKeys.sessions(analysisId),
      });
    },
  });
}

// ---------------------------------------------------------------------------
// Confirm pin — POST /api/investigate/sessions/{sessionId}/pin
// Invalidates session detail on success.
// ---------------------------------------------------------------------------

interface ConfirmPinBody {
  type: "ioc" | "technique" | "note";
  value: string;
  ioc_type?: string;
  context?: string;
}

interface ConfirmPinResponse {
  id: number;
  status: string;
}

export function useConfirmPin(sessionId: number) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (body: ConfirmPinBody) => {
      const { data } = await apiClient.post<ConfirmPinResponse>(
        `/api/investigate/sessions/${sessionId}/pin`,
        body,
      );
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: investigationKeys.session(sessionId),
      });
    },
  });
}

// ---------------------------------------------------------------------------
// Promote pin — POST /api/investigate/sessions/{sessionId}/pin/{pinId}/promote
// Invalidates session detail and the analysis record (promoted IOCs change it).
// ---------------------------------------------------------------------------

interface PromotePinResponse {
  status: "promoted" | "already_promoted" | "promotion_not_supported";
  reason?: string;
}

export function usePromotePin(sessionId: number) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (pinId: number) => {
      const { data } = await apiClient.post<PromotePinResponse>(
        `/api/investigate/sessions/${sessionId}/pin/${pinId}/promote`,
      );
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: investigationKeys.session(sessionId),
      });
      // Promoted IOCs/techniques are written back to the analysis record.
      queryClient.invalidateQueries({ queryKey: ["analysis"] });
    },
  });
}

// ---------------------------------------------------------------------------
// Switch model — POST /api/investigate/sessions/{sessionId}/model
// ---------------------------------------------------------------------------

interface SwitchModelResponse {
  model: string;
}

export function useSwitchModel(sessionId: number) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (model: string) => {
      const { data } = await apiClient.post<SwitchModelResponse>(
        `/api/investigate/sessions/${sessionId}/model`,
        { model },
      );
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: investigationKeys.session(sessionId),
      });
    },
  });
}

// ---------------------------------------------------------------------------
// Complete session — POST /api/investigate/sessions/{sessionId}/complete
// Invalidates both session detail and sessions list.
// ---------------------------------------------------------------------------

interface CompleteSessionResponse {
  status: string;
}

export function useCompleteSession(sessionId: number, analysisId: number) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post<CompleteSessionResponse>(
        `/api/investigate/sessions/${sessionId}/complete`,
      );
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: investigationKeys.session(sessionId),
      });
      queryClient.invalidateQueries({
        queryKey: investigationKeys.sessions(analysisId),
      });
    },
  });
}

// ---------------------------------------------------------------------------
// Report export — GET /api/investigate/sessions/{sessionId}/report
// Returns raw markdown; no query caching needed (on-demand export).
// ---------------------------------------------------------------------------

export async function fetchInvestigationReport(sessionId: number): Promise<string> {
  const { data } = await apiClient.get<{ markdown: string }>(
    `/api/investigate/sessions/${sessionId}/report`,
  );
  return data.markdown;
}

/** Mutation wrapper around fetchInvestigationReport for use inside components. */
export function useInvestigationReport() {
  return useMutation({
    mutationFn: fetchInvestigationReport,
  });
}

// ---------------------------------------------------------------------------
// SSE streaming — POST /api/investigate/{analysisId}/message
//
// EventSource cannot send POST bodies or Authorization headers, so we parse
// the SSE wire format manually using fetch + ReadableStream.
// ---------------------------------------------------------------------------

/**
 * Streams an investigation message exchange via fetch + ReadableStream.
 * EventSource can't send POST bodies or Authorization headers, so we parse
 * the SSE wire format manually.
 */
export function useInvestigationStream(
  analysisId: number,
  sessionId: number | undefined,
  onEvent: (event: InvestigationSSEEvent) => void,
) {
  const [isStreaming, setIsStreaming] = useState(false);
  const abortRef = useRef<AbortController | null>(null);

  const sendMessage = useCallback(
    async (content: string) => {
      if (!sessionId || isStreaming) return;
      setIsStreaming(true);
      abortRef.current = new AbortController();

      try {
        if (keycloak.authenticated) {
          await keycloak.updateToken(5).catch(() => {});
        }
        const baseUrl = import.meta.env.VITE_API_BASE_URL || "";
        const response = await fetch(
          `${baseUrl}/api/investigate/${analysisId}/message`,
          {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${keycloak.token}`,
            },
            body: JSON.stringify({ session_id: sessionId, content }),
            signal: abortRef.current.signal,
          },
        );

        if (!response.ok) {
          const err = await response
            .json()
            .catch(() => ({ detail: "Request failed" }));
          onEvent({
            event: "error",
            data: { message: (err as { detail?: string }).detail ?? "Request failed" },
          });
          return;
        }

        const reader = response.body?.getReader();
        if (!reader) {
          onEvent({ event: "error", data: { message: "Streaming not supported" } });
          return;
        }

        const decoder = new TextDecoder();
        let buffer = "";
        let currentEvent = "";

        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });

          const lines = buffer.split("\n");
          buffer = lines.pop() ?? "";

          for (const line of lines) {
            if (line.startsWith("event: ")) {
              currentEvent = line.slice(7).trim();
            } else if (line.startsWith("data: ") && currentEvent) {
              try {
                const data = JSON.parse(line.slice(6)) as Record<string, unknown>;
                onEvent({
                  event: currentEvent as InvestigationSSEEventType,
                  data,
                });
              } catch {
                // skip malformed event payloads
              }
              currentEvent = "";
            }
          }
        }
      } catch (e) {
        if (e instanceof DOMException && e.name === "AbortError") return;
        onEvent({ event: "error", data: { message: String(e) } });
      } finally {
        setIsStreaming(false);
      }
    },
    [analysisId, sessionId, isStreaming, onEvent],
  );

  const abort = useCallback(() => abortRef.current?.abort(), []);

  return { sendMessage, isStreaming, abort };
}
