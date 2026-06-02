// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// WebSocket hook — connects to /ws/pipeline, authenticates via first message,
// receives pipeline events, and invalidates TanStack Query caches.
// Auto-reconnects with exponential backoff.

import { useEffect, useRef, useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import keycloak from "#lib/keycloak";

/** Event type to query keys to invalidate */
const INVALIDATION_MAP: Record<string, string[]> = {
  stage_update: ["pipeline", "analyses", "analysis"],
  analysis_complete: ["pipeline", "analyses", "analysis", "stats", "techniques", "iocs", "evasions"],
  analysis_failed: ["pipeline", "analyses", "analysis"],
};

const MAX_BACKOFF_MS = 30_000;

export interface WebSocketStatus {
  isConnected: boolean;
  isReconnecting: boolean;
}

/**
 * Connects to the pipeline WebSocket and invalidates query caches on events.
 * Mount once at the app root level — not per page.
 */
export function useWebSocket(): WebSocketStatus {
  const queryClient = useQueryClient();
  const [isConnected, setIsConnected] = useState(false);
  const [isReconnecting, setIsReconnecting] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const backoffRef = useRef(1000);
  const mountedRef = useRef(true);

  useEffect(() => {
    mountedRef.current = true;

    function connect() {
      // Build WebSocket URL — no auth in URL, auth via first message
      const baseUrl = import.meta.env.VITE_API_BASE_URL || window.location.origin;
      const wsProtocol = baseUrl.startsWith("https") ? "wss" : "ws";
      const host = baseUrl.replace(/^https?:\/\//, "");
      const url = `${wsProtocol}://${host}/ws/pipeline`;

      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        if (!mountedRef.current) return;

        // Send auth as first message
        if (keycloak.authenticated && keycloak.token) {
          ws.send(JSON.stringify({ type: "auth", token: keycloak.token }));
        }

        setIsConnected(true);
        setIsReconnecting(false);
        backoffRef.current = 1000;
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data as string) as Record<string, unknown>;
          const eventType = data.event as string | undefined;

          // Initial state message (has "running" key, no "event" key)
          if (!eventType && "running" in data) {
            queryClient.invalidateQueries({ queryKey: ["pipeline"] });
            return;
          }

          if (eventType) {
            const keys = INVALIDATION_MAP[eventType];
            if (keys) {
              for (const key of keys) {
                queryClient.invalidateQueries({ queryKey: [key] });
              }
            }
          }
        } catch {
          // Ignore malformed messages
        }
      };

      ws.onclose = () => {
        if (!mountedRef.current) return;
        setIsConnected(false);
        scheduleReconnect();
      };

      ws.onerror = () => {
        ws.close();
      };
    }

    function scheduleReconnect() {
      if (!mountedRef.current) return;
      setIsReconnecting(true);
      const delay = backoffRef.current;
      backoffRef.current = Math.min(delay * 2, MAX_BACKOFF_MS);
      setTimeout(() => {
        if (mountedRef.current) connect();
      }, delay);
    }

    connect();

    return () => {
      mountedRef.current = false;
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [queryClient]);

  return { isConnected, isReconnecting };
}
