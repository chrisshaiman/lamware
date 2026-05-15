// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import { useWsStatus } from "#hooks/use-ws-context";
import type { PipelineStatusResponse } from "#lib/types";

export function usePipelineStatus() {
  const { isConnected } = useWsStatus();

  return useQuery({
    queryKey: ["pipeline"],
    queryFn: async () => {
      const { data } = await apiClient.get<PipelineStatusResponse>(
        "/api/pipeline/status",
      );
      return data;
    },
    // When WebSocket is connected, poll infrequently as a fallback.
    // When disconnected, use adaptive polling (10s active, 60s idle).
    refetchInterval: isConnected
      ? 300_000
      : (query) => {
          const data = query.state.data;
          return data && data.running.length > 0 ? 10_000 : 60_000;
        },
  });
}
