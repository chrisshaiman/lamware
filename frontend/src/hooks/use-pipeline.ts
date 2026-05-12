// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type { PipelineStatusResponse } from "#lib/types";

export function usePipelineStatus() {
  return useQuery({
    queryKey: ["pipeline"],
    queryFn: async () => {
      const { data } = await apiClient.get<PipelineStatusResponse>(
        "/api/pipeline/status",
      );
      return data;
    },
    // Poll every 10s when there are running analyses, 60s otherwise.
    // WebSocket will replace this polling when the endpoint is built.
    refetchInterval: (query) => {
      const data = query.state.data;
      return data && data.running.length > 0 ? 10_000 : 60_000;
    },
  });
}
