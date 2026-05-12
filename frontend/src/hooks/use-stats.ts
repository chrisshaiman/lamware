// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type { StatsResponse } from "#lib/types";

export function useStats() {
  return useQuery({
    queryKey: ["stats"],
    queryFn: async () => {
      const { data } = await apiClient.get<StatsResponse>("/api/stats");
      return data;
    },
    staleTime: 60_000,
  });
}
