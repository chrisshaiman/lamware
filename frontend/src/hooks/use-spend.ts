// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";

export interface ModelSpend {
  model: string;
  cost: number;
  requests: number;
  input_tokens: number;
  output_tokens: number;
  cache_creation_tokens: number;
  cache_read_tokens: number;
}

export interface DaySpend {
  date: string;
  cost: number;
  requests: number;
}

export interface SpendTotals {
  total_cost: number;
  total_requests: number;
  total_input_tokens: number;
  total_output_tokens: number;
  cache_creation_tokens: number;
  cache_read_tokens: number;
}

export interface SpendResponse {
  error?: string;
  by_model: ModelSpend[];
  by_day: DaySpend[];
  totals: SpendTotals;
}

export function useSpend(days: number = 30) {
  return useQuery({
    queryKey: ["spend", days],
    queryFn: async () => {
      const { data } = await apiClient.get<SpendResponse>("/api/spend", {
        params: { days },
      });
      return data;
    },
    staleTime: 300_000, // 5 min — spend data doesn't change fast
  });
}
