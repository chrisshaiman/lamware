// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type {
  AnalysisListResponse,
  AnalysisDetail,
  DeleteAnalysisResponse,
} from "#lib/types";

interface AnalysisListParams {
  q?: string;
  severity?: string;
  family?: string;
  limit?: number;
  offset?: number;
}

export function useAnalysesList(params: AnalysisListParams = {}) {
  return useQuery({
    queryKey: ["analyses", params],
    queryFn: async () => {
      const { data } = await apiClient.get<AnalysisListResponse>(
        "/api/analyses",
        { params },
      );
      return data;
    },
  });
}

export function useAnalysisDetail(id: number | undefined) {
  return useQuery({
    queryKey: ["analysis", id],
    queryFn: async () => {
      const { data } = await apiClient.get<AnalysisDetail>(
        `/api/analyses/${id}`,
      );
      return data;
    },
    enabled: id !== undefined,
  });
}

export function useDeleteAnalysis() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: async (id: number) => {
      const { data } = await apiClient.delete<DeleteAnalysisResponse>(
        `/api/analyses/${id}`,
      );
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["analyses"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
    },
  });
}
