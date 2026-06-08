// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";

export type EvasionCategory =
  | "guest_image"
  | "qemu"
  | "cape_config"
  | "automation"
  | "detection";

export type MitigationStatus = "mitigated" | "partial" | "open" | "na";

export interface EvasionTechnique {
  technique: string;
  mitre_id: string | null;
  evidence: string | null;
  sample_count: number;
  category: EvasionCategory;
  status: MitigationStatus;
}

export interface EvasionRecommendation {
  recommendation: string;
  frequency: number;
}

export interface EvasionsResponse {
  total_analyses_with_evasion: number;
  techniques: EvasionTechnique[];
  recommendations: EvasionRecommendation[];
}

export interface EvasionFilters {
  status?: MitigationStatus;
  category?: EvasionCategory;
  sort?: "sample_count" | "status" | "category";
}

export function useEvasions(filters: EvasionFilters = {}) {
  return useQuery({
    queryKey: ["evasions", filters],
    queryFn: async () => {
      const params: Record<string, string> = {};
      if (filters.status) params.status = filters.status;
      if (filters.category) params.category = filters.category;
      if (filters.sort) params.sort = filters.sort;
      const { data } = await apiClient.get<EvasionsResponse>("/api/evasions", {
        params,
      });
      return data;
    },
    staleTime: 120_000,
  });
}
