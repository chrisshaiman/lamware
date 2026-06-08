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

export interface EvasionTechnique {
  technique: string;
  mitre_id: string | null;
  evidence: string | null;
  sample_count: number;
  category: EvasionCategory;
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

export function useEvasions() {
  return useQuery({
    queryKey: ["evasions"],
    queryFn: async () => {
      const { data } = await apiClient.get<EvasionsResponse>("/api/evasions");
      return data;
    },
    staleTime: 120_000,
  });
}
