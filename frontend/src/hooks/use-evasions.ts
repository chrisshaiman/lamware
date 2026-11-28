// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";

export type EvasionCategory =
  | "guest_image"
  | "qemu"
  | "cape_config"
  | "automation"
  | "detection";

export type MitigationStatus = "mitigated" | "partial" | "open" | "na";

// One row per MITRE technique ID (entries without one group by category). The
// API groups server-side; the full evidence comes a page at a time (useEvasionEvidence).
export interface EvasionTechnique {
  group: string;
  name_variants: number;
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
  recommendations_total: number;
}

export interface EvidenceItem {
  analysis_id: number;
  technique: string;
  evidence: string | null;
}

interface Page<T> {
  total: number;
  offset: number;
  items: T[];
}

const nextOffset = <T,>(last: Page<T>) =>
  last.offset + last.items.length < last.total ? last.offset + last.items.length : undefined;

// GET /api/evasions/evidence — one group's evidence, newest analysis first, 20 at a time.
export function useEvasionEvidence(group: string, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: ["evasions", "evidence", group],
    queryFn: async ({ pageParam }) => {
      const { data } = await apiClient.get<Page<EvidenceItem>>("/api/evasions/evidence", {
        params: { group, offset: pageParam, limit: 20 },
      });
      return data;
    },
    initialPageParam: 0,
    getNextPageParam: nextOffset,
    enabled,
  });
}

// GET /api/evasions/recommendations — the ones after the first page the dashboard has.
export function useMoreRecommendations(start: number, enabled: boolean) {
  return useInfiniteQuery({
    queryKey: ["evasions", "recommendations", start],
    queryFn: async ({ pageParam }) => {
      const { data } = await apiClient.get<Page<EvasionRecommendation>>(
        "/api/evasions/recommendations",
        { params: { offset: pageParam, limit: 25 } },
      );
      return data;
    },
    initialPageParam: start,
    getNextPageParam: nextOffset,
    enabled,
  });
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
