// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type { TechniqueAnalysisLink } from "#lib/types";

/** Fetch analyses linked to a specific technique. */
export function useTechniqueAnalyses(techniqueId: number | null) {
  return useQuery({
    queryKey: ["technique-analyses", techniqueId],
    queryFn: async () => {
      const { data } = await apiClient.get<TechniqueAnalysisLink[]>(
        `/api/techniques/${techniqueId}/analyses`,
      );
      return data;
    },
    enabled: techniqueId !== null,
  });
}
