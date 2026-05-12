// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type { TechniqueBrowseItem } from "#lib/types";

interface TechniqueListParams {
  q?: string;
  tactic?: string;
  limit?: number;
  offset?: number;
}

export function useTechniquesList(params: TechniqueListParams = {}) {
  return useQuery({
    queryKey: ["techniques", params],
    queryFn: async () => {
      const { data } = await apiClient.get<TechniqueBrowseItem[]>(
        "/api/techniques",
        { params },
      );
      return data;
    },
  });
}
