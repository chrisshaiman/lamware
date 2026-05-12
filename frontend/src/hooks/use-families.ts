// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type { FamilyItem } from "#lib/types";

export function useFamiliesList(params: { q?: string; limit?: number; offset?: number } = {}) {
  return useQuery({
    queryKey: ["families", params],
    queryFn: async () => {
      const { data } = await apiClient.get<FamilyItem[]>("/api/families", { params });
      return data;
    },
  });
}
