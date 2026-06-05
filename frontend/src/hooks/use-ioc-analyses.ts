// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type { IocAnalysisLink } from "#lib/types";

/** Fetch analyses linked to a specific IOC. */
export function useIocAnalyses(iocId: number | null) {
  return useQuery({
    queryKey: ["ioc-analyses", iocId],
    queryFn: async () => {
      const { data } = await apiClient.get<IocAnalysisLink[]>(
        `/api/iocs/${iocId}/analyses`,
      );
      return data;
    },
    enabled: iocId !== null,
  });
}
