// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type { IocBrowseItem } from "#lib/types";

interface IocListParams {
  q?: string;
  type?: string;
  limit?: number;
  offset?: number;
}

export function useIocsList(params: IocListParams = {}) {
  return useQuery({
    queryKey: ["iocs", params],
    queryFn: async () => {
      const { data } = await apiClient.get<IocBrowseItem[]>("/api/iocs", {
        params,
      });
      return data;
    },
  });
}
