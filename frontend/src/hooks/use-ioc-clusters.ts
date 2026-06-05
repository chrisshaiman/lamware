// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type { IocCluster } from "#lib/types";

/** Fetch IOC-based clusters of related analyses. */
export function useIocClusters() {
  return useQuery({
    queryKey: ["ioc-clusters"],
    queryFn: async () => {
      const { data } = await apiClient.get<IocCluster[]>("/api/iocs/clusters");
      return data;
    },
  });
}
