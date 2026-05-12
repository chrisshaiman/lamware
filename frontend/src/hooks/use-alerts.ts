// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type { AlertsResponse } from "#lib/types";

export function useAlerts() {
  return useQuery({
    queryKey: ["alerts"],
    queryFn: async () => {
      const { data } = await apiClient.get<AlertsResponse>("/api/alerts");
      return data;
    },
    refetchInterval: 30_000,
  });
}
