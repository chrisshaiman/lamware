// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import apiClient from "#lib/api-client";
import type { FeederStatusResponse, FeederActionResponse } from "#lib/types";

export function useFeederStatus() {
  return useQuery({
    queryKey: ["feeder"],
    queryFn: async () => {
      const { data } = await apiClient.get<FeederStatusResponse>(
        "/api/feeder/status",
      );
      return data;
    },
    refetchInterval: 30_000,
  });
}

export function useFeederPause() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post<FeederActionResponse>(
        "/api/feeder/pause",
      );
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feeder"] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });
}

export function useFeederResume() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post<FeederActionResponse>(
        "/api/feeder/resume",
      );
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feeder"] });
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
  });
}

export function useFeederReset() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const { data } = await apiClient.post<FeederActionResponse>(
        "/api/feeder/reset",
      );
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feeder"] });
    },
  });
}
