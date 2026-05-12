// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Single axios instance for all API calls. Interceptor injects X-API-Key
// header on every request. This is the only file that knows about auth.
//
// Future JWT/OIDC migration: replace the static key read with a token
// from an auth context. Everything else stays the same.

import axios from "axios";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "",
  timeout: 30_000,
});

apiClient.interceptors.request.use((config) => {
  const apiKey = import.meta.env.VITE_API_KEY;
  if (apiKey) {
    config.headers["X-API-Key"] = apiKey;
  }
  return config;
});

export default apiClient;
