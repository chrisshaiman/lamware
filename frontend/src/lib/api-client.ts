// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Single axios instance for all API calls. Interceptor injects Bearer JWT
// from Keycloak on every request.

import axios from "axios";
import keycloak from "./keycloak";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "",
  timeout: 30_000,
});

// Request interceptor: inject JWT token
apiClient.interceptors.request.use(async (config) => {
  if (keycloak.authenticated) {
    // Ensure token has at least 5 seconds of validity
    try {
      await keycloak.updateToken(5);
    } catch {
      // Token refresh failed — request will go without valid token
    }
    config.headers["Authorization"] = `Bearer ${keycloak.token}`;
  }
  return config;
});

export default apiClient;
