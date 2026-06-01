// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Single axios instance for all API calls. Interceptor injects Bearer JWT
// from Keycloak on every request, with API key fallback for dev/testing.

import axios from "axios";
import keycloak from "./keycloak";

const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "",
  timeout: 30_000,
});

// Request interceptor: inject JWT or fall back to static API key
apiClient.interceptors.request.use(async (config) => {
  if (keycloak.authenticated) {
    // Ensure token has at least 5 seconds of validity
    try {
      await keycloak.updateToken(5);
    } catch {
      // Token refresh failed — request will likely get 401
    }
    config.headers["Authorization"] = `Bearer ${keycloak.token}`;
  } else {
    // Fallback: static API key for dev/testing without Keycloak
    const apiKey = import.meta.env.VITE_API_KEY;
    if (apiKey) {
      config.headers["X-API-Key"] = apiKey;
    }
  }
  return config;
});

// Response interceptor: redirect to login on 401
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && keycloak.authenticated) {
      keycloak.login();
    }
    return Promise.reject(error);
  },
);

export default apiClient;
