// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Keycloak instance — single shared instance used by the auth provider.
// Config comes from Vite build-time env vars (non-sensitive, public OIDC client).

import Keycloak from "keycloak-js";

const keycloak = new Keycloak({
  url: import.meta.env.VITE_KEYCLOAK_URL || "/auth",
  realm: import.meta.env.VITE_KEYCLOAK_REALM || "lamware",
  clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID || "lamware-web",
});

export default keycloak;
