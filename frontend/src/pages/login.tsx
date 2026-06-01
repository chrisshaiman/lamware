// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Branded login page — shown when the user is not authenticated.
// Single "Sign in" button triggers the Keycloak PKCE flow.

import { useAuth } from "#contexts/auth-context";

export function LoginPage() {
  const { login } = useAuth();

  return (
    <div className="flex min-h-screen items-center justify-center bg-[var(--color-bg)]">
      <div className="flex flex-col items-center gap-6 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-10 shadow-lg">
        {/* Security cat logo */}
        <img
          src="/favicon.svg"
          alt="lamware security cat"
          className="h-20 w-20"
        />

        <div className="text-center">
          <h1 className="text-2xl font-bold text-[var(--color-text-primary)]">
            lamware
          </h1>
          <p className="mt-1 text-sm text-[var(--color-text-secondary)]">
            Malware Analysis Platform
          </p>
        </div>

        <button
          onClick={login}
          className="rounded-md bg-[var(--color-accent)] px-6 py-2.5 text-sm font-medium text-white transition-colors hover:bg-[var(--color-accent-hover)]"
        >
          Sign in
        </button>

        <p className="text-xs text-[var(--color-text-muted)]">
          Secured by Keycloak SSO
        </p>
      </div>
    </div>
  );
}
