// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Role gate — renders children only if the user has the required role.
// UX polish only — the backend enforces the real security boundary.

import type { ReactNode } from "react";
import { useAuth } from "#contexts/auth-context";

interface RequireRoleProps {
  role: string;
  children: ReactNode;
  fallback?: ReactNode;
}

export function RequireRole({ role, children, fallback = null }: RequireRoleProps) {
  const { hasRole } = useAuth();
  return hasRole(role) ? <>{children}</> : <>{fallback}</>;
}
