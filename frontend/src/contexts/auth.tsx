// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// The auth context and its hook, apart from the provider component: a module that
// exports a component and a hook breaks Vite's fast refresh
// (react-refresh/only-export-components). KeycloakProvider (auth-context.tsx)
// supplies the value; components read it with useAuth().

import { createContext, useContext } from "react";

export interface User {
  id: string;
  email: string;
  name: string;
  username: string;
}

export interface AuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: User | null;
  roles: string[];
  token: string | null;
  login: () => void;
  logout: () => void;
  hasRole: (role: string) => boolean;
}

export const AuthContext = createContext<AuthContextValue>({
  isAuthenticated: false,
  isLoading: true,
  user: null,
  roles: [],
  token: null,
  login: () => {},
  logout: () => {},
  hasRole: () => false,
});

export function useAuth(): AuthContextValue {
  return useContext(AuthContext);
}
