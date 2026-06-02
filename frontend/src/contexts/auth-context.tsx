// Copyright 2026 Christopher Shaiman
// SPDX-License-Identifier: Apache-2.0
//
// Keycloak auth provider — wraps the app, handles init, token refresh,
// and exposes user/role info via useAuth() hook.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import keycloak from "#lib/keycloak";

interface User {
  id: string;
  email: string;
  name: string;
  username: string;
}

interface AuthContextValue {
  isAuthenticated: boolean;
  isLoading: boolean;
  user: User | null;
  roles: string[];
  token: string | null;
  login: () => void;
  logout: () => void;
  hasRole: (role: string) => boolean;
}

const AuthContext = createContext<AuthContextValue>({
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

function extractUser(): User | null {
  if (!keycloak.tokenParsed) return null;
  const t = keycloak.tokenParsed as Record<string, unknown>;
  return {
    id: (t.sub as string) || "",
    email: (t.email as string) || "",
    name: (t.name as string) || (t.preferred_username as string) || "",
    username: (t.preferred_username as string) || "",
  };
}

function extractRoles(): string[] {
  const ra = keycloak.tokenParsed?.realm_access as
    | { roles?: string[] }
    | undefined;
  return ra?.roles ?? [];
}

export function KeycloakProvider({ children }: { children: ReactNode }) {
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const [roles, setRoles] = useState<string[]>([]);
  const [token, setToken] = useState<string | null>(null);
  const initRef = useRef(false);

  useEffect(() => {
    if (initRef.current) return;
    initRef.current = true;

    keycloak
      .init({ checkLoginIframe: false })
      .then((authenticated) => {
        if (authenticated) {
          setIsAuthenticated(true);
          setUser(extractUser());
          setRoles(extractRoles());
          setToken(keycloak.token ?? null);
        }
        setIsLoading(false);
      })
      .catch(() => {
        setIsLoading(false);
      });

    keycloak.onTokenExpired = () => {
      keycloak
        .updateToken(30)
        .then(() => {
          setToken(keycloak.token ?? null);
        })
        .catch(() => {
          setIsAuthenticated(false);
          setUser(null);
          setRoles([]);
          setToken(null);
        });
    };

    keycloak.onAuthLogout = () => {
      setIsAuthenticated(false);
      setUser(null);
      setRoles([]);
      setToken(null);
    };
  }, []);

  const login = useCallback(() => {
    keycloak.login();
  }, []);

  const logout = useCallback(() => {
    keycloak.logout({ redirectUri: window.location.origin });
  }, []);

  const hasRole = useCallback(
    (role: string) => roles.includes(role),
    [roles],
  );

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        isLoading,
        user,
        roles,
        token,
        login,
        logout,
        hasRole,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
