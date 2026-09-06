import { apiFetch, setAuthToken, setOnUnauthorized } from "@/api/client";
import { SSO_SESSION_KEY, ssoTokenFromHash } from "@/auth/sso";
import type { LoginResponse } from "@/types/api";
import { createContext, type ReactNode, useCallback, useEffect, useState } from "react";

interface AuthState {
  token: string | null;
  userId: string | null;
  email: string | null;
}

export interface AuthContextValue extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  loading: boolean;
}

export const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode; }) {
  // The SSO callback redirects to "/#sso_token=<token>". The token must be
  // installed before the first render: a mount effect would race child
  // effects (route guards, data fetches) that already saw a null session.
  const [state, setState] = useState<AuthState>(() => {
    const sso = ssoTokenFromHash(window.location.hash);
    if (sso) {
      setAuthToken(sso.token);
      return {
        token: sso.token,
        userId: sso.claims.sub ?? null,
        email: sso.claims.email ?? null,
      };
    }
    return { token: null, userId: null, email: null };
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Drop the consumed fragment so the token cannot be replayed by a
    // refresh or shared in a copied link. Fragments without an sso_token
    // parameter (e.g. in-page anchors) are left untouched.
    const hash = window.location.hash;
    if (hash && new URLSearchParams(hash.slice(1)).has(SSO_SESSION_KEY)) {
      const clean = window.location.pathname + window.location.search;
      window.history.replaceState(null, "", clean);
    }
    setOnUnauthorized(() => {
      setState({ token: null, userId: null, email: null });
    });
    return () => setOnUnauthorized(null);
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    setLoading(true);
    try {
      const res = await apiFetch<LoginResponse>("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
        skipAuthRedirect: true,
      });
      setAuthToken(res.token);
      setState({ token: res.token, userId: res.user_id, email: res.email });
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    setAuthToken(null);
    setState({ token: null, userId: null, email: null });
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}
