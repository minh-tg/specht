import {
  apiFetch,
  clearStoredSession,
  getStoredSession,
  revokeRefreshToken,
  setAuthToken,
  setRefreshFailedHandler,
  setStoredSession,
  setUnauthorizedHandler,
} from "@/api/client";
import {
  clearSsoAttempt,
  hasPendingSsoAttempt,
  SSO_SESSION_KEY,
  ssoTokenFromHash,
} from "@/auth/sso";
import type { LoginResponse } from "@/types/api";
import { type ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { AuthContext, type AuthState } from "./context";

export function AuthProvider({ children }: { readonly children: ReactNode; }) {
  // Restore a persisted session before the first render: a mount effect
  // would race child effects (route guards, data fetches) that already saw
  // a null session. The SSO callback fragment takes precedence, and a
  // token there is installed immediately for the same reason.
  const [state, setState] = useState<AuthState>(() => {
    // Peek, don't consume: React may run this initializer twice. The marker is
    // cleared by the mount effect below.
    const sso = hasPendingSsoAttempt() ? ssoTokenFromHash(window.location.hash) : null;
    if (sso) {
      setAuthToken(sso.token);
      setStoredSession(sso.token, null, {
        userId: sso.claims.sub ?? null,
        email: sso.claims.email ?? null,
      });
      return {
        token: sso.token,
        refreshToken: null,
        userId: sso.claims.sub ?? null,
        email: sso.claims.email ?? null,
      };
    }
    const stored = getStoredSession();
    if (stored) {
      setAuthToken(stored.token);
      return {
        token: stored.token,
        refreshToken: stored.refreshToken,
        userId: stored.userId,
        email: stored.email,
      };
    }
    return { token: null, refreshToken: null, userId: null, email: null };
  });
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Each SSO attempt is single-use, whatever the fragment held.
    clearSsoAttempt();
    // Drop the fragment so the token cannot be replayed by a refresh or shared
    // in a copied link, including one that was refused above because no login
    // was started here. Fragments without an sso_token parameter (e.g. in-page
    // anchors) are left untouched.
    const hash = window.location.hash;
    if (hash && new URLSearchParams(hash.slice(1)).has(SSO_SESSION_KEY)) {
      const clean = window.location.pathname + window.location.search;
      window.history.replaceState(null, "", clean);
    }
    setUnauthorizedHandler(() => {
      setAuthToken(null);
      clearStoredSession();
      setState({ token: null, refreshToken: null, userId: null, email: null });
    });
    setRefreshFailedHandler(() => {
      setState({ token: null, refreshToken: null, userId: null, email: null });
    });
    return () => {
      setUnauthorizedHandler(null);
      setRefreshFailedHandler(null);
    };
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
      setStoredSession(res.token, res.refresh_token, { userId: res.user_id, email: res.email });
      setState({
        token: res.token,
        refreshToken: res.refresh_token,
        userId: res.user_id,
        email: res.email,
      });
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    const { refreshToken } = getStoredSession() ?? {};
    if (refreshToken) {
      void revokeRefreshToken(refreshToken);
    }
    setAuthToken(null);
    clearStoredSession();
    setState({ token: null, refreshToken: null, userId: null, email: null });
  }, []);

  const value = useMemo(
    () => ({ ...state, login, logout, loading }),
    [state, login, logout, loading],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
