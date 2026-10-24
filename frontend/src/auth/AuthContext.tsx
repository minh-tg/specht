import {
  APIError,
  apiFetch,
  clearStoredSession,
  getStoredSession,
  revokeRefreshToken,
  setAuthToken,
  setRefreshFailedHandler,
  setStoredSession,
  setUnauthorizedHandler,
} from "@/api/client";
import { clearSsoAttempt, hasPendingSsoAttempt, SSO_CODE_KEY, ssoCodeFromHash } from "@/auth/sso";
import type { LoginResponse } from "@/types/api";
import { type ReactNode, useCallback, useEffect, useMemo, useState } from "react";
import { AuthContext, type AuthState } from "./context";

export function AuthProvider({ children }: { readonly children: ReactNode; }) {
  // Restore a persisted session before the first render: a mount effect
  // would race child effects (route guards, data fetches) that already saw
  // a null session. A session never comes from the URL: when an SSO code is
  // present, loading starts true and an effect exchanges it with the server
  // for access and refresh tokens.
  const [state, setState] = useState<AuthState>(() => {
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
  const [loading, setLoading] = useState(() => {
    return hasPendingSsoAttempt() && Boolean(ssoCodeFromHash(window.location.hash));
  });
  const [ssoBrowserMismatch, setSsoBrowserMismatch] = useState(false);

  useEffect(() => {
    const isPending = hasPendingSsoAttempt();
    const ssoCode = isPending ? ssoCodeFromHash(window.location.hash) : null;

    // Each SSO attempt is single-use, whatever the fragment held.
    clearSsoAttempt();
    // Drop the fragment so the code cannot be replayed by a refresh or shared
    // in a copied link, including one that was refused above because no login
    // was started here. Fragments without an sso_code parameter (e.g. in-page
    // anchors) are left untouched.
    const hash = window.location.hash;
    if (hash && new URLSearchParams(hash.slice(1)).has(SSO_CODE_KEY)) {
      const clean = window.location.pathname + window.location.search;
      window.history.replaceState(null, "", clean);
    }

    if (ssoCode) {
      apiFetch<LoginResponse>("/api/v1/auth/sso/exchange", {
        method: "POST",
        body: JSON.stringify({ code: ssoCode }),
        skipAuthRedirect: true,
      })
        .then((res) => {
          setAuthToken(res.token);
          setStoredSession(res.token, res.refresh_token, {
            userId: res.user_id,
            email: res.email,
          });
          setSsoBrowserMismatch(false);
          setState({
            token: res.token,
            refreshToken: res.refresh_token,
            userId: res.user_id,
            email: res.email,
          });
        })
        .catch((err: unknown) => {
          setAuthToken(null);
          clearStoredSession();
          setSsoBrowserMismatch(err instanceof APIError && err.code === "sso_browser_mismatch");
          setState({ token: null, refreshToken: null, userId: null, email: null });
        })
        .finally(() => {
          setLoading(false);
        });
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

  const adopt = useCallback((res: LoginResponse) => {
    setAuthToken(res.token);
    setStoredSession(res.token, res.refresh_token, { userId: res.user_id, email: res.email });
    setState({
      token: res.token,
      refreshToken: res.refresh_token,
      userId: res.user_id,
      email: res.email,
    });
  }, []);

  const logout = useCallback(() => {
    const { refreshToken, token } = getStoredSession() ?? {};
    if (refreshToken) {
      void revokeRefreshToken(refreshToken, token);
    }
    setAuthToken(null);
    clearStoredSession();
    setState({ token: null, refreshToken: null, userId: null, email: null });
  }, []);

  const value = useMemo(
    () => ({ ...state, login, logout, adopt, loading, ssoBrowserMismatch }),
    [state, login, logout, adopt, loading, ssoBrowserMismatch],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
