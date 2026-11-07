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

const AUTH_CHANNEL = "specht-auth";
const SIGNED_OUT = "signed-out";
const SIGNED_OUT_KEY = "specht:signed-out";

/**
 * Remembers that this browser signed out, until the next sign-in. The sign-out request can fail, and
 * the cookie that resumes a session stays live if it did, so without this a reload would sign the
 * person back in without asking.
 */
function markSignedOut(signedOut: boolean): void {
  try {
    if (signedOut) localStorage.setItem(SIGNED_OUT_KEY, "1");
    else localStorage.removeItem(SIGNED_OUT_KEY);
  } catch {}
}

function signedOutHere(): boolean {
  try {
    return localStorage.getItem(SIGNED_OUT_KEY) === "1";
  } catch {
    return false;
  }
}

/**
 * Asks the server for a session for this tab from the browser's sign-in, for a link opened in a new
 * tab. Returns null when there is none, which is the normal state of a signed-out browser, or when
 * the server cannot be reached: the sign-in page is the answer to both.
 */
async function resumeSession(): Promise<LoginResponse | null> {
  if (signedOutHere()) return null;
  try {
    const response = await fetch("/api/v1/auth/resume", {
      method: "POST",
      headers: { "X-Specht-Resume": "1" },
    });
    return response.status === 200 ? await response.json() as LoginResponse : null;
  } catch {
    return null;
  }
}

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
    if (hasPendingSsoAttempt() && ssoCodeFromHash(window.location.hash)) return true;
    // No session in this tab: this browser may still have one to continue.
    return !getStoredSession();
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
          markSignedOut(false);
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
    } else if (!getStoredSession()) {
      void resumeSession().then((res) => {
        // A sign-out in another tab can land while the answer is on its way.
        if (res && !signedOutHere()) {
          setAuthToken(res.token);
          setStoredSession(res.token, res.refresh_token, {
            userId: res.user_id,
            email: res.email,
          });
          setState({
            token: res.token,
            refreshToken: res.refresh_token,
            userId: res.user_id,
            email: res.email,
          });
        }
        setLoading(false);
      });
    }

    // Signing out ends this sign-in in every tab of the browser, so say so at once
    // instead of leaving the others to find out from a failed refresh.
    const channel = typeof BroadcastChannel === "undefined"
      ? null
      : new BroadcastChannel(AUTH_CHANNEL);
    if (channel) {
      channel.onmessage = (event: MessageEvent<unknown>) => {
        if (event.data !== SIGNED_OUT) return;
        markSignedOut(true);
        setAuthToken(null);
        clearStoredSession();
        setState({ token: null, refreshToken: null, userId: null, email: null });
      };
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
      channel?.close();
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
      markSignedOut(false);
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
    markSignedOut(false);
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
    markSignedOut(true);
    if (typeof BroadcastChannel !== "undefined") {
      const channel = new BroadcastChannel(AUTH_CHANNEL);
      channel.postMessage(SIGNED_OUT);
      channel.close();
    }
  }, []);

  const value = useMemo(
    () => ({ ...state, login, logout, adopt, loading, ssoBrowserMismatch }),
    [state, login, logout, adopt, loading, ssoBrowserMismatch],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
