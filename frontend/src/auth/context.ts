import type { LoginResponse } from "@/types/api";
import { createContext } from "react";

export interface AuthState {
  token: string | null;
  refreshToken: string | null;
  userId: string | null;
  email: string | null;
}

export interface AuthContextValue extends AuthState {
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  /** Signs in with a session the server just issued, for pages that create the account (setup, invite). */
  adopt: (session: LoginResponse) => void;
  loading: boolean;
  /**
   * True when the SSO exchange was refused because this browser did not start the login. The
   * login has to be started again from here.
   */
  ssoBrowserMismatch: boolean;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
