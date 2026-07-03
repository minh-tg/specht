import { createContext, useState, useCallback, useEffect, type ReactNode } from "react"
import { apiFetch, setAuthToken, setOnUnauthorized } from "@/api/client"
import type { LoginResponse } from "@/types/api"

interface AuthState {
  token: string | null
  userId: string | null
  email: string | null
}

export interface AuthContextValue extends AuthState {
  login: (email: string, password: string) => Promise<void>
  logout: () => void
  loading: boolean
}

export const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>({ token: null, userId: null, email: null })
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setOnUnauthorized(() => {
      setState({ token: null, userId: null, email: null })
    })
    return () => setOnUnauthorized(null)
  }, [])

  const login = useCallback(async (email: string, password: string) => {
    setLoading(true)
    try {
      const res = await apiFetch<LoginResponse>("/api/v1/auth/login", {
        method: "POST",
        body: JSON.stringify({ email, password }),
        skipAuthRedirect: true,
      })
      setAuthToken(res.token)
      setState({ token: res.token, userId: res.user_id, email: res.email })
    } finally {
      setLoading(false)
    }
  }, [])

  const logout = useCallback(() => {
    setAuthToken(null)
    setState({ token: null, userId: null, email: null })
  }, [])

  return (
    <AuthContext.Provider value={{ ...state, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  )
}
