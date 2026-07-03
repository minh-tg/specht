import { useContext, type ReactNode } from "react"
import { Navigate, useLocation } from "react-router-dom"
import { AuthContext } from "./AuthContext"

export function ProtectedRoute({ children }: { children: ReactNode }) {
  const auth = useContext(AuthContext)
  const location = useLocation()

  if (!auth?.token) {
    return <Navigate to={`/login?redirect=${encodeURIComponent(location.pathname)}`} replace />
  }

  return <>{children}</>
}
