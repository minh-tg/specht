import { type ReactNode, useContext } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { AuthContext } from "./context";

export function ProtectedRoute({ children }: { readonly children: ReactNode; }) {
  const auth = useContext(AuthContext);
  const location = useLocation();

  if (auth?.loading) {
    return null;
  }

  if (!auth?.token) {
    return <Navigate to={`/login?redirect=${encodeURIComponent(location.pathname)}`} replace />;
  }

  return <>{children}</>;
}
