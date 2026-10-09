import { Skeleton } from "@/components/ui/skeleton";
import { type ReactNode, useContext } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { AuthContext } from "./context";

export function ProtectedRoute({ children }: { readonly children: ReactNode; }) {
  const auth = useContext(AuthContext);
  const location = useLocation();

  // The session is being restored. A blank page here reads as a broken app, so show the shape
  // of what is coming and tell assistive technology what is happening.
  if (auth?.loading) {
    return (
      <div role="status" aria-label="Loading" className="mx-auto max-w-5xl space-y-4 px-4 py-8">
        <Skeleton className="h-8 w-48" />
        <Skeleton className="h-64 rounded-lg" />
      </div>
    );
  }

  if (!auth?.token) {
    return <Navigate to={`/login?redirect=${encodeURIComponent(location.pathname)}`} replace />;
  }

  return <>{children}</>;
}
