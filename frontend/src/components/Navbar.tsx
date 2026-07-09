import { useAuth } from "@/auth/useAuth";
import { Link } from "react-router-dom";

export function Navbar() {
  const auth = useAuth();

  return (
    <header className="border-border bg-background border-b">
      <div className="mx-auto flex h-12 max-w-5xl items-center justify-between px-4">
        <div className="flex items-center gap-6">
          <Link to="/" className="text-sm font-semibold">
            Specht
          </Link>
          {auth.token && (
            <Link to="/ingest" className="text-muted-foreground hover:text-foreground text-sm">
              Ingest
            </Link>
          )}
        </div>
        <div className="flex items-center gap-3">
          {auth.token
            ? (
              <>
                <span className="text-muted-foreground text-xs">{auth.email}</span>
                <Link
                  to="/api-keys"
                  className="text-muted-foreground hover:text-foreground text-sm"
                >
                  API Keys
                </Link>
                <button
                  onClick={auth.logout}
                  className="text-muted-foreground hover:text-foreground text-sm"
                >
                  Logout
                </button>
              </>
            )
            : (
              <>
                <Link
                  to="/register"
                  className="text-muted-foreground hover:text-foreground text-sm"
                >
                  Register
                </Link>
                <Link to="/login" className="text-muted-foreground hover:text-foreground text-sm">
                  Sign in
                </Link>
              </>
            )}
        </div>
      </div>
    </header>
  );
}
