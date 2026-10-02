import { useMe } from "@/api/hooks";
import { useAuth } from "@/auth/useAuth";
import { BrandMark } from "@/components/BrandMark";
import { ThemeToggle } from "@/components/ThemeToggle";
import { NavLink } from "react-router-dom";

/** Shared link styling: active links get a clearly visible token colour. */
function navLinkClass({ isActive }: { isActive: boolean; }): string {
  return isActive
    ? "text-foreground text-sm font-medium py-1"
    : "text-muted-foreground hover:text-foreground text-sm py-1";
}

function SignedInLinks({ email, onLogout }: { email: string | null; onLogout: () => void; }) {
  const me = useMe();

  return (
    <>
      {email && (
        <span
          className="text-muted-foreground hidden max-w-[10rem] truncate text-xs sm:inline"
          title={email}
        >
          {email}
        </span>
      )}
      {me.data?.role === "admin" && (
        <NavLink to="/api-keys" className={navLinkClass}>
          API Keys
        </NavLink>
      )}
      <button
        type="button"
        onClick={onLogout}
        className="text-muted-foreground hover:text-foreground py-1 text-sm"
      >
        Logout
      </button>
    </>
  );
}

export function Navbar() {
  const auth = useAuth();

  return (
    <header className="border-border bg-background border-b">
      <nav
        aria-label="Main"
        className="mx-auto flex h-12 max-w-5xl items-center justify-between gap-3 px-4"
      >
        <NavLink to="/" className="inline-flex items-center gap-2 text-sm font-semibold">
          <BrandMark className="text-action h-5 w-5" />
          Specht
        </NavLink>
        <div className="flex min-w-0 items-center gap-3">
          <ThemeToggle />
          {auth.token
            ? <SignedInLinks email={auth.email} onLogout={auth.logout} />
            : (
              <>
                <NavLink to="/register" className={navLinkClass}>
                  Register
                </NavLink>
                <NavLink to="/login" className={navLinkClass}>
                  Sign in
                </NavLink>
              </>
            )}
        </div>
      </nav>
    </header>
  );
}
