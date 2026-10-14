import { useCapabilities, useMe } from "@/api/hooks";
import { useAuth } from "@/auth/useAuth";
import { BrandMark } from "@/components/BrandMark";
import { CommandPalette } from "@/components/CommandPalette";
import { ThemeToggle } from "@/components/ThemeToggle";
import { NavLink } from "react-router-dom";

/** Shared link styling: active links get a clearly visible token colour. */
function navLinkClass({ isActive }: { isActive: boolean; }): string {
  return isActive
    ? "text-foreground text-sm font-medium py-1"
    : "text-muted-foreground hover:text-foreground text-sm py-1";
}

function SignedOutLinks() {
  const capabilities = useCapabilities();

  return (
    <>
      {capabilities.data?.registration.enabled === true && (
        <NavLink to="/register" className={navLinkClass}>
          Register
        </NavLink>
      )}
      <NavLink to="/login" className={navLinkClass}>
        Sign in
      </NavLink>
    </>
  );
}

function SignedInLinks({ email, onLogout }: { email: string | null; onLogout: () => void; }) {
  const me = useMe();

  return (
    <>
      <CommandPalette />
      {email && (
        <span
          className="text-muted-foreground hidden max-w-[10rem] truncate text-xs sm:inline"
          title={email}
        >
          {email}
        </span>
      )}
      <div className="flex basis-full flex-wrap items-center gap-x-4 gap-y-1 sm:contents">
        <NavLink to="/profile" className={navLinkClass}>
          Profile
        </NavLink>
        <NavLink to="/teams" className={navLinkClass}>
          Teams
        </NavLink>
        <NavLink to="/api-keys" className={navLinkClass}>
          API keys
        </NavLink>
        {me.data?.role === "admin" && (
          <NavLink to="/admin" className={navLinkClass}>
            Admin
          </NavLink>
        )}
        <button
          type="button"
          onClick={onLogout}
          className="text-muted-foreground hover:text-foreground py-1 text-sm whitespace-nowrap"
        >
          Sign out
        </button>
      </div>
    </>
  );
}

export function Navbar() {
  const auth = useAuth();

  return (
    <header className="border-border bg-background border-b">
      <nav
        aria-label="Main"
        className="mx-auto flex min-h-12 max-w-5xl flex-wrap items-center max-sm:items-start justify-between gap-x-3 gap-y-0 px-4 py-1"
      >
        <NavLink to="/" className="inline-flex items-center gap-2 py-1.5 text-sm font-semibold">
          <BrandMark className="text-action h-5 w-5" />
          Specht
        </NavLink>
        <div className="flex min-w-0 flex-wrap items-center justify-end gap-x-3 gap-y-0 max-sm:flex-1">
          <ThemeToggle />
          {auth.token
            ? <SignedInLinks email={auth.email} onLogout={auth.logout} />
            : <SignedOutLinks />}
        </div>
      </nav>
    </header>
  );
}
