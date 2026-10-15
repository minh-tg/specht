import { useCapabilities, useMe } from "@/api/hooks";
import { useAuth } from "@/auth/useAuth";
import { AccountMenu } from "@/components/AccountMenu";
import { BrandMark } from "@/components/BrandMark";
import { CommandPalette } from "@/components/CommandPalette";
import { ThemeToggle } from "@/components/ThemeToggle";
import { buttonVariants } from "@/components/ui/button-variants";
import { cn } from "@/lib/utils";
import { NavLink } from "react-router-dom";

/** Primary links use the ghost button look; the current page keeps the hover fill. */
function navLinkClass({ isActive }: { isActive: boolean; }): string {
  return cn(
    buttonVariants({ variant: "ghost" }),
    isActive ? "bg-muted text-foreground" : "text-muted-foreground",
  );
}

function SignedOutLinks() {
  const capabilities = useCapabilities();

  return (
    <>
      {capabilities.data?.registration.enabled === true && (
        <NavLink to="/register" className={buttonVariants({ variant: "outline" })}>
          Register
        </NavLink>
      )}
      <NavLink to="/login" className={buttonVariants()}>
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
      <AccountMenu email={email} onLogout={onLogout} />
      <div className="flex basis-full flex-wrap items-center gap-1 sm:contents">
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
        className="mx-auto flex min-h-12 max-w-5xl flex-wrap items-center max-sm:items-start justify-between gap-x-2 gap-y-0 px-4 py-1"
      >
        <NavLink to="/" className="inline-flex items-center gap-2 py-1.5 text-sm font-semibold">
          <BrandMark className="text-action h-5 w-5" />
          Specht
        </NavLink>
        <div className="flex min-w-0 flex-wrap items-center justify-end gap-x-2 gap-y-1 max-sm:flex-1">
          <ThemeToggle />
          {auth.token
            ? <SignedInLinks email={auth.email} onLogout={auth.logout} />
            : <SignedOutLinks />}
        </div>
      </nav>
    </header>
  );
}
