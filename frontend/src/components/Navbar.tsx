import { useCapabilities, useMe } from "@/api/hooks";
import { useAuth } from "@/auth/useAuth";
import { AccountMenu } from "@/components/AccountMenu";
import { BrandMark } from "@/components/BrandMark";
import { CommandPalette } from "@/components/CommandPalette";
import { ThemeToggle } from "@/components/ThemeToggle";
import { buttonVariants } from "@/components/ui/button-variants";
import { useHeaderChrome } from "@/components/useHeaderChrome";
import { isProjectsPath } from "@/lib/commands";
import { cn } from "@/lib/utils";
import { Link, NavLink, useLocation } from "react-router-dom";

/** Primary links use the ghost button look; the current page keeps the hover fill. */
function navLinkClass({ isActive }: { isActive: boolean; }): string {
  return cn(
    buttonVariants({ variant: "ghost" }),
    isActive ? "bg-muted text-foreground" : "text-muted-foreground",
  );
}

/**
 * Home, the project list. It is the current page only on the list itself; inside a project, or on
 * the new-project form, it stays filled as the section you are in but is marked `aria-current`
 * "true", so a screen reader announces one current page and the brand link, a plain link, none.
 */
function ProjectsLink() {
  const { pathname } = useLocation();
  const onList = pathname === "/";
  const inside = !onList && isProjectsPath(pathname);

  return (
    <Link
      to="/"
      aria-current={onList ? "page" : inside ? "true" : undefined}
      className={navLinkClass({ isActive: onList || inside })}
    >
      Projects
    </Link>
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
      {
        /* Below sm the links wrap onto their own line under the account menu; from sm up the
          menu is the last item of the row. */
      }
      <div className="flex basis-full flex-wrap items-center gap-1 max-sm:order-last sm:contents">
        <ProjectsLink />
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
      <AccountMenu email={email} onLogout={onLogout} />
    </>
  );
}

/**
 * From `sm` up the header sticks to the top and is translucent with a blur. The solid
 * `bg-background` is the base, so a browser without `backdrop-filter` keeps it; reduced
 * transparency and forced colours are handled in index.css. The safe-area padding clears a notch.
 * `z-30` sits under the bulk bar (`z-40`) and under dialogs, menus and the skip link (`z-50`).
 */
const HEADER_CLASS = cn(
  "site-header border-border bg-background z-30 border-b sm:sticky sm:top-0",
  "supports-[backdrop-filter]:bg-background/90 supports-[backdrop-filter]:backdrop-blur-md",
  "data-scrolled:border-input transition-[border-color] duration-(--dur-quick)",
  "pt-[env(safe-area-inset-top)] pr-[env(safe-area-inset-right)] pl-[env(safe-area-inset-left)]",
);

export function Navbar() {
  const auth = useAuth();
  const { sentinelRef, headerRef, scrolled } = useHeaderChrome();

  return (
    <>
      <div
        ref={sentinelRef}
        aria-hidden="true"
        className="pointer-events-none absolute top-0 left-0 h-px w-px"
      />
      <header ref={headerRef} data-scrolled={scrolled ? "" : undefined} className={HEADER_CLASS}>
        <nav
          aria-label="Main"
          className="mx-auto flex min-h-12 max-w-5xl flex-wrap items-center max-sm:items-start justify-between gap-x-2 gap-y-0 px-4 py-1"
        >
          <Link to="/" className="inline-flex items-center gap-2 py-1.5 text-body font-semibold">
            <BrandMark className="text-action h-5 w-5" />
            Specht
          </Link>
          <div className="flex min-w-0 flex-wrap items-center justify-end gap-x-2 gap-y-1 max-sm:flex-1">
            <ThemeToggle />
            {auth.token
              ? <SignedInLinks email={auth.email} onLogout={auth.logout} />
              : <SignedOutLinks />}
          </div>
        </nav>
      </header>
    </>
  );
}
