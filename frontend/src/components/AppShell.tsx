import { ErrorBoundary } from "@/components/ErrorBoundary";
import { RouteAnnouncer } from "@/components/RouteAnnouncer";
import { MAIN_CONTENT_ID, SkipLink } from "@/components/SkipLink";
import { useRouteFocus } from "@/lib/useRouteFocus";
import { type ReactNode, useRef } from "react";
import { useLocation } from "react-router-dom";

/**
 * Page chrome shared by every route: the skip link, the header, and a `<main>`
 * landmark that receives focus after navigation, with the new page's title
 * announced alongside. Pages render inside an error
 * boundary that resets on navigation, while the header stays outside it so
 * users can always leave a page that crashed.
 */
export function AppShell({ header, children }: {
  readonly header: ReactNode;
  readonly children: ReactNode;
}) {
  const { pathname } = useLocation();
  const mainRef = useRef<HTMLElement>(null);
  useRouteFocus(mainRef);

  return (
    <>
      <SkipLink />
      {header}
      <main id={MAIN_CONTENT_ID} ref={mainRef} tabIndex={-1} className="outline-none">
        <ErrorBoundary key={pathname}>{children}</ErrorBoundary>
      </main>
      <RouteAnnouncer />
    </>
  );
}
