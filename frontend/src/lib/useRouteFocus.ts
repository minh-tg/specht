import { type RefObject, useEffect, useRef } from "react";
import { useLocation, useNavigationType } from "react-router-dom";

/**
 * Moves focus to `target` when the router pathname changes, so keyboard and
 * screen-reader users start at the new page's content instead of on the link
 * they just activated.
 *
 * A Back/Forward (`POP`) navigation restores the previous scroll position, so
 * focus moves with `preventScroll` while the offset stays put; PUSH and REPLACE
 * navigations still jump to the top of the new page.
 *
 * It does nothing on the first render and ignores search-only or hash-only
 * changes (filters, pagination, in-page anchors), which keep the user's place.
 */
export function useRouteFocus(target: RefObject<HTMLElement | null>) {
  const { pathname } = useLocation();
  const navigationType = useNavigationType();
  const previous = useRef(pathname);

  useEffect(() => {
    if (previous.current === pathname) return;
    previous.current = pathname;
    target.current?.focus({ preventScroll: true });
    if (navigationType !== "POP") window.scrollTo(0, 0);
  }, [pathname, navigationType, target]);
}
