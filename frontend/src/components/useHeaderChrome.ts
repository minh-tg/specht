import { useEffect, useRef, useState } from "react";

/** The root custom property that holds the header's height, read by `scroll-padding-top`. */
export const HEADER_HEIGHT_VAR = "--header-h";

/**
 * What the sticky header needs from the browser, without a scroll handler:
 *
 * - `sentinelRef` goes on a 1px element at the very top of the page. Once it scrolls out of view
 *   `scrolled` turns true, which the header uses to strengthen its bottom border.
 * - `headerRef` goes on the header. Its height is published as `--header-h` on the root, so
 *   `scroll-padding-top` keeps focused and anchored elements clear of it. The height is measured,
 *   not fixed, because the signed-in header wraps to two rows below the `sm` breakpoint.
 *
 * Both observers are skipped where the browser has none (jsdom), leaving the header in its
 * unscrolled state.
 */
export function useHeaderChrome() {
  const sentinelRef = useRef<HTMLDivElement>(null);
  const headerRef = useRef<HTMLElement>(null);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const sentinel = sentinelRef.current;
    if (!sentinel || typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver((entries) => {
      const latest = entries[entries.length - 1];
      if (latest) setScrolled(!latest.isIntersecting);
    });
    observer.observe(sentinel);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const header = headerRef.current;
    if (!header) return;
    const root = document.documentElement;
    const publish = () => root.style.setProperty(HEADER_HEIGHT_VAR, `${header.offsetHeight}px`);
    publish();
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(publish);
    observer?.observe(header);
    return () => {
      observer?.disconnect();
      root.style.removeProperty(HEADER_HEIGHT_VAR);
    };
  }, []);

  return { sentinelRef, headerRef, scrolled };
}
