import type { MouseEvent } from "react";

/** Id of the `<main>` landmark that the skip link and route focus target. */
export const MAIN_CONTENT_ID = "main-content";

/**
 * "Skip to main content" link: hidden until it receives keyboard focus, then
 * pinned to the top-left corner. It is the first focusable element so
 * keyboard users can bypass the navigation on every page.
 */
export function SkipLink() {
  // Move focus programmatically instead of letting the browser add a
  // `#main-content` fragment to the URL on every use.
  function handleClick(event: MouseEvent<HTMLAnchorElement>) {
    const main = document.getElementById(MAIN_CONTENT_ID);
    if (!main) return;
    event.preventDefault();
    main.focus();
  }

  return (
    <a
      href={`#${MAIN_CONTENT_ID}`}
      onClick={handleClick}
      className="sr-only focus:not-sr-only focus:fixed focus:top-4 focus:left-4 focus:z-50 focus:rounded-md focus:border focus:bg-background focus:px-3 focus:py-2 focus:text-sm focus:font-medium"
    >
      Skip to main content
    </a>
  );
}
