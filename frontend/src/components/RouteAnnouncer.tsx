import { useEffect, useRef, useState } from "react";
import { useLocation } from "react-router-dom";

/**
 * Announces the new page's title after a route change.
 *
 * Focus moves to `<main>`, which has no name of its own and may still be
 * showing a loading skeleton, so without this a screen reader says nothing about
 * where the user landed. Render it after the routed content: effects run
 * children first, which is what makes the page's `useDocumentTitle` update land
 * before this reads `document.title`.
 */
export function RouteAnnouncer() {
  const { pathname } = useLocation();
  const previous = useRef(pathname);
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (previous.current === pathname) return;
    previous.current = pathname;
    setMessage(document.title);
  }, [pathname]);

  return <p role="status" className="sr-only">{message}</p>;
}
