import { useEffect } from "react";

/**
 * Sets the document title to `${title} · Specht` while the calling component is
 * mounted and restores whatever title was there before on cleanup.
 */
export function useDocumentTitle(title: string) {
  useEffect(() => {
    const previous = document.title;
    document.title = `${title} · Specht`;
    return () => {
      document.title = previous;
    };
  }, [title]);
}
