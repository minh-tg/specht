import { useLayoutEffect } from "react";
import { useLocation, useNavigationType } from "react-router-dom";

const STORAGE_PREFIX = "specht:scroll:";
/** How often a scroll position is written to session storage while the page is moving. */
const SAVE_INTERVAL_MS = 150;
/** How long a cold-cache page gets to grow tall enough before the saved position is dropped. */
const GIVE_UP_MS = 3000;
/** Input that can start a navigation. */
const LEAVING_INPUT = ["pointerdown", "keydown", "click"] as const;

interface SavedScroll {
  /** Path and query the offset was recorded on. Entries made by a fresh load all share the key "default". */
  readonly at: string;
  readonly y: number;
}

function read(key: string): SavedScroll | null {
  try {
    const raw = sessionStorage.getItem(STORAGE_PREFIX + key);
    if (!raw) return null;
    const saved = JSON.parse(raw) as Partial<SavedScroll>;
    return typeof saved.at === "string" && typeof saved.y === "number"
      ? { at: saved.at, y: saved.y }
      : null;
  } catch {
    return null;
  }
}

function write(key: string, saved: SavedScroll): void {
  try {
    sessionStorage.setItem(STORAGE_PREFIX + key, JSON.stringify(saved));
  } catch {
    // Storage is full or blocked: the page then opens at the top, as it did before.
  }
}

/** Whether the document is tall enough to scroll to `y` without the browser clamping it. */
function canReach(y: number): boolean {
  return document.documentElement.scrollHeight - window.innerHeight >= y;
}

/**
 * Remembers how far each history entry was scrolled and puts the page back there on Back,
 * Forward and reload. A new entry (link click, redirect) starts at the top.
 *
 * The browser's own restoration is turned off while this is mounted. It runs before the router
 * has rendered the old page, finds a short document and clamps, and then this hook would be
 * fighting it. Rows that are not rendered yet (an empty query cache) are waited for, up to
 * `GIVE_UP_MS`, and the restore is dropped as soon as the person scrolls, types or clicks.
 *
 * Mount it once, inside the router.
 */
export function useScrollRestoration(): void {
  const { key, pathname, search } = useLocation();
  const navigationType = useNavigationType();
  const at = pathname + search;

  useLayoutEffect(() => {
    const previous = history.scrollRestoration;
    history.scrollRestoration = "manual";
    return () => {
      history.scrollRestoration = previous;
    };
  }, []);

  // Recording. A scroll after this entry committed belongs to it; when the entry changes the
  // pending value is saved under the old key from memory, because the DOM is already the next page.
  useLayoutEffect(() => {
    const state = { key, at, y: 0, dirty: false };
    let timer: ReturnType<typeof setTimeout> | undefined;

    const flush = () => {
      clearTimeout(timer);
      timer = undefined;
      if (state.dirty) write(state.key, { at: state.at, y: state.y });
      state.dirty = false;
    };
    const onScroll = () => {
      state.y = window.scrollY;
      state.dirty = true;
      timer ??= setTimeout(flush, SAVE_INTERVAL_MS);
    };

    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("pagehide", flush);
    // `scrollTo` moves `scrollY` at once, but the scroll event arrives with the next frame. A
    // navigation started inside that gap would save nothing, so input that can start one also
    // takes the position, in the capture phase before any handler runs.
    for (const type of LEAVING_INPUT) {
      window.addEventListener(type, onScroll, { capture: true, passive: true });
    }
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("pagehide", flush);
      for (const type of LEAVING_INPUT) {
        window.removeEventListener(type, onScroll, { capture: true });
      }
      flush();
    };
  }, [key, at]);

  // Restoring. Only Back, Forward and reload (POP) go back to a saved offset.
  useLayoutEffect(() => {
    if (navigationType !== "POP") return;
    const saved = read(key);
    if (!saved || saved.at !== at || saved.y <= 0) return;

    const restore = () => window.scrollTo(0, saved.y);
    if (canReach(saved.y)) {
      restore();
      return;
    }

    // Cold cache: the rows arrive after this commit. Try whenever the page changes, once.
    const stop = () => {
      observer.disconnect();
      clearTimeout(giveUp);
      for (const name of ["wheel", "touchstart", "keydown", "pointerdown"]) {
        window.removeEventListener(name, stop);
      }
    };
    const observer = new MutationObserver(() => {
      if (!canReach(saved.y)) return;
      stop();
      restore();
    });
    const giveUp = setTimeout(stop, GIVE_UP_MS);
    observer.observe(document.body, { childList: true, subtree: true });
    for (const name of ["wheel", "touchstart", "keydown", "pointerdown"]) {
      window.addEventListener(name, stop, { passive: true });
    }
    return stop;
  }, [key, at, navigationType]);
}
