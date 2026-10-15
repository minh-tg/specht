import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  applyTheme,
  isTheme,
  nextTheme,
  readStoredTheme,
  resetThemeStore,
  resolveTheme,
  storeTheme,
  THEME_STORAGE_KEY,
  useTheme,
} from "./theme";

type Listener = () => void;

/**
 * A controllable matchMedia: `setDark` flips the system preference and notifies listeners.
 * `reducedMotion` answers the reduced-motion query separately from the colour scheme.
 */
function mockSystemTheme(initialDark: boolean, reducedMotion = false) {
  let dark = initialDark;
  const listeners = new Set<Listener>();
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    get matches() {
      return query.includes("reduced-motion") ? reducedMotion : dark;
    },
    addEventListener: (_: string, listener: Listener) => listeners.add(listener),
    removeEventListener: (_: string, listener: Listener) => listeners.delete(listener),
  }));
  return {
    listeners,
    setDark(next: boolean) {
      dark = next;
      for (const listener of [...listeners]) listener();
    },
  };
}

beforeEach(() => {
  resetThemeStore();
  window.localStorage.clear();
  document.documentElement.classList.remove("dark");
  document.documentElement.style.colorScheme = "";
});

afterEach(() => {
  vi.restoreAllMocks();
  // @ts-expect-error jsdom has no matchMedia; remove the test double again.
  delete window.matchMedia;
  // @ts-expect-error jsdom has no startViewTransition; remove the test double again.
  delete document.startViewTransition;
});

describe("theme helpers", () => {
  it("accepts only the three theme names", () => {
    expect(["system", "light", "dark"].every(isTheme)).toBe(true);
    expect(isTheme("blue")).toBe(false);
    expect(isTheme(null)).toBe(false);
  });

  it("resolves system through the preference and passes explicit choices through", () => {
    expect(resolveTheme("system", true)).toBe("dark");
    expect(resolveTheme("system", false)).toBe("light");
    expect(resolveTheme("light", true)).toBe("light");
    expect(resolveTheme("dark", false)).toBe("dark");
  });

  it("cycles system, light, dark and back to system", () => {
    expect(nextTheme("system")).toBe("light");
    expect(nextTheme("light")).toBe("dark");
    expect(nextTheme("dark")).toBe("system");
  });

  it("reads a stored theme and falls back to system for anything invalid", () => {
    expect(readStoredTheme()).toBe("system");
    window.localStorage.setItem(THEME_STORAGE_KEY, "dark");
    expect(readStoredTheme()).toBe("dark");
    window.localStorage.setItem(THEME_STORAGE_KEY, "purple");
    expect(readStoredTheme()).toBe("system");
  });

  it("survives blocked storage on read and write", () => {
    vi.spyOn(window.localStorage, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(window.localStorage, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });

    expect(readStoredTheme()).toBe("system");
    expect(() => storeTheme("dark")).not.toThrow();
  });

  it("applies the dark class and colour scheme to the document", () => {
    mockSystemTheme(false);

    applyTheme("dark");
    expect(document.documentElement).toHaveClass("dark");
    expect(document.documentElement.style.colorScheme).toBe("dark");

    applyTheme("light");
    expect(document.documentElement).not.toHaveClass("dark");
    expect(document.documentElement.style.colorScheme).toBe("light");
  });

  it("follows the system preference when the choice is system", () => {
    mockSystemTheme(true);

    applyTheme("system");

    expect(document.documentElement).toHaveClass("dark");
  });

  it("does not throw where matchMedia is unavailable", () => {
    expect(() => applyTheme("system")).not.toThrow();
    expect(document.documentElement).not.toHaveClass("dark");
  });
});

describe("useTheme", () => {
  it("starts from the stored choice and applies it", () => {
    mockSystemTheme(false);
    window.localStorage.setItem(THEME_STORAGE_KEY, "dark");

    const { result } = renderHook(() => useTheme());

    expect(result.current.theme).toBe("dark");
    expect(document.documentElement).toHaveClass("dark");
  });

  it("persists and applies a new choice", () => {
    mockSystemTheme(false);
    const { result } = renderHook(() => useTheme());

    act(() => result.current.setTheme("dark"));

    expect(result.current.theme).toBe("dark");
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
    expect(document.documentElement).toHaveClass("dark");
  });

  it("follows live system changes only while the choice is system", () => {
    const system = mockSystemTheme(false);
    const { result } = renderHook(() => useTheme());
    expect(document.documentElement).not.toHaveClass("dark");

    act(() => system.setDark(true));
    expect(document.documentElement).toHaveClass("dark");

    act(() => result.current.setTheme("light"));
    expect(document.documentElement).not.toHaveClass("dark");
    act(() => system.setDark(false));
    act(() => system.setDark(true));
    expect(document.documentElement).not.toHaveClass("dark");
  });

  it("removes its system listener when it unmounts", () => {
    const system = mockSystemTheme(false);
    const { unmount } = renderHook(() => useTheme());
    expect(system.listeners.size).toBe(1);

    unmount();

    expect(system.listeners.size).toBe(0);
  });
});

describe("the shared theme store", () => {
  /** What another tab does: change the stored value, which fires `storage` in this tab only. */
  function otherTabWrites(key: string | null, value: string | null) {
    if (key !== null && value !== null) window.localStorage.setItem(key, value);
    if (key !== null && value === null) window.localStorage.removeItem(key);
    if (key === null) window.localStorage.clear();
    window.dispatchEvent(new StorageEvent("storage", { key, newValue: value }));
  }

  it("keeps every instance in step after a change", () => {
    mockSystemTheme(false);
    const toggle = renderHook(() => useTheme());
    const palette = renderHook(() => useTheme());

    act(() => toggle.result.current.setTheme("dark"));

    expect(toggle.result.current.theme).toBe("dark");
    expect(palette.result.current.theme).toBe("dark");
  });

  it("holds exactly one system listener however many components use it", () => {
    const system = mockSystemTheme(false);
    const first = renderHook(() => useTheme());
    renderHook(() => useTheme());
    renderHook(() => useTheme());
    expect(system.listeners.size).toBe(1);

    act(() => first.result.current.setTheme("light"));
    expect(system.listeners.size).toBe(0);

    act(() => first.result.current.setTheme("system"));
    expect(system.listeners.size).toBe(1);
  });

  it("keeps a manual choice when the system changes, whichever instance made it", () => {
    const system = mockSystemTheme(false);
    renderHook(() => useTheme());
    const palette = renderHook(() => useTheme());

    act(() => palette.result.current.setTheme("light"));
    act(() => system.setDark(true));

    expect(document.documentElement).not.toHaveClass("dark");
    expect(palette.result.current.theme).toBe("light");
  });

  it("follows a choice made in another tab", () => {
    mockSystemTheme(false);
    const { result } = renderHook(() => useTheme());

    act(() => otherTabWrites(THEME_STORAGE_KEY, "dark"));

    expect(result.current.theme).toBe("dark");
    expect(document.documentElement).toHaveClass("dark");
  });

  it("returns to system when another tab clears the storage", () => {
    mockSystemTheme(false);
    const { result } = renderHook(() => useTheme());
    act(() => result.current.setTheme("dark"));

    act(() => otherTabWrites(null, null));

    expect(result.current.theme).toBe("system");
    expect(document.documentElement).not.toHaveClass("dark");
  });

  it("drops a choice that only lived in memory when the storage is cleared", () => {
    mockSystemTheme(false);
    const blocked = vi.spyOn(window.localStorage, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const { result } = renderHook(() => useTheme());
    act(() => result.current.setTheme("dark"));
    blocked.mockRestore();

    act(() => otherTabWrites(null, null));

    expect(result.current.theme).toBe("system");
  });

  it("does not touch the page for storage events about other keys", () => {
    mockSystemTheme(false);
    const { result } = renderHook(() => useTheme());
    act(() => result.current.setTheme("dark"));
    document.documentElement.classList.remove("dark");

    act(() => otherTabWrites("specht.sound", "on"));

    expect(result.current.theme).toBe("dark");
    expect(document.documentElement).not.toHaveClass("dark");
  });

  it("stops following other tabs once nothing uses the store", () => {
    mockSystemTheme(false);
    const remove = vi.spyOn(window, "removeEventListener");
    const { unmount } = renderHook(() => useTheme());

    unmount();

    expect(remove).toHaveBeenCalledWith("storage", expect.any(Function));
  });

  it("holds the choice in memory when storage is blocked", () => {
    mockSystemTheme(false);
    vi.spyOn(window.localStorage, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    const toggle = renderHook(() => useTheme());
    const palette = renderHook(() => useTheme());

    act(() => toggle.result.current.setTheme("dark"));

    expect(palette.result.current.theme).toBe("dark");
    expect(document.documentElement).toHaveClass("dark");
  });

  it("forgets the in-memory choice when the store is reset", () => {
    mockSystemTheme(false);
    vi.spyOn(window.localStorage, "setItem").mockImplementationOnce(() => {
      throw new Error("blocked");
    });
    const { result } = renderHook(() => useTheme());
    act(() => result.current.setTheme("dark"));
    expect(readStoredTheme()).toBe("dark");

    resetThemeStore();

    expect(readStoredTheme()).toBe("system");
  });
});

describe("the cross-fade on a manual change", () => {
  /** A startViewTransition that holds the update callback until the test runs it. */
  function mockViewTransition() {
    const pending: Array<() => void> = [];
    const start = vi.fn((update: () => void) => {
      pending.push(update);
      return { ready: Promise.resolve() };
    });
    document.startViewTransition = start as unknown as Document["startViewTransition"];
    return { start, flush: () => pending.splice(0).forEach((update) => update()) };
  }

  it("switches the theme inside the transition callback, not before", () => {
    mockSystemTheme(false);
    const transition = mockViewTransition();
    const { result } = renderHook(() => useTheme());

    act(() => result.current.setTheme("dark"));

    expect(transition.start).toHaveBeenCalledOnce();
    expect(document.documentElement).not.toHaveClass("dark");
    expect(result.current.theme).toBe("system");

    act(() => transition.flush());

    expect(document.documentElement).toHaveClass("dark");
    expect(result.current.theme).toBe("dark");
  });

  it("still saves the choice before the transition runs", () => {
    mockSystemTheme(false);
    mockViewTransition();
    const { result } = renderHook(() => useTheme());

    act(() => result.current.setTheme("dark"));

    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("dark");
  });

  it("is skipped when the person asks for reduced motion", () => {
    mockSystemTheme(false, true);
    const transition = mockViewTransition();
    const { result } = renderHook(() => useTheme());

    act(() => result.current.setTheme("dark"));

    expect(transition.start).not.toHaveBeenCalled();
    expect(document.documentElement).toHaveClass("dark");
  });

  it("is not used for the first paint or for a change the system makes", () => {
    const system = mockSystemTheme(false);
    const transition = mockViewTransition();
    window.localStorage.setItem(THEME_STORAGE_KEY, "dark");
    renderHook(() => useTheme());
    expect(document.documentElement).toHaveClass("dark");

    window.localStorage.setItem(THEME_STORAGE_KEY, "system");
    act(() => {
      window.dispatchEvent(new StorageEvent("storage", { key: THEME_STORAGE_KEY }));
    });
    act(() => system.setDark(true));

    expect(document.documentElement).toHaveClass("dark");
    expect(transition.start).not.toHaveBeenCalled();
  });

  it("does not leave a rejected promise behind when the browser skips the transition", async () => {
    mockSystemTheme(false);
    const rejected = Promise.reject(new DOMException("Skipped", "AbortError"));
    document.startViewTransition = (() => ({ ready: rejected })) as unknown as Document[
      "startViewTransition"
    ];
    const { result } = renderHook(() => useTheme());
    const unhandled = vi.fn();
    process.on("unhandledRejection", unhandled);

    act(() => result.current.setTheme("dark"));
    await new Promise((resolve) => setTimeout(resolve, 0));
    process.off("unhandledRejection", unhandled);

    expect(unhandled).not.toHaveBeenCalled();
  });
});
