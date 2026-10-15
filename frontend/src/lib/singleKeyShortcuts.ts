import { useSyncExternalStore } from "react";

export const SINGLE_KEY_STORAGE_KEY = "specht.singlekeys";

// Storage can be blocked, so the choice also lives in memory for this page view.
let memory: boolean | null = null;
const listeners = new Set<() => void>();

function readEnabled(): boolean {
  try {
    const stored = window.localStorage.getItem(SINGLE_KEY_STORAGE_KEY);
    if (stored === "on") return true;
    if (stored === "off") return false;
    return memory ?? true;
  } catch {
    return memory ?? true;
  }
}

/**
 * Whether the shortcuts made of one character (`?` for the help sheet, `j`, `k` and `x` in a
 * findings list) are active. On by default; WCAG 2.1.4 requires a way to turn them off.
 */
export function isSingleKeyEnabled(): boolean {
  return readEnabled();
}

function notify() {
  for (const listener of listeners) listener();
}

export function setSingleKeyEnabled(on: boolean): void {
  memory = on;
  try {
    window.localStorage.setItem(SINGLE_KEY_STORAGE_KEY, on ? "on" : "off");
  } catch {
    // The choice then only lasts for this page view.
  }
  notify();
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  const onStorage = (event: StorageEvent) => {
    if (event.key === null || event.key === SINGLE_KEY_STORAGE_KEY) {
      memory = null;
      notify();
    }
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

/** The single-key preference, shared by every caller and followed across tabs. */
export function useSingleKeyEnabled(): boolean {
  return useSyncExternalStore(subscribe, readEnabled, () => true);
}

/** Test helper: forget the in-memory choice. */
export function resetSingleKeyForTests(): void {
  memory = null;
}
