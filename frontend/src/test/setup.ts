import "@testing-library/jest-dom";
import { toast } from "sonner";
import { afterEach } from "vitest";

// Sonner keeps its toasts in a module-level store that outlives a test's Toaster, so a toast
// raised by one test would otherwise be on screen in the next.
afterEach(() => {
  toast.dismiss();
});

/**
 * Newer Node versions ship an experimental global `localStorage` that shadows
 * jsdom's and is unusable without a storage file (its methods are missing).
 * Provide an in-memory replacement only when the one in scope cannot be used,
 * so tests behave the same on every Node version.
 */
class MemoryStorage implements Storage {
  private readonly data = new Map<string, string>();

  get length(): number {
    return this.data.size;
  }

  clear(): void {
    this.data.clear();
  }

  getItem(key: string): string | null {
    return this.data.get(key) ?? null;
  }

  key(index: number): string | null {
    return [...this.data.keys()][index] ?? null;
  }

  removeItem(key: string): void {
    this.data.delete(key);
  }

  setItem(key: string, value: string): void {
    this.data.set(key, String(value));
  }
}

if (typeof globalThis.localStorage?.getItem !== "function") {
  const storage = new MemoryStorage();
  Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true });
  Object.defineProperty(window, "localStorage", { value: storage, configurable: true });
}
