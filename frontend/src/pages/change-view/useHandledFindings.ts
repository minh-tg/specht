import { useEffect, useState } from "react";

const STORAGE_PREFIX = "specht.change-handled.";

function read(scope: string): ReadonlySet<string> {
  try {
    const raw = sessionStorage.getItem(STORAGE_PREFIX + scope);
    const saved: unknown = raw ? JSON.parse(raw) : [];
    return new Set(
      Array.isArray(saved) ? saved.filter((id): id is string => typeof id === "string") : [],
    );
  } catch {
    return new Set();
  }
}

function write(scope: string, handled: ReadonlySet<string>): void {
  try {
    if (handled.size === 0) sessionStorage.removeItem(STORAGE_PREFIX + scope);
    else sessionStorage.setItem(STORAGE_PREFIX + scope, JSON.stringify([...handled]));
  } catch {
    // Storage is full or blocked: the list still works until the page reloads.
  }
}

/**
 * The findings a reader has ticked off on one commit's change page. It is the reader's own note, so
 * it lives in this tab and goes away with it. A newer commit starts empty, because its findings
 * are what the scanner says now.
 */
export function useHandledFindings(scope: string) {
  const [handled, setHandled] = useState<ReadonlySet<string>>(() => read(scope));
  useEffect(() => write(scope, handled), [scope, handled]);
  return [handled, setHandled] as const;
}
