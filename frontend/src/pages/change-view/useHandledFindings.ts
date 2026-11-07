import { useEffect, useState } from "react";

const STORAGE_PREFIX = "specht.change-handled.";

function read(reportId: string): ReadonlySet<string> {
  try {
    const raw = sessionStorage.getItem(STORAGE_PREFIX + reportId);
    const saved: unknown = raw ? JSON.parse(raw) : [];
    return new Set(
      Array.isArray(saved) ? saved.filter((id): id is string => typeof id === "string") : [],
    );
  } catch {
    return new Set();
  }
}

function write(reportId: string, handled: ReadonlySet<string>): void {
  try {
    if (handled.size === 0) sessionStorage.removeItem(STORAGE_PREFIX + reportId);
    else sessionStorage.setItem(STORAGE_PREFIX + reportId, JSON.stringify([...handled]));
  } catch {
    // Storage is full or blocked: the list still works until the page reloads.
  }
}

/**
 * The findings a reader has ticked off on one report's change page. It is the reader's own note, so
 * it lives in this tab and goes away with it. A newer report starts empty, because its findings
 * are what the scanner says now.
 */
export function useHandledFindings(reportId: string) {
  const [handled, setHandled] = useState<ReadonlySet<string>>(() => read(reportId));
  useEffect(() => write(reportId, handled), [reportId, handled]);
  return [handled, setHandled] as const;
}
