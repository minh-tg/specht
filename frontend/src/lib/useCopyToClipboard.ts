import { useCallback, useEffect, useRef, useState } from "react";

export type CopyStatus = "idle" | "copied" | "failed";

/**
 * Copies text to the clipboard and reports whether it actually worked.
 *
 * The clipboard API can be missing (an insecure context) or can reject
 * (permission denied, a browser's user-gesture rules), so success is only
 * claimed after the write resolves. The status returns to "idle" after a
 * while; a failure stays visible longer so it can be read.
 */
export function useCopyToClipboard(): {
  status: CopyStatus;
  copy: (text: string) => Promise<boolean>;
} {
  const [status, setStatus] = useState<CopyStatus>("idle");
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = useCallback(async (text: string): Promise<boolean> => {
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      ok = false;
    }
    setStatus(ok ? "copied" : "failed");
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setStatus("idle"), ok ? 2000 : 6000);
    return ok;
  }, []);

  return { status, copy };
}
