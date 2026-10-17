import { APIError } from "@/api/client";
import { useEffect, useRef, useState } from "react";

/** The wait a `too_many_attempts` response asks for, in whole seconds rounded up. Null when
 * the error is anything else or carries no `Retry-After`, so the page keeps its own message. */
export function tooManyAttemptsWait(err: unknown): number | null {
  if (!(err instanceof APIError) || err.code !== "too_many_attempts") return null;
  if (err.retryAfter === undefined) return null;
  return Math.ceil(err.retryAfter);
}

/** The wait as the copy says it. From 60 seconds up it is whole minutes, rounded up so the
 * text never names a time shorter than the real wait. */
export function waitPhrase(seconds: number): string {
  if (seconds >= 60) {
    const minutes = Math.ceil(seconds / 60);
    return minutes === 1 ? "1 minute" : `${minutes} minutes`;
  }
  return seconds === 1 ? "1 second" : `${seconds} seconds`;
}

export function tooManyAttemptsMessage(seconds: number): string {
  return `Too many attempts. Try again in ${waitPhrase(seconds)}.`;
}

/** Holds a submit button disabled for a server-set wait, then calls `onEnd`. The wait only
 * ends the lock; nothing retries the request, so the user submits again by hand. */
export function useRetryWait(
  onEnd: () => void,
): { waiting: boolean; start: (seconds: number) => void; } {
  const [retryAt, setRetryAt] = useState<number | null>(null);
  const onEndRef = useRef(onEnd);

  useEffect(() => {
    onEndRef.current = onEnd;
  });

  useEffect(() => {
    if (retryAt === null) return;
    const timer = setTimeout(() => {
      setRetryAt(null);
      onEndRef.current();
    }, Math.max(0, retryAt - Date.now()));
    return () => clearTimeout(timer);
  }, [retryAt]);

  return {
    waiting: retryAt !== null,
    start: (seconds) => setRetryAt(Date.now() + seconds * 1000),
  };
}
