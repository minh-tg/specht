import { APIError } from "@/api/client";
import { findingQueryOptions } from "@/api/hooks";
import { shouldRetryQuery } from "@/api/retry";
import type { Finding } from "@/types/api";
import { useQueries } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";

/**
 * Most finding requests in flight at once. The findings list cannot return several findings by id
 * (it filters by severity, status, kind and so on, not by id), so the change view reads each
 * blocker from `GET /findings/{id}` and keeps this many going, starting the next as one settles.
 * Production allows a client 10 requests a second with a burst of 20, and the page makes others, so
 * the window stays small.
 */
export const FINDING_FETCH_WINDOW = 4;

/** Times a finding request is repeated after the server says to slow down (HTTP 429). */
export const RATE_LIMIT_RETRIES = 4;
/** The first wait after a 429 with no `Retry-After`; each further wait doubles. */
export const RATE_LIMIT_BASE_DELAY_MS = 1000;
/** The longest wait between two tries, whatever `Retry-After` asks for. */
export const RATE_LIMIT_MAX_DELAY_MS = 15_000;

function isRateLimited(error: unknown): error is APIError {
  return error instanceof APIError && error.status === 429;
}

/**
 * A 429 is the server pacing the page, not a failure, so it is tried again a few times. Any other
 * error follows the app's usual rule (client errors are final, server errors get two more tries).
 */
export function retryFindingRequest(failureCount: number, error: unknown): boolean {
  if (isRateLimited(error)) return failureCount < RATE_LIMIT_RETRIES;
  return shouldRetryQuery(failureCount, error);
}

/** How long to wait before the next try: `Retry-After` when sent, else 1 s doubling to a cap. */
export function findingRetryDelay(failureCount: number, error: unknown): number {
  if (isRateLimited(error) && error.retryAfter !== undefined) {
    return Math.min(error.retryAfter * 1000, RATE_LIMIT_MAX_DELAY_MS);
  }
  return Math.min(RATE_LIMIT_BASE_DELAY_MS * 2 ** failureCount, RATE_LIMIT_MAX_DELAY_MS);
}

export interface BlockerFindings {
  /** The loaded findings by id. */
  readonly byId: ReadonlyMap<string, Finding>;
  /** Per id, in the order given: the finding once loaded, absent while loading or after a failure. */
  readonly list: readonly (Finding | undefined)[];
  /** Per id: the request has not finished. */
  readonly pending: readonly boolean[];
  /** Per id: the request failed. */
  readonly failed: readonly boolean[];
  /** Ids whose request failed, in order. */
  readonly failedIds: readonly string[];
  /** Requests that have finished, loaded or failed. */
  readonly settled: number;
  readonly total: number;
  /** Every request has finished, so the whole list is known. */
  readonly done: boolean;
  /** The server asked the page to slow down and a request is waiting to try again. */
  readonly waiting: boolean;
  /** Fetches one finding again. */
  readonly retry: (id: string) => void;
  /** Fetches again every finding that failed. */
  readonly retryFailed: () => void;
}

/**
 * Loads every blocking finding, a few at a time. The queries share the cache entry of `useFinding`,
 * so a finding opened from here is already there. A failure is kept per finding: the rest of the
 * list loads, and the caller says which ones failed and offers a retry.
 */
export function useBlockerFindings(ids: readonly string[]): BlockerFindings {
  const [allowed, setAllowed] = useState(FINDING_FETCH_WINDOW);
  const results = useQueries({
    queries: ids.map((id, index) => ({
      ...findingQueryOptions(id),
      enabled: !!id && index < allowed,
      retry: retryFindingRequest,
      retryDelay: findingRetryDelay,
    })),
  });

  const settled = results.filter((result) => !result.isPending).length;
  useEffect(() => {
    const next = Math.min(ids.length, settled + FINDING_FETCH_WINDOW);
    setAllowed((current) => (next > current ? next : current));
  }, [settled, ids.length]);

  // `results` is a new array on every render, so the memo is keyed on what it reads from it.
  const dataKey = results.map((result) => result.dataUpdatedAt).join(",");
  const errorKey = results.map((result) => (result.isError ? "1" : "0")).join("");
  const waiting = results.some((result) => result.isPending && isRateLimited(result.failureReason));
  const refetchers = results.map((result) => result.refetch);
  return useMemo(() => {
    const list = results.map((result) => result.data);
    const failed = results.map((result) => result.isError);
    const byId = new Map<string, Finding>();
    ids.forEach((id, index) => {
      const finding = list[index];
      if (finding) byId.set(id, finding);
    });
    return {
      byId,
      list,
      pending: results.map((result) => result.isPending),
      failed,
      failedIds: ids.filter((_, index) => failed[index]),
      settled,
      total: ids.length,
      done: settled >= ids.length,
      waiting,
      retry: (id: string) => {
        const index = ids.indexOf(id);
        if (index >= 0) void refetchers[index]();
      },
      retryFailed: () => {
        failed.forEach((isFailed, index) => {
          if (isFailed) void refetchers[index]();
        });
      },
    };
    // oxlint-disable-next-line react-hooks/exhaustive-deps
  }, [ids, settled, dataKey, errorKey, waiting]);
}
