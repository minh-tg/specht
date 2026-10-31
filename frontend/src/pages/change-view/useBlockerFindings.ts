import { findingQueryOptions } from "@/api/hooks";
import type { Finding } from "@/types/api";
import { useQueries } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";

/**
 * Most finding requests in flight at once. The findings list cannot return several findings by id
 * (it filters by severity, status, kind and so on, not by id), so the change view reads each
 * blocker from `GET /findings/{id}` and keeps this many going, starting the next as one settles.
 */
export const FINDING_FETCH_WINDOW = 6;

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
  }, [ids, settled, dataKey, errorKey]);
}
