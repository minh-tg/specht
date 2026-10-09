import { APIError } from "./client";

/** Two retries for failed queries, except client errors (4xx). A 4xx means the
 * request itself is wrong or not allowed, so retrying only delays the error. */
const MAX_QUERY_RETRIES = 2;

/** React Query's `retry` predicate. `failureCount` counts the failures before
 * this one, so the first failure arrives as 0. */
export function shouldRetryQuery(failureCount: number, error: unknown): boolean {
  if (error instanceof APIError && error.status >= 400 && error.status < 500) {
    return false;
  }
  return failureCount < MAX_QUERY_RETRIES;
}
