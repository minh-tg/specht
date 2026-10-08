import { QueryClient } from "@tanstack/react-query";

/** Statuses the `Response` constructor refuses to pair with a body. */
const NULL_BODY_STATUSES = new Set([204, 205, 304]);

/**
 * Builds a real JSON `Response`, for fetch mocks in tests.
 *
 * A status that cannot carry a body (204, 205, 304) yields a bodyless response
 * for a `null` or `undefined` body and throws for anything else, instead of
 * the opaque `TypeError` the `Response` constructor would raise.
 */
export function jsonResponse(body: unknown, status = 200): Response {
  if (NULL_BODY_STATUSES.has(status)) {
    if (body !== null && body !== undefined) {
      throw new Error(`jsonResponse: status ${status} cannot carry a body`);
    }
    return new Response(null, { status });
  }
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** A `QueryClient` that never retries, so tests fail fast on a mocked fetch. */
export function createTestQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}
