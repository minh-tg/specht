import { QueryClient } from "@tanstack/react-query";

/** Builds a real JSON `Response`, for fetch mocks in tests. */
export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** A `QueryClient` that never retries, so tests fail fast on a mocked fetch. */
export function createTestQueryClient(): QueryClient {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}
