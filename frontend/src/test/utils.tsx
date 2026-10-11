import { createQueryClient } from "@/api/queryClient";
import type { QueryClient } from "@tanstack/react-query";
import { screen } from "@testing-library/react";
import type { UserEvent } from "@testing-library/user-event";

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

/**
 * The app's `QueryClient` without query retries, so tests fail fast on a mocked
 * fetch. Mutation success toasts still fire; they show when a test renders a Toaster.
 */
export function createTestQueryClient(): QueryClient {
  return createQueryClient(false);
}

/** Opens a dropdown (the Base UI Select) and picks the option with this visible label. */
export async function chooseOption(
  user: UserEvent,
  control: HTMLElement,
  label: string | RegExp,
): Promise<void> {
  await user.click(control);
  await user.click(await screen.findByRole("option", { name: label }));
}

/** The labels a dropdown offers, in order. The dropdown is left closed. */
export async function listOptions(
  user: UserEvent,
  control: HTMLElement,
): Promise<Array<string | null>> {
  await user.click(control);
  const labels = (await screen.findAllByRole("option")).map((o) => o.textContent);
  await user.keyboard("{Escape}");
  return labels;
}
