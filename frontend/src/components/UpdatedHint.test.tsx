import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { UpdatedHint } from "./UpdatedHint";

let client: QueryClient;

beforeEach(() => {
  client = new QueryClient();
  vi.useFakeTimers({ shouldAdvanceTime: true });
});

afterEach(() => {
  vi.useRealTimers();
});

function hint(watch: readonly unknown[]) {
  return (
    <QueryClientProvider client={client}>
      <UpdatedHint updatedAt={Date.now()} watch={watch} isFetching={false} onRefresh={() => {}} />
    </QueryClientProvider>
  );
}

const status = () => screen.getByRole("status", { name: "Page updates" });

describe("UpdatedHint", () => {
  it("says \"New changes\" once when a refetch brings different data", () => {
    const { rerender } = render(hint([{ id: 1 }]));
    expect(status()).toHaveTextContent("");

    rerender(hint([{ id: 2 }]));

    expect(status()).toHaveTextContent("New changes");
  });

  it("stays quiet when the change follows the person's own save", async () => {
    const { rerender } = render(hint([{ id: 1 }]));
    await act(async () => {
      await client.getMutationCache().build(client, { mutationFn: async () => 1 }).execute(
        undefined,
      );
    });

    rerender(hint([{ id: 2 }]));

    expect(status()).toHaveTextContent("");
  });

  it("announces a change again once the person's own save is long past", async () => {
    const { rerender } = render(hint([{ id: 1 }]));
    await act(async () => {
      await client.getMutationCache().build(client, { mutationFn: async () => 1 }).execute(
        undefined,
      );
    });
    act(() => {
      vi.advanceTimersByTime(11_000);
    });

    rerender(hint([{ id: 2 }]));

    expect(status()).toHaveTextContent("New changes");
  });
});
