import { beforeEach, describe, expect, it, vi } from "vitest";

const success = vi.hoisted(() => vi.fn());
vi.mock("sonner", () => ({ toast: { success } }));

import { announceMutationSuccess, createQueryClient } from "./queryClient";

beforeEach(() => {
  success.mockClear();
});

describe("announceMutationSuccess", () => {
  it("shows a fixed message", () => {
    announceMutationSuccess("Member added", {}, {});
    expect(success).toHaveBeenCalledExactlyOnceWith("Member added");
  });

  it("builds the message from the response and the variables", () => {
    announceMutationSuccess(
      ((data: { effect: string; }, vars: { id: string; }) => `${vars.id}: ${data.effect}`) as (
        data: never,
        variables: never,
      ) => string,
      { effect: "blocks" },
      { id: "f1" },
    );
    expect(success).toHaveBeenCalledExactlyOnceWith("f1: blocks");
  });

  it("stays silent when the mutation declared no message", () => {
    announceMutationSuccess(undefined, {}, {});
    expect(success).not.toHaveBeenCalled();
  });
});

describe("createQueryClient", () => {
  it("announces a successful mutation that declares meta.success", async () => {
    const client = createQueryClient(false);
    await client.getMutationCache()
      .build(client, { mutationFn: async () => ({ ok: true }), meta: { success: "Team created" } })
      .execute(undefined);
    expect(success).toHaveBeenCalledExactlyOnceWith("Team created");
  });

  it("does not announce a failed mutation", async () => {
    const client = createQueryClient(false);
    await client.getMutationCache()
      .build(client, {
        mutationFn: async () => {
          throw new Error("nope");
        },
        meta: { success: "Team created" },
      })
      .execute(undefined)
      .catch(() => undefined);
    expect(success).not.toHaveBeenCalled();
  });

  it("does not announce a mutation without meta", async () => {
    const client = createQueryClient(false);
    await client.getMutationCache()
      .build(client, { mutationFn: async () => 1 })
      .execute(undefined);
    expect(success).not.toHaveBeenCalled();
  });
});
