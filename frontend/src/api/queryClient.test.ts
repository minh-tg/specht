import { readdirSync, readFileSync } from "node:fs";
import { beforeEach, describe, expect, it, vi } from "vitest";

const success = vi.hoisted(() => vi.fn());
vi.mock("sonner", () => ({ toast: { success } }));

const playCue = vi.hoisted(() => vi.fn());
vi.mock("@/lib/sound", () => ({ playCue }));

import { APIError } from "./client";
import { announceMutationSuccess, createQueryClient } from "./queryClient";

beforeEach(() => {
  success.mockClear();
  playCue.mockClear();
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
    expect(playCue).not.toHaveBeenCalled();
  });

  it("plays the accepted cue once per toast", () => {
    announceMutationSuccess("Member added", {}, {});
    expect(playCue).toHaveBeenCalledExactlyOnceWith("accepted");
  });

  it("keeps the toast but plays no cue when the mutation declared sound none", () => {
    announceMutationSuccess("Team deleted", {}, {}, "none");
    expect(success).toHaveBeenCalledExactlyOnceWith("Team deleted");
    expect(playCue).not.toHaveBeenCalled();
  });

  it("lets sound depend on the response and the variables", () => {
    const sound =
      ((_data: unknown, vars: { active: boolean; }) => vars.active ? undefined : "none") as (
        data: never,
        variables: never,
      ) => "none" | undefined;
    announceMutationSuccess("Account deactivated", {}, { active: false }, sound);
    expect(playCue).not.toHaveBeenCalled();
    announceMutationSuccess("Account reactivated", {}, { active: true }, sound);
    expect(playCue).toHaveBeenCalledExactlyOnceWith("accepted");
  });
});

describe("mutation sound rules", () => {
  async function run(meta: { success: string; sound?: "none"; }) {
    const client = createQueryClient(false);
    await client.getMutationCache()
      .build(client, { mutationFn: async () => ({}), meta })
      .execute(undefined);
  }

  it("plays no cue after a deleting mutation", async () => {
    await run({ success: "Team deleted", sound: "none" });
    expect(success).toHaveBeenCalledExactlyOnceWith("Team deleted");
    expect(playCue).not.toHaveBeenCalled();
  });

  it("plays accepted after a creating mutation", async () => {
    await run({ success: "Team created" });
    expect(playCue).toHaveBeenCalledExactlyOnceWith("accepted");
  });

  it("silences every mutation whose toast reports a removal", () => {
    const removal = /deleted|removed|revoked|unlinked|withdrawn|deactivated/i;
    const dir = `${process.cwd()}/src/api/`;
    const loud: string[] = [];
    for (const file of readdirSync(dir)) {
      if (!/\.tsx?$/.test(file) || /\.test\./.test(file)) continue;
      const source = readFileSync(dir + file, "utf8");
      for (const block of source.matchAll(/meta: \{[\s\S]*?\n\s*\},?|meta: \{[^\n]*\}/g)) {
        if (removal.test(block[0]) && !/sound:/.test(block[0])) loud.push(`${file}: ${block[0]}`);
      }
    }
    expect(loud).toEqual([]);
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

  async function fail(error: Error, meta?: { success: string; }) {
    const client = createQueryClient(false);
    await client.getMutationCache()
      .build(client, {
        mutationFn: async () => {
          throw error;
        },
        meta,
      })
      .execute(undefined)
      .catch(() => undefined);
  }

  it("plays the error cue for a failed mutation that declares meta.success", async () => {
    await fail(new Error("nope"), { success: "Team created" });
    expect(playCue).toHaveBeenCalledExactlyOnceWith("error");
  });

  it("plays no cue for a failed mutation without meta.success", async () => {
    await fail(new Error("nope"));
    expect(playCue).not.toHaveBeenCalled();
  });

  it("plays no error cue for a 401", async () => {
    await fail(new APIError(401, "unauthorized", "Session expired"), { success: "Saved" });
    expect(playCue).not.toHaveBeenCalled();
  });

  it("still plays the error cue for other API errors", async () => {
    await fail(new APIError(403, "forbidden", "No"), { success: "Saved" });
    expect(playCue).toHaveBeenCalledExactlyOnceWith("error");
  });
});
