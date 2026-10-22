import type { LoginResponse } from "@/types/api";
import { describe, expect, it, vi } from "vitest";
import { createRefreshBroker } from "./refreshBroker";

function session(n: number): LoginResponse {
  return {
    token: `access-${n}`,
    refresh_token: `refresh-${n}`,
    user_id: "u1",
    email: "u1@example.com",
  };
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}

describe("refresh broker", () => {
  it("coalesces concurrent tabs and resolves a late copied token without replay", async () => {
    const held = deferred<LoginResponse>();
    const refresh = vi.fn().mockReturnValueOnce(held.promise).mockResolvedValueOnce(session(3));
    const broker = createRefreshBroker(refresh);
    const requests = Array.from({ length: 20 }, () => broker.rotate("refresh-1"));
    expect(refresh).toHaveBeenCalledTimes(1);
    held.resolve(session(2));
    expect(await Promise.all(requests)).toEqual(Array.from({ length: 20 }, () => session(2)));
    expect(await broker.rotate("refresh-1")).toEqual(session(2));
    expect(refresh).toHaveBeenCalledTimes(1);
    expect(await broker.rotate("refresh-2")).toEqual(session(3));
    expect(await broker.rotate("refresh-1")).toEqual(session(3));
    expect(await broker.rotate("refresh-2")).toEqual(session(3));
    expect(refresh.mock.calls).toEqual([["refresh-1"], ["refresh-2"]]);
  });

  it("accepts peer rotations without allowing a late ancestor to replace them", async () => {
    const refresh = vi.fn();
    const broker = createRefreshBroker(refresh);
    broker.adopt("refresh-1", session(2));
    broker.adopt("refresh-2", session(3));
    broker.adopt("refresh-1", session(2));
    expect(broker.peek("refresh-1")).toEqual(session(3));
    expect(await broker.rotate("refresh-2")).toEqual(session(3));
    expect(refresh).not.toHaveBeenCalled();
  });

  it("does not merge unrelated logins", async () => {
    const refresh = vi.fn().mockResolvedValueOnce(session(2)).mockResolvedValueOnce({
      ...session(2),
      user_id: "u2",
    });
    const broker = createRefreshBroker(refresh);
    await broker.rotate("login-a");
    const other = await broker.rotate("login-b");
    expect(other.user_id).toBe("u2");
    expect(refresh).toHaveBeenCalledTimes(2);
  });

  it("propagates a shared failure to every waiting tab", async () => {
    const error = new Error("refresh rejected");
    const refresh = vi.fn().mockRejectedValue(error);
    const broker = createRefreshBroker(refresh);
    const outcomes = await Promise.allSettled([broker.rotate("r1"), broker.rotate("r1")]);
    expect(outcomes).toEqual([{ status: "rejected", reason: error }, {
      status: "rejected",
      reason: error,
    }]);
    expect(refresh).toHaveBeenCalledTimes(1);
  });

  it("forgets every alias on logout and rejects a pending response", async () => {
    const held = deferred<LoginResponse>();
    const refresh = vi.fn().mockResolvedValueOnce(session(2)).mockReturnValueOnce(held.promise)
      .mockResolvedValueOnce(session(4));
    const broker = createRefreshBroker(refresh);
    await broker.rotate("refresh-1");
    const pending = broker.rotate("refresh-2");
    broker.forget("refresh-1");
    held.resolve(session(3));
    await expect(pending).rejects.toThrow("session ended");
    await broker.rotate("refresh-1");
    expect(refresh.mock.calls).toEqual([["refresh-1"], ["refresh-2"], ["refresh-1"]]);
  });
});
