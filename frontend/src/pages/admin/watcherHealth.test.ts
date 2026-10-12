import type { WatcherHealth } from "@/types/api";
import { describe, expect, it } from "vitest";
import { watcherHealthState } from "./watcherHealth";

const base: WatcherHealth = {
  consecutive_failures: 0,
  healthy: true,
  stale: false,
  last_successful_poll_at: "2026-10-12T10:00:00Z",
};

describe("watcherHealthState", () => {
  it("is healthy after a good poll with nothing wrong", () => {
    expect(watcherHealthState(base)).toEqual({ label: "Healthy", tone: "ok" });
  });

  it("is failing whenever polls are failing, even if the last good one is old", () => {
    expect(watcherHealthState({ ...base, consecutive_failures: 2, stale: true })).toEqual({
      label: "Failing",
      tone: "bad",
    });
  });

  it("is stale when the last poll is older than expected", () => {
    expect(watcherHealthState({ ...base, stale: true })).toEqual({ label: "Stale", tone: "warn" });
  });

  it("is not healthy before any poll has succeeded", () => {
    expect(watcherHealthState({ ...base, last_successful_poll_at: undefined })).toEqual({
      label: "No poll yet",
      tone: "off",
    });
  });
});
