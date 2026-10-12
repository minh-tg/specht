import { describe, expect, it } from "vitest";
import { durationLabel, intervalLabel, intervalOptions, STATUS } from "./watcherCopy";

describe("labels", () => {
  it("names a length of time in the largest whole unit", () => {
    expect(durationLabel(3600)).toBe("1 hour");
    expect(durationLabel(6 * 3600)).toBe("6 hours");
    expect(durationLabel(7 * 86400)).toBe("7 days");
    expect(durationLabel(90 * 60)).toBe("90 minutes");
    expect(durationLabel(45)).toBe("45 seconds");
  });

  it("says how often a poll runs", () => {
    expect(intervalLabel(3600)).toBe("every hour");
    expect(intervalLabel(86400)).toBe("every day");
    expect(intervalLabel(21600)).toBe("every 6 hours");
    expect(intervalLabel(2 * 86400)).toBe("every 2 days");
  });
});

describe("intervalOptions", () => {
  const range = { min_interval_seconds: 3600, max_interval_seconds: 604800 };

  it("offers the presets the server accepts, shortest first", () => {
    const options = intervalOptions({ ...range, interval_seconds: 3600 });
    expect(options.map((o) => o.label)).toEqual([
      "every hour",
      "every 6 hours",
      "every day",
      "every 7 days",
    ]);
  });

  it("leaves out a preset below the server's floor", () => {
    const options = intervalOptions({
      min_interval_seconds: 6 * 3600,
      max_interval_seconds: 604800,
      interval_seconds: 6 * 3600,
    });
    expect(options.map((o) => o.value)).toEqual(["21600", "86400", "604800"]);
  });

  it("keeps the project's own interval when it is not a preset", () => {
    const options = intervalOptions({ ...range, interval_seconds: 2 * 3600 });
    expect(options.map((o) => o.label)).toEqual([
      "every hour",
      "every 2 hours",
      "every 6 hours",
      "every day",
      "every 7 days",
    ]);
  });
});

describe("STATUS", () => {
  it("explains every state that needs explaining, and flags only the real problems", () => {
    expect(STATUS.ok.notice).toBeUndefined();
    expect(STATUS.disabled.notice).toBeUndefined();
    expect(STATUS.stale.problem).toBe(true);
    expect(STATUS.failing.problem).toBe(true);
    expect(STATUS.server_off.notice).toMatch(/takes effect when the server runs it/);
    expect(STATUS.server_off.problem).toBeUndefined();
    expect(STATUS.waiting.problem).toBeUndefined();
  });
});
