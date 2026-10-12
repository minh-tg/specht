import { describe, expect, it } from "vitest";
import { latestFailure } from "./latestFailure";

const failed = (at: number, message = "no") => ({
  isError: true,
  error: new Error(message),
  submittedAt: at,
});
const ok = (at: number) => ({ isError: false, error: null, submittedAt: at });
const idle = ok(0);

describe("latestFailure", () => {
  it("shows nothing when nothing has run", () => {
    expect(latestFailure(idle, idle)).toBeNull();
  });

  it("shows the failure of the last action", () => {
    expect(latestFailure(ok(1), failed(2, "refused"))?.message).toBe("refused");
  });

  it("drops an older failure once a later action succeeded", () => {
    expect(latestFailure(failed(1), ok(2))).toBeNull();
  });

  it("shows the newer of two failures", () => {
    expect(latestFailure(failed(1, "old"), failed(2, "new"))?.message).toBe("new");
  });
});
