import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useDelayedFlag } from "./useDelayedFlag";

afterEach(() => {
  vi.useRealTimers();
});

describe("useDelayedFlag", () => {
  it("is false until the delay has passed", () => {
    vi.useFakeTimers();
    const { result } = renderHook(() => useDelayedFlag(300));
    expect(result.current).toBe(false);

    act(() => {
      vi.advanceTimersByTime(299);
    });
    expect(result.current).toBe(false);

    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(result.current).toBe(true);
  });
});
