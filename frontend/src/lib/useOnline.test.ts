import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useOnline } from "./useOnline";

function setOnLine(value: boolean) {
  vi.spyOn(navigator, "onLine", "get").mockReturnValue(value);
  window.dispatchEvent(new Event(value ? "online" : "offline"));
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useOnline", () => {
  it("starts from navigator.onLine", () => {
    vi.spyOn(navigator, "onLine", "get").mockReturnValue(false);
    const { result } = renderHook(() => useOnline());

    expect(result.current).toBe(false);
  });

  it("follows the offline and online events", () => {
    const { result } = renderHook(() => useOnline());
    expect(result.current).toBe(true);

    act(() => setOnLine(false));
    expect(result.current).toBe(false);

    act(() => setOnLine(true));
    expect(result.current).toBe(true);
  });
});
