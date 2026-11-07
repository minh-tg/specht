import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useHandledFindings } from "./useHandledFindings";

describe("useHandledFindings", () => {
  beforeEach(() => sessionStorage.clear());

  it("starts empty", () => {
    const { result } = renderHook(() => useHandledFindings("r1"));
    expect([...result.current[0]]).toEqual([]);
  });

  it("keeps what was ticked for the same report", () => {
    const first = renderHook(() => useHandledFindings("r1"));
    act(() => first.result.current[1](new Set(["f1", "f2"])));
    first.unmount();

    const again = renderHook(() => useHandledFindings("r1"));
    expect([...again.result.current[0]]).toEqual(["f1", "f2"]);
  });

  it("starts a newer report empty", () => {
    const first = renderHook(() => useHandledFindings("r1"));
    act(() => first.result.current[1](new Set(["f1"])));
    first.unmount();

    const newer = renderHook(() => useHandledFindings("r2"));
    expect([...newer.result.current[0]]).toEqual([]);
  });

  it("removes the entry once nothing is ticked", () => {
    const { result } = renderHook(() => useHandledFindings("r1"));
    act(() => result.current[1](new Set(["f1"])));
    act(() => result.current[1](new Set()));
    expect(sessionStorage.length).toBe(0);
  });

  it("ignores a saved value it cannot read", () => {
    sessionStorage.setItem("specht.change-handled.r1", "{not json");
    const { result: broken } = renderHook(() => useHandledFindings("r1"));
    expect([...broken.current[0]]).toEqual([]);

    sessionStorage.setItem("specht.change-handled.r2", JSON.stringify(["f1", 7, null]));
    const { result: mixed } = renderHook(() => useHandledFindings("r2"));
    expect([...mixed.current[0]]).toEqual(["f1"]);
  });

  it("still works when storage is blocked", () => {
    const denied = vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("denied", "SecurityError");
    });
    const { result } = renderHook(() => useHandledFindings("r1"));
    act(() => result.current[1](new Set(["f1"])));
    expect([...result.current[0]]).toEqual(["f1"]);
    denied.mockRestore();
  });
});
