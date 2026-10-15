import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  isSingleKeyEnabled,
  resetSingleKeyForTests,
  setSingleKeyEnabled,
  SINGLE_KEY_STORAGE_KEY,
  useSingleKeyEnabled,
} from "./singleKeyShortcuts";

beforeEach(() => {
  window.localStorage.clear();
  resetSingleKeyForTests();
  vi.restoreAllMocks();
});

describe("single-key shortcut setting", () => {
  it("is on by default", () => {
    expect(isSingleKeyEnabled()).toBe(true);
  });

  it("stores off and on", () => {
    setSingleKeyEnabled(false);
    expect(window.localStorage.getItem(SINGLE_KEY_STORAGE_KEY)).toBe("off");
    expect(isSingleKeyEnabled()).toBe(false);
    setSingleKeyEnabled(true);
    expect(window.localStorage.getItem(SINGLE_KEY_STORAGE_KEY)).toBe("on");
    expect(isSingleKeyEnabled()).toBe(true);
  });

  it("reads a stored off after a reload", () => {
    window.localStorage.setItem(SINGLE_KEY_STORAGE_KEY, "off");
    expect(isSingleKeyEnabled()).toBe(false);
  });

  it("ignores a stored value it does not know", () => {
    window.localStorage.setItem(SINGLE_KEY_STORAGE_KEY, "maybe");
    expect(isSingleKeyEnabled()).toBe(true);
  });

  it("keeps the choice for the page view when storage throws", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("blocked");
    });
    expect(isSingleKeyEnabled()).toBe(true);
    setSingleKeyEnabled(false);
    expect(isSingleKeyEnabled()).toBe(false);
  });

  it("updates subscribers and follows another tab through the storage event", () => {
    const { result } = renderHook(() => useSingleKeyEnabled());
    expect(result.current).toBe(true);
    act(() => setSingleKeyEnabled(false));
    expect(result.current).toBe(false);

    act(() => {
      window.localStorage.setItem(SINGLE_KEY_STORAGE_KEY, "on");
      window.dispatchEvent(new StorageEvent("storage", { key: SINGLE_KEY_STORAGE_KEY }));
    });
    expect(result.current).toBe(true);
  });

  it("ignores storage events for other keys", () => {
    const { result } = renderHook(() => useSingleKeyEnabled());
    act(() => setSingleKeyEnabled(false));
    act(() => {
      window.localStorage.setItem(SINGLE_KEY_STORAGE_KEY, "on");
      window.dispatchEvent(new StorageEvent("storage", { key: "other" }));
    });
    expect(result.current).toBe(false);
  });
});
