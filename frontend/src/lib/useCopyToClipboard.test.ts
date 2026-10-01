import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { useCopyToClipboard } from "./useCopyToClipboard";

function stubClipboard(writeText: (text: string) => Promise<void>) {
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText } });
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  // @ts-expect-error remove the test double again
  delete navigator.clipboard;
});

it("reports copied only after the write resolves, then returns to idle", async () => {
  const writeText = vi.fn().mockResolvedValue(undefined);
  stubClipboard(writeText);
  const { result } = renderHook(() => useCopyToClipboard());
  expect(result.current.status).toBe("idle");

  let ok = false;
  await act(async () => {
    ok = await result.current.copy("secret");
  });

  expect(ok).toBe(true);
  expect(writeText).toHaveBeenCalledWith("secret");
  expect(result.current.status).toBe("copied");

  act(() => vi.advanceTimersByTime(2100));
  expect(result.current.status).toBe("idle");
});

it("reports a failure when the clipboard write rejects", async () => {
  stubClipboard(vi.fn().mockRejectedValue(new DOMException("denied", "NotAllowedError")));
  const { result } = renderHook(() => useCopyToClipboard());

  let ok = true;
  await act(async () => {
    ok = await result.current.copy("secret");
  });

  expect(ok).toBe(false);
  expect(result.current.status).toBe("failed");
});

it("reports a failure when the clipboard API does not exist", async () => {
  const { result } = renderHook(() => useCopyToClipboard());

  let ok = true;
  await act(async () => {
    ok = await result.current.copy("secret");
  });

  expect(ok).toBe(false);
  expect(result.current.status).toBe("failed");
});

it("keeps a failure on screen longer than a success", async () => {
  stubClipboard(vi.fn().mockRejectedValue(new Error("denied")));
  const { result } = renderHook(() => useCopyToClipboard());

  await act(async () => {
    await result.current.copy("secret");
  });
  act(() => vi.advanceTimersByTime(3000));
  expect(result.current.status).toBe("failed");

  act(() => vi.advanceTimersByTime(3100));
  expect(result.current.status).toBe("idle");
});

it("clears its timer when it unmounts", async () => {
  stubClipboard(vi.fn().mockResolvedValue(undefined));
  const { result, unmount } = renderHook(() => useCopyToClipboard());
  await act(async () => {
    await result.current.copy("secret");
  });

  unmount();

  expect(vi.getTimerCount()).toBe(0);
});
