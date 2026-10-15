import { MAX_PREFETCHES_IN_FLIGHT, PREFETCH_DWELL_MS } from "@/lib/usePrefetchOnIntent";
import { createTestQueryClient } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { PrefetchLink } from "./PrefetchLink";

let prefetch: ReturnType<typeof vi.fn>;
let pending: Array<() => void>;

beforeEach(() => {
  vi.useFakeTimers();
  pending = [];
  prefetch = vi.fn(() => new Promise<void>((resolve) => pending.push(resolve)));
});

afterEach(async () => {
  // The in-flight count is shared by every link, so a test must not leave a prefetch running.
  await act(async () => {
    for (const done of pending) done();
  });
  vi.useRealTimers();
  vi.unstubAllGlobals();
  Object.defineProperty(navigator, "connection", { value: undefined, configurable: true });
});

function renderLinks(count = 1) {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter>
        {Array.from(
          { length: count },
          (_, i) => <PrefetchLink key={i} to={`/f${i}`} warm={prefetch}>link {i}</PrefetchLink>,
        )}
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function hover(name: string, pointerType = "mouse") {
  fireEvent.pointerEnter(screen.getByRole("link", { name }), { pointerType });
}

function dwell() {
  act(() => {
    vi.advanceTimersByTime(PREFETCH_DWELL_MS);
  });
}

it("prefetches once the mouse has rested on the link for the dwell time", () => {
  renderLinks();
  hover("link 0");
  act(() => {
    vi.advanceTimersByTime(PREFETCH_DWELL_MS - 1);
  });
  expect(prefetch).not.toHaveBeenCalled();
  act(() => {
    vi.advanceTimersByTime(1);
  });
  expect(prefetch).toHaveBeenCalledTimes(1);
});

it("fetches nothing when the pointer sweeps past", () => {
  renderLinks();
  hover("link 0");
  fireEvent.pointerLeave(screen.getByRole("link", { name: "link 0" }));
  dwell();
  expect(prefetch).not.toHaveBeenCalled();
});

it("ignores touch and pen pointers", () => {
  renderLinks();
  hover("link 0", "touch");
  hover("link 0", "pen");
  dwell();
  expect(prefetch).not.toHaveBeenCalled();
});

it("drops the pending fetch when the link loses focus", () => {
  renderLinks();
  const link = screen.getByRole("link", { name: "link 0" });
  vi.spyOn(link, "matches").mockReturnValue(true);
  fireEvent.focus(link);
  fireEvent.blur(link);
  dwell();
  expect(prefetch).not.toHaveBeenCalled();
});

it("prefetches on keyboard focus but not on a mouse-click focus", () => {
  renderLinks();
  const link = screen.getByRole("link", { name: "link 0" });
  const matches = vi.spyOn(link, "matches").mockReturnValue(false);
  fireEvent.focus(link);
  dwell();
  expect(prefetch).not.toHaveBeenCalled();
  matches.mockReturnValue(true);
  fireEvent.focus(link);
  dwell();
  expect(prefetch).toHaveBeenCalledTimes(1);
});

it("does nothing when the browser asks to save data or reports a 2G connection", () => {
  renderLinks();
  Object.defineProperty(navigator, "connection", { value: { saveData: true }, configurable: true });
  hover("link 0");
  dwell();
  Object.defineProperty(navigator, "connection", {
    value: { saveData: false, effectiveType: "2g" },
    configurable: true,
  });
  hover("link 0");
  dwell();
  expect(prefetch).not.toHaveBeenCalled();
});

it("runs at most three prefetches at a time and frees a slot when one finishes", async () => {
  renderLinks(MAX_PREFETCHES_IN_FLIGHT + 1);
  for (let i = 0; i <= MAX_PREFETCHES_IN_FLIGHT; i++) {
    hover(`link ${i}`);
    dwell();
  }
  expect(prefetch).toHaveBeenCalledTimes(MAX_PREFETCHES_IN_FLIGHT);

  await act(async () => {
    pending[0]();
  });
  hover("link 3");
  dwell();
  expect(prefetch).toHaveBeenCalledTimes(MAX_PREFETCHES_IN_FLIGHT + 1);
});
