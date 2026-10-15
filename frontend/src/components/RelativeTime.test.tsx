import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RelativeTime } from "./RelativeTime";

const NOW = new Date("2026-10-15T12:00:00Z");
const ago = (ms: number) => new Date(NOW.getTime() - ms).toISOString();
const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

function setHidden(hidden: boolean) {
  Object.defineProperty(document, "hidden", { configurable: true, value: hidden });
  document.dispatchEvent(new Event("visibilitychange"));
}

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
});

afterEach(() => {
  setHidden(false);
  vi.useRealTimers();
});

describe("RelativeTime", () => {
  it("renders a time element with the exact local time in the title", () => {
    render(<RelativeTime iso={ago(3 * HOUR)} />);
    const el = screen.getByText("3 h ago");
    expect(el.tagName).toBe("TIME");
    expect(el).toHaveAttribute("datetime", ago(3 * HOUR));
    expect(el.getAttribute("title")).toMatch(/2026/);
  });

  it.each([
    [30 * 1000, "just now"],
    [59 * MIN, "59 min ago"],
    [HOUR, "1 h ago"],
    [30 * DAY, "30 d ago"],
  ])("keeps the existing wording at %i ms", (offset, text) => {
    render(<RelativeTime iso={ago(offset)} />);
    expect(screen.getByText(text)).toBeInTheDocument();
  });

  it("falls back to a date after 30 days", () => {
    render(<RelativeTime iso={ago(31 * DAY)} />);
    expect(screen.getByRole("time")).toHaveTextContent(/2026/);
  });

  it("renders the empty value, not a time element, for missing or invalid input", () => {
    const { rerender } = render(<RelativeTime iso={undefined} />);
    expect(screen.queryByRole("time")).toBeNull();
    expect(document.body).toHaveTextContent("None");
    rerender(<RelativeTime iso="not a date" />);
    expect(screen.queryByRole("time")).toBeNull();
  });

  it("refreshes once a minute", () => {
    render(<RelativeTime iso={ago(30 * 1000)} />);
    expect(screen.getByText("just now")).toBeInTheDocument();
    act(() => {
      vi.advanceTimersByTime(MIN);
    });
    expect(screen.getByText("1 min ago")).toBeInTheDocument();
  });

  it("runs one timer for many rows and clears it on unmount", () => {
    const set = vi.spyOn(globalThis, "setInterval");
    const clear = vi.spyOn(globalThis, "clearInterval");
    const { unmount } = render(
      <>
        <RelativeTime iso={ago(MIN)} />
        <RelativeTime iso={ago(2 * MIN)} />
        <RelativeTime iso={ago(3 * MIN)} />
      </>,
    );
    expect(set).toHaveBeenCalledTimes(1);
    unmount();
    expect(clear).toHaveBeenCalledTimes(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("pauses while the tab is hidden and catches up when it is shown", () => {
    render(<RelativeTime iso={ago(30 * 1000)} />);
    act(() => setHidden(true));
    expect(vi.getTimerCount()).toBe(0);
    act(() => {
      vi.setSystemTime(new Date(NOW.getTime() + 5 * MIN));
      setHidden(false);
    });
    expect(screen.getByText("5 min ago")).toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(1);
  });

  it("starts no timer when it mounts in a hidden tab", () => {
    Object.defineProperty(document, "hidden", { configurable: true, value: true });
    render(<RelativeTime iso={ago(MIN)} />);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("starts no timer when frozen or given a fixed now", () => {
    render(
      <>
        <RelativeTime iso={ago(HOUR)} frozen />
        <RelativeTime iso={ago(2 * HOUR)} now={NOW} />
      </>,
    );
    expect(screen.getByText("1 h ago")).toBeInTheDocument();
    expect(screen.getByText("2 h ago")).toBeInTheDocument();
    expect(vi.getTimerCount()).toBe(0);
  });
});
