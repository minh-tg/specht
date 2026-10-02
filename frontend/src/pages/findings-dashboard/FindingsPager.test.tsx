import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { FindingsPager } from "./FindingsPager";

function renderPager(overrides: Partial<Parameters<typeof FindingsPager>[0]> = {}) {
  const handlers = {
    onPrevious: vi.fn(),
    onNext: vi.fn(),
    onFirst: vi.fn(),
  };
  const props = {
    offset: 0,
    pageSize: 20,
    rowCount: 20,
    total: null as number | null,
    ...handlers,
    ...overrides,
  };
  render(<FindingsPager {...props} />);
  return handlers;
}

describe("FindingsPager", () => {
  it("labels the current range with the filtered total", () => {
    renderPager({ offset: 20, rowCount: 20, total: 45 });

    expect(screen.getByText("21–40 of 45")).toBeInTheDocument();
  });

  it("falls back to the bare range when the total is unknown", () => {
    renderPager({ offset: 20, rowCount: 20, total: null });

    expect(screen.getByText("21–40")).toBeInTheDocument();
  });

  it("disables Next on a full last page when the total is an exact multiple", () => {
    // 40 findings at 20 per page: page two is full, but there is no page three.
    renderPager({ offset: 20, rowCount: 20, total: 40 });

    expect(screen.getByText("21–40 of 40")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
  });

  it("enables Next with an unknown total when the page is full", () => {
    renderPager({ offset: 0, rowCount: 20, total: null });

    expect(screen.getByRole("button", { name: "Next page" })).toBeEnabled();
  });

  it("disables Next with an unknown total when the page is not full", () => {
    renderPager({ offset: 0, rowCount: 7, total: null });

    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
  });

  it("enables Next on a full page that is not the last one", () => {
    renderPager({ offset: 0, rowCount: 20, total: 45 });

    expect(screen.getByRole("button", { name: "Next page" })).toBeEnabled();
  });

  it("disables Previous on the first page", () => {
    renderPager({ offset: 0 });

    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
  });

  it("offers a way back from an empty page past the end", async () => {
    const { onFirst } = renderPager({ offset: 40, rowCount: 0, total: 40 });
    const user = userEvent.setup();

    expect(screen.getByText("No more results.")).toBeInTheDocument();
    const back = screen.getByRole("button", { name: "Back to the first page" });
    expect(back.className).toContain("underline");

    await user.click(back);

    expect(onFirst).toHaveBeenCalledTimes(1);
  });

  it("does not offer the first-page button when the page has rows", () => {
    renderPager({ offset: 20, rowCount: 20, total: 45 });

    expect(screen.queryByRole("button", { name: "Back to the first page" })).not
      .toBeInTheDocument();
  });

  it("announces the page range and names the navigation buttons", () => {
    renderPager({ offset: 20, rowCount: 20, total: 45 });

    expect(screen.getByText("21–40 of 45")).toHaveAttribute("aria-live", "polite");
    expect(screen.getByRole("button", { name: "Previous page" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next page" })).toBeInTheDocument();
  });

  it("delegates paging to the callbacks", async () => {
    const { onPrevious, onNext } = renderPager({ offset: 20, rowCount: 20, total: 45 });
    const user = userEvent.setup();

    await user.click(screen.getByRole("button", { name: "Previous page" }));
    await user.click(screen.getByRole("button", { name: "Next page" }));

    expect(onPrevious).toHaveBeenCalledTimes(1);
    expect(onNext).toHaveBeenCalledTimes(1);
  });
});
