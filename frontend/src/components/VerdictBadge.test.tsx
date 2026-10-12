import { act, render, screen } from "@testing-library/react";
import { VerdictBadge } from "./VerdictBadge";

describe("VerdictBadge", () => {
  it("renders the blocked label on the crown-red fill", () => {
    render(<VerdictBadge verdict="blocked" />);
    const el = screen.getByText("BLOCKED");
    expect(el.className).toContain("bg-verdict-block");
    expect(el.className).toContain("text-verdict-block-fg");
  });

  it("renders the passing label on the forest-green fill", () => {
    render(<VerdictBadge verdict="passing" />);
    const el = screen.getByText("PASSING");
    expect(el.className).toContain("bg-verdict-pass");
    expect(el.className).toContain("text-verdict-pass-fg");
  });

  it("draws unknown as an ink outline, not a fill", () => {
    render(<VerdictBadge verdict="unknown" />);
    const el = screen.getByText("UNKNOWN");
    expect(el.className).not.toContain("bg-verdict");
    expect(el.className).toContain("shadow-[inset_0_0_0_2px_var(--foreground)]");
  });

  it("draws no scans as a dashed outline", () => {
    render(<VerdictBadge verdict="no_scans" />);
    expect(screen.getByText("NO SCANS").className).toContain("border-dashed");
  });

  it("keeps no scans and unknown as distinct words", () => {
    render(<VerdictBadge verdict="no_scans" />);
    expect(screen.queryByText("UNKNOWN")).not.toBeInTheDocument();
    expect(screen.getByText("NO SCANS")).toBeInTheDocument();
  });

  it("sets the page stamp larger than the row stamp", () => {
    const { rerender } = render(<VerdictBadge verdict="blocked" size="lg" />);
    expect(screen.getByText("BLOCKED").className).toContain("h-10");
    rerender(<VerdictBadge verdict="blocked" />);
    expect(screen.getByText("BLOCKED").className).toContain("h-[26px]");
  });

  it("reads SCANNING with the drum while a scan runs, whatever the old verdict was", () => {
    render(<VerdictBadge verdict="blocked" scanning />);
    const el = screen.getByText("SCANNING");
    expect(el.className).not.toContain("bg-verdict-block");
    expect(el.querySelector(".drum")).not.toBeNull();
    expect(screen.queryByText("BLOCKED")).not.toBeInTheDocument();
  });

  it("does not animate on the first render", () => {
    render(<VerdictBadge verdict="blocked" />);
    expect(screen.getByText("BLOCKED")).not.toHaveAttribute("data-landed");
  });

  it("settles once when the verdict changes, then stops", () => {
    vi.useFakeTimers();
    try {
      const { rerender } = render(<VerdictBadge verdict="blocked" />);
      rerender(<VerdictBadge verdict="passing" />);
      const el = screen.getByText("PASSING");
      expect(el).toHaveAttribute("data-landed", "true");
      act(() => {
        vi.advanceTimersByTime(400);
      });
      expect(el).not.toHaveAttribute("data-landed");
    } finally {
      vi.useRealTimers();
    }
  });
});
