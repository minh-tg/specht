import { render, screen } from "@testing-library/react";
import { SeverityBadge } from "./severity-badge";

describe("SeverityBadge", () => {
  it("renders the canonical label, not the raw wire value", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("handles case-insensitive matching", () => {
    render(<SeverityBadge severity="HIGH" />);
    expect(screen.getByText("High")).toBeInTheDocument();
  });

  it("renders a finding the scanner did not rate as Unrated", () => {
    // The server stores `unknown` for it; that is a severity state, not garbage.
    render(<SeverityBadge severity="unknown" />);
    expect(screen.getByText("Unrated")).toBeInTheDocument();
    expect(screen.queryByText("Unknown")).not.toBeInTheDocument();
  });

  it("reads the documented none alias the same way", () => {
    render(<SeverityBadge severity="none" />);
    expect(screen.getByText("Unrated")).toBeInTheDocument();
  });

  it("gives Unrated an outline treatment rather than a tint", () => {
    // Unrated is the absence of severity, so it must not look like a filled chip.
    render(<SeverityBadge severity="unknown" />);
    expect(screen.getByText("Unrated").className).toContain("border");
    expect(screen.getByText("Unrated").className).not.toContain("bg-sev");
  });

  it("pairs a tinted severity with its matching background token", () => {
    // A `-fg` is only valid against its own `-bg`; mixing it with a neutral surface
    // measured 4.32:1 in a generated screen.
    render(<SeverityBadge severity="high" />);
    const el = screen.getByText("High");
    expect(el.className).toContain("bg-sev-high-bg");
    expect(el.className).toContain("text-sev-high-fg");
  });

  it("renders a controlled label for out-of-vocabulary severities", () => {
    // An unvalidated server value must never be rendered verbatim.
    render(<SeverityBadge severity="explosive" />);
    expect(screen.queryByText("explosive")).not.toBeInTheDocument();
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });

  it("renders a controlled label for blank severities", () => {
    render(<SeverityBadge severity="" />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
  });
});

describe("SeverityBadge depth meter", () => {
  it.each([
    ["critical", 4],
    ["high", 3],
    ["medium", 2],
    ["low", 1],
  ])("lights %s bars for %s", (severity, lit) => {
    const { container } = render(<SeverityBadge severity={severity} />);
    const bars = Array.from(container.querySelectorAll("i"));
    expect(bars).toHaveLength(4);
    expect(bars.filter((bar) => bar.dataset.lit === "true")).toHaveLength(lit);
  });

  it("hides the bars from assistive technology, since the word carries the level", () => {
    const { container } = render(<SeverityBadge severity="high" />);
    expect(container.querySelector("i")?.parentElement).toHaveAttribute("aria-hidden", "true");
  });

  it("draws no bars for an unrated finding", () => {
    const { container } = render(<SeverityBadge severity="unknown" />);
    expect(container.querySelectorAll("i")).toHaveLength(0);
  });

  it("drops the tint in plain mode and keeps the coloured word", () => {
    render(<SeverityBadge severity="critical" plain />);
    const el = screen.getByText("Critical");
    expect(el.className).toContain("text-sev-critical-fg");
    expect(el.className).not.toContain("bg-sev-critical-bg");
  });
});
