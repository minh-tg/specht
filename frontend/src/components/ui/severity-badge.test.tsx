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
