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

  it("renders the fifth severity as none, which is the API's value", () => {
    // Regression: the vocabulary previously said `unknown`, so every scanner-reported
    // `none` failed validation and rendered as "Unknown" — a different meaning.
    render(<SeverityBadge severity="none" />);
    expect(screen.getByText("None")).toBeInTheDocument();
    expect(screen.queryByText("Unknown")).not.toBeInTheDocument();
  });

  it("gives none an outline treatment rather than a tint", () => {
    // `none` is the absence of severity, so it must not look like a filled chip.
    render(<SeverityBadge severity="none" />);
    expect(screen.getByText("None").className).toContain("border");
  });

  it("pairs a tinted severity with its matching background token", () => {
    // A `-fg` is only valid against its own `-bg`; mixing it with a neutral surface
    // measured 4.32:1 in a generated screen.
    render(<SeverityBadge severity="high" />);
    const el = screen.getByText("High");
    expect(el.className).toContain("bg-sev-high-bg");
    expect(el.className).toContain("text-sev-high-fg");
  });

  it("treats unknown as out of vocabulary for severity", () => {
    // `unknown` is a reachability value. For severity it must fall back, never be
    // accepted as the fifth severity.
    render(<SeverityBadge severity="unknown" />);
    expect(screen.getByText("Unknown")).toBeInTheDocument();
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
