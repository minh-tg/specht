import { render, screen } from "@testing-library/react";
import { SeverityBadge } from "./severity-badge";

describe("SeverityBadge", () => {
  it("renders the severity text", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });

  it("handles case-insensitive matching", () => {
    render(<SeverityBadge severity="HIGH" />);
    expect(screen.getByText("HIGH")).toBeInTheDocument();
  });

  it("falls back to low styling for unknown severities", () => {
    render(<SeverityBadge severity="unknown" />);
    expect(screen.getByText("unknown")).toBeInTheDocument();
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
