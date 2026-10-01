import { render, screen } from "@testing-library/react";
import { VerdictBadge } from "./VerdictBadge";

describe("VerdictBadge", () => {
  it("renders the blocked label on the blocked fill", () => {
    render(<VerdictBadge verdict="blocked" />);
    const el = screen.getByText("BLOCKED");
    expect(el.className).toContain("bg-verdict-block");
    expect(el.className).toContain("text-verdict-block-fg");
  });

  it("renders the passing label on the passing fill", () => {
    render(<VerdictBadge verdict="passing" />);
    const el = screen.getByText("PASSING");
    expect(el.className).toContain("bg-verdict-pass");
    expect(el.className).toContain("text-verdict-pass-fg");
  });

  it("renders no scans on the indeterminate fill", () => {
    render(<VerdictBadge verdict="no_scans" />);
    const el = screen.getByText("NO SCANS");
    expect(el.className).toContain("bg-verdict-indeterminate");
    expect(el.className).toContain("text-verdict-indeterminate-fg");
  });

  it("renders unknown on the indeterminate fill", () => {
    render(<VerdictBadge verdict="unknown" />);
    const el = screen.getByText("UNKNOWN");
    expect(el.className).toContain("bg-verdict-indeterminate");
    expect(el.className).toContain("text-verdict-indeterminate-fg");
  });

  it("keeps no scans and unknown as distinct words", () => {
    // Both share a fill, so the label is the only thing separating them.
    render(<VerdictBadge verdict="no_scans" />);
    expect(screen.queryByText("UNKNOWN")).not.toBeInTheDocument();
    expect(screen.getByText("NO SCANS")).toBeInTheDocument();
  });
});
