import { formatDate } from "@/lib/format";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AnalysisNote } from "./AnalysisNote";

const EXPIRY = "2031-03-04T05:06:07Z";

describe("AnalysisNote", () => {
  it("shows the reason and the expiry date on one line", () => {
    render(<AnalysisNote reason="covered by the WAF rule" expiresAt={EXPIRY} />);
    expect(screen.getByText(/Reason: covered by the WAF rule/).textContent).toBe(
      `Reason: covered by the WAF rule · Expires ${formatDate(EXPIRY)}`,
    );
  });

  it("shows only the reason, or only the expiry, without a stray separator", () => {
    const { rerender, container } = render(<AnalysisNote reason="vendor patch pending" />);
    expect(container).toHaveTextContent(/^Reason: vendor patch pending$/);
    rerender(<AnalysisNote expiresAt={EXPIRY} />);
    expect(container.textContent).toBe(`Expires ${formatDate(EXPIRY)}`);
  });

  it("renders nothing when the state has neither", () => {
    const { container } = render(<AnalysisNote />);
    expect(container).toBeEmptyDOMElement();
  });
});
