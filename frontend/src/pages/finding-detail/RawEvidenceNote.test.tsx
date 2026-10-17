import { formatDate } from "@/lib/format";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { RawEvidenceNote } from "./RawEvidenceNote";

const EXPIRED_ON = "2026-09-17T08:00:00Z";

describe("RawEvidenceNote", () => {
  it("says the raw evidence expired on the window's end date", () => {
    render(<RawEvidenceNote expired expiresAt={EXPIRED_ON} />);
    expect(screen.getByText(/^Raw evidence expired on /)).toHaveTextContent(
      `Raw evidence expired on ${formatDate(EXPIRED_ON)} under the retention policy.`,
    );
  });

  it("drops the date when the expiry is unknown, rather than inventing one", () => {
    const { container } = render(<RawEvidenceNote expired expiresAt={null} />);
    expect(container.textContent).toBe("Raw evidence expired under the retention policy.");
  });

  it("renders nothing while the payload is kept", () => {
    const { container } = render(<RawEvidenceNote expired={false} expiresAt={EXPIRED_ON} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("renders nothing when the flag is absent, as on a list response", () => {
    const { container } = render(<RawEvidenceNote />);
    expect(container).toBeEmptyDOMElement();
  });
});
