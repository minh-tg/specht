import type { Finding } from "@/types/api";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FindingHeader } from "./FindingHeader";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: "fp1",
    current_title: "Test Vulnerability",
    current_severity: "high",
    current_score: null,
    state: "open",
    triage_status: "untriaged",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: new Date(Date.now() - 4 * 86_400_000).toISOString(),
    last_seen_at: "2025-01-02T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("FindingHeader", () => {
  it("puts the kind and how long it has been open above the title", () => {
    render(<FindingHeader finding={finding()} gateResult={null} />);

    expect(screen.getByText("SCA")).toBeInTheDocument();
    expect(screen.getByText("Open for 4 days")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "Test Vulnerability" }))
      .toBeInTheDocument();
  });

  it("says Open since today for a finding first seen today, and the state once a scan closed it", () => {
    const { rerender } = render(
      <FindingHeader
        finding={finding({ first_seen_at: new Date().toISOString() })}
        gateResult={null}
      />,
    );
    expect(screen.getByText("Open since today")).toBeInTheDocument();

    rerender(<FindingHeader finding={finding({ state: "fixed" })} gateResult={null} />);
    expect(screen.getByText("Fixed")).toBeInTheDocument();
    expect(screen.queryByText(/Open for/)).not.toBeInTheDocument();
  });

  it("claims nothing about the gate until the gate is known", () => {
    render(<FindingHeader finding={finding()} gateResult={null} />);
    expect(screen.queryByRole("region")).not.toBeInTheDocument();
  });

  it("explains a waived finding and a plain non-blocking one", () => {
    const { rerender } = render(
      <FindingHeader finding={finding()} gateResult={{ blocks: false, reason: "waived" }} />,
    );
    expect(screen.getByRole("region", { name: "Why this does not block" })).toHaveTextContent(
      "blocks again when the waiver expires",
    );

    rerender(<FindingHeader finding={finding()} gateResult={{ blocks: false }} />);
    expect(screen.getByRole("region", { name: "Why this does not block" })).toHaveTextContent(
      "This finding does not block the gate.",
    );
  });

  it("colours the panel's edge with the severity only while the finding blocks", () => {
    const { rerender } = render(
      <FindingHeader
        finding={finding({ current_severity: "critical" })}
        gateResult={{ blocks: true }}
        floor="high"
      />,
    );
    expect(screen.getByRole("region", { name: "Why this blocks" }).style.borderLeftColor).toBe(
      "var(--sev-critical)",
    );

    rerender(<FindingHeader finding={finding()} gateResult={{ blocks: false }} />);
    expect(screen.getByRole("region").style.borderLeftColor).toBe("var(--border)");
  });

  it("does not name a floor it was not told", () => {
    render(<FindingHeader finding={finding()} gateResult={{ blocks: true }} />);
    expect(screen.getByRole("region", { name: "Why this blocks" })).toHaveTextContent(
      "The gate stops a change that carries this finding until it is fixed or waived.",
    );
  });
});
