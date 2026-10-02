import type { Finding } from "@/types/api";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FindingHeader } from "./FindingHeader";

/** A finding that blocks nothing by itself; only the gate result varies. */
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
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-02T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
    ...overrides,
  };
}

describe("FindingHeader gate chip", () => {
  it("marks a waived finding with a hidden shield icon and standing-apart text", () => {
    render(<FindingHeader finding={finding()} gateResult={{ blocks: false, reason: "waived" }} />);

    const chip = screen.getByText("Waived: does not block gate");
    expect(chip).toHaveClass("border", "text-foreground");
    expect(chip).not.toHaveClass("text-muted-foreground");

    const icon = chip.querySelector("svg");
    expect(icon).not.toBeNull();
    expect(icon).toHaveAttribute("aria-hidden", "true");
    expect(icon).toHaveClass("size-3");
  });

  it("keeps the plain non-blocking chip unchanged", () => {
    render(<FindingHeader finding={finding()} gateResult={{ blocks: false }} />);

    const chip = screen.getByText("Does not block gate");
    expect(chip).toHaveClass("border", "text-muted-foreground");
    expect(chip).not.toHaveClass("text-foreground");
    expect(chip.querySelector("svg")).toBeNull();
  });
});
