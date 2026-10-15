import type { Finding } from "@/types/api";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { MetadataGrid } from "./MetadataGrid";

function finding(intel: Finding["intel"]): Finding {
  return {
    id: "f1",
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: "fp",
    current_title: "CVE-2024-3094",
    current_severity: "critical",
    current_score: 10,
    state: "open",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2026-10-01T00:00:00Z",
    last_seen_at: "2026-10-14T00:00:00Z",
    intel,
  };
}

function epss(probability: number): string {
  render(
    <MetadataGrid
      finding={finding({
        cve_id: "CVE-2024-3094",
        epss: probability,
        kev: false,
        sources: ["epss"],
        fetched_at: "2026-10-15T00:00:00Z",
      })}
    />,
  );
  return screen.getByText("EPSS").nextElementSibling?.textContent ?? "";
}

describe("MetadataGrid EPSS", () => {
  it("shows a small probability as a percentage that does not round to zero", () => {
    expect(epss(0.00043)).toBe("0.04%");
  });

  it("shows a large probability as a percentage with one decimal", () => {
    expect(epss(0.85)).toBe("85.0%");
  });
});
