import type { Finding } from "@/types/api";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AutoCloseNote } from "./AutoCloseNote";

function finding(over: Partial<Finding>): Finding {
  return {
    id: "f1",
    project_id: "p1",
    finding_kind: "secret",
    fingerprint: "fp",
    current_title: "A secret",
    current_severity: "high",
    state: "open",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2026-01-01T00:00:00Z",
    last_seen_at: "2026-01-02T00:00:00Z",
    ...over,
  } as Finding;
}

const NOTE = /cannot prove a fix/;

describe("AutoCloseNote", () => {
  it("names a scanner that cannot prove a fix", () => {
    render(
      <AutoCloseNote
        finding={finding({
          scanner: { name: "gitleaks", display_name: "Gitleaks", supports_auto_close: false },
        })}
      />,
    );
    expect(screen.getByText(NOTE)).toHaveTextContent("Gitleaks reports cannot prove a fix");
  });

  it("shows the note for a reopened finding", () => {
    render(
      <AutoCloseNote
        finding={finding({
          state: "reopened",
          scanner: { name: "gitleaks", display_name: "Gitleaks", supports_auto_close: false },
        })}
      />,
    );
    expect(screen.getByText(NOTE)).toBeInTheDocument();
  });

  it.each(
    [
      ["a scanner that can close findings", {
        scanner: { name: "trivy", display_name: "Trivy", supports_auto_close: true },
      }],
      ["a finding with no known scanner", {}],
      [
        "a finding that is already fixed",
        {
          state: "fixed",
          scanner: { name: "gitleaks", display_name: "Gitleaks", supports_auto_close: false },
        },
      ],
    ] as const,
  )("says nothing for %s", (_name, over) => {
    render(<AutoCloseNote finding={finding(over as Partial<Finding>)} />);
    expect(screen.queryByText(NOTE)).not.toBeInTheDocument();
  });
});
