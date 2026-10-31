import { Ledger } from "@/components/Ledger";
import type { Finding } from "@/types/api";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { BlockerEntry } from "./BlockerEntry";

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    project_id: "p1",
    finding_kind: "sca",
    fingerprint: "fp1",
    current_title: "Lodash prototype pollution",
    current_severity: "high",
    current_score: null,
    state: "open",
    triage_status: "untriaged",
    analysis_state: "unanalyzed",
    gate_effect: "block",
    first_seen_at: "2025-01-01T00:00:00Z",
    last_seen_at: "2025-01-01T00:00:00Z",
    created_at: "2025-01-01T00:00:00Z",
    updated_at: "2025-01-01T00:00:00Z",
    ...overrides,
  };
}

function renderEntry(item: Finding) {
  render(
    <MemoryRouter>
      <Ledger label="Blocking findings">
        <BlockerEntry
          slug="acme"
          index={1}
          findingId="f1"
          finding={item}
          isLoading={false}
          isError={false}
          onRetry={vi.fn()}
          open
          onOpenChange={vi.fn()}
          handled={false}
          onHandledChange={vi.fn()}
          waiverRequested={false}
          canRequestWaiver
          onRequestWaiver={vi.fn()}
        />
      </Ledger>
    </MemoryRouter>,
  );
}

describe("BlockerEntry fix", () => {
  it("shows the upgrade and a copy button for an SCA finding with a real fix", async () => {
    const user = userEvent.setup();
    renderEntry(finding({
      suggestion: { action: "upgrade", target: "lodash", confidence: "high" },
    }));

    expect(screen.getAllByText("Upgrade lodash").length).toBeGreaterThan(0);
    expect(screen.queryByText("No known fix.")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^Copy fix: / }));
    expect(await navigator.clipboard.readText()).toBe("Upgrade lodash");
  });

  it("says there is no known fix for a SAST finding with the fallback suggestion", () => {
    renderEntry(finding({
      finding_kind: "sast",
      current_title: "SQL injection",
      location: { file: "src/db.ts", start_line: 42 },
      suggestion: {
        action: "review",
        target: "src/db.ts",
        detail: "No fix description reported",
        confidence: "low",
      },
    }));

    expect(screen.getByText("No known fix.")).toBeInTheDocument();
    expect(screen.getByText(/Start at/)).toBeInTheDocument();
    expect(screen.getAllByText("src/db.ts:42").length).toBeGreaterThan(0);
    expect(screen.queryByText(/Review src\/db\.ts/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Copy fix/ })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Open the full finding" })).toBeInTheDocument();
  });

  it("does not name a place to start when the finding has no location", () => {
    renderEntry(finding({
      suggestion: { action: "review", confidence: "low" },
    }));

    expect(screen.getByText("No known fix.")).toBeInTheDocument();
    expect(screen.getByText(/Open the full finding to decide what to do/)).toBeInTheDocument();
    expect(screen.queryByText(/Start at/)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Copy fix/ })).not.toBeInTheDocument();
  });
});
