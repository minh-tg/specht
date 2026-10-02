import type { Finding } from "@/types/api";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { BlockerRowView } from "./BlockerRow";

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

function renderRow(props: Partial<Parameters<typeof BlockerRowView>[0]> = {}) {
  const onRetry = vi.fn();
  render(
    <MemoryRouter>
      <ul>
        <BlockerRowView
          slug="acme"
          findingId="f1"
          isLoading={false}
          isError={false}
          onRetry={onRetry}
          {...props}
        />
      </ul>
    </MemoryRouter>,
  );
  return { onRetry };
}

describe("BlockerRowView", () => {
  it("renders a skeleton row while loading", () => {
    renderRow({ isLoading: true });

    expect(document.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });

  it("names the failed finding and retries without crashing", async () => {
    const { onRetry } = renderRow({ isError: true });

    expect(screen.getByText("Could not load this finding")).toBeInTheDocument();
    expect(screen.getByText("f1")).toBeInTheDocument();
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it("links the title and the Decide action to the finding", () => {
    renderRow({ finding: finding() });

    expect(screen.getByRole("link", { name: "Lodash prototype pollution" }))
      .toHaveAttribute("href", "/acme/findings/f1");
    expect(screen.getByRole("link", { name: "Decide" }))
      .toHaveAttribute("href", "/acme/findings/f1");
    expect(screen.getByText("High")).toBeInTheDocument();
  });

  it("shows file and line, then the remediation summary", () => {
    renderRow({
      finding: finding({
        location: { file: "src/db.ts", start_line: 42 },
        remediation: { summary: "Upgrade lodash\nthen redeploy" },
      }),
    });

    expect(screen.getByText("src/db.ts:42")).toBeInTheDocument();
    expect(screen.getByText("Do this")).toBeInTheDocument();
    expect(screen.getByText("Upgrade lodash")).toBeInTheDocument();
  });

  it("falls back to the suggestion and then to no fix", () => {
    renderRow({
      finding: finding({
        location: { resource: "pkg:lodash" },
        suggestion: { action: "Upgrade", target: "lodash@4.17.21", confidence: "high" },
      }),
    });
    expect(screen.getByText("pkg:lodash")).toBeInTheDocument();
    expect(screen.getByText("Upgrade lodash@4.17.21")).toBeInTheDocument();
  });

  it("starts the action with a capital letter when the scanner wrote it lowercase", () => {
    renderRow({
      finding: finding({
        suggestion: { action: "review", target: "src/db.ts", confidence: "low" },
      }),
    });

    expect(screen.getByText("Review src/db.ts")).toBeInTheDocument();
  });

  it("treats the server's fallback label as no known fix", () => {
    renderRow({
      finding: finding({
        remediation: { summary: "No fix description reported", fallback: true },
      }),
    });

    expect(screen.getByText("No automated fix is known.")).toBeInTheDocument();
    expect(screen.queryByText("No fix description reported")).not.toBeInTheDocument();
  });

  it("says honestly when no fix is known, and still points at the decision", () => {
    renderRow({ finding: finding({ location: {} }) });

    expect(screen.getByText("Do this")).toBeInTheDocument();
    expect(screen.getByText("No automated fix is known.")).toBeInTheDocument();
    expect(screen.queryByText("No fix suggested")).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Decide" })).toBeInTheDocument();
  });
});
