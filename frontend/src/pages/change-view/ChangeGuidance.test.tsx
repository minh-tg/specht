import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { ChangeAside } from "./ChangeAside";
import { ChangeHero } from "./ChangeHero";

describe("report-source guidance", () => {
  it("asks for fresh scanner evidence without assuming automatic scans", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={null}
        state="blocked"
        blockers={1}
        existing={0}
        waived={0}
      />,
    );

    expect(
      screen.getByText("Fix the findings and send a fresh scanner report, or request a waiver."),
    ).toBeInTheDocument();
    expect(screen.queryByText(/re-scans on its own/)).not.toBeInTheDocument();
  });

  it("gives upload, CI and conditional watcher instructions without changing the gate", () => {
    render(
      <ChangeAside
        items={[]}
        onHandledChange={vi.fn()}
        fixesText=""
        waiting={false}
        stalled={false}
        onStartWaiting={vi.fn()}
        onCheckAgain={vi.fn()}
      />,
    );

    expect(screen.getByText(/upload a report through the API with matching scan metadata/))
      .toBeInTheDocument();
    expect(screen.getByText(/If a watcher is configured/)).toBeInTheDocument();
    expect(screen.getByText(/This checklist only tracks your progress/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Wait for a new report" })).toBeInTheDocument();
    expect(screen.queryByText(/re-scans on its own/)).not.toBeInTheDocument();
  });

  it("does not require a push to recover from a failed report", () => {
    render(
      <ChangeHero
        commit="abcdef1234"
        report={null}
        state="failed"
        blockers={0}
        existing={0}
        waived={0}
      />,
    );

    expect(screen.getByText("Check your scanner or CI job, then send a fresh report."))
      .toBeInTheDocument();
    expect(screen.queryByText("PASSING")).not.toBeInTheDocument();
  });
});
