import type { PolicyEffective } from "@/types/api";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ChangeVerdict } from "./ChangeVerdict";

const POLICY: PolicyEffective = {
  template_name: "Baseline",
  template_version: 1,
  severity_floor: "high",
  severity_source: "template",
  watcher_gate: "off",
  watcher_source: "default",
};

describe("ChangeVerdict", () => {
  it("reads BLOCKED with the right singular for one finding", () => {
    render(<ChangeVerdict kind="blocked" blockers={1} waived={0} policy={POLICY} />);

    expect(screen.getByRole("heading", { name: "BLOCKED — 1 finding blocks this change" }))
      .toBeInTheDocument();
    expect(screen.getByText("Floor: high (from team template)")).toBeInTheDocument();
  });

  it("pluralises the blockers and appends the waived count", () => {
    render(<ChangeVerdict kind="blocked" blockers={3} waived={1} policy={POLICY} />);

    expect(screen.getByRole("heading", { name: "BLOCKED — 3 findings block this change" }))
      .toBeInTheDocument();
    expect(screen.getByText(/1 waived/)).toBeInTheDocument();
  });

  it("reads PASSING with no blocking findings", () => {
    render(<ChangeVerdict kind="passing" blockers={0} waived={0} policy={POLICY} />);

    expect(
      screen.getByRole("heading", {
        name: "PASSING — this change introduces no blocking findings",
      }),
    ).toBeInTheDocument();
  });

  it("does not claim passing when there is no verdict", () => {
    render(<ChangeVerdict kind="no_verdict" blockers={0} waived={0} />);

    expect(screen.getByRole("heading", { name: "NO VERDICT — this scan did not complete" }))
      .toBeInTheDocument();
    expect(screen.queryByText(/PASSING/)).not.toBeInTheDocument();
  });

  it("hides the floor line when no policy or waivers are known", () => {
    render(<ChangeVerdict kind="passing" blockers={0} waived={0} />);

    expect(screen.queryByText(/Floor:/)).not.toBeInTheDocument();
    expect(screen.queryByText(/waived/)).not.toBeInTheDocument();
  });

  it("renders a skeleton while loading", () => {
    render(<ChangeVerdict kind="no_verdict" blockers={0} waived={0} loading />);

    expect(screen.getByLabelText("Change verdict")).toHaveAttribute("aria-busy", "true");
    expect(document.querySelectorAll(".animate-pulse").length).toBeGreaterThan(0);
  });
});
