import { WAIVER_TARGETS_MAX } from "@/lib/waiverRequest";
import type { Waiver } from "@/types/api";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { GroupWaiverControl, type GroupWaiverControlProps } from "./GroupWaiverControl";
import { waiverViewsByFinding } from "./waiverState";

const NOW = new Date("2026-11-01T12:00:00Z");

function waiver(findingId: string, extra: Partial<Waiver> = {}): Waiver {
  return {
    id: `w-${findingId}`,
    project_id: "p1",
    name: "Waiver request",
    description: "",
    enabled: true,
    status: "pending",
    scope_all: false,
    reason: "",
    decision_note: "",
    expires_at: "2026-12-01T00:00:00Z",
    targets: [{ id: `t-${findingId}`, finding_id: findingId }],
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-01T00:00:00Z",
    ...extra,
  };
}

function ids(count: number): string[] {
  return Array.from({ length: count }, (_, index) => `f${index}`);
}

function renderControl(overrides: Partial<GroupWaiverControlProps> = {}) {
  const onRequest = vi.fn();
  render(
    <GroupWaiverControl
      ids={ids(3)}
      views={new Map()}
      request={{ kind: "available" }}
      waitingForWaivers={false}
      context="Upgrade lodash to 4.17.21"
      onRequest={onRequest}
      noteId="note"
      {...overrides}
    />,
  );
  return onRequest;
}

describe("GroupWaiverControl", () => {
  it("asks for every blocker in the set with one request", async () => {
    const onRequest = renderControl();

    await userEvent.setup().click(
      screen.getByRole("button", {
        name: "Request one waiver for all 3: Upgrade lodash to 4.17.21",
      }),
    );

    expect(onRequest).toHaveBeenCalledWith(["f0", "f1", "f2"]);
    expect(document.getElementById("note")).toBeNull();
  });

  it("leaves out blockers that are waived or waiting, and says which", async () => {
    const views = waiverViewsByFinding(
      [waiver("f0"), waiver("f1", { status: "approved" })],
      NOW,
    );
    const onRequest = renderControl({ ids: ids(4), views });

    await userEvent.setup().click(
      screen.getByRole("button", { name: /^Request one waiver for 2 findings/ }),
    );

    expect(onRequest).toHaveBeenCalledWith(["f2", "f3"]);
    expect(document.getElementById("note")).toHaveTextContent(
      "2 blockers left out: 1 already waived, 1 with a request waiting for a manager.",
    );
  });

  it("names at most 50 findings and says how to ask for the rest", async () => {
    const onRequest = renderControl({ ids: ids(WAIVER_TARGETS_MAX + 10) });

    await userEvent.setup().click(
      screen.getByRole("button", { name: /^Request one waiver for the first 50/ }),
    );

    expect(onRequest).toHaveBeenCalledTimes(1);
    expect(onRequest.mock.calls[0][0]).toEqual(ids(WAIVER_TARGETS_MAX));
    expect(document.getElementById("note")).toHaveTextContent(
      "One request can name at most 50 findings. 60 can be requested, so this sends the first 50. Ask again for the rest once it is sent.",
    );
  });

  it("sends all 50 without a split note when the set is exactly at the limit", () => {
    renderControl({ ids: ids(WAIVER_TARGETS_MAX) });

    expect(screen.getByRole("button", { name: /^Request one waiver for all 50/ }))
      .toBeInTheDocument();
    expect(document.getElementById("note")).toBeNull();
  });

  it("drops the button and says so when every blocker is already covered", () => {
    const views = waiverViewsByFinding([waiver("f0"), waiver("f1"), waiver("f2")], NOW);
    renderControl({ views });

    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(document.getElementById("note")).toHaveTextContent(
      "3 blockers left out: 3 with a request waiting for a manager. Nothing is left to ask for.",
    );
  });

  it("is disabled with the reason when the viewer may not ask", () => {
    renderControl({
      request: { kind: "disabled", reason: "You are not a member of this project." },
    });

    expect(screen.getByRole("button", { name: /^Request one waiver for all 3/ })).toBeDisabled();
    expect(screen.getAllByText("You are not a member of this project.").length).toBeGreaterThan(0);
  });

  it("is disabled until the waivers list has loaded, and says why", () => {
    renderControl({ waitingForWaivers: true });

    expect(screen.getByRole("button", { name: /^Request one waiver for all 3/ })).toBeDisabled();
    expect(screen.getAllByText("Checking which blockers already have a waiver.").length)
      .toBeGreaterThan(0);
  });
});
