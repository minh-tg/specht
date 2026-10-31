import type { Waiver } from "@/types/api";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { WaiverPath } from "./WaiverPath";
import { waiverView } from "./waiverState";

const NOW = new Date("2026-11-01T12:00:00Z");

function waiver(extra: Partial<Waiver> = {}): Waiver {
  return {
    id: "w1",
    project_id: "p1",
    name: "Waiver request: x",
    description: "",
    enabled: true,
    status: "pending",
    scope_all: false,
    reason: "Not reachable from the API.",
    requested_by: "u-tomas",
    requested_by_name: "Tomas",
    requested_at: "2026-11-01T10:00:00Z",
    decision_note: "",
    expires_at: "2026-12-01T00:00:00Z",
    targets: [{ id: "t1", finding_id: "f1" }],
    created_at: "2026-10-01T00:00:00Z",
    updated_at: "2026-10-01T00:00:00Z",
    ...extra,
  };
}

function renderPath(
  w: Waiver,
  options: { viewer?: string; canApprove?: boolean; onWithdraw?: () => void; } = {},
) {
  const { viewer = "u-ada", canApprove = false, onWithdraw = vi.fn() } = options;
  render(
    <MemoryRouter>
      <WaiverPath
        slug="acme"
        findingId="f1"
        title="SQL injection"
        view={waiverView(w, NOW)}
        who={{ me: { id: viewer } as never }}
        canApprove={canApprove}
        onWithdraw={onWithdraw}
      />
    </MemoryRouter>,
  );
  return screen.getByRole("group", { name: "Waiver for SQL injection" });
}

describe("WaiverPath pending", () => {
  it("says who asked, what happens next and who can act", () => {
    const group = renderPath(waiver());
    expect(within(group).getByText("Waiver requested. Waiting for a manager."))
      .toBeInTheDocument();
    expect(group).toHaveTextContent("Tomas asked");
    expect(group).toHaveTextContent("A project manager decides.");
    expect(group).toHaveTextContent("Only Tomas can withdraw it.");
    expect(group).toHaveTextContent("Until then this finding still blocks this change.");
    expect(group).toHaveTextContent("If nobody decides by");
    expect(within(group).getByText("Not reachable from the API.")).toBeInTheDocument();
    expect(within(group).getByRole("link", { name: "See it on the Waivers page" }))
      .toHaveAttribute("href", "/acme/waivers");
    expect(within(group).queryByRole("button")).not.toBeInTheDocument();
  });

  it("lets the requester withdraw their own request", async () => {
    const onWithdraw = vi.fn();
    const group = renderPath(waiver(), { viewer: "u-tomas", onWithdraw });
    expect(group).toHaveTextContent("You asked");
    await userEvent.click(
      within(group).getByRole("button", { name: "Withdraw request: SQL injection" }),
    );
    expect(onWithdraw).toHaveBeenCalledWith(expect.objectContaining({ id: "w1" }));
  });

  it("tells an approver they can decide someone else's request", () => {
    const group = renderPath(waiver(), { canApprove: true });
    expect(group).toHaveTextContent("You can decide it on the Waivers page.");
    expect(within(group).getByRole("link", { name: "Decide it on the Waivers page" }))
      .toBeInTheDocument();
  });

  it("says a manager cannot approve their own request", () => {
    const group = renderPath(waiver(), { viewer: "u-tomas", canApprove: true });
    expect(group).toHaveTextContent(
      "You cannot approve your own request, so another manager has to decide it.",
    );
    expect(within(group).getByRole("button", { name: /Withdraw request/ })).toBeInTheDocument();
    expect(within(group).getByRole("link", { name: "See it on the Waivers page" }))
      .toBeInTheDocument();
  });
});

describe("WaiverPath after a decision", () => {
  it("shows an approved waiver and when it ends", () => {
    const group = renderPath(
      waiver({ status: "approved", decided_by: "u-kim", decided_by_name: "A. Kim" }),
    );
    expect(group).toHaveTextContent("Waiver approved by A. Kim.");
    expect(group).toHaveTextContent("It is in force until");
  });

  it("shows a rejection with the manager's note", () => {
    const group = renderPath(waiver({
      status: "rejected",
      decided_by: "u-kim",
      decided_by_name: "A. Kim",
      decision_note: "Reachable from the admin API.",
    }));
    expect(group).toHaveTextContent("Waiver rejected by A. Kim.");
    expect(within(group).getByText("Note from A. Kim")).toBeInTheDocument();
    expect(within(group).getByText("Reachable from the admin API.")).toBeInTheDocument();
    expect(group).toHaveTextContent("still blocks this change");
  });

  it("shows a request that expired before a decision, without echoing the note", () => {
    const group = renderPath(
      waiver({
        status: "rejected",
        decision_reason: "expired",
        decision_note: "expired before a decision",
      }),
      { viewer: "u-tomas" },
    );
    expect(group).toHaveTextContent("Your request expired before anyone decided.");
    expect(group).toHaveTextContent("Nobody approved or rejected it");
    expect(within(group).queryByText("expired before a decision")).not.toBeInTheDocument();
  });

  it("shows a withdrawn request", () => {
    const group = renderPath(waiver({ status: "withdrawn" }), { viewer: "u-tomas" });
    expect(group).toHaveTextContent("Request withdrawn by you.");
    expect(group).toHaveTextContent("Fix it, or ask again.");
  });

  it("shows a revoked waiver as switched off before its end date", () => {
    const group = renderPath(waiver({ status: "approved", enabled: false }));
    expect(group).toHaveTextContent("Waiver revoked.");
    expect(group).toHaveTextContent("a manager switched it off");
  });

  it("shows an approved waiver that ran out", () => {
    const group = renderPath(
      waiver({ status: "approved", enabled: false, expires_at: "2026-10-20T00:00:00Z" }),
    );
    expect(group).toHaveTextContent("Waiver expired on");
    expect(group).toHaveTextContent("blocks this change again");
  });
});
