import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Waiver } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { WaiverRow, type WaiverRowActions } from "./WaiverRow";

const auth: AuthContextValue = {
  token: "t",
  userId: "u-me",
  email: "me@acme.example",
  login: async () => {},
  logout: () => {},
  adopt: () => {},
  loading: false,
};

const actions: WaiverRowActions = {
  canDecide: false,
  canRevoke: false,
  canManage: false,
  currentUserId: "u-me",
  busy: false,
  onApprove: () => {},
  onReject: () => {},
  onWithdraw: () => {},
  onRevoke: () => {},
  onRestore: () => {},
  onEdit: () => {},
  onDelete: () => {},
};

const waiver = (over: Partial<Waiver>): Waiver => ({
  id: "w1",
  project_id: "p1",
  name: "not reachable",
  description: "",
  enabled: true,
  status: "approved",
  scope_all: false,
  reason: "behind the gateway",
  decision_note: "",
  conditions: [],
  contexts: [],
  targets: [],
  created_at: "2026-10-01T09:00:00Z",
  updated_at: "2026-10-01T09:00:00Z",
  ...over,
});

function renderRow(
  w: Waiver,
  bucket: "pending" | "in_force" | "closed",
  rowActions: WaiverRowActions = actions,
) {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter>
          <ul>
            <WaiverRow
              slug="my-app"
              waiver={w}
              bucket={bucket}
              now={new Date("2026-10-02T09:00:00Z")}
              who={{ me: null, directory: null }}
              actions={rowActions}
            />
          </ul>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

describe("WaiverRow second approver", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn().mockResolvedValue(jsonResponse({}));
  });

  const own = waiver({ status: "pending", requested_by: "u-me", requested_by_name: "Me" });

  it("will not let a manager approve their own request, and says why", () => {
    renderRow(own, "pending", { ...actions, canDecide: true });
    const approve = screen.getByRole("button", { name: /^Approve/ });
    expect(approve).toBeDisabled();
    expect(approve).toHaveAttribute("title", expect.stringContaining("someone else"));
  });

  it("lets a global admin approve their own request", () => {
    renderRow(own, "pending", { ...actions, canDecide: true, isGlobalAdmin: true });
    expect(screen.getByRole("button", { name: /^Approve/ })).toBeEnabled();
  });

  it("lets a project's only manager approve their own request, and says a note is needed", () => {
    renderRow(own, "pending", { ...actions, canDecide: true, canSelfApprove: true });
    const approve = screen.getByRole("button", { name: /^Approve/ });
    expect(approve).toBeEnabled();
    expect(approve).not.toHaveAttribute("title");
    expect(
      screen.getByText("No other manager can decide this, so you can approve it with a note."),
    ).toBeInTheDocument();
  });

  it("does not show the only-manager line on someone else's request or to a global admin", () => {
    renderRow(waiver({ status: "pending", requested_by: "u-tomas" }), "pending", {
      ...actions,
      canDecide: true,
      canSelfApprove: true,
    });
    renderRow(own, "pending", {
      ...actions,
      canDecide: true,
      canSelfApprove: true,
      isGlobalAdmin: true,
    });
    expect(screen.queryByText(/No other manager can decide this/)).not.toBeInTheDocument();
  });

  it("marks a waiver someone approved for themselves", () => {
    renderRow(
      waiver({
        status: "approved",
        requested_by: "u-ada",
        decided_by: "u-ada",
        decided_by_name: "Ada",
      }),
      "in_force",
    );
    expect(screen.getByText(/their own request/)).toBeInTheDocument();
  });
});
