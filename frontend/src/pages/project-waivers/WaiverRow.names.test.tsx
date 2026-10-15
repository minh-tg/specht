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

function renderRow(w: Waiver, bucket: "pending" | "in_force" | "closed") {
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
              actions={actions}
            />
          </ul>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

describe("WaiverRow names", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({}));
  });

  it("says who asked, by name, to a viewer who cannot read the account directory", () => {
    renderRow(
      waiver({
        status: "pending",
        requested_by: "u-ada",
        requested_by_name: "Ada Okafor",
        requested_at: "2026-10-01T09:00:00Z",
      }),
      "pending",
    );
    expect(screen.getByText(/asked by Ada Okafor/)).toBeInTheDocument();
    expect(screen.queryByText(/A team member/)).not.toBeInTheDocument();
  });

  it("says who decided, by name", () => {
    renderRow(
      waiver({
        decided_by: "u-bo",
        decided_by_name: "bo@acme.example",
        decision_note: "fine for now",
      }),
      "in_force",
    );
    expect(screen.getByText(/by bo@acme.example: fine for now/)).toBeInTheDocument();
  });

  it("still says You when the viewer is the requester", () => {
    renderRow(
      waiver({ status: "pending", requested_by: "u-me", requested_by_name: "Me Myself" }),
      "pending",
    );
    expect(screen.getByText(/asked by Me Myself|asked by You/)).toBeInTheDocument();
  });
});
