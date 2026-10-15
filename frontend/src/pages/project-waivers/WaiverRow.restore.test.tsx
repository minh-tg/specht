import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Waiver } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
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

const NOW = new Date("2026-10-02T09:00:00Z");

const waiver = (over: Partial<Waiver>): Waiver => ({
  id: "w1",
  project_id: "p1",
  name: "not reachable",
  description: "",
  enabled: false,
  status: "approved",
  scope_all: false,
  reason: "behind the gateway",
  decision_note: "",
  conditions: [],
  contexts: [],
  targets: [],
  created_at: "2026-09-01T09:00:00Z",
  updated_at: "2026-09-20T09:00:00.5Z",
  ...over,
});

const onRestore = vi.fn();
const onEdit = vi.fn();

function renderRow(w: Waiver, over: Partial<WaiverRowActions> = {}) {
  const actions: WaiverRowActions = {
    canDecide: false,
    canRevoke: true,
    canManage: true,
    currentUserId: "u-me",
    busy: false,
    onApprove: () => {},
    onReject: () => {},
    onWithdraw: () => {},
    onRevoke: () => {},
    onRestore,
    onEdit,
    onDelete: () => {},
    ...over,
  };
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter>
          <ul>
            <WaiverRow
              slug="my-app"
              waiver={w}
              bucket="closed"
              now={NOW}
              who={{ me: null, directory: null }}
              actions={actions}
            />
          </ul>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

describe("WaiverRow Restore", () => {
  beforeEach(() => {
    onRestore.mockClear();
    onEdit.mockClear();
    globalThis.fetch = vi.fn().mockImplementation(async () => jsonResponse({}));
  });

  it("restores a revoked waiver, passing the waiver it was shown", async () => {
    const revoked = waiver({});
    renderRow(revoked);
    await userEvent.click(screen.getByRole("button", { name: "Restore not reachable" }));
    expect(onRestore).toHaveBeenCalledExactlyOnceWith(revoked);
  });

  it("hides Restore from a person who cannot revoke", () => {
    renderRow(waiver({}), { canRevoke: false });
    expect(screen.queryByRole("button", { name: /Restore/ })).not.toBeInTheDocument();
  });

  it("disables Restore while another change is running", () => {
    renderRow(waiver({}), { busy: true });
    expect(screen.getByRole("button", { name: "Restore not reachable" })).toBeDisabled();
  });

  it.each(["rejected", "withdrawn"] as const)("offers no Restore on a %s request", (status) => {
    renderRow(waiver({ status }));
    expect(screen.queryByRole("button", { name: /Restore/ })).not.toBeInTheDocument();
  });

  it("offers Edit expiry, not Restore, once the expiry has passed", async () => {
    const lapsed = waiver({ expires_at: "2026-10-01T00:00:00Z" });
    renderRow(lapsed);
    expect(screen.queryByRole("button", { name: /Restore/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit not reachable" })).not.toBeInTheDocument();
    const edit = screen.getByRole("button", { name: "Edit expiry of not reachable" });
    // The accessible name starts with the visible words, so voice control can say them.
    expect(edit).toHaveTextContent(/^Edit expiry$/);
    await userEvent.click(edit);
    expect(onEdit).toHaveBeenCalledExactlyOnceWith(lapsed);
  });

  it("keeps the plain Edit on a revoked waiver that still has time left", () => {
    renderRow(waiver({ expires_at: "2026-12-01T00:00:00Z" }));
    expect(screen.getByRole("button", { name: "Edit not reachable" })).toHaveTextContent(/^Edit$/);
    expect(screen.getByRole("button", { name: "Restore not reachable" })).toBeInTheDocument();
  });
});
