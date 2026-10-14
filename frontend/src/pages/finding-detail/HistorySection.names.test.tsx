import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { FindingEvent } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { HistorySection } from "./HistorySection";

const auth: AuthContextValue = {
  token: "t",
  userId: "u-me",
  email: "me@acme.example",
  login: async () => {},
  logout: () => {},
  adopt: () => {},
  loading: false,
};

const event = (over: Partial<FindingEvent>): FindingEvent => ({
  id: "e1",
  finding_id: "f1",
  user_id: "u-ada",
  event_type: "analysis_changed",
  created_at: "2026-10-01T09:00:00Z",
  ...over,
});

function renderHistory(events: FindingEvent[]) {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter>
          <HistorySection events={events} isLoading={false} isError={false} />
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

describe("HistorySection names", () => {
  const calls: string[] = [];
  beforeEach(() => {
    calls.length = 0;
    globalThis.fetch = vi.fn().mockImplementation(async (url) => {
      calls.push(String(url));
      return jsonResponse({ id: "u-me", email: "me@acme.example", role: "member", created_at: "" });
    });
  });

  it("shows who did it from the name the API sent, to a member", async () => {
    renderHistory([event({ user_name: "Ada Okafor" })]);
    expect(await screen.findByText("by Ada Okafor")).toBeInTheDocument();
    expect(screen.queryByText(/A team member/)).not.toBeInTheDocument();
  });

  it("does not ask for the admin-only account directory just to label a history", async () => {
    renderHistory([event({ user_name: "Ada Okafor" })]);
    await screen.findByText("by Ada Okafor");
    expect(calls.some((u) => u.includes("/api/v1/users"))).toBe(false);
  });

  it("calls an automated action System", async () => {
    renderHistory([event({ user_id: "", user_name: undefined })]);
    expect(await screen.findByText("by System")).toBeInTheDocument();
  });
});
