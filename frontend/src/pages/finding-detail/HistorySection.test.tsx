import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { FindingEvent, UserProfile } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { HistorySection } from "./HistorySection";

const ADMIN: UserProfile = {
  id: "u-admin",
  email: "admin@example.test",
  role: "admin",
  created_at: "2025-01-01T00:00:00Z",
};

const MEMBER: UserProfile = {
  id: "u-member",
  email: "member@example.test",
  role: "member",
  created_at: "2025-01-01T00:00:00Z",
};

const ADA: UserProfile = {
  id: "u-ada",
  email: "ada@example.test",
  display_name: "Ada Lovelace",
  role: "admin",
  created_at: "2025-01-01T00:00:00Z",
};

const GRACE: UserProfile = {
  id: "u-grace",
  email: "grace@example.test",
  role: "member",
  created_at: "2025-01-01T00:00:00Z",
};

const UUID = "11111111-2222-3333-4444-555555555555";

function event(overrides: Partial<FindingEvent>): FindingEvent {
  return {
    id: "e1",
    finding_id: "f1",
    user_id: "",
    event_type: "analysis_changed",
    old_value: "unanalyzed",
    new_value: "accepted_risk",
    created_at: "2025-02-01T00:00:00Z",
    ...overrides,
  };
}

function mockApi(me: UserProfile, requested: string[], directory: UserProfile[] | null) {
  globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
    const url = String(input);
    requested.push(url);
    if (url === "/api/v1/me") return Promise.resolve(jsonResponse(me));
    if (url === "/api/v1/users?limit=500") {
      if (directory == null) return Promise.resolve(jsonResponse({ error: {} }, 403));
      return Promise.resolve(jsonResponse(directory));
    }
    return Promise.resolve(jsonResponse({ error: { code: "not_found" } }, 404));
  });
}

function renderHistory(events: FindingEvent[]) {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <HistorySection events={events} isLoading={false} isError={false} />
    </QueryClientProvider>,
  );
}

let requested: string[];

beforeEach(() => {
  requested = [];
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("HistorySection actors", () => {
  it("shows display names and email fallbacks for an admin", async () => {
    mockApi(ADMIN, requested, [ADA, GRACE]);
    renderHistory([
      event({ id: "e1", user_id: "u-ada" }),
      event({ id: "e2", user_id: "u-grace" }),
    ]);

    expect(await screen.findByText("by Ada Lovelace")).toBeInTheDocument();
    expect(screen.getByText("by grace@example.test")).toBeInTheDocument();
  });

  it("shows You for the viewer and a generic label for others", async () => {
    mockApi(MEMBER, requested, null);
    renderHistory([
      event({ id: "e1", user_id: "u-member" }),
      event({ id: "e2", user_id: "u-other" }),
    ]);

    expect(await screen.findByText("by You")).toBeInTheDocument();
    expect(screen.getByText("by A team member")).toBeInTheDocument();
    expect(requested.filter((url) => url.startsWith("/api/v1/users"))).toHaveLength(0);
  });

  it("shows System for an event with no actor", async () => {
    mockApi(MEMBER, requested, null);
    renderHistory([event({ id: "e1", user_id: "" })]);

    expect(await screen.findByText("by System")).toBeInTheDocument();
  });

  it("falls back to a generic label when the admin directory fails", async () => {
    mockApi(ADMIN, requested, null);
    renderHistory([event({ id: "e1", user_id: UUID })]);

    expect(await screen.findByText("by A team member")).toBeInTheDocument();
    expect(screen.queryByText(new RegExp(UUID))).not.toBeInTheDocument();
  });

  it("never renders the raw user id", async () => {
    mockApi(MEMBER, requested, null);
    const { container } = renderHistory([event({ id: "e1", user_id: UUID })]);

    await waitFor(() => expect(screen.getByText("by A team member")).toBeInTheDocument());
    expect(container.textContent).not.toContain(UUID);
  });
});
