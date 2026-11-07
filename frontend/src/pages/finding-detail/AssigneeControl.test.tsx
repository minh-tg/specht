import { AuthContext, type AuthContextValue } from "@/auth/context";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Finding } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AssigneeControl } from "./AssigneeControl";

const finding = (over: Partial<Finding> = {}) => ({ id: "f1", ...over } as Finding);
let triage = false;
let puts: unknown[] = [];

function renderControl(f: Finding) {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={{ userId: "me" } as AuthContextValue}>
        <AssigneeControl finding={f} slug="acme" />
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  puts = [];
  triage = false;
  globalThis.fetch = vi.fn().mockImplementation(async (input, init) => {
    const url = String(input);
    if (url.endsWith("/assignee")) {
      puts.push(JSON.parse((init as RequestInit).body as string));
      return jsonResponse({ assignee: null });
    }
    if (url.endsWith("/members")) return jsonResponse([]);
    if (url === "/api/v1/me") return jsonResponse({ id: "me", email: "m@e", role: "member" });
    if (url === "/api/v1/projects/acme") {
      return jsonResponse({
        id: "p",
        slug: "acme",
        name: "Acme",
        role: triage ? "manager" : "member",
        permissions: { triage },
      });
    }
    return jsonResponse({});
  });
});

describe("AssigneeControl", () => {
  it("lets a member take a finding nobody owns", async () => {
    const user = userEvent.setup();
    renderControl(finding());
    await user.click(await screen.findByRole("button", { name: "Take it" }));
    await waitFor(() => expect(puts).toEqual([{ user_id: "me" }]));
  });

  it("lets a member let go of their own", async () => {
    const user = userEvent.setup();
    renderControl(finding({ assignee: { user_id: "me", name: "Me" } }));
    await user.click(await screen.findByRole("button", { name: "Let go" }));
    await waitFor(() => expect(puts).toEqual([{ user_id: "" }]));
  });

  it("offers a member no control over someone else's", async () => {
    renderControl(finding({ assignee: { user_id: "them", name: "Them" } }));
    expect(await screen.findByText("Them")).toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });

  it("lets a manager pick anyone", async () => {
    triage = true;
    renderControl(finding());
    expect(await screen.findByRole("combobox", { name: "Assigned to" })).toHaveTextContent(
      "Nobody",
    );
  });
});
