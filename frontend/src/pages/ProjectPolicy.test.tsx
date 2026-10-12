import { AuthContext, type AuthContextValue } from "@/auth/context";
import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import type { PolicyEffective } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectPolicy } from "./ProjectPolicy";

const auth: AuthContextValue = {
  token: "t",
  userId: "u1",
  email: "ada@acme.example",
  login: async () => {},
  logout: () => {},
  adopt: () => {},
  loading: false,
};

const fromTemplate: PolicyEffective = {
  template_name: "Strict production",
  template_version: 3,
  severity_floor: "critical",
  severity_source: "template",
  watcher_gate: "require_triage",
  watcher_source: "default",
};

let policy: PolicyEffective;
let role: "admin" | "user";
let writes: { url: string; body: unknown; }[];
let failNextWrite: boolean;

function renderPage() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/payments/policy"]}>
          <Routes>
            <Route path="/:slug/policy" element={<ProjectPolicy />} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

describe("ProjectPolicy", () => {
  beforeEach(() => {
    policy = { ...fromTemplate };
    role = "admin";
    writes = [];
    failNextWrite = false;
    globalThis.fetch = vi.fn().mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/api/v1/me")) {
          return jsonResponse({ id: "u1", email: "ada@acme.example", role });
        }
        if (url.endsWith("/members")) return jsonResponse([]);
        if (url.endsWith("/api/v1/policy-templates")) {
          return jsonResponse([
            { id: "t1", name: "Strict production", description: "", definition: {}, version: 3 },
            { id: "t2", name: "Relaxed internal", description: "", definition: {}, version: 1 },
          ]);
        }
        if (method === "PUT") {
          const body = JSON.parse(String(init?.body));
          writes.push({ url, body });
          if (failNextWrite) {
            return jsonResponse({ error: { code: "invalid_policy", message: "bad value" } }, 400);
          }
          if (url.endsWith("/policy/overrides")) {
            const o = body.overrides as Record<string, string>;
            policy = {
              ...policy,
              severity_floor: o["severity_floor"] ?? "critical",
              severity_source: o["severity_floor"] ? "override" : "template",
              watcher_gate: o["watcher_gate"] ?? "require_triage",
              watcher_source: o["watcher_gate"] ? "override" : "default",
            };
          }
          return jsonResponse(policy);
        }
        if (url.endsWith("/policy")) return jsonResponse(policy);
        throw new Error(`unexpected request ${method} ${url}`);
      },
    );
  });

  it("shows each rule with the layer it comes from", async () => {
    role = "user";
    renderPage();
    expect(await screen.findByRole("heading", { name: "Policy" })).toBeInTheDocument();
    expect(screen.getByText("Strict production")).toBeInTheDocument();
    expect(screen.getByText("v3")).toBeInTheDocument();
    const floor = screen.getByRole("group", { name: "Severity floor" });
    expect(floor).toHaveTextContent("Template");
    expect(floor).toHaveTextContent("Critical");
    const watcher = screen.getByRole("group", { name: "Watcher findings" });
    expect(watcher).toHaveTextContent("Default");
    expect(watcher).toHaveTextContent("Needs triage");
  });

  it("gives someone who is not a project admin no way to change anything", async () => {
    role = "user";
    renderPage();
    await screen.findByRole("heading", { name: "Policy" });
    expect(screen.queryByRole("button", { name: /Override/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox", { name: "Template" })).not.toBeInTheDocument();
    expect(screen.getByText(/Only project admins can change this page/)).toBeInTheDocument();
  });

  it("overrides the severity floor and keeps the other overrides", async () => {
    policy = { ...policy, watcher_gate: "off", watcher_source: "override" };
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Override Severity floor" }));
    await chooseOption(user, screen.getByRole("combobox", { name: "Severity floor" }), "Medium");
    await user.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]!.url).toMatch(/\/projects\/payments\/policy\/overrides$/);
    expect(writes[0]!.body).toEqual({
      overrides: { severity_floor: "medium", watcher_gate: "off" },
    });
    expect(await screen.findByRole("button", { name: "Change Severity floor" }))
      .toBeInTheDocument();
  });

  it("removes one override and leaves the rest in place", async () => {
    policy = {
      ...policy,
      severity_floor: "low",
      severity_source: "override",
      watcher_gate: "immediate",
      watcher_source: "override",
    };
    const user = userEvent.setup();
    renderPage();
    await user.click(
      await screen.findByRole("button", { name: "Remove override for Severity floor" }),
    );
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]!.body).toEqual({ overrides: { watcher_gate: "immediate" } });
  });

  it("links a template by name and unlinks with the empty name", async () => {
    const user = userEvent.setup();
    renderPage();
    const select = await screen.findByRole("combobox", { name: "Template" });
    await chooseOption(user, select, "Relaxed internal");
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]!.url).toMatch(/\/projects\/payments\/policy$/);
    expect(writes[0]!.body).toEqual({ template_name: "Relaxed internal" });

    await chooseOption(user, screen.getByRole("combobox", { name: "Template" }), "No template");
    await waitFor(() => expect(writes).toHaveLength(2));
    expect(writes[1]!.body).toEqual({ template_name: "" });
  });

  it("says so when a change is refused", async () => {
    failNextWrite = true;
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Override Severity floor" }));
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("bad value");
  });

  it("drops a refused change's message once another change goes through", async () => {
    failNextWrite = true;
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("button", { name: "Override Severity floor" }));
    await user.click(screen.getByRole("button", { name: "Save" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("bad value");

    failNextWrite = false;
    await chooseOption(
      user,
      screen.getByRole("combobox", { name: "Template" }),
      "Relaxed internal",
    );
    await waitFor(() => expect(screen.queryByRole("alert")).not.toBeInTheDocument());
  });

  it("offers a retry when the policy cannot be loaded", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.endsWith("/api/v1/me")) {
        return jsonResponse({ id: "u1", email: "a@b.c", role: "admin" });
      }
      if (url.endsWith("/members")) return jsonResponse([]);
      if (url.endsWith("/api/v1/policy-templates")) return jsonResponse([]);
      return jsonResponse({ error: { code: "internal", message: "down" } }, 500);
    });
    renderPage();
    expect(await screen.findByText("Could not load the policy.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });
});
