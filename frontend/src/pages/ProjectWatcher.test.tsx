import { AuthContext, type AuthContextValue } from "@/auth/context";
import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import type { ProjectWatcher as Watcher } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ProjectWatcher } from "./ProjectWatcher";

const auth: AuthContextValue = {
  token: "t",
  userId: "u1",
  email: "ada@acme.example",
  login: async () => {},
  logout: () => {},
  adopt: () => {},
  loading: false,
};

const working: Watcher = {
  enabled: true,
  interval_seconds: 3600,
  default_interval_seconds: 3600,
  min_interval_seconds: 3600,
  max_interval_seconds: 604800,
  server_enabled: true,
  effective_enabled: true,
  effective_interval_seconds: 3600,
  last_poll_at: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
  status: "ok",
  healthy: true,
};

let watcher: Watcher;
let role: "admin" | "user";
let writes: unknown[];
let loadFails: boolean;
let writeFails: boolean;

function renderPage() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <AuthContext.Provider value={auth}>
        <MemoryRouter initialEntries={["/payments/watcher"]}>
          <Routes>
            <Route path="/:slug/watcher" element={<ProjectWatcher />} />
          </Routes>
        </MemoryRouter>
      </AuthContext.Provider>
    </QueryClientProvider>,
  );
}

describe("ProjectWatcher", () => {
  beforeEach(() => {
    watcher = { ...working };
    role = "admin";
    writes = [];
    loadFails = false;
    writeFails = false;
    globalThis.fetch = vi.fn().mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.endsWith("/api/v1/me")) {
          return jsonResponse({ id: "u1", email: "ada@acme.example", role });
        }
        if (url.endsWith("/members")) return jsonResponse([]);
        if (url.endsWith("/watcher") && method === "GET") {
          return loadFails
            ? jsonResponse({ error: { code: "internal", message: "down" } }, 500)
            : jsonResponse(watcher);
        }
        if (url.endsWith("/watcher") && method === "PUT") {
          const body = JSON.parse(String(init?.body));
          writes.push(body);
          if (writeFails) {
            return jsonResponse({
              error: { code: "invalid_watcher_settings", message: "too short" },
            }, 400);
          }
          watcher = {
            ...watcher,
            ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
            ...("interval_seconds" in body
              ? { interval_seconds: body.interval_seconds ?? watcher.default_interval_seconds }
              : {}),
          };
          return jsonResponse(watcher);
        }
        throw new Error(`unexpected request ${method} ${url}`);
      },
    );
  });

  it("shows a working watcher with its interval and last poll", async () => {
    renderPage();
    expect(await screen.findByText("Working")).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "Watch this project" })).toHaveAttribute(
      "aria-checked",
      "true",
    );
    expect(screen.getByRole("combobox", { name: "Interval" })).toHaveTextContent("every hour");
    expect(screen.getByText("12 min ago.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Reset/ })).not.toBeInTheDocument();
  });

  it.each(
    [
      ["stale", "Stale", /may be stuck/, "alert"],
      ["failing", "Failing", /not being checked/, "alert"],
      ["server_off", "Off on the server", /takes effect when the server runs it/, "status"],
      ["waiting", "Waiting for the first poll", /No poll has finished yet/, "status"],
    ] as const,
  )("explains the %s state", async (status, label, notice, kind) => {
    watcher = { ...working, status, healthy: status !== "stale" && status !== "failing" };
    if (status === "waiting") delete watcher.last_poll_at;
    renderPage();
    expect(await screen.findByText(label)).toBeInTheDocument();
    expect(screen.getByRole(kind, { name: "" })).toHaveTextContent(notice);
  });

  it("says a project is off without raising an alarm", async () => {
    watcher = { ...working, enabled: false, effective_enabled: false, status: "disabled" };
    renderPage();
    expect(await screen.findByText("Off for this project")).toBeInTheDocument();
    expect(screen.getByRole("switch")).toHaveAttribute("aria-checked", "false");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("switches the watcher off for the project", async () => {
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("switch", { name: "Watch this project" }));
    await waitFor(() => expect(writes).toEqual([{ enabled: false }]));
    expect(await screen.findByRole("switch")).toHaveAttribute("aria-checked", "false");
  });

  it("changes the interval and resets it to the default", async () => {
    const user = userEvent.setup();
    renderPage();
    await chooseOption(
      user,
      await screen.findByRole("combobox", { name: "Interval" }),
      "every 6 hours",
    );
    await waitFor(() => expect(writes).toEqual([{ interval_seconds: 21600 }]));
    const reset = await screen.findByRole("button", { name: "Reset to every hour" });
    await user.click(reset);
    await waitFor(() =>
      expect(writes).toEqual([{ interval_seconds: 21600 }, { interval_seconds: null }])
    );
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: /^Reset/ })).not.toBeInTheDocument()
    );
  });

  it("gives someone who is not a project admin the settings to read and nothing to change", async () => {
    role = "user";
    renderPage();
    expect(await screen.findByText("Working")).toBeInTheDocument();
    expect(screen.queryByRole("switch")).not.toBeInTheDocument();
    expect(screen.queryByRole("combobox")).not.toBeInTheDocument();
    expect(screen.getByText("On")).toBeInTheDocument();
    expect(screen.getByText("every hour")).toBeInTheDocument();
  });

  it("says so when the server refuses a change", async () => {
    writeFails = true;
    const user = userEvent.setup();
    renderPage();
    await user.click(await screen.findByRole("switch", { name: "Watch this project" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("too short");
  });

  it("offers a retry when the watcher cannot be loaded", async () => {
    loadFails = true;
    renderPage();
    expect(await screen.findByText("Could not load the watcher.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /retry/i })).toBeInTheDocument();
  });
});
