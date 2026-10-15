import {
  findingQueryOptions,
  findingsQueryOptions,
  PREFETCH_STALE_MS,
  useFinding,
} from "@/api/hooks";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, fireEvent, render, renderHook, screen, waitFor } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FindingDetail } from "./FindingDetail";
import { FindingsDashboard } from "./FindingsDashboard";

const finding = {
  id: "f1",
  project_id: "p1",
  finding_kind: "sca",
  fingerprint: "fp1",
  current_title: "Test Vuln",
  current_severity: "high",
  state: "open",
  triage_status: "untriaged",
  analysis_state: "unanalyzed",
  gate_effect: "block",
  first_seen_at: "2025-01-01T00:00:00Z",
  last_seen_at: "2025-01-02T00:00:00Z",
  created_at: "2025-01-01T00:00:00Z",
  updated_at: "2025-01-01T00:00:00Z",
};

let calls: string[];
let titles: { list: string; one: string; };

const count = (path: string) => calls.filter((c) => c === path).length;

function setVisible(visible: boolean) {
  Object.defineProperty(document, "visibilityState", {
    configurable: true,
    value: visible ? "visible" : "hidden",
  });
  Object.defineProperty(document, "hidden", { configurable: true, value: !visible });
  document.dispatchEvent(new Event("visibilitychange"));
}

async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
  await act(async () => {
    await vi.advanceTimersByTimeAsync(1);
  });
}

beforeEach(() => {
  calls = [];
  titles = { list: "Test Vuln", one: "Test Vuln" };
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
  setVisible(true);
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = new URL(String(input), "http://localhost");
    calls.push(url.pathname);
    if (url.pathname.endsWith("/gate")) return jsonResponse({ blocked_by: [] });
    if (url.pathname.endsWith("/stats")) return jsonResponse({ by_severity: [] });
    if (url.pathname === "/api/v1/projects/payments") {
      return jsonResponse({ id: "p1", slug: "payments", name: "payments", permissions: {} });
    }
    if (url.pathname.endsWith("/events") || url.pathname.endsWith("/reachability")) {
      return jsonResponse([]);
    }
    if (url.pathname.endsWith("/waivers")) return jsonResponse([]);
    if (url.pathname.endsWith("/findings")) {
      return jsonResponse([{ ...finding, current_title: titles.list }]);
    }
    if (url.pathname === "/api/v1/findings/f1") {
      return jsonResponse({ ...finding, current_title: titles.one });
    }
    return jsonResponse({});
  });
});

afterEach(() => {
  vi.useRealTimers();
  setVisible(true);
});

function renderAt(path: string, route: string, element: React.ReactElement) {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path={route} element={element} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const renderList = () => renderAt("/payments/findings", "/:slug/findings", <FindingsDashboard />);
const renderOne = () =>
  renderAt("/payments/findings/f1", "/:slug/findings/:findingId", <FindingDetail />);

describe("fresher findings", () => {
  it("keeps the fresh window to a few seconds, for prefetch de-duplication only", () => {
    expect(PREFETCH_STALE_MS).toBe(5000);
  });

  it("puts no poll in the shared query options, which the per-row finding queries use", () => {
    expect(findingQueryOptions("f1")).not.toHaveProperty("refetchInterval");
    expect(findingsQueryOptions("payments", {})).not.toHaveProperty("refetchInterval");
  });

  it("does not poll a finding that a list row loads with useFinding", async () => {
    // BlockerRow and WaiverRow call useFinding(id) once per row. A poll there would multiply.
    renderHook(() => useFinding("f1"), {
      wrapper: ({ children }) => (
        <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>
      ),
    });
    await advance(1);
    expect(count("/api/v1/findings/f1")).toBe(1);
    await advance(120_000);
    expect(count("/api/v1/findings/f1")).toBe(1);
  });

  it("passes a poll interval only from the findings list and the finding page", () => {
    const src = (path: string) => readFileSync(join(import.meta.dirname, "..", path), "utf8");
    expect(src("pages/change-view/BlockerRow.tsx")).toContain("useFinding(findingId)");
    expect(src("pages/project-waivers/WaiverRow.tsx")).toContain("useFinding(findingId)");
    expect(src("pages/FindingDetail.tsx")).toContain("POLL_MS");
    expect(src("pages/FindingsDashboard.tsx")).toContain("POLL_MS");
    for (const row of ["pages/change-view/BlockerRow.tsx", "pages/project-waivers/WaiverRow.tsx"]) {
      expect(src(row)).not.toContain("POLL_MS");
    }
  });

  it("polls the findings list every 30 seconds and shows a new title", async () => {
    renderList();
    expect(await screen.findByText("Test Vuln")).toBeInTheDocument();
    expect(count("/api/v1/projects/payments/findings")).toBe(1);

    titles.list = "Renamed by someone else";
    await advance(29_000);
    expect(count("/api/v1/projects/payments/findings")).toBe(1);
    await advance(1_000);
    expect(count("/api/v1/projects/payments/findings")).toBe(2);
    expect(await screen.findByText("Renamed by someone else")).toBeInTheDocument();
  });

  it("makes no request from a hidden tab and picks up again when it is shown", async () => {
    renderList();
    await screen.findByText("Test Vuln");
    setVisible(false);
    await advance(95_000);
    expect(count("/api/v1/projects/payments/findings")).toBe(1);

    setVisible(true);
    await advance(30_000);
    expect(count("/api/v1/projects/payments/findings")).toBeGreaterThan(1);
  });

  it("polls the finding and its history every 30 seconds", async () => {
    renderOne();
    await screen.findByRole("heading", { name: "Decide" });
    expect(count("/api/v1/findings/f1")).toBe(1);
    expect(count("/api/v1/findings/f1/events")).toBe(1);

    await advance(30_000);
    expect(count("/api/v1/findings/f1")).toBe(2);
    expect(count("/api/v1/findings/f1/events")).toBe(2);
    // The gate and the project refresh on focus, not on a timer.
    expect(count("/api/v1/projects/payments/gate")).toBe(1);
    expect(count("/api/v1/projects/payments")).toBe(1);
  });

  it("shows when the page was updated, outside any live region, and a Refresh button", async () => {
    renderList();
    await screen.findByText("Test Vuln");
    const hint = screen.getByText(/^Updated /);
    expect(hint).toHaveTextContent("Updated just now");
    expect(hint.closest("[aria-live], [role=status], [role=alert]")).toBeNull();

    await advance(10_000);
    expect(screen.getByText(/^Updated /)).toHaveTextContent(/Updated \d+ seconds? ago/);
  });

  it("Refresh asks again at once", async () => {
    renderList();
    await screen.findByText("Test Vuln");
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await advance(0);
    expect(count("/api/v1/projects/payments/findings")).toBe(2);
  });

  it("ignores a Refresh click while a request is already in flight", async () => {
    renderList();
    await screen.findByText("Test Vuln");
    let release: () => void = () => {};
    const gate = new Promise<void>((resolve) => (release = resolve));
    const original = vi.mocked(globalThis.fetch).getMockImplementation()!;
    vi.mocked(globalThis.fetch).mockImplementation(async (input, init) => {
      await gate;
      return original(input, init);
    });
    const button = screen.getByRole("button", { name: "Refresh" });
    fireEvent.click(button);
    // TanStack batches its notifications with a real setTimeout, so wait for the DOM, not the clock.
    await waitFor(() => expect(button).toHaveAttribute("aria-busy", "true"));
    expect(button).toHaveAttribute("aria-disabled", "true");
    fireEvent.click(button);
    release();
    await advance(0);
    expect(count("/api/v1/projects/payments/findings")).toBe(2);
  });

  it("stops the timers of a hidden tab for the finding page too", async () => {
    renderOne();
    await screen.findByRole("heading", { name: "Decide" });
    setVisible(false);
    await advance(95_000);
    expect(count("/api/v1/findings/f1")).toBe(1);
    expect(count("/api/v1/findings/f1/events")).toBe(1);
  });

  it("announces New changes politely, once, when a poll brings different data", async () => {
    renderOne();
    await screen.findByRole("heading", { name: "Decide" });
    const region = screen.getByRole("status", { name: "Page updates" });
    expect(region).toHaveTextContent("");

    await advance(30_000);
    expect(region).toHaveTextContent("");

    titles.one = "Changed by a teammate";
    await advance(30_000);
    const announced = screen.getByRole("status", { name: "Page updates" });
    await waitFor(() => expect(announced).toHaveTextContent("New changes"));
    expect(announced).not.toHaveAttribute("aria-live", "assertive");

    // A second change is not announced again: the text stays the same, so a reader hears it once.
    titles.one = "Changed again";
    await advance(30_000);
    await waitFor(() => expect(count("/api/v1/findings/f1")).toBe(4));
    expect(screen.getByRole("status", { name: "Page updates" })).toHaveTextContent(/^New changes$/);
  });
});
