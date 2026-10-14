import { chooseOption, createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { EvidenceSection } from "./EvidenceSection";

const EVIDENCE = {
  id: "ev-1",
  finding_id: "f1",
  type: "log",
  url: "https://ci.example.com/runs/42",
  description: "Failing build log",
  uploaded_by: "u-mgr",
  created_at: "2026-10-01T09:30:00Z",
};

interface MockOptions {
  role?: "manager" | "member";
  evidence?: unknown[];
  listStatus?: number;
}

/** Routes the fetch calls this section makes and records every request. */
function mockApi({ role = "manager", evidence = [EVIDENCE], listStatus = 200 }: MockOptions = {}) {
  const calls: Array<{ method: string; url: string; body?: unknown; }> = [];
  globalThis.fetch = vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
    const u = String(url);
    const method = init?.method ?? "GET";
    calls.push({
      method,
      url: u,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    });
    if (u.endsWith("/api/v1/me")) {
      return jsonResponse({ id: "u-mgr", email: "manager@example.corp", role: "member" });
    }
    if (/\/api\/v1\/projects\/[^/]+$/.test(u)) {
      const manager = role === "manager";
      return jsonResponse({
        id: "p1",
        slug: "core-api",
        name: "core-api",
        role: manager ? "manager" : "member",
        permissions: { triage: manager, manage_members: manager },
      });
    }
    if (u.endsWith("/api/v1/findings/f1/evidence") && method === "GET") {
      if (listStatus !== 200) {
        return jsonResponse({ code: "internal", message: "boom" }, listStatus);
      }
      return jsonResponse(evidence);
    }
    if (u.endsWith("/api/v1/findings/f1/evidence") && method === "POST") {
      return jsonResponse({ ...EVIDENCE, id: "ev-2" }, 201);
    }
    if (u.includes("/api/v1/findings/f1/evidence/") && method === "DELETE") {
      return new Response(null, { status: 204 });
    }
    return jsonResponse({});
  });
  return calls;
}

function renderEvidenceSection() {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/core-api/findings/f1"]}>
        <Routes>
          <Route
            path="/:slug/findings/:findingId"
            element={<EvidenceSection findingId="f1" projectSlug="core-api" />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("EvidenceSection", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("lists attached evidence with its type, link, description and uploader", async () => {
    mockApi();
    renderEvidenceSection();

    expect(await screen.findByText("Failing build log")).toBeInTheDocument();
    expect(screen.getByText("Log")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "https://ci.example.com/runs/42" })).toHaveAttribute(
      "href",
      "https://ci.example.com/runs/42",
    );
    expect(screen.getByText(/by You/)).toBeInTheDocument();
  });

  it("says so when nothing is attached", async () => {
    mockApi({ evidence: [] });
    renderEvidenceSection();

    expect(await screen.findByText("No evidence attached yet.")).toBeInTheDocument();
  });

  it("shows an error with a retry that refetches the list", async () => {
    const calls = mockApi({ listStatus: 500 });
    const user = userEvent.setup();
    renderEvidenceSection();

    expect(await screen.findByText("Could not load evidence.")).toBeInTheDocument();
    const listReads = () =>
      calls.filter((c) => c.method === "GET" && c.url.endsWith("/evidence")).length;
    const before = listReads();
    await user.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(listReads()).toBeGreaterThan(before));
  });

  it("rejects a link that is not http or https and sends nothing", async () => {
    const calls = mockApi();
    const user = userEvent.setup();
    renderEvidenceSection();
    await screen.findByText("Failing build log");

    await user.type(screen.getByLabelText("Evidence URL"), "ftp://files.example.com/log.txt");
    await user.click(screen.getByRole("button", { name: "Add evidence" }));

    expect(await screen.findByText("Use an http or https link.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
  });

  it("posts the type, url and description exactly as entered", async () => {
    const calls = mockApi();
    const user = userEvent.setup();
    renderEvidenceSection();
    await screen.findByText("Failing build log");

    await chooseOption(user, screen.getByRole("combobox", { name: "Evidence type" }), "Log");
    await user.type(screen.getByLabelText("Evidence URL"), "https://ci.example.com/runs/43");
    await user.type(screen.getByLabelText("Description"), "Retry log");
    await user.click(screen.getByRole("button", { name: "Add evidence" }));

    await waitFor(() => {
      const post = calls.find((c) => c.method === "POST");
      expect(post?.url).toMatch(/\/api\/v1\/findings\/f1\/evidence$/);
      expect(post?.body).toEqual({
        type: "log",
        url: "https://ci.example.com/runs/43",
        description: "Retry log",
      });
    });
  });

  it("asks before deleting and sends nothing on Cancel", async () => {
    const calls = mockApi();
    const user = userEvent.setup();
    renderEvidenceSection();
    await screen.findByText("Failing build log");

    await user.click(screen.getByRole("button", { name: "Delete" }));
    expect(await screen.findByText("Delete this evidence?")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancel" }));

    expect(calls.some((c) => c.method === "DELETE")).toBe(false);
  });

  it("deletes the item once the deletion is confirmed", async () => {
    const calls = mockApi();
    const user = userEvent.setup();
    renderEvidenceSection();
    await screen.findByText("Failing build log");

    await user.click(screen.getByRole("button", { name: "Delete" }));
    await user.click(await screen.findByRole("button", { name: "Delete evidence" }));

    await waitFor(() => {
      const del = calls.find((c) => c.method === "DELETE");
      expect(del?.url).toMatch(/\/api\/v1\/findings\/f1\/evidence\/ev-1$/);
    });
  });

  it("hides the add and delete controls from people who cannot triage", async () => {
    mockApi({ role: "member" });
    renderEvidenceSection();

    expect(await screen.findByText("Failing build log")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Add evidence" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Evidence URL")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Delete" })).not.toBeInTheDocument();
  });
});
