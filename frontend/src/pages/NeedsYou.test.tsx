import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { NeedsYou } from "./NeedsYou";

let reply: () => Response;

function item(overrides: Record<string, unknown>) {
  return {
    kind: "waiver_to_decide",
    project_slug: "payments",
    project_name: "Payments API",
    title: "Waiver request: lodash",
    at: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(),
    link: "/payments/waivers",
    ...overrides,
  };
}

beforeEach(() => {
  reply = () => jsonResponse({ count: 0, items: [], assigned_findings: 0 });
  globalThis.fetch = vi.fn().mockImplementation(async () => reply());
});

function renderPage() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <MemoryRouter>
        <NeedsYou />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("NeedsYou", () => {
  it("says nothing waits when nothing does", async () => {
    renderPage();

    expect(await screen.findByText("Nothing waits on you")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { level: 2 })).not.toBeInTheDocument();
  });

  it("groups what waits, most urgent first, and links each item", async () => {
    reply = () =>
      jsonResponse({
        count: 4,
        assigned_findings: 1,
        items: [
          item({
            kind: "request_decided",
            title: "Waiver request: old",
            status: "approved",
            link: "/payments/waivers",
          }),
          item({
            kind: "finding_assigned",
            title: "lodash: prototype pollution",
            severity: "high",
            link: "/payments/findings/f1",
          }),
          item({
            kind: "waiver_to_decide",
            title: "Waiver request: lodash",
            detail: "Only reachable from the admin network.",
          }),
          item({
            kind: "waiver_ending",
            title: "Waiver request: express",
            at: "2099-01-02T10:00:00Z",
          }),
        ],
      });
    renderPage();

    await screen.findByText("Waiver requests to decide");
    const headings = screen.getAllByRole("heading", { level: 2 }).map((h) => h.textContent);
    expect(headings).toEqual([
      "Waiver requests to decide1",
      "Waivers ending soon1",
      "Assigned to you1",
      "Answers to your requests1",
    ]);
    const decide = screen.getByRole("region", { name: /Waiver requests to decide/ });
    expect(within(decide).getByRole("link", { name: "lodash" })).toHaveAttribute(
      "href",
      "/payments/waivers",
    );
    expect(within(decide).getByText("Only reachable from the admin network.")).toBeInTheDocument();
    expect(within(decide).getByText(/Payments API · Asked/)).toBeInTheDocument();
    const assigned = screen.getByRole("region", { name: /Assigned to you/ });
    expect(within(assigned).getByRole("link", { name: "lodash: prototype pollution" }))
      .toHaveAttribute(
        "href",
        "/payments/findings/f1",
      );
    expect(within(assigned).getByText("High")).toBeInTheDocument();
  });

  it("spells out when a waiver ends instead of saying 'just now'", async () => {
    reply = () =>
      jsonResponse({
        count: 1,
        assigned_findings: 0,
        items: [item({ kind: "waiver_ending", at: "2099-01-02T10:00:00Z" })],
      });
    renderPage();

    const ending = await screen.findByRole("region", { name: /Waivers ending soon/ });
    expect(within(ending).queryByText("just now")).not.toBeInTheDocument();
    expect(ending.querySelector("time")).toHaveAttribute("dateTime", "2099-01-02T10:00:00Z");
    expect(within(ending).getByText(/2099/)).toBeInTheDocument();
  });

  it("gives the answer and the reviewer's note for each way a request ended", async () => {
    reply = () =>
      jsonResponse({
        count: 3,
        assigned_findings: 0,
        items: [
          item({
            kind: "request_decided",
            title: "A",
            status: "approved",
            detail: "Fine until the VPN change.",
          }),
          item({ kind: "request_decided", title: "B", status: "rejected", detail: "Too broad." }),
          item({ kind: "request_decided", title: "C", status: "expired" }),
        ],
      });
    renderPage();

    const answers = await screen.findByRole("region", { name: /Answers to your requests/ });
    expect(within(answers).getByText("Approved")).toBeInTheDocument();
    expect(answers).toHaveTextContent("Approved: Fine until the VPN change.");
    expect(answers).toHaveTextContent("Rejected: Too broad.");
    expect(answers).toHaveTextContent("Expired without an answer");
  });

  it("counts every assigned finding and says how many are not listed", async () => {
    reply = () =>
      jsonResponse({
        count: 12,
        assigned_findings: 12,
        items: [
          item({
            kind: "finding_assigned",
            title: "lodash",
            severity: "high",
            link: "/payments/findings/f1",
          }),
        ],
      });
    renderPage();

    const assigned = await screen.findByRole("region", { name: /Assigned to you/ });
    expect(assigned).toHaveTextContent("Assigned to you12");
    expect(assigned).toHaveTextContent("and 11 more findings assigned to you");
  });

  it("offers a retry when the list cannot load", async () => {
    reply = () => jsonResponse({ error: { code: "internal_error", message: "boom" } }, 500);
    renderPage();

    expect(await screen.findByText("Could not load what needs you.")).toBeInTheDocument();
    reply = () => jsonResponse({ count: 0, items: [], assigned_findings: 0 });
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("Nothing waits on you")).toBeInTheDocument();
  });

  it("treats a missing item list as nothing waiting", async () => {
    reply = () => jsonResponse({ count: 0, items: null, assigned_findings: 0 });
    renderPage();

    expect(await screen.findByText("Nothing waits on you")).toBeInTheDocument();
  });
});
