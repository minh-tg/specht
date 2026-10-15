import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Environment } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Inventory } from "./Inventory";

const environment: Environment = {
  id: "e1",
  project_id: "p1",
  name: "prod-eu",
  tier: "development",
  internet_facing: false,
  data_sensitivity: "internal",
  created_at: "2026-10-01T00:00:00Z",
};

let stored: Environment;
let sessionRole: "admin" | "user";
let projectRole: "admin" | "manager" | "member";
let putStatus: number;
let puts: Array<{ url: string; body: unknown; }>;

function renderInventory() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <Inventory slug="payments" />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  stored = { ...environment };
  sessionRole = "admin";
  projectRole = "admin";
  putStatus = 200;
  puts = [];
  globalThis.fetch = vi.fn().mockImplementation(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.endsWith("/api/v1/me")) {
        return jsonResponse({ id: "u1", email: "ada@acme.example", role: sessionRole });
      }
      if (url.endsWith("/api/v1/projects/payments")) {
        return jsonResponse({ id: "p1", slug: "payments", name: "Payments", role: projectRole });
      }
      if (url.endsWith("/environments") && method === "GET") return jsonResponse([stored]);
      if (url.endsWith("/environments/e1") && method === "PUT") {
        const body = JSON.parse(String(init?.body));
        puts.push({ url, body });
        if (putStatus !== 200) {
          return jsonResponse(
            { error: { code: "invalid_environment", message: "tier is wrong" } },
            putStatus,
          );
        }
        stored = { ...stored, ...body };
        return jsonResponse(stored);
      }
      if (url.endsWith("/targets") || url.endsWith("/artifacts")) return jsonResponse([]);
      throw new Error(`unexpected request ${method} ${url}`);
    },
  );
});

async function openEditor() {
  const user = userEvent.setup();
  renderInventory();
  await user.click(await screen.findByRole("button", { name: "Edit prod-eu" }));
  return { user, dialog: await screen.findByRole("dialog", { name: "Classify prod-eu" }) };
}

describe("editing an environment", () => {
  it("is offered to a project admin and to a global admin", async () => {
    renderInventory();
    expect(await screen.findByRole("button", { name: "Edit prod-eu" })).toBeInTheDocument();
  });

  it("is not offered to a manager or a member", async () => {
    sessionRole = "user";
    projectRole = "manager";
    renderInventory();
    expect(await screen.findByText("prod-eu")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Edit prod-eu" })).not.toBeInTheDocument();
  });

  it("starts from the stored values and saves nothing until one changes", async () => {
    const { dialog } = await openEditor();
    expect(within(dialog).getByRole("combobox", { name: "Tier" })).toHaveTextContent("Development");
    expect(within(dialog).getByRole("checkbox", { name: "Reachable from the internet" }))
      .not.toBeChecked();
    expect(within(dialog).getByRole("combobox", { name: "Data sensitivity" }))
      .toHaveTextContent("Internal");
    expect(within(dialog).getByRole("button", { name: "Save" })).toBeDisabled();
  });

  it("sends all three settings and shows the new ones", async () => {
    const { user, dialog } = await openEditor();

    await user.click(within(dialog).getByRole("combobox", { name: "Tier" }));
    await user.click(await screen.findByRole("option", { name: "Production" }));
    await user.click(within(dialog).getByRole("checkbox", { name: "Reachable from the internet" }));
    await user.click(within(dialog).getByRole("combobox", { name: "Data sensitivity" }));
    await user.click(await screen.findByRole("option", { name: "Restricted" }));
    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(puts).toEqual([{
      url: expect.stringContaining("/api/v1/projects/payments/environments/e1"),
      body: { tier: "production", internet_facing: true, data_sensitivity: "restricted" },
    }]);
    const row = within(await screen.findByRole("list", { name: "Environments" })).getByRole(
      "listitem",
    );
    await waitFor(() => expect(row).toHaveTextContent("Internet facing"));
    expect(row).toHaveTextContent("restricted");
  });

  it("keeps the dialog open and says what the server refused", async () => {
    putStatus = 400;
    const { user, dialog } = await openEditor();

    await user.click(within(dialog).getByRole("checkbox", { name: "Reachable from the internet" }));
    await user.click(within(dialog).getByRole("button", { name: "Save" }));

    expect(await within(dialog).findByRole("alert")).toHaveTextContent("tier is wrong");
    expect(screen.getByRole("dialog", { name: "Classify prod-eu" })).toBeInTheDocument();
  });
});
