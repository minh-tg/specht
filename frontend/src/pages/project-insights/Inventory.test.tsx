import { EMPTY_VALUE } from "@/lib/format";
import { createTestQueryClient, jsonResponse } from "@/test/utils";
import type { Artifact, Environment, Target } from "@/types/api";
import { QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { Inventory } from "./Inventory";

const environment: Environment = {
  id: "e1",
  project_id: "p1",
  name: "prod-eu",
  tier: "production",
  internet_facing: true,
  data_sensitivity: "confidential",
  created_at: "2026-10-01T00:00:00Z",
};

const internal: Environment = {
  ...environment,
  id: "e2",
  name: "staging",
  tier: "staging",
  internet_facing: false,
  data_sensitivity: "",
};

const target: Target = {
  id: "t1",
  project_id: "p1",
  name: "payments-api",
  kind: "repository",
  locator: "git@git.example.com:shop/payments-api.git",
  created_at: "2026-10-01T00:00:00Z",
};

const artifact: Artifact = {
  id: "a1",
  project_id: "p1",
  target_id: "t1",
  artifact_type: "container-image",
  name: "payments",
  version: "1.4.2",
  digest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  locator: "registry.example.com/payments",
  created_at: "2026-10-01T00:00:00Z",
};

type Answer = { status: number; body: unknown; } | "pending";

let answers: Record<"environments" | "targets" | "artifacts", Answer>;

function answer(kind: keyof typeof answers): Answer {
  return answers[kind];
}

function renderInventory() {
  return render(
    <QueryClientProvider client={createTestQueryClient()}>
      <Inventory slug="payments" />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  answers = {
    environments: { status: 200, body: [] },
    targets: { status: 200, body: [] },
    artifacts: { status: 200, body: [] },
  };
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    const url = String(input);
    const kind = (["environments", "targets", "artifacts"] as const).find((k) =>
      url.endsWith(`/${k}`)
    );
    if (!kind) throw new Error(`unexpected request ${url}`);
    const a = answer(kind);
    if (a === "pending") return new Promise<Response>(() => {});
    return jsonResponse(a.body, a.status);
  });
});

describe("Inventory", () => {
  it("names the section and says what it holds", async () => {
    renderInventory();
    expect(await screen.findByRole("heading", { name: "Where it runs" })).toBeInTheDocument();
    expect(screen.getByText(
      "What the project's scans said about where the code runs and what was scanned.",
    )).toBeInTheDocument();
  });

  it("writes out each environment with its exposure in words", async () => {
    answers.environments = { status: 200, body: [environment, internal] };
    renderInventory();
    const list = await screen.findByRole("list", { name: "Environments" });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveTextContent("prod-eu");
    expect(rows[0]).toHaveTextContent("production");
    expect(rows[0]).toHaveTextContent("Internet facing");
    expect(rows[0]).toHaveTextContent("confidential");
    expect(rows[1]).toHaveTextContent("Internal");
    expect(rows[1]).not.toHaveTextContent("Internet facing");
    expect(rows[1]).toHaveTextContent(EMPTY_VALUE);
  });

  it("shows each target with its kind and locator", async () => {
    answers.targets = { status: 200, body: [target] };
    renderInventory();
    const list = await screen.findByRole("list", { name: "Scan targets" });
    const row = within(list).getByRole("listitem");
    expect(row).toHaveTextContent("payments-api");
    expect(row).toHaveTextContent("repository");
    const locator = within(row).getByText(target.locator!);
    expect(locator.className).toContain("break-all");
  });

  it("shows the artifact version and a short digest with the full one in its title", async () => {
    answers.artifacts = { status: 200, body: [artifact] };
    renderInventory();
    const list = await screen.findByRole("list", { name: "Artifacts" });
    const row = within(list).getByRole("listitem");
    expect(row).toHaveTextContent("payments 1.4.2");
    expect(row).toHaveTextContent("container-image");
    const code = row.querySelector("code")!;
    expect(code).toHaveTextContent("0123456789ab");
    expect(code).not.toHaveTextContent("sha256");
    expect(code).toHaveAttribute("title", artifact.digest);
  });

  it("counts each list in its heading", async () => {
    answers.targets = { status: 200, body: [target] };
    answers.artifacts = { status: 200, body: [artifact, { ...artifact, id: "a2", name: "sbom" }] };
    renderInventory();
    expect(await screen.findByRole("heading", { name: /^Scan targets\s*1$/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /^Artifacts\s*2$/ })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /^Environments\s*0$/ })).toBeInTheDocument();
  });

  it("says what to expect when a list is empty", async () => {
    renderInventory();
    expect(
      await screen.findByText(
        "No environments recorded yet. Scans that send context fill this in.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText(/No scan targets recorded yet/)).toBeInTheDocument();
    expect(screen.getByText(/No artifacts recorded yet/)).toBeInTheDocument();
  });

  it("reads a null list as empty", async () => {
    answers.environments = { status: 200, body: null };
    answers.targets = { status: 200, body: null };
    answers.artifacts = { status: 200, body: null };
    renderInventory();
    expect(await screen.findByText(/No environments recorded yet/)).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Environments" })).not.toBeInTheDocument();
  });

  it("shows a loading skeleton for each list while it loads", async () => {
    answers = { environments: "pending", targets: "pending", artifacts: "pending" };
    renderInventory();
    expect(await screen.findByRole("status", { name: "Loading environments" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading scan targets" })).toBeInTheDocument();
    expect(screen.getByRole("status", { name: "Loading artifacts" })).toBeInTheDocument();
  });

  it("fails one list without hiding the others, and retries it", async () => {
    answers.environments = { status: 500, body: { error: { code: "internal", message: "down" } } };
    answers.targets = { status: 200, body: [target] };
    renderInventory();
    expect(await screen.findByText("Could not load environments.")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Scan targets" })).toBeInTheDocument();

    answers.environments = { status: 200, body: [environment] };
    await userEvent.setup().click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("list", { name: "Environments" })).toBeInTheDocument();
    expect(screen.queryByText("Could not load environments.")).not.toBeInTheDocument();
  });

  it("caps a long list at 20 rows and reveals the rest on request", async () => {
    const many: Target[] = Array.from({ length: 23 }, (_, i) => ({
      ...target,
      id: `t${i}`,
      name: `service-${i}`,
    }));
    answers.targets = { status: 200, body: many };
    renderInventory();
    const list = await screen.findByRole("list", { name: "Scan targets" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(20);
    await userEvent.setup().click(screen.getByRole("button", { name: "Show all 23" }));
    expect(within(list).getAllByRole("listitem")).toHaveLength(23);
    expect(screen.queryByRole("button", { name: /Show all/ })).not.toBeInTheDocument();
  });
});
