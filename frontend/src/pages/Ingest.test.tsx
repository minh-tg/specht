import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { Ingest } from "./Ingest";

function renderIngest() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <Ingest />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function createJsonFile(content: string, name = "report.json") {
  return new File([content], name, { type: "application/json" });
}

let fetchCalls: { url: string; method: string; body?: string; }[] = [];

describe("Ingest", () => {
  beforeEach(() => {
    fetchCalls = [];
    globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
      const u = String(url);
      const method = ((opts as RequestInit)?.method ?? "GET").toUpperCase();
      fetchCalls.push({ url: u, method, body: (opts as RequestInit)?.body as string | undefined });

      if (u === "/api/v1/scanners" && method === "GET") {
        return {
          ok: true,
          json: () =>
            Promise.resolve([
              {
                name: "trivy",
                version: "2",
                finding_kinds: ["sca", "secret", "iac"],
                scan_types: ["image", "iac", "filesystem"],
                provides_packages: true,
                supports_auto_detection: true,
              },
              {
                name: "osv-scanner",
                version: "1",
                finding_kinds: ["sca"],
                scan_types: ["lockfile", "sbom", "repository", "image", "filesystem"],
                provides_packages: true,
                supports_auto_detection: true,
              },
            ]),
        } as Response;
      }
      if (u === "/api/v1/reports" && method === "POST") {
        return {
          ok: true,
          json: () =>
            Promise.resolve({
              id: "r1",
              project_id: "p1",
              tool_name: "trivy",
              status: "completed",
              scan_target: null,
              total_findings: null,
              created_at: "",
              updated_at: "",
            }),
        } as Response;
      }
      return {
        ok: true,
        json: () =>
          Promise.resolve([
            {
              id: "p1",
              slug: "test-project",
              name: "Test Project",
              description: null,
              created_at: "",
              updated_at: "",
            },
          ]),
      } as Response;
    });
  });

  it("shows validation error for non-json files", async () => {
    renderIngest();

    const file = new File(["test"], "report.txt", { type: "text/plain" });
    const input = screen.getByLabelText(/scan file/i) as HTMLInputElement;

    fireEvent.change(input, { target: { files: [file] } });

    await waitFor(() => {
      expect(screen.getByText("Unsupported file format")).toBeInTheDocument();
    });
  });

  it("shows upload button disabled until all fields filled", async () => {
    renderIngest();
    const btn = screen.getByRole("button", { name: /upload/i });
    expect(btn).toBeDisabled();
  });

  it("submits JSON body on valid form", async () => {
    renderIngest();
    const user = userEvent.setup();

    await waitFor(() => {
      expect(screen.getByText("Test Project")).toBeInTheDocument();
    });
    await waitFor(() => {
      expect(screen.getByRole("combobox", { name: /scanner/i })).not.toBeDisabled();
    });

    await user.selectOptions(screen.getByRole("combobox", { name: /project/i }), "test-project");
    await user.selectOptions(
      screen.getByRole("combobox", { name: /scanner/i }),
      "trivy (2)",
    );
    await user.upload(screen.getByLabelText(/scan file/i), createJsonFile("{\"vuln\":true}"));
    await user.click(screen.getByRole("button", { name: /upload/i }));

    await waitFor(() => {
      expect(screen.getByText(/Report submitted/)).toBeInTheDocument();
    });

    const postCall = fetchCalls.find((c) => c.url === "/api/v1/reports" && c.method === "POST");
    expect(postCall).toBeDefined();
    const body = JSON.parse(postCall!.body!);
    expect(body.project).toBe("test-project");
    expect(body.scanner).toBe("trivy");
    expect(body.raw_data).toBe("{\"vuln\":true}");
  });
});

describe("Ingest scanner loading and error states", () => {
  it("shows loading then an error when the scanners endpoint fails", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url) => {
      const u = String(url);
      if (u === "/api/v1/scanners") {
        return { ok: false, status: 500, json: () => Promise.resolve({}) } as Response;
      }
      if (u === "/api/v1/projects") {
        return { ok: true, json: () => Promise.resolve([]) } as Response;
      }
      return { ok: true, json: () => Promise.resolve([]) } as Response;
    });

    renderIngest();
    await waitFor(() => {
      expect(screen.getByText(/failed to load scanners/i)).toBeInTheDocument();
    });
  });

  it("shows the empty state when the scanners endpoint returns no rows", async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url) => {
      const u = String(url);
      if (u === "/api/v1/scanners") {
        return { ok: true, json: () => Promise.resolve([]) } as Response;
      }
      if (u === "/api/v1/projects") {
        return { ok: true, json: () => Promise.resolve([]) } as Response;
      }
      return { ok: true, json: () => Promise.resolve([]) } as Response;
    });

    renderIngest();
    await waitFor(() => {
      expect(screen.getByText(/no scanners available/i)).toBeInTheDocument();
    });
  });
});
