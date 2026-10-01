import { createTestQueryClient } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { vi } from "vitest";
import { UploadReport } from "./UploadReport";

const PROJECT = {
  id: "p1",
  slug: "test-project",
  name: "Test Project",
  description: null,
  created_at: "",
  updated_at: "",
};

const SCANNERS = [
  {
    name: "trivy",
    version: "2",
    finding_kinds: ["sca", "secret", "iac"],
    scan_types: ["image", "iac", "filesystem"],
    provides_packages: true,
    supports_auto_detection: true,
  },
];

function renderUpload() {
  const qc = createTestQueryClient();
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter initialEntries={["/test-project/reports/upload"]}>
        <Routes>
          <Route path="/:slug/reports/upload" element={<UploadReport />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function createJsonFile(content: string, name = "report.json") {
  return new File([content], name, { type: "application/json" });
}

let fetchCalls: { url: string; method: string; body?: string; }[] = [];

function postCall() {
  return fetchCalls.find((c) => c.url === "/api/v1/reports" && c.method === "POST");
}

function installFetch(postResponse: () => Response) {
  fetchCalls = [];
  globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
    const u = String(url);
    const method = ((opts as RequestInit)?.method ?? "GET").toUpperCase();
    fetchCalls.push({ url: u, method, body: (opts as RequestInit)?.body as string | undefined });

    if (u === "/api/v1/scanners" && method === "GET") {
      return { ok: true, json: () => Promise.resolve(SCANNERS) } as Response;
    }
    if (u === "/api/v1/projects/test-project" && method === "GET") {
      return { ok: true, json: () => Promise.resolve(PROJECT) } as Response;
    }
    if (u === "/api/v1/reports" && method === "POST") {
      return postResponse();
    }
    return { ok: true, json: () => Promise.resolve([]) } as Response;
  });
}

async function fillValidForm() {
  const user = userEvent.setup();
  await waitFor(() => {
    expect(screen.getByRole("combobox", { name: /scanner/i })).toBeInTheDocument();
  });
  await user.selectOptions(screen.getByRole("combobox", { name: /scanner/i }), "trivy (2)");
  await user.upload(screen.getByLabelText(/scan file/i), createJsonFile("{\"vuln\":true}"));
  return user;
}

describe("UploadReport", () => {
  it("shows the project context and back link", async () => {
    installFetch(() => ({ ok: true, json: () => Promise.resolve({}) } as Response));
    renderUpload();

    expect(await screen.findByRole("heading", { name: "Upload a report" })).toBeInTheDocument();
    expect(await screen.findByText("Uploading to Test Project")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Test Project/ })).toHaveAttribute(
      "href",
      "/test-project/reports",
    );
    expect(screen.queryByLabelText(/project/i)).not.toBeInTheDocument();
  });

  it("shows a blocked result card and posts the upload", async () => {
    installFetch(() => ({
      ok: true,
      json: () => Promise.resolve({ report_id: "r1", total_findings: 3, threshold_breached: true }),
    } as Response));
    renderUpload();

    const user = await fillValidForm();
    await user.click(screen.getByRole("button", { name: /^upload$/i }));

    const card = await screen.findByRole("status");
    expect(card).toHaveTextContent("3 findings found");
    expect(within(card).getByText("BLOCKED")).toBeInTheDocument();
    expect(within(card).getByText("The gate would block this project.")).toBeInTheDocument();
    expect(within(card).getByRole("link", { name: "View findings" })).toHaveAttribute(
      "href",
      "/test-project/findings",
    );
    expect(within(card).getByRole("link", { name: "Back to reports" })).toHaveAttribute(
      "href",
      "/test-project/reports",
    );

    const post = postCall();
    expect(post).toBeDefined();
    expect(JSON.parse(post!.body!)).toEqual({
      project: "test-project",
      scanner: "trivy",
      raw_data: { vuln: true },
    });

    // The URL fixes the project: never sent from a dropdown.
    expect(screen.queryByRole("combobox", { name: /project/i })).not.toBeInTheDocument();

    await user.click(within(card).getByRole("button", { name: "Upload another" }));
    expect(screen.queryByRole("status")).not.toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: /scanner/i })).toHaveValue("");
  });

  it("shows a passing result card", async () => {
    installFetch(() => ({
      ok: true,
      json: () =>
        Promise.resolve({ report_id: "r2", total_findings: 1, threshold_breached: false }),
    } as Response));
    renderUpload();

    const user = await fillValidForm();
    await user.click(screen.getByRole("button", { name: /^upload$/i }));

    const card = await screen.findByRole("status");
    expect(card).toHaveTextContent("1 finding found");
    expect(within(card).getByText("PASSING")).toBeInTheDocument();
    expect(within(card).getByText("The gate passes.")).toBeInTheDocument();
  });

  it("shows validation error for non-json files", async () => {
    installFetch(() => ({ ok: true, json: () => Promise.resolve({}) } as Response));
    renderUpload();

    const file = new File(["test"], "report.txt", { type: "text/plain" });
    fireEvent.change(screen.getByLabelText(/scan file/i), { target: { files: [file] } });

    expect(await screen.findByText("Unsupported file format")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^upload$/i })).toBeDisabled();
    expect(postCall()).toBeUndefined();
  });

  it("rejects files larger than 10MB", async () => {
    installFetch(() => ({ ok: true, json: () => Promise.resolve({}) } as Response));
    renderUpload();

    const file = new File([new Uint8Array(10 * 1024 * 1024 + 1)], "big.json", {
      type: "application/json",
    });
    fireEvent.change(screen.getByLabelText(/scan file/i), { target: { files: [file] } });

    expect(await screen.findByText("File too large (max 10MB)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^upload$/i })).toBeDisabled();
    expect(postCall()).toBeUndefined();
  });

  it("rejects a .json file whose contents are not JSON", async () => {
    installFetch(() => ({ ok: true, json: () => Promise.resolve({}) } as Response));
    renderUpload();

    const user = userEvent.setup();
    await waitFor(() => {
      expect(screen.getByRole("combobox", { name: /scanner/i })).toBeInTheDocument();
    });
    await user.selectOptions(screen.getByRole("combobox", { name: /scanner/i }), "trivy (2)");
    await user.upload(screen.getByLabelText(/scan file/i), createJsonFile("not json"));

    expect(await screen.findByText("Invalid JSON")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^upload$/i })).toBeDisabled();
    expect(postCall()).toBeUndefined();
  });

  it("shows the permission message on a 403", async () => {
    installFetch(() => ({
      ok: false,
      status: 403,
      json: () => Promise.resolve({ error: { code: "forbidden", message: "Forbidden" } }),
    } as Response));
    renderUpload();

    const user = await fillValidForm();
    await user.click(screen.getByRole("button", { name: /^upload$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(
      "You don't have permission to upload reports to this project.",
    );
  });

  it("shows the server message for other API errors", async () => {
    installFetch(() => ({
      ok: false,
      status: 422,
      json: () => Promise.resolve({ error: { code: "invalid", message: "Unprocessable payload" } }),
    } as Response));
    renderUpload();

    const user = await fillValidForm();
    await user.click(screen.getByRole("button", { name: /^upload$/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Unprocessable payload");
  });
});

describe("UploadReport scanner loading and error states", () => {
  it("shows an error when the scanners endpoint fails", async () => {
    fetchCalls = [];
    globalThis.fetch = vi.fn().mockImplementation(async (url) => {
      const u = String(url);
      if (u === "/api/v1/scanners") {
        return { ok: false, status: 500, json: () => Promise.resolve({}) } as Response;
      }
      if (u === "/api/v1/projects/test-project") {
        return { ok: true, json: () => Promise.resolve(PROJECT) } as Response;
      }
      return { ok: true, json: () => Promise.resolve([]) } as Response;
    });

    renderUpload();
    await waitFor(() => {
      expect(screen.getByText(/failed to load scanners/i)).toBeInTheDocument();
    });
  });

  it("retries the scanners request and keeps the chosen file", async () => {
    const user = userEvent.setup();
    let scannerCalls = 0;
    fetchCalls = [];
    globalThis.fetch = vi.fn().mockImplementation(async (url, opts) => {
      const u = String(url);
      const method = ((opts as RequestInit)?.method ?? "GET").toUpperCase();
      fetchCalls.push({ url: u, method, body: (opts as RequestInit)?.body as string | undefined });
      if (u === "/api/v1/scanners" && method === "GET") {
        scannerCalls += 1;
        if (scannerCalls === 1) {
          return { ok: false, status: 500, json: () => Promise.resolve({}) } as Response;
        }
        return { ok: true, json: () => Promise.resolve(SCANNERS) } as Response;
      }
      if (u === "/api/v1/projects/test-project" && method === "GET") {
        return { ok: true, json: () => Promise.resolve(PROJECT) } as Response;
      }
      return { ok: true, json: () => Promise.resolve([]) } as Response;
    });

    renderUpload();

    const retry = await screen.findByRole("button", { name: "Retry" });
    await user.upload(screen.getByLabelText(/scan file/i), createJsonFile("{\"vuln\":true}"));
    expect(await screen.findByText("report.json loaded")).toBeInTheDocument();

    await user.click(retry);

    await waitFor(() => {
      expect(screen.getByRole("combobox", { name: /scanner/i })).toBeInTheDocument();
    });
    expect(scannerCalls).toBe(2);
    // Choosing a file must survive the retry: refetching does not reset the form.
    expect(screen.getByText("report.json loaded")).toBeInTheDocument();
  });

  it("shows the empty state when the scanners endpoint returns no rows", async () => {
    fetchCalls = [];
    globalThis.fetch = vi.fn().mockImplementation(async (url) => {
      const u = String(url);
      if (u === "/api/v1/scanners") {
        return { ok: true, json: () => Promise.resolve([]) } as Response;
      }
      if (u === "/api/v1/projects/test-project") {
        return { ok: true, json: () => Promise.resolve(PROJECT) } as Response;
      }
      return { ok: true, json: () => Promise.resolve([]) } as Response;
    });

    renderUpload();
    await waitFor(() => {
      expect(screen.getByText(/no scanners available/i)).toBeInTheDocument();
    });
  });
});
