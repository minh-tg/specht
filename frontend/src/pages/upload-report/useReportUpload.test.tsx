import { createTestQueryClient } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook } from "@testing-library/react";
import type { ChangeEvent, ReactNode, SubmitEvent } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_FILE_SIZE, useReportUpload } from "./useReportUpload";

function makeWrapper() {
  const queryClient = createTestQueryClient();
  return function Wrapper({ children }: { children: ReactNode; }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
  };
}

function renderUploadHook() {
  return renderHook(() => useReportUpload("test-project"), { wrapper: makeWrapper() });
}

function fileChangeEvent(file: File): ChangeEvent<HTMLInputElement> {
  return { target: { files: [file] } } as unknown as ChangeEvent<HTMLInputElement>;
}

const submitEvent = { preventDefault: () => {} } as unknown as SubmitEvent;

function jsonFile(content: string, name = "report.json") {
  return new File([content], name, { type: "application/json" });
}

async function chooseScannerAndFile(
  result: { current: ReturnType<typeof useReportUpload>; },
  content = "{\"vuln\":true}",
) {
  await act(async () => {
    await result.current.handleFileChange(fileChangeEvent(jsonFile(content)));
  });
  act(() => result.current.setSelectedScanner("trivy"));
}

describe("useReportUpload", () => {
  beforeEach(() => {
    globalThis.fetch = vi.fn();
  });

  it("rejects a file larger than 10 MiB", async () => {
    const { result } = renderUploadHook();

    await act(async () => {
      await result.current.handleFileChange(
        fileChangeEvent(
          new File([new Uint8Array(MAX_FILE_SIZE + 1)], "big.json", { type: "application/json" }),
        ),
      );
    });

    expect(result.current.fileError).toBe("File too large (max 10MB)");
    expect(result.current.fileName).toBeNull();
    expect(result.current.canSubmit).toBe(false);
  });

  it("rejects a file whose name is not .json", async () => {
    const { result } = renderUploadHook();

    await act(async () => {
      await result.current.handleFileChange(
        fileChangeEvent(new File(["test"], "report.txt", { type: "text/plain" })),
      );
    });

    expect(result.current.fileError).toBe("Unsupported file format");
    expect(result.current.fileName).toBeNull();
    expect(result.current.canSubmit).toBe(false);
  });

  it("rejects a .json file whose contents are not JSON", async () => {
    const { result } = renderUploadHook();

    await act(async () => {
      await result.current.handleFileChange(fileChangeEvent(jsonFile("not json")));
    });

    expect(result.current.fileError).toBe("Invalid JSON");
    expect(result.current.fileName).toBeNull();
  });

  it("sets the result after a successful submit", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          report_id: "r1",
          total_findings: 3,
          threshold_breached: true,
          replayed: false,
        }),
    } as Response);
    const { result } = renderUploadHook();

    await chooseScannerAndFile(result);
    expect(result.current.canSubmit).toBe(true);

    await act(async () => {
      await result.current.handleSubmit(submitEvent);
    });

    expect(result.current.result).toEqual({
      report_id: "r1",
      total_findings: 3,
      threshold_breached: true,
      replayed: false,
    });
    expect(result.current.uploadError).toBeNull();
    expect(result.current.submitting).toBe(false);
    expect(result.current.fileName).toBeNull();

    const [url, opts] = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe("/api/v1/reports");
    expect(JSON.parse(opts.body as string)).toEqual({
      project: "test-project",
      scanner: "trivy",
      raw_data: { vuln: true },
    });
  });

  it("sets the permission error when a 403 comes back", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      json: () => Promise.resolve({ error: { code: "forbidden", message: "Forbidden" } }),
    } as Response);
    const { result } = renderUploadHook();

    await chooseScannerAndFile(result);
    await act(async () => {
      await result.current.handleSubmit(submitEvent);
    });

    expect(result.current.uploadError).toBe(
      "You don't have permission to upload reports to this project.",
    );
    expect(result.current.result).toBeNull();
    expect(result.current.submitting).toBe(false);
  });

  it("surfaces the server message for other API errors", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      json: () => Promise.resolve({ error: { code: "invalid", message: "Unprocessable payload" } }),
    } as Response);
    const { result } = renderUploadHook();

    await chooseScannerAndFile(result);
    await act(async () => {
      await result.current.handleSubmit(submitEvent);
    });

    expect(result.current.uploadError).toBe("Unprocessable payload");
  });

  it("clears every field on reset", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          report_id: "r1",
          total_findings: 3,
          threshold_breached: false,
          replayed: false,
        }),
    } as Response);
    const { result } = renderUploadHook();

    await chooseScannerAndFile(result);
    await act(async () => {
      await result.current.handleSubmit(submitEvent);
    });
    expect(result.current.result).not.toBeNull();

    act(() => result.current.resetForm());
    expect(result.current.result).toBeNull();
    expect(result.current.selectedScanner).toBe("");
    expect(result.current.fileName).toBeNull();

    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 403,
      json: () => Promise.resolve({ error: { code: "forbidden", message: "Forbidden" } }),
    } as Response);
    await chooseScannerAndFile(result);
    await act(async () => {
      await result.current.handleSubmit(submitEvent);
    });
    expect(result.current.uploadError).toBe(
      "You don't have permission to upload reports to this project.",
    );

    act(() => result.current.resetForm());
    expect(result.current.uploadError).toBeNull();
    expect(result.current.fileError).toBeNull();
    expect(result.current.fileName).toBeNull();
    expect(result.current.canSubmit).toBe(false);
  });
});
