const playCue = vi.hoisted(() => vi.fn());
vi.mock("@/lib/sound", () => ({ playCue }));

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
    playCue.mockClear();
  });

  it("handleFile takes a dropped file through the same size, format and JSON checks", async () => {
    const { result } = renderUploadHook();

    await act(async () => {
      await result.current.handleFile(
        new File([new Uint8Array(MAX_FILE_SIZE + 1)], "big.json", { type: "application/json" }),
      );
    });
    expect(result.current.fileError).toBe("File too large (max 10MB)");

    await act(async () => {
      await result.current.handleFile(new File(["x"], "report.txt", { type: "text/plain" }));
    });
    expect(result.current.fileError).toBe("Unsupported file format");

    await act(async () => {
      await result.current.handleFile(jsonFile("not json"));
    });
    expect(result.current.fileError).toBe("Invalid JSON");
    expect(result.current.fileName).toBeNull();

    await act(async () => {
      await result.current.handleFile(jsonFile("{\"vuln\":true}"));
    });
    expect(result.current.fileError).toBeNull();
    expect(result.current.fileName).toBe("report.json");
    expect(result.current.fileSize).toBe(13);
  });

  it("clearFile drops the file and empties the input so the same file can be chosen again", async () => {
    const { result } = renderUploadHook();
    const input = document.createElement("input");
    input.type = "file";
    Object.defineProperty(input, "value", { value: "C:\\fakepath\\report.json", writable: true });
    (result.current.fileRef as { current: HTMLInputElement | null; }).current = input;
    await chooseScannerAndFile(result);
    expect(result.current.canSubmit).toBe(true);

    act(() => result.current.clearFile());

    expect(result.current.fileName).toBeNull();
    expect(result.current.fileSize).toBeNull();
    expect(result.current.fileError).toBeNull();
    expect(result.current.canSubmit).toBe(false);
    expect(input.value).toBe("");
  });

  it("empties the input when a file is refused, so choosing it again fires change", async () => {
    const { result } = renderUploadHook();
    const input = document.createElement("input");
    input.type = "file";
    Object.defineProperty(input, "value", { value: "C:\\fakepath\\report.json", writable: true });
    (result.current.fileRef as { current: HTMLInputElement | null; }).current = input;

    await act(async () => {
      await result.current.handleFile(jsonFile("not json"));
    });

    expect(input.value).toBe("");
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

  it("rejects a file whose name is neither .json nor .jsonl", async () => {
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

  it("accepts a .jsonl file and sends its lines as an array", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ report_id: "r2", total_findings: 2, replayed: false }),
    } as Response);
    const { result } = renderUploadHook();

    await act(async () => {
      await result.current.handleFileChange(
        fileChangeEvent(
          jsonFile("{\"template-id\":\"a\"}\n{\"template-id\":\"b\"}\n", "nuclei.jsonl"),
        ),
      );
    });
    act(() => result.current.setSelectedScanner("nuclei"));
    expect(result.current.fileError).toBeNull();
    expect(result.current.fileName).toBe("nuclei.jsonl");

    await act(async () => {
      await result.current.handleSubmit(submitEvent);
    });

    const call = vi.mocked(globalThis.fetch).mock.calls[0];
    const sent = JSON.parse(String((call[1] as RequestInit).body));
    expect(sent.scanner).toBe("nuclei");
    expect(sent.raw_data).toEqual([{ "template-id": "a" }, { "template-id": "b" }]);
  });

  it("reports the line of a .jsonl file that is not JSON", async () => {
    const { result } = renderUploadHook();

    await act(async () => {
      await result.current.handleFileChange(
        fileChangeEvent(jsonFile("{\"a\":1}\noops", "scan.jsonl")),
      );
    });

    expect(result.current.fileError).toBe("Line 2 is not valid JSON");
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

  it.each([[false, "pass"], [true, "block"]])(
    "plays the gate verdict cue (breached: %s -> %s)",
    async (breached, cue) => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: () =>
          Promise.resolve({
            report_id: "r1",
            total_findings: 1,
            threshold_breached: breached,
            replayed: false,
          }),
      } as Response);
      const { result } = renderUploadHook();
      await chooseScannerAndFile(result);
      expect(playCue).not.toHaveBeenCalled();
      await act(async () => {
        await result.current.handleSubmit(submitEvent);
      });
      expect(playCue).toHaveBeenCalledExactlyOnceWith(cue);
    },
  );

  it("plays no cue when the upload fails", async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      ok: false,
      status: 422,
      json: () => Promise.resolve({ error: { code: "invalid", message: "Bad" } }),
    } as Response);
    const { result } = renderUploadHook();
    await chooseScannerAndFile(result);
    await act(async () => {
      await result.current.handleSubmit(submitEvent);
    });
    expect(playCue).not.toHaveBeenCalled();
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
