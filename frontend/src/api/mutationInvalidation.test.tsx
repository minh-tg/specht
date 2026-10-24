import { useReportUpload } from "@/pages/upload-report/useReportUpload";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, renderHook } from "@testing-library/react";
import { type ReactNode, type SubmitEvent } from "react";
import { describe, expect, it, vi } from "vitest";
import { queryKeys, useAddProjectMember, useRemoveProjectMember } from "./hooks";

vi.mock("./client", () => ({
  apiFetch: vi.fn(async () => ({ report_id: "r1", threshold_breached: false })),
  apiFetchWithTotal: vi.fn(),
  APIError: class APIError extends Error {},
}));
vi.mock("@/lib/sound", () => ({ playCue: vi.fn() }));

function harness() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  function wrapper({ children }: { children: ReactNode; }) {
    return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  }
  return { client, wrapper };
}

describe("mutation query invalidation", () => {
  it("refreshes permissions after adding, changing or removing a member", async () => {
    const { client, wrapper } = harness();
    client.setQueryData(queryKeys.project("probe"), { permissions: { triage: true } });
    const add = renderHook(() => useAddProjectMember("probe"), { wrapper });
    await act(async () => {
      await add.result.current.mutateAsync({ user_id: "me", role: "member" });
    });
    expect(client.getQueryState(queryKeys.project("probe"))?.isInvalidated).toBe(true);
    client.setQueryData(queryKeys.project("probe"), { permissions: { triage: true } });
    const remove = renderHook(() => useRemoveProjectMember("probe"), { wrapper });
    await act(async () => {
      await remove.result.current.mutateAsync({ userId: "me", role: "member", restorable: false });
    });
    expect(client.getQueryState(queryKeys.project("probe"))?.isInvalidated).toBe(true);
  });

  it("refreshes all cached finding filters after a report upload", async () => {
    const { client, wrapper } = harness();
    const keys = [
      queryKeys.findings("probe", {}),
      queryKeys.findings("probe", { severity: "high" }),
    ];
    for (const key of keys) client.setQueryData(key, { findings: [], total: 0 });
    const upload = renderHook(() => useReportUpload("probe"), { wrapper });
    await act(async () => {
      upload.result.current.setSelectedScanner("trivy");
      await upload.result.current.handleFile(
        { name: "scan.json", size: 2, text: async () => "{}" } as File,
      );
    });
    await act(async () => {
      await upload.result.current.handleSubmit({ preventDefault() {} } as SubmitEvent);
    });
    expect(upload.result.current.result).not.toBeNull();
    for (const key of keys) expect(client.getQueryState(key)?.isInvalidated).toBe(true);
  });
});
