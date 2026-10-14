import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { useArtifacts, useEnvironments, useTargets } from "./inventory";

function wrapper({ children }: { children: React.ReactNode; }) {
  return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
}

let urls: string[];

beforeEach(() => {
  urls = [];
  globalThis.fetch = vi.fn().mockImplementation(async (input: RequestInfo | URL) => {
    urls.push(String(input));
    return jsonResponse([]);
  });
});

describe("inventory hooks", () => {
  it.each([
    ["useEnvironments", useEnvironments, "/api/v1/projects/payments/environments"],
    ["useTargets", useTargets, "/api/v1/projects/payments/targets"],
    ["useArtifacts", useArtifacts, "/api/v1/projects/payments/artifacts"],
  ])("%s reads its list for the project", async (_name, hook, path) => {
    const { result } = renderHook(() => hook("payments"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(urls).toEqual([path]);
  });

  it.each([
    ["useEnvironments", useEnvironments],
    ["useTargets", useTargets],
    ["useArtifacts", useArtifacts],
  ])("%s does not fetch without a project slug", async (_name, hook) => {
    const { result } = renderHook(() => hook(""), { wrapper });
    expect(result.current.fetchStatus).toBe("idle");
    expect(urls).toEqual([]);
  });

  it("encodes the slug in the path", async () => {
    const { result } = renderHook(() => useTargets("a/b"), { wrapper });
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(urls).toEqual(["/api/v1/projects/a%2Fb/targets"]);
  });
});
