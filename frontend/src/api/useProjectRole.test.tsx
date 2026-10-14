import { createTestQueryClient, jsonResponse } from "@/test/utils";
import { QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { useProjectRole } from "./hooks";

type Json = Record<string, unknown>;

let me: Json;
let project: Json;
let memberFetches: number;

function wrapper({ children }: { children: ReactNode; }) {
  return <QueryClientProvider client={createTestQueryClient()}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  memberFetches = 0;
  me = { id: "u1", email: "ada@acme.example", role: "member", created_at: "2026-01-01T00:00:00Z" };
  project = { id: "p1", slug: "payments", name: "Payments" };
  globalThis.fetch = vi.fn().mockImplementation((input: RequestInfo | URL) => {
    const url = String(input);
    if (url.endsWith("/api/v1/me")) return Promise.resolve(jsonResponse(me));
    if (url.endsWith("/api/v1/projects/payments")) return Promise.resolve(jsonResponse(project));
    if (url.includes("/members")) memberFetches++;
    return Promise.resolve(jsonResponse([]));
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useProjectRole", () => {
  it("trusts the role the server computed, so a role granted through a team counts", async () => {
    project = {
      ...project,
      role: "manager",
      permissions: { manage_members: true, triage: true },
    };
    const { result } = renderHook(() => useProjectRole("payments"), { wrapper });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.role).toBe("manager");
    expect(result.current.canManageMembers).toBe(true);
    expect(result.current.canTriage).toBe(true);
    expect(result.current.isAdmin).toBe(false);
    expect(memberFetches, "the roster is not a second source for the role").toBe(0);
  });

  it("follows the server's permissions over the rank of the role", async () => {
    project = {
      ...project,
      role: "member",
      permissions: { manage_members: false, triage: true },
    };
    const { result } = renderHook(() => useProjectRole("payments"), { wrapper });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.role).toBe("member");
    expect(result.current.canTriage).toBe(true);
    expect(result.current.canManageMembers).toBe(false);
  });

  it("gives an administrator of the platform admin authority without reading the project role", async () => {
    me = { ...me, role: "admin" };
    const { result } = renderHook(() => useProjectRole("payments"), { wrapper });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current).toMatchObject({ role: "admin", isAdmin: true, canManageMembers: true });
  });

  it("treats a project that names no role as a plain member", async () => {
    const { result } = renderHook(() => useProjectRole("payments"), { wrapper });

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current).toMatchObject({
      role: "member",
      isAdmin: false,
      canManageMembers: false,
      canTriage: false,
    });
  });
});
