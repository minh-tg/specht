import type { Finding, Project, Report, Waiver } from "@/types/api";
import { afterEach, describe, expect, it, vi } from "vitest";
import { apiFetch, apiFetchResponse, apiFetchWithTotal } from "./client";
import snapshot from "./snapshot.json";

const root = `/api/v1/projects/${snapshot.slug}`;
afterEach(() => vi.restoreAllMocks());

describe("read-only sample transport", () => {
  it.each(["POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])(
    "refuses %s without network access",
    async (method) => {
      const network = vi.spyOn(globalThis, "fetch");
      await expect(apiFetch(`${root}/findings`, { method, body: "{}" })).rejects.toMatchObject({
        status: 403,
        code: "demo_read_only",
      });
      expect(network).not.toHaveBeenCalled();
    },
  );
  it.each([
    "/api/v1/auth/login",
    "/api/v1/admin/users",
    "/api/v1/projects/other",
    "https://example.com/api/v1/projects",
    "//example.com/api/v1/projects",
    "/api/v1/../../me",
  ])("refuses unsupported path %s locally", async (path) => {
    const network = vi.spyOn(globalThis, "fetch");
    await expect(apiFetch(path)).rejects.toMatchObject({ status: 404, code: "demo_unavailable" });
    expect(network).not.toHaveBeenCalled();
  });
  it("reads known data without a fetch fallback and returns independent copies", async () => {
    const network = vi.spyOn(globalThis, "fetch");
    const first = await apiFetch<Project>(root);
    first.name = "changed";
    expect((await apiFetch<Project>(root)).name).toBe(snapshot.slug);
    expect(network).not.toHaveBeenCalled();
  });
  it("filters severity, analysis and text and reports totals before paging", async () => {
    const all = await apiFetch<Finding[]>(`${root}/findings?sort=title&dir=asc`);
    const page = await apiFetchWithTotal<Finding[]>(
      `${root}/findings?sort=title&dir=asc&offset=1&limit=1`,
    );
    expect(page).toEqual({ data: all.slice(1, 2), total: 3 });
    expect(
      (await apiFetchWithTotal<Finding[]>(
        `${root}/findings?severity=high&status=open,reopened&analysis_state=unanalyzed,in_triage`,
      )).total,
    ).toBe(2);
    expect((await apiFetchWithTotal<Finding[]>(`${root}/findings?q=urllib3`)).total).toBe(1);
    expect(await apiFetchWithTotal(`${root}/findings?q=not-present`)).toEqual({
      data: [],
      total: 0,
    });
  });
  it.each(["limit=-1", "limit=0", "limit=501", "offset=1.5", "unknown=true"])(
    "rejects invalid query %s",
    async (query) => {
      await expect(apiFetch(`${root}/findings?${query}`)).rejects.toMatchObject({ status: 400 });
    },
  );
  it("preserves exact report lookup versus explicit abbreviated commit matching", async () => {
    const prefix = snapshot.commit.slice(0, 7);
    expect(await apiFetch(`${root}/reports?commit=${prefix}`)).toEqual([]);
    const reports = await apiFetch<Report[]>(`${root}/reports?commit=${prefix}&commit_prefix=true`);
    expect(reports).toHaveLength(1);
    expect((await apiFetch<Report>(`/api/v1/reports/${reports[0].id}`)).id).toBe(reports[0].id);
  });
  it("does not invent a gate for an unknown report or a different floor", async () => {
    await expect(apiFetch(`${root}/gate?introduced_only=true&report_id=missing`)).rejects
      .toMatchObject({ status: 404 });
    await expect(apiFetch(`${root}/gate?severity=critical`)).rejects.toMatchObject({ status: 404 });
  });
  it("keeps the observer distinct from the requester and denies every management permission", async () => {
    const project = await apiFetch<Project>(root);
    expect(Object.values(project.permissions!)).not.toContain(true);
    const waivers = await apiFetch<Waiver[]>(`${root}/waivers`);
    const observer = await apiFetch<{ id: string; role: string; }>("/api/v1/me");
    expect(observer.role).toBe("member");
    expect(waivers.every((waiver) => waiver.requested_by !== observer.id)).toBe(true);
  });
  it("exposes a real total header and normalizes empty lists as arrays", async () => {
    const result = await apiFetchResponse<Finding[]>(`${root}/findings?limit=1`);
    expect(result.response.headers.get("X-Total-Count")).toBe("3");
    const finding = result.data[0];
    expect(await apiFetch(`/api/v1/findings/${finding.id}/events`)).toEqual([]);
    expect(await apiFetch(`/api/v1/findings/${finding.id}/reachability`)).toEqual([]);
  });
});
