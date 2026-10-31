import type { Finding, Project, Report, Waiver } from "@/types/api";
import snapshot from "./snapshot.json";

export class APIError extends Error {
  readonly retryAfter = undefined;
  readonly requestId = undefined;
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "APIError";
    this.status = status;
    this.code = code;
  }
}

interface Fixture {
  data: unknown;
  total: number | null;
}
interface Options extends RequestInit {
  skipAuthRedirect?: boolean;
}
export interface ApiResponseWithTotal<T> {
  data: T;
  total: number | null;
}
const fixtures = snapshot.fixtures as Record<string, Fixture>;
const project = `/api/v1/projects/${snapshot.slug}`;
const clockOffset = Date.now() - Date.parse((fixtures[project].data as Project).created_at);
const relativeDates = new Set([
  "created_at",
  "updated_at",
  "first_seen_at",
  "last_seen_at",
  "completed_at",
  "expires_at",
  "requested_at",
  "decided_at",
  "analysis_expires_at",
  "raw_data_expires_at",
]);

/** Keeps synthetic relative ages consistent without changing the browser's clock. */
export function copySample<T>(value: T): T {
  const copy = structuredClone(value);
  function visit(node: unknown) {
    if (!node || typeof node !== "object") return;
    for (const [key, item] of Object.entries(node)) {
      if (relativeDates.has(key) && typeof item === "string" && Number.isFinite(Date.parse(item))) {
        (node as Record<string, unknown>)[key] = new Date(Date.parse(item) + clockOffset)
          .toISOString();
      } else visit(item);
    }
  }
  visit(copy);
  return copy;
}
const severityRank: Record<string, number> = {
  unknown: 0,
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  critical: 5,
};

function unavailable(message = "This view is not included in the read-only sample."): never {
  throw new APIError(404, "demo_unavailable", message);
}
function queryKeys(url: URL, allowed: readonly string[]) {
  for (const key of url.searchParams.keys()) {
    if (!allowed.includes(key)) {
      throw new APIError(400, "demo_query", "This filter is not included in the sample.");
    }
  }
}
function integer(url: URL, key: string, fallback: number, max: number): number {
  const raw = url.searchParams.get(key);
  if (raw === null) return fallback;
  if (!/^\d+$/.test(raw) || Number(raw) > max || (key === "limit" && Number(raw) === 0)) {
    throw new APIError(400, "demo_query", "Use a valid sample page size or offset.");
  }
  return Number(raw);
}
function stored(key: string): Fixture {
  if (!Object.hasOwn(fixtures, key)) unavailable();
  return fixtures[key];
}
function findings(url: URL): Fixture {
  queryKeys(url, [
    "severity",
    "status",
    "kind",
    "analysis_state",
    "q",
    "sort",
    "dir",
    "limit",
    "offset",
  ]);
  let rows = [...stored(url.pathname).data as Finding[]];
  const fields = {
    severity: "current_severity",
    status: "state",
    kind: "finding_kind",
    analysis_state: "analysis_state",
  } as const;
  for (const [key, field] of Object.entries(fields)) {
    const values = url.searchParams.get(key)?.split(",");
    if (values) {
      rows = rows.filter((row) =>
        values.includes(String(row[field] ?? (field === "analysis_state" ? "unanalyzed" : "")))
      );
    }
  }
  const text = url.searchParams.get("q")?.toLowerCase();
  if (text) {
    rows = rows.filter((row) =>
      `${row.current_title} ${row.fingerprint}`.toLowerCase().includes(text)
    );
  }
  const sort = url.searchParams.get("sort") ?? "severity";
  if (!["severity", "title", "first_seen", "last_seen"].includes(sort)) {
    unavailable("This ordering is not included in the sample.");
  }
  const direction = url.searchParams.get("dir") ?? "desc";
  if (!["asc", "desc"].includes(direction)) {
    throw new APIError(400, "demo_query", "Choose ascending or descending order.");
  }
  rows.sort((a, b) => {
    const delta = sort === "severity"
      ? severityRank[a.current_severity] - severityRank[b.current_severity]
      : sort === "title"
      ? a.current_title.localeCompare(b.current_title)
      : Date.parse(a[sort === "first_seen" ? "first_seen_at" : "last_seen_at"])
        - Date.parse(b[sort === "first_seen" ? "first_seen_at" : "last_seen_at"]);
    return (direction === "asc" ? delta : -delta) || a.id.localeCompare(b.id);
  });
  const total = rows.length;
  const offset = integer(url, "offset", 0, Number.MAX_SAFE_INTEGER);
  const limit = integer(url, "limit", 50, 500);
  return { data: rows.slice(offset, offset + limit), total };
}
function resolve(path: string, options: Options): Fixture {
  if ((options.method ?? "GET").toUpperCase() !== "GET") {
    throw new APIError(403, "demo_read_only", "This demo is read-only. No changes were made.");
  }
  if (!path.startsWith("/api/v1/") || path.includes("\\")) unavailable();
  const url = new URL(path, "https://demo.invalid");
  if (url.origin !== "https://demo.invalid" || !url.pathname.startsWith("/api/v1/")) unavailable();
  if (url.pathname === `${project}/findings`) return findings(url);
  if (url.pathname === `${project}/reports`) {
    queryKeys(url, ["commit", "commit_prefix", "branch", "limit", "offset"]);
    let rows = stored(url.pathname).data as Report[];
    const commit = url.searchParams.get("commit");
    if (commit) {
      rows = rows.filter((report) =>
        url.searchParams.get("commit_prefix") === "true"
          ? report.commit_sha?.startsWith(commit)
          : report.commit_sha === commit
      );
    }
    const branch = url.searchParams.get("branch");
    if (branch !== null) rows = rows.filter((report) => report.branch === branch);
    const offset = integer(url, "offset", 0, Number.MAX_SAFE_INTEGER);
    return {
      data: rows.slice(offset, offset + integer(url, "limit", 50, 500)),
      total: rows.length,
    };
  }
  if (url.pathname === `${project}/waivers`) {
    queryKeys(url, ["status"]);
    const statuses = url.searchParams.get("status")?.split(",");
    const rows = stored(url.pathname).data as Waiver[];
    return {
      data: statuses ? rows.filter((row) => statuses.includes(row.status)) : rows,
      total: null,
    };
  }
  if (url.pathname === `${project}/gate`) {
    queryKeys(url, ["severity", "introduced_only", "report_id"]);
    const severity = url.searchParams.get("severity");
    if (severity && severity !== "high") {
      unavailable("Only the sample's high-severity floor is available in this demo.");
    }
    if (url.searchParams.get("introduced_only") === "true") {
      return stored(
        `${url.pathname}?introduced_only=true&report_id=${url.searchParams.get("report_id") ?? ""}`,
      );
    }
    return stored(url.pathname);
  }
  queryKeys(url, url.pathname.endsWith("/events") ? ["limit"] : []);
  return stored(url.pathname);
}

export async function apiFetchWithTotal<T>(
  path: string,
  options: Options = {},
): Promise<ApiResponseWithTotal<T>> {
  const result = resolve(path, options);
  return { data: copySample(result.data) as T, total: result.total };
}
export async function apiFetch<T>(path: string, options: Options = {}): Promise<T> {
  return (await apiFetchWithTotal<T>(path, options)).data;
}
export async function apiFetchResponse<T>(
  path: string,
  options: Options = {},
): Promise<{ data: T; response: Response; }> {
  const result = await apiFetchWithTotal<T>(path, options);
  const headers = new Headers({ "Content-Type": "application/json" });
  if (result.total !== null) headers.set("X-Total-Count", String(result.total));
  return { data: result.data, response: new Response(JSON.stringify(result.data), { headers }) };
}
