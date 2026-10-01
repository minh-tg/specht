import { useFindings } from "@/api/hooks";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { analysisStateLabel, technicalStateLabel } from "@/lib/enums";
import type { Finding } from "@/types/api";
import { useState } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";

const PAGE_SIZE = 20;

const severityOrder: Record<string, number> = {
  critical: 3,
  high: 2,
  medium: 1,
  low: 0,
};

function sortFindings(findings: Finding[], by: string, dir: "asc" | "desc") {
  return [...findings].sort((a, b) => {
    let cmp = 0;
    if (by === "severity") {
      cmp = (severityOrder[a.current_severity] ?? -1) - (severityOrder[b.current_severity] ?? -1);
    } else if (by === "title") {
      cmp = a.current_title.localeCompare(b.current_title);
    } else {
      cmp = new Date(a.last_seen_at).getTime() - new Date(b.last_seen_at).getTime();
    }
    return dir === "desc" ? -cmp : cmp;
  });
}

const kindColors: Record<string, string> = {
  sca: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
  sast: "bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400",
  iac: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
  secret: "bg-rose-100 text-rose-700 dark:bg-rose-900/30 dark:text-rose-400",
};

export function FindingsDashboard() {
  const { slug } = useParams<{ slug: string; }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();

  const severity = searchParams.get("severity") ?? "";
  const status = searchParams.get("status") ?? "";
  const kind = searchParams.get("kind") ?? "";
  const offset = Number.parseInt(searchParams.get("offset") ?? "0", 10);

  const [sortBy, setSortBy] = useState("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const { data: findings, isLoading, isFetching, isError, error, refetch } = useFindings(
    slug ?? "",
    {
      severity: severity || undefined,
      status: status || undefined,
      kind: kind || undefined,
      offset,
      limit: PAGE_SIZE,
    },
  );

  function updateFilter(key: string, value: string) {
    const next = new URLSearchParams(searchParams);
    if (value) {
      next.set(key, value);
    } else {
      next.delete(key);
    }
    next.set("offset", "0");
    setSearchParams(next);
  }

  function clearFilters() {
    const next = new URLSearchParams(searchParams);
    next.delete("severity");
    next.delete("status");
    next.delete("kind");
    next.set("offset", "0");
    setSearchParams(next);
  }

  function toggleSort(column: string) {
    if (sortBy === column) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(column);
      setSortDir(column === "severity" ? "desc" : "asc");
    }
  }

  function goToPage(newOffset: number) {
    const next = new URLSearchParams(searchParams);
    next.set("offset", String(newOffset));
    setSearchParams(next);
  }

  const sorted = findings ? sortFindings(findings, sortBy, sortDir) : [];
  const hasFilters = Boolean(severity || status || kind);
  // Rows already on screen stay put while the next request is in flight, so the
  // toolbar the user is operating never unmounts under them.
  const isRefetching = isFetching && findings !== undefined;
  const showResults = !isLoading && !isError;
  const showPager = offset > 0 || sorted.length > 0;
  // An empty page past the first one is not an empty project: the pager says so.
  const showEmptyState = showResults && offset === 0 && sorted.length === 0;

  const sortIndicator = (col: string) => {
    if (sortBy !== col) return "";
    return sortDir === "asc" ? " ▲" : " ▼";
  };

  const ariaSort = (col: string): "ascending" | "descending" | "none" => {
    if (sortBy !== col) return "none";
    return sortDir === "asc" ? "ascending" : "descending";
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <select
          aria-label="Filter by severity"
          className="border-input bg-background rounded-md border px-3 py-1 text-sm"
          value={severity}
          onChange={(e) => updateFilter("severity", e.target.value)}
        >
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select
          aria-label="Filter by status"
          className="border-input bg-background rounded-md border px-3 py-1 text-sm"
          value={status}
          onChange={(e) => updateFilter("status", e.target.value)}
        >
          <option value="">All statuses</option>
          <option value="open">Open</option>
          <option value="fixed">Fixed</option>
          <option value="reopened">Reopened</option>
        </select>
        <select
          aria-label="Filter by finding type"
          className="border-input bg-background rounded-md border px-3 py-1 text-sm"
          value={kind}
          onChange={(e) => updateFilter("kind", e.target.value)}
        >
          <option value="">All kinds</option>
          <option value="sca">SCA</option>
          <option value="sast">SAST</option>
          <option value="iac">IaC</option>
          <option value="secret">Secret</option>
        </select>
      </div>

      <div
        aria-busy={isRefetching}
        className={isRefetching ? "space-y-4 opacity-60" : "space-y-4"}
      >
        {isLoading && (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="bg-muted h-10 animate-pulse rounded" />
            ))}
          </div>
        )}

        {!isLoading && isError && (
          <div className="flex flex-col items-center gap-2 py-16">
            <p className="text-destructive text-sm">
              {error?.message ?? "Failed to load findings"}
            </p>
            <button
              className="text-primary text-sm underline hover:no-underline"
              onClick={() => refetch()}
            >
              Retry
            </button>
          </div>
        )}

        {showEmptyState && (
          <div className="flex flex-col items-center gap-2 py-16">
            {hasFilters
              ? (
                <>
                  <p className="text-muted-foreground text-sm">No findings match these filters.</p>
                  <button
                    type="button"
                    className="text-primary text-sm underline hover:no-underline"
                    onClick={clearFilters}
                  >
                    Clear filters
                  </button>
                </>
              )
              : (
                <>
                  <p className="text-muted-foreground text-sm">No findings found</p>
                  <p className="text-muted-foreground text-xs">
                    Ingest a scan report to see findings
                  </p>
                </>
              )}
          </div>
        )}

        {showResults && sorted.length > 0 && (
          <div className="space-y-2">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-border border-b text-left">
                    <th
                      aria-sort={ariaSort("severity")}
                      className="px-3 py-2 font-medium"
                    >
                      <button
                        type="button"
                        className="w-full cursor-pointer text-left"
                        onClick={() => toggleSort("severity")}
                      >
                        Severity{sortIndicator("severity")}
                      </button>
                    </th>
                    <th className="px-3 py-2 font-medium">Kind</th>
                    <th
                      aria-sort={ariaSort("title")}
                      className="px-3 py-2 font-medium"
                    >
                      <button
                        type="button"
                        className="w-full cursor-pointer text-left"
                        onClick={() => toggleSort("title")}
                      >
                        Title{sortIndicator("title")}
                      </button>
                    </th>
                    <th className="px-3 py-2 font-medium">State</th>
                    <th className="px-3 py-2 font-medium">Analysis</th>
                    <th
                      aria-sort={ariaSort("last_seen")}
                      className="px-3 py-2 font-medium"
                    >
                      <button
                        type="button"
                        className="w-full cursor-pointer text-left"
                        onClick={() => toggleSort("last_seen")}
                      >
                        Last Seen{sortIndicator("last_seen")}
                      </button>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((f) => (
                    <tr
                      key={f.id}
                      className="border-border hover:bg-muted/50 cursor-pointer border-b"
                      onClick={() => navigate(`/${slug}/findings/${f.id}`)}
                    >
                      <td className="px-3 py-2">
                        <SeverityBadge severity={f.current_severity} />
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={`inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium ${
                            kindColors[f.finding_kind] ?? "bg-muted text-muted-foreground"
                          }`}
                        >
                          {f.finding_kind}
                        </span>
                      </td>
                      <td className="px-3 py-2">{f.current_title}</td>
                      <td className="px-3 py-2 capitalize">
                        {technicalStateLabel(f.state) ?? "–"}
                      </td>
                      <td className="px-3 py-2 text-xs">
                        {analysisStateLabel(f.analysis_state)
                          ? (
                            <span className="bg-muted rounded px-1.5 py-0.5 capitalize">
                              {analysisStateLabel(f.analysis_state)}
                            </span>
                          )
                          : <span className="text-muted-foreground">–</span>}
                      </td>
                      <td className="text-muted-foreground px-3 py-2">
                        {new Date(f.last_seen_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-muted-foreground text-xs">
              Sorting applies only to the findings on this page.
            </p>
          </div>
        )}

        {showResults && showPager && (
          <div className="flex items-center justify-between">
            <button
              className="text-muted-foreground hover:text-foreground disabled:opacity-50 text-sm"
              disabled={offset === 0}
              onClick={() => goToPage(Math.max(0, offset - PAGE_SIZE))}
            >
              Previous
            </button>
            <span className="text-muted-foreground text-xs">
              {sorted.length === 0
                ? "No more results."
                : `${offset + 1}–${offset + sorted.length}`}
            </span>
            <button
              className="text-muted-foreground hover:text-foreground disabled:opacity-50 text-sm"
              disabled={sorted.length < PAGE_SIZE}
              onClick={() => goToPage(offset + PAGE_SIZE)}
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
