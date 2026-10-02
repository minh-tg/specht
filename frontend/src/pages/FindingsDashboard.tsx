import { useFindings, useGateStatus } from "@/api/hooks";
import { SeverityBadge } from "@/components/ui/severity-badge";
import {
  analysisStateLabel,
  FINDING_KINDS,
  findingKindLabel,
  SEVERITIES,
  severityLabel,
  TECHNICAL_STATES,
  technicalStateLabel,
} from "@/lib/enums";
import { formatDate } from "@/lib/format";
import { blocksGate, blocksGateLabel } from "@/lib/gate";
import { type MouseEvent } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { compactMeta, PAGE_SIZE, SORT_OPTIONS, sortFindings } from "./findings-dashboard/sort";
import { useFindingsQuery } from "./findings-dashboard/useFindingsQuery";

/** Clicks on these keep their own behaviour instead of opening the finding. */
const INTERACTIVE_SELECTOR = "a, button, input, select, textarea, label";

export function FindingsDashboard() {
  const { slug } = useParams<{ slug: string; }>();
  const navigate = useNavigate();
  const location = useLocation();

  const { filters, sort, offset, setFilter, setSort, setPage, clearFilters } = useFindingsQuery();

  // The detail page reads `state.from` to return to this exact filtered page.
  const detailState = { from: location.search };

  function openFinding(event: MouseEvent<HTMLTableRowElement>, findingId: string) {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
      return;
    }
    if ((event.target as Element).closest(INTERACTIVE_SELECTOR)) return;
    if (window.getSelection()?.toString()) return;
    navigate(`/${slug}/findings/${findingId}`, { state: detailState });
  }

  const { data: findings, isLoading, isFetching, isError, error, refetch } = useFindings(
    slug ?? "",
    {
      severity: filters.severity || undefined,
      status: filters.status || undefined,
      kind: filters.kind || undefined,
      offset,
      limit: PAGE_SIZE,
    },
  );
  const { data: gate } = useGateStatus(slug ?? "");

  function toggleSort(column: string) {
    if (sort.by === column) {
      setSort(column, sort.dir === "asc" ? "desc" : "asc");
    } else {
      setSort(column, column === "severity" ? "desc" : "asc");
    }
  }

  const sorted = findings ? sortFindings(findings, sort.by, sort.dir) : [];
  const hasFilters = Boolean(filters.severity || filters.status || filters.kind);
  // Rows already on screen stay put while the next request is in flight, so the
  // toolbar the user is operating never unmounts under them.
  const isRefetching = isFetching && findings !== undefined;
  const showResults = !isLoading && !isError;
  const showPager = offset > 0 || sorted.length > 0;
  // An empty page past the first one is not an empty project: the pager says so.
  const showEmptyState = showResults && offset === 0 && sorted.length === 0;

  const sortIndicator = (col: string) => {
    if (sort.by !== col) return "";
    return sort.dir === "asc" ? " ▲" : " ▼";
  };

  const ariaSort = (col: string): "ascending" | "descending" | "none" => {
    if (sort.by !== col) return "none";
    return sort.dir === "asc" ? "ascending" : "descending";
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-2">
        <select
          aria-label="Filter by severity"
          className="border-input bg-background rounded-md border px-3 py-1 text-sm"
          value={filters.severity}
          onChange={(e) => setFilter("severity", e.target.value)}
        >
          <option value="">All severities</option>
          {SEVERITIES.map((value) => (
            <option key={value} value={value}>{severityLabel(value)}</option>
          ))}
        </select>
        <select
          aria-label="Filter by status"
          className="border-input bg-background rounded-md border px-3 py-1 text-sm"
          value={filters.status}
          onChange={(e) => setFilter("status", e.target.value)}
        >
          <option value="">All statuses</option>
          {TECHNICAL_STATES.map((value) => (
            <option key={value} value={value}>{technicalStateLabel(value)}</option>
          ))}
        </select>
        <select
          aria-label="Filter by finding type"
          className="border-input bg-background rounded-md border px-3 py-1 text-sm"
          value={filters.kind}
          onChange={(e) => setFilter("kind", e.target.value)}
        >
          <option value="">All kinds</option>
          {FINDING_KINDS.map((value) => (
            <option key={value} value={value}>{findingKindLabel(value)}</option>
          ))}
        </select>
        <select
          aria-label="Sort findings"
          className="border-input bg-background rounded-md border px-3 py-1 text-sm md:hidden"
          value={`${sort.by}:${sort.dir}`}
          onChange={(e) => {
            const [by, dir] = e.target.value.split(":");
            setSort(by, dir === "asc" ? "asc" : "desc");
          }}
        >
          {SORT_OPTIONS.map(({ value, label }) => <option key={value} value={value}>{label}
          </option>)}
        </select>
      </div>

      <div
        aria-busy={isRefetching}
        className={isRefetching ? "space-y-4 opacity-60" : "space-y-4"}
      >
        {isLoading && (
          <div
            role="status"
            aria-busy="true"
            aria-label="Loading findings"
            className="space-y-2"
          >
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
                    Findings appear here once a report is uploaded or sent from CI.
                  </p>
                </>
              )}
          </div>
        )}

        {showResults && sorted.length > 0 && (
          <div className="space-y-2">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <caption className="sr-only">Findings</caption>
                <thead>
                  <tr className="border-border border-b text-left">
                    <th
                      scope="col"
                      aria-sort={ariaSort("severity")}
                      className="px-3 py-2 font-medium"
                    >
                      <button
                        type="button"
                        className="w-full cursor-pointer text-left whitespace-nowrap"
                        onClick={() => toggleSort("severity")}
                      >
                        Severity{sortIndicator("severity")}
                      </button>
                    </th>
                    <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">Kind</th>
                    <th
                      scope="col"
                      aria-sort={ariaSort("title")}
                      className="px-3 py-2 font-medium"
                    >
                      <button
                        type="button"
                        className="w-full cursor-pointer text-left whitespace-nowrap"
                        onClick={() => toggleSort("title")}
                      >
                        Title{sortIndicator("title")}
                      </button>
                    </th>
                    <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">
                      Status
                    </th>
                    <th scope="col" className="hidden px-3 py-2 font-medium md:table-cell">
                      Triage
                    </th>
                    <th scope="col" className="px-3 py-2 font-medium">Blocks gate</th>
                    <th
                      scope="col"
                      aria-sort={ariaSort("last_seen")}
                      className="hidden px-3 py-2 font-medium md:table-cell"
                    >
                      <button
                        type="button"
                        className="w-full cursor-pointer text-left whitespace-nowrap"
                        onClick={() => toggleSort("last_seen")}
                      >
                        Last Seen{sortIndicator("last_seen")}
                      </button>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((f) => {
                    const gateResult = blocksGate(f, gate);
                    return (
                      <tr
                        key={f.id}
                        className="border-border hover:bg-muted/50 focus-within:bg-muted/50 cursor-pointer border-b"
                        onClick={(event) => openFinding(event, f.id)}
                      >
                        <td className="px-3 py-2">
                          <SeverityBadge severity={f.current_severity} />
                        </td>
                        <td className="hidden px-3 py-2 md:table-cell">
                          <span className="bg-muted text-muted-foreground inline-flex items-center rounded-md px-1.5 py-0.5 text-xs font-medium">
                            {findingKindLabel(f.finding_kind) ?? "–"}
                          </span>
                        </td>
                        <td className="px-3 py-2">
                          <Link
                            to={`/${slug}/findings/${f.id}`}
                            state={detailState}
                            className="underline-offset-2 hover:underline"
                          >
                            {f.current_title}
                          </Link>
                          <p className="text-muted-foreground mt-0.5 text-xs md:hidden">
                            {compactMeta(f)}
                          </p>
                        </td>
                        <td className="hidden px-3 py-2 capitalize md:table-cell">
                          {technicalStateLabel(f.state) ?? "–"}
                        </td>
                        <td className="hidden px-3 py-2 text-xs md:table-cell">
                          {analysisStateLabel(f.analysis_state)
                            ? (
                              <span className="bg-muted rounded px-1.5 py-0.5 whitespace-nowrap">
                                {analysisStateLabel(f.analysis_state)}
                              </span>
                            )
                            : <span className="text-muted-foreground">–</span>}
                        </td>
                        <td className="px-3 py-2">
                          {gateResult?.blocks
                            ? (
                              <span className="bg-sev-critical-bg text-sev-critical-fg rounded-sm px-1.5 py-0.5 text-xs font-medium">
                                Yes
                              </span>
                            )
                            : (
                              <span className="text-muted-foreground text-xs">
                                {blocksGateLabel(gateResult)}
                              </span>
                            )}
                        </td>
                        <td className="text-muted-foreground hidden px-3 py-2 whitespace-nowrap md:table-cell">
                          {formatDate(f.last_seen_at)}
                        </td>
                      </tr>
                    );
                  })}
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
              onClick={() => setPage(Math.max(0, offset - PAGE_SIZE))}
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
              onClick={() => setPage(offset + PAGE_SIZE)}
            >
              Next
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
