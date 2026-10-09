import { useFindings, useGateStatus } from "@/api/hooks";
import { Skeleton } from "@/components/ui/skeleton";
import { useParams } from "react-router-dom";
import { ClearFiltersButton, FindingsFilters } from "./findings-dashboard/FindingsFilters";
import { FindingsPager } from "./findings-dashboard/FindingsPager";
import { FindingsTable } from "./findings-dashboard/FindingsTable";
import { PAGE_SIZE, sortFindings } from "./findings-dashboard/sort";
import { useFindingsQuery } from "./findings-dashboard/useFindingsQuery";

export function FindingsDashboard() {
  const { slug } = useParams<{ slug: string; }>();

  const { filters, sort, offset, setFilter, setSort, setPage, clearFilters } = useFindingsQuery();

  const { data, isLoading, isFetching, isError, error, refetch } = useFindings(
    slug ?? "",
    {
      severity: filters.severity || undefined,
      status: filters.status || undefined,
      kind: filters.kind || undefined,
      offset,
      limit: PAGE_SIZE,
    },
  );
  const findings = data?.findings;
  const total = data?.total ?? null;
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

  return (
    <div className="space-y-4">
      <FindingsFilters
        filters={filters}
        sort={sort}
        onFilterChange={setFilter}
        onSortChange={setSort}
      />

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
            {Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-10 rounded" />)}
          </div>
        )}

        {!isLoading && isError && (
          <div className="flex flex-col items-center gap-2 py-16">
            <p className="text-destructive text-sm">
              {error?.message ?? "Failed to load findings"}
            </p>
            <button
              className="text-action text-sm underline hover:no-underline"
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
                  <ClearFiltersButton onClear={clearFilters} />
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
          <FindingsTable
            slug={slug}
            findings={sorted}
            gate={gate}
            sort={sort}
            onToggleSort={toggleSort}
          />
        )}

        {showResults && showPager && (
          <FindingsPager
            offset={offset}
            pageSize={PAGE_SIZE}
            rowCount={sorted.length}
            total={total}
            onPrevious={() => setPage(Math.max(0, offset - PAGE_SIZE))}
            onNext={() => setPage(offset + PAGE_SIZE)}
            onFirst={() => setPage(0)}
          />
        )}
      </div>
    </div>
  );
}
