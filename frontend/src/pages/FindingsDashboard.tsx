import {
  type FindingSort,
  POLL_MS,
  useFindings,
  useGateStatus,
  useProject,
  useProjectStats,
} from "@/api/hooks";
import { INLINE_LINK } from "@/components/inlineLink";
import { Skeleton } from "@/components/ui/skeleton";
import { UpdatedHint } from "@/components/UpdatedHint";
import { NEEDS_TRIAGE_QUERY, OPEN_CRITICAL_HIGH_QUERY } from "@/lib/findingViews";
import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { WaiverRequestDialog } from "./change-view/WaiverRequestDialog";
import { BulkBar } from "./findings-dashboard/BulkBar";
import { BulkTriageDialog } from "./findings-dashboard/BulkTriageDialog";
import { ClearFiltersButton, FindingsFilters } from "./findings-dashboard/FindingsFilters";
import { FindingsPager } from "./findings-dashboard/FindingsPager";
import { findingsRequest } from "./findings-dashboard/findingsRequest";
import { FindingsTable } from "./findings-dashboard/FindingsTable";
import { PAGE_SIZE } from "./findings-dashboard/sort";
import { defaultSortDir, useFindingsQuery } from "./findings-dashboard/useFindingsQuery";

const EMPTY_SELECTION: ReadonlySet<string> = new Set();

export function FindingsDashboard() {
  const { slug } = useParams<{ slug: string; }>();

  const { filters, sort, offset, setFilter, setSort, setPage, clearFilters } = useFindingsQuery();

  // The list asks again every 30 s while the tab is visible, so other people's changes show up.
  const { data, dataUpdatedAt, isLoading, isFetching, isError, error, refetch } = useFindings(
    slug ?? "",
    findingsRequest(filters, sort, offset),
    { refetchInterval: POLL_MS },
  );
  const findings = data?.findings;
  const total = data?.total ?? null;
  const { data: gate } = useGateStatus(slug ?? "");
  const { data: stats } = useProjectStats(slug ?? "");
  const { data: project } = useProject(slug ?? "");
  // The server says what this person may do; until it has, nothing is offered.
  const canTriage = project?.permissions?.triage === true;
  const canRequestWaiver = project?.permissions?.request_waiver === true;

  // What is selected belongs to the view it was selected in. A different filter, sort or page is a
  // different list, so the selection is not carried over: it reads as empty there.
  const viewKey = JSON.stringify([slug, filters, sort, offset]);
  const [picked, setPicked] = useState<{ view: string; ids: ReadonlySet<string>; }>({
    view: viewKey,
    ids: new Set(),
  });
  const selectedIds = picked.view === viewKey ? picked.ids : EMPTY_SELECTION;
  const [triageOpen, setTriageOpen] = useState(false);
  const [waiverOpen, setWaiverOpen] = useState(false);

  function toggleSelected(findingId: string) {
    const next = new Set(selectedIds);
    if (next.has(findingId)) next.delete(findingId);
    else next.add(findingId);
    setPicked({ view: viewKey, ids: next });
  }

  function toggleAll(selectAll: boolean) {
    setPicked({
      view: viewKey,
      ids: new Set(selectAll ? (findings ?? []).map((f) => f.id) : []),
    });
  }

  const clearSelection = () => setPicked({ view: viewKey, ids: new Set() });

  function toggleSort(column: string) {
    const by = column as FindingSort;
    if (sort.by === by) {
      setSort(by, sort.dir === "asc" ? "desc" : "asc");
    } else {
      setSort(by, defaultSortDir(by));
    }
  }

  // The server orders the whole result, so the page shows the rows as they come.
  const sorted = findings ?? [];
  const hasFilters = Boolean(
    filters.severity || filters.status || filters.kind || filters.analysisState || filters.q,
  );
  // Rows already on screen stay put while the next request is in flight, so the
  // toolbar the user is operating never unmounts under them.
  const isRefetching = isFetching && findings !== undefined;
  const showResults = !isLoading && !isError;
  const showPager = offset > 0 || sorted.length > 0;
  // An empty page past the first one is not an empty project: the pager says so.
  const showEmptyState = showResults && offset === 0 && sorted.length === 0;

  return (
    <div className="space-y-4">
      <nav
        aria-label="Finding quick views"
        className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm"
      >
        <span className="text-muted-foreground">Quick views</span>
        <Link
          to={`/${slug}/findings?${NEEDS_TRIAGE_QUERY}`}
          className={`${INLINE_LINK} inline-flex min-h-8 items-center`}
        >
          Needs triage
        </Link>
        <Link
          to={`/${slug}/findings?${OPEN_CRITICAL_HIGH_QUERY}`}
          className={`${INLINE_LINK} inline-flex min-h-8 items-center`}
        >
          Open critical/high
        </Link>
      </nav>
      <FindingsFilters
        filters={filters}
        sort={sort}
        onFilterChange={setFilter}
        onSortChange={setSort}
        severityCounts={stats?.by_severity}
      />

      <UpdatedHint
        className="text-muted-foreground flex items-center justify-end gap-2 text-xs"
        updatedAt={dataUpdatedAt}
        watch={[data]}
        isFetching={isFetching}
        onRefresh={() => void refetch()}
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
              className={`${INLINE_LINK} text-sm`}
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
            selection={canTriage || canRequestWaiver
              ? { keys: selectedIds, onToggle: toggleSelected, onToggleAll: toggleAll }
              : undefined}
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
      <BulkBar
        count={selectedIds.size}
        onTriage={canTriage ? () => setTriageOpen(true) : undefined}
        onRequestWaiver={canRequestWaiver ? () => setWaiverOpen(true) : undefined}
        onClear={clearSelection}
      />
      <BulkTriageDialog
        findingIds={[...selectedIds]}
        open={triageOpen}
        onOpenChange={setTriageOpen}
        onApplied={clearSelection}
      />
      <WaiverRequestDialog
        slug={slug ?? ""}
        findingIds={[...selectedIds]}
        subject={selectedIds.size === 1
          ? "the finding you selected"
          : `${selectedIds.size} findings`}
        open={waiverOpen}
        onOpenChange={setWaiverOpen}
        onRequested={clearSelection}
      />
    </div>
  );
}
