import type { FindingsQuery } from "@/api/hooks";
import { PAGE_SIZE } from "./sort";
import type { FindingsFilters, FindingsSort } from "./useFindingsQuery";

/** The sort a project's findings open in: most severe first. */
export const DEFAULT_FINDINGS_SORT: FindingsSort = { by: "severity", dir: "desc" };

const NO_FILTERS: FindingsFilters = {
  severity: "",
  status: "",
  kind: "",
  analysisState: "",
  q: "",
};

/**
 * The request for one page of the findings list. The dashboard builds its query here from the
 * URL's view state, and the hover prefetch builds the default view the same way, so the two
 * always produce the same cache key.
 */
export function findingsRequest(
  filters: FindingsFilters = NO_FILTERS,
  sort: FindingsSort = DEFAULT_FINDINGS_SORT,
  offset = 0,
): FindingsQuery {
  return {
    severity: filters.severity || undefined,
    status: filters.status || undefined,
    kind: filters.kind || undefined,
    analysisState: filters.analysisState || undefined,
    q: filters.q || undefined,
    sort: sort.by,
    dir: sort.dir,
    offset,
    limit: PAGE_SIZE,
  };
}
