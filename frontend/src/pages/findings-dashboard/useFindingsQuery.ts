import type { FindingSort } from "@/api/hooks";
import { useSearchParams } from "react-router-dom";
import { DEFAULT_FINDINGS_SORT } from "./findingsRequest";

export interface FindingsFilters {
  severity: string;
  status: string;
  kind: string;
  /** Comma list of analysis states, or empty for all. */
  analysisState: string;
  /** Free text matched against the title and the fingerprint. */
  q: string;
}

export interface FindingsSort {
  by: FindingSort;
  dir: "asc" | "desc";
}

const SORTS: readonly FindingSort[] = ["severity", "first_seen", "last_seen", "title"];

/** The direction a column starts in: the one that answers "what should I look at first". */
export function defaultSortDir(by: FindingSort): "asc" | "desc" {
  return by === "severity" || by === "last_seen" ? "desc" : "asc";
}

const DEFAULT_SORT = DEFAULT_FINDINGS_SORT;

const FILTER_KEYS = ["severity", "status", "kind", "analysis_state", "q"] as const;

/**
 * Reads the list's filters, sort and page from its query string. The finding page reads the same
 * string from router state to walk the list the person came from.
 */
export function findingsViewFromSearch(
  searchParams: URLSearchParams,
): { filters: FindingsFilters; sort: FindingsSort; offset: number; } {
  const filters: FindingsFilters = {
    severity: searchParams.get("severity") ?? "",
    status: searchParams.get("status") ?? "",
    kind: searchParams.get("kind") ?? "",
    analysisState: searchParams.get("analysis_state") ?? "",
    q: searchParams.get("q") ?? "",
  };

  const rawSort = searchParams.get("sort");
  const by = SORTS.find((s) => s === rawSort) ?? DEFAULT_SORT.by;
  const rawDir = searchParams.get("dir");
  const sort: FindingsSort = {
    by,
    dir: rawDir === "asc" || rawDir === "desc" ? rawDir : defaultSortDir(by),
  };

  const parsedOffset = Number.parseInt(searchParams.get("offset") ?? "0", 10);
  const offset = Number.isFinite(parsedOffset) && parsedOffset > 0 ? parsedOffset : 0;
  return { filters, sort, offset };
}

/**
 * The list's view state. Everything lives in the URL, so a filtered, sorted, searched page is
 * linkable and the back button restores it. The sort and the search are applied by the server
 * across every page, never to the rows on screen alone.
 */
export function useFindingsQuery() {
  const [searchParams, setSearchParams] = useSearchParams();
  const { filters, sort, offset } = findingsViewFromSearch(searchParams);

  function setFilter(key: string, value: string) {
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
    for (const key of FILTER_KEYS) next.delete(key);
    next.set("offset", "0");
    setSearchParams(next);
  }

  function setSort(nextBy: FindingSort, dir: "asc" | "desc") {
    const next = new URLSearchParams(searchParams);
    if (nextBy === DEFAULT_SORT.by && dir === DEFAULT_SORT.dir) {
      next.delete("sort");
      next.delete("dir");
    } else {
      next.set("sort", nextBy);
      next.set("dir", dir);
    }
    next.set("offset", "0");
    setSearchParams(next);
  }

  function setPage(newOffset: number) {
    const next = new URLSearchParams(searchParams);
    next.set("offset", String(newOffset));
    setSearchParams(next);
  }

  return { filters, sort, offset, setFilter, setSort, setPage, clearFilters };
}
