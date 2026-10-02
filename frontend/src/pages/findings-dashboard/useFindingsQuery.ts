import { useState } from "react";
import { useSearchParams } from "react-router-dom";

export interface FindingsFilters {
  severity: string;
  status: string;
  kind: string;
}

export interface FindingsSort {
  by: string;
  dir: "asc" | "desc";
}

/**
 * The dashboard's view state. The filters and the page offset live in the URL
 * so a filtered page is linkable and restored by the back button; the sort is
 * local to the view and resets when the page is reloaded.
 */
export function useFindingsQuery() {
  const [searchParams, setSearchParams] = useSearchParams();

  const [sortBy, setSortBy] = useState("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const filters: FindingsFilters = {
    severity: searchParams.get("severity") ?? "",
    status: searchParams.get("status") ?? "",
    kind: searchParams.get("kind") ?? "",
  };
  const offset = Number.parseInt(searchParams.get("offset") ?? "0", 10);

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
    next.delete("severity");
    next.delete("status");
    next.delete("kind");
    next.set("offset", "0");
    setSearchParams(next);
  }

  function setSort(by: string, dir: "asc" | "desc") {
    setSortBy(by);
    setSortDir(dir);
  }

  function setPage(newOffset: number) {
    const next = new URLSearchParams(searchParams);
    next.set("offset", String(newOffset));
    setSearchParams(next);
  }

  return {
    filters,
    sort: { by: sortBy, dir: sortDir },
    offset,
    setFilter,
    setSort,
    setPage,
    clearFilters,
  };
}
