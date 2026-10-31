import { findingsQueryOptions } from "@/api/hooks";
import type { Finding } from "@/types/api";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
import { findingsRequest } from "../findings-dashboard/findingsRequest";
import { PAGE_SIZE } from "../findings-dashboard/sort";
import { findingsViewFromSearch } from "../findings-dashboard/useFindingsQuery";

/** A neighbour in the list: where to go, and the list query to carry along as `state.from`. */
export interface QueueStep {
  readonly id: string;
  readonly title: string;
  readonly from: string;
}

export interface FindingQueue {
  /** 1-based place in the whole filtered list, or null while the list is loading. */
  readonly position: number | null;
  readonly total: number | null;
  readonly previous: QueueStep | null;
  readonly next: QueueStep | null;
  /** The page next to this one is still loading, so a missing neighbour is not the list's end. */
  readonly loadingEdge: boolean;
}

interface Page {
  readonly ids: readonly Pick<Finding, "id" | "current_title">[];
  readonly total: number;
}

function withOffset(from: string, offset: number): string {
  const params = new URLSearchParams(from);
  params.set("offset", String(offset));
  return `?${params}`;
}

function rows(
  data: { findings?: Finding[] | null; total?: number | null; } | undefined,
): Page | null {
  if (!data) return null;
  const ids = Array.isArray(data.findings) ? data.findings : [];
  return { ids, total: data.total ?? ids.length };
}

/**
 * The filtered findings list a finding was opened from, as a queue: its place in the list and the
 * finding before and after it, across page boundaries. `from` is the list's query string from
 * router state; with none there is no queue.
 *
 * A decision can drop the finding out of the filter it was opened from ("Needs triage"). The queue
 * then keeps the neighbours it last saw for this finding, so the next one is still the next one.
 */
export function useFindingQueue(
  slug: string,
  findingId: string,
  from: string | null,
): FindingQueue | null {
  const view = findingsViewFromSearch(new URLSearchParams(from ?? ""));
  const { filters, sort, offset } = view;
  const page = useQuery({
    ...findingsQueryOptions(slug, findingsRequest(filters, sort, offset)),
    enabled: from !== null && !!slug,
  });
  const current = rows(page.data);
  const index = current ? current.ids.findIndex((row) => row.id === findingId) : -1;

  const [kept, setKept] = useState<{ findingId: string; offset: number; page: Page; } | null>(
    null,
  );
  if (current && index >= 0 && (kept?.findingId !== findingId || kept.page.ids !== current.ids)) {
    setKept({ findingId, offset, page: current });
  }
  const seen = index >= 0 && current
    ? { offset, page: current }
    : kept?.findingId === findingId
    ? kept
    : null;
  const at = seen ? seen.page.ids.findIndex((row) => row.id === findingId) : -1;
  const last = seen ? seen.page.ids.length - 1 : -1;
  const seenOffset = seen?.offset ?? 0;
  const total = seen?.page.total ?? null;

  // At either end of the page, the neighbour lives on the page next to it.
  const needNext = seen !== null && at === last
    && seenOffset + seen.page.ids.length < seen.page.total;
  const needPrevious = seen !== null && at === 0 && seenOffset > 0;
  const nextPage = useQuery({
    ...findingsQueryOptions(slug, findingsRequest(filters, sort, seenOffset + PAGE_SIZE)),
    enabled: needNext,
  });
  const previousOffset = Math.max(0, seenOffset - PAGE_SIZE);
  const previousPage = useQuery({
    ...findingsQueryOptions(slug, findingsRequest(filters, sort, previousOffset)),
    enabled: needPrevious,
  });

  if (from === null) return null;
  if (!seen || at < 0) {
    return { position: null, total, previous: null, next: null, loadingEdge: false };
  }

  const step = (row: Pick<Finding, "id" | "current_title"> | undefined, rowOffset: number) =>
    row ? { id: row.id, title: row.current_title, from: withOffset(from, rowOffset) } : null;
  const nextRows = rows(nextPage.data)?.ids ?? [];
  const previousRows = rows(previousPage.data)?.ids ?? [];
  return {
    loadingEdge: (needNext && nextPage.isPending) || (needPrevious && previousPage.isPending),
    position: seenOffset + at + 1,
    total,
    next: at < last
      ? step(seen.page.ids[at + 1], seenOffset)
      : needNext
      ? step(nextRows[0], seenOffset + PAGE_SIZE)
      : null,
    previous: at > 0
      ? step(seen.page.ids[at - 1], seenOffset)
      : needPrevious
      ? step(previousRows[previousRows.length - 1], previousOffset)
      : null,
  };
}
