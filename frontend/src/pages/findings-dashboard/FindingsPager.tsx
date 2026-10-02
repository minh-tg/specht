interface FindingsPagerProps {
  offset: number;
  pageSize: number;
  rowCount: number;
  total: number | null;
  onPrevious: () => void;
  onNext: () => void;
  onFirst: () => void;
}

/**
 * Page controls for the findings list. It only describes the current page and
 * delegates navigation, so the label it renders can change without touching the
 * route component.
 */
export function FindingsPager(
  { offset, pageSize, rowCount, total, onPrevious, onNext, onFirst }: FindingsPagerProps,
) {
  // A known total tells us where the list ends, so a full last page does not
  // offer an empty one after it. Without one, a page is the last only when it
  // is not full.
  const atEnd = total !== null ? offset + rowCount >= total : rowCount < pageSize;
  const range = `${offset + 1}–${offset + rowCount}`;
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="flex w-full items-center justify-between">
        <button
          className="text-muted-foreground hover:text-foreground disabled:opacity-50 text-sm"
          disabled={offset === 0}
          onClick={onPrevious}
          aria-label="Previous page"
        >
          Previous
        </button>
        <span className="text-muted-foreground text-xs" aria-live="polite">
          {rowCount === 0 ? "No more results." : total !== null ? `${range} of ${total}` : range}
        </span>
        <button
          className="text-muted-foreground hover:text-foreground disabled:opacity-50 text-sm"
          disabled={atEnd}
          onClick={onNext}
          aria-label="Next page"
        >
          Next
        </button>
      </div>
      {offset > 0 && rowCount === 0 && (
        <button
          className="text-action text-sm underline hover:no-underline"
          onClick={onFirst}
        >
          Back to the first page
        </button>
      )}
    </div>
  );
}
