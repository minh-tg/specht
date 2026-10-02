interface FindingsPagerProps {
  offset: number;
  pageSize: number;
  rowCount: number;
  onPrevious: () => void;
  onNext: () => void;
}

/**
 * Page controls for the findings list. It only describes the current page and
 * delegates navigation, so the label it renders can change without touching the
 * route component.
 */
export function FindingsPager(
  { offset, pageSize, rowCount, onPrevious, onNext }: FindingsPagerProps,
) {
  return (
    <div className="flex items-center justify-between">
      <button
        className="text-muted-foreground hover:text-foreground disabled:opacity-50 text-sm"
        disabled={offset === 0}
        onClick={onPrevious}
      >
        Previous
      </button>
      <span className="text-muted-foreground text-xs">
        {rowCount === 0 ? "No more results." : `${offset + 1}–${offset + rowCount}`}
      </span>
      <button
        className="text-muted-foreground hover:text-foreground disabled:opacity-50 text-sm"
        disabled={rowCount < pageSize}
        onClick={onNext}
      >
        Next
      </button>
    </div>
  );
}
