import { Button } from "@/components/ui/button";

/**
 * What can be done to the selected findings, floating above the list while any are selected. It is
 * a labelled region, so a screen reader finds it, and it holds only the actions the person may take.
 */
export function BulkBar({ count, onTriage, onRequestWaiver, onClear }: {
  readonly count: number;
  /** Absent when the person may not triage. */
  readonly onTriage?: () => void;
  /** Absent when the person may not request waivers. */
  readonly onRequestWaiver?: () => void;
  readonly onClear: () => void;
}) {
  if (count === 0) return null;
  return (
    <div
      role="region"
      aria-label="Bulk actions"
      className="bg-foreground text-background fixed bottom-5 left-1/2 z-40 flex -translate-x-1/2 items-center gap-2.5 rounded-lg py-2 pr-2 pl-4 shadow-lg motion-safe:animate-in motion-safe:fade-in-0 motion-safe:slide-in-from-bottom-4"
    >
      <span aria-live="polite" className="text-sm whitespace-nowrap">
        <b className="tabular-nums">{count}</b> selected
      </span>
      {onTriage && (
        <Button
          size="sm"
          variant="ghost"
          className="bg-background/15 hover:bg-background/25 hover:text-background"
          onClick={onTriage}
        >
          Triage…
        </Button>
      )}
      {onRequestWaiver && (
        <Button
          size="sm"
          className="bg-background text-foreground hover:bg-background/90"
          onClick={onRequestWaiver}
        >
          Request waiver
        </Button>
      )}
      <Button
        size="sm"
        variant="ghost"
        className="hover:bg-background/15 hover:text-background"
        onClick={onClear}
      >
        Clear
      </Button>
    </div>
  );
}
