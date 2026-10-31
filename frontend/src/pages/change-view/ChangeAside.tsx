import { HoleTracker } from "@/components/HoleTracker";
import { Button } from "@/components/ui/button";
import { useCopyToClipboard } from "@/lib/useCopyToClipboard";
import { type WatchState, WatchStrip } from "@/pages/change-view/WatchStrip";

export interface AsideItem {
  readonly id: string;
  readonly title: string;
  readonly handled: boolean;
}

export interface ChangeAsideProps {
  readonly items: readonly AsideItem[];
  readonly onHandledChange: (id: string, handled: boolean) => void;
  /** Every fix the scanners know, one per line, for pasting into a terminal or a ticket. */
  readonly fixesText: string;
  /** The page is watching for a newer scan. Absent when it is not, for example on an old change. */
  readonly watch?: WatchState;
  /** The branch being watched, named in the strip. */
  readonly branch?: string | null;
}

/**
 * The margin note beside the ledger: the reader's own progress (holes and a checklist), one primary
 * action, how to send fresh evidence, and whether the page is watching for it. Ticking an item
 * tracks the reader's progress and nothing else; the verdict changes only when a scan lands.
 */
export function ChangeAside(
  { items, onHandledChange, fixesText, watch, branch }: ChangeAsideProps,
) {
  const { status, copy } = useCopyToClipboard();
  const done = items.filter((item) => item.handled).length;
  return (
    <aside
      aria-label="Your progress"
      className="border-border grid content-start gap-3.5 lg:border-l lg:pl-6"
    >
      <h2 className="text-section leading-tight font-semibold">Smallest safe actions</h2>
      <p className="text-muted-foreground text-meta">
        {done} of {items.length} handled
      </p>
      <HoleTracker total={items.length} filled={done} />
      <ul className="m-0 grid list-none gap-1 p-0">
        {items.map((item) => (
          <li key={item.id}>
            <label className="-mx-2 flex min-h-[40px] cursor-pointer items-center gap-3 rounded-lg px-2 py-1.5 text-body hover:bg-muted/60">
              <input
                type="checkbox"
                checked={item.handled}
                onChange={(event) => onHandledChange(item.id, event.target.checked)}
                className="border-input accent-foreground size-5 flex-none rounded-sm"
              />
              <span className="min-w-0 [overflow-wrap:anywhere]">{item.title}</span>
            </label>
          </li>
        ))}
      </ul>
      {fixesText && (
        <Button
          type="button"
          onClick={() => void copy(fixesText)}
          className="h-9 w-full"
        >
          {status === "copied" ? "Copied" : status === "failed" ? "Copy failed" : "Copy all fixes"}
        </Button>
      )}
      <div className="border-border border-t pt-3.5 text-meta">
        <p className="font-semibold">After a fix</p>
        <p className="text-muted-foreground mt-1">
          Run your CI scan again, or upload a report through the API with matching scan metadata. If
          a watcher is configured, wait for its next scan. This checklist only tracks your progress.
        </p>
        {watch && (
          <WatchStrip
            className="mt-3"
            label={`Watching for the next scan${branch ? ` of ${branch}` : ""}`}
            watch={watch}
            announce={watch.online && !watch.stalled}
          />
        )}
      </div>
    </aside>
  );
}
