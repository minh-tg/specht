import { Drum } from "@/components/Drum";
import { HoleTracker } from "@/components/HoleTracker";
import { Button } from "@/components/ui/button";
import { useCopyToClipboard } from "@/lib/useCopyToClipboard";

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
  /** The page is waiting for a newer scan to land. */
  readonly waiting: boolean;
  readonly stalled: boolean;
  readonly onStartWaiting: () => void;
  readonly onCheckAgain: () => void;
}

/**
 * The margin note beside the ledger: the reader's own progress (holes and a checklist), one primary
 * action, and what happens after a push. Ticking an item tracks the reader's progress and nothing
 * else; the verdict changes only when a scan lands.
 */
export function ChangeAside(
  { items, onHandledChange, fixesText, waiting, stalled, onStartWaiting, onCheckAgain }:
    ChangeAsideProps,
) {
  const { status, copy } = useCopyToClipboard();
  const done = items.filter((item) => item.handled).length;
  return (
    <aside
      aria-label="Your progress"
      className="border-border grid content-start gap-3.5 lg:border-l lg:pl-6"
    >
      <h2 className="text-lg leading-tight font-semibold">Smallest safe actions</h2>
      <p className="text-muted-foreground text-[13px]">
        {done} of {items.length} handled
      </p>
      <HoleTracker total={items.length} filled={done} />
      <ul className="m-0 grid list-none gap-1 p-0">
        {items.map((item) => (
          <li key={item.id}>
            <label className="-mx-2 flex min-h-[40px] cursor-pointer items-center gap-3 rounded-lg px-2 py-1.5 text-sm hover:bg-muted/60">
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
      <div className="border-border border-t pt-3.5 text-[13px]">
        <p className="font-semibold">After you push</p>
        <p className="text-muted-foreground mt-1">
          Specht re-scans on its own and this page updates. Only a scan changes the verdict; ticking
          an item only tracks your progress.
        </p>
        {waiting
          ? (
            <p role="status" className="mt-3 flex items-center gap-2">
              <Drum />
              {stalled
                ? "Nothing yet after ten minutes. Check the CI job."
                : "Waiting for the next scan"}
            </p>
          )
          : (
            <button
              type="button"
              onClick={onStartWaiting}
              className="text-foreground mt-3 underline underline-offset-3 hover:decoration-2"
            >
              I pushed a fix
            </button>
          )}
        {waiting && stalled && (
          <button
            type="button"
            onClick={onCheckAgain}
            className="text-foreground mt-2 underline underline-offset-3 hover:decoration-2"
          >
            Check again
          </button>
        )}
      </div>
    </aside>
  );
}
