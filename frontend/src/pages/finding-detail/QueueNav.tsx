import { DisabledReason } from "@/components/DisabledReason";
import { Button } from "@/components/ui/button";
import { matchesPageKey } from "@/lib/shortcuts";
import { useSingleKeyEnabled } from "@/lib/singleKeyShortcuts";
import { useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import type { FindingQueue, QueueStep } from "./useFindingQueue";

const FIRST = "This is the first finding in the list.";
const LAST = "This is the last finding in the list.";

/**
 * Previous and next in the filtered list the finding was opened from, with J and K. The move is
 * spoken in the page's live region, since focus goes back to the top of the new page.
 */
export function QueueNav({ slug, queue, announce }: {
  readonly slug: string;
  readonly queue: FindingQueue;
  readonly announce: (message: string) => void;
}) {
  const navigate = useNavigate();
  const singleKeys = useSingleKeyEnabled();
  const { position, total, previous, next, loadingEdge } = queue;
  const loading = position === null || loadingEdge;

  // Moves one step, or says the list ends here. Nothing happens while the place is unknown.
  const move = useCallback((step: QueueStep | null, by: 1 | -1) => {
    if (position === null || loadingEdge) return;
    if (!step) {
      announce(by === 1 ? LAST : FIRST);
      return;
    }
    navigate(`/${slug}/findings/${step.id}`, { state: { from: step.from } });
    announce(`Finding ${position + by}${total === null ? "" : ` of ${total}`}: ${step.title}`);
  }, [announce, loadingEdge, navigate, position, slug, total]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (!matchesPageKey(event)) return;
      const key = event.key.toLowerCase();
      if (key === "j") move(next, 1);
      else if (key === "k") move(previous, -1);
      else return;
      event.preventDefault();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [move, next, previous]);

  const hint = (key: string) =>
    singleKeys && (
      <kbd aria-hidden="true" className="bg-muted rounded px-1 font-mono text-code">{key}</kbd>
    );

  return (
    <nav
      aria-label="Findings in this list"
      className="flex flex-wrap items-center gap-2 sm:mr-auto"
    >
      <span className="text-muted-foreground text-meta tabular-nums">
        {position === null
          ? "Finding its place in the list..."
          : `Finding ${position}${total === null ? "" : ` of ${total}`} in this list`}
      </span>
      <DisabledReason reason={loading || previous ? undefined : FIRST}>
        <Button
          type="button"
          variant="outline"
          size="xs"
          disabled={!previous}
          onClick={() => move(previous, -1)}
        >
          Previous {hint("K")}
        </Button>
      </DisabledReason>
      <DisabledReason reason={loading || next ? undefined : LAST}>
        <Button
          type="button"
          variant="outline"
          size="xs"
          disabled={!next}
          onClick={() => move(next, 1)}
        >
          Next {hint("J")}
        </Button>
      </DisabledReason>
    </nav>
  );
}
