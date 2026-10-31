import { DisabledReason } from "@/components/DisabledReason";
import { Button } from "@/components/ui/button";
import { pluralize } from "@/lib/format";
import { WAIVER_TARGETS_MAX, type WaiverAction } from "@/lib/waiverRequest";
import { waiverCandidates, type WaiverView } from "@/pages/change-view/waiverState";

export interface GroupWaiverControlProps {
  /** The blockers the control speaks for. */
  readonly ids: readonly string[];
  readonly views: ReadonlyMap<string, WaiverView>;
  /** What requesting does for this viewer, and why when it cannot be used. */
  readonly request: WaiverAction;
  /** The waivers list has not loaded, so which blockers are covered is not known yet. */
  readonly waitingForWaivers: boolean;
  /** Names the set in the button's accessible name, for example "Upgrade lodash to 4.17.21". */
  readonly context: string;
  /** Opens the request dialog with the findings to name, at most the server's limit. */
  readonly onRequest: (ids: readonly string[]) => void;
  /** The id of the note, so focus can return to it after a request is sent. */
  readonly noteId: string;
}

/** The sentence that says which blockers a request leaves out, or null when none are left out. */
function leftOut(waiting: number, inForce: number): string | null {
  if (waiting + inForce === 0) return null;
  const parts = [
    inForce > 0 ? `${inForce} already waived` : null,
    waiting > 0 ? `${waiting} with a request waiting for a manager` : null,
  ].filter((part) => part !== null);
  return `${pluralize(waiting + inForce, "blocker")} left out: ${parts.join(", ")}.`;
}

/**
 * One request for many blockers. It names every blocker in the set that has no request waiting and
 * no waiver in force, up to the most one request may name; the rest are listed in a note, with
 * what to do when the set is over the limit. The control is never dropped: when the viewer cannot
 * ask, it is disabled and says why.
 */
export function GroupWaiverControl(
  { ids, views, request, waitingForWaivers, context, onRequest, noteId }: GroupWaiverControlProps,
) {
  const { eligible, waiting, inForce } = waiverCandidates(ids, views);
  const sendable = eligible.slice(0, WAIVER_TARGETS_MAX);
  const capped = eligible.length > sendable.length;
  const left = leftOut(waiting, inForce);

  const label = capped
    ? `Request one waiver for the first ${sendable.length}`
    : left || sendable.length === 1
    ? `Request one waiver for ${pluralize(sendable.length, "finding")}`
    : `Request one waiver for all ${sendable.length}`;

  const reason = waitingForWaivers
    ? "Checking which blockers already have a waiver."
    : request.kind === "disabled"
    ? request.reason
    : undefined;

  const notes = [
    left,
    eligible.length === 0 ? "Nothing is left to ask for." : null,
    capped
      ? `One request can name at most ${WAIVER_TARGETS_MAX} findings. ${eligible.length} can be requested, so this sends the first ${sendable.length}. Ask again for the rest once it is sent.`
      : null,
  ].filter((note) => note !== null);

  return (
    <>
      {sendable.length > 0 && (
        <DisabledReason reason={reason}>
          <Button
            type="button"
            variant="outline"
            aria-label={`${label}: ${context}`}
            disabled={!!reason}
            onClick={() => onRequest(sendable)}
          >
            {label}
          </Button>
        </DisabledReason>
      )}
      {notes.length > 0 && (
        <p
          id={noteId}
          tabIndex={-1}
          className="text-muted-foreground basis-full text-meta outline-offset-2"
        >
          {notes.join(" ")}
        </p>
      )}
    </>
  );
}
