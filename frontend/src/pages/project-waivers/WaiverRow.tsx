import { useFinding } from "@/api/hooks";
import { type ActorContext, actorLabel } from "@/api/users";
import { RelativeTime } from "@/components/RelativeTime";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { pluralize } from "@/lib/format";
import type { Waiver } from "@/types/api";
import { useState } from "react";
import { Link } from "react-router-dom";
import { expiresIn } from "../project-access/expiry";
import { closedReason, type WaiverBucket, waiverTitle } from "./classify";
import { WaiverHistory } from "./WaiverHistory";

/** The severity of the first finding a request names. A request for several shows the first's. */
function FirstSeverity({ findingId }: { readonly findingId: string; }) {
  const { data } = useFinding(findingId);
  return data ? <SeverityBadge severity={data.current_severity} plain /> : null;
}

export interface WaiverRowActions {
  readonly canDecide: boolean;
  readonly canRevoke: boolean;
  readonly canManage: boolean;
  /** The signed-in person, so they can take back their own request. */
  readonly currentUserId: string | null;
  readonly busy: boolean;
  readonly onApprove: (waiver: Waiver) => void;
  readonly onReject: (waiver: Waiver) => void;
  readonly onWithdraw: (waiver: Waiver) => void;
  readonly onRevoke: (waiver: Waiver) => void;
  readonly onRestore: (waiver: Waiver) => void;
  readonly onEdit: (waiver: Waiver) => void;
  readonly onDelete: (waiver: Waiver) => void;
}

function decisionLine(waiver: Waiver, who: ActorContext, reason: string | null): string | null {
  if (!waiver.decided_by && !reason) return null;
  const by = waiver.decided_by
    ? actorLabel({ user_id: waiver.decided_by, user_name: waiver.decided_by_name }, who)
    : null;
  const verb = reason ?? "Decided";
  const head = by ? `${verb} by ${by}` : verb;
  return waiver.decision_note ? `${head}: ${waiver.decision_note}` : head;
}

/**
 * One waiver: what it covers, who asked and why, how long it lasts, and what the viewer can do
 * with it. A request for several findings links to the first.
 */
export function WaiverRow({ slug, waiver, bucket, now, who, actions }: {
  readonly slug: string;
  readonly waiver: Waiver;
  readonly bucket: WaiverBucket;
  readonly now: Date;
  readonly who: ActorContext;
  readonly actions: WaiverRowActions;
}) {
  const first = waiver.targets[0]?.finding_id;
  const title = waiverTitle(waiver);
  const count = waiver.targets.length;
  const closed = bucket === "closed" ? closedReason(waiver, now) : null;
  const requester = waiver.requested_by
    ? actorLabel({ user_id: waiver.requested_by, user_name: waiver.requested_by_name }, who)
    : null;
  const mine = !!waiver.requested_by && waiver.requested_by === actions.currentUserId;
  const decision = bucket === "pending" ? null : decisionLine(waiver, who, closed);
  const [historyOpen, setHistoryOpen] = useState(false);
  const historyId = `waiver-history-${waiver.id}`;

  return (
    <li className="border-border grid gap-x-5 gap-y-2 border-b px-0.5 py-4 sm:grid-cols-[minmax(0,1fr)_auto]">
      <div className="min-w-0">
        <p className="font-semibold">
          {first
            ? (
              <Link
                to={`/${slug}/findings/${first}`}
                className="underline-offset-4 hover:underline"
              >
                {title}
              </Link>
            )
            : title}
        </p>
        <p className="text-muted-foreground mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-meta">
          {first && <FirstSeverity findingId={first} />}
          {count > 1 && <span>{pluralize(count, "finding")}</span>}
          {requester && (
            <span>
              asked by {requester}
              {waiver.requested_at && (
                <>
                  , <RelativeTime iso={waiver.requested_at} />
                </>
              )}
            </span>
          )}
          {!requester && <span>created by a manager</span>}
          {waiver.expires_at && bucket !== "closed" && (
            <span>· ends in {expiresIn(waiver.expires_at, now.getTime())}</span>
          )}
        </p>
        {waiver.reason && (
          <blockquote className="border-border mt-2 max-w-[70ch] border-l-[3px] pl-3 text-body">
            {waiver.reason}
          </blockquote>
        )}
        {decision && <p className="text-muted-foreground mt-2 text-meta">{decision}</p>}
        <button
          type="button"
          aria-expanded={historyOpen}
          aria-controls={historyId}
          aria-label={`History of ${title}`}
          onClick={() => setHistoryOpen((open) => !open)}
          className="text-muted-foreground hover:text-foreground mt-2 text-meta underline-offset-4 hover:underline"
        >
          History
        </button>
        {historyOpen && <WaiverHistory id={historyId} slug={slug} waiverId={waiver.id} who={who} />}
      </div>
      <div className="flex flex-wrap items-start gap-2 sm:justify-end">
        {bucket === "pending" && actions.canDecide && (
          <>
            <Button
              size="sm"
              disabled={actions.busy}
              aria-label={`Approve ${title}`}
              onClick={() => actions.onApprove(waiver)}
            >
              Approve
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={actions.busy}
              aria-label={`Reject ${title}`}
              onClick={() => actions.onReject(waiver)}
            >
              Reject
            </Button>
          </>
        )}
        {bucket === "pending" && mine && (
          <Button
            size="sm"
            variant="outline"
            disabled={actions.busy}
            aria-label={`Withdraw ${title}`}
            onClick={() => actions.onWithdraw(waiver)}
          >
            Withdraw
          </Button>
        )}
        {bucket === "in_force" && actions.canRevoke && (
          <Button
            size="sm"
            variant="outline"
            disabled={actions.busy}
            aria-label={`Revoke ${title}`}
            onClick={() => actions.onRevoke(waiver)}
          >
            Revoke
          </Button>
        )}
        {closed === "Revoked" && actions.canRevoke && (
          <Button
            size="sm"
            variant="outline"
            disabled={actions.busy}
            aria-label={`Restore ${title}`}
            onClick={() => actions.onRestore(waiver)}
          >
            Restore
          </Button>
        )}
        {actions.canManage && (
          <Button
            size="sm"
            variant="outline"
            disabled={actions.busy}
            aria-label={closed === "Expired" ? `Edit expiry of ${title}` : `Edit ${title}`}
            onClick={() => actions.onEdit(waiver)}
          >
            {closed === "Expired" ? "Edit expiry" : "Edit"}
          </Button>
        )}
        {actions.canManage && (
          <Button
            size="sm"
            variant="outline"
            disabled={actions.busy}
            aria-label={`Delete ${title}`}
            onClick={() => actions.onDelete(waiver)}
          >
            Delete
          </Button>
        )}
      </div>
    </li>
  );
}
