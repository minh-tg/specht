import { useFinding } from "@/api/hooks";
import { type ActorContext, actorLabel } from "@/api/users";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { formatRelativeTime, pluralize } from "@/lib/format";
import type { Waiver } from "@/types/api";
import { Link } from "react-router-dom";
import { expiresIn } from "../project-access/expiry";
import { closedReason, type WaiverBucket, waiverTitle } from "./classify";

/** The severity of the first finding a request names. A request for several shows the first's. */
function FirstSeverity({ findingId }: { readonly findingId: string; }) {
  const { data } = useFinding(findingId);
  return data ? <SeverityBadge severity={data.current_severity} plain /> : null;
}

export interface WaiverRowActions {
  readonly canDecide: boolean;
  readonly canRevoke: boolean;
  /** The signed-in person, so they can take back their own request. */
  readonly currentUserId: string | null;
  readonly busy: boolean;
  readonly onApprove: (waiver: Waiver) => void;
  readonly onReject: (waiver: Waiver) => void;
  readonly onWithdraw: (waiver: Waiver) => void;
  readonly onRevoke: (waiver: Waiver) => void;
}

function decisionLine(waiver: Waiver, who: ActorContext, reason: string | null): string | null {
  if (!waiver.decided_by && !reason) return null;
  const by = waiver.decided_by
    ? actorLabel({ user_id: waiver.decided_by }, who)
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
    ? actorLabel({ user_id: waiver.requested_by }, who)
    : null;
  const mine = !!waiver.requested_by && waiver.requested_by === actions.currentUserId;
  const decision = bucket === "pending" ? null : decisionLine(waiver, who, closed);

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
        <p className="text-muted-foreground mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-[0.8125rem]">
          {first && <FirstSeverity findingId={first} />}
          {count > 1 && <span>{pluralize(count, "finding")}</span>}
          {requester && (
            <span>
              asked by {requester}
              {waiver.requested_at && <>, {formatRelativeTime(waiver.requested_at, now)}</>}
            </span>
          )}
          {!requester && <span>created by a manager</span>}
          {waiver.expires_at && bucket !== "closed" && (
            <span>· ends in {expiresIn(waiver.expires_at, now.getTime())}</span>
          )}
        </p>
        {waiver.reason && (
          <blockquote className="border-border mt-2 max-w-[70ch] border-l-[3px] pl-3 text-[0.9375rem]">
            {waiver.reason}
          </blockquote>
        )}
        {decision && <p className="text-muted-foreground mt-2 text-[0.8125rem]">{decision}</p>}
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
      </div>
    </li>
  );
}
