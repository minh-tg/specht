import { type ActorContext, actorLabel } from "@/api/users";
import { INLINE_LINK } from "@/components/inlineLink";
import { RelativeTime } from "@/components/RelativeTime";
import { Button } from "@/components/ui/button";
import { formatDate } from "@/lib/format";
import { waiverPathId, type WaiverView } from "@/pages/change-view/waiverState";
import type { Waiver } from "@/types/api";
import type { ReactNode } from "react";
import { Link } from "react-router-dom";

export interface WaiverPathProps {
  readonly slug: string;
  readonly findingId: string;
  readonly title: string;
  readonly view: WaiverView;
  readonly who: ActorContext;
  /** The viewer may approve and reject requests (`permissions.approve_waivers`). */
  readonly canApprove: boolean;
  readonly onWithdraw: (waiver: Waiver) => void;
}

function personLabel(waiver: Waiver, kind: "requested" | "decided", who: ActorContext) {
  const id = kind === "requested" ? waiver.requested_by : waiver.decided_by;
  const name = kind === "requested" ? waiver.requested_by_name : waiver.decided_by_name;
  return id ? actorLabel({ user_id: id, user_name: name }, who) : null;
}

/**
 * What became of the waiver for one blocking finding, and what happens next: who can act, and what
 * the finding does in the meantime. It is plain text, not a live region; the page announces
 * changes through its toast and the watching strip.
 */
export function WaiverPath(
  { slug, findingId, title, view, who, canApprove, onWithdraw }: WaiverPathProps,
) {
  const { waiver } = view;
  const requester = personLabel(waiver, "requested", who);
  const decider = personLabel(waiver, "decided", who);
  const mine = !!waiver.requested_by && waiver.requested_by === who.me?.id;
  const ends = waiver.expires_at ? formatDate(waiver.expires_at) : null;
  const waiversPage = `/${slug}/waivers`;

  let headline: string;
  let body: ReactNode;
  let quote: { label: string; text: string; } | null = null;
  let actions: ReactNode = null;

  switch (view.kind) {
    case "pending": {
      headline = "Waiver requested. Waiting for a manager.";
      const asked = (
        <>
          {mine ? "You asked " : `${requester ?? "A manager"} asked `}
          {waiver.requested_at ? <RelativeTime iso={waiver.requested_at} /> : "earlier"}.
        </>
      );
      const next = mine
        ? canApprove
          ? "You cannot approve your own request, so another manager has to decide it."
          : "A project manager decides."
        : canApprove
        ? "You can decide it on the Waivers page."
        : `A project manager decides. Only ${requester ?? "the person who asked"} can withdraw it.`;
      body = (
        <>
          {asked} {next} Until then this finding still blocks this change.
          {ends && ` If nobody decides by ${ends}, the request expires.`}{" "}
          <Link to={waiversPage} className={INLINE_LINK}>
            {canApprove && !mine ? "Decide it on the Waivers page" : "See it on the Waivers page"}
          </Link>
        </>
      );
      if (waiver.reason) quote = { label: "Reason given", text: waiver.reason };
      if (mine) {
        actions = (
          <Button
            type="button"
            size="sm"
            variant="outline"
            aria-label={`Withdraw request: ${title}`}
            onClick={() => onWithdraw(waiver)}
          >
            Withdraw request
          </Button>
        );
      }
      break;
    }
    case "in_force":
      headline = `Waiver approved${decider ? ` by ${decider}` : ""}.`;
      body = ends
        ? `It is in force until ${ends}. After that the finding blocks again.`
        : "It is in force and has no end date.";
      break;
    case "rejected":
      headline = `Waiver rejected${decider ? ` by ${decider}` : ""}.`;
      body = "This finding still blocks this change. Fix it, or ask again with more detail.";
      if (waiver.decision_note) {
        quote = {
          label: decider ? `Note from ${decider}` : "Note from the reviewer",
          text: waiver.decision_note,
        };
      }
      break;
    case "request_expired":
      headline = mine
        ? "Your request expired before anyone decided."
        : "The request expired before anyone decided.";
      body = `Nobody approved or rejected it${
        ends ? ` by ${ends}` : ""
      }. This finding still blocks this change. Fix it, or ask again.`;
      break;
    case "withdrawn":
      headline = `Request withdrawn${mine ? " by you" : ""}.`;
      body = "This finding still blocks this change. Fix it, or ask again.";
      break;
    case "revoked":
      headline = "Waiver revoked.";
      body = `It was approved${
        ends ? ` until ${ends}` : ""
      }, but a manager switched it off, so it no longer counts. Fix the finding, or ask for a new waiver.`;
      break;
    case "expired":
      headline = `Waiver expired${ends ? ` on ${ends}` : ""}.`;
      body = "This finding blocks this change again. Fix it, or ask for a new waiver.";
      break;
  }

  return (
    <div
      id={waiverPathId(findingId)}
      role="group"
      aria-label={`Waiver for ${title}`}
      tabIndex={-1}
      className="bg-muted grid gap-1.5 rounded-lg px-3.5 py-2.5 outline-offset-2"
    >
      <p className="font-label text-muted-foreground text-label">Waiver</p>
      <p className="font-semibold">{headline}</p>
      <p className="text-body">{body}</p>
      {quote && (
        <div className="text-body">
          <p className="text-muted-foreground text-meta">{quote.label}</p>
          <blockquote className="border-border mt-0.5 max-w-[70ch] border-l-[3px] pl-3 [overflow-wrap:anywhere]">
            {quote.text}
          </blockquote>
        </div>
      )}
      {actions && <div className="mt-1 flex flex-wrap gap-2">{actions}</div>}
    </div>
  );
}
