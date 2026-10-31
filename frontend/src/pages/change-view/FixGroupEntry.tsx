import { INLINE_LINK } from "@/components/inlineLink";
import { LedgerEntry, type LedgerTone } from "@/components/Ledger";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { changeViewState, fromChangePath } from "@/lib/entryMode";
import { normalizeSeverity } from "@/lib/enums";
import { pluralize } from "@/lib/format";
import { useCopyToClipboard } from "@/lib/useCopyToClipboard";
import type { WaiverAction } from "@/lib/waiverRequest";
import {
  type GroupItem,
  groupWaiverNoteId,
  upgradeInstruction,
  worstSeverity,
} from "@/pages/change-view/groupByFix";
import { GroupWaiverControl } from "@/pages/change-view/GroupWaiverControl";
import { waiverChip, type WaiverView } from "@/pages/change-view/waiverState";
import type { Finding } from "@/types/api";
import { Link, useLocation } from "react-router-dom";

export interface FixGroupEntryProps {
  readonly slug: string;
  readonly item: GroupItem;
  readonly findings: ReadonlyMap<string, Finding>;
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  /** Finding ids the reader has marked as done. */
  readonly handled: ReadonlySet<string>;
  /** Marks every member done, or none. */
  readonly onHandledChange: (handled: boolean) => void;
  readonly floor?: string;
  readonly views: ReadonlyMap<string, WaiverView>;
  readonly request: WaiverAction;
  readonly waitingForWaivers: boolean;
  readonly onRequestWaiver: (ids: readonly string[]) => void;
}

function toneFor(severity: string): LedgerTone {
  const normalized = normalizeSeverity(severity);
  return normalized === "critical" ? "critical" : normalized === "high" ? "high" : "neutral";
}

function installedVersions(ids: readonly string[], findings: ReadonlyMap<string, Finding>) {
  const seen = new Set<string>();
  for (const id of ids) {
    const version = findings.get(id)?.suggestion?.installed_version?.trim();
    if (version) seen.add(version);
  }
  return [...seen];
}

/**
 * Several blockers that one upgrade clears, as one ledger entry. It says why they are together,
 * lists each member with its own number and a link to the full finding, and offers the one
 * instruction and one waiver request. The members stay separate findings: a waiver, a triage or a
 * scan treats each on its own.
 */
export function FixGroupEntry(
  {
    slug,
    item,
    findings,
    open,
    onOpenChange,
    handled,
    onHandledChange,
    floor,
    views,
    request,
    waitingForWaivers,
    onRequestWaiver,
  }: FixGroupEntryProps,
) {
  const { status, copy } = useCopyToClipboard();
  const routerLocation = useLocation();
  const state = changeViewState(routerLocation);
  const instruction = upgradeInstruction(item.target);
  const count = item.ids.length;
  const severity = worstSeverity(item.ids, findings);
  const allHandled = item.ids.every((id) => handled.has(id));
  const installed = installedVersions(item.ids, findings);
  const copyLabel = status === "copied"
    ? "Copied"
    : status === "failed"
    ? "Copy failed"
    : "Copy fix";

  return (
    <LedgerEntry
      entryId={item.key}
      index={item.position}
      open={open}
      onOpenChange={onOpenChange}
      tone={toneFor(severity)}
      resolved={allHandled}
      summary={
        <>
          <SeverityBadge severity={severity} plain />{" "}
          <span className="min-w-[10rem] font-semibold [overflow-wrap:anywhere] max-sm:min-w-0">
            {instruction}
          </span>{" "}
          <span className="text-muted-foreground ml-auto flex-none text-meta">
            clears {count} blockers
          </span>
        </>
      }
    >
      <div className="grid gap-3.5 pr-[18px] pb-4 pl-[18px] sm:pl-[52px]">
        <p className="text-body">
          The scanner reports the same package, ecosystem and fixed version for these {count}{" "}
          findings, so one upgrade clears all of them. They stay {count}{" "}
          separate findings: each keeps its own number, waiver and verdict, and each one still
          blocks this change until a new scan no longer finds it.
        </p>
        <dl className="m-0 grid grid-cols-[104px_minmax(0,1fr)] gap-x-3.5 gap-y-1.5 text-body">
          <dt className="text-muted-foreground pt-0.5 text-meta">Package</dt>
          <dd className="m-0 min-w-0 font-mono text-code [overflow-wrap:anywhere]">
            {item.target.packageName} ({item.target.ecosystem})
          </dd>
          {installed.length > 0 && (
            <>
              <dt className="text-muted-foreground pt-0.5 text-meta">Installed</dt>
              <dd className="m-0 min-w-0 font-mono text-code [overflow-wrap:anywhere]">
                {installed.join(", ")}
              </dd>
            </>
          )}
          <dt className="text-muted-foreground pt-0.5 text-meta">Fixed in</dt>
          <dd className="m-0 min-w-0 font-mono text-code">{item.target.fixedVersion}</dd>
          <dt className="text-muted-foreground pt-0.5 text-meta">Why it blocks</dt>
          <dd className="m-0 min-w-0">
            {floor
              ? `Each one is at or above the project floor (${floor.toUpperCase()}), so together they block this change.`
              : "Each one blocks the gate, so together they block this change."}
          </dd>
        </dl>
        <div className="bg-muted rounded-lg px-3.5 py-2.5">
          <p className="font-label text-muted-foreground text-label">Do this</p>
          <p className="mt-0.5 font-mono text-code [overflow-wrap:anywhere]">{instruction}</p>
        </div>
        <div>
          <p className="font-label text-muted-foreground text-label">
            The {pluralize(count, "blocker")} it clears
          </p>
          <ul className="m-0 mt-1 list-none p-0">
            {item.ids.map((id, index) => {
              const finding = findings.get(id);
              const view = views.get(id);
              return (
                <li
                  key={id}
                  className="border-border flex flex-wrap items-center gap-x-2 gap-y-1 border-b py-1.5 last:border-b-0"
                >
                  <span className="text-muted-foreground w-[22px] flex-none font-mono text-code max-sm:hidden">
                    {String(item.positions[index]).padStart(2, "0")}
                  </span>
                  {finding && <SeverityBadge severity={finding.current_severity} plain />}
                  <Link
                    to={fromChangePath(`/${slug}/findings/${id}`)}
                    state={state}
                    className={`${INLINE_LINK} min-w-0 text-body [overflow-wrap:anywhere]`}
                  >
                    {finding?.current_title ?? id}
                  </Link>
                  {view && (
                    <span className="font-label text-muted-foreground text-label">
                      {waiverChip(view.kind)}
                    </span>
                  )}
                </li>
              );
            })}
          </ul>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            type="button"
            variant="outline"
            aria-label={`${copyLabel}: ${instruction}`}
            onClick={() => void copy(instruction)}
          >
            {copyLabel}
          </Button>
          <GroupWaiverControl
            ids={item.ids}
            views={views}
            request={request}
            waitingForWaivers={waitingForWaivers}
            context={instruction}
            onRequest={onRequestWaiver}
            noteId={groupWaiverNoteId(item.key)}
          />
          <label className="ml-auto flex min-h-[34px] cursor-pointer items-center gap-2 px-1.5 text-meta">
            <input
              type="checkbox"
              checked={allHandled}
              onChange={(event) => onHandledChange(event.target.checked)}
              aria-label={`I've done this: ${instruction}`}
              className="border-input accent-foreground size-5 rounded-sm"
            />
            I&apos;ve done this
          </label>
        </div>
      </div>
    </LedgerEntry>
  );
}
