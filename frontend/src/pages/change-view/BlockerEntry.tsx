import { INLINE_LINK } from "@/components/inlineLink";
import { LedgerEntry, type LedgerTone } from "@/components/Ledger";
import { Button } from "@/components/ui/button";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import { normalizeSeverity } from "@/lib/enums";
import { useCopyToClipboard } from "@/lib/useCopyToClipboard";
import { fixSentence, locationLine } from "@/pages/change-view/resolve";
import type { Finding } from "@/types/api";
import { Link } from "react-router-dom";

function toneFor(severity: string): LedgerTone {
  const normalized = normalizeSeverity(severity);
  return normalized === "critical" ? "critical" : normalized === "high" ? "high" : "neutral";
}

export interface BlockerEntryProps {
  readonly slug: string;
  readonly index: number;
  readonly findingId: string;
  readonly finding?: Finding;
  readonly isLoading: boolean;
  readonly isError: boolean;
  readonly onRetry: () => void;
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  readonly handled: boolean;
  readonly onHandledChange: (handled: boolean) => void;
  /** The severity floor the finding is judged against, in words. */
  readonly floor?: string;
  /** A request for this finding is waiting for a decision. */
  readonly waiverRequested: boolean;
  readonly canRequestWaiver: boolean;
  readonly onRequestWaiver: () => void;
}

/** One blocking finding as a ledger entry, from data the caller already has. */
export function BlockerEntry(props: BlockerEntryProps) {
  const { findingId, finding, isLoading, isError, onRetry, index } = props;

  if (isLoading) {
    return (
      <li aria-busy="true" className="border-border border-b px-[18px] py-3.5">
        <Skeleton className="h-4 w-1/2 rounded" />
        <Skeleton className="mt-2 h-3 w-2/3 rounded" />
      </li>
    );
  }
  if (isError || !finding) {
    return (
      <li className="border-border border-b px-[18px] py-3.5">
        <p className="text-body">
          Could not load this finding{" "}
          <span className="text-muted-foreground font-mono text-code">{findingId}</span>
        </p>
        <button type="button" className={`${INLINE_LINK} mt-1 text-body`} onClick={onRetry}>
          Retry
        </button>
      </li>
    );
  }
  return <LoadedEntry {...props} finding={finding} index={index} />;
}

function LoadedEntry(
  {
    slug,
    index,
    findingId,
    finding,
    open,
    onOpenChange,
    handled,
    onHandledChange,
    floor,
    waiverRequested,
    canRequestWaiver,
    onRequestWaiver,
  }: BlockerEntryProps & { finding: Finding; },
) {
  const { status, copy } = useCopyToClipboard();
  const where = locationLine(finding.location);
  const fix = fixSentence(finding);
  const target = `/${slug}/findings/${findingId}`;
  const severity = normalizeSeverity(finding.current_severity);

  return (
    <LedgerEntry
      index={index}
      open={open}
      onOpenChange={onOpenChange}
      label={finding.current_title}
      tone={toneFor(finding.current_severity)}
      resolved={handled}
      summary={
        <>
          <SeverityBadge severity={finding.current_severity} plain />
          <span className="min-w-[10rem] font-semibold [overflow-wrap:anywhere] max-sm:min-w-0">
            {finding.current_title}
          </span>
          {waiverRequested && (
            <span className="font-label text-muted-foreground text-label">Waiver requested</span>
          )}
          {fix && (
            <span
              title={fix}
              className="text-muted-foreground ml-auto min-w-0 max-w-[40%] truncate text-meta max-sm:hidden"
            >
              {fix}
            </span>
          )}
        </>
      }
    >
      <div className="grid gap-3.5 pr-[18px] pb-4 pl-[18px] sm:pl-[52px]">
        <dl className="m-0 grid grid-cols-[104px_minmax(0,1fr)] gap-x-3.5 gap-y-1.5 text-body">
          {where && (
            <>
              <dt className="text-muted-foreground pt-0.5 text-meta">Where</dt>
              <dd className="m-0 min-w-0 font-mono text-code [overflow-wrap:anywhere]">
                {where}
              </dd>
            </>
          )}
          <dt className="text-muted-foreground pt-0.5 text-meta">Why it blocks</dt>
          <dd className="m-0 min-w-0">
            Severity {severity.toUpperCase()}
            {floor
              ? ` is at or above the project floor (${floor.toUpperCase()}).`
              : " blocks the gate."}
          </dd>
        </dl>
        <div className="bg-muted rounded-lg px-3.5 py-2.5">
          <p className="font-label text-muted-foreground text-label">Do this</p>
          {fix
            ? <p className="mt-0.5 font-mono text-code [overflow-wrap:anywhere]">{fix}</p>
            : (
              <p className="mt-0.5 text-body">
                <strong>No automated fix is known.</strong> Open it to decide what to do.
              </p>
            )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {fix && (
            <Button
              type="button"
              variant="outline"
              aria-label={status === "copied"
                ? `Copied the fix for ${finding.current_title}`
                : `Copy the fix for ${finding.current_title}`}
              onClick={() => void copy(fix)}
            >
              {status === "copied" ? "Copied" : status === "failed" ? "Copy failed" : "Copy fix"}
            </Button>
          )}
          {waiverRequested
            ? (
              <span className="text-muted-foreground text-meta">
                Waiting for a manager to decide.
              </span>
            )
            : canRequestWaiver && (
              <Button type="button" variant="outline" onClick={onRequestWaiver}>
                Request waiver
              </Button>
            )}
          <label className="ml-auto flex min-h-[34px] cursor-pointer items-center gap-2 px-1.5 text-meta">
            <input
              type="checkbox"
              checked={handled}
              onChange={(event) => onHandledChange(event.target.checked)}
              aria-label={`I've done this: ${finding.current_title}`}
              className="border-input accent-foreground size-5 rounded-sm"
            />
            I&apos;ve done this
          </label>
        </div>
        <p className="text-meta">
          <Link to={target} className={INLINE_LINK}>Open the full finding</Link>
        </p>
      </div>
    </LedgerEntry>
  );
}
