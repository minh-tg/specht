import { findingQueryOptions, useWaivers } from "@/api/hooks";
import { INLINE_LINK } from "@/components/inlineLink";
import { Ledger } from "@/components/Ledger";
import { BlockerEntry } from "@/pages/change-view/BlockerEntry";
import { ChangeAside } from "@/pages/change-view/ChangeAside";
import { fixSentence } from "@/pages/change-view/resolve";
import { WaiverRequestDialog } from "@/pages/change-view/WaiverRequestDialog";
import { useQueries } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";

/** Entries fetched and rendered before the "Show all" control reveals the rest. */
export const MAX_BLOCKER_ROWS = 20;

export interface BlockerSectionProps {
  readonly slug: string;
  /** Finding ids that block this change, worst first. */
  readonly ids: readonly string[];
  /** The policy severity floor, in words. */
  readonly floor?: string;
  readonly canRequestWaiver: boolean;
  readonly projectWide?: boolean;
  readonly waiting: boolean;
  readonly stalled: boolean;
  readonly onStartWaiting: () => void;
  readonly onCheckAgain: () => void;
}

/**
 * The findings that block this change, as a ledger the reader works down, with the margin note beside
 * it. What the reader has handled, which entries are open and which finding a waiver dialog is about
 * all live here, so the ledger and the note stay in step.
 */
export function BlockerSection(
  {
    slug,
    ids,
    floor,
    canRequestWaiver,
    projectWide = false,
    waiting,
    stalled,
    onStartWaiting,
    onCheckAgain,
  }: BlockerSectionProps,
) {
  const [showAll, setShowAll] = useState(false);
  const shown = showAll ? ids : ids.slice(0, MAX_BLOCKER_ROWS);
  const results = useQueries({
    queries: shown.map((id) => findingQueryOptions(id)),
  });
  const pending = useWaivers(slug, ["pending"]);
  const [handled, setHandled] = useState<ReadonlySet<string>>(new Set());
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set(ids.slice(0, 1)));
  const [dialog, setDialog] = useState<{ id: string; title: string; } | null>(null);

  const requested = useMemo(() => {
    const covered = new Set<string>();
    for (const waiver of pending.data ?? []) {
      for (const target of waiver.targets) covered.add(target.finding_id);
    }
    return covered;
  }, [pending.data]);

  function toggle(set: ReadonlySet<string>, id: string, on: boolean): Set<string> {
    const next = new Set(set);
    if (on) next.add(id);
    else next.delete(id);
    return next;
  }

  const allHandled = ids.length > 0 && ids.every((id) => handled.has(id));
  useEffect(() => {
    // Handling the last blocker means a push is next, so start listening for the scan.
    if (allHandled) onStartWaiting();
  }, [allHandled, onStartWaiting]);

  const items = shown.map((id, index) => ({
    id,
    title: results[index]?.data?.current_title ?? "Loading…",
    handled: handled.has(id),
  }));
  const fixesText = shown
    .map((_, index) => {
      const finding = results[index]?.data;
      const fix = finding ? fixSentence(finding) : null;
      return finding && fix ? `${index + 1}. ${finding.current_title}: ${fix}` : null;
    })
    .filter((line): line is string => line !== null)
    .join("\n");

  if (ids.length === 0) return null;

  return (
    <>
      <div className="mt-8 grid items-start gap-x-10 gap-y-8 lg:grid-cols-[minmax(0,1fr)_280px]">
        <section
          aria-label={projectWide
            ? "Findings blocking this project"
            : "Findings introduced by this change"}
        >
          <div className="mb-2.5 flex items-baseline justify-between">
            <h2 className="text-section leading-tight font-semibold">What is in the way</h2>
            <span className="text-muted-foreground text-[13px]">Worst first</span>
          </div>
          <Ledger label="Blocking findings">
            {shown.map((id, index) => {
              const query = results[index];
              return (
                <BlockerEntry
                  key={id}
                  slug={slug}
                  index={index + 1}
                  findingId={id}
                  finding={query.data}
                  isLoading={query.isPending}
                  isError={query.isError}
                  onRetry={() => void query.refetch()}
                  open={open.has(id)}
                  onOpenChange={(next) => setOpen((set) => toggle(set, id, next))}
                  handled={handled.has(id)}
                  onHandledChange={(next) => setHandled((set) => toggle(set, id, next))}
                  floor={floor}
                  waiverRequested={requested.has(id)}
                  canRequestWaiver={canRequestWaiver}
                  onRequestWaiver={() =>
                    setDialog({ id, title: query.data?.current_title ?? "this finding" })}
                />
              );
            })}
          </Ledger>
          {shown.length < ids.length && (
            <button
              type="button"
              className={`${INLINE_LINK} mt-2 text-sm`}
              onClick={() => setShowAll(true)}
            >
              Show all {ids.length}
            </button>
          )}
        </section>
        <ChangeAside
          items={items}
          onHandledChange={(id, next) => setHandled((set) => toggle(set, id, next))}
          fixesText={fixesText}
          waiting={waiting}
          stalled={stalled}
          onStartWaiting={onStartWaiting}
          onCheckAgain={onCheckAgain}
        />
      </div>
      {dialog && (
        <WaiverRequestDialog
          slug={slug}
          findingIds={[dialog.id]}
          subject={dialog.title}
          open
          onOpenChange={(next) => {
            if (!next) setDialog(null);
          }}
          onRequested={() => setDialog(null)}
        />
      )}
    </>
  );
}
