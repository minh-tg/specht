import { findingQueryOptions, useMe, useWaivers } from "@/api/hooks";
import { INLINE_LINK } from "@/components/inlineLink";
import { Ledger } from "@/components/Ledger";
import { waiverAction } from "@/lib/waiverRequest";
import { BlockerEntry } from "@/pages/change-view/BlockerEntry";
import { ChangeAside } from "@/pages/change-view/ChangeAside";
import { fixesText } from "@/pages/change-view/resolve";
import { WaiverRequestDialog } from "@/pages/change-view/WaiverRequestDialog";
import { waiverPathId, waiverViewsByFinding } from "@/pages/change-view/waiverState";
import type { WatchState } from "@/pages/change-view/WatchStrip";
import { WithdrawWaiverDialog } from "@/pages/change-view/WithdrawWaiverDialog";
import type { Project } from "@/types/api";
import { useQueries } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";

/** Entries fetched and rendered before the "Show all" control reveals the rest. */
export const MAX_BLOCKER_ROWS = 20;

export interface BlockerSectionProps {
  readonly slug: string;
  /** Finding ids that block this change, worst first. */
  readonly ids: readonly string[];
  /** The policy severity floor, in words. */
  readonly floor?: string;
  /** What the project read says the viewer may do, or absent until it has loaded. */
  readonly permissions?: Project["permissions"];
  readonly permissionsLoading?: boolean;
  readonly projectWide?: boolean;
  /** The branch the page watches for the next scan. */
  readonly branch?: string | null;
  /** The page's watching, or absent when it is not watching. */
  readonly watch?: WatchState;
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
    permissions,
    permissionsLoading = false,
    projectWide = false,
    branch,
    watch,
  }: BlockerSectionProps,
) {
  const [showAll, setShowAll] = useState(false);
  const shown = showAll ? ids : ids.slice(0, MAX_BLOCKER_ROWS);
  const results = useQueries({
    queries: shown.map((id) => findingQueryOptions(id)),
  });
  const waivers = useWaivers(slug);
  const { data: me } = useMe();
  const [handled, setHandled] = useState<ReadonlySet<string>>(new Set());
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set(ids.slice(0, 1)));
  const [dialog, setDialog] = useState<{ id: string; title: string; } | null>(null);
  const [withdrawing, setWithdrawing] = useState<
    { waiverId: string; findingId: string; title: string; } | null
  >(null);
  const [withdrawOpen, setWithdrawOpen] = useState(false);
  // A finding whose request was just sent: focus moves to its waiver block once the list shows it.
  const focusAfterRequest = useRef<string | null>(null);

  // Expiry is judged as of the last fetch, so a waiver changes state when the data does.
  const views = useMemo(
    () =>
      waiverViewsByFinding(
        Array.isArray(waivers.data) ? waivers.data : [],
        new Date(waivers.dataUpdatedAt),
      ),
    [waivers.data, waivers.dataUpdatedAt],
  );
  const who = useMemo(() => ({ me }), [me]);

  useEffect(() => {
    const id = focusAfterRequest.current;
    if (!id || !views.has(id)) return;
    document.getElementById(waiverPathId(id))?.focus();
    focusAfterRequest.current = null;
  }, [views]);

  function toggle(set: ReadonlySet<string>, id: string, on: boolean): Set<string> {
    const next = new Set(set);
    if (on) next.add(id);
    else next.delete(id);
    return next;
  }

  const items = shown.map((id, index) => ({
    id,
    title: results[index]?.data?.current_title ?? "Loading…",
    handled: handled.has(id),
  }));
  const allFixes = fixesText(shown.map((_, index) => results[index]?.data));

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
            <span className="text-muted-foreground text-meta">Worst first</span>
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
                  waiver={views.get(id)}
                  request={waiverAction({
                    permissions: permissions?.request_waiver,
                    loading: permissionsLoading,
                    pending: false,
                    // These ids are the ones the gate says block, so the finding blocks.
                    blocking: { blocks: true },
                    gateRechecking: false,
                  })}
                  canApprove={permissions?.approve_waivers === true}
                  who={who}
                  onRequestWaiver={() =>
                    setDialog({ id, title: query.data?.current_title ?? "this finding" })}
                  onWithdrawWaiver={(waiver) => {
                    setWithdrawing({
                      waiverId: waiver.id,
                      findingId: id,
                      title: query.data?.current_title ?? "this finding",
                    });
                    setWithdrawOpen(true);
                  }}
                />
              );
            })}
          </Ledger>
          {shown.length < ids.length && (
            <button
              type="button"
              className={`${INLINE_LINK} mt-2 text-body`}
              onClick={() => setShowAll(true)}
            >
              Show all {ids.length}
            </button>
          )}
        </section>
        <ChangeAside
          items={items}
          onHandledChange={(id, next) => setHandled((set) => toggle(set, id, next))}
          fixesText={allFixes}
          watch={watch}
          branch={branch}
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
          onRequested={() => {
            focusAfterRequest.current = dialog.id;
            setDialog(null);
          }}
        />
      )}
      <WithdrawWaiverDialog
        slug={slug}
        target={withdrawing}
        open={withdrawOpen}
        onClose={() => setWithdrawOpen(false)}
      />
    </>
  );
}
