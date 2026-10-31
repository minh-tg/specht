import { useMe, useWaivers } from "@/api/hooks";
import { INLINE_LINK } from "@/components/inlineLink";
import { Ledger } from "@/components/Ledger";
import { waiverAction } from "@/lib/waiverRequest";
import { BlockerEntry } from "@/pages/change-view/BlockerEntry";
import { ChangeAside } from "@/pages/change-view/ChangeAside";
import { FixGroupEntry } from "@/pages/change-view/FixGroupEntry";
import {
  type BlockerItem,
  buildBlockerItems,
  groupWaiverNoteId,
  itemFixesText,
  itemIds,
  upgradeInstruction,
} from "@/pages/change-view/groupByFix";
import { GroupWaiverControl } from "@/pages/change-view/GroupWaiverControl";
import { FINDING_FETCH_WINDOW, useBlockerFindings } from "@/pages/change-view/useBlockerFindings";
import { WaiverRequestDialog } from "@/pages/change-view/WaiverRequestDialog";
import { waiverPathId, waiverViewsByFinding } from "@/pages/change-view/waiverState";
import type { WatchState } from "@/pages/change-view/WatchStrip";
import { WithdrawWaiverDialog } from "@/pages/change-view/WithdrawWaiverDialog";
import type { Project } from "@/types/api";
import { useEffect, useMemo, useRef, useState } from "react";

/**
 * Entries drawn before the "Show all" control reveals the rest. Every blocker is still fetched, so
 * that blockers one upgrade clears can be grouped; this only keeps a very long page short.
 */
export const MAX_BLOCKER_ROWS = 20;

/** The id of the note under the "request one waiver for all" control. */
const BATCH_NOTE_ID = "blocker-waiver-all";

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
  const found = useBlockerFindings(ids);
  const waivers = useWaivers(slug);
  const { data: me } = useMe();
  const [handled, setHandled] = useState<ReadonlySet<string>>(new Set());
  // Open entries by key: a finding id for a plain row, the group's key for a group. A group is also
  // open when a member was, so folding rows together does not close what the reader had open.
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set(ids.slice(0, 1)));
  const [dialog, setDialog] = useState<
    { ids: readonly string[]; subject: string; focusId: string; focusTarget: string; } | null
  >(null);
  const [withdrawing, setWithdrawing] = useState<
    { waiverId: string; findingId: string; title: string; } | null
  >(null);
  const [withdrawOpen, setWithdrawOpen] = useState(false);
  const [announcement, setAnnouncement] = useState("");
  const announced = useRef(false);
  // A request just sent: focus moves to the block that now speaks for it once the list shows it.
  const focusAfterRequest = useRef<{ id: string; target: string; } | null>(null);
  // The entry the reader last had focus in, so folding rows into a group can keep focus on it.
  const lastFocused = useRef<string | null>(null);
  const sectionRef = useRef<HTMLElement>(null);

  // Rows are grouped once every blocker has loaded; until then each is a row of its own, in order.
  const items = useMemo<BlockerItem[]>(
    () =>
      found.done
        ? buildBlockerItems(ids, found.byId)
        : ids.map((id, index) => ({ kind: "single", key: id, id, position: index + 1 })),
    [ids, found.done, found.byId],
  );
  const shown = showAll ? items : items.slice(0, MAX_BLOCKER_ROWS);
  const groupCount = items.filter((item) => item.kind === "group").length;

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
  const request = waiverAction({
    permissions: permissions?.request_waiver,
    loading: permissionsLoading,
    pending: false,
    // These ids are the ones the gate says block, so the finding blocks.
    blocking: { blocks: true },
    gateRechecking: false,
  });

  useEffect(() => {
    const target = focusAfterRequest.current;
    if (!target || !views.has(target.id)) return;
    document.getElementById(target.target)?.focus();
    focusAfterRequest.current = null;
  }, [views]);

  // One announcement, when the whole list is known and the rows have settled into their groups.
  useEffect(() => {
    if (!found.done || announced.current || ids.length < 2) return;
    announced.current = true;
    const failed = found.failedIds.length;
    const grouped = items.reduce(
      (sum, item) => sum + (item.kind === "group" ? item.ids.length : 0),
      0,
    );
    const loaded = ids.length - failed;
    const base = failed > 0
      ? `Loaded ${loaded} of ${ids.length} blockers. ${failed} could not be loaded.`
      : `Loaded all ${ids.length} blockers.`;
    setAnnouncement(
      groupCount > 0
        ? `${base} ${grouped} of them are grouped into ${groupCount} ${
          groupCount === 1 ? "fix" : "fixes"
        }.`
        : `${base} None share a fix.`,
    );
  }, [found.done, found.failedIds.length, ids.length, items, groupCount]);

  // If the row the reader was in has been folded into a group, focus its group instead of letting
  // it fall to the page. Focus that is anywhere else is left where it is.
  useEffect(() => {
    const from = lastFocused.current;
    if (!from || document.activeElement !== document.body) return;
    const item = items.find((entry) => itemIds(entry).includes(from));
    if (!item || item.key === from) return;
    const entries = sectionRef.current?.querySelectorAll<HTMLElement>("[data-entry-id]") ?? [];
    for (const entry of entries) {
      if (entry.dataset.entryId === item.key) entry.querySelector("button")?.focus();
    }
  }, [items]);

  function toggle(set: ReadonlySet<string>, id: string, on: boolean): Set<string> {
    const next = new Set(set);
    if (on) next.add(id);
    else next.delete(id);
    return next;
  }

  function setOpenItem(item: BlockerItem, next: boolean) {
    setOpen((set) => {
      const result = toggle(set, item.key, next);
      if (!next) { for (const id of itemIds(item)) result.delete(id); }
      return result;
    });
  }

  function setHandledMany(handledIds: readonly string[], next: boolean) {
    setHandled((set) => {
      const result = new Set(set);
      for (const id of handledIds) {
        if (next) result.add(id);
        else result.delete(id);
      }
      return result;
    });
  }

  function titleOf(id: string): string {
    return found.byId.get(id)?.current_title ?? "this finding";
  }

  const asideItems = shown.map((item) => {
    if (item.kind === "group") {
      return {
        id: item.key,
        title: `${upgradeInstruction(item.target)} (clears ${item.ids.length} blockers)`,
        handled: item.ids.every((id) => handled.has(id)),
      };
    }
    return {
      id: item.id,
      title: found.list[item.position - 1]?.current_title ?? "Loading…",
      handled: handled.has(item.id),
    };
  });
  const allFixes = itemFixesText(shown, found.byId);

  if (ids.length === 0) return null;

  const failedIds = found.failedIds;
  const shownFailed = failedIds.slice(0, 5);

  return (
    <>
      <div className="mt-8 grid items-start gap-x-10 gap-y-8 lg:grid-cols-[minmax(0,1fr)_280px]">
        <section
          ref={sectionRef}
          aria-label={projectWide
            ? "Findings blocking this project"
            : "Findings introduced by this change"}
          onFocusCapture={(event) => {
            const entry = (event.target as HTMLElement).closest<HTMLElement>("[data-entry-id]");
            lastFocused.current = entry?.dataset.entryId ?? null;
          }}
        >
          <div className="mb-2.5 flex items-baseline justify-between">
            <h2 className="text-section leading-tight font-semibold">What is in the way</h2>
            <span className="text-muted-foreground text-meta">Worst first</span>
          </div>
          <p role="status" className="sr-only">{announcement}</p>
          {!found.done && found.total > FINDING_FETCH_WINDOW && (
            <p aria-busy="true" className="text-muted-foreground mb-2 text-meta">
              Loading blockers: {found.settled} of{" "}
              {found.total}. Blockers that one upgrade fixes are grouped when all have loaded.
            </p>
          )}
          {failedIds.length > 0 && (
            <div className="mb-2 text-body">
              <p>
                Could not load {failedIds.length} of {ids.length} blockers:{" "}
                <span className="font-mono text-code [overflow-wrap:anywhere]">
                  {shownFailed.join(", ")}
                </span>
                {failedIds.length > shownFailed.length
                  && ` and ${failedIds.length - shownFailed.length} more`}. Each is listed on its
                own, so a group may be missing them.
              </p>
              <button
                type="button"
                className={`${INLINE_LINK} mt-1 text-body`}
                onClick={found.retryFailed}
              >
                Retry the {failedIds.length} that failed
              </button>
            </div>
          )}
          <Ledger label="Blocking findings">
            {shown.map((item) => {
              if (item.kind === "group") {
                return (
                  <FixGroupEntry
                    key={item.key}
                    slug={slug}
                    item={item}
                    findings={found.byId}
                    open={open.has(item.key) || item.ids.some((id) => open.has(id))}
                    onOpenChange={(next) => setOpenItem(item, next)}
                    handled={handled}
                    onHandledChange={(next) => setHandledMany(item.ids, next)}
                    floor={floor}
                    views={views}
                    request={request}
                    waitingForWaivers={waivers.isPending}
                    onRequestWaiver={(requestIds) => {
                      setDialog({
                        ids: requestIds,
                        subject:
                          `the ${requestIds.length} findings that upgrading ${item.target.packageName} to ${item.target.fixedVersion} fixes`,
                        focusId: requestIds[0],
                        focusTarget: groupWaiverNoteId(item.key),
                      });
                    }}
                  />
                );
              }
              const id = item.id;
              const at = item.position - 1;
              return (
                <BlockerEntry
                  key={id}
                  slug={slug}
                  index={item.position}
                  findingId={id}
                  finding={found.list[at]}
                  isLoading={found.pending[at]}
                  isError={found.failed[at]}
                  onRetry={() => found.retry(id)}
                  open={open.has(id)}
                  onOpenChange={(next) => setOpenItem(item, next)}
                  handled={handled.has(id)}
                  onHandledChange={(next) => setHandledMany([id], next)}
                  floor={floor}
                  waiver={views.get(id)}
                  request={request}
                  canApprove={permissions?.approve_waivers === true}
                  who={who}
                  onRequestWaiver={() =>
                    setDialog({
                      ids: [id],
                      subject: titleOf(id),
                      focusId: id,
                      focusTarget: waiverPathId(id),
                    })}
                  onWithdrawWaiver={(waiver) => {
                    setWithdrawing({ waiverId: waiver.id, findingId: id, title: titleOf(id) });
                    setWithdrawOpen(true);
                  }}
                />
              );
            })}
          </Ledger>
          {shown.length < items.length && (
            <button
              type="button"
              className={`${INLINE_LINK} mt-2 text-body`}
              onClick={() => setShowAll(true)}
            >
              Show all {items.length}
            </button>
          )}
          {ids.length > 1 && (
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <GroupWaiverControl
                ids={ids}
                views={views}
                request={request}
                waitingForWaivers={waivers.isPending}
                context="every blocker of this change"
                noteId={BATCH_NOTE_ID}
                onRequest={(requestIds) =>
                  setDialog({
                    ids: requestIds,
                    subject: `${requestIds.length} blocking findings`,
                    focusId: requestIds[0],
                    focusTarget: BATCH_NOTE_ID,
                  })}
              />
            </div>
          )}
        </section>
        <ChangeAside
          items={asideItems}
          onHandledChange={(id, next) => {
            const group = shown.find((item) => item.kind === "group" && item.key === id);
            setHandledMany(group ? itemIds(group) : [id], next);
          }}
          fixesText={allFixes}
          watch={watch}
          branch={branch}
        />
      </div>
      {dialog && (
        <WaiverRequestDialog
          slug={slug}
          findingIds={dialog.ids}
          subject={dialog.subject}
          open
          onOpenChange={(next) => {
            if (!next) setDialog(null);
          }}
          onRequested={() => {
            focusAfterRequest.current = { id: dialog.focusId, target: dialog.focusTarget };
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
