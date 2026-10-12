import { useMe, useProject, useRevokeWaiver, useWaivers, useWithdrawWaiver } from "@/api/hooks";
import { useUserDirectory } from "@/api/users";
import { useAuth } from "@/auth/useAuth";
import { ErrorState } from "@/components/ErrorState";
import { SkeletonLines } from "@/components/SkeletonLines";
import { cn } from "@/lib/utils";
import type { Waiver } from "@/types/api";
import { type KeyboardEvent, useMemo, useRef, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import {
  BUCKET_LABEL,
  BUCKETS,
  countByBucket,
  type WaiverBucket,
  waiverBucket,
} from "./project-waivers/classify";
import { DecideDialog, type Decision } from "./project-waivers/DecideDialog";
import { WaiverRow } from "./project-waivers/WaiverRow";

const EMPTY_TEXT: Record<WaiverBucket, string> = {
  pending: "Nothing is waiting for a decision.",
  in_force: "No waiver is letting a finding through.",
  closed: "Nothing has been closed yet.",
};

const TAB_PARAM = "state";

function bucketFromParam(value: string | null): WaiverBucket {
  return BUCKETS.find((b) => b === value) ?? "pending";
}

/**
 * The project's waivers in three lists: waiting for a decision, in force, and closed. A manager
 * decides the waiting ones and can revoke one in force; the person who asked can withdraw their own.
 */
export function ProjectWaivers() {
  const { slug } = useParams<{ slug: string; }>();
  const currentSlug = slug ?? "";
  const [params, setParams] = useSearchParams();
  const tab = bucketFromParam(params.get(TAB_PARAM));
  const tabRefs = useRef<Partial<Record<WaiverBucket, HTMLButtonElement | null>>>({});

  const { data: waivers, isLoading, isError, refetch, dataUpdatedAt } = useWaivers(currentSlug);
  const { data: project } = useProject(currentSlug);
  const { data: me } = useMe();
  const { data: directory } = useUserDirectory();
  const { userId } = useAuth();
  const withdraw = useWithdrawWaiver(currentSlug);
  const revoke = useRevokeWaiver(currentSlug);

  const [deciding, setDeciding] = useState<{ waiver: Waiver; decision: Decision; } | null>(null);

  // Expiry is judged as of the last fetch, so the lists only move when the data does.
  const now = useMemo(() => new Date(dataUpdatedAt), [dataUpdatedAt]);
  const counts = useMemo(() => countByBucket(waivers ?? [], now), [waivers, now]);
  const shown = useMemo(
    () => (waivers ?? []).filter((w) => waiverBucket(w, now) === tab),
    [waivers, now, tab],
  );

  function select(next: WaiverBucket) {
    const nextParams = new URLSearchParams(params);
    if (next === "pending") nextParams.delete(TAB_PARAM);
    else nextParams.set(TAB_PARAM, next);
    setParams(nextParams, { replace: true });
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const step = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    if (step === 0) return;
    event.preventDefault();
    const next = BUCKETS[(BUCKETS.indexOf(tab) + step + BUCKETS.length) % BUCKETS.length]!;
    select(next);
    tabRefs.current[next]?.focus();
  }

  if (isLoading) return <SkeletonLines label="Loading waivers" />;
  if (isError || !waivers) {
    return <ErrorState title="Could not load waivers." onRetry={() => void refetch()} />;
  }

  const permissions = project?.permissions;
  const busy = withdraw.isPending || revoke.isPending;
  const failure = withdraw.error ?? revoke.error;

  return (
    <section aria-labelledby="waivers-heading" className="grid gap-5">
      <div>
        <h2 id="waivers-heading" className="text-lg font-semibold">Waivers</h2>
        <p className="text-muted-foreground mt-0.5 text-sm">
          <span className="tabular-nums">{counts.pending}</span> waiting for a decision ·{" "}
          <span className="tabular-nums">{counts.in_force}</span> in force
        </p>
      </div>

      <div
        role="tablist"
        aria-label="Waiver states"
        onKeyDown={onKeyDown}
        className="border-border -mb-2 flex flex-wrap gap-1 border-b"
      >
        {BUCKETS.map((bucket) => (
          <button
            key={bucket}
            ref={(el) => {
              tabRefs.current[bucket] = el;
            }}
            type="button"
            role="tab"
            id={`waivers-tab-${bucket}`}
            aria-selected={tab === bucket}
            aria-controls="waivers-panel"
            tabIndex={tab === bucket ? 0 : -1}
            onClick={() => select(bucket)}
            className={cn(
              "-mb-px h-10 border-b-2 px-3 text-sm font-medium",
              tab === bucket
                ? "border-foreground text-foreground"
                : "text-muted-foreground hover:text-foreground border-transparent",
            )}
          >
            {BUCKET_LABEL[bucket]} <span className="ml-0.5 tabular-nums">{counts[bucket]}</span>
          </button>
        ))}
      </div>

      <div
        role="tabpanel"
        id="waivers-panel"
        aria-labelledby={`waivers-tab-${tab}`}
        tabIndex={-1}
      >
        {shown.length === 0
          ? (
            <p className="text-muted-foreground border-foreground border-t-2 py-6 text-sm">
              {EMPTY_TEXT[tab]}
            </p>
          )
          : (
            <ul className="border-foreground m-0 list-none border-t-2 p-0">
              {shown.map((waiver) => (
                <WaiverRow
                  key={waiver.id}
                  slug={currentSlug}
                  waiver={waiver}
                  bucket={tab}
                  now={now}
                  who={{ me, directory }}
                  actions={{
                    canDecide: !!permissions?.approve_waivers,
                    canRevoke: !!permissions?.manage_waivers,
                    currentUserId: userId,
                    busy,
                    onApprove: (w) => setDeciding({ waiver: w, decision: "approve" }),
                    onReject: (w) => setDeciding({ waiver: w, decision: "reject" }),
                    onWithdraw: (w) => withdraw.mutate(w.id),
                    onRevoke: (w) => revoke.mutate(w.id),
                  }}
                />
              ))}
            </ul>
          )}
      </div>

      {failure && (
        <p role="alert" className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-sm">
          {failure.message || "Could not change the waiver."}
        </p>
      )}

      <DecideDialog
        slug={currentSlug}
        waiver={deciding?.waiver ?? null}
        decision={deciding?.decision ?? "approve"}
        onClose={() => setDeciding(null)}
      />
    </section>
  );
}
