import { useProjectRole, useProjectWatcher, useUpdateProjectWatcher } from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
import { RelativeTime } from "@/components/RelativeTime";
import { SelectField } from "@/components/SelectField";
import { SettingLine } from "@/components/SettingLine";
import { SkeletonLines } from "@/components/SkeletonLines";
import { StatusPill } from "@/components/StatusPill";
import { Switch } from "@/components/Switch";
import { Button } from "@/components/ui/button";
import { EMPTY_VALUE, formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useParams } from "react-router-dom";
import {
  durationLabel,
  intervalLabel,
  intervalOptions,
  STATUS,
} from "./project-watcher/watcherCopy";

/**
 * The CVE watcher for one project: whether it checks this project's packages against new CVEs
 * between scans, how often, when it last ran, and whether it is healthy. A project admin changes the
 * switch and the interval; everyone in the project can read it.
 */
export function ProjectWatcher() {
  const { slug } = useParams<{ slug: string; }>();
  const currentSlug = slug ?? "";
  const { data: watcher, isLoading, isError, refetch } = useProjectWatcher(
    currentSlug,
  );
  const { isAdmin } = useProjectRole(currentSlug);
  const update = useUpdateProjectWatcher(currentSlug);

  if (isLoading) return <SkeletonLines label="Loading the watcher" />;
  if (isError || !watcher) {
    return <ErrorState title="Could not load the watcher." onRetry={() => void refetch()} />;
  }

  const status = STATUS[watcher.status];
  const atDefault = watcher.interval_seconds === watcher.default_interval_seconds;

  return (
    <section aria-labelledby="watcher-heading" className="grid gap-6">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 id="watcher-heading" className="text-lg font-semibold">Watcher</h2>
          <p className="text-muted-foreground mt-0.5 text-sm">
            Checks your packages against new CVEs between scans.
          </p>
        </div>
        <StatusPill tone={status.tone}>{status.label}</StatusPill>
      </div>

      <div className="border-foreground border-t-2">
        <SettingLine
          title="Watch this project"
          help="Polls on its own schedule and files new findings that match your packages."
        >
          {isAdmin
            ? (
              <Switch
                aria-label="Watch this project"
                checked={watcher.enabled}
                disabled={update.isPending}
                onCheckedChange={(enabled) => update.mutate({ enabled })}
              />
            )
            : <b className="text-[0.9375rem]">{watcher.enabled ? "On" : "Off"}</b>}
        </SettingLine>

        <SettingLine
          title="How often"
          help={`Between ${durationLabel(watcher.min_interval_seconds)} and ${
            durationLabel(watcher.max_interval_seconds)
          }. The server polls no faster than ${durationLabel(watcher.min_interval_seconds)}.`}
        >
          {isAdmin
            ? (
              <>
                <SelectField
                  aria-label="Interval"
                  size="sm"
                  className="w-40"
                  value={String(watcher.interval_seconds)}
                  disabled={update.isPending}
                  options={intervalOptions(watcher)}
                  onValueChange={(next) => update.mutate({ interval_seconds: Number(next) })}
                />
                {!atDefault && (
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={update.isPending}
                    onClick={() => update.mutate({ interval_seconds: null })}
                  >
                    Reset to {intervalLabel(watcher.default_interval_seconds)}
                  </Button>
                )}
              </>
            )
            : <b className="text-[0.9375rem]">{intervalLabel(watcher.interval_seconds)}</b>}
        </SettingLine>

        <SettingLine
          title="Last poll"
          help={watcher.last_poll_at
            ? (
              <>
                <RelativeTime iso={watcher.last_poll_at} />.
              </>
            )
            : "No poll has finished yet."}
        >
          <span className="font-mono text-[0.8125rem]">
            {watcher.last_poll_at ? formatDateTime(watcher.last_poll_at) : EMPTY_VALUE}
          </span>
        </SettingLine>
      </div>

      {update.isError && (
        <p role="alert" className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-sm">
          {update.error.message || "Could not save the watcher settings."}
        </p>
      )}

      {status.notice && (
        <p
          role={status.problem ? "alert" : "status"}
          className={cn(
            "rounded-md px-3.5 py-3 text-[0.8125rem]",
            status.problem
              ? "bg-sev-critical-bg text-foreground border-sev-critical border-l-4"
              : "bg-muted text-muted-foreground",
          )}
        >
          {status.notice}
        </p>
      )}
    </section>
  );
}
