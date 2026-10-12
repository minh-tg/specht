import { useAdminStatus } from "@/api/admin";
import { useMe } from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
import { SkeletonLines } from "@/components/SkeletonLines";
import { formatDate } from "@/lib/format";
import { PeopleSection } from "./admin/PeopleSection";
import { RetentionSection } from "./admin/RetentionSection";
import { WatcherHealthSection } from "./admin/WatcherHealthSection";

function Stat({ value, label }: { readonly value: number; readonly label: string; }) {
  return (
    <div className="border-border border-b py-3.5 pr-3.5">
      <div className="text-3xl leading-none font-bold tabular-nums">
        {value.toLocaleString("en-US")}
      </div>
      <div className="text-muted-foreground mt-1.5 text-[0.8125rem]">{label}</div>
    </div>
  );
}

/** The whole server: its totals, its people, the CVE watcher and old reports. Global admins only. */
export function Admin() {
  const me = useMe();
  const isAdmin = me.data?.role === "admin";
  const status = useAdminStatus(isAdmin);

  if (me.isLoading) {
    return <SkeletonLines label="Loading" className="mx-auto max-w-5xl px-4 py-8" />;
  }
  if (!isAdmin) {
    return (
      <div className="mx-auto max-w-5xl px-4 py-8">
        <h1 className="text-2xl font-bold">Admin</h1>
        <p className="text-muted-foreground mt-2 text-sm">Only global admins can see this page.</p>
      </div>
    );
  }

  return (
    <div className="mx-auto grid max-w-5xl gap-9 px-4 py-8">
      <div>
        <h1 className="text-2xl font-bold">Admin</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          The whole server. Only global admins see this.
        </p>
      </div>

      {status.isLoading
        ? <SkeletonLines label="Loading totals" />
        : status.isError || !status.data
        ? <ErrorState title="Could not load the totals." onRetry={() => void status.refetch()} />
        : (
          <div>
            <div className="border-foreground grid grid-cols-[repeat(auto-fit,minmax(9.5rem,1fr))] border-t-2">
              <Stat
                value={status.data.projects}
                label={status.data.projects === 1 ? "project" : "projects"}
              />
              <Stat
                value={status.data.users}
                label={status.data.users === 1 ? "person" : "people"}
              />
              <Stat value={status.data.open_findings} label="open findings" />
              <Stat
                value={status.data.reports}
                label={status.data.reports === 1 ? "report" : "reports"}
              />
            </div>
            {status.data.oldest_settled_report_at && (
              <p className="text-muted-foreground mt-2 text-[0.8125rem]">
                Oldest finished report: {formatDate(status.data.oldest_settled_report_at)}.
              </p>
            )}
          </div>
        )}

      <PeopleSection />
      <WatcherHealthSection />
      <RetentionSection />
    </div>
  );
}
