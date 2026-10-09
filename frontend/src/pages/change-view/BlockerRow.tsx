import { useFinding } from "@/api/hooks";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { Skeleton } from "@/components/ui/skeleton";
import { fixAction, locationLine } from "@/pages/change-view/resolve";
import type { Finding } from "@/types/api";
import { type ReactNode } from "react";
import { Link } from "react-router-dom";

const LINK_CLASS = "text-action underline underline-offset-2 hover:no-underline";
const ROW_CLASS = "border-b px-3 py-3 last:border-b-0";

export interface BlockerRowProps {
  slug: string;
  findingId: string;
  finding?: Finding;
  isLoading: boolean;
  isError: boolean;
  onRetry: () => void;
}

function Row({ children, busy }: { children: ReactNode; busy?: boolean; }) {
  return (
    <li className={ROW_CLASS} aria-busy={busy ? "true" : undefined}>
      {children}
    </li>
  );
}

/**
 * One blocking finding, rendered only from data the caller already has. Kept
 * separate from the fetching wrapper so a page that loads many findings at once
 * can hand each row its query result without a hook per row.
 */
export function BlockerRowView(
  { slug, findingId, finding, isLoading, isError, onRetry }: BlockerRowProps,
) {
  if (isLoading) {
    return (
      <Row busy>
        <Skeleton className="h-4 w-1/2 rounded" />
        <Skeleton className="mt-2 h-3 w-2/3 rounded" />
      </Row>
    );
  }

  if (isError || !finding) {
    return (
      <Row>
        <p className="text-sm">
          Could not load this finding{" "}
          <span className="text-muted-foreground font-mono text-xs">{findingId}</span>
        </p>
        <button type="button" className={`${LINK_CLASS} mt-1 text-sm`} onClick={onRetry}>
          Retry
        </button>
      </Row>
    );
  }

  const target = `/${slug}/findings/${findingId}`;
  const location = locationLine(finding.location);
  const rawAction = fixAction(finding);
  // Scanner text is shown as written, except that a suggestion such as "review src/db.ts" starts
  // the sentence with a capital.
  const action = rawAction ? rawAction.charAt(0).toUpperCase() + rawAction.slice(1) : null;

  return (
    <Row>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.current_severity} />
        <Link to={target} className="font-medium hover:underline">
          {finding.current_title}
        </Link>
        <Link to={target} className={`${LINK_CLASS} ml-auto text-sm`}>
          Decide
        </Link>
      </div>
      {location && <p className="text-muted-foreground mt-1 font-mono text-xs">{location}</p>}
      <div className="mt-2 rounded-md border px-3 py-2">
        <p className="text-muted-foreground text-xs font-semibold tracking-wide uppercase">
          Do this
        </p>
        {action
          ? <p className="text-sm font-semibold">{action}</p>
          : (
            <p className="text-sm">
              <span className="font-semibold">No automated fix is known.</span>{" "}
              Open it to decide what to do.
            </p>
          )}
      </div>
    </Row>
  );
}

/** A blocking finding that fetches itself; used where rows are revealed lazily. */
export function BlockerRow({ slug, findingId }: { slug: string; findingId: string; }) {
  const query = useFinding(findingId);
  return (
    <BlockerRowView
      slug={slug}
      findingId={findingId}
      finding={query.data}
      isLoading={query.isPending}
      isError={query.isError}
      onRetry={() => void query.refetch()}
    />
  );
}
