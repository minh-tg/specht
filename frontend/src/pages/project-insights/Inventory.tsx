import { useArtifacts, useEnvironments, useTargets } from "@/api/inventory";
import { ErrorState } from "@/components/ErrorState";
import { SkeletonLines } from "@/components/SkeletonLines";
import { buttonVariants } from "@/components/ui/button-variants";
import { EMPTY_VALUE } from "@/lib/format";
import type { Artifact, Environment, Target } from "@/types/api";
import { type ReactNode, useState } from "react";

const ROW_CAP = 20;

/** The part of a query result the list reads. */
interface ListQuery<T> {
  readonly data: T[] | null | undefined;
  readonly isLoading: boolean;
  readonly isError: boolean;
  readonly refetch: () => unknown;
}

/** Servers send a list that is empty as `null`; anything that is not an array counts as empty. */
function asList<T>(value: T[] | null | undefined): T[] {
  return Array.isArray(value) ? value : [];
}

/** The first twelve characters of a digest, with any `sha256:` prefix left off. */
function shortDigest(digest: string): string {
  return digest.replace(/^sha256:/, "").slice(0, 12);
}

function InventoryList<T>({
  title,
  noun,
  emptyText,
  query,
  rowKey,
  renderRow,
}: {
  readonly title: string;
  readonly noun: string;
  readonly emptyText: string;
  readonly query: ListQuery<T>;
  readonly rowKey: (item: T) => string;
  readonly renderRow: (item: T) => ReactNode;
}) {
  const [showAll, setShowAll] = useState(false);

  if (query.isLoading) return <SkeletonLines label={`Loading ${noun}`} lines={2} />;
  if (query.isError) {
    return <ErrorState title={`Could not load ${noun}.`} onRetry={() => void query.refetch()} />;
  }

  const items = asList(query.data);
  const shown = showAll ? items : items.slice(0, ROW_CAP);

  return (
    <div className="min-w-0">
      <h4 className="flex items-baseline gap-2 text-sm font-semibold">
        {title}
        <span className="text-muted-foreground font-normal tabular-nums">{items.length}</span>
      </h4>
      {items.length === 0
        ? <p className="text-muted-foreground mt-2 text-[0.8125rem]">{emptyText}</p>
        : (
          <>
            <ul
              aria-label={title}
              className="border-foreground m-0 mt-2 list-none border-t-2 p-0"
            >
              {shown.map((item) => (
                <li key={rowKey(item)} className="border-border border-b py-2.5 text-sm">
                  {renderRow(item)}
                </li>
              ))}
            </ul>
            {!showAll && items.length > ROW_CAP && (
              <button
                type="button"
                onClick={() => setShowAll(true)}
                className={`${buttonVariants({ variant: "outline", size: "sm" })} mt-2.5`}
              >
                Show all {items.length}
              </button>
            )}
          </>
        )}
    </div>
  );
}

function Meta({ children }: { readonly children: ReactNode; }) {
  return <p className="text-muted-foreground mt-0.5 text-[0.8125rem]">{children}</p>;
}

function EnvironmentRow({ environment }: { readonly environment: Environment; }) {
  return (
    <>
      <p className="font-semibold">{environment.name}</p>
      <Meta>
        <span>{environment.tier || EMPTY_VALUE}</span>
        <span>{" · "}</span>
        <span>{environment.internet_facing ? "Internet facing" : "Internal"}</span>
        <span>{" · "}</span>
        <span>{environment.data_sensitivity || EMPTY_VALUE}</span>
      </Meta>
    </>
  );
}

function TargetRow({ target }: { readonly target: Target; }) {
  return (
    <>
      <p className="font-semibold">{target.name}</p>
      <Meta>{target.kind || EMPTY_VALUE}</Meta>
      {target.locator && (
        <p className="text-muted-foreground mt-1 text-xs break-all">{target.locator}</p>
      )}
    </>
  );
}

function ArtifactRow({ artifact }: { readonly artifact: Artifact; }) {
  return (
    <>
      <p className="font-semibold">
        {artifact.name}
        {artifact.version && (
          <span className="text-muted-foreground font-normal">{` ${artifact.version}`}</span>
        )}
      </p>
      <Meta>
        <span>{artifact.artifact_type || EMPTY_VALUE}</span>
        <span>{" · "}</span>
        {artifact.digest
          ? (
            <code title={artifact.digest} className="font-mono text-xs">
              {shortDigest(artifact.digest)}
            </code>
          )
          : <span>{EMPTY_VALUE}</span>}
      </Meta>
    </>
  );
}

/**
 * What the project's scans described: the environments the code runs in, the subjects scans ran
 * against, and the build artifacts they saw. Read-only; each list loads and fails on its own.
 */
export function Inventory({ slug }: { readonly slug: string; }) {
  const environments = useEnvironments(slug);
  const targets = useTargets(slug);
  const artifacts = useArtifacts(slug);

  return (
    <section aria-labelledby="inventory-heading" className="min-w-0">
      <h3 id="inventory-heading" className="text-base font-semibold">Where it runs</h3>
      <p className="text-muted-foreground mt-0.5 mb-4 text-[0.8125rem]">
        What the project's scans said about where the code runs and what was scanned.
      </p>
      <div className="grid gap-x-10 gap-y-8 md:grid-cols-2">
        <InventoryList
          title="Environments"
          noun="environments"
          emptyText="No environments recorded yet. Scans that send context fill this in."
          query={environments}
          rowKey={(item) => item.id}
          renderRow={(item) => <EnvironmentRow environment={item} />}
        />
        <InventoryList
          title="Scan targets"
          noun="scan targets"
          emptyText="No scan targets recorded yet. Scans fill this in."
          query={targets}
          rowKey={(item) => item.id}
          renderRow={(item) => <TargetRow target={item} />}
        />
        <div className="md:col-span-2">
          <InventoryList
            title="Artifacts"
            noun="artifacts"
            emptyText="No artifacts recorded yet. Scans that send context fill this in."
            query={artifacts}
            rowKey={(item) => item.id}
            renderRow={(item) => <ArtifactRow artifact={item} />}
          />
        </div>
      </div>
    </section>
  );
}
