import { APIError } from "@/api/client";
import { useFindingCve } from "@/api/hooks";
import { INLINE_LINK } from "@/components/inlineLink";
import { Section } from "@/components/Section";
import { formatDateTime } from "@/lib/format";
import type { CveDetail, CveProvenance } from "@/types/cve";
import { type ReactNode, useId, useState } from "react";
import { BandWord, CvssCard } from "./CveDetailsCvss";
import {
  cweLink,
  formatDay,
  formatPercent,
  highestCvss,
  provenanceLabel,
  providerName,
  providerStatusText,
} from "./cveText";

const SECTION = "border-border mt-8 border-t pt-5";

/** Short names for the summary line, where a full provenance sentence would not fit. */
function sourceWord(p: CveProvenance): string {
  switch (p.kind) {
    case "scan_report":
      return "scan report";
    case "watcher":
      return "CVE watcher";
    case "provider":
      return providerName(p.provider);
    default:
      return "unknown source";
  }
}

function Summary({ detail }: { readonly detail: CveDetail; }) {
  const best = highestCvss(detail.cvss);
  const score = best ? best.base_score ?? best.reported_score : null;
  return (
    <p className="text-muted-foreground flex flex-wrap items-center gap-x-2 gap-y-1 text-body">
      <span className="font-mono">{detail.cve_id}</span>
      {best && score !== null
        ? (
          <>
            <span aria-hidden="true">·</span>
            <span className="inline-flex items-center gap-1.5">
              CVSS{" "}
              <span className="text-foreground font-mono tabular-nums">{score.toFixed(1)}</span>
              <BandWord severity={best.severity} />
              <span>(v{best.version}, {sourceWord(best.provenance)})</span>
            </span>
          </>
        )
        : (
          <>
            <span aria-hidden="true">·</span>
            <span>No CVSS vector known</span>
          </>
        )}
      {detail.epss && (
        <>
          <span aria-hidden="true">·</span>
          <span>EPSS {formatPercent(detail.epss.probability)}</span>
        </>
      )}
      {detail.kev?.listed && (
        <>
          <span aria-hidden="true">·</span>
          <span className="text-sev-critical-fg font-medium">Known exploited</span>
        </>
      )}
    </p>
  );
}

function Fact({ label, children, source }: {
  readonly label: string;
  readonly children: ReactNode;
  readonly source?: string;
}) {
  return (
    <div className="contents">
      <dt className="text-muted-foreground">{label}</dt>
      <dd>
        <span className="font-medium">{children}</span>
        {source && <span className="text-muted-foreground block text-meta">{source}</span>}
      </dd>
    </div>
  );
}

function ExternalLink(
  { href, children }: { readonly href: string; readonly children: ReactNode; },
) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className={`${INLINE_LINK} break-all`}>
      {children}
      <span className="sr-only">(opens in a new tab)</span>
    </a>
  );
}

/** Items that share a source are listed once under it, so twenty links do not repeat one sentence. */
function bySource<T extends { provenance: CveProvenance; }>(items: readonly T[]) {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const label = provenanceLabel(item.provenance);
    groups.set(label, [...(groups.get(label) ?? []), item]);
  }
  return [...groups.entries()];
}

function Exploitation({ detail }: { readonly detail: CveDetail; }) {
  const { epss, kev } = detail;
  return (
    <dl className="grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-x-4 gap-y-3 text-body">
      {epss
        ? (
          <Fact
            label="EPSS"
            source={`${provenanceLabel(epss.provenance)}${
              epss.date ? `, scored ${formatDay(epss.date)}` : ""
            }`}
          >
            {formatPercent(epss.probability)} chance of exploitation in the next 30 days
            {epss.percentile !== null && <>, percentile {formatPercent(epss.percentile)}</>}
          </Fact>
        )
        : <Fact label="EPSS">No score available</Fact>}
      {kev?.listed
        ? (
          <Fact label="Known exploited" source={provenanceLabel(kev.provenance)}>
            <span className="text-sev-critical-fg">Listed in the CISA KEV catalog</span>
            {kev.date_added && <>, added {formatDay(kev.date_added)}</>}
            {kev.due_date && <>, remediation due {formatDay(kev.due_date)}</>}
            {kev.known_ransomware_use && <>, ransomware use: {kev.known_ransomware_use}</>}
          </Fact>
        )
        : <Fact label="Known exploited">Not listed in the KEV data this server holds</Fact>}
    </dl>
  );
}

function Weaknesses({ detail }: { readonly detail: CveDetail; }) {
  if (detail.cwes.length === 0) {
    return <p className="text-muted-foreground text-body">No CWE identifiers are known.</p>;
  }
  return (
    <div className="space-y-2 text-body">
      {bySource(detail.cwes).map(([source, cwes]) => (
        <div key={source}>
          <p className="text-muted-foreground text-meta">{source}</p>
          <ul className="flex flex-wrap gap-x-4 gap-y-1">
            {cwes.map((cwe) => {
              const href = cweLink(cwe.id);
              return (
                <li key={cwe.id} className="font-mono">
                  {href ? <ExternalLink href={href}>{cwe.id}</ExternalLink> : cwe.id}
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </div>
  );
}

function References({ detail }: { readonly detail: CveDetail; }) {
  // The server sends https links only; a link of any other scheme is dropped here as well.
  const safe = detail.references.filter((ref) => ref.url.startsWith("https://"));
  if (safe.length === 0) return null;
  return (
    <div className={SECTION}>
      <h3 className="mb-3 text-body font-semibold">References</h3>
      <div className="space-y-3 text-body">
        {bySource(safe).map(([source, refs]) => (
          <div key={source}>
            <p className="text-muted-foreground text-meta">{source}</p>
            <ul className="mt-1 space-y-1">
              {refs.map((ref) => (
                <li key={ref.url} className="text-meta">
                  <ExternalLink href={ref.url}>{ref.url}</ExternalLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}

function Providers({ detail }: { readonly detail: CveDetail; }) {
  if (detail.providers.every((p) => p.status === "disabled")) {
    return (
      <p className="text-muted-foreground text-meta">
        No external provider is configured on this server, so only the scan report and the EPSS and
        KEV feeds were used.
      </p>
    );
  }
  return (
    <p className="text-muted-foreground text-meta">
      External providers: {detail.providers.map((p, index) => (
        <span key={p.name}>
          {index > 0 && "; "}
          {providerName(p.name)} {providerStatusText(p.status)}
          {p.status === "found" && p.fetched_at && <>, fetched {formatDateTime(p.fetched_at)}</>}
        </span>
      ))}
      .
    </p>
  );
}

function Breakdown({ detail, id }: { readonly detail: CveDetail; readonly id: string; }) {
  const dates = [
    { label: "Published", value: detail.published_at },
    { label: "Last modified", value: detail.modified_at },
  ].filter((d) => d.value);
  return (
    <div id={id} className="mt-4">
      {detail.pending && (
        <p className="bg-muted text-muted-foreground mb-4 rounded-md px-3.5 py-3 text-body">
          Looking up more details from external providers. This section updates when they answer.
        </p>
      )}
      <h3 className="mb-3 text-body font-semibold">CVSS scores</h3>
      {detail.cvss.length === 0
        ? (
          <p className="text-muted-foreground text-body">
            No CVSS vector is known for this CVE. The scan report carried none
            {detail.providers.some((p) => p.status === "found") ? "" : " and no provider has one"}.
          </p>
        )
        : (
          <div className="space-y-3">
            {detail.cvss.map((cvss) => (
              <CvssCard
                key={`${cvss.version}-${cvss.vector}-${cvss.provenance.kind}`}
                cvss={cvss}
              />
            ))}
          </div>
        )}

      <div className={SECTION}>
        <h3 className="mb-3 text-body font-semibold">Exploitation</h3>
        <Exploitation detail={detail} />
      </div>

      <div className={SECTION}>
        <h3 className="mb-3 text-body font-semibold">Weaknesses</h3>
        <Weaknesses detail={detail} />
      </div>

      {dates.length > 0 && (
        <div className={SECTION}>
          <h3 className="mb-3 text-body font-semibold">Dates</h3>
          <dl className="grid grid-cols-[minmax(0,10rem)_minmax(0,1fr)] gap-x-4 gap-y-3 text-body">
            {dates.map(({ label, value }) => (
              <Fact key={label} label={label} source={provenanceLabel(value!.provenance)}>
                {formatDay(value!.value)}
              </Fact>
            ))}
          </dl>
        </div>
      )}

      <References detail={detail} />

      <div className={SECTION}>
        <Providers detail={detail} />
      </div>
    </div>
  );
}

/**
 * The CVE evaluation of a finding: every CVSS version the data carries, EPSS, KEV, CWE, dates and
 * references, each saying where it came from. It stays folded to a one-line summary because the
 * page is already long and most visits do not need the metric breakdown; the disclosure button
 * opens it. A finding without a CVE shows nothing, and a failed read shows a small note, never a
 * page error.
 */
export function CveDetails({ findingId }: { readonly findingId: string; }) {
  const { data, isError, error } = useFindingCve(findingId);
  const [open, setOpen] = useState(false);
  const bodyId = useId();

  if (isError) {
    if (error instanceof APIError && error.status === 404 && error.code === "not_cve") return null;
    return (
      <Section title="CVE details" id={`${bodyId}-title`} region headingClassName="mb-1">
        <p className="text-muted-foreground text-body">CVE details are not available right now.</p>
      </Section>
    );
  }
  if (!data) return null;

  return (
    <Section title="CVE details" id={`${bodyId}-title`} region headingClassName="mb-1">
      <Summary detail={data} />
      {data.pending && !open && (
        <p className="text-muted-foreground mt-1 text-meta">Looking up more details.</p>
      )}
      <button
        type="button"
        aria-expanded={open}
        aria-controls={bodyId}
        onClick={() => setOpen((value) => !value)}
        className="text-action mt-2 rounded-sm text-body font-medium underline underline-offset-3"
      >
        {open ? "Hide the full CVE breakdown" : "Show the full CVE breakdown"}
      </button>
      {open && <Breakdown detail={data} id={bodyId} />}
    </Section>
  );
}
