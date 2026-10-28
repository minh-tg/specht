import { CopyButton } from "@/components/CopyButton";
import { SeverityBadge } from "@/components/ui/severity-badge";
import { groupMetrics, scoreMismatch } from "@/lib/cvssMetrics";
import type { CveCvss } from "@/types/cve";
import { useId } from "react";
import { provenanceLabel, reporterOf } from "./cveText";

/** The band as a word. The tint and bars only repeat it. */
export function BandWord({ severity }: { readonly severity: CveCvss["severity"]; }) {
  if (severity === null) return <span className="text-muted-foreground text-xs">Not rated</span>;
  if (severity === "none") return <span className="text-sev-none-fg text-xs">None</span>;
  return <SeverityBadge severity={severity} plain />;
}

/** One CVSS vector: its score and band, where it came from, the vector itself and every metric. */
export function CvssCard({ cvss }: { readonly cvss: CveCvss; }) {
  const headingId = useId();
  const score = cvss.base_score ?? cvss.reported_score;
  const mismatch = scoreMismatch(cvss, reporterOf(cvss.provenance));
  const groups = groupMetrics(cvss.version, cvss.metrics);
  const scoredBy = cvss.provenance.detail;

  return (
    <article aria-labelledby={headingId} className="border-border rounded-lg border p-4">
      <h4 id={headingId} className="text-body font-semibold">CVSS {cvss.version}</h4>
      <p className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
        <span>
          <span className="text-muted-foreground">
            {cvss.base_score === null ? "Reported score" : "Base score"}
          </span>{" "}
          <span className="font-mono text-section font-semibold tabular-nums">
            {score === null ? "None" : score.toFixed(1)}
          </span>
        </span>
        <BandWord severity={cvss.severity} />
      </p>
      <p className="text-muted-foreground mt-1 text-xs">
        {provenanceLabel(cvss.provenance)}
        {scoredBy ? `, scored by ${scoredBy}` : ""}
      </p>
      {mismatch && <p className="mt-2 text-sm">{mismatch}</p>}
      <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1">
        <code
          aria-label={`CVSS ${cvss.version} vector`}
          className="bg-muted min-w-0 rounded px-2 py-1 font-mono text-xs break-all"
        >
          {cvss.vector}
        </code>
        <CopyButton text={cvss.vector} label={`CVSS ${cvss.version} vector`} />
      </div>
      {groups.length > 0 && (
        <div className="mt-4 grid gap-x-8 gap-y-4 sm:grid-cols-2">
          {groups.map((group) => (
            <section key={group.title} aria-label={`${group.title} metrics`}>
              <h5 className="text-muted-foreground mb-1.5 text-xs font-medium">{group.title}</h5>
              <dl className="grid grid-cols-[minmax(0,1fr)_minmax(0,1fr)] gap-x-4 gap-y-1.5 text-sm">
                {group.rows.map((row) => (
                  <div key={row.key} className="contents">
                    <dt className={row.known ? "" : "font-mono"}>{row.name}</dt>
                    <dd className={row.known ? "font-medium" : "font-mono"}>{row.value}</dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
      )}
    </article>
  );
}
