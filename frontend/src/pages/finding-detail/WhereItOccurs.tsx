import { DetailList, type DetailRow } from "@/components/DetailList";
import { Section } from "@/components/Section";
import type { Finding } from "@/types/api";
import { locationLineRange, locationSubjectLabel } from "./format";
import { RawEvidenceNote } from "./RawEvidenceNote";

/** The file, resource or URL the scanner observed the finding at. */
export function WhereItOccurs({ finding }: { readonly finding: Finding; }) {
  const rows: DetailRow[] = [];
  const location = finding.location;
  if (location && (location.file || location.resource || location.summary)) {
    const subjectText = (location.file ?? location.resource ?? location.summary ?? "")
      + locationLineRange(location);
    rows.push({
      label: locationSubjectLabel(finding.finding_kind),
      value: <span className="select-all">{subjectText}</span>,
      code: true,
    });
    // The summary often repeats the subject ("src/repository.go:88"), so it earns a row only
    // when it says something else.
    if (
      location.summary && (location.file || location.resource) && location.summary !== subjectText
    ) {
      rows.push({ label: "Detail", value: location.summary });
    }
  }

  return (
    <Section title="Where it occurs">
      {rows.length > 0
        ? <DetailList rows={rows} />
        : (
          <p className="text-muted-foreground text-body">
            No location reported. The scanner gave no file, resource, or URL.
          </p>
        )}
      <RawEvidenceNote expired={finding.raw_data_expired} expiresAt={finding.raw_data_expires_at} />
    </Section>
  );
}
