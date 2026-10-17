import { formatDate } from "@/lib/format";

/**
 * Says when the scan payload behind a finding was cleared by the retention sweep. Nothing renders
 * while the payload is kept. The date comes from `expiresAt`; without one (no retention window is
 * set now) the sentence drops the date instead of guessing it.
 */
export function RawEvidenceNote(
  { expired, expiresAt }: { readonly expired?: boolean; readonly expiresAt?: string | null; },
) {
  if (!expired) return null;
  return (
    <p className="text-muted-foreground mt-3 text-xs">
      {expiresAt
        ? <>Raw evidence expired on {formatDate(expiresAt)} under the retention policy.</>
        : <>Raw evidence expired under the retention policy.</>}
    </p>
  );
}
