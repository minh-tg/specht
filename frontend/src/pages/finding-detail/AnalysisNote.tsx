import { formatDate } from "@/lib/format";

/**
 * The reason and expiry recorded with the finding's current analysis state, as one plain line
 * under "Currently:". Nothing renders when the state carries neither.
 */
export function AnalysisNote(
  { reason, expiresAt }: { readonly reason?: string; readonly expiresAt?: string; },
) {
  if (!reason && !expiresAt) return null;
  return (
    <p className="text-muted-foreground -mt-3 mb-4 text-meta">
      {reason && <>Reason: {reason}</>}
      {reason && expiresAt && " · "}
      {expiresAt && <>Expires {formatDate(expiresAt)}</>}
    </p>
  );
}
