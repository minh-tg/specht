/**
 * Persistent live regions for a form's outcome. They are always mounted and
 * only their text changes: a live region that appears together with its text
 * is announced unreliably by screen readers.
 */
export function OutcomeRegions({ label, error, success }: {
  readonly label: string;
  readonly error: string | null;
  readonly success: string | null;
}) {
  return (
    <>
      <div role="status" aria-live="polite" aria-label={label} className="text-xs">
        {success && (
          <span className="bg-sev-success-bg text-sev-success-fg mt-2 inline-block rounded-sm px-2 py-1">
            {success}
          </span>
        )}
      </div>
      <div role="alert" aria-label={`${label} error`} className="text-destructive text-xs">
        {error && <p className="mt-2">{error}</p>}
      </div>
    </>
  );
}
