/**
 * A form's error region. It is always mounted and only its text changes: a
 * live region that appears together with its text is announced unreliably by
 * screen readers. Success is confirmed by a toast (see api/queryClient), so
 * only the state that must stay on screen lives here.
 */
export function OutcomeRegions({ label, error }: {
  readonly label: string;
  readonly error: string | null;
}) {
  return (
    <div role="alert" aria-label={`${label} error`} className="text-destructive text-xs">
      {error && <p className="mt-2">{error}</p>}
    </div>
  );
}
