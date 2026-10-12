interface MutationOutcome {
  readonly isError: boolean;
  readonly error: Error | null;
  /** When the mutation last ran; zero when it never has. */
  readonly submittedAt: number;
}

/**
 * The error to show for a group of related actions on one screen: the last action's, and only if it
 * failed. Reading `a.error ?? b.error` instead leaves an old failure on screen after a different
 * action has since succeeded.
 */
export function latestFailure(...mutations: readonly MutationOutcome[]): Error | null {
  let latest: MutationOutcome | null = null;
  for (const m of mutations) {
    if (latest === null || m.submittedAt > latest.submittedAt) latest = m;
  }
  return latest?.isError ? latest.error : null;
}
