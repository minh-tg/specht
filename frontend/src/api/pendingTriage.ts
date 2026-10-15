import type { AnalysisState } from "@/lib/enums";
import { useMutationState } from "@tanstack/react-query";
import { TRIAGE_MUTATION_KEY } from "./hooks";

/**
 * The state a triage of this finding is changing it to, while that request is in flight, or
 * undefined. The finding page shows it at once instead of waiting for the refetch. It is read from
 * the mutation's variables, not written into the query cache, so a refetch cannot overwrite it and
 * a refusal puts the old state back by itself.
 */
export function usePendingTriage(findingId: string): { analysisState: AnalysisState; } | undefined {
  const pending = useMutationState({
    filters: { mutationKey: TRIAGE_MUTATION_KEY, status: "pending" },
    select: (mutation) =>
      mutation.state.variables as { findingId: string; analysisState: AnalysisState; },
  });
  return pending.findLast((variables) => variables.findingId === findingId);
}
