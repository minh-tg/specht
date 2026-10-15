import { useVerifyFinding } from "@/api/findingActions";
import { useProjectRole } from "@/api/hooks";
import { Button } from "@/components/ui/button";
import { playCue } from "@/lib/sound";
import { useParams } from "react-router-dom";
import { OutcomeRegions } from "./OutcomeRegions";

function verdictText(outcome: string): string | null {
  if (outcome === "still_present") return "Still present in the latest complete scan.";
  if (outcome === "verified_fixed") return "Verified fixed. The finding is now marked fixed.";
  if (outcome === "inconclusive") {
    return "Not conclusive: the newest scan cannot vouch for completeness.";
  }
  return null;
}

/** Asks the server whether a finding is still present in the latest complete scan. */
export function VerifyFixSection({
  findingId,
  projectSlug,
}: {
  readonly findingId: string;
  readonly projectSlug?: string;
}) {
  const params = useParams<{ slug: string; }>();
  const slug = projectSlug ?? params.slug ?? "";
  const { canTriage } = useProjectRole(slug);
  const verifyMutation = useVerifyFinding(findingId);
  const verdict = verifyMutation.data;
  const message = verdict ? verdictText(verdict.outcome) : null;
  const detail = verdict?.outcome === "inconclusive" && verdict.detail ? verdict.detail : null;

  if (!canTriage) return null;

  return (
    <div className="mt-4">
      <Button
        variant="outline"
        onClick={() =>
          verifyMutation.mutate(undefined, {
            // Only a confirmed fix is good news worth a sound; the other verdicts stay quiet.
            onSuccess: (data) => {
              if (data.outcome === "verified_fixed") playCue("pass");
            },
          })}
        disabled={verifyMutation.isPending}
      >
        {verifyMutation.isPending && (
          <span
            aria-hidden="true"
            className="mr-2 inline-block h-3 w-3 animate-spin rounded-full border-2 border-current border-t-transparent"
          />
        )}
        {verifyMutation.isPending ? "Checking..." : "Check if it is fixed"}
      </Button>
      <p role="status" className="text-muted-foreground mt-2 text-sm">
        {message}
        {detail && <span className="block">{detail}</span>}
      </p>
      <OutcomeRegions
        label="Fix check"
        error={verifyMutation.isError ? verifyMutation.error.message : null}
      />
    </div>
  );
}
