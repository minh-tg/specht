import { useProjectRole, useTriageFinding } from "@/api/hooks";
import { type AnalysisState, gateEffectLabel, isAnalysisState } from "@/lib/enums";
import { GLOSSARY } from "@/lib/glossary";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { toExpiryTimestamp } from "./format";
import { TRIAGE_GLOSSARY, TRIAGE_OPTIONS } from "./options";
import { OutcomeRegions } from "./OutcomeRegions";

/** Triage controls and status feedback for one finding. */
export function TriageSection({
  findingId,
  projectSlug,
}: {
  readonly findingId: string;
  readonly projectSlug?: string;
}) {
  const params = useParams<{ slug: string; }>();
  const slug = projectSlug ?? params.slug ?? "";
  const { canTriage, isLoading: roleLoading } = useProjectRole(slug);
  const triageMutation = useTriageFinding();
  const [selectedState, setSelectedState] = useState<AnalysisState | "">("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");

  const selectedOption = TRIAGE_OPTIONS.find((o) => o.value === selectedState);
  const hintKey = selectedState ? TRIAGE_GLOSSARY[selectedState] : undefined;
  const hint = hintKey ? GLOSSARY[hintKey].short : null;

  async function handleTriage() {
    if (!selectedState || !canTriage) return;
    try {
      await triageMutation.mutateAsync({
        findingId,
        analysisState: selectedState,
        reason: selectedOption?.requiresReason ? reason : undefined,
        analysisExpiresAt: selectedOption?.requiresExpiry
          ? toExpiryTimestamp(expiresAt)
          : undefined,
      });
      setSelectedState("");
      setReason("");
      setExpiresAt("");
    } catch {}
  }

  const triageReady = canTriage
    && selectedState !== ""
    && (!selectedOption?.requiresExpiry || expiresAt !== "")
    && (!selectedOption?.requiresReason || reason.trim() !== "");

  return (
    <section aria-labelledby="triage-heading">
      <h3 id="triage-heading" className="mb-3 text-sm font-medium">Triage</h3>
      <div className="flex flex-wrap gap-2">
        <select
          aria-label="Triage action"
          aria-describedby={hint ? "triage-hint" : undefined}
          disabled={!canTriage}
          className="border-input bg-background rounded-md border px-3 py-1.5 text-sm disabled:opacity-50"
          value={selectedState}
          onChange={(e) => {
            const value = e.target.value;
            setSelectedState(isAnalysisState(value) ? value : "");
            setReason("");
            setExpiresAt("");
          }}
        >
          <option value="">Select action...</option>
          {TRIAGE_OPTIONS.map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
        {selectedOption?.requiresReason && (
          <input
            className="border-input bg-background min-w-[200px] rounded-md border px-3 py-1.5 text-sm disabled:opacity-50"
            aria-label="Reason"
            placeholder="Reason"
            disabled={!canTriage}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        )}
        {selectedOption?.requiresExpiry && (
          <input
            aria-label="Expiry date"
            type="date"
            disabled={!canTriage}
            className="border-input bg-background rounded-md border px-3 py-1.5 text-sm disabled:opacity-50"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
          />
        )}
        <button
          onClick={handleTriage}
          disabled={!triageReady || triageMutation.isPending}
          title={!canTriage ? "Requires Project Manager role" : undefined}
          className="bg-primary text-primary-foreground hover:bg-primary/90 rounded-md px-4 py-1.5 text-sm font-medium disabled:opacity-50"
        >
          {triageMutation.isPending ? "Saving..." : "Apply"}
        </button>
      </div>
      {!canTriage && !roleLoading && (
        <p className="text-muted-foreground mt-2 text-xs">
          Requires Project Manager role to triage findings or request waivers.
        </p>
      )}
      {hint && <p id="triage-hint" className="text-muted-foreground mt-2 text-sm">{hint}</p>}
      <OutcomeRegions
        label="Triage result"
        error={triageMutation.isError ? triageMutation.error.message : null}
        success={triageMutation.isSuccess
          ? `Triage saved (effect: ${
            gateEffectLabel(triageMutation.data.gate_effect) ?? "Unknown"
          })`
          : null}
      />
    </section>
  );
}
