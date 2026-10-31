import { useProject, useProjectRole, useTriageFinding } from "@/api/hooks";
import { DisabledReason } from "@/components/DisabledReason";
import { SelectField } from "@/components/SelectField";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { type AnalysisState, isAnalysisState } from "@/lib/enums";
import { GLOSSARY } from "@/lib/glossary";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { localDateValue, toExpiryTimestamp } from "./format";
import { TRIAGE_GLOSSARY, TRIAGE_OPTIONS } from "./options";
import { OutcomeRegions } from "./OutcomeRegions";

/** The server lets only project managers and admins record a triage decision. */
const TRIAGE_MANAGER_ONLY = "Only project managers can record a triage decision.";

/** Triage controls and status feedback for one finding. */
export function TriageSection({
  findingId,
  projectSlug,
  currentState,
}: {
  readonly findingId: string;
  readonly projectSlug?: string;
  /** The finding's state now. It names the state Undo restores in its confirmation. */
  readonly currentState?: AnalysisState;
}) {
  const params = useParams<{ slug: string; }>();
  const slug = projectSlug ?? params.slug ?? "";
  const { canTriage, isLoading: roleLoading } = useProjectRole(slug);
  const { data: project } = useProject(slug);
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
        previousState: currentState,
        expectedState: currentState,
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

  const minExpiryDate = localDateValue();
  const triageReady = canTriage
    && selectedState !== ""
    && (!selectedOption?.requiresExpiry || expiresAt >= minExpiryDate)
    && (!selectedOption?.requiresReason || reason.trim() !== "");

  return (
    <section aria-labelledby="triage-heading">
      <h3 id="triage-heading" className="mb-3 text-body font-semibold">Triage</h3>
      <div className="flex flex-wrap gap-2">
        <SelectField
          aria-label="Triage action"
          aria-describedby={hint ? "triage-hint" : undefined}
          disabled={!canTriage}
          value={selectedState}
          onValueChange={(value) => {
            setSelectedState(isAnalysisState(value) ? value : "");
            setReason("");
            setExpiresAt("");
          }}
          options={[
            { value: "", label: "Select action..." },
            ...TRIAGE_OPTIONS.map((opt) => ({ value: opt.value, label: opt.label })),
          ]}
        />
        {selectedOption?.requiresReason && (
          <Input
            className="w-auto min-w-[200px]"
            aria-label="Reason"
            placeholder="Reason"
            disabled={!canTriage}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
          />
        )}
        {selectedOption?.requiresExpiry && (
          <Input
            aria-label="Expiry date"
            type="date"
            min={minExpiryDate}
            disabled={!canTriage}
            className="w-auto"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
          />
        )}
        <DisabledReason reason={canTriage ? undefined : TRIAGE_MANAGER_ONLY}>
          <Button onClick={handleTriage} disabled={!triageReady || triageMutation.isPending}>
            {triageMutation.isPending ? "Saving..." : "Apply"}
          </Button>
        </DisabledReason>
      </div>
      {!canTriage && !roleLoading && (
        <p className="text-muted-foreground mt-2 text-meta">
          {TRIAGE_MANAGER_ONLY}
          {project?.permissions?.request_waiver === true && " You can still request a waiver."}
        </p>
      )}
      {hint && <p id="triage-hint" className="text-muted-foreground mt-2 text-body">{hint}</p>}
      <OutcomeRegions
        label="Triage result"
        error={triageMutation.isError ? triageMutation.error.message : null}
      />
    </section>
  );
}
