import { usePolicy, useSetPolicyOverrides } from "@/api/hooks";
import { INLINE_LINK } from "@/components/inlineLink";
import { Link } from "react-router-dom";
import { gateModeHelp, overridesOf } from "../project-policy/policyCopy";

const MODES = [
  {
    value: "changes_only",
    label: "Block new findings only",
    note: "Start here on a repository that already has findings.",
  },
  { value: "report_only", label: "Report only", note: "Start here to look around first." },
  { value: "enforce", label: "Block", note: "Start here on a repository with no findings yet." },
] as const;

/**
 * How strict the gate starts. The pipeline below also scans the default branch, so on a repository
 * with existing findings the default would turn CI red on the first run. Only a project admin can
 * change it; everyone else sees what applies.
 */
export function GateModeStep(
  { slug, canEdit }: { readonly slug: string; readonly canEdit: boolean; },
) {
  const { data: policy } = usePolicy(slug);
  const setOverrides = useSetPolicyOverrides(slug);
  const current = policy?.gate_mode ?? "enforce";

  return (
    <fieldset className="mt-3 grid gap-2" disabled={!canEdit || !policy || setOverrides.isPending}>
      <legend className="sr-only">When findings block</legend>
      {MODES.map((mode) => (
        <label key={mode.value} className="flex items-start gap-2 text-body">
          <input
            type="radio"
            name="gate-mode"
            className="mt-1"
            checked={current === mode.value}
            onChange={() => {
              if (!policy) return;
              setOverrides.mutate({ ...overridesOf(policy), gate_mode: mode.value });
            }}
          />
          <span>
            <span className="font-medium">{mode.label}.</span>{" "}
            <span className="text-muted-foreground">{mode.note}</span>
          </span>
        </label>
      ))}
      <p className="text-muted-foreground text-meta">
        {gateModeHelp(current)} You can change this any time in{" "}
        <Link to={`/${slug}/policy`} className={INLINE_LINK}>Policy</Link>.
      </p>
      {setOverrides.isError && (
        <p role="alert" className="text-destructive text-meta">
          Could not save this. Try again, or change it in Policy.
        </p>
      )}
    </fieldset>
  );
}
