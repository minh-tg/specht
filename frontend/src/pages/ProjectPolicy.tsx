import {
  usePolicy,
  usePolicyTemplates,
  useProjectRole,
  useSetPolicyOverrides,
  useSetPolicyTemplate,
} from "@/api/hooks";
import { ErrorState } from "@/components/ErrorState";
import { SelectField } from "@/components/SelectField";
import { SettingLine } from "@/components/SettingLine";
import { SkeletonLines } from "@/components/SkeletonLines";
import { latestFailure } from "@/lib/latestFailure";
import { InfoIcon } from "lucide-react";
import { useParams } from "react-router-dom";
import {
  overridesOf,
  type PolicyKey,
  SEVERITY_FLOOR_OPTIONS,
  WATCHER_GATE_OPTIONS,
  watcherGateHelp,
} from "./project-policy/policyCopy";
import { PolicyRow } from "./project-policy/PolicyRow";

const NO_TEMPLATE = "";

/**
 * What blocks a change in this project and where each rule comes from. Everyone in the project can
 * read it; a project admin can link a template and override single settings.
 */
export function ProjectPolicy() {
  const { slug } = useParams<{ slug: string; }>();
  const currentSlug = slug ?? "";
  const { data: policy, isLoading, isError, refetch } = usePolicy(currentSlug);
  const { isAdmin } = useProjectRole(currentSlug);
  const { data: templates } = usePolicyTemplates(isAdmin);
  const setTemplate = useSetPolicyTemplate(currentSlug);
  const setOverrides = useSetPolicyOverrides(currentSlug);

  if (isLoading) return <SkeletonLines label="Loading the policy" />;
  if (isError || !policy) {
    return <ErrorState title="Could not load the policy." onRetry={() => void refetch()} />;
  }

  const current = overridesOf(policy);
  const override = (key: PolicyKey) => (value: string) =>
    setOverrides.mutateAsync({ ...current, [key]: value });
  const clear = (key: PolicyKey) => () => {
    const { [key]: _removed, ...rest } = current;
    return setOverrides.mutateAsync(rest);
  };

  const templateName = policy.template_name ?? NO_TEMPLATE;
  const failure = latestFailure(setTemplate, setOverrides);

  return (
    <section aria-labelledby="policy-heading" className="grid gap-6">
      <div>
        <h2 id="policy-heading" className="text-lg font-semibold">Policy</h2>
        <p className="text-muted-foreground mt-0.5 text-sm">
          What blocks a change in this project, and where each rule comes from.
        </p>
      </div>

      <div className="border-foreground border-t-2">
        <SettingLine
          title="Template"
          help="A shared baseline from your platform team. Overrides below win over it."
        >
          {isAdmin
            ? (
              <SelectField
                aria-label="Template"
                size="sm"
                className="w-52"
                value={templateName}
                disabled={setTemplate.isPending}
                onValueChange={(next) => setTemplate.mutate(next)}
                options={[
                  { value: NO_TEMPLATE, label: "No template" },
                  ...(templates ?? []).map((t) => ({ value: t.name, label: t.name })),
                ]}
              />
            )
            : (
              <span className="text-[0.9375rem]">
                {policy.template_name ?? "No template"}
              </span>
            )}
          {policy.template_name && (
            <span className="text-muted-foreground text-[0.8125rem]">
              v{policy.template_version}
            </span>
          )}
        </SettingLine>

        <PolicyRow
          title="Severity floor"
          help="Findings at or above this block a change."
          value={policy.severity_floor}
          source={policy.severity_source}
          options={SEVERITY_FLOOR_OPTIONS}
          editable={isAdmin}
          saving={setOverrides.isPending}
          onSave={override("severity_floor")}
          onClear={clear("severity_floor")}
        />

        <PolicyRow
          title="Watcher findings"
          help={watcherGateHelp(policy.watcher_gate)}
          value={policy.watcher_gate}
          source={policy.watcher_source}
          options={WATCHER_GATE_OPTIONS}
          editable={isAdmin}
          saving={setOverrides.isPending}
          onSave={override("watcher_gate")}
          onClear={clear("watcher_gate")}
        />
      </div>

      {failure && (
        <p role="alert" className="bg-destructive/10 text-destructive rounded-md px-3 py-2 text-sm">
          {failure.message || "Could not save the policy."}
        </p>
      )}

      <p className="bg-muted text-muted-foreground flex items-start gap-2.5 rounded-md px-3.5 py-3 text-[0.8125rem]">
        <InfoIcon aria-hidden="true" className="mt-0.5 size-4 flex-none" />
        <span>
          {isAdmin
            ? "You can change this page as a project admin."
            : "Only project admins can change this page. Everyone else sees what applies and why."}
          {" "}
          Waivers are the way to let one finding through; policy sets the rule for all of them.
        </span>
      </p>
    </section>
  );
}
