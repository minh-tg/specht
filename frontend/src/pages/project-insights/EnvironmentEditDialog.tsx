import { useUpdateEnvironment } from "@/api/inventory";
import { SelectField, type SelectOption } from "@/components/SelectField";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import type { Environment } from "@/types/api";
import { type SubmitEvent, useState } from "react";

const TIERS: readonly SelectOption[] = [
  { value: "production", label: "Production" },
  { value: "staging", label: "Staging" },
  { value: "development", label: "Development" },
  { value: "test", label: "Test" },
];

const SENSITIVITIES: readonly SelectOption[] = [
  { value: "public", label: "Public" },
  { value: "internal", label: "Internal" },
  { value: "confidential", label: "Confidential" },
  { value: "restricted", label: "Restricted" },
];

/**
 * Sets how an environment is classified: its tier, whether it can be reached from the internet,
 * and how sensitive its data is. A project admin only. Scans create an environment with plain
 * defaults and never overwrite what is set here.
 */
export function EnvironmentEditDialog({ slug, environment, onClose }: {
  readonly slug: string;
  readonly environment: Environment | null;
  readonly onClose: () => void;
}) {
  return (
    <Dialog open={environment !== null} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-md">
        {environment && (
          <EditFields
            key={environment.id}
            slug={slug}
            environment={environment}
            onClose={onClose}
          />
        )}
      </DialogContent>
    </Dialog>
  );
}

function EditFields({ slug, environment, onClose }: {
  readonly slug: string;
  readonly environment: Environment;
  readonly onClose: () => void;
}) {
  const mutation = useUpdateEnvironment(slug);
  const [tier, setTier] = useState(environment.tier);
  const [internetFacing, setInternetFacing] = useState(environment.internet_facing);
  const [sensitivity, setSensitivity] = useState(environment.data_sensitivity);
  const changed = tier !== environment.tier
    || internetFacing !== environment.internet_facing
    || sensitivity !== environment.data_sensitivity;
  const canSave = changed && tier !== "" && sensitivity !== "" && !mutation.isPending;

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!canSave) return;
    try {
      await mutation.mutateAsync({
        id: environment.id,
        settings: { tier, internet_facing: internetFacing, data_sensitivity: sensitivity },
      });
      onClose();
    } catch {}
  }

  return (
    <>
      <DialogHeader>
        <DialogTitle>Classify {environment.name}</DialogTitle>
        <DialogDescription>
          Scans of this environment keep these settings. They tell people how exposed it is.
        </DialogDescription>
      </DialogHeader>
      <form onSubmit={(e) => void submit(e)} className="grid gap-4">
        <div className="grid gap-1.5">
          <label htmlFor="environment-tier" className="text-body font-medium">Tier</label>
          <SelectField id="environment-tier" value={tier} onValueChange={setTier} options={TIERS} />
        </div>
        <label className="flex items-center gap-2 text-body">
          <input
            type="checkbox"
            className="size-4"
            checked={internetFacing}
            onChange={(e) => setInternetFacing(e.target.checked)}
          />
          Reachable from the internet
        </label>
        <div className="grid gap-1.5">
          <label htmlFor="environment-sensitivity" className="text-body font-medium">
            Data sensitivity
          </label>
          <SelectField
            id="environment-sensitivity"
            value={sensitivity}
            onValueChange={setSensitivity}
            options={SENSITIVITIES}
          />
        </div>
        {mutation.isError && (
          <p role="alert" className="text-destructive text-body">
            {mutation.error.message || "Could not save the environment."}
          </p>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>Cancel</Button>
          <Button type="submit" disabled={!canSave}>Save</Button>
        </DialogFooter>
      </form>
    </>
  );
}
