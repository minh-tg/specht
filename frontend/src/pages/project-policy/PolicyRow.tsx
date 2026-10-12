import { SelectField } from "@/components/SelectField";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { type ReactNode, useId, useState } from "react";
import { optionLabel, type PolicyOption, type PolicySource, SOURCE_LABEL } from "./policyCopy";

/** Where a value comes from. An override is filled in, so it stands out from the inherited rest. */
export function SourceTag({ source }: { readonly source: PolicySource; }) {
  return (
    <span
      data-source={source}
      className={cn(
        "font-label rounded border px-2 py-0.5 text-[0.6875rem]",
        source === "override"
          ? "border-foreground bg-foreground text-background"
          : "border-border text-muted-foreground",
      )}
    >
      {SOURCE_LABEL[source]}
    </span>
  );
}

/** The frame every policy line shares: a name and its explanation on the left, the control on the right. */
export function PolicyLine({ title, help, children }: {
  readonly title: string;
  readonly help: ReactNode;
  readonly children: ReactNode;
}) {
  const headingId = useId();
  return (
    <div
      role="group"
      aria-labelledby={headingId}
      className="border-border grid items-center gap-x-6 gap-y-3 border-b px-0.5 py-4 sm:grid-cols-[minmax(0,1fr)_auto]"
    >
      <div>
        <h3 id={headingId} className="text-[0.9375rem] font-semibold">{title}</h3>
        <p className="text-muted-foreground mt-0.5 max-w-[62ch] text-[0.8125rem]">{help}</p>
      </div>
      <div className="flex flex-wrap items-center gap-2.5">{children}</div>
    </div>
  );
}

/**
 * One overridable setting. Shows the value and its source; a project admin can override it, change
 * the override, or take it back to what the template or the default says.
 */
export function PolicyRow({
  title,
  help,
  value,
  source,
  options,
  editable,
  saving,
  onSave,
  onClear,
}: {
  readonly title: string;
  readonly help: ReactNode;
  readonly value: string;
  readonly source: PolicySource;
  readonly options: readonly PolicyOption[];
  readonly editable: boolean;
  readonly saving: boolean;
  readonly onSave: (value: string) => Promise<unknown>;
  readonly onClear: () => Promise<unknown>;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);

  function startEditing() {
    setDraft(value);
    setEditing(true);
  }

  async function save() {
    try {
      await onSave(draft);
      setEditing(false);
    } catch {}
  }

  async function clear() {
    try {
      await onClear();
      setEditing(false);
    } catch {}
  }

  return (
    <PolicyLine title={title} help={help}>
      <SourceTag source={source} />
      {editing
        ? (
          <>
            <SelectField
              aria-label={title}
              size="sm"
              className="w-40"
              value={draft}
              onValueChange={setDraft}
              options={options}
            />
            <Button size="sm" disabled={saving} onClick={() => void save()}>
              {saving ? "Saving…" : "Save"}
            </Button>
            <Button size="sm" variant="ghost" disabled={saving} onClick={() => setEditing(false)}>
              Cancel
            </Button>
          </>
        )
        : (
          <>
            <b className="text-[0.9375rem]">{optionLabel(options, value)}</b>
            {editable && (
              <Button
                size="sm"
                variant="outline"
                aria-label={`${source === "override" ? "Change" : "Override"} ${title}`}
                onClick={startEditing}
              >
                {source === "override" ? "Change" : "Override"}
              </Button>
            )}
            {editable && source === "override" && (
              <Button
                size="sm"
                variant="ghost"
                disabled={saving}
                aria-label={`Remove override for ${title}`}
                onClick={() => void clear()}
              >
                Remove override
              </Button>
            )}
          </>
        )}
    </PolicyLine>
  );
}
