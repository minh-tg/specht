import { useScanners } from "@/api/hooks";
import { SettingLine } from "@/components/SettingLine";
import { Button } from "@/components/ui/button";
import { useState } from "react";
import type { PolicySource } from "./policyCopy";
import { SourceTag } from "./PolicyRow";

/**
 * Which scanners close a finding when a full scan no longer reports it. All of them do unless the
 * project keeps one manual: for a scanner often run over part of the code, a clean run proves little.
 */
export function ManualCloseRow({
  value,
  source,
  editable,
  saving,
  onSave,
  onClear,
}: {
  readonly value: readonly string[];
  readonly source: PolicySource;
  readonly editable: boolean;
  readonly saving: boolean;
  readonly onSave: (scanners: string) => Promise<unknown>;
  readonly onClear: () => Promise<unknown>;
}) {
  const { data: scanners } = useScanners();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<readonly string[]>(value);

  const nameOf = (name: string) => scanners?.find((s) => s.name === name)?.display_name ?? name;
  const summary = value.length === 0
    ? "Every scanner closes automatically"
    : `Manual: ${value.map(nameOf).join(", ")}`;

  function toggle(name: string, manual: boolean) {
    setDraft((current) => manual ? [...current, name] : current.filter((n) => n !== name));
  }

  async function run(action: () => Promise<unknown>) {
    try {
      await action();
      setEditing(false);
    } catch {}
  }

  return (
    <SettingLine
      title="Closing findings"
      help="A full scan that no longer reports a finding closes it. A scanner kept manual leaves it open until someone decides."
    >
      <SourceTag source={source} />
      {editing
        ? (
          <>
            <fieldset className="grid w-full gap-1 sm:grid-cols-2">
              <legend className="text-muted-foreground mb-1 text-meta">
                Tick a scanner to keep its findings open after a clean scan
              </legend>
              {(scanners ?? []).map((s) => (
                <label key={s.name} className="flex items-center gap-2 text-body">
                  <input
                    type="checkbox"
                    checked={draft.includes(s.name)}
                    onChange={(e) =>
                      toggle(s.name, e.target.checked)}
                  />
                  {s.display_name}
                </label>
              ))}
            </fieldset>
            <Button
              size="sm"
              disabled={saving}
              onClick={() => void run(() => onSave(draft.join(",")))}
            >
              {saving ? "Saving…" : "Save"}
            </Button>
            <Button size="sm" variant="ghost" disabled={saving} onClick={() => setEditing(false)}>
              Cancel
            </Button>
          </>
        )
        : (
          <>
            <b className="text-body">{summary}</b>
            {editable && (
              <Button
                size="sm"
                variant="outline"
                aria-label={`${source === "override" ? "Change" : "Override"} closing findings`}
                onClick={() => {
                  setDraft(value);
                  setEditing(true);
                }}
              >
                {source === "override" ? "Change" : "Override"}
              </Button>
            )}
            {editable && source === "override" && (
              <Button
                size="sm"
                variant="ghost"
                disabled={saving}
                onClick={() => void run(onClear)}
              >
                Remove override
              </Button>
            )}
          </>
        )}
    </SettingLine>
  );
}
