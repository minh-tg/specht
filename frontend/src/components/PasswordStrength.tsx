import { loadStrengthEngine } from "@/components/PasswordStrengthEngine";
import { Meter } from "@base-ui/react/meter";
import type { ZxcvbnFactory } from "@zxcvbn-ts/core";
import { useEffect, useMemo, useState } from "react";

/** The four levels the meter shows. zxcvbn scores 0 to 4; 0 and 1 both read as Weak. */
const LEVELS = [
  { label: "Weak", bar: "bg-sev-critical", text: "text-sev-critical-fg" },
  { label: "Fair", bar: "bg-sev-high", text: "text-sev-high-fg" },
  { label: "Good", bar: "bg-sev-success", text: "text-sev-success-fg" },
  { label: "Strong", bar: "bg-sev-success", text: "text-sev-success-fg" },
] as const;

/**
 * How strong the password looks, as advice only: the meter never blocks the form, the server's
 * rules do. It loads the estimator once `active` turns true and shows nothing until then or while
 * the field is empty. `userInputs` are words the person's own account gives away, such as their
 * email, which make a password weaker when it contains them.
 */
export function PasswordStrength({ value, active, userInputs = [] }: {
  readonly value: string;
  readonly active: boolean;
  readonly userInputs?: readonly string[];
}) {
  const [zxcvbn, setZxcvbn] = useState<ZxcvbnFactory | null>(null);

  useEffect(() => {
    if (!active || zxcvbn) return;
    let current = true;
    loadStrengthEngine().then(
      (loaded) => {
        if (current) setZxcvbn(loaded);
      },
      () => {
        // No meter is better than a broken form: the rules above still apply.
      },
    );
    return () => {
      current = false;
    };
  }, [active, zxcvbn]);

  // Joined into one string so a new array with the same words does not recompute the estimate.
  const inputs = userInputs.filter((input) => input !== "").join("\n");
  const result = useMemo(
    () => (zxcvbn && value !== "" ? zxcvbn.check(value, inputs ? inputs.split("\n") : []) : null),
    [zxcvbn, value, inputs],
  );
  if (!result) return null;

  const levelIndex = Math.max(result.score - 1, 0);
  const level = LEVELS[levelIndex];
  const advice = result.feedback.warning ?? result.feedback.suggestions[0] ?? null;

  return (
    <div className="grid gap-1 text-meta">
      <Meter.Root
        value={levelIndex + 1}
        min={0}
        max={LEVELS.length}
        getAriaValueText={() => level.label}
        className="grid gap-1"
      >
        <div className="flex items-center justify-between gap-2">
          <Meter.Label className="text-muted-foreground">Strength</Meter.Label>
          <Meter.Value className={`font-medium ${level.text}`}>{() => level.label}</Meter.Value>
        </div>
        <Meter.Track className="bg-muted h-1.5 overflow-hidden rounded-full">
          <Meter.Indicator className={`${level.bar} h-full rounded-full transition-[width]`} />
        </Meter.Track>
      </Meter.Root>
      {/* Outside the meter: a meter's children are hidden from screen readers. */}
      {advice && <p className="text-muted-foreground">{advice}</p>}
    </div>
  );
}
