import { Drum } from "@/components/Drum";
import { cn } from "@/lib/utils";
import type { Verdict } from "@/lib/verdict";
import { useEffect, useRef, useState } from "react";

/**
 * The verdict stamp: a rectangular mark in condensed heavy capitals, the only solid block on a page.
 *
 * The label is mandatory: colour alone is never the signal. Blocked is crown red and passing is
 * forest green; `unknown` is drawn in ink as an outline and `no_scans` as a dashed outline, so the
 * three that are not a decision look different from the two that are. When the verdict changes while
 * the stamp is on screen it settles once, scale 1.08 to 1, so the change is seen.
 */
const VERDICT_VARIANTS: Record<Verdict, string> = {
  blocked: "bg-verdict-block text-verdict-block-fg",
  passing: "bg-verdict-pass text-verdict-pass-fg",
  unknown: "text-foreground shadow-[inset_0_0_0_2px_var(--foreground)]",
  no_scans: "text-muted-foreground border-input border-2 border-dashed",
};

const VERDICT_LABELS: Record<Verdict, string> = {
  blocked: "BLOCKED",
  passing: "PASSING",
  no_scans: "NO SCANS",
  unknown: "UNKNOWN",
};

const SIZES = {
  sm: "h-[26px] gap-1.5 px-[9px] text-[13px]",
  lg: "h-10 gap-2.5 px-3.5 text-xl",
} as const;

export interface VerdictBadgeProps {
  readonly verdict: Verdict;
  /** `lg` is the page stamp; `sm` sits in a list row or a sentence. */
  readonly size?: keyof typeof SIZES;
  /** A scan is running: the stamp reads SCANNING with the drum, whatever the old verdict was. */
  readonly scanning?: boolean;
}

/** How long the stamp keeps its landing flag: the animation takes 180ms, so this clears it after. */
const LANDING_MS = 300;

/**
 * True for a moment after `value` changes, never on the first render. It clears on a timer, not on
 * the animation's end event, so a stamp that never plays the animation (hidden, or reduced motion)
 * does not keep the flag and replay it later.
 */
function useChanged(value: string): boolean {
  const previous = useRef(value);
  const [changed, setChanged] = useState(false);
  useEffect(() => {
    if (previous.current === value) return;
    previous.current = value;
    setChanged(true);
    const timer = setTimeout(() => setChanged(false), LANDING_MS);
    return () => clearTimeout(timer);
  }, [value]);
  return changed;
}

export function VerdictBadge({ verdict, size = "sm", scanning = false }: VerdictBadgeProps) {
  const shown: Verdict = scanning ? "unknown" : verdict;
  const landed = useChanged(scanning ? "scanning" : verdict);
  return (
    <span
      data-landed={landed ? "true" : undefined}
      className={cn(
        "font-label inline-flex items-center rounded-lg leading-none",
        "data-[landed=true]:animate-stamp-land",
        SIZES[size],
        VERDICT_VARIANTS[shown],
      )}
    >
      {scanning ? "SCANNING" : VERDICT_LABELS[verdict]}
      {scanning && <Drum />}
    </span>
  );
}
