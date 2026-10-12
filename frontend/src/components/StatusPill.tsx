import { cn } from "@/lib/utils";

export type StatusTone = "ok" | "warn" | "bad" | "off";

const TONE_CLASS: Record<StatusTone, string> = {
  ok: "text-sev-success-fg",
  warn: "text-sev-high-fg",
  bad: "text-sev-critical-fg",
  off: "text-muted-foreground",
};

/**
 * A short state word with a dot. The word carries the meaning and the dot only repeats it: a filled
 * dot is something running, a hollow one is something switched off or not started.
 */
export function StatusPill({ tone, children }: {
  readonly tone: StatusTone;
  readonly children: string;
}) {
  return (
    <span
      data-tone={tone}
      className={cn(
        "border-border inline-flex h-[26px] items-center gap-[7px] rounded border px-2.5 text-[0.8125rem] font-semibold whitespace-nowrap",
        TONE_CLASS[tone],
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          "size-[7px] rounded-full",
          tone === "off" ? "border-[1.5px] border-current" : "bg-current",
        )}
      />
      {children}
    </span>
  );
}
