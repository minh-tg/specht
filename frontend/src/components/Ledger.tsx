import { cn } from "@/lib/utils";
import { type ReactNode, useId } from "react";

/**
 * A ledger: numbered entries between hairline rules, with a heavy rule on top. It takes the place of
 * a stack of cards for a list the reader works through in order, such as the findings that block a
 * change. Only the open entry sits on the sheet.
 */
export function Ledger({ label, children, className }: {
  readonly label: string;
  readonly children: ReactNode;
  readonly className?: string;
}) {
  return (
    <ol
      aria-label={label}
      className={cn("border-foreground m-0 list-none border-t-2 p-0", className)}
    >
      {children}
    </ol>
  );
}

/** The edge colour of an open entry; it carries the severity of what the entry is about. */
export type LedgerTone = "critical" | "high" | "neutral";

const TONE_EDGE: Record<LedgerTone, string> = {
  critical: "shadow-[inset_4px_0_0_var(--sev-critical)]",
  high: "shadow-[inset_4px_0_0_var(--sev-high)]",
  neutral: "shadow-[inset_4px_0_0_var(--foreground)]",
};

export interface LedgerEntryProps {
  /** Position in the ledger, shown as 01, 02, ... */
  readonly index: number;
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  /** The always-visible row: severity, title, the one-line fix. Must not contain interactive elements. */
  readonly summary: ReactNode;
  /** An accessible name for the toggle, since the summary is rich content. */
  readonly label: string;
  readonly tone?: LedgerTone;
  /** A handled entry is dimmed and loses its edge, so progress reads at a glance. */
  readonly resolved?: boolean;
  readonly children: ReactNode;
}

/**
 * One entry. The summary row is a button that opens the detail below it. Closed detail is `inert`,
 * so its buttons and links leave the tab order and the accessibility tree while it is hidden, which a
 * height of zero alone would not do.
 */
export function LedgerEntry(
  { index, open, onOpenChange, summary, label, tone = "neutral", resolved = false, children }:
    LedgerEntryProps,
) {
  const bodyId = useId();
  return (
    <li
      data-open={open ? "true" : "false"}
      data-resolved={resolved ? "true" : "false"}
      className={cn(
        "border-border relative border-b transition-[background-color,opacity] duration-(--dur-base) ease-entering",
        open && !resolved && cn("bg-card", TONE_EDGE[tone]),
        resolved && "opacity-60",
      )}
    >
      <h3 className="m-0">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={bodyId}
          aria-label={label}
          onClick={() => onOpenChange(!open)}
          className={cn(
            "flex min-h-[52px] w-full cursor-pointer items-center gap-3 py-3 pr-4 pl-[18px] text-left",
            "hover:bg-muted/60",
          )}
        >
          <span className="text-muted-foreground w-[22px] flex-none font-mono text-code max-sm:hidden">
            {String(index).padStart(2, "0")}
          </span>
          {summary}
          <svg
            aria-hidden="true"
            viewBox="0 0 16 16"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className={cn(
              "text-muted-foreground ease-entering size-4 flex-none transition-transform duration-(--dur-quick)",
              open && "rotate-90",
            )}
          >
            <path d="m6 3.5 4.5 4.5L6 12.5" />
          </svg>
        </button>
      </h3>
      <div
        id={bodyId}
        inert={!open}
        className={cn(
          "grid transition-[grid-template-rows] duration-(--dur-base) ease-entering",
          open ? "grid-rows-[1fr]" : "grid-rows-[0fr]",
        )}
      >
        <div className="min-h-0 overflow-hidden">{children}</div>
      </div>
    </li>
  );
}
