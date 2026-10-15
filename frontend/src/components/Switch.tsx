import { cn } from "@/lib/utils";

/**
 * An on/off control for a setting that applies at once. It is a button with the switch role, so it
 * works with Space and Enter, and its state is announced as on or off rather than checked.
 */
export function Switch({ checked, onCheckedChange, disabled, "aria-label": ariaLabel, className }: {
  readonly checked: boolean;
  readonly onCheckedChange: (checked: boolean) => void;
  readonly disabled?: boolean;
  readonly "aria-label": string;
  readonly className?: string;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={ariaLabel}
      disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className={cn(
        "border-input relative h-[26px] w-[46px] shrink-0 cursor-pointer rounded-full border p-0",
        "transition-colors duration-(--dur-quick) ease-entering outline-none",
        "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50",
        "disabled:cursor-not-allowed disabled:opacity-50",
        checked
          ? "bg-foreground border-foreground hover:bg-foreground/85"
          : "bg-muted hover:bg-border",
        className,
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          "absolute top-[3px] left-[3px] size-[18px] rounded-full transition-transform duration-(--dur-quick) ease-entering",
          checked ? "bg-background translate-x-5" : "bg-foreground",
        )}
      />
    </button>
  );
}
