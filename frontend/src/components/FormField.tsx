import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import { TriangleAlertIcon } from "lucide-react";
import { type ComponentProps, type ReactNode, useId } from "react";

/**
 * A labelled input with an optional hint and an error. The error is announced when it appears and
 * marks the input invalid; the hint stays tied to the input as its description.
 */
export function FormField({ label, hint, error, extra, className, inputClassName, id, ...input }: {
  readonly label: ReactNode;
  readonly hint?: ReactNode;
  readonly error?: string | null;
  /** Extra description below the input, referenced by the input (for example the password rules). */
  readonly extra?: { readonly id: string; readonly node: ReactNode; };
  readonly className?: string;
  /** Extra classes for the input itself, for example a monospace face for a token. */
  readonly inputClassName?: string;
} & ComponentProps<typeof Input>) {
  const generated = useId();
  const inputId = id ?? generated;
  const hintId = `${inputId}-hint`;
  const errorId = `${inputId}-error`;
  const described = [hint ? hintId : null, extra?.node ? extra.id : null, error ? errorId : null]
    .filter(Boolean)
    .join(" ");

  return (
    <div className={className ?? "grid gap-1.5"}>
      <label htmlFor={inputId} className="text-body font-medium">{label}</label>
      <Input
        id={inputId}
        aria-invalid={error ? true : undefined}
        aria-describedby={described || undefined}
        className={cn("h-10 text-control", inputClassName)}
        {...input}
      />
      {hint && <p id={hintId} className="text-muted-foreground text-meta">{hint}</p>}
      {extra?.node}
      {error && (
        <p
          id={errorId}
          role="alert"
          className="text-destructive flex items-start gap-1.5 text-meta"
        >
          <TriangleAlertIcon aria-hidden="true" className="mt-0.5 size-3.5 shrink-0" />
          {error}
        </p>
      )}
    </div>
  );
}
