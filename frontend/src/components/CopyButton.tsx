import { useCopyToClipboard } from "@/lib/useCopyToClipboard";
import { cn } from "@/lib/utils";

/**
 * A button that copies `text` and says honestly what happened.
 *
 * The visible word ("Copy", "Copied", "Copy failed") always begins the
 * accessible name, and `label` finishes it ("Copy API key") so several of these
 * on one page are told apart. A persistent status region announces success, and
 * a failure explains how to copy by hand instead of pretending it worked.
 */
export function CopyButton({ text, label, className }: {
  readonly text: string;
  readonly label: string;
  readonly className?: string;
}) {
  const { status, copy } = useCopyToClipboard();
  const word = status === "copied" ? "Copied" : status === "failed" ? "Copy failed" : "Copy";

  return (
    <>
      <button
        type="button"
        aria-label={`${word} ${label}`}
        onClick={() => void copy(text)}
        className={cn(
          "text-action hover:text-action/80 inline-flex min-h-6 shrink-0 items-center rounded-md px-2 py-1 text-xs font-medium",
          className,
        )}
      >
        {word}
      </button>
      <span
        role="status"
        className={status === "failed" ? "text-destructive text-xs" : "sr-only"}
      >
        {status === "copied" ? `${label} copied` : ""}
        {status === "failed"
          ? "Couldn't copy to the clipboard. Select the text and copy it manually."
          : ""}
      </span>
    </>
  );
}
