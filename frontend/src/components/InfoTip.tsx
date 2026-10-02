import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { GLOSSARY, type GlossaryKey } from "@/lib/glossary";
import { cn } from "@/lib/utils";
import { Info } from "lucide-react";
import { useId, useState } from "react";

/** Hover intent for an explicit "i" button: quick, but not on a pointer merely passing by. */
const HOVER_DELAY_MS = 150;

/**
 * A small "i" button that explains one of Specht's own words, using the glossary. It opens on
 * hover and on keyboard focus, stays open while the pointer moves onto the text, and closes on
 * Escape. Base UI tooltips ignore touch, so a tap toggles it here (and a click must not undo that
 * tap), and a tap elsewhere closes it.
 * The button is a real control with a name that says what it explains, and the explanation is its
 * accessible description, so a screen reader announces the answer and not only the question. The
 * popup stays mounted (hidden) so that description is always there to reference.
 */
export function InfoTip(
  { term, className }: { readonly term: GlossaryKey; readonly className?: string; },
) {
  const entry = GLOSSARY[term];
  const [open, setOpen] = useState(false);
  const descriptionId = useId();

  return (
    <Tooltip open={open} onOpenChange={setOpen}>
      <TooltipTrigger
        aria-label={`What is ${entry.label}?`}
        aria-describedby={descriptionId}
        delay={HOVER_DELAY_MS}
        closeOnClick={false}
        onPointerDown={(event) => {
          if (event.pointerType === "touch") setOpen((current) => !current);
        }}
        className={cn(
          "text-muted-foreground hover:text-foreground inline-flex size-6 shrink-0 items-center justify-center rounded-full align-middle",
          className,
        )}
      >
        <Info aria-hidden="true" className="size-3.5" />
      </TooltipTrigger>
      <TooltipContent id={descriptionId}>{entry.short}</TooltipContent>
    </Tooltip>
  );
}
