import { previewCue, setSoundEnabled, useSoundEnabled } from "@/lib/sound";
import { cn } from "@/lib/utils";
import { Menu } from "@base-ui/react/menu";
import { CheckIcon } from "lucide-react";

const ITEM_CLASS =
  "flex min-h-8 w-full cursor-default items-center gap-2 rounded-md px-2 text-sm outline-none select-none data-highlighted:bg-muted data-highlighted:text-foreground";

/**
 * The opt-in for sound effects, a checkable menu item. The click that switches it on is the user
 * gesture the browser needs, so the audio context is created here and a short cue confirms it.
 */
export function SoundSetting({ className }: { className?: string; }) {
  const enabled = useSoundEnabled();
  return (
    <Menu.CheckboxItem
      checked={enabled}
      closeOnClick={false}
      onCheckedChange={(next) => {
        setSoundEnabled(next);
        if (next) previewCue("accepted");
      }}
      className={cn(ITEM_CLASS, className)}
    >
      <span className="flex size-4 items-center justify-center">
        <Menu.CheckboxItemIndicator>
          <CheckIcon aria-hidden="true" className="size-3.5" />
        </Menu.CheckboxItemIndicator>
      </span>
      Sound effects
    </Menu.CheckboxItem>
  );
}
