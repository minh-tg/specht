import { setSingleKeyEnabled, useSingleKeyEnabled } from "@/lib/singleKeyShortcuts";
import { cn } from "@/lib/utils";
import { Menu } from "@base-ui/react/menu";
import { CheckIcon } from "lucide-react";

const ITEM_CLASS =
  "flex min-h-8 w-full cursor-default items-center gap-2 rounded-md px-2 text-sm outline-none select-none data-highlighted:bg-muted data-highlighted:text-foreground";

/**
 * The switch for shortcuts made of one character, a checkable menu item. It is on by default and
 * keeps the menu open so the effect can be tried straight away.
 */
export function SingleKeySetting({ className }: { className?: string; }) {
  const enabled = useSingleKeyEnabled();
  return (
    <Menu.CheckboxItem
      checked={enabled}
      closeOnClick={false}
      onCheckedChange={setSingleKeyEnabled}
      className={cn(ITEM_CLASS, className)}
    >
      <span className="flex size-4 items-center justify-center">
        <Menu.CheckboxItemIndicator>
          <CheckIcon aria-hidden="true" className="size-3.5" />
        </Menu.CheckboxItemIndicator>
      </span>
      Single-key shortcuts
    </Menu.CheckboxItem>
  );
}
