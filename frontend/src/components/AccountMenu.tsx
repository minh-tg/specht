import { SoundSetting } from "@/components/SoundSetting";
import { buttonVariants } from "@/components/ui/button-variants";
import { type Theme, useTheme } from "@/lib/theme";
import { cn } from "@/lib/utils";
import { Menu } from "@base-ui/react/menu";
import { CheckIcon, ChevronDownIcon, UserIcon } from "lucide-react";
import { Link } from "react-router-dom";

const ITEM_CLASS =
  "flex min-h-8 w-full cursor-default items-center rounded-md px-2 text-sm outline-none select-none data-highlighted:bg-muted data-highlighted:text-foreground";

const APPEARANCE: readonly { value: Theme; label: string; }[] = [
  { value: "system", label: "System" },
  { value: "light", label: "Light" },
  { value: "dark", label: "Dark" },
];

/**
 * The signed-in person's menu: Profile, the appearance choice and Sign out. The trigger shows the email truncated; below
 * the sm breakpoint only an icon is left, so the accessible name carries the email.
 */
export function AccountMenu({ email, onLogout }: { email: string | null; onLogout: () => void; }) {
  const { theme, setTheme } = useTheme();

  return (
    <Menu.Root>
      <Menu.Trigger
        aria-label={email ? `Account menu, ${email}` : "Account menu"}
        className={cn(
          buttonVariants({ variant: "ghost" }),
          "text-muted-foreground max-w-[14rem] min-w-0",
        )}
      >
        <UserIcon aria-hidden="true" className="sm:hidden" />
        {email && (
          <span className="truncate max-sm:hidden" title={email}>
            {email}
          </span>
        )}
        <ChevronDownIcon aria-hidden="true" />
      </Menu.Trigger>
      <Menu.Portal>
        <Menu.Positioner align="end" sideOffset={6} className="isolate z-50">
          <Menu.Popup className="bg-popover text-popover-foreground ring-foreground/10 min-w-40 origin-(--transform-origin) rounded-lg p-1 shadow-md ring-1 transition-[opacity,scale] duration-(--dur-instant) ease-entering data-ending-style:scale-95 data-ending-style:opacity-0 data-starting-style:scale-95 data-starting-style:opacity-0 motion-reduce:transition-none">
            <Menu.LinkItem render={<Link to="/profile" />} className={ITEM_CLASS}>
              Profile
            </Menu.LinkItem>
            <Menu.Separator className="bg-border -mx-1 my-1 h-px" />
            {
              /* The radio group is the labelled group: it supplies its own group role and takes the
                label from the GroupLabel inside it, so no outer Menu.Group is needed. */
            }
            <Menu.RadioGroup
              value={theme}
              onValueChange={(value) => setTheme(value as Theme)}
            >
              <Menu.GroupLabel className="text-muted-foreground px-2 pt-1 pb-0.5 text-xs">
                Appearance
              </Menu.GroupLabel>
              {APPEARANCE.map(({ value, label }) => (
                <Menu.RadioItem
                  key={value}
                  value={value}
                  className={cn(ITEM_CLASS, "relative pl-7")}
                >
                  <Menu.RadioItemIndicator className="absolute left-2 inline-flex items-center">
                    <CheckIcon aria-hidden="true" size={14} />
                  </Menu.RadioItemIndicator>
                  {label}
                </Menu.RadioItem>
              ))}
            </Menu.RadioGroup>
            <Menu.Separator className="bg-border -mx-1 my-1 h-px" />
            <SoundSetting />
            <Menu.Separator className="bg-border -mx-1 my-1 h-px" />
            <Menu.Item onClick={onLogout} className={ITEM_CLASS}>
              Sign out
            </Menu.Item>
          </Menu.Popup>
        </Menu.Positioner>
      </Menu.Portal>
    </Menu.Root>
  );
}
