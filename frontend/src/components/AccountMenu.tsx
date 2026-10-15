import { buttonVariants } from "@/components/ui/button-variants";
import { cn } from "@/lib/utils";
import { Menu } from "@base-ui/react/menu";
import { ChevronDownIcon, UserIcon } from "lucide-react";
import { Link } from "react-router-dom";

const ITEM_CLASS =
  "flex min-h-8 w-full cursor-default items-center rounded-md px-2 text-sm outline-none select-none data-highlighted:bg-muted data-highlighted:text-foreground";

/**
 * The signed-in person's menu: Profile and Sign out. The trigger shows the email truncated; below
 * the sm breakpoint only an icon is left, so the accessible name carries the email.
 */
export function AccountMenu({ email, onLogout }: { email: string | null; onLogout: () => void; }) {
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
            <Menu.Item onClick={onLogout} className={ITEM_CLASS}>
              Sign out
            </Menu.Item>
          </Menu.Popup>
        </Menu.Positioner>
      </Menu.Portal>
    </Menu.Root>
  );
}
