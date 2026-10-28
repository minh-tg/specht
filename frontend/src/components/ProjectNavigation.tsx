import { Menu } from "@base-ui/react/menu";
import { ChevronDownIcon } from "lucide-react";
import { Link } from "react-router-dom";

const WORK_LINKS = [
  { tab: "findings", label: "Findings" },
  { tab: "reports", label: "Reports" },
  { tab: "waivers", label: "Waivers" },
  { tab: "insights", label: "Insights" },
];
const CONFIG_LINKS = [
  { tab: "policy", label: "Policy" },
  { tab: "watcher", label: "Watcher" },
  { tab: "access", label: "Access & Members" },
  { tab: "settings", label: "Settings" },
];

export function ProjectNavigation({ slug, currentTab, isAdmin }: {
  readonly slug: string;
  readonly currentTab: string;
  readonly isAdmin: boolean;
}) {
  const configuration = CONFIG_LINKS.filter(({ tab }) => tab !== "settings" || isAdmin);
  const active = configuration.find(({ tab }) => tab === currentTab);
  const tabClass = (current: boolean) =>
    `pb-2 text-body font-medium ${
      current
        ? "border-primary text-foreground border-b-2"
        : "text-muted-foreground hover:text-foreground"
    }`;

  return (
    <nav
      aria-label="Project sections"
      className="mb-6 flex flex-wrap items-center gap-x-4 gap-y-2 border-b"
    >
      {WORK_LINKS.map(({ tab, label }) => (
        <Link
          key={tab}
          to={`/${slug}/${tab}`}
          aria-current={tab === currentTab ? "page" : undefined}
          className={tabClass(tab === currentTab)}
        >
          {label}
        </Link>
      ))}
      <Menu.Root>
        <Menu.Trigger
          aria-current={active ? "location" : undefined}
          className={`flex min-h-9 items-center gap-1.5 ${tabClass(Boolean(active))}`}
        >
          Configuration
          {active && <span className="text-foreground">· {active.label}</span>}
          <ChevronDownIcon aria-hidden="true" className="size-3.5" />
        </Menu.Trigger>
        <Menu.Portal>
          <Menu.Positioner align="end" sideOffset={6} className="isolate z-50">
            <Menu.Popup className="bg-popover text-popover-foreground ring-foreground/10 min-w-48 rounded-lg p-1 shadow-md ring-1">
              {configuration.map(({ tab, label }) => (
                <Menu.LinkItem
                  key={tab}
                  closeOnClick
                  render={<Link to={`/${slug}/${tab}`} />}
                  aria-current={tab === currentTab ? "page" : undefined}
                  className="flex min-h-9 items-center rounded-md px-2 text-body outline-none select-none data-highlighted:bg-muted data-highlighted:text-foreground aria-[current=page]:font-semibold"
                >
                  {label}
                </Menu.LinkItem>
              ))}
            </Menu.Popup>
          </Menu.Positioner>
        </Menu.Portal>
      </Menu.Root>
    </nav>
  );
}
