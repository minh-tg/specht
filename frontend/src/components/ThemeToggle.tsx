import { nextTheme, type Theme, useTheme } from "@/lib/theme";
import { Monitor, Moon, Sun } from "lucide-react";

const ICONS: Record<Theme, typeof Sun> = {
  system: Monitor,
  light: Sun,
  dark: Moon,
};

/** One button that cycles system, light and dark; the icon shows the current choice. */
export function ThemeToggle() {
  const { theme, setTheme } = useTheme();
  const Icon = ICONS[theme];
  const label = `Theme: ${theme} (click to change)`;

  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={() => setTheme(nextTheme(theme))}
      className="text-muted-foreground hover:text-foreground hover:bg-muted inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md"
    >
      <Icon aria-hidden="true" size={16} />
    </button>
  );
}
