import { type ReactNode, useId } from "react";

/**
 * One line of a settings page: the name and what it does on the left, the control on the right.
 * The line is a named group, so a screen reader announces which setting the controls belong to.
 */
export function SettingLine({ title, help, children }: {
  readonly title: string;
  readonly help: ReactNode;
  readonly children: ReactNode;
}) {
  const headingId = useId();
  return (
    <div
      role="group"
      aria-labelledby={headingId}
      className="border-border grid items-center gap-x-6 gap-y-3 border-b px-0.5 py-4 sm:grid-cols-[minmax(0,1fr)_auto]"
    >
      <div>
        <h3 id={headingId} className="text-[0.9375rem] font-semibold">{title}</h3>
        <p className="text-muted-foreground mt-0.5 max-w-[62ch] text-[0.8125rem]">{help}</p>
      </div>
      <div className="flex flex-wrap items-center gap-2.5">{children}</div>
    </div>
  );
}
