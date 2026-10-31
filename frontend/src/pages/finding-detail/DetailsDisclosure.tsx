import { type ReactNode, useId, useState } from "react";

/**
 * Folds the secondary sections of a page behind one button. The body mounts on the first open and
 * is only hidden after that, so a half-typed form survives closing and reopening the disclosure.
 * Sections that load their own data do not ask for it until the person opens it.
 */
export function DetailsDisclosure({ summary, children }: {
  readonly summary: ReactNode;
  readonly children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [opened, setOpened] = useState(false);
  const headingId = useId();
  const bodyId = useId();
  const summaryId = useId();

  return (
    <section aria-labelledby={headingId} className="border-border mt-8 border-t pt-4">
      <h2 id={headingId} className="text-section font-semibold">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={bodyId}
          aria-describedby={summaryId}
          onClick={() => {
            setOpen(!open);
            setOpened(true);
          }}
          className="flex w-full flex-wrap items-baseline gap-x-3 rounded-sm py-1 text-left"
        >
          <span aria-hidden="true" className="text-muted-foreground w-3 text-meta">
            {open ? "▾" : "▸"}
          </span>
          <span>Details</span>
          <span
            id={summaryId}
            aria-hidden="true"
            className="text-muted-foreground text-meta font-normal"
          >
            {summary}
          </span>
        </button>
      </h2>
      <div id={bodyId} hidden={!open}>
        {opened && children}
      </div>
    </section>
  );
}
