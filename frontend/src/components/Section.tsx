import { cn } from "@/lib/utils";
import { type ReactNode, useId } from "react";

const FRAME = "border-border mt-8 border-t pt-5";
const COMPACT_FRAME =
  "border-border mt-6 flex flex-wrap items-baseline gap-x-3 gap-y-1 border-t pt-4";

/**
 * One titled block of a page: the hairline frame and heading that the finding
 * sections share.
 *
 * The section is a plain element unless `region` is set, so a page with many
 * sections does not fill the screen reader's landmark list with an entry per
 * section. A section that is empty collapses to one compact line when the
 * caller says what to print there, and draws nothing when it does not.
 */
export function Section({
  title,
  level = 2,
  id,
  region = false,
  description,
  headingClassName,
  isEmpty = false,
  empty,
  className,
  children,
}: {
  readonly title: ReactNode;
  readonly level?: 2 | 3;
  readonly id?: string;
  readonly region?: boolean;
  readonly description?: ReactNode;
  readonly headingClassName?: string;
  readonly isEmpty?: boolean;
  readonly empty?: ReactNode;
  readonly className?: string;
  readonly children?: ReactNode;
}) {
  const generatedId = useId();
  const headingId = id ?? generatedId;
  const Heading = level === 3 ? "h3" : "h2";
  const labelledBy = region ? headingId : undefined;

  if (isEmpty) {
    if (empty == null) return null;
    return (
      <section className={cn(COMPACT_FRAME, className)} aria-labelledby={labelledBy}>
        <Heading id={headingId} className={cn("text-body font-semibold", headingClassName)}>
          {title}
        </Heading>
        <p className="text-muted-foreground text-meta">{empty}</p>
      </section>
    );
  }

  return (
    <section className={cn(FRAME, className)} aria-labelledby={labelledBy}>
      <Heading
        id={headingId}
        className={cn(
          level === 3 ? "text-body font-semibold" : "text-section font-semibold",
          description ? "mb-1" : "mb-3",
          headingClassName,
        )}
      >
        {title}
      </Heading>
      {description && <p className="text-muted-foreground mb-4 text-meta">{description}</p>}
      {children}
    </section>
  );
}
