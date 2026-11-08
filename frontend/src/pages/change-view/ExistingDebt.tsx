import { INLINE_LINK } from "@/components/inlineLink";
import { pluralize } from "@/lib/format";
import { BlockerRow } from "@/pages/change-view/BlockerRow";
import { AsOfNow } from "@/pages/change-view/ChangeHero";
import { type SyntheticEvent, useState } from "react";
import { Link } from "react-router-dom";

/** Findings listed inline before the "See all" link takes over. */
export const EXISTING_DEBT_PREVIEW = 10;

export interface ExistingDebtProps {
  slug: string;
  ids: string[];
  /**
   * The change passed. The older findings then get a plain note instead of the blocking wording:
   * they are open, and they do not count for this change.
   */
  passing?: boolean;
  projectName?: string;
  /**
   * When the project gate behind this list was evaluated, set only when the report is not the
   * newest on its branch, so the list does not read as the debt at this commit.
   */
  asOf?: string;
}

/**
 * Pre-existing debt stays secondary: the findings the project gate blocks on but
 * the change did not introduce are folded behind a native `<details>`. The rows
 * are mounted only while it is open, so their finding requests fire on demand
 * rather than on every visit to the page.
 */
export function ExistingDebt(
  { slug, ids, passing = false, projectName, asOf }: ExistingDebtProps,
) {
  const [open, setOpen] = useState(false);

  if (ids.length === 0) return null;

  const preview = ids.slice(0, EXISTING_DEBT_PREVIEW);

  return (
    <details
      className="bg-card mt-6 rounded-lg border"
      onToggle={(event: SyntheticEvent<HTMLDetailsElement>) => setOpen(event.currentTarget.open)}
    >
      <summary className="cursor-pointer px-3 py-3 text-body font-medium">
        {passing
          ? (
            <>
              {pluralize(ids.length, "existing finding")} {ids.length === 1 ? "is" : "are"} open in
              {" "}
              {projectName ?? slug}
              {asOf && (
                <>
                  {" "}
                  <AsOfNow iso={asOf} />
                </>
              )}. {ids.length === 1 ? "It is" : "They are"} not counted for this change.
            </>
          )
          : (
            <>
              {pluralize(ids.length, "other finding")} {ids.length === 1 ? "blocks" : "block"}{" "}
              this project{asOf && (
                <>
                  {" "}
                  <AsOfNow iso={asOf} />
                </>
              )} (not introduced by this change)
            </>
          )}
      </summary>
      {open && (
        <ul className="border-t">
          {preview.map((id) => <BlockerRow key={id} slug={slug} findingId={id} />)}
        </ul>
      )}
      <div className="border-t px-3 py-2">
        <Link
          to={`/${slug}/findings`}
          className={`${INLINE_LINK} text-body`}
        >
          See all in Findings
        </Link>
      </div>
    </details>
  );
}
