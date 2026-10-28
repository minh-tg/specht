import { DetailList, type DetailRow, hasDetails } from "@/components/DetailList";
import { INLINE_LINK } from "@/components/inlineLink";
import { Section } from "@/components/Section";
import type { FindingContext } from "@/types/api";
import { parseSourceLink } from "./format";

/** Deployment context of the finding's latest observation. */
export function ContextGrid({ context }: { readonly context?: FindingContext; }) {
  if (!context) return null;

  const rows: DetailRow[] = [
    {
      label: "Target",
      value: [context.target_name, context.target_kind].filter(Boolean).join(" · ") || undefined,
    },
    { label: "Environment", value: context.environment_name },
    { label: "Branch", value: context.branch, code: true },
    { label: "Commit", value: context.commit_sha?.slice(0, 12), code: true },
  ];
  if (parseSourceLink(context.source_link)) {
    rows.push({
      label: "Source",
      value: (
        <a
          href={context.source_link}
          target="_blank"
          rel="noreferrer"
          className={`${INLINE_LINK} text-body`}
        >
          {parseSourceLink(context.source_link)!.hostname}
          {parseSourceLink(context.source_link)!.pathname}
        </a>
      ),
    });
  }

  return (
    <Section
      title="Context"
      isEmpty={!hasDetails(rows)}
      empty="No deployment context in this report."
    >
      <DetailList rows={rows} />
    </Section>
  );
}
