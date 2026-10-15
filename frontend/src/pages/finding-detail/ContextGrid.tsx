import { INLINE_LINK } from "@/components/inlineLink";
import { EMPTY_VALUE } from "@/lib/format";
import type { FindingContext } from "@/types/api";
import { parseSourceLink } from "./format";

/** Deployment context of the finding's latest observation. */
export function ContextGrid({ context }: { readonly context?: FindingContext; }) {
  if (!context) return null;

  return (
    <div className="border-border mt-8 border-t pt-5">
      <h2 className="mb-3 text-lg font-semibold">Context</h2>
      <div className="grid grid-cols-1 gap-4 text-sm sm:grid-cols-2">
        <div>
          <span className="text-muted-foreground">Target</span>
          <p className="font-medium">
            {[context.target_name, context.target_kind]
              .filter(Boolean)
              .join(" · ") || EMPTY_VALUE}
          </p>
        </div>
        <div>
          <span className="text-muted-foreground">Environment</span>
          <p className="font-medium">{context.environment_name || EMPTY_VALUE}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Branch</span>
          <p className="font-mono text-xs">{context.branch || EMPTY_VALUE}</p>
        </div>
        <div>
          <span className="text-muted-foreground">Commit</span>
          <p className="font-mono text-xs">
            {context.commit_sha ? context.commit_sha.slice(0, 12) : EMPTY_VALUE}
          </p>
        </div>
        {parseSourceLink(context.source_link) && (
          <div className="sm:col-span-2">
            <span className="text-muted-foreground">Source</span>
            <p className="font-medium">
              <a
                href={context.source_link}
                target="_blank"
                rel="noreferrer"
                className={`${INLINE_LINK} text-sm`}
              >
                {parseSourceLink(context.source_link)!.hostname}
                {parseSourceLink(context.source_link)!.pathname}
              </a>
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
