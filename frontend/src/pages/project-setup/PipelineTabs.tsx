import { CopyButton } from "@/components/CopyButton";
import { useState } from "react";

const PRE_CLASS =
  "bg-muted max-h-[28rem] overflow-auto rounded-md p-3 text-code break-words whitespace-pre-wrap";
const STORAGE_KEY = "specht:setup-pipeline";

export interface Pipeline {
  readonly id: string;
  readonly label: string;
  readonly copyLabel: string;
  readonly snippet: string;
}

function rememberedTab(pipelines: readonly Pipeline[]): string {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (pipelines.some((p) => p.id === stored)) return stored as string;
  } catch {}
  return pipelines[0].id;
}

/** One pipeline at a time: nobody runs both, and stacked they pushed the status off the page. */
export function PipelineTabs({ pipelines }: { readonly pipelines: readonly Pipeline[]; }) {
  const [active, setActive] = useState(() => rememberedTab(pipelines));
  const shown = pipelines.find((p) => p.id === active) ?? pipelines[0];

  function choose(id: string) {
    setActive(id);
    try {
      localStorage.setItem(STORAGE_KEY, id);
    } catch {}
  }

  return (
    <div className="mt-3">
      <div className="flex items-center justify-between gap-3">
        <div role="tablist" aria-label="CI system" className="flex gap-1">
          {pipelines.map((p) => (
            <button
              key={p.id}
              type="button"
              role="tab"
              id={`pipeline-tab-${p.id}`}
              aria-selected={p.id === shown.id}
              aria-controls="pipeline-panel"
              className={`rounded-md px-3 py-1.5 text-body pointer-coarse:min-h-11 ${
                p.id === shown.id ? "bg-muted font-medium" : "text-muted-foreground"
              }`}
              onClick={() => choose(p.id)}
            >
              {p.label}
            </button>
          ))}
        </div>
        <CopyButton text={shown.snippet} label={shown.copyLabel} />
      </div>
      <div
        role="tabpanel"
        id="pipeline-panel"
        aria-labelledby={`pipeline-tab-${shown.id}`}
        className="mt-2"
      >
        <pre className={PRE_CLASS} tabIndex={0}>
          <code>{shown.snippet}</code>
        </pre>
      </div>
    </div>
  );
}
