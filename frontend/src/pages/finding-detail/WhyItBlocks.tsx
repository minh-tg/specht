import { normalizeSeverity, type Severity, severityLabel } from "@/lib/enums";
import type { BlocksGateResult } from "@/lib/gate";

/**
 * Says in one sentence whether the gate stops on this finding, and why, in the finding's own
 * colour. The reason is the gate's: the floor comes from the policy, the waiver from the waiver
 * list. While the gate is unknown nothing is claimed.
 */
export function WhyItBlocks({ severity, gateResult, floor }: {
  readonly severity: string;
  readonly gateResult: BlocksGateResult | null;
  /** The project's severity floor, when the gate has said what it is. */
  readonly floor?: string;
}) {
  if (!gateResult) return null;

  const word = (severityLabel(severity) ?? "Unknown").toUpperCase();
  const floorWord = floor ? (severityLabel(floor) ?? floor).toUpperCase() : null;

  let heading = "Why this does not block";
  let text: string;
  if (gateResult.blocks) {
    heading = "Why this blocks";
    text = floorWord
      ? `Severity ${word} is at or above the project floor (${floorWord}). The gate stops a change that carries it until it is fixed or waived.`
      : "The gate stops a change that carries this finding until it is fixed or waived.";
  } else if (gateResult.reason === "waived") {
    text =
      "An approved waiver lets this finding through the gate. It blocks again when the waiver expires.";
  } else if (gateResult.reason === "ignored") {
    text =
      "Triage marked this finding as not blocking the gate. It stays on the list until someone fixes it.";
  } else if (gateResult.reason === "below_floor") {
    text = `Severity ${word} is below the project floor${
      floorWord ? ` (${floorWord})` : ""
    }, so this finding does not block a change. It stays on the list until someone fixes or accepts it.`;
  } else {
    text = "This finding does not block the gate.";
  }

  const normalized = normalizeSeverity(severity);
  const known = (["critical", "high", "medium", "low"] as Severity[]).includes(
    normalized as Severity,
  );
  const edge = gateResult.blocks && known ? `var(--sev-${normalized})` : "var(--border)";

  return (
    <section
      aria-label={heading}
      data-blocks={gateResult.blocks}
      style={{ borderLeftColor: edge }}
      className="bg-muted mt-5 grid gap-1 rounded-md border-l-4 py-3 pr-4 pl-4"
    >
      <h2 className="font-label text-muted-foreground text-label">{heading}</h2>
      <p className="text-body">{text}</p>
    </section>
  );
}
