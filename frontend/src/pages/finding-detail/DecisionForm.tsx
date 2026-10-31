import { APIError } from "@/api/client";
import {
  useMe,
  useProject,
  useProjectRole,
  useTriageFinding,
  useUpsertReachability,
} from "@/api/hooks";
import { actorLabel } from "@/api/users";
import { DisabledReason } from "@/components/DisabledReason";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { type AnalysisState, analysisStateLabel, type ReachabilityState } from "@/lib/enums";
import { formatDate, formatDateTime } from "@/lib/format";
import { matchesPageKey } from "@/lib/shortcuts";
import { useSingleKeyEnabled } from "@/lib/singleKeyShortcuts";
import { truncateText } from "@/lib/utils";
import type { WaiverAction } from "@/lib/waiverRequest";
import type { Finding, FindingEvent } from "@/types/api";
import { type FormEvent, type ReactNode, useEffect, useEffectEvent, useState } from "react";
import {
  dayFromNow,
  type DecisionId,
  DECISIONS,
  detailsFor,
  exemptsFromGate,
  REACH_ANSWERS,
  reachEffect,
  triageWrite,
} from "./decision";
import { MAX_EVIDENCE_LENGTH } from "./options";
import { WaiverControl } from "./WaiverControl";

/** The server lets only project managers and admins record a triage or reachability decision. */
export const DECISION_MANAGER_ONLY = "Only project managers can record a triage decision.";
const CHECKING_ROLE = "Checking what you may do on this project.";
const MAX_REASON = 1000;
const TRIAGE_EVENTS = new Set(["analysis_changed", "bulk_triage_applied"]);

type Part = "triage" | "reach";
/** What one request did. A refused triage after a conflict is retried from the conflict panel. */
interface PartResult {
  readonly ok: boolean;
  readonly text: string;
  readonly retry?: boolean;
}

/** The reachability the form starts from: the latest saved answer, once it has loaded. */
export interface ReachabilityInput {
  readonly status: "loading" | "error" | "ready";
  /** The latest saved answer, or null when nobody has answered. */
  readonly latest: ReachabilityState | null;
  readonly updatedAt?: string;
  readonly evidence?: string;
}

export interface DecisionFormProps {
  readonly finding: Pick<Finding, "id" | "analysis_state" | "analysis_reason">;
  readonly slug: string;
  readonly reachability: ReachabilityInput;
  /** The finding's history, newest first. The conflict panel names who made the newer decision. */
  readonly events: readonly FindingEvent[] | null | undefined;
  readonly waiver: WaiverAction;
  readonly onRequestWaiver: () => void;
  /** Speaks a sentence in the page's polite live region. */
  readonly announce: (message: string) => void;
}

const reachName = (state: ReachabilityState) =>
  REACH_ANSWERS.find((answer) => answer.value === state)?.name ?? state;

function errorText(error: unknown, fallback: string): string {
  return error instanceof APIError && error.message ? error.message : fallback;
}

/**
 * The decide-first form: what the finding is, and optionally whether anyone can reach it. The two
 * answers are stored by two requests, so one can save while the other fails. The form then says
 * which part saved, keeps the input of the part that did not, and retries only that part.
 */
export function DecisionForm(
  { finding, slug, reachability, events, waiver, onRequestWaiver, announce }: DecisionFormProps,
) {
  const { canTriage, isLoading: roleLoading } = useProjectRole(slug);
  const triage = useTriageFinding();
  const upsertReach = useUpsertReachability();
  const { data: me } = useMe();
  const { data: project } = useProject(slug);

  const [decision, setDecision] = useState<DecisionId | null>(null);
  const [detail, setDetail] = useState<string | null>(null);
  // null follows the saved answer; a value is the person's own pick.
  const [reach, setReach] = useState<ReachabilityState | null>(null);
  const [reason, setReason] = useState("");
  // The state the person saw when they started deciding. Triage sends it as `expected_state`.
  const [base, setBase] = useState<AnalysisState | undefined>(undefined);
  const [results, setResults] = useState<Partial<Record<Part, PartResult>>>({});
  const [conflict, setConflict] = useState<{ saw: AnalysisState; } | null>(null);
  const [busy, setBusy] = useState(false);

  const allowed = !roleLoading && canTriage;
  const lockedReason = roleLoading ? CHECKING_ROLE : canTriage ? undefined : DECISION_MANAGER_ONLY;
  const reachReady = reachability.status === "ready";
  const evidence = reachability.evidence?.trim();
  const savedReach: ReachabilityState = reachability.latest ?? "unknown";
  const shownReach = reach ?? savedReach;
  const reachChanged = reachReady && reach !== null && reach !== savedReach;
  const write = decision ? triageWrite(decision, detail) : null;
  const needsReason = (write?.needsReason ?? false) || (reachChanged && exemptsFromGate(reach));
  const reasonMissing = needsReason && reason.trim() === "";
  const nothingPicked = !decision && !reachChanged;
  const canSave = allowed && !busy && !nothingPicked && !reasonMissing;

  function startEditing() {
    if (base === undefined) setBase(finding.analysis_state);
  }

  function pickDecision(next: DecisionId) {
    startEditing();
    setDecision(next);
    setDetail(detailsFor(next)[0]?.id ?? null);
    // A real issue has to keep counting, so an answer that would exempt it is cleared.
    if (next === "real" && exemptsFromGate(shownReach)) setReach("unknown");
  }

  // Keys 1 to 3 pick the three answers, in their order on screen.
  const singleKeys = useSingleKeyEnabled();
  const onDecisionKey = useEffectEvent((event: KeyboardEvent) => {
    const choice = /^[1-3]$/.test(event.key) ? DECISIONS[Number(event.key) - 1] : undefined;
    if (!choice || !allowed || !matchesPageKey(event)) return;
    event.preventDefault();
    pickDecision(choice.id);
  });
  useEffect(() => {
    const listener = (event: KeyboardEvent) => onDecisionKey(event);
    document.addEventListener("keydown", listener);
    return () => document.removeEventListener("keydown", listener);
  }, []);

  function clearDecision() {
    setDecision(null);
    setDetail(null);
    setBase(undefined);
  }

  async function runTriage(
    target: { state: AnalysisState; expiresAt?: string; withReason: boolean; },
    expected: AnalysisState,
  ): Promise<PartResult> {
    try {
      await triage.mutateAsync({
        findingId: finding.id,
        analysisState: target.state,
        previousState: finding.analysis_state,
        expectedState: expected,
        reason: target.withReason ? reason.trim() : undefined,
        analysisExpiresAt: target.expiresAt,
      });
      clearDecision();
      setConflict(null);
      return { ok: true, text: `Decision saved: ${analysisStateLabel(target.state)}.` };
    } catch (error) {
      if (error instanceof APIError && error.code === "analysis_conflict") {
        setConflict({ saw: expected });
        return {
          ok: false,
          text: "Decision not saved: someone else triaged this finding since you opened it.",
        };
      }
      return {
        ok: false,
        retry: true,
        text: `Decision not saved: ${errorText(error, "the request failed.")}`,
      };
    }
  }

  async function runReach(state: ReachabilityState): Promise<PartResult> {
    try {
      await upsertReach.mutateAsync({ findingId: finding.id, state, evidence: reason.trim() });
      setReach(null);
      return { ok: true, text: `Reachability saved: ${reachName(state)}.` };
    } catch (error) {
      return {
        ok: false,
        retry: true,
        text: `Reachability not saved: ${errorText(error, "the request failed.")}`,
      };
    }
  }

  /**
   * Saves the parts that have input, or only `only`. Both requests run together and neither is
   * undone when the other fails: each result stays on screen for its own part.
   */
  async function save(only?: Part, expected: AnalysisState = base ?? finding.analysis_state) {
    if (!allowed) return;
    const jobs: Promise<[Part, PartResult]>[] = [];
    if (write && only !== "reach") {
      jobs.push(
        runTriage({ state: write.state, expiresAt: write.expiresAt, withReason: true }, expected)
          .then((result) => ["triage", result]),
      );
    }
    if (reachChanged && reach && only !== "triage") {
      jobs.push(runReach(reach).then((result) => ["reach", result]));
    }
    if (jobs.length === 0) return;
    setBusy(true);
    const outcomes = await Promise.all(jobs);
    setBusy(false);
    const next = Object.fromEntries(outcomes) as Partial<Record<Part, PartResult>>;
    setResults((previous) => only ? { ...previous, ...next } : next);
    if (outcomes.every(([, result]) => result.ok)) setReason("");
    announce(outcomes.map(([, result]) => result.text).join(" "));
  }

  async function saveState(state: AnalysisState) {
    setBusy(true);
    const result = await runTriage(
      { state, withReason: false },
      base ?? finding.analysis_state,
    );
    setBusy(false);
    setResults({ triage: result });
    announce(result.text);
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    void save();
  }

  // The conflict panel names the decision that won, once the reload has brought it.
  const reloaded = conflict !== null && finding.analysis_state !== conflict.saw;
  const latestTriage = reloaded
    ? (Array.isArray(events) ? events : []).find((event) => TRIAGE_EVENTS.has(event.event_type))
    : undefined;

  const saveHint = !allowed
    ? null
    : nothingPicked
    ? "Pick one of the three first."
    : reasonMissing
    ? "Add a reason to save."
    : null;

  return (
    <form onSubmit={submit} aria-labelledby="decision-legend" className="grid gap-5">
      {lockedReason && !roleLoading && (
        <p id="decision-locked" className="text-muted-foreground text-meta">
          {lockedReason}
          {project?.permissions?.request_waiver === true && " You can still request a waiver."}
        </p>
      )}
      <fieldset
        disabled={!allowed}
        aria-describedby={lockedReason && !roleLoading ? "decision-locked" : undefined}
        className="grid gap-2"
      >
        <legend id="decision-legend" className="mb-2 text-body font-semibold">
          What is this finding?
        </legend>
        {allowed && (
          <p className="text-muted-foreground -mt-1 mb-1 text-meta">
            {singleKeys
              ? "Keys 1 to 3 pick. They pause while you type in a field."
              : "Single-key shortcuts are off. Turn them on in the account menu."}
          </p>
        )}
        <div className="grid gap-2 sm:grid-cols-3">
          {DECISIONS.map((choice) => (
            <Choice
              key={choice.id}
              name="decision"
              checked={decision === choice.id}
              onChange={() => pickDecision(choice.id)}
              title={choice.name}
              note={choice.effect}
            />
          ))}
        </div>
      </fieldset>

      {decision && decision !== "real" && (
        <fieldset disabled={!allowed} className="grid gap-2">
          <legend className="mb-2 text-body font-medium">
            {decision === "accept" ? "Until when?" : "Why is it not a problem?"}
          </legend>
          {detailsFor(decision).map((option) => (
            <Choice
              key={option.id}
              name="decision-detail"
              checked={detail === option.id}
              onChange={() => setDetail(option.id)}
              title={option.days
                ? `${formatDate(`${dayFromNow(option.days)}T12:00:00`)} (${option.name})`
                : option.name}
              note={option.note}
            />
          ))}
          {decision === "accept" && (
            <p className="text-muted-foreground text-meta">
              This is a project manager's decision and takes effect now. A member asks for the same
              thing with Request waiver, which needs a manager's approval.
            </p>
          )}
        </fieldset>
      )}

      <fieldset disabled={!allowed || !reachReady} className="grid gap-2">
        <legend className="mb-2 text-body font-medium">
          Can an attacker reach this code?{" "}
          <span className="text-muted-foreground font-normal">(optional)</span>
        </legend>
        <p className="text-muted-foreground text-meta">
          {reachability.status === "loading"
            ? "Loading the saved answer."
            : reachability.status === "error"
            ? "Could not load the saved answer, so this part is off. Reload the page to try again."
            : reachability.latest
            ? (
              <>
                Saved answer: {reachName(reachability.latest)}
                {reachability.updatedAt && <>, {formatDateTime(reachability.updatedAt)}</>}.
                {evidence && (
                  <span title={evidence}>{" "}{truncateText(evidence, MAX_EVIDENCE_LENGTH)}</span>
                )}
              </>
            )
            : "Nobody has answered yet."}
        </p>
        <div className="flex flex-wrap gap-x-5 gap-y-1">
          {REACH_ANSWERS.map((answer) => {
            const off = decision === "real" && exemptsFromGate(answer.value);
            return (
              <label key={answer.value} className="flex items-center gap-2 text-body">
                <input
                  type="radio"
                  name="reach"
                  className="accent-primary size-4"
                  checked={shownReach === answer.value}
                  disabled={off}
                  onChange={() => setReach(answer.value)}
                />
                {answer.name}
              </label>
            );
          })}
        </div>
        {reachReady && (
          <p className="text-muted-foreground text-meta">
            {reachEffect(shownReach, decision === "real")}
          </p>
        )}
      </fieldset>

      {(!nothingPicked || reason !== "") && (
        <div className="grid gap-1.5">
          <label htmlFor="decision-reason" className="text-body font-medium">
            Reason{" "}
            <span className="text-muted-foreground font-normal">
              ({needsReason ? "required" : "optional"}, kept in the audit trail)
            </span>
          </label>
          <Textarea
            id="decision-reason"
            rows={2}
            maxLength={MAX_REASON}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder={decision === "accept"
              ? "What makes it acceptable until then, and who owns the fix"
              : "What you checked, so the next person does not repeat it"}
          />
        </div>
      )}

      {conflict && (
        <div className="border-border bg-muted grid gap-2 rounded-md border px-3.5 py-3 text-body">
          <p className="font-medium">Someone else triaged this finding since you opened it.</p>
          {reloaded && (
            <>
              <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-meta">
                <dt className="text-muted-foreground">You saw</dt>
                <dd>{analysisStateLabel(conflict.saw)}</dd>
                <dt className="text-muted-foreground">Now</dt>
                <dd>
                  {analysisStateLabel(finding.analysis_state)}
                  {finding.analysis_reason && <>, &ldquo;{finding.analysis_reason}&rdquo;</>}
                  {latestTriage && (
                    <>
                      {", by "}
                      {actorLabel(latestTriage, { me })}, {formatDateTime(latestTriage.created_at)}
                    </>
                  )}
                </dd>
              </dl>
              <p className="text-muted-foreground text-meta">
                Your choice and reason are still filled in. Saving again replaces their decision.
              </p>
            </>
          )}
          <div className="flex flex-wrap gap-2">
            <DisabledReason reason={reloaded ? undefined : "Waiting for the reloaded finding."}>
              <Button
                type="button"
                disabled={!reloaded || busy}
                onClick={() => {
                  setBase(finding.analysis_state);
                  void save("triage", finding.analysis_state);
                }}
              >
                Save mine on top
              </Button>
            </DisabledReason>
            <Button
              type="button"
              variant="outline"
              onClick={() => {
                clearDecision();
                setConflict(null);
                setResults(({ triage: _dropped, ...rest }) => rest);
              }}
            >
              Keep theirs
            </Button>
          </div>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <DisabledReason reason={lockedReason}>
          <Button type="submit" disabled={!canSave} aria-describedby="decision-save-hint">
            {busy ? "Saving..." : "Save decision"}
          </Button>
        </DisabledReason>
        <span id="decision-save-hint" className="text-muted-foreground text-meta">
          {saveHint}
        </span>
      </div>

      <PartResults results={results} busy={busy} onRetry={(part) => void save(part)} />

      <details className="text-body">
        <summary className="text-muted-foreground cursor-pointer text-meta">Other states</summary>
        <div className="mt-2 flex flex-wrap gap-2">
          {(["in_triage", "unanalyzed"] as const).map((state) => (
            <DisabledReason key={state} reason={lockedReason}>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={!allowed || busy}
                onClick={() =>
                  void saveState(state)}
              >
                {state === "in_triage" ? "Mark as in triage" : "Reset to not triaged"}
              </Button>
            </DisabledReason>
          ))}
        </div>
      </details>

      <div className="grid gap-1">
        <WaiverControl waiver={waiver} onRequest={onRequestWaiver} />
      </div>
    </form>
  );
}

function Choice({ name, checked, onChange, title, note }: {
  readonly name: string;
  readonly checked: boolean;
  readonly onChange: () => void;
  readonly title: ReactNode;
  readonly note: string;
}) {
  return (
    <label className="has-[:checked]:border-primary has-[:disabled]:opacity-60 flex cursor-pointer items-start gap-2.5 rounded-md border px-3 py-2.5">
      <input
        type="radio"
        name={name}
        className="accent-primary mt-0.5 size-4 shrink-0"
        checked={checked}
        onChange={onChange}
      />
      <span className="grid gap-0.5">
        <span className="text-body font-medium">{title}</span>
        <span className="text-muted-foreground text-meta">{note}</span>
      </span>
    </label>
  );
}

/** One line per part that was sent: what saved, and a retry for only the part that did not. */
function PartResults({ results, busy, onRetry }: {
  readonly results: Partial<Record<Part, PartResult>>;
  readonly busy: boolean;
  readonly onRetry: (part: Part) => void;
}) {
  const parts = (["triage", "reach"] as const).filter((part) => results[part]);
  if (parts.length === 0) return null;
  return (
    <ul aria-label="Save results" className="grid gap-1.5 text-body">
      {parts.map((part) => {
        const result = results[part]!;
        return (
          <li
            key={part}
            className={result.ok
              ? "text-muted-foreground"
              : "text-destructive flex flex-wrap items-center gap-2"}
          >
            {result.text}
            {result.retry && (
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={busy}
                onClick={() => onRetry(part)}
              >
                {part === "triage" ? "Retry the decision" : "Retry reachability"}
              </Button>
            )}
          </li>
        );
      })}
    </ul>
  );
}
