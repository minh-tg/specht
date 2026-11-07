import { useAssignFinding, useProjectMembers, useProjectRole } from "@/api/hooks";
import { AuthContext } from "@/auth/context";
import { SelectField } from "@/components/SelectField";
import { Button } from "@/components/ui/button";
import type { Finding } from "@/types/api";
import { useContext } from "react";

const NOBODY = "";

/**
 * Who owns this finding. A manager picks anyone in the project. A member can take it or let go of
 * their own, which changes no verdict.
 */
export function AssigneeControl({ finding, slug }: {
  readonly finding: Finding;
  readonly slug: string;
}) {
  const userId = useContext(AuthContext)?.userId;
  const { canTriage } = useProjectRole(slug);
  const { data } = useProjectMembers(slug);
  // Go serializes an empty list as null.
  const members = Array.isArray(data) ? data : [];
  const assign = useAssignFinding();
  const current = finding.assignee;
  const mine = !!current && current.user_id === userId;

  const send = (userId: string) => assign.mutate({ findingId: finding.id, userId });

  return (
    <div className="border-border grid gap-1 border-t pt-4">
      <p className="text-muted-foreground text-meta">Assigned to</p>
      {canTriage
        ? (
          <SelectField
            aria-label="Assigned to"
            size="sm"
            value={current?.user_id ?? NOBODY}
            disabled={assign.isPending}
            onValueChange={send}
            options={[
              { value: NOBODY, label: "Nobody" },
              ...(current && !members.some((m) => m.user_id === current.user_id)
                ? [{ value: current.user_id, label: current.name }]
                : []),
              ...members.map((m) => ({
                value: m.user_id,
                label: m.display_name || m.email || m.user_id,
              })),
            ]}
          />
        )
        : <p className="text-body">{current?.name ?? "Nobody"}</p>}
      {!canTriage && (!current || mine) && (
        <Button
          type="button"
          size="sm"
          variant="outline"
          className="justify-self-start"
          disabled={assign.isPending || !userId}
          onClick={() => send(mine ? NOBODY : userId ?? NOBODY)}
        >
          {mine ? "Let go" : "Take it"}
        </Button>
      )}
      {assign.isError && (
        <p role="alert" className="text-destructive text-meta">Could not change this. Try again.</p>
      )}
    </div>
  );
}
