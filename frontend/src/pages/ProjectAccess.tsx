import {
  useAddProjectMember,
  useLinkProjectTeam,
  useProjectMembers,
  useProjectRole,
  useProjectTeams,
  useRemoveProjectMember,
  useTeams,
  useUnlinkProjectTeam,
} from "@/api/hooks";
import { useUserDirectory } from "@/api/users";
import { DisabledReason } from "@/components/DisabledReason";
import { ErrorState } from "@/components/ErrorState";
import { SelectField } from "@/components/SelectField";
import { SkeletonLines } from "@/components/SkeletonLines";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { isUuid } from "@/lib/uuid";
import type { ProjectMember, ProjectRole } from "@/types/api";
import { LockIcon, ShieldCheckIcon } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { InvitesSection } from "./project-access/InvitesSection";

/** The role as a word in an outline. The word carries the meaning; nothing relies on colour. */
function RoleBadge({ role }: { role: ProjectRole; }) {
  return (
    <span className="font-label border-border justify-self-start rounded border px-2 py-0.5 text-[0.6875rem]">
      {role}
    </span>
  );
}

function toProjectRole(value: string): ProjectRole {
  return value === "admin" || value === "manager" ? value : "member";
}

/** The grantable project roles; only a project admin may grant admin. */
function roleOptions(isAdmin: boolean) {
  return [
    { value: "member", label: "Member: view findings and reports" },
    { value: "manager", label: "Manager: triage findings and manage members" },
    {
      value: "admin",
      label: `Admin: full project control${isAdmin ? "" : " (Project Admins only)"}`,
      disabled: !isAdmin,
    },
  ];
}

export function ProjectAccess() {
  const { slug } = useParams<{ slug: string; }>();
  const currentSlug = slug ?? "";

  const {
    data: members,
    isLoading: membersLoading,
    isError: membersError,
    refetch: refetchMembers,
  } = useProjectMembers(currentSlug);
  const {
    data: teams,
    isLoading: teamsLoading,
    isError: teamsError,
    refetch: refetchTeams,
  } = useProjectTeams(currentSlug);
  const { data: directory } = useUserDirectory();
  const { data: allCompanyTeams } = useTeams();
  const { canManageMembers, isAdmin, role: currentRole } = useProjectRole(currentSlug);

  const addMemberMutation = useAddProjectMember(currentSlug);
  const removeMemberMutation = useRemoveProjectMember(currentSlug);
  const linkTeamMutation = useLinkProjectTeam(currentSlug);
  const unlinkTeamMutation = useUnlinkProjectTeam(currentSlug);

  const [showAddMember, setShowAddMember] = useState(false);
  const [memberUserId, setMemberUserId] = useState("");
  const [memberRole, setMemberRole] = useState<ProjectRole>("member");
  const [memberInputError, setMemberInputError] = useState<string | null>(null);

  const [showLinkTeam, setShowLinkTeam] = useState(false);
  const [selectedTeamId, setSelectedTeamId] = useState("");
  const [teamRole, setTeamRole] = useState<ProjectRole>("member");

  const adminCount = members?.filter((m) => m.role === "admin").length ?? 0;

  /**
   * Who a member is. The roster names them; the admin directory fills in for older answers. A raw id
   * is never shown: someone who cannot be named is "A team member".
   */
  function resolveUserLabel(member: ProjectMember) {
    if (member.email) {
      return { name: member.display_name || member.email, email: member.email };
    }
    const user = directory?.find((u) => u.id === member.user_id);
    if (user) {
      return { name: user.display_name || user.email, email: user.email };
    }
    return { name: "A team member", email: null };
  }

  async function handleAddMember(e: React.FormEvent) {
    e.preventDefault();
    const userId = memberUserId.trim();
    if (!userId) return;
    if (!isUuid(userId)) {
      setMemberInputError(
        "User ID must be a UUID, for example 3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f.",
      );
      return;
    }
    setMemberInputError(null);
    try {
      await addMemberMutation.mutateAsync({
        user_id: userId,
        role: memberRole,
      });
      setMemberUserId("");
      setMemberRole("member");
      setShowAddMember(false);
    } catch {}
  }

  async function handleLinkTeam(e: React.FormEvent) {
    e.preventDefault();
    if (!selectedTeamId) return;
    try {
      await linkTeamMutation.mutateAsync({
        team_id: selectedTeamId,
        role: teamRole,
      });
      setSelectedTeamId("");
      setTeamRole("member");
      setShowLinkTeam(false);
    } catch {}
  }

  return (
    <div className="space-y-8">
      {currentRole === "manager" && (
        <div className="border border-ring/40 bg-ring/5 text-foreground rounded-lg p-3 text-sm flex items-center gap-2">
          <ShieldCheckIcon aria-hidden="true" className="size-4 shrink-0" />
          <div>
            <strong>Manager Authority:</strong>{" "}
            You can manage direct members and link company teams. Assigning or removing Admin roles
            is restricted to Project Admins.
          </div>
        </div>
      )}

      {currentRole === "member" && (
        <div className="border border-border bg-muted/50 text-muted-foreground rounded-lg p-3 text-sm flex items-center gap-2">
          <LockIcon aria-hidden="true" className="size-4 shrink-0" />
          <div>
            <strong>Read-Only Member View:</strong>{" "}
            You are viewing project members and linked teams. Modifications require Project Manager
            or Admin authority.
          </div>
        </div>
      )}

      <section aria-labelledby="members-heading">
        <div className="flex items-end justify-between gap-4">
          <div>
            <h2 id="members-heading" className="flex items-center gap-2 text-lg font-semibold">
              Direct Members
              <span className="bg-muted text-muted-foreground rounded-full px-2 py-0.5 text-xs font-normal tabular-nums">
                {members?.length ?? 0}
              </span>
            </h2>
            <p className="text-muted-foreground mt-0.5 max-w-[60ch] text-sm">
              Individual contributors with explicit access grants on this project.
            </p>
          </div>
          {canManageMembers && (
            <Button size="sm" onClick={() => setShowAddMember(true)}>
              + Add Member
            </Button>
          )}
        </div>

        {membersLoading
          ? <SkeletonLines label="Loading members" className="mt-4" />
          : membersError
          ? (
            <div className="mt-4">
              <ErrorState title="Could not load members." onRetry={() => refetchMembers()} />
            </div>
          )
          : (
            <ul
              aria-label="Direct members"
              className="border-foreground m-0 mt-3 list-none border-t-2 p-0"
            >
              {members && members.length > 0
                ? (
                  members.map((member) => {
                    const { name, email } = resolveUserLabel(member);
                    const isLastAdmin = member.role === "admin" && adminCount <= 1;
                    const isPeerRestricted = !isAdmin
                      && (member.role === "admin" || member.role === "manager");
                    const canRemove = canManageMembers && !isLastAdmin && !isPeerRestricted;

                    let disabledReason: string | undefined;
                    if (isLastAdmin) {
                      disabledReason = "Cannot remove the last project admin";
                    } else if (isPeerRestricted) {
                      disabledReason = "Managers cannot modify fellow Managers or Admins";
                    }

                    return (
                      <li
                        key={member.user_id}
                        className="border-border grid items-center gap-x-5 gap-y-1 border-b px-0.5 py-3.5 sm:grid-cols-[minmax(0,1fr)_auto_auto_5.5rem]"
                      >
                        <div className="min-w-0">
                          <p className="truncate font-semibold">{name}</p>
                          {email && email !== name && (
                            <p className="text-muted-foreground truncate text-[0.8125rem]">
                              {email}
                            </p>
                          )}
                        </div>
                        <RoleBadge role={member.role} />
                        <span className="text-muted-foreground text-[0.8125rem]">
                          Added {new Date(member.created_at).toLocaleDateString()}
                        </span>
                        <div className="sm:text-right">
                          {canManageMembers
                            ? (
                              <DisabledReason reason={disabledReason}>
                                <Button
                                  variant="outline"
                                  size="sm"
                                  disabled={!canRemove || removeMemberMutation.isPending}
                                  onClick={() => removeMemberMutation.mutate(member.user_id)}
                                >
                                  Remove
                                </Button>
                              </DisabledReason>
                            )
                            : <span className="text-muted-foreground text-xs">View only</span>}
                        </div>
                      </li>
                    );
                  })
                )
                : (
                  <li className="text-muted-foreground border-border border-b py-5 text-sm">
                    No direct members granted yet.
                  </li>
                )}
            </ul>
          )}
        {removeMemberMutation.isError && (
          <p role="alert" className="text-destructive mt-2 text-xs">
            {removeMemberMutation.error?.message ?? "Failed to remove member"}
          </p>
        )}
      </section>

      {canManageMembers && <InvitesSection slug={currentSlug} />}

      <section aria-labelledby="teams-heading">
        <div className="flex items-end justify-between gap-4">
          <div>
            <h2 id="teams-heading" className="flex items-center gap-2 text-lg font-semibold">
              Linked Teams
              <span className="bg-muted text-muted-foreground rounded-full px-2 py-0.5 text-xs font-normal tabular-nums">
                {teams?.length ?? 0}
              </span>
            </h2>
            <p className="text-muted-foreground mt-0.5 max-w-[60ch] text-sm">
              Company-wide teams linked to delegate blanket role access.
            </p>
          </div>
          {canManageMembers && (
            <Button size="sm" onClick={() => setShowLinkTeam(true)}>
              + Link Team
            </Button>
          )}
        </div>

        {teamsLoading
          ? <SkeletonLines label="Loading linked teams" className="mt-4" />
          : teamsError
          ? (
            <div className="mt-4">
              <ErrorState title="Could not load linked teams." onRetry={() => refetchTeams()} />
            </div>
          )
          : (
            <ul
              aria-label="Linked teams"
              className="border-foreground m-0 mt-3 list-none border-t-2 p-0"
            >
              {teams && teams.length > 0
                ? (
                  teams.map((team) => {
                    const isRestrictedAdminTeam = !isAdmin && team.role === "admin";
                    const canUnlink = canManageMembers && !isRestrictedAdminTeam;

                    return (
                      <li
                        key={team.team_id}
                        className="border-border grid items-center gap-x-5 gap-y-1 border-b px-0.5 py-3.5 sm:grid-cols-[minmax(0,1fr)_auto_5.5rem]"
                      >
                        <p className="truncate font-semibold">{team.team_name}</p>
                        <RoleBadge role={team.role} />
                        <div className="sm:text-right">
                          {canManageMembers
                            ? (
                              <DisabledReason
                                reason={isRestrictedAdminTeam
                                  ? "Only Project Admins can unlink Admin-tier teams"
                                  : undefined}
                              >
                                <Button
                                  variant="outline"
                                  size="sm"
                                  disabled={!canUnlink || unlinkTeamMutation.isPending}
                                  onClick={() => unlinkTeamMutation.mutate(team.team_id)}
                                >
                                  Unlink
                                </Button>
                              </DisabledReason>
                            )
                            : <span className="text-muted-foreground text-xs">View only</span>}
                        </div>
                      </li>
                    );
                  })
                )
                : (
                  <li className="text-muted-foreground border-border border-b py-5 text-sm">
                    No company teams linked to this project.
                  </li>
                )}
            </ul>
          )}
        {unlinkTeamMutation.isError && (
          <p role="alert" className="text-destructive mt-2 text-xs">
            {unlinkTeamMutation.error?.message ?? "Failed to unlink team"}
          </p>
        )}
      </section>

      <Dialog open={showAddMember} onOpenChange={setShowAddMember}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Add Direct Member</DialogTitle>
            <DialogDescription>Grant a user direct permissions on this project.</DialogDescription>
          </DialogHeader>
          <form onSubmit={handleAddMember} className="grid gap-4">
            <div>
              <label
                htmlFor="member-id-input"
                className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
              >
                User ID
              </label>
              <Input
                id="member-id-input"
                required
                value={memberUserId}
                onChange={(e) => {
                  setMemberUserId(e.target.value);
                  setMemberInputError(null);
                  addMemberMutation.reset();
                }}
                placeholder="e.g. 3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f"
              />
            </div>

            <div>
              <label
                htmlFor="member-role-select"
                className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
              >
                Project Role
              </label>
              <SelectField
                id="member-role-select"
                className="w-full"
                value={memberRole}
                onValueChange={(v) => setMemberRole(toProjectRole(v))}
                options={roleOptions(isAdmin)}
              />
              {!isAdmin && (
                <p className="text-xs text-muted-foreground mt-1">
                  * Only Project Admins can grant the Admin role.
                </p>
              )}
            </div>

            {memberInputError && <p className="text-destructive text-xs">{memberInputError}</p>}
            {addMemberMutation.isError && (
              <p className="text-destructive text-xs">
                {addMemberMutation.error?.message ?? "Failed to add member"}
              </p>
            )}

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowAddMember(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={addMemberMutation.isPending}>
                {addMemberMutation.isPending ? "Adding..." : "Add Member"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={showLinkTeam} onOpenChange={setShowLinkTeam}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Link Company Team</DialogTitle>
            <DialogDescription>
              Select an organization team from the central directory.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleLinkTeam} className="grid gap-4">
            <div>
              <label
                htmlFor="link-team-select"
                className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
              >
                Company Team
              </label>
              <SelectField
                id="link-team-select"
                required
                className="w-full"
                value={selectedTeamId}
                onValueChange={setSelectedTeamId}
                options={[
                  { value: "", label: "Select a team..." },
                  ...(allCompanyTeams ?? []).map((t) => ({ value: t.id, label: t.name })),
                ]}
              />
            </div>

            <div>
              <label
                htmlFor="link-team-role-select"
                className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
              >
                Granted Role
              </label>
              <SelectField
                id="link-team-role-select"
                className="w-full"
                value={teamRole}
                onValueChange={(v) => setTeamRole(toProjectRole(v))}
                options={roleOptions(isAdmin)}
              />
            </div>

            {linkTeamMutation.isError && (
              <p className="text-destructive text-xs">
                {linkTeamMutation.error?.message ?? "Failed to link team"}
              </p>
            )}

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowLinkTeam(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={!selectedTeamId || linkTeamMutation.isPending}>
                {linkTeamMutation.isPending ? "Linking..." : "Link Team"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  );
}
