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
import { Button } from "@/components/ui/button";
import { isUuid } from "@/lib/uuid";
import type { ProjectRole } from "@/types/api";
import { useState } from "react";
import { useParams } from "react-router-dom";

function RoleBadge({ role }: { role: ProjectRole; }) {
  const styles: Record<ProjectRole, string> = {
    admin:
      "bg-[oklch(0.92_0.05_305)] text-[oklch(0.4_0.14_305)] dark:bg-[oklch(0.28_0.06_305)] dark:text-[oklch(0.85_0.1_305)]",
    manager:
      "bg-[oklch(0.92_0.04_250)] text-[oklch(0.4_0.12_250)] dark:bg-[oklch(0.28_0.05_250)] dark:text-[oklch(0.85_0.08_250)]",
    member: "bg-muted text-muted-foreground",
  };

  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider ${
        styles[role]
      }`}
    >
      {role}
    </span>
  );
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

  function resolveUserLabel(userId: string) {
    const user = directory?.find((u) => u.id === userId);
    if (user) {
      return {
        name: user.display_name || user.email,
        email: user.email,
      };
    }
    return {
      name: userId,
      email: null,
    };
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
          <span aria-hidden="true">🛡️</span>
          <div>
            <strong>Manager Authority:</strong>{" "}
            You can manage direct members and link company teams. Assigning or removing Admin roles
            is restricted to Project Admins.
          </div>
        </div>
      )}

      {currentRole === "member" && (
        <div className="border border-border bg-muted/50 text-muted-foreground rounded-lg p-3 text-sm flex items-center gap-2">
          <span aria-hidden="true">🔒</span>
          <div>
            <strong>Read-Only Member View:</strong>{" "}
            You are viewing project members and linked teams. Modifications require Project Manager
            or Admin authority.
          </div>
        </div>
      )}

      {/* Direct Members Section */}
      <section className="bg-card border border-border rounded-lg overflow-hidden shadow-xs">
        <div className="p-4 sm:p-5 border-b border-border flex items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold flex items-center gap-2">
              Direct Members
              <span className="bg-muted text-muted-foreground rounded-full px-2 py-0.5 text-xs font-normal">
                {members?.length ?? 0}
              </span>
            </h2>
            <p className="text-muted-foreground text-xs mt-0.5">
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
          ? <div className="p-6 text-center text-muted-foreground text-sm">Loading members...</div>
          : membersError
          ? (
            <div className="p-6 text-center text-sm">
              <p className="text-destructive mb-2">Could not load members.</p>
              <button
                type="button"
                className="text-action underline hover:no-underline"
                onClick={() => refetchMembers()}
              >
                Retry
              </button>
            </div>
          )
          : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="bg-muted text-muted-foreground text-xs uppercase tracking-wider border-b border-border">
                    <th scope="col" className="px-5 py-3">User</th>
                    <th scope="col" className="px-5 py-3">Role</th>
                    <th scope="col" className="px-5 py-3">Added</th>
                    <th scope="col" className="px-5 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {members && members.length > 0
                    ? (
                      members.map((member) => {
                        const { name, email } = resolveUserLabel(member.user_id);
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
                          <tr key={member.user_id} className="hover:bg-muted/30">
                            <td className="px-5 py-3.5">
                              <div className="font-medium text-foreground">{name}</div>
                              {email && (
                                <div className="text-muted-foreground text-xs">{email}</div>
                              )}
                            </td>
                            <td className="px-5 py-3.5">
                              <RoleBadge role={member.role} />
                            </td>
                            <td className="px-5 py-3.5 text-muted-foreground text-xs">
                              {new Date(member.created_at).toLocaleDateString()}
                            </td>
                            <td className="px-5 py-3.5 text-right">
                              {canManageMembers
                                ? (
                                  <Button
                                    variant="ghost"
                                    size="xs"
                                    disabled={!canRemove || removeMemberMutation.isPending}
                                    title={disabledReason}
                                    className="text-destructive hover:bg-destructive/10"
                                    onClick={() => removeMemberMutation.mutate(member.user_id)}
                                  >
                                    Remove
                                  </Button>
                                )
                                : <span className="text-muted-foreground text-xs">View only</span>}
                            </td>
                          </tr>
                        );
                      })
                    )
                    : (
                      <tr>
                        <td
                          colSpan={4}
                          className="px-5 py-6 text-center text-muted-foreground text-sm"
                        >
                          No direct members granted yet.
                        </td>
                      </tr>
                    )}
                </tbody>
              </table>
            </div>
          )}
        {removeMemberMutation.isError && (
          <p role="alert" className="border-t border-border px-5 py-3 text-destructive text-xs">
            {removeMemberMutation.error?.message ?? "Failed to remove member"}
          </p>
        )}
      </section>

      {/* Linked Teams Section */}
      <section className="bg-card border border-border rounded-lg overflow-hidden shadow-xs">
        <div className="p-4 sm:p-5 border-b border-border flex items-center justify-between gap-4">
          <div>
            <h2 className="text-base font-semibold flex items-center gap-2">
              Linked Teams
              <span className="bg-muted text-muted-foreground rounded-full px-2 py-0.5 text-xs font-normal">
                {teams?.length ?? 0}
              </span>
            </h2>
            <p className="text-muted-foreground text-xs mt-0.5">
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
          ? (
            <div className="p-6 text-center text-muted-foreground text-sm">
              Loading linked teams...
            </div>
          )
          : teamsError
          ? (
            <div className="p-6 text-center text-sm">
              <p className="text-destructive mb-2">Could not load linked teams.</p>
              <button
                type="button"
                className="text-action underline hover:no-underline"
                onClick={() => refetchTeams()}
              >
                Retry
              </button>
            </div>
          )
          : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-sm">
                <thead>
                  <tr className="bg-muted text-muted-foreground text-xs uppercase tracking-wider border-b border-border">
                    <th scope="col" className="px-5 py-3">Team Name</th>
                    <th scope="col" className="px-5 py-3">Inherited Role</th>
                    <th scope="col" className="px-5 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {teams && teams.length > 0
                    ? (
                      teams.map((team) => {
                        const isRestrictedAdminTeam = !isAdmin && team.role === "admin";
                        const canUnlink = canManageMembers && !isRestrictedAdminTeam;

                        return (
                          <tr key={team.team_id} className="hover:bg-muted/30">
                            <td className="px-5 py-3.5 font-medium text-foreground">
                              {team.team_name}
                            </td>
                            <td className="px-5 py-3.5">
                              <RoleBadge role={team.role} />
                            </td>
                            <td className="px-5 py-3.5 text-right">
                              {canManageMembers
                                ? (
                                  <Button
                                    variant="ghost"
                                    size="xs"
                                    disabled={!canUnlink || unlinkTeamMutation.isPending}
                                    title={isRestrictedAdminTeam
                                      ? "Only Project Admins can unlink Admin-tier teams"
                                      : undefined}
                                    className="text-destructive hover:bg-destructive/10"
                                    onClick={() => unlinkTeamMutation.mutate(team.team_id)}
                                  >
                                    Unlink
                                  </Button>
                                )
                                : <span className="text-muted-foreground text-xs">View only</span>}
                            </td>
                          </tr>
                        );
                      })
                    )
                    : (
                      <tr>
                        <td
                          colSpan={3}
                          className="px-5 py-6 text-center text-muted-foreground text-sm"
                        >
                          No company teams linked to this project.
                        </td>
                      </tr>
                    )}
                </tbody>
              </table>
            </div>
          )}
        {unlinkTeamMutation.isError && (
          <p role="alert" className="border-t border-border px-5 py-3 text-destructive text-xs">
            {unlinkTeamMutation.error?.message ?? "Failed to unlink team"}
          </p>
        )}
      </section>

      {/* Add Member Modal */}
      {showAddMember && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="add-member-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
        >
          <div className="bg-card border border-border rounded-lg max-w-md w-full p-6 shadow-xl">
            <h3 id="add-member-title" className="text-lg font-semibold text-foreground">
              Add Direct Member
            </h3>
            <p className="text-muted-foreground text-xs mt-1 mb-4">
              Grant a user direct permissions on this project.
            </p>
            <form onSubmit={handleAddMember} className="space-y-4">
              <div>
                <label
                  htmlFor="member-id-input"
                  className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
                >
                  User ID
                </label>
                <input
                  id="member-id-input"
                  required
                  value={memberUserId}
                  onChange={(e) => {
                    setMemberUserId(e.target.value);
                    setMemberInputError(null);
                    addMemberMutation.reset();
                  }}
                  placeholder="e.g. 3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f"
                  className="w-full px-3 py-2 border border-border rounded-md bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>

              <div>
                <label
                  htmlFor="member-role-select"
                  className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
                >
                  Project Role
                </label>
                <select
                  id="member-role-select"
                  value={memberRole}
                  onChange={(e) => setMemberRole(e.target.value as ProjectRole)}
                  className="w-full px-3 py-2 border border-border rounded-md bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="member">Member: view findings and reports</option>
                  <option value="manager">Manager: triage findings and manage members</option>
                  <option value="admin" disabled={!isAdmin}>
                    Admin: full project control {!isAdmin ? "(Project Admins only)" : ""}
                  </option>
                </select>
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

              <div className="flex justify-end gap-2 pt-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowAddMember(false)}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={addMemberMutation.isPending}>
                  {addMemberMutation.isPending ? "Adding..." : "Add Member"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Link Team Modal */}
      {showLinkTeam && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="link-team-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
        >
          <div className="bg-card border border-border rounded-lg max-w-md w-full p-6 shadow-xl">
            <h3 id="link-team-title" className="text-lg font-semibold text-foreground">
              Link Company Team
            </h3>
            <p className="text-muted-foreground text-xs mt-1 mb-4">
              Select an organization team from the central directory.
            </p>
            <form onSubmit={handleLinkTeam} className="space-y-4">
              <div>
                <label
                  htmlFor="link-team-select"
                  className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
                >
                  Company Team
                </label>
                <select
                  id="link-team-select"
                  required
                  value={selectedTeamId}
                  onChange={(e) => setSelectedTeamId(e.target.value)}
                  className="w-full px-3 py-2 border border-border rounded-md bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="">Select a team...</option>
                  {allCompanyTeams?.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label
                  htmlFor="link-team-role-select"
                  className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
                >
                  Granted Role
                </label>
                <select
                  id="link-team-role-select"
                  value={teamRole}
                  onChange={(e) => setTeamRole(e.target.value as ProjectRole)}
                  className="w-full px-3 py-2 border border-border rounded-md bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="member">Member: view findings and reports</option>
                  <option value="manager">Manager: triage findings and manage members</option>
                  <option value="admin" disabled={!isAdmin}>
                    Admin: full project control {!isAdmin ? "(Project Admins only)" : ""}
                  </option>
                </select>
              </div>

              {linkTeamMutation.isError && (
                <p className="text-destructive text-xs">
                  {linkTeamMutation.error?.message ?? "Failed to link team"}
                </p>
              )}

              <div className="flex justify-end gap-2 pt-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowLinkTeam(false)}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={!selectedTeamId || linkTeamMutation.isPending}>
                  {linkTeamMutation.isPending ? "Linking..." : "Link Team"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
