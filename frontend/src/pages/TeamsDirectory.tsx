import {
  useAddTeamMember,
  useCreateTeam,
  useDeleteTeam,
  useMe,
  useRemoveTeamMember,
  useTeamMembers,
  useTeams,
} from "@/api/hooks";
import { useUserDirectory } from "@/api/users";
import { Button } from "@/components/ui/button";
import type { Team } from "@/types/api";
import { useState } from "react";

function TeamCard({
  team,
  isGlobalAdmin,
  onOpenRoster,
  onDeleteTeam,
}: {
  team: Team;
  isGlobalAdmin: boolean;
  onOpenRoster: (team: Team) => void;
  onDeleteTeam: (teamId: string) => void;
}) {
  const { data: members } = useTeamMembers(team.id);

  return (
    <div className="bg-card border border-border rounded-lg p-5 flex flex-col justify-between shadow-xs">
      <div>
        <h3 className="font-semibold text-base text-foreground mb-1">{team.name}</h3>
        <p className="text-muted-foreground text-xs line-clamp-2 mb-4">
          {team.description || "No description provided."}
        </p>
      </div>

      <div>
        <div className="flex items-center justify-between pt-3 border-t border-border text-xs text-muted-foreground mb-3">
          <span>👥 {members?.length ?? 0} members</span>
          <span>Created {new Date(team.created_at).toLocaleDateString()}</span>
        </div>

        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            className="flex-1"
            onClick={() => onOpenRoster(team)}
          >
            {isGlobalAdmin ? "Manage Roster" : "View Roster"}
          </Button>
          {isGlobalAdmin && (
            <Button
              variant="ghost"
              size="sm"
              className="text-destructive hover:bg-destructive/10"
              onClick={() => onDeleteTeam(team.id)}
            >
              Delete
            </Button>
          )}
        </div>
      </div>
    </div>
  );
}

export function TeamsDirectory() {
  const me = useMe();
  const isGlobalAdmin = me.data?.role === "admin";

  const { data: teams, isLoading: teamsLoading } = useTeams();
  const createTeamMutation = useCreateTeam();
  const deleteTeamMutation = useDeleteTeam();

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTeamName, setNewTeamName] = useState("");
  const [newTeamDesc, setNewTeamDesc] = useState("");

  const [activeRosterTeam, setActiveRosterTeam] = useState<Team | null>(null);
  const [rosterUserId, setRosterUserId] = useState("");

  const { data: activeMembers, isLoading: rosterLoading } = useTeamMembers(
    activeRosterTeam?.id ?? "",
  );
  const { data: directory } = useUserDirectory();

  const addMemberMutation = useAddTeamMember(activeRosterTeam?.id ?? "");
  const removeMemberMutation = useRemoveTeamMember(activeRosterTeam?.id ?? "");

  async function handleCreateTeam(e: React.FormEvent) {
    e.preventDefault();
    if (!newTeamName.trim()) return;
    try {
      await createTeamMutation.mutateAsync({
        name: newTeamName.trim(),
        description: newTeamDesc.trim() || undefined,
      });
      setNewTeamName("");
      setNewTeamDesc("");
      setShowCreateModal(false);
    } catch {}
  }

  async function handleAddRosterMember(e: React.FormEvent) {
    e.preventDefault();
    if (!rosterUserId.trim()) return;
    try {
      await addMemberMutation.mutateAsync(rosterUserId.trim());
      setRosterUserId("");
    } catch {}
  }

  function resolveUserLabel(userId: string) {
    const user = directory?.find((u) => u.id === userId);
    if (user) {
      return user.display_name || user.email;
    }
    return userId;
  }

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Company Teams</h1>
          <p className="text-muted-foreground text-sm mt-1">
            Central organization teams for managing permissions across projects.
          </p>
        </div>

        {isGlobalAdmin
          ? <Button onClick={() => setShowCreateModal(true)}>+ Create Team</Button>
          : (
            <div className="text-muted-foreground text-xs bg-muted px-3 py-1.5 rounded-md border border-border">
              Global Admin required to create teams
            </div>
          )}
      </div>

      {teamsLoading
        ? <div className="py-12 text-center text-muted-foreground text-sm">Loading teams...</div>
        : teams && teams.length > 0
        ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {teams.map((team) => (
              <TeamCard
                key={team.id}
                team={team}
                isGlobalAdmin={isGlobalAdmin}
                onOpenRoster={(t) => setActiveRosterTeam(t)}
                onDeleteTeam={(id) => {
                  if (window.confirm("Are you sure you want to delete this company team?")) {
                    deleteTeamMutation.mutate(id);
                  }
                }}
              />
            ))}
          </div>
        )
        : (
          <div className="bg-card border border-border rounded-lg p-12 text-center">
            <p className="text-muted-foreground text-sm mb-4">No company teams exist yet.</p>
            {isGlobalAdmin && (
              <Button onClick={() => setShowCreateModal(true)}>Create First Team</Button>
            )}
          </div>
        )}

      {/* Create Team Modal */}
      {showCreateModal && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="create-team-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
        >
          <div className="bg-card border border-border rounded-lg max-w-md w-full p-6 shadow-xl">
            <h3 id="create-team-title" className="text-lg font-semibold text-foreground">
              Create Company Team
            </h3>
            <p className="text-muted-foreground text-xs mt-1 mb-4">
              Add a new group to the central company directory.
            </p>
            <form onSubmit={handleCreateTeam} className="space-y-4">
              <div>
                <label
                  htmlFor="team-name-input"
                  className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
                >
                  Team Name
                </label>
                <input
                  id="team-name-input"
                  required
                  value={newTeamName}
                  onChange={(e) => setNewTeamName(e.target.value)}
                  placeholder="e.g. Security Operations"
                  className="w-full px-3 py-2 border border-border rounded-md bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>

              <div>
                <label
                  htmlFor="team-desc-input"
                  className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
                >
                  Description
                </label>
                <textarea
                  id="team-desc-input"
                  rows={3}
                  value={newTeamDesc}
                  onChange={(e) => setNewTeamDesc(e.target.value)}
                  placeholder="Scope and purpose of this team..."
                  className="w-full px-3 py-2 border border-border rounded-md bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>

              {createTeamMutation.isError && (
                <p className="text-destructive text-xs">
                  {createTeamMutation.error?.message ?? "Failed to create team"}
                </p>
              )}

              <div className="flex justify-end gap-2 pt-2">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => setShowCreateModal(false)}
                >
                  Cancel
                </Button>
                <Button type="submit" disabled={createTeamMutation.isPending}>
                  {createTeamMutation.isPending ? "Creating..." : "Create Team"}
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Roster Modal */}
      {activeRosterTeam && (
        <div
          role="dialog"
          aria-modal="true"
          aria-labelledby="roster-modal-title"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
        >
          <div className="bg-card border border-border rounded-lg max-w-lg w-full p-6 shadow-xl space-y-4">
            <div>
              <h3 id="roster-modal-title" className="text-lg font-semibold text-foreground">
                {activeRosterTeam.name} — Members
              </h3>
              <p className="text-muted-foreground text-xs mt-0.5">
                {activeRosterTeam.description || "Manage individuals in this company team."}
              </p>
            </div>

            {isGlobalAdmin && (
              <form onSubmit={handleAddRosterMember} className="flex gap-2">
                <input
                  required
                  value={rosterUserId}
                  onChange={(e) => setRosterUserId(e.target.value)}
                  placeholder="User ID or email..."
                  className="flex-1 px-3 py-1.5 border border-border rounded-md bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
                <Button type="submit" size="sm" disabled={addMemberMutation.isPending}>
                  {addMemberMutation.isPending ? "Adding..." : "Add"}
                </Button>
              </form>
            )}

            <div className="border border-border rounded-md max-h-60 overflow-y-auto">
              {rosterLoading
                ? (
                  <div className="p-4 text-center text-muted-foreground text-xs">
                    Loading roster...
                  </div>
                )
                : activeMembers && activeMembers.length > 0
                ? (
                  <ul className="divide-y divide-border text-sm">
                    {activeMembers.map((member) => (
                      <li
                        key={member.user_id}
                        className="px-4 py-2.5 flex items-center justify-between hover:bg-muted/30"
                      >
                        <span className="font-medium text-foreground">
                          {resolveUserLabel(member.user_id)}
                        </span>
                        {isGlobalAdmin && (
                          <Button
                            variant="ghost"
                            size="xs"
                            className="text-destructive hover:bg-destructive/10"
                            disabled={removeMemberMutation.isPending}
                            onClick={() => removeMemberMutation.mutate(member.user_id)}
                          >
                            Remove
                          </Button>
                        )}
                      </li>
                    ))}
                  </ul>
                )
                : (
                  <div className="p-4 text-center text-muted-foreground text-xs">
                    No members in this team yet.
                  </div>
                )}
            </div>

            <div className="flex justify-end pt-2">
              <Button variant="outline" onClick={() => setActiveRosterTeam(null)}>
                Close
              </Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
