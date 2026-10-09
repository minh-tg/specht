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
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
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
import { Textarea } from "@/components/ui/textarea";
import { isUuid } from "@/lib/uuid";
import type { Team } from "@/types/api";
import { useState } from "react";

function TeamCard({
  team,
  isGlobalAdmin,
  deleteError,
  onOpenRoster,
  onDeleteTeam,
}: {
  team: Team;
  isGlobalAdmin: boolean;
  deleteError?: string;
  onOpenRoster: (team: Team) => void;
  onDeleteTeam: (team: Team) => void;
}) {
  const { data: members, isError: membersError, refetch: refetchMembers } = useTeamMembers(
    team.id,
  );

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
          {membersError
            ? (
              <span className="flex items-center gap-2">
                <span className="text-destructive">Could not load members</span>
                <button
                  type="button"
                  className="text-action underline hover:no-underline"
                  onClick={() => refetchMembers()}
                >
                  Retry
                </button>
              </span>
            )
            : <span>{members?.length ?? 0} members</span>}
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
              onClick={() => onDeleteTeam(team)}
            >
              Delete
            </Button>
          )}
        </div>
        {deleteError && <p className="text-destructive text-xs mt-2">{deleteError}</p>}
      </div>
    </div>
  );
}

export function TeamsDirectory() {
  const me = useMe();
  const isGlobalAdmin = me.data?.role === "admin";

  const { data: teams, isLoading: teamsLoading, isError: teamsError, refetch: refetchTeams } =
    useTeams();
  const createTeamMutation = useCreateTeam();
  const deleteTeamMutation = useDeleteTeam();

  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTeamName, setNewTeamName] = useState("");
  const [newTeamDesc, setNewTeamDesc] = useState("");

  // The roster and delete dialogs keep their team until the exit animation ends, so the
  // content does not blank while the dialog fades out.
  const [activeRosterTeam, setActiveRosterTeam] = useState<Team | null>(null);
  const [rosterOpen, setRosterOpen] = useState(false);
  const [teamToDelete, setTeamToDelete] = useState<Team | null>(null);
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [rosterUserId, setRosterUserId] = useState("");
  const [rosterRole, setRosterRole] = useState<"admin" | "member">("member");
  const [rosterInputError, setRosterInputError] = useState<string | null>(null);

  const {
    data: activeMembers,
    isLoading: rosterLoading,
    isError: rosterError,
    refetch: refetchRoster,
  } = useTeamMembers(activeRosterTeam?.id ?? "");
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
    const userId = rosterUserId.trim();
    if (!userId) return;
    if (!isUuid(userId)) {
      setRosterInputError(
        "User ID must be a UUID, for example 3f9c1d2e-6b7a-4c1e-9f0a-2d8e5b6c7a8f.",
      );
      return;
    }
    setRosterInputError(null);
    try {
      await addMemberMutation.mutateAsync({ userId, role: rosterRole });
      setRosterUserId("");
      setRosterRole("member");
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
        : teamsError
        ? (
          <div className="bg-card border border-border rounded-lg p-12 text-center">
            <p className="text-destructive text-sm mb-4">Could not load company teams.</p>
            <Button variant="outline" onClick={() => refetchTeams()}>Retry</Button>
          </div>
        )
        : teams && teams.length > 0
        ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {teams.map((team) => (
              <TeamCard
                key={team.id}
                team={team}
                isGlobalAdmin={isGlobalAdmin}
                deleteError={deleteTeamMutation.isError && deleteTeamMutation.variables === team.id
                  ? deleteTeamMutation.error?.message ?? "Failed to delete team"
                  : undefined}
                onOpenRoster={(t) => {
                  setActiveRosterTeam(t);
                  setRosterOpen(true);
                }}
                onDeleteTeam={(t) => {
                  setTeamToDelete(t);
                  setDeleteOpen(true);
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

      <Dialog open={showCreateModal} onOpenChange={setShowCreateModal}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>Create Company Team</DialogTitle>
            <DialogDescription>Add a new group to the central company directory.</DialogDescription>
          </DialogHeader>
          <form onSubmit={handleCreateTeam} className="grid gap-4">
            <div>
              <label
                htmlFor="team-name-input"
                className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
              >
                Team Name
              </label>
              <Input
                id="team-name-input"
                required
                value={newTeamName}
                onChange={(e) => setNewTeamName(e.target.value)}
                placeholder="e.g. Security Operations"
              />
            </div>

            <div>
              <label
                htmlFor="team-desc-input"
                className="block text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-1"
              >
                Description
              </label>
              <Textarea
                id="team-desc-input"
                rows={3}
                value={newTeamDesc}
                onChange={(e) => setNewTeamDesc(e.target.value)}
                placeholder="Scope and purpose of this team..."
              />
            </div>

            {createTeamMutation.isError && (
              <p className="text-destructive text-xs">
                {createTeamMutation.error?.message ?? "Failed to create team"}
              </p>
            )}

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setShowCreateModal(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={createTeamMutation.isPending}>
                {createTeamMutation.isPending ? "Creating..." : "Create Team"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog
        open={rosterOpen}
        onOpenChange={setRosterOpen}
        onOpenChangeComplete={(open) => {
          if (!open) setActiveRosterTeam(null);
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>{activeRosterTeam?.name} members</DialogTitle>
            <DialogDescription>
              {activeRosterTeam?.description || "Manage individuals in this company team."}
            </DialogDescription>
          </DialogHeader>

          {isGlobalAdmin && (
            <form onSubmit={handleAddRosterMember} className="space-y-2">
              <div className="flex gap-2">
                <Input
                  required
                  aria-label="User ID"
                  value={rosterUserId}
                  onChange={(e) => {
                    setRosterUserId(e.target.value);
                    setRosterInputError(null);
                    addMemberMutation.reset();
                  }}
                  placeholder="User ID"
                  className="flex-1"
                />
                <select
                  aria-label="Team role"
                  value={rosterRole}
                  onChange={(e) => setRosterRole(e.target.value as "admin" | "member")}
                  className="px-2 py-1.5 border border-border rounded-md bg-background text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                >
                  <option value="member">Member</option>
                  <option value="admin">Admin</option>
                </select>
                <Button type="submit" size="sm" disabled={addMemberMutation.isPending}>
                  {addMemberMutation.isPending ? "Adding..." : "Add"}
                </Button>
              </div>
              {rosterInputError && <p className="text-destructive text-xs">{rosterInputError}</p>}
              {addMemberMutation.isError && (
                <p className="text-destructive text-xs">
                  {addMemberMutation.error?.message ?? "Failed to add member"}
                </p>
              )}
            </form>
          )}

          <div className="border border-border rounded-md max-h-60 overflow-y-auto">
            {rosterLoading
              ? (
                <div className="p-4 text-center text-muted-foreground text-xs">
                  Loading roster...
                </div>
              )
              : rosterError
              ? (
                <div className="p-4 text-center text-xs">
                  <p className="text-destructive mb-2">Could not load the roster.</p>
                  <button
                    type="button"
                    className="text-action underline hover:no-underline"
                    onClick={() => refetchRoster()}
                  >
                    Retry
                  </button>
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
          {removeMemberMutation.isError && (
            <p className="text-destructive text-xs">
              {removeMemberMutation.error?.message ?? "Failed to remove member"}
            </p>
          )}

          <DialogFooter>
            <Button variant="outline" onClick={() => setRosterOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <AlertDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        onOpenChangeComplete={(open) => {
          if (!open) setTeamToDelete(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete {teamToDelete?.name ?? "this team"}?</AlertDialogTitle>
            <AlertDialogDescription>This cannot be undone.</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                if (teamToDelete) deleteTeamMutation.mutate(teamToDelete.id);
                setDeleteOpen(false);
              }}
            >
              Delete team
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
