import {
  useAddTeamMember,
  useCapabilities,
  useCreateTeam,
  useDeleteTeam,
  useMe,
  useRemoveTeamMember,
  useTeamMembers,
  useTeams,
} from "@/api/hooks";
import { suggestFromDirectory } from "@/api/memberSuggestions";
import { useUserDirectory } from "@/api/users";
import { EmptyState } from "@/components/EmptyState";
import { ErrorState } from "@/components/ErrorState";
import { INLINE_LINK } from "@/components/inlineLink";
import { OpenRegistrationNote } from "@/components/OpenRegistrationNote";
import { PersonCombobox } from "@/components/PersonCombobox";
import { SelectField } from "@/components/SelectField";
import { SkeletonLines } from "@/components/SkeletonLines";
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
import { looksLikeEmail } from "@/lib/email";
import type { Team, TeamMember } from "@/types/api";
import { useState } from "react";

/**
 * Whether the caller may add and remove people on a team: a global admin, or an admin of that
 * team, the same rule the server applies. Deleting a team stays with global admins.
 */
function canManageRoster(
  isGlobalAdmin: boolean,
  userId: string | undefined,
  members: readonly TeamMember[] | undefined,
): boolean {
  if (isGlobalAdmin) return true;
  if (!userId || !members) return false;
  return members.some((m) => m.user_id === userId && m.role === "admin");
}

function TeamCard({
  team,
  isGlobalAdmin,
  userId,
  deleteError,
  onOpenRoster,
  onDeleteTeam,
}: {
  team: Team;
  isGlobalAdmin: boolean;
  userId: string | undefined;
  deleteError?: string;
  onOpenRoster: (team: Team) => void;
  onDeleteTeam: (team: Team) => void;
}) {
  const { data: members, isError: membersError, refetch: refetchMembers } = useTeamMembers(
    team.id,
  );
  const canManage = canManageRoster(isGlobalAdmin, userId, members);

  return (
    <div className="bg-card border border-border rounded-lg p-5 flex flex-col justify-between shadow-xs">
      <div>
        <h3 className="font-semibold text-body text-foreground mb-1">{team.name}</h3>
        <p className="text-muted-foreground text-meta line-clamp-2 mb-4">
          {team.description || "No description provided."}
        </p>
      </div>

      <div>
        <div className="flex items-center justify-between pt-3 border-t border-border text-meta text-muted-foreground mb-3">
          {membersError
            ? (
              <span className="flex items-center gap-2">
                <span className="text-destructive">Could not load members</span>
                <button
                  type="button"
                  className={INLINE_LINK}
                  onClick={() => refetchMembers()}
                >
                  Retry
                </button>
              </span>
            )
            : <span>{members?.length ?? 0} members</span>}
          {team.created_at && <span>Created {new Date(team.created_at).toLocaleDateString()}</span>}
        </div>

        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            className="flex-1"
            onClick={() => onOpenRoster(team)}
          >
            {canManage ? "Manage Roster" : "View Roster"}
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
        {deleteError && <p className="text-destructive text-meta mt-2">{deleteError}</p>}
      </div>
    </div>
  );
}

const TEAM_ROLE_OPTIONS = [
  { value: "member", label: "Member" },
  { value: "admin", label: "Admin" },
] as const;

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
  const [rosterEmail, setRosterEmail] = useState("");
  const [rosterRole, setRosterRole] = useState<"admin" | "member">("member");
  const [rosterInputError, setRosterInputError] = useState<string | null>(null);

  const {
    data: activeMembers,
    isLoading: rosterLoading,
    isError: rosterError,
    refetch: refetchRoster,
  } = useTeamMembers(activeRosterTeam?.id ?? "");

  const canManageActiveRoster = canManageRoster(isGlobalAdmin, me.data?.id, activeMembers);

  const addMemberMutation = useAddTeamMember(activeRosterTeam?.id ?? "");
  // Instance admins have the user directory loaded already, so their suggestions are filtered in
  // the browser with the server's rules instead of asked for per key. A team admin cannot read
  // the directory and types the address without suggestions.
  const { data: directory } = useUserDirectory();
  const registrationOpen = useCapabilities().data?.registration?.enabled !== false;
  // Nothing is offered until the members have loaded, or people already on the team would show up.
  const rosterSuggestionsActive = !registrationOpen && !!directory && !!activeMembers
    && [...rosterEmail.trim()].length >= 3;
  const rosterSuggestions = rosterSuggestionsActive
    ? suggestFromDirectory(directory, rosterEmail, new Set(activeMembers.map((m) => m.user_id)))
    : [];
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
    const email = rosterEmail.trim();
    if (!email) return;
    if (!looksLikeEmail(email)) {
      setRosterInputError("Enter the person's email address, for example ada@example.com.");
      return;
    }
    setRosterInputError(null);
    try {
      await addMemberMutation.mutateAsync({ email, role: rosterRole });
      setRosterEmail("");
      setRosterRole("member");
    } catch {}
  }

  return (
    <div className="mx-auto max-w-5xl px-4 py-8 space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-title font-bold">Company Teams</h1>
          <p className="text-muted-foreground text-body mt-1">
            Central organization teams for managing permissions across projects.
          </p>
        </div>

        {isGlobalAdmin
          ? <Button onClick={() => setShowCreateModal(true)}>+ Create Team</Button>
          : (
            <div className="text-muted-foreground text-meta bg-muted px-3 py-1.5 rounded-md border border-border">
              Global Admin required to create teams
            </div>
          )}
      </div>

      {teamsLoading
        ? <SkeletonLines label="Loading teams" lines={4} className="py-6" />
        : teamsError
        ? <ErrorState title="Could not load company teams." onRetry={() => refetchTeams()} />
        : teams && teams.length > 0
        ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
            {teams.map((team) => (
              <TeamCard
                key={team.id}
                team={team}
                isGlobalAdmin={isGlobalAdmin}
                userId={me.data?.id}
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
          <EmptyState
            title="No company teams exist yet."
            action={isGlobalAdmin
              ? <Button onClick={() => setShowCreateModal(true)}>Create First Team</Button>
              : undefined}
          />
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
                className="block text-meta font-semibold uppercase tracking-wider text-muted-foreground mb-1"
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
                className="block text-meta font-semibold uppercase tracking-wider text-muted-foreground mb-1"
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
              <p className="text-destructive text-meta">
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

          {canManageActiveRoster && (
            <form onSubmit={handleAddRosterMember} className="space-y-2">
              <div className="flex gap-2">
                <div className="flex-1">
                  <PersonCombobox
                    id="roster-email-input"
                    required
                    aria-label="Email address"
                    value={rosterEmail}
                    onValueChange={(value) => {
                      setRosterEmail(value);
                      setRosterInputError(null);
                      addMemberMutation.reset();
                    }}
                    suggestions={rosterSuggestions}
                    active={rosterSuggestionsActive}
                    placeholder="Email address"
                  />
                </div>
                <SelectField
                  aria-label="Team role"
                  value={rosterRole}
                  onValueChange={(v) => setRosterRole(v === "admin" ? "admin" : "member")}
                  options={TEAM_ROLE_OPTIONS}
                />
                <Button type="submit" size="sm" disabled={addMemberMutation.isPending}>
                  {addMemberMutation.isPending ? "Adding..." : "Add"}
                </Button>
              </div>
              <OpenRegistrationNote />
              {rosterInputError && <p className="text-destructive text-meta">{rosterInputError}</p>}
              {addMemberMutation.isError && (
                <p className="text-destructive text-meta">
                  {addMemberMutation.error?.message ?? "Failed to add member"}
                </p>
              )}
            </form>
          )}

          <div className="border border-border rounded-md max-h-60 overflow-y-auto">
            {rosterLoading
              ? <SkeletonLines label="Loading roster" className="p-4" />
              : rosterError
              ? (
                <div className="p-4">
                  <ErrorState title="Could not load the roster." onRetry={() => refetchRoster()} />
                </div>
              )
              : activeMembers && activeMembers.length > 0
              ? (
                <ul className="divide-y divide-border text-body">
                  {activeMembers.map((member) => (
                    <li
                      key={member.user_id}
                      className="px-4 py-2.5 flex items-center justify-between hover:bg-muted/30"
                    >
                      <span className="min-w-0">
                        <span className="block font-medium text-foreground">
                          {member.display_name || member.user_email || "Unnamed account"}
                        </span>
                        {member.display_name && member.user_email && (
                          <span className="block text-meta text-muted-foreground">
                            {member.user_email}
                          </span>
                        )}
                      </span>
                      {canManageActiveRoster && (
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
                <div className="p-4 text-center text-muted-foreground text-meta">
                  No members in this team yet.
                </div>
              )}
          </div>
          {removeMemberMutation.isError && (
            <p className="text-destructive text-meta">
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
