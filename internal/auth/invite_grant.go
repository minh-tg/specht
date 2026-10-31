package auth

// InviteGrantor describes the account that made an invite, as it stands now.
type InviteGrantor struct {
	// Active is false for a deactivated account.
	Active bool
	// GlobalRole is the account's instance-wide role.
	GlobalRole string
	// DirectRole is the role of the account's own project_members row, empty
	// when it has none.
	DirectRole string
	// TeamRole is the strongest role a team link gives the account on the
	// project, empty when there is none.
	TeamRole string
}

// MayGrantInvite reports whether the grantor may hand out an invite for
// inviteRole on the project today. It is the rule CreateInvite applies when a
// link is made, applied again when the link is used: the creator must be able
// to manage the project's members, may not hand out more than their own role,
// and may hand out manager only on the strength of a direct project role, since
// a team link can be revoked and the row it wrote would stay.
func MayGrantInvite(g InviteGrantor, inviteRole string) bool {
	if !g.Active {
		return false
	}
	isAdmin := g.GlobalRole == RoleAdmin
	effective := g.DirectRole
	if RoleRank(g.TeamRole) > RoleRank(effective) {
		effective = g.TeamRole
	}
	if isAdmin {
		effective = RoleAdmin
	}
	if RoleRank(effective) < RoleRank(RoleManager) {
		return false
	}
	if RoleRank(inviteRole) > RoleRank(effective) {
		return false
	}
	if RoleRank(inviteRole) > RoleRank(RoleMember) && !isAdmin && RoleRank(g.DirectRole) < RoleRank(inviteRole) {
		return false
	}
	return true
}
