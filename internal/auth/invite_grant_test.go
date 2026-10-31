package auth

import "testing"

func TestMayGrantInvite(t *testing.T) {
	tests := []struct {
		name   string
		grant  InviteGrantor
		invite string
		want   bool
	}{
		{"manager hands out member", InviteGrantor{Active: true, DirectRole: RoleManager}, RoleMember, true},
		{"manager hands out manager", InviteGrantor{Active: true, DirectRole: RoleManager}, RoleManager, true},
		{"project admin hands out manager", InviteGrantor{Active: true, DirectRole: RoleAdmin}, RoleManager, true},
		{"global admin without a row", InviteGrantor{Active: true, GlobalRole: RoleAdmin}, RoleManager, true},
		{"deactivated manager", InviteGrantor{Active: false, DirectRole: RoleManager}, RoleMember, false},
		{"deactivated global admin", InviteGrantor{Active: false, GlobalRole: RoleAdmin}, RoleMember, false},
		{"demoted to member", InviteGrantor{Active: true, DirectRole: RoleMember}, RoleMember, false},
		{"removed from the project", InviteGrantor{Active: true}, RoleMember, false},
		{"former global admin with a member row", InviteGrantor{Active: true, GlobalRole: RoleViewer, DirectRole: RoleMember}, RoleManager, false},
		{"team manager hands out member", InviteGrantor{Active: true, DirectRole: RoleMember, TeamRole: RoleManager}, RoleMember, true},
		{"team manager cannot hand out manager", InviteGrantor{Active: true, DirectRole: RoleMember, TeamRole: RoleManager}, RoleManager, false},
		{"team only, no row", InviteGrantor{Active: true, TeamRole: RoleAdmin}, RoleManager, false},
		{"legacy editor row counts as manager", InviteGrantor{Active: true, DirectRole: RoleEditor}, RoleManager, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := MayGrantInvite(tc.grant, tc.invite); got != tc.want {
				t.Fatalf("MayGrantInvite(%+v, %q) = %v, want %v", tc.grant, tc.invite, got, tc.want)
			}
		})
	}
}
