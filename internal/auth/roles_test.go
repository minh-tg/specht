package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRoleRank(t *testing.T) {
	assert.Equal(t, 3, RoleRank(RoleAdmin))
	assert.Equal(t, 2, RoleRank(RoleManager))
	assert.Equal(t, 2, RoleRank("editor"))
	assert.Equal(t, 1, RoleRank(RoleMember))
	assert.Equal(t, 1, RoleRank("viewer"))
	assert.Equal(t, 0, RoleRank("unknown"))
	assert.Equal(t, 0, RoleRank(""))

	assert.True(t, RoleRank(RoleAdmin) > RoleRank(RoleManager))
	assert.True(t, RoleRank(RoleManager) > RoleRank(RoleMember))
}

func TestRoleScope(t *testing.T) {
	scope, ok := RoleScope(RoleAdmin)
	assert.True(t, ok)
	assert.Equal(t, ScopeAdmin, scope)

	scope, ok = RoleScope(RoleManager)
	assert.True(t, ok)
	assert.Equal(t, ScopeAdmin, scope)

	scope, ok = RoleScope(RoleMember)
	assert.True(t, ok)
	assert.Equal(t, ScopeRead, scope)

	scope, ok = RoleScope("editor")
	assert.True(t, ok)
	assert.Equal(t, ScopeAdmin, scope)

	scope, ok = RoleScope("viewer")
	assert.True(t, ok)
	assert.Equal(t, ScopeRead, scope)

	_, ok = RoleScope("invalid")
	assert.False(t, ok)
}

func TestValidRole(t *testing.T) {
	assert.True(t, ValidRole(RoleAdmin))
	assert.True(t, ValidRole(RoleManager))
	assert.True(t, ValidRole(RoleMember))
	assert.True(t, ValidRole("editor"))
	assert.True(t, ValidRole("viewer"))
	assert.False(t, ValidRole("guest"))
	assert.False(t, ValidRole(""))
}

func TestTokenRole(t *testing.T) {
	assert.Equal(t, RoleAdmin, TokenRole(RoleAdmin))
	assert.Equal(t, RoleMember, TokenRole(RoleMember))
	assert.Equal(t, RoleManager, TokenRole(RoleManager))
	assert.Equal(t, RoleManager, TokenRole("editor"))
	assert.Equal(t, RoleMember, TokenRole("viewer"))
}
