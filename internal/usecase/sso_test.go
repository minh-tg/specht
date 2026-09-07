package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/port"
)

func ssoTestDeps(ur *mockUserRepo) Deps {
	return Deps{Stores: &port.Stores{Users: ur}}
}

func TestFindOrProvisionSSOUser_ExistingKeepsLocalRole(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		u := makeUser("user-1")
		u.Email = email
		u.Role = "admin"
		return u, nil
	}
	uc := New(ssoTestDeps(ur))
	userID, role, provisioned, err := uc.FindOrProvisionSSOUser(context.Background(), "sub-1", "Ada@Example.COM", nil)
	require.NoError(t, err)
	assert.Equal(t, "user-1", userID)
	assert.Equal(t, auth.RoleAdmin, role, "existing accounts keep their local role")
	assert.False(t, provisioned)
}

func TestFindOrProvisionSSOUser_UnknownDomainDenied(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}
	ur.createFn = func(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
		return port.User{}, assert.AnError
	}
	uc := New(ssoTestDeps(ur))
	_, _, _, err := uc.FindOrProvisionSSOUser(context.Background(), "sub-9", "mallory@evil.example", []string{"example.com"})
	assert.ErrorIs(t, err, auth.ErrSSONotProvisioned)
}

func TestFindOrProvisionSSOUser_AllowedDomainProvisions(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}
	var gotHash *string
	ur.createFn = func(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
		gotHash = passwordHash
		u := makeUser("user-9")
		u.Email = email
		u.Role = "member"
		return u, nil
	}
	uc := New(ssoTestDeps(ur))
	userID, role, provisioned, err := uc.FindOrProvisionSSOUser(context.Background(), "sub-9", "New@Example.COM", []string{"example.com"})
	require.NoError(t, err)
	assert.Equal(t, "user-9", userID)
	assert.Equal(t, auth.RoleViewer, role, "provisioned member accounts map to viewer claims")
	assert.True(t, provisioned)
	assert.Nil(t, gotHash, "SSO accounts must have no password hash so password login stays impossible")
}

func TestFindOrProvisionSSOUser_EmptyEmailDenied(t *testing.T) {
	uc := New(Deps{Stores: &port.Stores{Users: &mockUserRepo{}}})
	_, _, _, err := uc.FindOrProvisionSSOUser(context.Background(), "sub-1", "", []string{"example.com"})
	assert.ErrorIs(t, err, auth.ErrSSONotProvisioned)
}
