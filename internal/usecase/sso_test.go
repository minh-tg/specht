package usecase

import (
	"context"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ssoTestDeps(ur *mockUserRepo) Deps {
	return ssoDepsWith(ur, newMockIdentityRepo())
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
	userID, role, provisioned, err := uc.FindOrProvisionSSOUser(context.Background(), auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-1", Email: "Ada@Example.COM"}, nil, nil)
	require.NoError(t, err)
	assert.Equal(t, "user-1", userID)
	assert.Equal(t, auth.RoleAdmin, role, "existing accounts keep their local role")
	assert.False(t, provisioned)
}

func TestFindOrProvisionSSOUser_NormalisesEmailForLookupAndCreate(t *testing.T) {
	ur := &mockUserRepo{}
	var lookedUp, created string
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		lookedUp = email
		return port.User{}, port.ErrNotFound
	}
	ur.createFn = func(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
		created = email
		u := makeUser("user-9")
		u.Email = email
		u.Role = "member"
		return u, nil
	}
	uc := New(ssoTestDeps(ur))
	_, _, _, err := uc.FindOrProvisionSSOUser(context.Background(), auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-9", Email: "  New@Example.COM "}, []string{"example.com"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "new@example.com", lookedUp, "the IdP's casing must not decide which account is found")
	assert.Equal(t, "new@example.com", created, "and must not create a second account for the same person")
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
	_, _, _, err := uc.FindOrProvisionSSOUser(context.Background(), auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-9", Email: "mallory@evil.example"}, []string{"example.com"}, nil)
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
	userID, role, provisioned, err := uc.FindOrProvisionSSOUser(context.Background(), auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-9", Email: "New@Example.COM"}, []string{"example.com"}, nil)
	require.NoError(t, err)
	assert.Equal(t, "user-9", userID)
	assert.Equal(t, auth.RoleViewer, role, "provisioned member accounts map to viewer claims")
	assert.True(t, provisioned)
	assert.Nil(t, gotHash, "SSO accounts must have no password hash so password login stays impossible")
}

func TestFindOrProvisionSSOUser_EmptyEmailDenied(t *testing.T) {
	uc := New(ssoTestDeps(&mockUserRepo{}))
	_, _, _, err := uc.FindOrProvisionSSOUser(context.Background(), auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-1", Email: ""}, []string{"example.com"}, nil)
	assert.ErrorIs(t, err, auth.ErrSSONotProvisioned)
}

func TestFindOrProvisionSSOUser_AdminGroupProvisionsAdmin(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}
	ur.createFn = func(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
		u := makeUser("user-9")
		u.Email = email
		u.Role = "member"
		return u, nil
	}
	var gotRole string
	ur.setRoleFn = func(ctx context.Context, userID, role string) (port.User, error) {
		gotRole = role
		u := makeUser(userID)
		u.Role = role
		return u, nil
	}
	uc := New(ssoTestDeps(ur))
	userID, role, provisioned, err := uc.FindOrProvisionSSOUser(
		context.Background(), auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-9", Email: "new@example.com", Groups: []string{"idp-viewers", "idp-admins"}},
		[]string{"example.com"}, []string{"idp-admins"},
	)
	require.NoError(t, err)
	assert.Equal(t, "user-9", userID)
	assert.Equal(t, auth.RoleAdmin, gotRole, "IdP admin group must elevate")
	assert.Equal(t, auth.RoleAdmin, role)
	assert.True(t, provisioned)
}

func TestFindOrProvisionSSOUser_NonAdminGroupStaysMember(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}
	ur.createFn = func(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
		u := makeUser("user-9")
		u.Email = email
		u.Role = "member"
		return u, nil
	}
	calls := 0
	ur.setRoleFn = func(ctx context.Context, userID, role string) (port.User, error) {
		calls++
		return makeUser(userID), nil
	}
	uc := New(ssoTestDeps(ur))
	_, role, provisioned, err := uc.FindOrProvisionSSOUser(
		context.Background(), auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-9", Email: "new@example.com", Groups: []string{"idp-viewers"}},
		[]string{"example.com"}, []string{"idp-admins"},
	)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleViewer, role)
	assert.True(t, provisioned)
	assert.Zero(t, calls, "no elevation without a matching admin group")
}

func TestFindOrProvisionSSOUser_ExistingRoleNeverChanges(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		u := makeUser("user-1")
		u.Email = email
		u.Role = "member"
		return u, nil
	}
	calls := 0
	ur.setRoleFn = func(ctx context.Context, userID, role string) (port.User, error) {
		calls++
		return makeUser(userID), nil
	}
	uc := New(ssoTestDeps(ur))
	_, role, provisioned, err := uc.FindOrProvisionSSOUser(
		context.Background(), auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-1", Email: "ada@example.com", Groups: []string{"idp-admins"}},
		[]string{"example.com"}, []string{"idp-admins"},
	)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleViewer, role, "IdP groups never change an established role")
	assert.False(t, provisioned)
	assert.Zero(t, calls)
}

func TestFindOrProvisionSSOUser_ElevationFailureFailsClosed(t *testing.T) {
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}
	ur.createFn = func(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
		u := makeUser("user-9")
		u.Email = email
		u.Role = "member"
		return u, nil
	}
	ur.setRoleFn = func(ctx context.Context, userID, role string) (port.User, error) {
		return port.User{}, assert.AnError
	}
	uc := New(ssoTestDeps(ur))
	_, _, _, err := uc.FindOrProvisionSSOUser(
		context.Background(), auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-9", Email: "new@example.com", Groups: []string{"idp-admins"}},
		[]string{"example.com"}, []string{"idp-admins"},
	)
	require.Error(t, err, "failed elevation must fail the login, not mint an admin token")
}

// An address the provider sends is held to the rules a person's address meets
// at registration. These are refused before any lookup, link or insert.
func TestFindOrProvisionSSOUser_RefusesAnInvalidProviderEmail(t *testing.T) {
	tooLong := strings.Repeat("a", 5010) + "@example.com"
	require.Len(t, tooLong, 5022)

	for name, email := range map[string]string{
		"5022 bytes":            tooLong,
		"newline inside":        "ada@example.com\nbcc: eve@evil.example",
		"newline in local part": "ada\n@example.com",
		"trailing newline":      "ada@example.com\n",
		"tab":                   "ada\t@example.com",
		"nul":                   "ada\x00@example.com",
		"display name":          "Ada <ada@example.com>",
		"no at sign":            "ada.example.com",
	} {
		t.Run(name, func(t *testing.T) {
			ur := &mockUserRepo{}
			var touched []string
			ur.getByEmailFn = func(context.Context, string) (port.User, error) {
				touched = append(touched, "lookup")
				return port.User{}, port.ErrNotFound
			}
			ur.createFn = func(_ context.Context, email string, _, _ *string) (port.User, error) {
				touched = append(touched, "create")
				return makeUser("user-new"), nil
			}
			ids := newMockIdentityRepo()
			deps := ssoDepsWith(ur, ids)
			claims := auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-bad", Email: email}

			_, _, _, err := New(deps).FindOrProvisionSSOUser(context.Background(), claims, []string{"example.com"}, nil)

			require.ErrorIs(t, err, auth.ErrSSOInvalidEmail)
			assert.NotErrorIs(t, err, auth.ErrSSONotProvisioned)
			assert.Empty(t, touched, "no lookup and no user row for an address that was refused")
		})
	}
}

func TestFindOrProvisionSSOUser_InvalidEmailIsNotLogged(t *testing.T) {
	logs := captureLogs(t)
	ur := &mockUserRepo{}

	_, _, _, err := New(ssoTestDeps(ur)).FindOrProvisionSSOUser(context.Background(),
		auth.SSOClaims{Issuer: ssoTestIssuer, EmailVerified: true, Subject: "sub-bad", Email: "ada@example.com\nforged log line"},
		[]string{"example.com"}, nil)

	require.ErrorIs(t, err, auth.ErrSSOInvalidEmail)
	assert.NotContains(t, logs.String(), "forged log line", "a provider value must not reach the log")
	assert.Contains(t, logs.String(), "sub-bad")
}
