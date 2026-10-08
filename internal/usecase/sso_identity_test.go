package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const ssoTestIssuer = "https://idp.example.com"

// verifiedClaims is a first-time login whose email the provider vouches for.
func verifiedClaims(sub, email string) auth.SSOClaims {
	return auth.SSOClaims{Issuer: ssoTestIssuer, Subject: sub, Email: email, EmailVerified: true}
}

// mockIdentityRepo is an in-memory IdentityStore that records what was linked.
type mockIdentityRepo struct {
	port.IdentityStore
	bySubject map[string]port.UserIdentity
	byUser    map[string]port.UserIdentity
	linkErr   error
	links     []port.UserIdentity
}

func newMockIdentityRepo() *mockIdentityRepo {
	return &mockIdentityRepo{
		bySubject: map[string]port.UserIdentity{},
		byUser:    map[string]port.UserIdentity{},
	}
}

// seed registers an existing link without counting it as a new one.
func (m *mockIdentityRepo) seed(userID, issuer, subject string) {
	id := port.UserIdentity{UserID: userID, Issuer: issuer, Subject: subject}
	m.bySubject[issuer+"|"+subject] = id
	m.byUser[userID+"|"+issuer] = id
}

func (m *mockIdentityRepo) GetBySubject(ctx context.Context, issuer, subject string) (port.UserIdentity, error) {
	if id, ok := m.bySubject[issuer+"|"+subject]; ok {
		return id, nil
	}
	return port.UserIdentity{}, port.ErrNotFound
}

func (m *mockIdentityRepo) GetForUser(ctx context.Context, userID, issuer string) (port.UserIdentity, error) {
	if id, ok := m.byUser[userID+"|"+issuer]; ok {
		return id, nil
	}
	return port.UserIdentity{}, port.ErrNotFound
}

func (m *mockIdentityRepo) Link(ctx context.Context, userID, issuer, subject string) (port.UserIdentity, error) {
	if m.linkErr != nil {
		return port.UserIdentity{}, m.linkErr
	}
	id := port.UserIdentity{UserID: userID, Issuer: issuer, Subject: subject}
	m.links = append(m.links, id)
	m.seed(userID, issuer, subject)
	return id, nil
}

func ssoDepsWith(ur *mockUserRepo, ids *mockIdentityRepo) Deps {
	return Deps{Stores: &port.Stores{Users: ur, Identities: ids}}
}

func existingUser(id, role string) func(context.Context, string) (port.User, error) {
	return func(ctx context.Context, email string) (port.User, error) {
		u := makeUser(id)
		u.Email = email
		u.Role = role
		return u, nil
	}
}

func TestFindOrProvisionSSOUser_LinkedSubjectIgnoresTheEmailClaim(t *testing.T) {
	ids := newMockIdentityRepo()
	ids.seed("user-1", ssoTestIssuer, "sub-1")
	ur := &mockUserRepo{}
	ur.getByIDFn = func(ctx context.Context, id string) (port.User, error) {
		u := makeUser(id)
		u.Role = "admin"
		return u, nil
	}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		t.Fatal("a linked subject must be resolved by identity, never by the email claim")
		return port.User{}, nil
	}
	claims := auth.SSOClaims{Issuer: ssoTestIssuer, Subject: "sub-1", Email: "changed@elsewhere.example", EmailVerified: false}

	userID, role, provisioned, err := New(ssoDepsWith(ur, ids)).FindOrProvisionSSOUser(context.Background(), claims, nil, nil)

	require.NoError(t, err)
	assert.Equal(t, "user-1", userID)
	assert.Equal(t, auth.RoleAdmin, role)
	assert.False(t, provisioned)
	assert.Empty(t, ids.links)
}

func TestFindOrProvisionSSOUser_UnverifiedEmailCannotStartALink(t *testing.T) {
	ids := newMockIdentityRepo()
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		t.Fatal("an unverified email must not be used to look up an account")
		return port.User{}, nil
	}
	claims := auth.SSOClaims{Issuer: ssoTestIssuer, Subject: "sub-evil", Email: "admin@corp.example", EmailVerified: false}

	_, _, _, err := New(ssoDepsWith(ur, ids)).FindOrProvisionSSOUser(context.Background(), claims, []string{"corp.example"}, nil)

	assert.ErrorIs(t, err, auth.ErrSSONotProvisioned)
	assert.Empty(t, ids.links)
}

func TestFindOrProvisionSSOUser_VerifiedEmailLinksTheExistingAccount(t *testing.T) {
	ids := newMockIdentityRepo()
	ur := &mockUserRepo{getByEmailFn: existingUser("user-1", "member")}

	userID, role, provisioned, err := New(ssoDepsWith(ur, ids)).FindOrProvisionSSOUser(
		context.Background(), verifiedClaims("sub-1", "Ada@Example.COM"), nil, nil)

	require.NoError(t, err)
	assert.Equal(t, "user-1", userID)
	assert.Equal(t, auth.RoleViewer, role)
	assert.False(t, provisioned)
	require.Len(t, ids.links, 1)
	assert.Equal(t, port.UserIdentity{UserID: "user-1", Issuer: ssoTestIssuer, Subject: "sub-1"}, ids.links[0])
}

func TestFindOrProvisionSSOUser_AccountBoundToAnotherSubjectIsRefused(t *testing.T) {
	ids := newMockIdentityRepo()
	ids.seed("user-1", ssoTestIssuer, "sub-original")
	ur := &mockUserRepo{getByEmailFn: existingUser("user-1", "admin")}

	_, _, _, err := New(ssoDepsWith(ur, ids)).FindOrProvisionSSOUser(
		context.Background(), verifiedClaims("sub-impostor", "ada@example.com"), nil, nil)

	assert.ErrorIs(t, err, auth.ErrSSONotProvisioned,
		"a second subject carrying the same email must not take over an account that is already linked")
	assert.Empty(t, ids.links)
}

func TestFindOrProvisionSSOUser_ProvisionedAccountIsLinked(t *testing.T) {
	ids := newMockIdentityRepo()
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

	userID, _, provisioned, err := New(ssoDepsWith(ur, ids)).FindOrProvisionSSOUser(
		context.Background(), verifiedClaims("sub-9", "new@example.com"), []string{"example.com"}, nil)

	require.NoError(t, err)
	assert.Equal(t, "user-9", userID)
	assert.True(t, provisioned)
	require.Len(t, ids.links, 1)
	assert.Equal(t, "user-9", ids.links[0].UserID)
	assert.Equal(t, "sub-9", ids.links[0].Subject)
}

func TestFindOrProvisionSSOUser_WithoutAStableIdentityIsRefused(t *testing.T) {
	tests := []struct {
		name   string
		claims auth.SSOClaims
	}{
		{"no subject", auth.SSOClaims{Issuer: ssoTestIssuer, Email: "ada@example.com", EmailVerified: true}},
		{"no issuer", auth.SSOClaims{Subject: "sub-1", Email: "ada@example.com", EmailVerified: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ids := newMockIdentityRepo()
			ur := &mockUserRepo{getByEmailFn: existingUser("user-1", "member")}

			_, _, _, err := New(ssoDepsWith(ur, ids)).FindOrProvisionSSOUser(context.Background(), tc.claims, nil, nil)

			assert.ErrorIs(t, err, auth.ErrSSONotProvisioned)
			assert.Empty(t, ids.links)
		})
	}
}

func TestFindOrProvisionSSOUser_LosingALinkRaceIsRefused(t *testing.T) {
	ids := newMockIdentityRepo()
	ids.linkErr = port.ErrIdentityLinked
	ur := &mockUserRepo{getByEmailFn: existingUser("user-1", "member")}

	_, _, _, err := New(ssoDepsWith(ur, ids)).FindOrProvisionSSOUser(
		context.Background(), verifiedClaims("sub-1", "ada@example.com"), nil, nil)

	assert.ErrorIs(t, err, auth.ErrSSONotProvisioned)
}

func TestFindOrProvisionSSOUser_UnverifiedEmailAllowedByOperatorOptIn(t *testing.T) {
	ids := newMockIdentityRepo()
	ur := &mockUserRepo{getByEmailFn: existingUser("user-1", "member")}
	deps := ssoDepsWith(ur, ids)
	deps.SSOAllowUnverifiedEmail = true
	claims := auth.SSOClaims{Issuer: ssoTestIssuer, Subject: "sub-1", Email: "ada@example.com", EmailVerified: false}

	userID, _, _, err := New(deps).FindOrProvisionSSOUser(context.Background(), claims, nil, nil)

	require.NoError(t, err, "providers that never send email_verified need the explicit opt-in")
	assert.Equal(t, "user-1", userID)
	require.Len(t, ids.links, 1, "even then the login is bound to its subject, so later email changes do not matter")
}
