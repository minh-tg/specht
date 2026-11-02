package usecase

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const ssoSyncAdminGroup = "specht-admins"

// ssoSyncFixture is a linked, passwordless account signing in through SSO
// with SSO_ADMIN_GROUPS set. syncCalls records every SyncSSOAdmin call, and
// sync answers it.
type ssoSyncFixture struct {
	user      port.User
	syncCalls []bool
	sync      func(admin bool) (port.User, error)
	auditLog  bytes.Buffer
}

func newSSOSyncFixture(role, source string) *ssoSyncFixture {
	u := makeUser("user-7")
	u.Role = role
	u.AdminSource = source
	return &ssoSyncFixture{user: u}
}

func (f *ssoSyncFixture) login(t *testing.T, groups ...string) (string, error) {
	t.Helper()
	ids := newMockIdentityRepo()
	ids.seed(f.user.ID, ssoTestIssuer, "sub-7")
	ur := &mockUserRepo{}
	ur.getByIDFn = func(context.Context, string) (port.User, error) { return f.user, nil }
	ur.syncSSOAdminFn = func(_ context.Context, id string, admin bool) (port.User, error) {
		require.Equal(t, f.user.ID, id)
		f.syncCalls = append(f.syncCalls, admin)
		return f.sync(admin)
	}
	deps := ssoDepsWith(ur, ids)
	deps.Audit = audit.NewLogger(slog.New(slog.NewTextHandler(&f.auditLog, nil)))
	claims := auth.SSOClaims{Issuer: ssoTestIssuer, Subject: "sub-7", Groups: groups}
	_, role, _, err := New(deps).FindOrProvisionSSOUser(context.Background(), claims, nil, []string{ssoSyncAdminGroup})
	return role, err
}

func withRole(u port.User, role, source string) port.User {
	u.Role = role
	u.AdminSource = source
	return u
}

func TestSSOAdminSync_AdminGroupPromotesAndAudits(t *testing.T) {
	f := newSSOSyncFixture(auth.RoleMember, port.AdminSourceManual)
	f.sync = func(bool) (port.User, error) {
		return withRole(f.user, auth.RoleAdmin, port.AdminSourceSSO), nil
	}

	role, err := f.login(t, ssoSyncAdminGroup)

	require.NoError(t, err)
	assert.Equal(t, auth.RoleAdmin, role)
	assert.Equal(t, []bool{true}, f.syncCalls)
	assert.Contains(t, f.auditLog.String(), "audit=user.role")
	assert.Contains(t, f.auditLog.String(), "principal_id=sso")
	assert.Contains(t, f.auditLog.String(), "outcome=success")
}

func TestSSOAdminSync_RemovedGroupDemotesAnSSOAdmin(t *testing.T) {
	f := newSSOSyncFixture(auth.RoleAdmin, port.AdminSourceSSO)
	f.sync = func(bool) (port.User, error) {
		return withRole(f.user, auth.RoleMember, port.AdminSourceManual), nil
	}

	role, err := f.login(t, "some-other-group")

	require.NoError(t, err)
	assert.Equal(t, auth.RoleViewer, role, "the token carries the member role")
	assert.Equal(t, []bool{false}, f.syncCalls)
	assert.Contains(t, f.auditLog.String(), "audit=user.role")
	assert.Contains(t, f.auditLog.String(), "target=user-7")
	assert.Contains(t, f.auditLog.String(), "outcome=success")
}

func TestSSOAdminSync_NoGroupsClaimDemotesAnSSOAdmin(t *testing.T) {
	f := newSSOSyncFixture(auth.RoleAdmin, port.AdminSourceSSO)
	f.sync = func(bool) (port.User, error) {
		return withRole(f.user, auth.RoleMember, port.AdminSourceManual), nil
	}

	role, err := f.login(t)

	require.NoError(t, err)
	assert.Equal(t, auth.RoleViewer, role)
	assert.Equal(t, []bool{false}, f.syncCalls)
}

func TestSSOAdminSync_ManualAdminIsNeverDemoted(t *testing.T) {
	f := newSSOSyncFixture(auth.RoleAdmin, port.AdminSourceManual)

	role, err := f.login(t, "some-other-group")

	require.NoError(t, err)
	assert.Equal(t, auth.RoleAdmin, role)
	assert.Empty(t, f.syncCalls, "a manual admin is not the IdP's to take back")
	assert.Empty(t, f.auditLog.String())
}

func TestSSOAdminSync_ManualAdminInTheGroupKeepsItsSource(t *testing.T) {
	f := newSSOSyncFixture(auth.RoleAdmin, port.AdminSourceManual)

	role, err := f.login(t, ssoSyncAdminGroup)

	require.NoError(t, err)
	assert.Equal(t, auth.RoleAdmin, role)
	assert.Empty(t, f.syncCalls, "an admin is not rewritten into one the IdP granted")
}

func TestSSOAdminSync_TheLastAdminKeepsTheRole(t *testing.T) {
	f := newSSOSyncFixture(auth.RoleAdmin, port.AdminSourceSSO)
	f.sync = func(bool) (port.User, error) { return f.user, port.ErrLastGlobalAdmin }

	role, err := f.login(t)

	require.NoError(t, err, "the login goes on with the role kept")
	assert.Equal(t, auth.RoleAdmin, role)
	assert.Equal(t, []bool{false}, f.syncCalls)
	assert.Contains(t, f.auditLog.String(), "audit=user.role")
	assert.Contains(t, f.auditLog.String(), "outcome=failure")
	assert.Contains(t, f.auditLog.String(), "last global admin")
}

func TestSSOAdminSync_APasswordAccountIsNotPromoted(t *testing.T) {
	f := newSSOSyncFixture(auth.RoleMember, port.AdminSourceManual)
	f.user.PasswordHash = "hash"

	role, err := f.login(t, ssoSyncAdminGroup)

	require.NoError(t, err)
	assert.Equal(t, auth.RoleViewer, role)
	assert.Empty(t, f.syncCalls)
}

func TestSSOAdminSync_ADeactivationInBetweenRefusesTheLogin(t *testing.T) {
	f := newSSOSyncFixture(auth.RoleAdmin, port.AdminSourceSSO)
	f.sync = func(bool) (port.User, error) { return f.user, port.ErrAccountDeactivated }

	_, err := f.login(t)

	assert.ErrorIs(t, err, auth.ErrSSONotProvisioned)
}

func TestSSOAdminSync_NothingChangesWithoutAdminGroups(t *testing.T) {
	ids := newMockIdentityRepo()
	ids.seed("user-7", ssoTestIssuer, "sub-7")
	u := makeUser("user-7")
	u.Role = auth.RoleAdmin
	u.AdminSource = port.AdminSourceSSO
	ur := &mockUserRepo{getByIDFn: func(context.Context, string) (port.User, error) { return u, nil }}

	_, role, _, err := New(ssoDepsWith(ur, ids)).FindOrProvisionSSOUser(context.Background(),
		auth.SSOClaims{Issuer: ssoTestIssuer, Subject: "sub-7"}, nil, nil)

	require.NoError(t, err, "SyncSSOAdmin is not called while SSO_ADMIN_GROUPS is empty")
	assert.Equal(t, auth.RoleAdmin, role)
}
