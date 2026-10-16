package usecase

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// fakeInvites keeps invites in memory, keyed by token hash.
type fakeInvites struct {
	port.InviteStore
	byHash  map[string]*port.Invite
	revoked map[string]bool
	nextID  int

	acceptErr  error
	acceptedAs *port.InviteeAccount
	joinedUser string
	pending    int64
}

func newFakeInvites() *fakeInvites {
	return &fakeInvites{byHash: map[string]*port.Invite{}, revoked: map[string]bool{}}
}

func (f *fakeInvites) Create(_ context.Context, in port.NewInvite) (port.Invite, error) {
	f.nextID++
	inv := port.Invite{
		ID:        "00000000-0000-4000-8000-00000000010" + string(rune('0'+f.nextID)),
		ProjectID: in.ProjectID, Role: in.Role, Email: in.Email, CreatedBy: &in.CreatedBy,
		CreatedAt: time.Now(), ExpiresAt: in.ExpiresAt,
	}
	f.byHash[in.TokenHash] = &inv
	return inv, nil
}

func (f *fakeInvites) CountPending(context.Context, string) (int64, error) {
	return f.pending + int64(len(f.byHash)), nil
}

func (f *fakeInvites) ListPending(context.Context, string) ([]port.Invite, error) {
	var out []port.Invite
	for _, inv := range f.byHash {
		out = append(out, *inv)
	}
	return out, nil
}

func (f *fakeInvites) find(id string) (*port.Invite, string) {
	for hash, inv := range f.byHash {
		if inv.ID == id && !f.revoked[id] {
			return inv, hash
		}
	}
	return nil, ""
}

func (f *fakeInvites) GetPending(_ context.Context, _, id string) (port.Invite, error) {
	inv, _ := f.find(id)
	if inv == nil {
		return port.Invite{}, port.ErrNotFound
	}
	return *inv, nil
}

func (f *fakeInvites) Revoke(_ context.Context, _, id string) (port.Invite, error) {
	inv, _ := f.find(id)
	if inv == nil {
		return port.Invite{}, port.ErrNotFound
	}
	f.revoked[id] = true
	return *inv, nil
}

func (f *fakeInvites) Lookup(_ context.Context, hash string) (port.InviteView, error) {
	inv := f.byHash[hash]
	if inv == nil || f.revoked[inv.ID] {
		return port.InviteView{}, port.ErrNotFound
	}
	return port.InviteView{ProjectName: "Payments", Role: inv.Role, Email: inv.Email}, nil
}

func (f *fakeInvites) AcceptWithNewAccount(_ context.Context, hash string, account port.InviteeAccount) (port.AcceptedInvite, error) {
	if f.acceptErr != nil {
		return port.AcceptedInvite{}, f.acceptErr
	}
	inv := f.byHash[hash]
	if inv == nil {
		return port.AcceptedInvite{}, port.ErrNotFound
	}
	f.acceptedAs = &account
	delete(f.byHash, hash)
	user := makeUser("00000000-0000-0000-0000-0000000000c1")
	user.Email = account.Email
	return port.AcceptedInvite{User: user, ProjectSlug: "payments", Role: inv.Role, InviteID: inv.ID}, nil
}

func (f *fakeInvites) AcceptAsUser(_ context.Context, hash, userID string) (port.AcceptedInvite, error) {
	if f.acceptErr != nil {
		return port.AcceptedInvite{}, f.acceptErr
	}
	inv := f.byHash[hash]
	if inv == nil {
		return port.AcceptedInvite{}, port.ErrNotFound
	}
	f.joinedUser = userID
	delete(f.byHash, hash)
	return port.AcceptedInvite{ProjectSlug: "payments", Role: inv.Role, InviteID: inv.ID}, nil
}

type inviteFixture struct {
	uc      *Usecases
	invites *fakeInvites
	role    string
}

// newInviteTestFixture builds the use cases with a caller whose project role is role.
func newInviteTestFixture(t *testing.T, role string) *inviteFixture {
	t.Helper()
	f := &inviteFixture{invites: newFakeInvites(), role: role}
	projects := &mockProjectRepo{
		getBySlugFn: func(_ context.Context, slug string) (port.Project, error) {
			if slug == "payments" {
				return port.Project{ID: "00000000-0000-0000-0000-000000000001", Slug: "payments", Name: "Payments"}, nil
			}
			return port.Project{}, port.ErrNotFound
		},
		effectiveRoleFn: func(context.Context, string, string) (string, error) { return f.role, nil },
	}
	refresh := &mockRefreshTokenRepo{createFn: func(context.Context, port.NewRefreshToken) (port.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}}
	f.uc = New(Deps{
		Stores:    &port.Stores{Projects: projects, Users: &mockUserRepo{}, RefreshTokens: refresh, Invites: f.invites},
		Tokens:    testJWT(t),
		Passwords: auth.NewPasswordHasher(),
	})
	return f
}

func callerCtx() context.Context {
	return sessionCtx("00000000-0000-0000-0000-0000000000b1", auth.RoleViewer)
}

func TestCreateInvite_ReturnsALinkAndStoresOnlyItsHash(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)

	resp, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member", Email: "New@Example.com"})

	require.NoError(t, err)
	require.True(t, strings.HasPrefix(resp.Link, "/invite/"))
	token := strings.TrimPrefix(resp.Link, "/invite/")
	assert.GreaterOrEqual(t, len(token), 40, "256 bits of randomness")
	assert.Equal(t, "new@example.com", resp.Email)
	assert.Equal(t, auth.RoleMember, resp.Role)

	require.Len(t, f.invites.byHash, 1)
	for hash, stored := range f.invites.byHash {
		assert.Equal(t, hashInviteToken(token), hash)
		assert.NotContains(t, hash, token)
		assert.WithinDuration(t, time.Now().Add(7*24*time.Hour), stored.ExpiresAt, time.Minute, "default is seven days")
	}
}

func TestCreateInvite_LinksAreUnique(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	a, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member"})
	require.NoError(t, err)
	b, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member"})
	require.NoError(t, err)
	assert.NotEqual(t, a.Link, b.Link)
}

func TestCreateInvite_WhoMayInviteWhom(t *testing.T) {
	tests := []struct {
		name       string
		callerRole string
		ctx        context.Context
		inviteRole string
		wantErr    error
	}{
		{"manager invites member", auth.RoleManager, callerCtx(), "member", nil},
		{"manager invites manager", auth.RoleManager, callerCtx(), "manager", nil},
		{"legacy editor means manager", auth.RoleManager, callerCtx(), "editor", nil},
		{"project admin invites manager", auth.RoleAdmin, callerCtx(), "manager", nil},
		{"global admin without membership", "", sessionCtx("g1", auth.RoleAdmin), "manager", nil},
		{"member cannot invite", auth.RoleMember, callerCtx(), "member", ErrProjectAccessDenied},
		{"API key cannot invite", auth.RoleAdmin, apiKeyCtx("k1", "00000000-0000-0000-0000-000000000001"), "member", ErrProjectAccessDenied},
		{"anonymous cannot invite", auth.RoleAdmin, context.Background(), "member", ErrProjectAccessDenied},
		{"admin invites are not offered", auth.RoleAdmin, callerCtx(), "admin", ErrInvalidInviteRole},
		{"unknown role", auth.RoleAdmin, callerCtx(), "owner", ErrInvalidInviteRole},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newInviteTestFixture(t, tc.callerRole)
			_, err := f.uc.CreateInvite(tc.ctx, "payments", CreateInviteInput{Role: tc.inviteRole})
			if tc.wantErr == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
			assert.Empty(t, f.invites.byHash, "nothing is stored for a refused invite")
		})
	}
}

func TestCreateInvite_UnknownProjectLooksLikeNoAccess(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleAdmin)
	_, err := f.uc.CreateInvite(callerCtx(), "no-such-project", CreateInviteInput{Role: "member"})
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestCreateInvite_ValidatesExpiryAndEmail(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	for name, in := range map[string]CreateInviteInput{
		"negative expiry":   {Role: "member", ExpiresInDays: -1},
		"past the maximum":  {Role: "member", ExpiresInDays: 31},
		"not an address":    {Role: "member", Email: "not-an-email"},
		"display-name form": {Role: "member", Email: "Bob <bob@example.com>"},
	} {
		_, err := f.uc.CreateInvite(callerCtx(), "payments", in)
		assert.ErrorIs(t, err, ErrInvalidInviteInput, name)
	}
	resp, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member", ExpiresInDays: 30})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.ExpiresAt)
}

func TestCreateInvite_CapsOpenLinks(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	f.invites.pending = maxPendingInvites
	_, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member"})
	assert.ErrorIs(t, err, ErrTooManyInvites)
}

func TestListInvites_NeverShowsTokens(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	created, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member"})
	require.NoError(t, err)

	list, err := f.uc.ListInvites(callerCtx(), "payments")

	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, created.ID, list[0].ID)
	assert.Empty(t, list[0].Link)

	f.role = auth.RoleMember
	_, err = f.uc.ListInvites(callerCtx(), "payments")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestRevokeInvite(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	created, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "manager"})
	require.NoError(t, err)
	token := strings.TrimPrefix(created.Link, "/invite/")

	_, err = f.uc.RevokeInvite(callerCtx(), "payments", "not-a-uuid")
	assert.ErrorIs(t, err, ErrInvalidID)

	_, err = f.uc.RevokeInvite(callerCtx(), "payments", "00000000-0000-4000-8000-0000000009ff")
	assert.ErrorIs(t, err, ErrInviteNotFound)

	f.role = auth.RoleMember
	_, err = f.uc.RevokeInvite(callerCtx(), "payments", created.ID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	f.role = auth.RoleManager
	_, err = f.uc.RevokeInvite(callerCtx(), "payments", created.ID)
	require.NoError(t, err)
	_, err = f.uc.LookupInvite(context.Background(), token)
	assert.ErrorIs(t, err, ErrInviteNotFound, "a revoked link is dead")
	_, err = f.uc.RevokeInvite(callerCtx(), "payments", created.ID)
	assert.ErrorIs(t, err, ErrInviteNotFound, "revoking twice")
}

func TestRevokeInvite_ManagerCannotRevokeAHigherRole(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	inv, err := f.invites.Create(context.Background(), port.NewInvite{TokenHash: "h", ProjectID: "p", Role: auth.RoleAdmin, CreatedBy: "u"})
	require.NoError(t, err)

	_, err = f.uc.RevokeInvite(callerCtx(), "payments", inv.ID)

	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestLookupInvite(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	created, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "manager", Email: "a@example.com"})
	require.NoError(t, err)

	got, err := f.uc.LookupInvite(context.Background(), strings.TrimPrefix(created.Link, "/invite/"))
	require.NoError(t, err)
	assert.Equal(t, &InviteLookupResponse{ProjectName: "Payments", Role: "manager", Email: "a@example.com"}, got)

	for name, token := range map[string]string{"unknown": "nope", "empty": "", "oversized": strings.Repeat("x", 500)} {
		_, err := f.uc.LookupInvite(context.Background(), token)
		assert.ErrorIs(t, err, ErrInviteNotFound, name)
	}
}

func TestAcceptInvite_CreatesTheAccountAndSignsItIn(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	created, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member"})
	require.NoError(t, err)
	token := strings.TrimPrefix(created.Link, "/invite/")

	resp, err := f.uc.AcceptInvite(context.Background(), token, AcceptInviteInput{
		Email: "Newcomer@Example.com", Password: "correct-horse-battery", DisplayName: " New ",
	})

	require.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, "newcomer@example.com", resp.Email)
	assert.Equal(t, "payments", resp.ProjectSlug)
	assert.Equal(t, auth.RoleMember, resp.Role)
	require.NotNil(t, f.invites.acceptedAs)
	assert.Equal(t, "New", *f.invites.acceptedAs.DisplayName)
	assert.NotEqual(t, "correct-horse-battery", f.invites.acceptedAs.PasswordHash, "only a hash is stored")

	_, err = f.uc.AcceptInvite(context.Background(), token, AcceptInviteInput{Email: "other@example.com", Password: "correct-horse-battery"})
	assert.ErrorIs(t, err, ErrInviteNotFound, "the link works once")
}

func TestAcceptInvite_RejectsABadAccountBeforeTouchingTheLink(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	created, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member"})
	require.NoError(t, err)
	token := strings.TrimPrefix(created.Link, "/invite/")

	for name, in := range map[string]AcceptInviteInput{
		"no email":       {Password: "correct-horse-battery"},
		"bad email":      {Email: "nope", Password: "correct-horse-battery"},
		"short password": {Email: "a@example.com", Password: "short"},
	} {
		_, err := f.uc.AcceptInvite(context.Background(), token, in)
		assert.ErrorIs(t, err, ErrInvalidCredentialInput, name)
	}
	_, err = f.uc.LookupInvite(context.Background(), token)
	assert.NoError(t, err, "a typo does not use up the link")
}

func TestAcceptInvite_ErrorMapping(t *testing.T) {
	for name, tc := range map[string]struct {
		storeErr error
		want     error
	}{
		"dead link":                 {port.ErrNotFound, ErrInviteNotFound},
		"wrong address":             {port.ErrInviteEmailMismatch, ErrInviteEmailMismatch},
		"address already has login": {port.ErrEmailTaken, ErrRegistrationFailed},
	} {
		t.Run(name, func(t *testing.T) {
			f := newInviteTestFixture(t, auth.RoleManager)
			f.invites.acceptErr = tc.storeErr
			_, err := f.uc.AcceptInvite(context.Background(), "some-token", AcceptInviteInput{Email: "a@example.com", Password: "correct-horse-battery"})
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestJoinInvite(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	created, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "manager"})
	require.NoError(t, err)
	token := strings.TrimPrefix(created.Link, "/invite/")

	_, err = f.uc.JoinInvite(context.Background(), token)
	assert.ErrorIs(t, err, ErrProjectAccessDenied, "anonymous callers use the accept route")
	_, err = f.uc.JoinInvite(apiKeyCtx("k1", "p1"), token)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	resp, err := f.uc.JoinInvite(sessionCtx("00000000-0000-0000-0000-0000000000d1", auth.RoleViewer), token)
	require.NoError(t, err)
	assert.Equal(t, &JoinInviteResponse{ProjectSlug: "payments", Role: "manager"}, resp)
	assert.Equal(t, "00000000-0000-0000-0000-0000000000d1", f.invites.joinedUser)

	_, err = f.uc.JoinInvite(sessionCtx("00000000-0000-0000-0000-0000000000d1", auth.RoleViewer), token)
	assert.ErrorIs(t, err, ErrInviteNotFound)
}

func TestJoinInvite_WrongAddress(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	f.invites.acceptErr = port.ErrInviteEmailMismatch
	_, err := f.uc.JoinInvite(sessionCtx("00000000-0000-0000-0000-0000000000d1", auth.RoleViewer), "tok")
	assert.ErrorIs(t, err, ErrInviteEmailMismatch)
}
