//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// newKeyBy stores a key created by creator in project and returns its id and
// the hash a bearer would hash to.
func newKeyBy(t *testing.T, repos *Repos, project sqlc.Project, creator, name string) (id, hash string) {
	t.Helper()
	hash = "hash-" + uuid.NewString()
	row, err := repos.APIKeys.Create(context.Background(), sqlc.CreateAPIKeyParams{
		ProjectID: project.ID,
		Name:      name,
		KeyPrefix: "vuln_test",
		KeyHash:   hash,
		LastFour:  pgtype.Text{String: "0000", Valid: true},
		Scopes:    []byte(`["ingest","read"]`),
		CreatedBy: pgtype.UUID{Bytes: uuid.MustParse(creator), Valid: true},
	})
	require.NoError(t, err)
	return uuid.UUID(row.ID.Bytes).String(), hash
}

func keyRevoked(t *testing.T, repos *Repos, id string) bool {
	t.Helper()
	var revoked bool
	require.NoError(t, repos.pool.QueryRow(context.Background(),
		"SELECT revoked_at IS NOT NULL FROM api_keys WHERE id = $1", id).Scan(&revoked))
	return revoked
}

func TestDeactivateRevokesEveryKeyTheAccountCreated(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	admin := newUser(t, repos, "admin@test.com", "admin")
	leaver := newUser(t, repos, "leaver@test.com", "member")
	projectA := createTestProject(t, repos)
	projectB := createTestProject(t, repos)

	inA, _ := newKeyBy(t, repos, projectA, leaver.ID, "ci-a")
	inB, _ := newKeyBy(t, repos, projectB, leaver.ID, "ci-b")
	alreadyRevoked, _ := newKeyBy(t, repos, projectA, leaver.ID, "old")
	_, err := repos.pool.Exec(ctx, "UPDATE api_keys SET revoked_at = now() WHERE id = $1", alreadyRevoked)
	require.NoError(t, err)
	others, _ := newKeyBy(t, repos, projectA, admin.ID, "someone-elses")

	user, revoked, err := stores.Users.Deactivate(ctx, leaver.ID, true)
	require.NoError(t, err)
	require.NotNil(t, user.DisabledAt)

	assert.ElementsMatch(t, []port.RevokedAPIKey{
		{ID: inA, ProjectSlug: projectA.Slug, Name: "ci-a"},
		{ID: inB, ProjectSlug: projectB.Slug, Name: "ci-b"},
	}, revoked, "only the live keys the account created are reported")
	assert.True(t, keyRevoked(t, repos, inA))
	assert.True(t, keyRevoked(t, repos, inB))
	assert.False(t, keyRevoked(t, repos, others), "another person's key is left alone")

	again, revokedAgain, err := stores.Users.Deactivate(ctx, leaver.ID, true)
	require.NoError(t, err, "deactivating twice is harmless")
	assert.Empty(t, revokedAgain)
	assert.Equal(t, user.DisabledAt.Unix(), again.DisabledAt.Unix())

	reactivated, err := stores.Users.SetDisabled(ctx, leaver.ID, false)
	require.NoError(t, err)
	assert.Nil(t, reactivated.DisabledAt)
	assert.True(t, keyRevoked(t, repos, inA), "reactivating does not bring a key back")
	assert.True(t, keyRevoked(t, repos, inB))
}

func TestSetDisabledRevokesKeysToo(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")
	leaver := newUser(t, repos, "leaver@test.com", "member")
	key, _ := newKeyBy(t, repos, createTestProject(t, repos), leaver.ID, "ci")

	_, err := stores.Users.SetDisabled(ctx, leaver.ID, true)
	require.NoError(t, err)
	assert.True(t, keyRevoked(t, repos, key), "no route to a deactivated account leaves its keys live")
}

func TestRefusedDeactivationRevokesNothing(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	only := newUser(t, repos, "only@test.com", "admin")
	key, _ := newKeyBy(t, repos, createTestProject(t, repos), only.ID, "ci")

	_, _, err := stores.Users.Deactivate(ctx, only.ID, true)
	require.ErrorIs(t, err, port.ErrLastGlobalAdmin)
	assert.False(t, keyRevoked(t, repos, key), "the refusal and the revocation are one transaction")
}

func TestKeyOfADeactivatedCreatorDoesNotResolve(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")
	creator := newUser(t, repos, "creator@test.com", "member")
	_, hash := newKeyBy(t, repos, createTestProject(t, repos), creator.ID, "ci")

	_, err := stores.APIKeys.GetByHash(ctx, hash)
	require.NoError(t, err, "a key of an active creator resolves")

	// A key that survived a deactivation (a row written by another route, or a
	// revocation that never ran) must still not authenticate.
	_, err = repos.pool.Exec(ctx, "UPDATE users SET disabled_at = now() WHERE id = $1", creator.ID)
	require.NoError(t, err)
	_, err = stores.APIKeys.GetByHash(ctx, hash)
	require.ErrorIs(t, err, port.ErrNotFound, "port lookup")
	_, err = repos.APIKeys.GetByHash(ctx, hash)
	require.Error(t, err, "repository lookup")

	_, err = repos.pool.Exec(ctx, "UPDATE users SET disabled_at = NULL WHERE id = $1", creator.ID)
	require.NoError(t, err)
	_, err = stores.APIKeys.GetByHash(ctx, hash)
	require.NoError(t, err, "the check follows the account's current state")
}

func TestLinkRevokingKeysRevokesTheAccountsKeysWithTheLink(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	squatter := newUser(t, repos, "victim@test.com", "member")
	bystander := newUser(t, repos, "bystander@test.com", "member")
	project := createTestProject(t, repos)
	mine, _ := newKeyBy(t, repos, project, squatter.ID, "squatter-key")
	theirs, _ := newKeyBy(t, repos, project, bystander.ID, "bystander-key")

	identity, revoked, err := stores.Identities.LinkRevokingKeys(ctx, squatter.ID, "https://idp.example.com", "sub-victim", true)
	require.NoError(t, err)
	assert.Equal(t, squatter.ID, identity.UserID)
	assert.Equal(t, []port.RevokedAPIKey{{ID: mine, ProjectSlug: project.Slug, Name: "squatter-key"}}, revoked)
	assert.True(t, keyRevoked(t, repos, mine))
	assert.False(t, keyRevoked(t, repos, theirs), "another account's key is untouched")

	found, err := stores.Identities.GetBySubject(ctx, "https://idp.example.com", "sub-victim")
	require.NoError(t, err)
	assert.Equal(t, squatter.ID, found.UserID)
}

func TestLinkRevokingKeysRefusedLinkRevokesNothing(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	const issuer = "https://idp.example.com"
	owner := newUser(t, repos, "owner@test.com", "member")
	squatter := newUser(t, repos, "squatter@test.com", "member")
	key, _ := newKeyBy(t, repos, createTestProject(t, repos), squatter.ID, "ci")
	_, err := stores.Identities.Link(ctx, owner.ID, issuer, "sub-taken", false)
	require.NoError(t, err)

	_, _, err = stores.Identities.LinkRevokingKeys(ctx, squatter.ID, issuer, "sub-taken", true)

	require.ErrorIs(t, err, port.ErrIdentityLinked, "the subject already belongs to another account")
	assert.False(t, keyRevoked(t, repos, key), "the revocation rolls back with the refused link")
}

func TestListByProjectReportsWhetherTheCreatorIsStillAMember(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	project := createTestProject(t, repos)
	other := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()

	direct := newUser(t, repos, "direct@test.com", "member")
	viaTeam := newUser(t, repos, "via-team@test.com", "member")
	removed := newUser(t, repos, "removed@test.com", "member")
	leftTeam := newUser(t, repos, "left-team@test.com", "member")
	memberElsewhere := newUser(t, repos, "elsewhere@test.com", "member")

	_, err := stores.Projects.UpsertMember(ctx, projectID, direct.ID, "manager")
	require.NoError(t, err)
	_, err = stores.Projects.UpsertMember(ctx, projectID, removed.ID, "manager")
	require.NoError(t, err)
	_, err = stores.Projects.UpsertMember(ctx, uuid.UUID(other.ID.Bytes).String(), memberElsewhere.ID, "manager")
	require.NoError(t, err)
	team, err := stores.Teams.CreateTeam(ctx, "platform", "")
	require.NoError(t, err)
	_, err = stores.Teams.LinkProjectTeam(ctx, projectID, team.ID, "member")
	require.NoError(t, err)
	_, err = stores.Teams.UpsertTeamMember(ctx, team.ID, viaTeam.ID, "member")
	require.NoError(t, err)
	_, err = stores.Teams.UpsertTeamMember(ctx, team.ID, leftTeam.ID, "member")
	require.NoError(t, err)

	byName := map[string]string{}
	for _, c := range []struct{ name, creator string }{
		{"direct", direct.ID},
		{"via-team", viaTeam.ID},
		{"removed", removed.ID},
		{"left-team", leftTeam.ID},
		{"member-elsewhere", memberElsewhere.ID},
	} {
		id, _ := newKeyBy(t, repos, project, c.creator, c.name)
		byName[c.name] = id
	}

	// removed leaves the project, leftTeam leaves the only team that gave access.
	require.NoError(t, stores.Projects.DeleteMember(ctx, projectID, removed.ID))
	require.NoError(t, stores.Teams.RemoveTeamMember(ctx, team.ID, leftTeam.ID))

	keys, err := stores.APIKeys.ListByProject(ctx, projectID)
	require.NoError(t, err)
	got := map[string]bool{}
	for _, k := range keys {
		got[k.Name] = k.CreatorIsMember
	}
	assert.Equal(t, map[string]bool{
		"direct":           true,
		"via-team":         true,
		"removed":          false,
		"left-team":        false,
		"member-elsewhere": false,
	}, got, "a key stays listed and live; only the flag changes")
	for name, id := range byName {
		assert.False(t, keyRevoked(t, repos, id), "%s: removing a member never revokes their keys", name)
	}
}

// The key list carries each key's expiry, and a key past it stays listed (it
// no longer authenticates) until someone revokes it.
func TestListByProjectReturnsExpiryAndKeepsExpiredKeys(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	creator := newUser(t, repos, "expiry-creator@test.com", "admin")
	project := createTestProject(t, repos)

	permanent, _ := newKeyBy(t, repos, project, creator.ID, "permanent")
	expiring, _ := newKeyBy(t, repos, project, creator.ID, "expiring")
	expired, _ := newKeyBy(t, repos, project, creator.ID, "expired")
	_, err := repos.pool.Exec(ctx, "UPDATE api_keys SET expires_at = now() + interval '2 days' WHERE id = $1", expiring)
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, "UPDATE api_keys SET expires_at = now() - interval '1 day' WHERE id = $1", expired)
	require.NoError(t, err)

	keys, err := stores.APIKeys.ListByProject(ctx, toUUID(project.ID))
	require.NoError(t, err)
	byID := map[string]port.APIKey{}
	for _, k := range keys {
		byID[k.ID] = k
	}
	require.Len(t, byID, 3)
	assert.Nil(t, byID[permanent].ExpiresAt)
	require.NotNil(t, byID[expiring].ExpiresAt)
	assert.True(t, byID[expiring].ExpiresAt.After(time.Now()))
	require.NotNil(t, byID[expired].ExpiresAt)
	assert.True(t, byID[expired].ExpiresAt.Before(time.Now()), "the expired key is listed with its past expiry")
}

// Revoking a key twice keeps the first revocation time and reports the second
// call as a missing key, so the use case writes no second audit line for it.
func TestRevokeKeepsTheFirstRevocationTime(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	creator := newUser(t, repos, "revoke-twice@test.com", "admin")
	project := createTestProject(t, repos)
	id, _ := newKeyBy(t, repos, project, creator.ID, "twice")

	_, err := stores.APIKeys.Revoke(ctx, id, toUUID(project.ID))
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, "UPDATE api_keys SET revoked_at = revoked_at - interval '1 hour' WHERE id = $1", id)
	require.NoError(t, err)
	var first time.Time
	require.NoError(t, repos.pool.QueryRow(ctx, "SELECT revoked_at FROM api_keys WHERE id = $1", id).Scan(&first))

	_, err = stores.APIKeys.Revoke(ctx, id, toUUID(project.ID))
	assert.ErrorIs(t, err, port.ErrNotFound)
	var after time.Time
	require.NoError(t, repos.pool.QueryRow(ctx, "SELECT revoked_at FROM api_keys WHERE id = $1", id).Scan(&after))
	assert.True(t, first.Equal(after), "the second revoke did not move revoked_at")
}
