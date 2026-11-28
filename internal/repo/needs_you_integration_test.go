//go:build integration

package repo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nyFixture is a project with two people, for the Needs you queries.
type nyFixture struct {
	repos             *Repos
	project           string
	alice, bob        string
	projectUUID       pgtype.UUID
	aliceUUID, bobUID pgtype.UUID
}

func newNYFixture(t *testing.T, repos *Repos) nyFixture {
	t.Helper()
	project := createTestProject(t, repos)
	alice, bob := createTestRefreshUser(t, repos), createTestRefreshUser(t, repos)
	return nyFixture{
		repos: repos, project: uuid.UUID(project.ID.Bytes).String(),
		alice: uuid.UUID(alice.ID.Bytes).String(), bob: uuid.UUID(bob.ID.Bytes).String(),
		projectUUID: project.ID, aliceUUID: alice.ID, bobUID: bob.ID,
	}
}

// waiver inserts a waiver row with the columns the Needs you queries read.
func (f nyFixture) waiver(t *testing.T, name, status string, requestedBy, decidedBy any, decidedAt, expiresAt *time.Time) {
	t.Helper()
	_, err := f.repos.pool.Exec(context.Background(), `INSERT INTO waivers
		(project_id, name, status, enabled, requested_by, requested_at, decided_by, decided_at, expires_at)
		VALUES ($1, $2, $3, true, $4, now(), $5, $6, $7)`,
		f.projectUUID, name, status, requestedBy, decidedBy, decidedAt, expiresAt)
	require.NoError(t, err)
}

func ago(d time.Duration) *time.Time {
	at := time.Now().Add(-d)
	return &at
}

// The caller's own requests drop out only in the projects named for that, from the list and the
// total alike, and the total counts beyond the limit.
func TestNeedsYouStore_PendingRequests(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	f := newNYFixture(t, repos)
	store := NewPortStores(repos.pool).NeedsYou
	ctx := context.Background()
	for i := range 3 {
		f.waiver(t, fmt.Sprintf("bob-%d", i), "pending", f.bobUID, nil, nil, nil)
	}
	for i := range 2 {
		f.waiver(t, fmt.Sprintf("alice-%d", i), "pending", f.aliceUUID, nil, nil, nil)
	}
	f.waiver(t, "nobody's", "pending", nil, nil, nil, nil)
	f.waiver(t, "decided", "approved", f.bobUID, f.aliceUUID, ago(time.Hour), nil)

	all, err := store.ListPendingWaiverRequests(ctx, f.alice, []string{f.project}, nil, 50)
	require.NoError(t, err)
	assert.Len(t, all.Items, 6)
	assert.Equal(t, 6, all.Total)

	hidden, err := store.ListPendingWaiverRequests(ctx, f.alice, []string{f.project}, []string{f.project}, 50)
	require.NoError(t, err)
	assert.Len(t, hidden.Items, 4, "alice's two requests drop out; one with no requester stays")
	assert.Equal(t, 4, hidden.Total)

	limited, err := store.ListPendingWaiverRequests(ctx, f.alice, []string{f.project}, []string{f.project}, 2)
	require.NoError(t, err)
	assert.Len(t, limited.Items, 2)
	assert.Equal(t, 4, limited.Total, "the total counts past the limit")

	own, err := store.ListProjectsWithOwnPendingRequests(ctx, f.alice, []string{f.project})
	require.NoError(t, err)
	assert.Equal(t, []string{f.project}, own)
	none, err := store.ListProjectsWithOwnPendingRequests(ctx, f.alice, []string{uuid.NewString()})
	require.NoError(t, err)
	assert.Empty(t, none)
}

// Answers count in full past the limit, and fresh counts those decided since the given time.
func TestNeedsYouStore_DecidedRequests(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	f := newNYFixture(t, repos)
	store := NewPortStores(repos.pool).NeedsYou
	ctx := context.Background()
	f.waiver(t, "fresh", "approved", f.aliceUUID, f.bobUID, ago(time.Hour), ago(-48*time.Hour))
	f.waiver(t, "older", "rejected", f.aliceUUID, f.bobUID, ago(5*24*time.Hour), nil)
	f.waiver(t, "lapsed", "rejected", f.aliceUUID, nil, ago(2*time.Hour), nil)
	f.waiver(t, "too old", "approved", f.aliceUUID, f.bobUID, ago(20*24*time.Hour), nil)
	f.waiver(t, "bob's", "approved", f.bobUID, f.aliceUUID, ago(time.Hour), nil)

	got, err := store.ListDecidedWaiverRequests(ctx, f.alice, []string{f.project},
		time.Now().Add(-14*24*time.Hour), time.Now().Add(-3*24*time.Hour), 2)
	require.NoError(t, err)
	require.Len(t, got.Items, 2)
	assert.Equal(t, "fresh", got.Items[0].Name, "newest first")
	assert.True(t, got.Items[0].Enabled)
	require.NotNil(t, got.Items[0].ExpiresAt)
	assert.Equal(t, 3, got.Total, "fresh, lapsed and older; not the one past 14 days, not bob's")
	assert.Equal(t, 2, got.Fresh, "fresh and lapsed were decided in the last three days")
}

// Ending waivers and assigned findings count in full past the limit.
func TestNeedsYouStore_EndingWaiversAndAssignedFindings(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	f := newNYFixture(t, repos)
	store := NewPortStores(repos.pool).NeedsYou
	ctx := context.Background()
	for i := range 3 {
		f.waiver(t, fmt.Sprintf("ending-%d", i), "approved", nil, nil, nil, ago(-time.Duration(i+1)*24*time.Hour))
	}
	f.waiver(t, "later", "approved", nil, nil, nil, ago(-30*24*time.Hour))

	ending, err := store.ListWaiversEnding(ctx, []string{f.project}, time.Now(), time.Now().Add(7*24*time.Hour), 2)
	require.NoError(t, err)
	assert.Len(t, ending.Items, 2)
	assert.Equal(t, 3, ending.Total)

	seedFindings(t, repos, f.projectUUID, []seededFinding{
		{fingerprint: "a", title: "a", severity: "high", rank: 4},
		{fingerprint: "b", title: "b", severity: "low", rank: 2},
		{fingerprint: "c", title: "c", severity: "critical", rank: 5},
		{fingerprint: "d", title: "d", severity: "medium", rank: 3},
	})
	_, err = repos.pool.Exec(ctx, `UPDATE findings SET assignee_id = $1 WHERE project_id = $2 AND fingerprint IN ('a', 'b', 'c')`,
		f.aliceUUID, f.projectUUID)
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, `UPDATE findings SET state = 'fixed' WHERE project_id = $1 AND fingerprint = 'b'`, f.projectUUID)
	require.NoError(t, err)

	assigned, err := store.ListOpenFindingsAssignedTo(ctx, f.alice, []string{f.project}, 1)
	require.NoError(t, err)
	require.Len(t, assigned.Items, 1)
	assert.Equal(t, "c", assigned.Items[0].Title, "most severe first")
	assert.Equal(t, 2, assigned.Total, "a and c are open; b is fixed and d is nobody's")
}
