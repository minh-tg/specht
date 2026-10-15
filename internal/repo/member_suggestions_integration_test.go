//go:build integration

package repo

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func newNamedUser(t *testing.T, repos *Repos, email, displayName string) port.User {
	t.Helper()
	row, err := repos.Users.Create(context.Background(), email,
		pgtype.Text{String: displayName, Valid: displayName != ""}, pgtype.Text{String: "$2a$10$hash", Valid: true})
	require.NoError(t, err)
	return userToPort(row)
}

func suggestedEmails(t *testing.T, users port.UserStore, projectID, prefix string, limit int32) []string {
	t.Helper()
	got, err := users.SuggestMembers(context.Background(), projectID, prefix, limit)
	require.NoError(t, err)
	emails := make([]string, len(got))
	for i, u := range got {
		emails[i] = u.Email
	}
	return emails
}

func TestSuggestMembers(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	projectID := toUUID(createTestProject(t, repos).ID)

	newNamedUser(t, repos, "ada@acme.example", "Ada Lovelace")
	newNamedUser(t, repos, "adam@acme.example", "")
	newNamedUser(t, repos, "grace@acme.example", "Grace Hopper")
	newNamedUser(t, repos, "bob@acme.example", "Hopperson Smith")
	newNamedUser(t, repos, "a_b@acme.example", "")
	newNamedUser(t, repos, "axb@acme.example", "")
	newNamedUser(t, repos, "pct%x@acme.example", "")
	newNamedUser(t, repos, "pctyx@acme.example", "")
	newNamedUser(t, repos, `back\slash@acme.example`, "")
	newNamedUser(t, repos, "backxslash@acme.example", "")
	member := newNamedUser(t, repos, "adele@acme.example", "Adele Member")
	_, err := stores.Projects.UpsertMember(ctx, projectID, member.ID, "member")
	require.NoError(t, err)
	gone := newNamedUser(t, repos, "adrian@acme.example", "")
	_, err = stores.Users.SetDisabled(ctx, gone.ID, true)
	require.NoError(t, err)

	t.Run("email prefix, case-insensitive, ordered by email", func(t *testing.T) {
		assert.Equal(t, []string{"ada@acme.example", "adam@acme.example"}, suggestedEmails(t, stores.Users, projectID, "ADA", 8))
	})
	t.Run("a substring inside the email is not a prefix", func(t *testing.T) {
		assert.Empty(t, suggestedEmails(t, stores.Users, projectID, "acme", 8))
	})
	t.Run("prefix of any display-name word", func(t *testing.T) {
		assert.Equal(t, []string{"ada@acme.example"}, suggestedEmails(t, stores.Users, projectID, "love", 8))
		assert.Equal(t, []string{"bob@acme.example", "grace@acme.example"}, suggestedEmails(t, stores.Users, projectID, "hop", 8))
	})
	t.Run("the middle of a display-name word does not match", func(t *testing.T) {
		assert.Empty(t, suggestedEmails(t, stores.Users, projectID, "pper", 8))
		assert.Empty(t, suggestedEmails(t, stores.Users, projectID, "lace", 8))
	})
	t.Run("LIKE wildcards are literal", func(t *testing.T) {
		assert.Equal(t, []string{"a_b@acme.example"}, suggestedEmails(t, stores.Users, projectID, "a_b", 8))
		assert.Equal(t, []string{"pct%x@acme.example"}, suggestedEmails(t, stores.Users, projectID, "pct%", 8))
		assert.Empty(t, suggestedEmails(t, stores.Users, projectID, "%", 8))
	})
	t.Run("a backslash matches itself, not an escape", func(t *testing.T) {
		assert.Equal(t, []string{`back\slash@acme.example`}, suggestedEmails(t, stores.Users, projectID, `back\`, 8))
		assert.Equal(t, []string{`back\slash@acme.example`}, suggestedEmails(t, stores.Users, projectID, `back\s`, 8))
		assert.Empty(t, suggestedEmails(t, stores.Users, projectID, `\`, 8))
	})
	t.Run("direct members, disabled and system accounts are left out", func(t *testing.T) {
		assert.Equal(t, []string{"ada@acme.example", "adam@acme.example"}, suggestedEmails(t, stores.Users, projectID, "ad", 8))
		assert.Empty(t, suggestedEmails(t, stores.Users, projectID, "system", 8))
	})
	t.Run("a member of another project is still offered", func(t *testing.T) {
		other := toUUID(createTestProject(t, repos).ID)
		assert.Contains(t, suggestedEmails(t, stores.Users, other, "ade", 8), "adele@acme.example")
	})
	t.Run("the limit caps the rows", func(t *testing.T) {
		for i := range 10 {
			newNamedUser(t, repos, fmt.Sprintf("bulk%02d@acme.example", i), "")
		}
		got := suggestedEmails(t, stores.Users, projectID, "bulk", 8)
		require.Len(t, got, 8)
		assert.Equal(t, "bulk00@acme.example", got[0])
		assert.Equal(t, "bulk07@acme.example", got[7])
	})
}
