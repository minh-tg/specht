package usecase

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const suggestCaller = "00000000-0000-4000-8000-000000000021"

// suggestUserRepo records what the use case asks the store for.
type suggestUserRepo struct {
	port.UserStore
	calls     int
	projectID string
	prefix    string
	limit     int32
	users     []port.User
}

func (r *suggestUserRepo) SuggestMembers(_ context.Context, projectID, prefix string, limit int32) ([]port.User, error) {
	r.calls++
	r.projectID, r.prefix, r.limit = projectID, prefix, limit
	return r.users, nil
}

// suggestFixture builds use cases where suggestCaller holds callerRole on the
// test project ("" means no membership).
func suggestFixture(callerRole string, users ...port.User) (*Usecases, *suggestUserRepo) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		if slug != "my-app" {
			return port.Project{}, port.ErrNotFound
		}
		return memberTestProject(), nil
	}
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		if callerRole == "" || userID != suggestCaller {
			return "", port.ErrNotFound
		}
		return callerRole, nil
	}
	ur := &suggestUserRepo{users: users}
	return New(Deps{Stores: &port.Stores{Projects: pr, Users: ur}}), ur
}

func suggestUser(n int, email, name string) port.User {
	u := port.User{ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", 100+n), Email: email}
	if name != "" {
		u.DisplayName = &name
	}
	return u
}

func TestSuggestProjectMembers_ManagersAndAdminsMaySearch(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  context.Context
		role string
	}{
		{"project manager", sessionCtx(suggestCaller, auth.RoleMember), auth.RoleManager},
		{"legacy editor", sessionCtx(suggestCaller, auth.RoleMember), auth.RoleEditor},
		{"project admin", sessionCtx(suggestCaller, auth.RoleMember), auth.RoleAdmin},
		{"instance admin with no membership", sessionCtx(suggestCaller, auth.RoleAdmin), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc, ur := suggestFixture(tc.role, suggestUser(1, "ada@acme.example", "Ada Lovelace"))
			got, err := uc.SuggestProjectMembers(tc.ctx, "my-app", "ada", false)
			require.NoError(t, err)
			assert.Equal(t, []MemberSuggestion{{UserID: suggestUser(1, "", "").ID, Email: "ada@acme.example", DisplayName: "Ada Lovelace"}}, got)
			assert.Equal(t, findingFixtureProjectID, ur.projectID)
			assert.Equal(t, int32(MemberSuggestionLimit), ur.limit)
		})
	}
}

func TestSuggestProjectMembers_RefusedWithoutManagerRole(t *testing.T) {
	for _, tc := range []struct {
		name string
		ctx  context.Context
		role string
		slug string
	}{
		{"plain member", sessionCtx(suggestCaller, auth.RoleMember), auth.RoleMember, "my-app"},
		{"legacy viewer", sessionCtx(suggestCaller, auth.RoleMember), auth.RoleViewer, "my-app"},
		{"no membership", sessionCtx(suggestCaller, auth.RoleMember), "", "my-app"},
		{"project API key with admin scope", apiKeyCtx(suggestCaller, findingFixtureProjectID), auth.RoleAdmin, "my-app"},
		{"unknown project", sessionCtx(suggestCaller, auth.RoleAdmin), auth.RoleAdmin, "nope"},
		{"no identity", context.Background(), auth.RoleAdmin, "my-app"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc, ur := suggestFixture(tc.role, suggestUser(1, "ada@acme.example", ""))
			got, err := uc.SuggestProjectMembers(tc.ctx, tc.slug, "ada", false)
			require.ErrorIs(t, err, ErrProjectAccessDenied)
			assert.Nil(t, got)
			assert.Zero(t, ur.calls, "a refused caller never reaches the directory")
		})
	}
}

func TestSuggestProjectMembers_RefusalComesBeforeQueryValidation(t *testing.T) {
	uc, _ := suggestFixture(auth.RoleMember)
	_, err := uc.SuggestProjectMembers(sessionCtx(suggestCaller, auth.RoleMember), "my-app", strings.Repeat("a", 65), false)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestSuggestProjectMembers_QueryLength(t *testing.T) {
	ctx := sessionCtx(suggestCaller, auth.RoleMember)
	for _, tc := range []struct {
		name     string
		query    string
		searches bool
	}{
		{"empty", "", false},
		{"two letters", "ad", false},
		{"two letters padded with spaces", "   ad   ", false},
		{"two multibyte letters are two characters, not four bytes", "äö", false},
		{"three letters", "ada", true},
		{"three multibyte letters", "äöü", true},
		{"64 characters", strings.Repeat("a", 64), true},
		{"64 multibyte characters", strings.Repeat("ä", 64), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uc, ur := suggestFixture(auth.RoleManager, suggestUser(1, "ada@acme.example", ""))
			got, err := uc.SuggestProjectMembers(ctx, "my-app", tc.query, false)
			require.NoError(t, err)
			require.NotNil(t, got, "no suggestions is an empty list, not null")
			if tc.searches {
				assert.Equal(t, 1, ur.calls)
				assert.Equal(t, strings.TrimSpace(tc.query), ur.prefix, "the store gets the trimmed query")
			} else {
				assert.Empty(t, got)
				assert.Zero(t, ur.calls, "a short query never reaches the directory")
			}
		})
	}

	uc, ur := suggestFixture(auth.RoleManager)
	_, err := uc.SuggestProjectMembers(ctx, "my-app", strings.Repeat("a", 65), false)
	assert.ErrorIs(t, err, ErrSuggestionQueryTooLong)
	assert.Zero(t, ur.calls)
}

func TestSuggestProjectMembers_PassesWildcardsThroughAsText(t *testing.T) {
	// LIKE escaping belongs to the store, which treats the prefix as literal
	// text; the use case must not strip or rewrite the characters.
	uc, ur := suggestFixture(auth.RoleManager)
	_, err := uc.SuggestProjectMembers(sessionCtx(suggestCaller, auth.RoleMember), "my-app", ` a%_\ `, false)
	require.NoError(t, err)
	assert.Equal(t, `a%_\`, ur.prefix)
}

func TestSuggestProjectMembers_OpenRegistrationReturnsNothing(t *testing.T) {
	uc, ur := suggestFixture(auth.RoleManager, suggestUser(1, "ada@acme.example", "Ada Lovelace"))
	got, err := uc.SuggestProjectMembers(sessionCtx(suggestCaller, auth.RoleMember), "my-app", "ada", true)
	require.NoError(t, err)
	assert.Equal(t, []MemberSuggestion{}, got)
	assert.Zero(t, ur.calls)

	member, _ := suggestFixture(auth.RoleMember)
	_, err = member.SuggestProjectMembers(sessionCtx(suggestCaller, auth.RoleMember), "my-app", "ada", true)
	assert.ErrorIs(t, err, ErrProjectAccessDenied, "open registration does not turn a refusal into an empty list")
}

func TestSuggestProjectMembers_LeavesOutDisabledAndSystemAccounts(t *testing.T) {
	disabled := suggestUser(2, "adrian@acme.example", "")
	now := time.Now()
	disabled.DisabledAt = &now
	uc, _ := suggestFixture(auth.RoleManager,
		suggestUser(1, "ada@acme.example", ""),
		disabled,
		suggestUser(3, "System@Specht.Local", ""),
	)
	got, err := uc.SuggestProjectMembers(sessionCtx(suggestCaller, auth.RoleMember), "my-app", "ada", false)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "ada@acme.example", got[0].Email)
}

func TestSuggestProjectMembers_CapsTheResult(t *testing.T) {
	var users []port.User
	for i := range MemberSuggestionLimit + 3 {
		users = append(users, suggestUser(i, fmt.Sprintf("ada%02d@acme.example", i), ""))
	}
	uc, _ := suggestFixture(auth.RoleManager, users...)
	got, err := uc.SuggestProjectMembers(sessionCtx(suggestCaller, auth.RoleMember), "my-app", "ada", false)
	require.NoError(t, err)
	require.Len(t, got, MemberSuggestionLimit)
	assert.Equal(t, "ada00@acme.example", got[0].Email)
}
