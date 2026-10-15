package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"unicode/utf8"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const (
	// MemberSuggestionMinQuery is the shortest query that searches. A shorter
	// one returns no suggestions, so one or two letters cannot list the directory.
	MemberSuggestionMinQuery = 3
	// MemberSuggestionMaxQuery is the longest query accepted.
	MemberSuggestionMaxQuery = 64
	// MemberSuggestionLimit caps the suggestions returned for one query.
	MemberSuggestionLimit = 8
)

// ErrSuggestionQueryTooLong is returned for a member-suggestion query over
// MemberSuggestionMaxQuery characters. Handlers map it to 400.
var ErrSuggestionQueryTooLong = fmt.Errorf("query must be at most %d characters", MemberSuggestionMaxQuery)

// MemberSuggestion is a person offered when adding a direct project member.
type MemberSuggestion struct {
	UserID      string `json:"user_id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

// SuggestProjectMembers returns up to MemberSuggestionLimit active accounts
// whose email, or any word of whose display name, starts with query. Only a
// signed-in project manager or admin may ask; it is the same check that guards
// adding a member, so API keys are refused.
//
// With open self-registration the answer is always empty: anyone can register
// an account under an address and a display name of their choosing, so a
// suggestion would help a stranger who squatted a colleague's name.
func (u *Usecases) SuggestProjectMembers(ctx context.Context, projectSlug, query string, registrationOpen bool) ([]MemberSuggestion, error) {
	p, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrProjectAccessDenied
		}
		return nil, fmt.Errorf("lookup project: %w", err)
	}
	callerRole, err := u.callerProjectRole(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	if auth.RoleRank(callerRole) < auth.RoleRank(auth.RoleManager) {
		return nil, ErrProjectAccessDenied
	}

	query = strings.TrimSpace(query)
	length := utf8.RuneCountInString(query)
	if length > MemberSuggestionMaxQuery {
		return nil, ErrSuggestionQueryTooLong
	}
	// The query text is a partial address; only its length is logged.
	slog.DebugContext(ctx, "member suggestions", "user_id", auth.ContextIdentity(ctx).UserID, "query_len", length)
	if registrationOpen || length < MemberSuggestionMinQuery {
		return []MemberSuggestion{}, nil
	}

	users, err := u.deps.Stores.Users.SuggestMembers(ctx, p.ID, query, MemberSuggestionLimit)
	if err != nil {
		return nil, fmt.Errorf("suggest members: %w", err)
	}
	out := make([]MemberSuggestion, 0, len(users))
	for _, user := range users {
		// The store leaves these out already; checking again keeps a store bug
		// from offering an account nobody may add.
		if user.DisabledAt != nil || isSystemAccount(user.Email) {
			continue
		}
		s := MemberSuggestion{UserID: user.ID, Email: user.Email}
		if user.DisplayName != nil {
			s.DisplayName = *user.DisplayName
		}
		out = append(out, s)
		if len(out) == MemberSuggestionLimit {
			break
		}
	}
	return out, nil
}
