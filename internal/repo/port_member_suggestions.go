package repo

import (
	"context"
	"strings"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// SuggestMembers finds accounts to offer when adding a project member. The
// prefix is lowercased and its LIKE wildcards escaped, so "a_b" matches only
// the literal text.
func (r *pgUserPort) SuggestMembers(ctx context.Context, projectID, prefix string, limit int32) ([]port.User, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.SuggestMembers(ctx, sqlc.SuggestMembersParams{
		Prefix:      escapeLikePattern(strings.ToLower(prefix)),
		ProjectID:   pid,
		ResultLimit: limit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]port.User, len(rows))
	for i, row := range rows {
		out[i] = userToPort(row)
	}
	return out, nil
}
