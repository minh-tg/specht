package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestListTeams_DirectoryVisibility(t *testing.T) {
	directory := []port.Team{{ID: "11111111-1111-1111-1111-111111111111", Name: "backend"}}

	tests := []struct {
		name       string
		ctx        context.Context
		accessible []string
		wantTeams  int
		wantErr    error
		wantListed bool
	}{
		{"global admin sees the directory", adminCtx(), nil, 1, nil, true},
		{"member of a project sees the directory", teamMemberCtx(), []string{"p1"}, 1, nil, true},
		{"registrant with no access sees nothing", teamMemberCtx(), nil, 0, nil, false},
		{"api key is refused", apiKeyCtx("00000000-0000-0000-0000-000000000040", "p1"), nil, 0, ErrProjectAccessDenied, false},
		{"anonymous is refused", context.Background(), nil, 0, ErrProjectAccessDenied, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uc, pr, tr, _ := teamHarness()
			pr.listAccessibleIDsFn = func(ctx context.Context, userID string) ([]string, error) {
				return tc.accessible, nil
			}
			listed := false
			tr.listFn = func(ctx context.Context) ([]port.Team, error) {
				listed = true
				return directory, nil
			}

			got, err := uc.ListTeams(tc.ctx)

			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Len(t, got, tc.wantTeams)
			assert.Equal(t, tc.wantListed, listed, "the directory is only read for callers allowed to see it")
		})
	}
}
