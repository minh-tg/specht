package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestListTeams_DirectoryVisibility(t *testing.T) {
	directory := []port.Team{
		{ID: "11111111-1111-1111-1111-111111111111", Name: "backend"},
		{ID: "22222222-2222-2222-2222-222222222222", Name: "payments"},
	}
	visible := directory[:1]

	tests := []struct {
		name        string
		ctx         context.Context
		wantTeams   int
		wantErr     error
		wantAll     bool
		wantVisible bool
	}{
		{"global admin sees every team", adminCtx(), 2, nil, true, false},
		{"a person sees the teams visible to them", teamMemberCtx(), 1, nil, false, true},
		{"api key is refused", apiKeyCtx("00000000-0000-0000-0000-000000000040", "p1"), 0, ErrProjectAccessDenied, false, false},
		{"anonymous is refused", context.Background(), 0, ErrProjectAccessDenied, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uc, _, tr, _ := teamHarness()
			readAll, readVisible := false, false
			tr.listFn = func(ctx context.Context) ([]port.Team, error) {
				readAll = true
				return directory, nil
			}
			tr.listVisibleFn = func(ctx context.Context, userID string) ([]port.Team, error) {
				readVisible = true
				assert.Equal(t, "00000000-0000-0000-0000-000000000040", userID)
				return visible, nil
			}

			got, err := uc.ListTeams(tc.ctx)

			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			assert.Len(t, got, tc.wantTeams)
			assert.Equal(t, tc.wantAll, readAll)
			assert.Equal(t, tc.wantVisible, readVisible)
		})
	}
}
