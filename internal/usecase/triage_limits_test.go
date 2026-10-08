package usecase

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func uuidList(n int) []string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = uuid.NewString()
	}
	return ids
}

func TestValidateBulkTriage_Limits(t *testing.T) {
	atLimit := strings.Repeat("r", MaxTriageReasonBytes)
	tests := []struct {
		name    string
		ids     []string
		reason  string
		wantErr error
	}{
		{"exactly the id cap is accepted", uuidList(MaxBulkTriageFindings), "ok", nil},
		{"one id over the cap", uuidList(MaxBulkTriageFindings + 1), "ok", ErrTooManyFindings},
		{"reason exactly at the limit", uuidList(2), atLimit, nil},
		{"reason one byte over", uuidList(2), atLimit + "r", ErrReasonTooLong},
		{"the limit counts bytes, not characters", uuidList(2), strings.Repeat("é", MaxTriageReasonBytes/2+1), ErrReasonTooLong},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBulkTriage(BulkTriageInput{FindingIDs: tc.ids, AnalysisState: "false_positive", Reason: tc.reason})

			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestBulkTriage_RefusesOversizedInputBeforeAnyLookup(t *testing.T) {
	uc := New(Deps{}) // no stores: reaching one would panic
	userID := uuid.NewString()

	_, err := uc.BulkTriage(context.Background(), BulkTriageInput{
		FindingIDs: uuidList(MaxBulkTriageFindings + 1), AnalysisState: "false_positive", Reason: "x", UserID: userID,
	})
	assert.ErrorIs(t, err, ErrTooManyFindings)

	_, err = uc.BulkTriage(context.Background(), BulkTriageInput{
		FindingIDs: uuidList(1), AnalysisState: "false_positive", Reason: strings.Repeat("r", MaxTriageReasonBytes+1), UserID: userID,
	})
	assert.ErrorIs(t, err, ErrReasonTooLong)
}

func TestTriageFinding_RefusesAnOverlongReasonBeforeAnyLookup(t *testing.T) {
	uc := New(Deps{})

	_, err := uc.TriageFinding(context.Background(), TriageInput{
		FindingID:     uuid.NewString(),
		UserID:        uuid.NewString(),
		AnalysisState: "false_positive",
		Reason:        strings.Repeat("r", MaxTriageReasonBytes+1),
	})

	assert.ErrorIs(t, err, ErrReasonTooLong, fmt.Sprintf("reasons are stored on every event, so they are capped at %d bytes", MaxTriageReasonBytes))
}
