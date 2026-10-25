package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// The finding id reads report a malformed id as ErrInvalidFindingID, which the
// handlers map to 400, before any store lookup.
func TestFindingIDReads_MalformedIDIsErrInvalidFindingID(t *testing.T) {
	uc := New(Deps{})
	ctx := context.Background()

	_, err := uc.GetFindingEvents(ctx, "abc", nil, 50, 0)
	assert.ErrorIs(t, err, ErrInvalidFindingID)
	_, err = uc.ListEvidence(ctx, "abc")
	assert.ErrorIs(t, err, ErrInvalidFindingID)
	_, err = uc.GetSignoff(ctx, "abc")
	assert.ErrorIs(t, err, ErrInvalidFindingID)
}
