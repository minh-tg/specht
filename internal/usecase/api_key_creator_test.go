package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// The creator passed authentication, then was deactivated before the key was
// stored: the store sees the deactivated account and refuses. The caller gets
// the access-denied answer, not a server error, and no key material.
func TestCreateAPIKey_CreatorDeactivatedBeforeTheInsert(t *testing.T) {
	pr := &mockProjectRepo{getBySlugFn: func(context.Context, string) (port.Project, error) {
		return makeProject(true), nil
	}}
	stored := 0
	akr := &mockAPIKeyRepo{createFn: func(context.Context, port.CreateAPIKeyInput) (port.APIKey, error) {
		stored++
		return port.APIKey{}, port.ErrCreatorInactive
	}}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, APIKeys: akr}})

	resp, err := uc.CreateAPIKey(adminCtx(), "my-app", "ci-key", "00000000-0000-0000-0000-000000000001", nil)

	require.ErrorIs(t, err, ErrProjectAccessDenied)
	assert.Nil(t, resp)
	assert.Equal(t, 1, stored)
}
