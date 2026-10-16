package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
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

func keyCreatorHarness(t *testing.T) (*Usecases, *port.CreateAPIKeyInput) {
	t.Helper()
	pr := &mockProjectRepo{getBySlugFn: func(context.Context, string) (port.Project, error) {
		return makeProject(true), nil
	}}
	var got port.CreateAPIKeyInput
	akr := &mockAPIKeyRepo{createFn: func(_ context.Context, in port.CreateAPIKeyInput) (port.APIKey, error) {
		got = in
		return port.APIKey{ID: "key-1", Name: in.Name}, nil
	}}
	return New(Deps{Stores: &port.Stores{Projects: pr, APIKeys: akr}}), &got
}

// The key is stored against the token generation the session authenticated
// with, so an SSO link or a deactivation that committed in between refuses it.
func TestCreateAPIKey_StoresTheSessionTokenGeneration(t *testing.T) {
	uc, got := keyCreatorHarness(t)
	version := int32(5)
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000040", Role: auth.RoleAdmin, TokenVersion: &version,
	})

	_, err := uc.CreateAPIKey(ctx, "my-app", "ci-key", "00000000-0000-0000-0000-000000000040", nil)
	require.NoError(t, err)
	require.NotNil(t, got.CreatorTokenVersion)
	assert.Equal(t, int32(5), *got.CreatorTokenVersion)
}

// A request that is not a versioned session of the creator carries no
// generation to compare.
func TestCreateAPIKey_NoGenerationWithoutAVersionedSessionOfTheCreator(t *testing.T) {
	version := int32(5)
	for name, ident := range map[string]*auth.Identity{
		"session without the claim": {UserID: "00000000-0000-0000-0000-000000000040", Role: auth.RoleAdmin},
		"another account": {
			UserID: "00000000-0000-0000-0000-000000000099", Role: auth.RoleAdmin, TokenVersion: &version,
		},
	} {
		t.Run(name, func(t *testing.T) {
			uc, got := keyCreatorHarness(t)
			ctx := auth.ContextWithIdentity(context.Background(), ident)
			_, err := uc.CreateAPIKey(ctx, "my-app", "ci-key", "00000000-0000-0000-0000-000000000040", nil)
			require.NoError(t, err)
			assert.Nil(t, got.CreatorTokenVersion)
		})
	}
}

// An API key never creates keys, so it is refused before the store is asked and
// the generation check does not apply to it.
func TestCreateAPIKey_APIKeyIdentityIsRefusedBeforeTheStore(t *testing.T) {
	uc, got := keyCreatorHarness(t)
	version := int32(5)
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000040", Role: auth.RoleAdmin, IsAPIKey: true, TokenVersion: &version,
	})

	_, err := uc.CreateAPIKey(ctx, "my-app", "ci-key", "00000000-0000-0000-0000-000000000040", nil)
	require.ErrorIs(t, err, ErrProjectAccessDenied)
	assert.Empty(t, got.KeyHash, "the store was not called")
}

// The store refuses a creator that started a new token generation after the
// request authenticated. The caller gets the same answer as for a deactivated
// creator.
func TestCreateAPIKey_StaleGenerationGetsTheAccessDeniedAnswer(t *testing.T) {
	pr := &mockProjectRepo{getBySlugFn: func(context.Context, string) (port.Project, error) {
		return makeProject(true), nil
	}}
	akr := &mockAPIKeyRepo{createFn: func(context.Context, port.CreateAPIKeyInput) (port.APIKey, error) {
		return port.APIKey{}, port.ErrCreatorInactive
	}}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, APIKeys: akr}})
	version := int32(1)
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000040", Role: auth.RoleAdmin, TokenVersion: &version,
	})

	_, err := uc.CreateAPIKey(ctx, "my-app", "ci-key", "00000000-0000-0000-0000-000000000040", nil)
	require.ErrorIs(t, err, ErrProjectAccessDenied)
}
