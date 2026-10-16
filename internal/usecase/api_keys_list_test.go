package usecase

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// A key whose creator left the project keeps working, so the list has to say
// so: the manager reading it decides whether the key should go.
func TestListAPIKeysSaysWhetherTheCreatorIsStillAMember(t *testing.T) {
	keys := &mockAPIKeyRepo{
		listByProjectFn: func(context.Context, string) ([]port.APIKey, error) {
			return []port.APIKey{
				{ID: "k1", Name: "ci", KeyPrefix: "vuln_aaaa", CreatorIsMember: true},
				{ID: "k2", Name: "deploy", KeyPrefix: "vuln_bbbb", CreatorIsMember: false},
			}, nil
		},
	}
	uc := permissionsUsecase(auth.RoleManager, true)
	uc.deps.Stores.APIKeys = keys

	got, err := uc.ListAPIKeys(sessionCtx("00000000-0000-0000-0000-0000000000a1", auth.RoleMember), "my-app")

	require.NoError(t, err)
	require.Len(t, got, 2)
	require.NotNil(t, got[0].CreatorIsMember)
	require.NotNil(t, got[1].CreatorIsMember)
	assert.True(t, *got[0].CreatorIsMember)
	assert.False(t, *got[1].CreatorIsMember)

	raw, err := json.Marshal(got[1])
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"creator_is_member":false`, "false is sent, not dropped as an empty value")
}

func TestListAPIKeysWithNoKeysIsAnEmptyList(t *testing.T) {
	uc := permissionsUsecase(auth.RoleManager, true)
	uc.deps.Stores.APIKeys = &mockAPIKeyRepo{
		listByProjectFn: func(context.Context, string) ([]port.APIKey, error) { return nil, nil },
	}

	got, err := uc.ListAPIKeys(sessionCtx("00000000-0000-0000-0000-0000000000a1", auth.RoleMember), "my-app")

	require.NoError(t, err)
	raw, err := json.Marshal(got)
	require.NoError(t, err)
	assert.JSONEq(t, `[]`, string(raw), "a project with no keys lists as [] and never null")
}

func TestCreateAPIKeyResponseOmitsTheMembershipFlag(t *testing.T) {
	uc := permissionsUsecase(auth.RoleManager, true)
	uc.deps.Stores.APIKeys = &mockAPIKeyRepo{
		createFn: func(_ context.Context, in port.CreateAPIKeyInput) (port.APIKey, error) {
			return port.APIKey{ID: "k1", Name: in.Name, KeyPrefix: in.KeyPrefix}, nil
		},
	}
	const userID = "00000000-0000-0000-0000-0000000000a1"

	got, err := uc.CreateAPIKey(sessionCtx(userID, auth.RoleMember), "my-app", "ci", userID, nil)

	require.NoError(t, err)
	raw, err := json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "creator_is_member", "the flag belongs to the list")
}
