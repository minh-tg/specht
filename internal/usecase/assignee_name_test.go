package usecase

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// A finding names its assignee for a person reading it. An API key gets the id only, as the
// member list gives a key no names or email addresses.
func TestAttachAssignees_NamesThePersonOnlyForASignedInUser(t *testing.T) {
	fr := &mockFindingRepo{listAssigneesFn: func() (map[string]port.FindingAssignee, error) {
		return map[string]port.FindingAssignee{"f1": {UserID: "u-dev", Name: "dev@example.com"}}, nil
	}}
	uc := New(Deps{Stores: &port.Stores{Findings: fr}})

	read := func(as string) *AssigneeResponse {
		ctx := sessionCtx("u-reader", "member")
		if as == "key" {
			ctx = apiKeyCtx("u-key-owner", findingFixtureProjectID)
		}
		findings := []FindingResponse{{ID: "f1"}}
		require.NoError(t, uc.attachAssignees(ctx, findings))
		require.NotNil(t, findings[0].Assignee)
		return findings[0].Assignee
	}

	assert.Equal(t, AssigneeResponse{UserID: "u-dev", Name: "dev@example.com"}, *read("person"))
	assert.Equal(t, AssigneeResponse{UserID: "u-dev"}, *read("key"))
}
