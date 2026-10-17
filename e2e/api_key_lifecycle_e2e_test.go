//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// openE2EDB opens a connection to the suite database, closed when the test ends.
func openE2EDB(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// keyReads reports the status a key gets when it lists a project's findings.
func keyReads(t *testing.T, key, slug string) int {
	t.Helper()
	status, _ := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/findings", key, nil)
	return status
}

// liveKeyIDs lists the ids of a project's keys that are not revoked.
func liveKeyIDs(t *testing.T, slug string) []string {
	t.Helper()
	keys := request[[]struct {
		ID string `json:"id"`
	}](t, http.MethodGet, "/api/v1/auth/apikeys?project="+slug, adminToken, nil, http.StatusOK)
	ids := make([]string, len(keys))
	for i, k := range keys {
		ids[i] = k.ID
	}
	return ids
}

// TestE2E_DeactivationRevokesTheAccountsKeys: a key does not outlive the
// account that created it. Deactivating the account revokes every key it
// created, in every project, and writes one audit line per key. Reactivating
// the account does not bring them back, and another person's key is untouched.
func TestE2E_DeactivationRevokesTheAccountsKeys(t *testing.T) {
	slugA := newProject(t, "leaver-a")
	slugB := newProject(t, "leaver-b")
	leaver := azRegister(t, "leaver")
	azAddMember(t, slugA, leaver.UserID, "manager")
	azAddMember(t, slugB, leaver.UserID, "manager")
	keyA := azKeyBy(t, leaver.Token, slugA)
	keyB := azKeyBy(t, leaver.Token, slugB)
	kept := request[apiKeyResponse](t, http.MethodPost, "/api/v1/auth/apikeys", adminToken,
		map[string]string{"project": slugA, "name": "kept"}, http.StatusCreated)

	require.Equal(t, http.StatusOK, keyReads(t, keyA.Token, slugA))
	require.Equal(t, http.StatusOK, keyReads(t, keyB.Token, slugB))

	azSetActive(t, leaver.UserID, false)

	for _, tc := range []struct{ key, slug string }{{keyA.Token, slugA}, {keyB.Token, slugB}} {
		require.Equal(t, http.StatusUnauthorized, keyReads(t, tc.key, tc.slug), "the leaver's key is dead")
		status, _ := doJSON(t, http.MethodPost, "/api/v1/reports", tc.key,
			ingestBody(t, tc.slug, "high-medium.sarif.json"))
		require.Equal(t, http.StatusUnauthorized, status, "and cannot upload a report either")
	}
	require.Equal(t, http.StatusOK, keyReads(t, kept.RawKey, slugA), "another person's key keeps working")
	require.NotContains(t, liveKeyIDs(t, slugA), keyA.KeyID)
	require.Contains(t, liveKeyIDs(t, slugA), kept.ID)

	require.Eventually(t, func() bool {
		var seenA, seenB bool
		for _, line := range auditLines(t, "auth.apikey.revoke") {
			seenA = seenA || strings.Contains(line, "target="+keyA.KeyID) && strings.Contains(line, "project="+slugA)
			seenB = seenB || strings.Contains(line, "target="+keyB.KeyID) && strings.Contains(line, "project="+slugB)
		}
		return seenA && seenB
	}, 2*time.Second, 50*time.Millisecond, "one audit line per revoked key, naming its project")

	azSetActive(t, leaver.UserID, true)
	require.Equal(t, http.StatusUnauthorized, keyReads(t, keyA.Token, slugA), "reactivating does not resurrect a key")
	require.Equal(t, http.StatusUnauthorized, keyReads(t, keyB.Token, slugB))
}

// TestE2E_KeyOfADeactivatedCreatorIsRefusedEvenIfNotRevoked: a key that
// survived the deactivation, for instance because the revocation never ran,
// answers 401 like an unknown key while its creator is deactivated.
func TestE2E_KeyOfADeactivatedCreatorIsRefusedEvenIfNotRevoked(t *testing.T) {
	slug := newProject(t, "stale-key")
	creator := azRegister(t, "stale")
	azAddMember(t, slug, creator.UserID, "manager")
	key := azKeyBy(t, creator.Token, slug)
	require.Equal(t, http.StatusOK, keyReads(t, key.Token, slug))

	db := openE2EDB(t)
	_, err := db.Exec(context.Background(), "UPDATE users SET disabled_at = now() WHERE id = $1", creator.UserID)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, keyReads(t, key.Token, slug), "the key itself is not revoked, its creator is off")
	unknown := keyReads(t, "vuln_"+randomHex(32), slug)
	require.Equal(t, unknown, keyReads(t, key.Token, slug), "same answer as an unknown key")

	_, err = db.Exec(context.Background(), "UPDATE users SET disabled_at = NULL WHERE id = $1", creator.UserID)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, keyReads(t, key.Token, slug), "the check follows the account's current state")
}

// TestE2E_SSOLinkRevokesTheKeysOfTheSquattedAccount: someone registers an
// address they do not own, mints a key, and the real owner then signs in
// through the provider for the first time. The link hands the account to the
// owner, so the key the squatter minted stops working.
func TestE2E_SSOLinkRevokesTheKeysOfTheSquattedAccount(t *testing.T) {
	defer fakes.idp.setEmail(e2eSSOEmail)
	slug := newProject(t, "squatted")
	email := "e2e-sso-squat-" + randomHex(3) + "@example.com"
	squatter := request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": email, "password": adminPass}, http.StatusCreated)
	azAddMember(t, slug, squatter.UserID, "manager")
	key := azKeyBy(t, squatter.Token, slug)
	bystander := request[apiKeyResponse](t, http.MethodPost, "/api/v1/auth/apikeys", adminToken,
		map[string]string{"project": slug, "name": "bystander"}, http.StatusCreated)
	require.Equal(t, http.StatusOK, keyReads(t, key.Token, slug))

	fakes.idp.setEmail(email)
	status, location, cookies := ssoExchange(t, "")
	owner := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", ssoToken(t, status, location, cookies), nil, http.StatusOK)
	require.Equal(t, squatter.UserID, owner.ID, "the provider login took over the squatted account")

	require.Equal(t, http.StatusUnauthorized, keyReads(t, key.Token, slug), "the squatter's key died with the link")
	require.Equal(t, http.StatusOK, keyReads(t, bystander.RawKey, slug), "another person's key is untouched")
	require.NotContains(t, liveKeyIDs(t, slug), key.KeyID)
}

// TestE2E_KeyListSaysWhenTheCreatorLeftTheProject: a CI key outlives the
// person who made it on purpose, so removing a member revokes nothing. The key
// list carries creator_is_member so a manager can see which keys belong to
// someone who is gone. Access through a team counts as membership.
func TestE2E_KeyListSaysWhenTheCreatorLeftTheProject(t *testing.T) {
	slug := newProject(t, "former-member")
	direct := azRegister(t, "direct")
	azAddMember(t, slug, direct.UserID, "manager")
	viaTeam := azRegister(t, "via-team")
	team := request[struct {
		ID string `json:"id"`
	}](t, http.MethodPost, "/api/v1/teams", adminToken, map[string]string{"name": "former-" + randomHex(4)}, http.StatusCreated)
	request[map[string]any](t, http.MethodPost, "/api/v1/projects/"+slug+"/teams", adminToken,
		map[string]string{"team_id": team.ID, "role": "manager"}, http.StatusCreated)
	azAddTeamMember(t, team.ID, viaTeam.UserID, "member")

	directKey := azKeyBy(t, direct.Token, slug)
	teamKey := azKeyBy(t, viaTeam.Token, slug)

	flags := func() map[string]*bool {
		keys := request[[]struct {
			ID              string `json:"id"`
			CreatorIsMember *bool  `json:"creator_is_member"`
		}](t, http.MethodGet, "/api/v1/auth/apikeys?project="+slug, adminToken, nil, http.StatusOK)
		out := map[string]*bool{}
		for _, k := range keys {
			out[k.ID] = k.CreatorIsMember
		}
		return out
	}
	isMember := func(id string) bool {
		t.Helper()
		flag, listed := flags()[id]
		require.True(t, listed, "key %s is listed", id)
		require.NotNil(t, flag, "the list always carries the flag")
		return *flag
	}

	require.True(t, isMember(directKey.KeyID))
	require.True(t, isMember(teamKey.KeyID))

	status, raw := doJSON(t, http.MethodDelete, "/api/v1/projects/"+slug+"/members/"+direct.UserID, adminToken, nil)
	require.Equal(t, http.StatusNoContent, status, string(raw))
	status, raw = doJSON(t, http.MethodDelete, "/api/v1/teams/"+team.ID+"/members/"+viaTeam.UserID, adminToken, nil)
	require.Equal(t, http.StatusNoContent, status, string(raw))

	require.False(t, isMember(directKey.KeyID), "the creator was removed from the project")
	require.False(t, isMember(teamKey.KeyID), "the creator left the team that gave access")
	require.Equal(t, http.StatusOK, keyReads(t, directKey.Token, slug), "removing a person does not revoke their key")
	require.Equal(t, http.StatusOK, keyReads(t, teamKey.Token, slug))

	azAddMember(t, slug, direct.UserID, "member")
	require.True(t, isMember(directKey.KeyID), "the flag follows current membership")
}
