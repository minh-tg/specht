//go:build e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type inflightAnswer struct {
	status int
	body   []byte
}

// inflightUpload starts a report upload with the given bearer token, sends half
// the body, runs mid, and sends the rest.
func inflightUpload(t *testing.T, slug, token string, mid func()) inflightAnswer {
	t.Helper()
	body, err := json.Marshal(ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{"commit_sha": randomHex(20), "branch": "inflight"}))
	require.NoError(t, err)

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/reports", pr)
	require.NoError(t, err)
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	done := make(chan inflightAnswer, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- inflightAnswer{status: -1}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		done <- inflightAnswer{resp.StatusCode, raw}
	}()
	_, err = pw.Write(body[:len(body)/2])
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	mid()
	_, err = pw.Write(body[len(body)/2:])
	require.NoError(t, err)
	require.NoError(t, pw.Close())
	return <-done
}

func requireInflightRefused(t *testing.T, slug string, got inflightAnswer, what string) {
	t.Helper()
	require.Equalf(t, http.StatusUnauthorized, got.status, "%s: the report landed: %s", what, got.body)
	require.Equal(t, "invalid_token", errorCode(t, got.body))
	reports := request[[]projectReport](t, http.MethodGet, "/api/v1/projects/"+slug+"/reports", adminToken, nil, http.StatusOK)
	require.Emptyf(t, reports, "%s: a refused upload stores no report", what)
}

// An upload that authenticated before its key's creator was deactivated and
// finishes sending its body after the deactivation is refused with the answer a
// revoked key gets, and stores nothing.
func TestIngestStraddlingCreatorDeactivationIsRefused(t *testing.T) {
	slug := newProject(t, "inflight-deactivation")
	creator := azRegister(t, "inflight")
	azAddMember(t, slug, creator.UserID, "admin")
	key := azKeyBy(t, azLogin(t, creator), slug)

	got := inflightUpload(t, slug, key.Token, func() { azSetActive(t, creator.UserID, false) })
	requireInflightRefused(t, slug, got, "key whose creator was deactivated mid-flight")
}

// The same holds for an upload made with a session, not a key.
func TestIngestStraddlingSessionDeactivationIsRefused(t *testing.T) {
	slug := newProject(t, "inflight-session")
	person := azRegister(t, "inflight-session")
	azAddMember(t, slug, person.UserID, "admin")
	time.Sleep(150 * time.Millisecond)
	session := azLogin(t, person)

	got := inflightUpload(t, slug, session, func() { azSetActive(t, person.UserID, false) })
	requireInflightRefused(t, slug, got, "session deactivated mid-flight")
}

// A control: nothing changes mid-flight, the report lands.
func TestIngestWithAnUnchangedSessionStillLands(t *testing.T) {
	slug := newProject(t, "inflight-control")
	person := azRegister(t, "inflight-control")
	azAddMember(t, slug, person.UserID, "admin")
	time.Sleep(150 * time.Millisecond)
	session := azLogin(t, person)

	got := inflightUpload(t, slug, session, func() {})
	require.Equalf(t, http.StatusCreated, got.status, "%s", got.body)
}
