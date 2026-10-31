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

// An upload that authenticated before its key's creator was deactivated and
// finishes sending its body after the deactivation is refused with the answer a
// revoked key gets, and stores nothing.
func TestIngestStraddlingCreatorDeactivationIsRefused(t *testing.T) {
	slug := newProject(t, "inflight-deactivation")
	creator := azRegister(t, "inflight")
	azAddMember(t, slug, creator.UserID, "admin")
	key := azKeyBy(t, azLogin(t, creator), slug)
	body, err := json.Marshal(ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{"commit_sha": randomHex(20), "branch": "inflight"}))
	require.NoError(t, err)

	pr, pw := io.Pipe()
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/reports", pr)
	require.NoError(t, err)
	req.ContentLength = int64(len(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key.Token)
	type answer struct {
		status int
		body   []byte
	}
	done := make(chan answer, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- answer{status: -1}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		done <- answer{resp.StatusCode, raw}
	}()
	_, err = pw.Write(body[:len(body)/2])
	require.NoError(t, err)
	time.Sleep(300 * time.Millisecond)
	azSetActive(t, creator.UserID, false)
	_, err = pw.Write(body[len(body)/2:])
	require.NoError(t, err)
	require.NoError(t, pw.Close())

	got := <-done
	require.Equal(t, http.StatusUnauthorized, got.status, "the report landed after its key's creator was deactivated: %s", got.body)
	require.Equal(t, "invalid_token", errorCode(t, got.body))

	reports := request[[]projectReport](t, http.MethodGet, "/api/v1/projects/"+slug+"/reports", adminToken, nil, http.StatusOK)
	require.Empty(t, reports, "a refused upload stores no report")
}
