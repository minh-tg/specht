//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// outsiderToken registers a fresh account that belongs to no project and
// returns its session token.
func outsiderToken(t *testing.T) string {
	t.Helper()
	email := fmt.Sprintf("outsider-%s@example.com", randomHex(4))
	status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/register", "",
		map[string]string{"email": email, "password": adminPass})
	require.Equalf(t, http.StatusCreated, status, "register: %s", raw)
	return login(t, email, adminPass)
}

// Eight signed-in users with no access to a project used to hold all eight
// ingest slots by sending their bodies slowly, so every tenant's CI got 503
// ingest_busy. They are now refused as soon as the project is read, and a
// project's own key is not delayed.
func TestE2E_TricklingOutsidersDoNotStarveAnIngestKey(t *testing.T) {
	slug := newProject(t, "fair")
	key := mintKey(t, slug)
	outsider := outsiderToken(t)

	addr := strings.TrimPrefix(baseURL, "http://")
	for range 8 {
		conn, err := net.Dial("tcp", addr)
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		_, err = fmt.Fprintf(conn, "POST /api/v1/reports HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: 1048576\r\n\r\n%s",
			addr, outsider, `{"project":"`+slug+`","scanner":"sarif","raw_data":"`)
		require.NoError(t, err)

		require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err, "the outsider is answered without finishing its body")
		require.Equal(t, http.StatusForbidden, resp.StatusCode)
		_ = resp.Body.Close()
	}

	start := time.Now()
	status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", key, ingestBody(t, slug, "high-medium.sarif.json"))
	require.Equal(t, http.StatusCreated, status, string(raw))
	require.Less(t, time.Since(start), 5*time.Second, "the project's key does not wait for the outsiders")
}

// A caller with no access to the project is refused from the head of its body.
// The body here is broken JSON after the head: the old order decoded all of it
// first and answered 400 invalid_json, so a 403 shows nothing was decoded.
func TestE2E_AnOutsiderIsRefusedBeforeTheBodyIsDecoded(t *testing.T) {
	slug := newProject(t, "fair-decode")
	outsider := outsiderToken(t)

	var body bytes.Buffer
	fmt.Fprintf(&body, `{"project":%q,"scanner":"sarif","raw_data":{"version":"2.1.0","runs":[],"pad":"`, slug)
	body.WriteString(strings.Repeat("a", 20<<20))
	body.WriteString(`"}`) // the raw_data and outer objects stay open

	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/reports", &body)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+outsider)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// A project that is not named near the start of the body is refused with a
// message that says so.
func TestE2E_AProjectNamedAfterAHugeValueIsRefused(t *testing.T) {
	slug := newProject(t, "fair-late")
	key := mintKey(t, slug)

	body := `{"raw_data":"` + strings.Repeat("a", 100<<10) + `","project":"` + slug + `","scanner":"sarif"}`
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/reports", strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}
