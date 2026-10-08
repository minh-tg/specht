package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// slowUpload posts a body that trickles in over about 600ms against a server
// whose ReadTimeout and WriteTimeout are far shorter, which is the situation
// of a large report arriving over a slow CI link.
func slowUpload(t *testing.T, handler http.Handler) (status int, body string, err error) {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.Config.ReadTimeout = 150 * time.Millisecond
	srv.Config.WriteTimeout = 150 * time.Millisecond
	srv.Start()
	defer srv.Close()

	pr, pw := io.Pipe()
	go func() {
		for i := 0; i < 3; i++ {
			_, _ = pw.Write([]byte("chunk"))
			time.Sleep(200 * time.Millisecond)
		}
		_ = pw.Close()
	}()
	req, reqErr := http.NewRequest(http.MethodPost, srv.URL, pr)
	require.NoError(t, reqErr)
	resp, doErr := srv.Client().Do(req)
	if doErr != nil {
		return 0, "", doErr
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func drainAndAnswer() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusRequestTimeout)
			return
		}
		time.Sleep(200 * time.Millisecond) // processing that outlasts WriteTimeout
		_, _ = w.Write(got)
	})
}

func TestIngestLimits_SlowUploadSurvivesTheServerTimeouts(t *testing.T) {
	// Control: without the extended deadlines the server cuts the upload off.
	status, _, err := slowUpload(t, drainAndAnswer())
	if err == nil {
		assert.NotEqual(t, http.StatusOK, status, "the control must fail, or this test proves nothing")
	}

	gated := ingestLimits(1, time.Second, 5*time.Second, 5*time.Second)(drainAndAnswer())
	status, body, err := slowUpload(t, gated)

	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "chunkchunkchunk", body, "the whole upload arrived and the response was written")
}
