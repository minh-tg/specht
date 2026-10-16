package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

// slowUpload posts a body that trickles in over about 400ms against a server
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
		for _, chunk := range []string{`{"project":"my-app",`, `"scanner":"trivy",`, `"raw_data":{"a":1}}`} {
			_, _ = pw.Write([]byte(chunk))
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

func TestIngestReport_SlowUploadSurvivesTheServerTimeouts(t *testing.T) {
	// Control: without the extended deadlines the server cuts the upload off.
	status, _, err := slowUpload(t, drainAndAnswer())
	if err == nil {
		assert.NotEqual(t, http.StatusOK, status, "the control must fail, or this test proves nothing")
	}

	h := NewHandler(&mockUsecases{
		ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			time.Sleep(200 * time.Millisecond) // processing that outlasts WriteTimeout
			return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
		},
	})
	asAdmin := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.IngestReport(w, r.WithContext(auth.ContextWithIdentity(r.Context(), &auth.Identity{UserID: "u-admin", Role: auth.RoleAdmin})))
	})
	status, body, err := slowUpload(t, asAdmin)

	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, status)
	assert.Contains(t, body, "rep-1", "the whole upload arrived and the response was written")
}
