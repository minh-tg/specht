package server

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// The body window is a promise to operators and to CI links: deploy/README.md
// says the body has 30 s. That is long enough for the 25 MiB cap over a slow
// link (about 0.85 MiB/s) and short enough that a caller who trickles a body
// gives its place back soon. The other tests measure against the constant, so
// this one fails any change to it, and it runs under -short, which CI uses.
// Change the documentation together with the constant.
func TestIngestBodyWindow_IsThirtySeconds(t *testing.T) {
	assert.Equal(t, 30*time.Second, ingestBodyWindow)
}

// The handler must arm the connection with that window and not another value:
// the read deadline in force while the report is processed is the body window
// counted from the request, and the write deadline allows the whole upload,
// the processing window and the response.
func TestIngestReport_ArmsTheConnectionWithTheBodyWindow(t *testing.T) {
	var read, write time.Time
	var w *deadlineRecorder
	h := NewHandler(&mockUsecases{
		ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			w.mu.Lock()
			defer w.mu.Unlock()
			read, write = w.read, w.write
			return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
		},
	})
	w = &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodPost, ingestPath, strings.NewReader(validIngest))
	r = r.WithContext(auth.ContextWithIdentity(r.Context(), &auth.Identity{UserID: "u-admin", Role: auth.RoleAdmin}))
	before := time.Now()

	h.IngestReport(w, r)

	require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
	assert.WithinDuration(t, before.Add(ingestBodyWindow), read, 5*time.Second, "the body has the body window")
	assert.WithinDuration(t, before.Add(ingestWindow+ingestWriteSlack), write, 5*time.Second,
		"the response can be written a processing window and its slack after the body is in")
}

// A caller who trickles an authorized body over a real connection is cut at
// the body window with 408, and its place is given back.
func TestIngestReport_AnswersATricklingCallerWith408AtTheBodyWindow(t *testing.T) {
	if testing.Short() {
		t.Skip("takes the full body window")
	}
	srv, h := fairnessServer(t, 8, time.Second, okIngest())
	conn := trickleBody(t, srv, "key-a", `{"project":"my-app","scanner":"trivy","raw_data":"`, 1<<20)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Second):
				if _, err := conn.Write([]byte("a")); err != nil {
					return
				}
			}
		}
	}()
	start := time.Now()
	_ = conn.SetReadDeadline(time.Now().Add(ingestBodyWindow + 15*time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err, "no answer within the body window plus 15 s")
	defer resp.Body.Close()
	took := time.Since(start)

	assert.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
	assert.GreaterOrEqual(t, took, ingestBodyWindow-time.Second, "cut before the window ended")
	assert.Less(t, took, ingestBodyWindow+10*time.Second, "cut well after the window ended")
	_ = conn.Close()
	assert.Eventually(t, h.ingest.idle, 5*time.Second, 10*time.Millisecond, "the cut caller still holds its place")
}
