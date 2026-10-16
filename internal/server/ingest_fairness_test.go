package server

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

// countingReader counts the bytes read from it.
type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

func (c *countingReader) count() int64 { return c.n.Load() }

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) { clear(p); return len(p), nil }

// zeroes yields n bytes of 'a' without holding them.
func zeroes(n int64) io.Reader {
	return io.LimitReader(readerFunc(func(p []byte) (int, error) {
		for i := range p {
			p[i] = 'a'
		}
		return len(p), nil
	}), n)
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

const fairnessProjectID = "00000000-0000-0000-0000-000000000001"

// fairnessCallers maps a bearer to the identity the test server gives it, so
// real connections can stand for different callers.
func fairnessCaller(token string) *auth.Identity {
	switch token {
	case "key-a":
		return &auth.Identity{UserID: "creator", ProjectID: fairnessProjectID, KeyHash: "hash-a", IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
	case "key-b":
		return &auth.Identity{UserID: "creator", ProjectID: fairnessProjectID, KeyHash: "hash-b", IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
	case "key-c":
		return &auth.Identity{UserID: "creator", ProjectID: fairnessProjectID, KeyHash: "hash-c", IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
	case "key-d":
		return &auth.Identity{UserID: "creator-d", ProjectID: "id-other-app", KeyHash: "hash-d", IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
	case "key-e":
		return &auth.Identity{UserID: "creator-e", ProjectID: "id-third-app", KeyHash: "hash-e", IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
	case "outsider":
		return &auth.Identity{UserID: "outsider", Role: auth.RoleMember}
	}
	return nil
}

// fairnessServer serves the ingest handler over real connections. The
// callers are "key-a" and "key-b" (ingest keys of the one project) and
// "outsider" (a signed-in user with no project).
func fairnessServer(t *testing.T, concurrency int, queueWait time.Duration, mock *mockUsecases) (*httptest.Server, *Handler) {
	t.Helper()
	if mock.isProjectMemberFn == nil {
		mock.isProjectMemberFn = func(context.Context, string, string) (bool, error) { return false, nil }
	}
	if mock.getProjectFn == nil {
		// "my-app" is the default project; other slugs are projects of their
		// own, for tests that need callers who share nothing.
		mock.getProjectFn = func(_ context.Context, slug string) (*usecase.ProjectResponse, error) {
			if slug == "my-app" {
				return &usecase.ProjectResponse{ID: fairnessProjectID, Slug: slug}, nil
			}
			return &usecase.ProjectResponse{ID: "id-" + slug, Slug: slug}, nil
		}
	}
	h := NewHandler(mock)
	h.ingest = newIngestAdmission(concurrency, 0, queueWait)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident := fairnessCaller(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if ident == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.IngestReport(w, r.WithContext(auth.ContextWithIdentity(r.Context(), ident)))
	}))
	t.Cleanup(srv.Close)
	return srv, h
}

// trickle opens a connection, sends the request line, the headers and first,
// and then nothing more until the test sends the rest or closes it. The body
// is announced as 1 MiB.
func trickle(t *testing.T, srv *httptest.Server, token, first string) net.Conn {
	t.Helper()
	return trickleBody(t, srv, token, first, 1<<20)
}

// trickleBody is trickle for a body of the given length.
func trickleBody(t *testing.T, srv *httptest.Server, token, first string, length int) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	_, err = fmt.Fprintf(conn, "POST /api/v1/reports HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", token, length, first)
	require.NoError(t, err)
	return conn
}

func postIngest(t *testing.T, srv *httptest.Server, token, body string) (int, string, time.Duration) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)
	start := time.Now()
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), time.Since(start)
}

const validIngest = `{"project":"my-app","scanner":"trivy","raw_data":{"a":1}}`

func okIngest() *mockUsecases {
	return &mockUsecases{ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
		return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
	}}
}

// Eight signed-in users with no access, each trickling a body, used to hold
// every ingest slot and make every tenant's CI wait. They are now refused as
// soon as the project is known, and hold nothing.
func TestIngestFairness_TricklingOutsidersDoNotDelayALegitimateKey(t *testing.T) {
	srv, h := fairnessServer(t, 8, 300*time.Millisecond, okIngest())

	for range 8 {
		conn := trickle(t, srv, "outsider", `{"project":"my-app","scanner":"sarif","raw_data":"`)
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		require.NoError(t, err, "the outsider is answered without finishing its body")
		assert.Equal(t, http.StatusForbidden, resp.StatusCode)
		_ = resp.Body.Close()
	}

	status, body, took := postIngest(t, srv, "key-a", validIngest)
	assert.Equal(t, http.StatusCreated, status, body)
	assert.Less(t, took, 250*time.Millisecond, "the legitimate key does not wait")
	assert.True(t, h.ingest.idle())
}

// A caller who is allowed in but sends its body slowly fills its own places
// and nobody else's. Its extra requests wait their turn and are told to retry.
func TestIngestFairness_ASlowCallerFillsOnlyItsOwnPlaces(t *testing.T) {
	srv, h := fairnessServer(t, 4, 300*time.Millisecond, okIngest()) // two places each

	var slow []net.Conn
	for range 2 {
		slow = append(slow, trickle(t, srv, "key-a", `{"project":"my-app","scanner":"trivy","raw_data":"`))
	}
	time.Sleep(50 * time.Millisecond)

	// The same caller's next upload has no place and is told to retry.
	extra := trickle(t, srv, "key-a", `{"project":"my-app","scanner":"trivy","raw_data":"`)
	resp, err := http.ReadResponse(bufio.NewReader(extra), nil)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("Retry-After"))
	_ = resp.Body.Close()

	// Another caller is not delayed while the first one's bodies are in flight.
	status, body, took := postIngest(t, srv, "key-b", validIngest)
	assert.Equal(t, http.StatusCreated, status, body)
	assert.Less(t, took, 250*time.Millisecond)

	for _, c := range slow {
		_ = c.Close()
	}
	extra.Close()
	require.Eventually(t, h.ingest.idle, 5*time.Second, 10*time.Millisecond, "hung-up uploads give their places back")
}

// A body that is still arriving holds no global slot: with every slot taken
// by running ingests, another caller can still send its body, is not told to
// retry while it sends, and gets a slot once it has all of it and one is free.
func TestIngestFairness_ASlowBodyHoldsNoGlobalSlot(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 8)
	var once sync.Once
	mock := &mockUsecases{ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
		entered <- struct{}{}
		<-release
		return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
	}}
	srv, h := fairnessServer(t, 2, 400*time.Millisecond, mock) // two global slots, one place each
	defer once.Do(func() { close(release) })

	// Two projects, so that the project limit is not what holds the slots.
	var wg sync.WaitGroup
	for token, project := range map[string]string{"key-a": "my-app", "key-d": "other-app"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			postIngest(t, srv, token, strings.ReplaceAll(validIngest, "my-app", project))
		}()
	}
	<-entered
	<-entered // both global slots are taken by running ingests

	// A third caller, of a third project, sends the start of a 1 MiB body and waits. (The body is
	// big on purpose: for a small one the server holds its answer back until
	// the body has arrived, which would hide a refusal.)
	const prefix, suffix = `{"project":"third-app","scanner":"trivy","raw_data":"`, `"}`
	full := prefix + strings.Repeat("a", 1<<20-len(prefix)-len(suffix)) + suffix
	half := 4096
	conn := trickleBody(t, srv, "key-e", full[:half], len(full))
	got := make(chan *http.Response, 1)
	go func() {
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err == nil {
			got <- resp
		}
	}()
	select {
	case resp := <-got:
		t.Fatalf("answered %d while its body was still arriving, so it was waiting on a slot", resp.StatusCode)
	case <-time.After(900 * time.Millisecond): // more than twice the queue wait
	}

	// The rest of the body arrives. Every slot is still taken, so the ingest
	// waits for one and is told to retry once the wait runs out.
	_, err := io.WriteString(conn, full[half:])
	require.NoError(t, err)
	select {
	case resp := <-got:
		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
		_ = resp.Body.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("no answer once the body was complete")
	}

	once.Do(func() { close(release) })
	wg.Wait()
	require.Eventually(t, h.ingest.idle, 5*time.Second, 10*time.Millisecond)
}

// An outsider with a 25 MiB body is refused after reading a few KiB of it, and
// the report is never decoded or handed to a parser.
func TestIngestReport_AnOutsiderCostsNoParseTime(t *testing.T) {
	mock := &mockUsecases{ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
		t.Error("the use case (and so the parser) must not run for a caller without access")
		return nil, errors.New("unexpected")
	}}
	mock.isProjectMemberFn = func(context.Context, string, string) (bool, error) { return false, nil }
	h := NewHandler(mock)
	// A body that is not valid JSON after its first bytes: a handler that
	// decoded it would answer 400 invalid_json, not 403.
	src := &countingReader{r: io.MultiReader(strings.NewReader(`{"project":"my-app","scanner":"sarif","raw_data":{"pad":"`), zeroes(25<<20))}
	req := httptest.NewRequest("POST", "/api/v1/reports", src)
	req.ContentLength = -1
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "outsider", Role: auth.RoleMember}))
	w := httptest.NewRecorder()

	h.IngestReport(w, req)

	requireAPIError(t, w, http.StatusForbidden, "project_access_denied")
	assert.Less(t, src.count(), int64(ingestHeadBytes), "only the head of the 25 MiB body was read")
	assert.True(t, h.ingest.idle())
}

// The role check runs before the body is read too: a member who may not ingest
// is refused at the head.
func TestIngestReport_ARoleThatMayNotIngestIsRefusedAtTheHead(t *testing.T) {
	mock := &mockUsecases{
		isProjectMemberFn: func(context.Context, string, string) (bool, error) { return true, nil },
		authorizeIngestFn: func(context.Context, string) error { return usecase.ErrProjectAccessDenied },
	}
	h := NewHandler(mock)
	src := &countingReader{r: io.MultiReader(strings.NewReader(`{"project":"my-app","scanner":"sarif","raw_data":"`), zeroes(5<<20))}
	req := httptest.NewRequest("POST", "/api/v1/reports", src)
	req.ContentLength = -1
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "viewer", Role: auth.RoleViewer}))
	w := httptest.NewRecorder()

	h.IngestReport(w, req)

	requireAPIError(t, w, http.StatusForbidden, "project_access_denied")
	assert.Less(t, src.count(), int64(ingestHeadBytes))
}

// The project that was authorized is the one that is ingested. A body that
// names another project later, or in another letter case, is refused.
func TestIngestReport_TheAuthorizedProjectIsTheIngestedProject(t *testing.T) {
	for name, body := range map[string]string{
		"repeated key":    `{"project":"mine","scanner":"trivy","raw_data":{"a":1},"project":"victim"}`,
		"other key case":  `{"project":"mine","scanner":"trivy","raw_data":{"a":1},"PROJECT":"victim"}`,
		"decoded last":    `{"project":"mine","scanner":"trivy","raw_data":{"a":1},"Project":"victim"}`,
		"differs in case": `{"project":"mine","scanner":"trivy","raw_data":{"a":1},"project":"MINE"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var authorized []string
			mock := &mockUsecases{
				authorizeIngestFn: func(_ context.Context, slug string) error { authorized = append(authorized, slug); return nil },
				ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
					t.Error("the report must not be ingested")
					return nil, errors.New("unexpected")
				},
			}
			h := NewHandler(mock)
			req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(body))
			req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "u-admin", Role: auth.RoleAdmin}))
			w := httptest.NewRecorder()

			h.IngestReport(w, req)

			requireAPIError(t, w, http.StatusBadRequest, "invalid_field")
			assert.Equal(t, []string{"mine"}, authorized, "only the project in the head was authorized")
			assert.True(t, h.ingest.idle())
		})
	}
}

func TestIngestReport_AProjectNamedTooLateIsRefused(t *testing.T) {
	h := NewHandler(okIngest())
	body := `{"raw_data":"` + strings.Repeat("a", ingestHeadBytes) + `","project":"my-app","scanner":"trivy"}`
	req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "u-admin", Role: auth.RoleAdmin}))
	w := httptest.NewRecorder()

	h.IngestReport(w, req)

	requireAPIError(t, w, http.StatusBadRequest, "missing_field")
	assert.Contains(t, w.Body.String(), "project must be named in the first")
}

// Everything an ingest holds comes back whichever way the request ends.
func TestIngestReport_ReleasesEverythingOnEveryPath(t *testing.T) {
	admin := &auth.Identity{UserID: "u-admin", Role: auth.RoleAdmin}
	denied := &auth.Identity{UserID: "outsider", Role: auth.RoleMember}
	deadline := &deadlineBody{head: `{"project":"my-app","scanner":"trivy","raw_data":"`}
	tests := []struct {
		name   string
		ident  *auth.Identity
		body   io.Reader
		length int64
		mock   *mockUsecases
		status int
	}{
		{"success", admin, strings.NewReader(validIngest), -1, okIngest(), http.StatusCreated},
		{
			"use case error", admin, strings.NewReader(validIngest), -1,
			&mockUsecases{ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
				return nil, errors.New("boom")
			}}, http.StatusUnprocessableEntity,
		},
		{"no access", denied, strings.NewReader(validIngest), -1, &mockUsecases{isProjectMemberFn: func(context.Context, string, string) (bool, error) { return false, nil }}, http.StatusForbidden},
		{"malformed json", admin, strings.NewReader(`{"project":"my-app","scanner":`), -1, okIngest(), http.StatusBadRequest},
		{"missing scanner", admin, strings.NewReader(`{"project":"my-app","raw_data":{}}`), -1, okIngest(), http.StatusBadRequest},
		{"bad field", admin, strings.NewReader(`{"project":"my-app","scanner":"trivy","raw_data":{},"branch":"a\nb"}`), -1, okIngest(), http.StatusBadRequest},
		{"declared too large", admin, strings.NewReader(validIngest), maxIngestBodyBytes + 1, okIngest(), http.StatusRequestEntityTooLarge},
		{"streamed too large", admin, io.MultiReader(strings.NewReader(`{"project":"my-app","scanner":"trivy","raw_data":"`), zeroes(maxIngestBodyBytes+10)), -1, okIngest(), http.StatusRequestEntityTooLarge},
		{"body deadline", admin, deadline, -1, okIngest(), http.StatusRequestTimeout},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler(tc.mock)
			req := httptest.NewRequest("POST", "/api/v1/reports", tc.body)
			req.ContentLength = tc.length
			req = req.WithContext(auth.ContextWithIdentity(req.Context(), tc.ident))
			w := httptest.NewRecorder()

			h.IngestReport(w, req)

			assert.Equal(t, tc.status, w.Code, w.Body.String())
			assert.True(t, h.ingest.idle(), "a slot, a gate or a memory charge was left behind")
		})
	}
}

// deadlineBody yields its head and then fails the way a connection read does
// when the read deadline passes.
type deadlineBody struct {
	head string
	done bool
}

func (d *deadlineBody) Read(p []byte) (int, error) {
	if d.done {
		return 0, os.ErrDeadlineExceeded
	}
	d.done = true
	return copy(p, d.head), nil
}

// A caller that is busy is told so with Retry-After, and the use case never
// runs for it.
func TestIngestReport_AnOverCapCallerIsToldToRetry(t *testing.T) {
	var runs atomic.Int32
	mock := okIngest()
	inner := mock.ingestReportFn
	mock.ingestReportFn = func(ctx context.Context, in usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
		runs.Add(1)
		return inner(ctx, in)
	}
	h := NewHandler(mock)
	h.ingest = newIngestAdmission(2, 0, 20*time.Millisecond) // one place per caller
	hold, err := h.ingest.enter(context.Background(), "user:u-admin", "user:u-admin")
	require.NoError(t, err)
	defer hold.release()

	req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(validIngest))
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "u-admin", Role: auth.RoleAdmin}))
	w := httptest.NewRecorder()
	h.IngestReport(w, req)

	requireAPIError(t, w, http.StatusServiceUnavailable, "ingest_busy")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.Zero(t, runs.Load())
}
