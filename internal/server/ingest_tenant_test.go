package server

import (
	"context"
	"net/http"
	"net/http/httptest"
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

// admitFor enters and admits one ingest of rawBytes for a principal of a
// project.
func admitFor(t *testing.T, a *ingestAdmission, principal, tenant string, rawBytes int) *ingestTicket {
	t.Helper()
	tk, err := a.enter(context.Background(), principal, tenant)
	require.NoError(t, err)
	require.NoError(t, admitTicket(tk, context.Background(), rawBytes), "%s of %s should get a slot", principal, tenant)
	return tk
}

func TestIngestAdmission_AProjectHoldsAtMostHalfTheGlobalSlots(t *testing.T) {
	a := newIngestAdmission(8, 0, 30*time.Millisecond)
	assert.Equal(t, 4, a.perTenant)
	assert.Equal(t, 1, newIngestAdmission(1, 0, time.Second).perTenant, "a single slot is still usable")
	assert.Equal(t, 1, newIngestAdmission(2, 0, time.Second).perTenant)
	assert.Equal(t, 1, newIngestAdmission(3, 0, time.Second).perTenant)
	assert.Equal(t, 4, newIngestAdmission(9, 0, time.Second).perTenant)

	// Two principals of one project, two ingests each: every principal is
	// within its own limit, and together they hold the project's four.
	var held []*ingestTicket
	for _, principal := range []string{"key:1", "user:manager"} {
		for range 2 {
			held = append(held, admitFor(t, a, principal, "project-a", 10))
		}
	}
	assert.Len(t, a.slots, 4)

	extra, err := a.enter(context.Background(), "key:3", "project-a")
	require.NoError(t, err, "reading a body costs the project nothing")
	require.ErrorIs(t, admitTicket(extra, context.Background(), 10), errIngestBusy, "a fifth slot for one project, whoever asks")
	extra.release()
	assert.Len(t, a.slots, 4, "the refused ingest left no slot behind")

	other := admitFor(t, a, "key:b", "project-b", 10)
	assert.Len(t, a.slots, 5, "another project still gets a slot")
	other.release()

	held[0].release()
	again := admitFor(t, a, "key:3", "project-a", 10)
	again.release()
	for _, tk := range held[1:] {
		tk.release()
	}
	assert.True(t, a.idle(), "the project's gate is dropped with its last ingest")
}

func TestIngestAdmission_AProjectGetsAProportionalShareOfTheMemory(t *testing.T) {
	a := newIngestAdmission(8, 64*8000, 30*time.Millisecond) // budget for 8000 raw bytes
	assert.EqualValues(t, 64*4000, a.tenantShare, "half the budget for half the slots")

	big := admitFor(t, a, "key:1", "project-a", 4000)

	// A second principal has memory allowance of its own, but the project's
	// is used up.
	second, err := a.enter(context.Background(), "key:2", "project-a")
	require.NoError(t, err)
	require.ErrorIs(t, admitTicket(second, context.Background(), 100), errIngestBusy)
	second.release()

	rival := admitFor(t, a, "key:b", "project-b", 3000)
	rival.release()
	big.release()
	assert.True(t, a.idle(), "a refused admit gives back the allowance it took first")
}

// tenantCaller maps a bearer to an identity: two principals of project A (a
// manager's session and an ingest key) and the one ingest key of project B.
func tenantCaller(token string) *auth.Identity {
	switch token {
	case "a-key":
		return &auth.Identity{UserID: "a-manager", ProjectID: tenantA, KeyHash: "a1", IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
	case "a-manager-session":
		return &auth.Identity{UserID: "a-manager", Role: auth.RoleMember}
	case "b-key":
		return &auth.Identity{UserID: "b-owner", ProjectID: tenantB, KeyHash: "b1", IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
	}
	return nil
}

const (
	tenantA = "00000000-0000-0000-0000-00000000000a"
	tenantB = "00000000-0000-0000-0000-00000000000b"
)

// One project with two principals, each within its own limit, used to hold all
// eight global slots and make another project's CI wait. The project is now
// held to half of them.
func TestIngestReport_OneProjectWithTwoPrincipalsLeavesSlotsForAnother(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	var running atomic.Int32
	mock := &mockUsecases{
		getProjectFn: func(_ context.Context, slug string) (*usecase.ProjectResponse, error) {
			id := tenantA
			if slug == "b-app" {
				id = tenantB
			}
			return &usecase.ProjectResponse{ID: id, Slug: slug}, nil
		},
		isProjectMemberFn: func(_ context.Context, projectID, userID string) (bool, error) {
			return projectID == tenantA && userID == "a-manager", nil
		},
		// A report that takes long to store: it holds its slot until released
		// unless it is project B's.
		ingestReportFn: func(_ context.Context, in usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			if in.ProjectSlug == "a-app" {
				running.Add(1)
				<-release
			}
			return &usecase.IngestReportOutput{ReportID: "r"}, nil
		},
	}
	h := NewHandler(mock)
	h.ingest = newIngestAdmission(DefaultIngestConcurrency, 0, 400*time.Millisecond)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident := tenantCaller(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if ident == nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.IngestReport(w, r.WithContext(auth.ContextWithIdentity(r.Context(), ident)))
	}))
	defer srv.Close()
	// Registered last, so it runs first: srv.Close waits for requests that
	// are blocked on release, which a failed assertion must not leave closed.
	defer once.Do(func() { close(release) })

	var wg sync.WaitGroup
	statuses := make(chan int, 2*DefaultIngestConcurrency)
	for _, token := range []string{"a-key", "a-manager-session"} {
		for range DefaultIngestConcurrency / 2 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				status, _, _ := postIngest(t, srv, token, `{"project":"a-app","scanner":"trivy","raw_data":{"a":1}}`)
				statuses <- status
			}()
		}
	}
	require.Eventually(t, func() bool { return running.Load() >= int32(DefaultIngestConcurrency/2) }, 5*time.Second, 10*time.Millisecond,
		"project A takes its half of the slots")
	time.Sleep(200 * time.Millisecond)
	assert.EqualValues(t, DefaultIngestConcurrency/2, running.Load(), "and no more, though its eight requests come from two principals")

	status, body, took := postIngest(t, srv, "b-key", `{"project":"b-app","scanner":"trivy","raw_data":{"a":1}}`)
	assert.Equal(t, http.StatusCreated, status, body)
	assert.Less(t, took, 300*time.Millisecond, "project B does not wait")

	// A's other four wait their queue wait and are told to retry.
	for range DefaultIngestConcurrency / 2 {
		select {
		case status := <-statuses:
			assert.Equal(t, http.StatusServiceUnavailable, status)
		case <-time.After(5 * time.Second):
			t.Fatal("a refused ingest of project A was not answered")
		}
	}
	once.Do(func() { close(release) })
	wg.Wait()
	for range DefaultIngestConcurrency / 2 {
		assert.Equal(t, http.StatusCreated, <-statuses)
	}
	assert.True(t, h.ingest.idle())
}
