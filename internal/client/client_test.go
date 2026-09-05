package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}))
	defer srv.Close()

	cl := New(srv.URL)
	status, err := cl.Health()
	require.NoError(t, err)
	assert.Equal(t, "ok", status)
}

func TestAuth(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		json.NewEncoder(w).Encode(AuthResponse{
			Token:  "tok",
			UserID: "uid",
			Email:  "a@b.com",
		})
	}))
	defer srv.Close()

	cl := New(srv.URL)
	resp, err := cl.Register("a@b.com", "pass")
	require.NoError(t, err)
	assert.Equal(t, "tok", resp.Token)

	resp, err = cl.Login("a@b.com", "pass")
	require.NoError(t, err)
	assert.Equal(t, "uid", resp.UserID)

	resp, err = cl.Refresh("rtok")
	require.NoError(t, err)
	assert.Equal(t, "a@b.com", resp.Email)

	err = cl.Logout("rtok")
	require.NoError(t, err)
}

func TestProjects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/projects":
			json.NewEncoder(w).Encode([]Project{{Slug: "my-app"}})
		case "POST /api/v1/projects":
			json.NewEncoder(w).Encode(Project{Slug: "new-app"})
		case "GET /api/v1/projects/test-app":
			json.NewEncoder(w).Encode(Project{Slug: "test-app"})
		}
	}))
	defer srv.Close()

	cl := New(srv.URL, WithToken("key"))
	projects, err := cl.ListProjects()
	require.NoError(t, err)
	assert.Len(t, projects, 1)

	p, err := cl.CreateProject("New", "new-app", "")
	require.NoError(t, err)
	assert.Equal(t, "new-app", p.Slug)

	p, err = cl.GetProject("test-app")
	require.NoError(t, err)
	assert.Equal(t, "test-app", p.Slug)
}

func TestGateStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(GateStatus{ThresholdBreached: true, BlockingCount: 5})
	}))
	defer srv.Close()

	cl := New(srv.URL, WithToken("key"))
	gs, err := cl.GetGateStatus("my-app", "critical")
	require.NoError(t, err)
	assert.True(t, gs.ThresholdBreached)
	assert.Equal(t, int64(5), gs.BlockingCount)
}

func TestFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v1/projects/my-app/findings":
			json.NewEncoder(w).Encode([]Finding{{ID: "f1"}})
		case "GET /api/v1/findings/f1":
			json.NewEncoder(w).Encode(Finding{ID: "f1", CurrentSeverity: "high"})
		case "PATCH /api/v1/findings/f1":
			json.NewEncoder(w).Encode(TriageResponse{FindingID: "f1", AnalysisState: "false_positive"})
		case "POST /api/v1/findings/bulk-analysis":
			json.NewEncoder(w).Encode([]TriageResponse{{FindingID: "f1"}})
		case "GET /api/v1/findings/f1/events":
			json.NewEncoder(w).Encode([]FindingEvent{{EventType: "analysis_changed"}})
		case "POST /api/v1/findings/f1/verify":
			json.NewEncoder(w).Encode(VerifyResponse{FindingID: "f1", Outcome: "verified_fixed"})
		}
	}))
	defer srv.Close()

	cl := New(srv.URL, WithToken("key"))

	findings, err := cl.ListFindings("my-app", []string{"high"}, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, findings, 1)

	f, err := cl.GetFinding("f1")
	require.NoError(t, err)
	assert.Equal(t, "high", f.CurrentSeverity)

	tr, err := cl.TriageFinding("f1", &TriageRequest{AnalysisState: "false_positive"})
	require.NoError(t, err)
	assert.Equal(t, "false_positive", tr.AnalysisState)

	btr, err := cl.BulkTriage(&BulkTriageRequest{FindingIDs: []string{"f1"}, AnalysisState: "false_positive"})
	require.NoError(t, err)
	assert.Len(t, btr, 1)

	events, err := cl.ListFindingEvents("f1", nil, 0, 0)
	require.NoError(t, err)
	assert.Len(t, events, 1)

	vr, err := cl.VerifyFinding("f1")
	require.NoError(t, err)
	assert.Equal(t, "verified_fixed", vr.Outcome)
}

func TestAPIKeyEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/auth/apikeys":
			json.NewEncoder(w).Encode(APIKey{Name: "test"})
		case "GET /api/v1/auth/apikeys":
			json.NewEncoder(w).Encode([]APIKey{{Name: "test"}})
		case "DELETE /api/v1/auth/apikeys/key-1":
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	cl := New(srv.URL, WithToken("key"))
	ak, err := cl.CreateAPIKey("my-app", "test")
	require.NoError(t, err)
	assert.Equal(t, "test", ak.Name)

	keys, err := cl.ListAPIKeys("my-app")
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	err = cl.RevokeAPIKey("my-app", "key-1")
	require.NoError(t, err)
}

func TestListEndpoints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects/my-app/reports":
			json.NewEncoder(w).Encode([]Report{{ID: "r1"}})
		case "/api/v1/reports/r1":
			json.NewEncoder(w).Encode(Report{ID: "r1", ToolName: "trivy"})
		case "/api/v1/projects/my-app/environments":
			json.NewEncoder(w).Encode([]Environment{{Name: "prod"}})
		case "/api/v1/projects/my-app/targets":
			json.NewEncoder(w).Encode([]Target{{Name: "app"}})
		case "/api/v1/projects/my-app/artifacts":
			json.NewEncoder(w).Encode([]Artifact{{Name: "img"}})
		}
	}))
	defer srv.Close()

	cl := New(srv.URL, WithToken("key"))

	reports, err := cl.ListReports("my-app", 10, 0)
	require.NoError(t, err)
	assert.Len(t, reports, 1)

	r, err := cl.GetReport("r1")
	require.NoError(t, err)
	assert.Equal(t, "trivy", r.ToolName)

	envs, err := cl.ListEnvironments("my-app")
	require.NoError(t, err)
	assert.Len(t, envs, 1)

	targets, err := cl.ListTargets("my-app")
	require.NoError(t, err)
	assert.Len(t, targets, 1)

	arts, err := cl.ListArtifacts("my-app")
	require.NoError(t, err)
	assert.Len(t, arts, 1)
}

func TestWaivers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "POST /api/v1/projects/my-app/waivers":
			json.NewEncoder(w).Encode(Waiver{Name: "w1"})
		case "GET /api/v1/projects/my-app/waivers":
			json.NewEncoder(w).Encode([]Waiver{{Name: "w1"}})
		case "GET /api/v1/projects/my-app/waivers/w-1":
			json.NewEncoder(w).Encode(WaiverDetail{})
		case "PUT /api/v1/projects/my-app/waivers/w-1":
			json.NewEncoder(w).Encode(Waiver{Name: "updated"})
		case "DELETE /api/v1/projects/my-app/waivers/w-1":
			w.WriteHeader(http.StatusNoContent)
		case "POST /api/v1/projects/my-app/waivers/w-1/toggle":
			json.NewEncoder(w).Encode(Waiver{Enabled: false})
		case "GET /api/v1/projects/my-app/waivers/w-1/events":
			json.NewEncoder(w).Encode([]WaiverEvent{{EventType: "created"}})
		case "POST /api/v1/projects/my-app/waivers/check-match":
			json.NewEncoder(w).Encode(CheckWaiverMatchResponse{Matched: true})
		}
	}))
	defer srv.Close()

	cl := New(srv.URL, WithToken("key"))

	w, err := cl.CreateWaiver("my-app", &CreateWaiverRequest{Name: "w1"})
	require.NoError(t, err)
	assert.Equal(t, "w1", w.Name)

	waivers, err := cl.ListWaivers("my-app")
	require.NoError(t, err)
	assert.Len(t, waivers, 1)

	_, err = cl.GetWaiver("my-app", "w-1")
	require.NoError(t, err)

	w, err = cl.UpdateWaiver("my-app", "w-1", &UpdateWaiverRequest{Name: "updated"})
	require.NoError(t, err)
	assert.Equal(t, "updated", w.Name)

	err = cl.DeleteWaiver("my-app", "w-1")
	require.NoError(t, err)

	w, err = cl.ToggleWaiver("my-app", "w-1")
	require.NoError(t, err)
	assert.False(t, w.Enabled)

	events, err := cl.ListWaiverEvents("my-app", "w-1")
	require.NoError(t, err)
	assert.Len(t, events, 1)

	matched, err := cl.CheckWaiverMatch("my-app", "f1")
	require.NoError(t, err)
	assert.True(t, matched)
}

func TestErrorHandling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "invalid_token", "message": "bad key"},
		})
	}))
	defer srv.Close()

	cl := New(srv.URL, WithToken("bad"))
	_, err := cl.ListProjects()
	require.Error(t, err)

	var ce *Error
	require.ErrorAs(t, err, &ce)
	assert.True(t, ce.Unauthorized())
	assert.Equal(t, "invalid_token", ce.Code)
	assert.Contains(t, ce.Message, "bad key")
}

func TestWithHTTPClient(t *testing.T) {
	hc := &http.Client{}
	cl := New("http://localhost", WithHTTPClient(hc))
	assert.Same(t, hc, cl.httpClient)
}

func TestMe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(UserProfile{Email: "a@b.com"})
	}))
	defer srv.Close()

	cl := New(srv.URL, WithToken("key"))
	profile, err := cl.Me()
	require.NoError(t, err)
	assert.Equal(t, "a@b.com", profile.Email)
}

func TestListScanners(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/scanners" {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode([]ScannerDescriptor{
			{Name: "trivy", Version: "2", FindingKinds: []string{"sca", "secret", "iac"}, ProvidesPackages: true},
			{Name: "semgrep", Version: "2.1", FindingKinds: []string{"sast"}},
		})
	}))
	defer srv.Close()

	cl := New(srv.URL, WithToken("key"))
	scanners, err := cl.ListScanners()
	require.NoError(t, err)
	require.Len(t, scanners, 2)
	assert.Equal(t, "trivy", scanners[0].Name)
	assert.Equal(t, []string{"sca", "secret", "iac"}, scanners[0].FindingKinds)
	assert.True(t, scanners[0].ProvidesPackages)
	assert.Equal(t, "sast", scanners[1].FindingKinds[0])
}
