package client

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeleteReportReportsHowManyFindingsWereArchived(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
		assert.Equal(t, "/api/v1/projects/demo/reports/r1", r.URL.Path)
		w.Header().Set("X-Archived-Findings", "2")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	archived, err := New(srv.URL, WithToken("k")).DeleteReport("demo", "r1")

	require.NoError(t, err)
	assert.Equal(t, 2, archived)
}

func TestDeleteReportWithoutTheHeaderMeansNoneWereCounted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	archived, err := New(srv.URL, WithToken("k")).DeleteReport("demo", "r1")

	require.NoError(t, err)
	assert.Zero(t, archived)
}

func TestDeleteReportSurfacesTheServersRefusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"report not found"}}`))
	}))
	defer srv.Close()

	_, err := New(srv.URL, WithToken("k")).DeleteReport("demo", "nope")

	require.Error(t, err)
	assert.Contains(t, err.Error(), "report not found")
}

func TestUpdateEnvironmentSendsAllThreeSettings(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/v1/projects/demo/environments/e1", r.URL.Path)
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"id":"e1","name":"production","tier":"production","internet_facing":true,"data_sensitivity":"restricted"}`))
	}))
	defer srv.Close()

	env, err := New(srv.URL, WithToken("k")).UpdateEnvironment("demo", "e1", EnvironmentSettings{Tier: "production", InternetFacing: true, DataSensitivity: "restricted"})

	require.NoError(t, err)
	assert.Equal(t, map[string]any{"tier": "production", "internet_facing": true, "data_sensitivity": "restricted"}, got,
		"false must be sent too, or it could never be set")
	assert.True(t, env.InternetFacing)
	assert.Equal(t, "restricted", env.DataSensitivity)
}

func TestUpdateEnvironmentSendsFalseToo(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"id":"e1"}`))
	}))
	defer srv.Close()

	_, err := New(srv.URL, WithToken("k")).UpdateEnvironment("demo", "e1", EnvironmentSettings{Tier: "test", DataSensitivity: "public"})

	require.NoError(t, err)
	assert.Equal(t, false, got["internet_facing"])
}

func TestIngestResponseSaysWhenItWasAReplay(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"report_id":"r1","total_findings":3,"threshold_breached":false,"scan_mode":"full","replayed":true}`))
	}))
	defer srv.Close()

	resp, err := New(srv.URL, WithToken("k")).IngestReport(&IngestPayload{Project: "demo", Scanner: "trivy", RawData: json.RawMessage(`{}`)})

	require.NoError(t, err)
	assert.True(t, resp.Replayed)
}
