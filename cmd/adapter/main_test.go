package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/client"
)

func TestIngestReport_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/reports", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		json.NewEncoder(w).Encode(client.IngestResponse{
			ReportID:          "rep-123",
			TotalFindings:     3,
			ThresholdBreached: false,
		})
	}))
	defer srv.Close()

	cl := client.New(srv.URL, client.WithToken("test-key"))
	resp, err := cl.IngestReport(&client.IngestPayload{
		Project: "my-app",
		Scanner: "trivy",
		RawData: json.RawMessage(`{"image":"test"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "rep-123", resp.ReportID)
	assert.Equal(t, 3, resp.TotalFindings)
	assert.False(t, resp.ThresholdBreached)
}

func TestIngestReport_ThresholdBreached(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(client.IngestResponse{
			ReportID:          "rep-123",
			TotalFindings:     1,
			ThresholdBreached: true,
		})
	}))
	defer srv.Close()

	cl := client.New(srv.URL, client.WithToken("test-key"))
	resp, err := cl.IngestReport(&client.IngestPayload{
		Project: "my-app",
		Scanner: "trivy",
		RawData: json.RawMessage(`{"image":"test"}`),
	})
	require.NoError(t, err)
	assert.True(t, resp.ThresholdBreached)
}

func TestIngestReport_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "ingest_failed", "message": "unknown scanner"},
		})
	}))
	defer srv.Close()

	cl := client.New(srv.URL, client.WithToken("test-key"))
	_, err := cl.IngestReport(&client.IngestPayload{
		Project: "my-app",
		Scanner: "unknown",
		RawData: json.RawMessage(`{}`),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown scanner")
}

func TestIngestReport_IntroducedOnly_Payload(t *testing.T) {
	var captured client.IngestPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		err := json.NewDecoder(r.Body).Decode(&captured)
		require.NoError(t, err)

		json.NewEncoder(w).Encode(client.IngestResponse{
			ReportID:          "rep-456",
			TotalFindings:     5,
			ThresholdBreached: false,
			ScanMode:          "full",
			IntroducedCount:   0,
			PreExistingCount:  5,
		})
	}))
	defer srv.Close()

	cl := client.New(srv.URL, client.WithToken("test-key"))
	resp, err := cl.IngestReport(&client.IngestPayload{
		Project:            "my-app",
		Scanner:            "trivy",
		RawData:            json.RawMessage(`{"image":"test"}`),
		BaseRevision:       "main",
		CommitSha:          "abc12345",
		Branch:             "feat/test",
		GateIntroducedOnly: true,
	})
	require.NoError(t, err)
	assert.True(t, captured.GateIntroducedOnly)
	assert.Equal(t, "main", captured.BaseRevision)
	assert.Equal(t, "abc12345", captured.CommitSha)
	assert.Equal(t, "feat/test", captured.Branch)
	assert.Equal(t, 0, resp.IntroducedCount)
	assert.Equal(t, 5, resp.PreExistingCount)
	assert.False(t, resp.ThresholdBreached)
}

func TestDetectCIEnvironment_GitHub(t *testing.T) {
	t.Setenv("GITHUB_BASE_REF", "main")
	t.Setenv("GITHUB_SHA", "commit123")
	t.Setenv("GITHUB_REF_NAME", "feature-branch")

	var baseRef, commit, branch string
	detectCIEnvironment(&baseRef, &commit, &branch)

	assert.Equal(t, "main", baseRef)
	assert.Equal(t, "commit123", commit)
	assert.Equal(t, "feature-branch", branch)
}

func TestDetectCIEnvironment_GitLab(t *testing.T) {
	t.Setenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "master")
	t.Setenv("CI_COMMIT_SHA", "commit456")
	t.Setenv("CI_COMMIT_REF_NAME", "mr-branch")

	var baseRef, commit, branch string
	detectCIEnvironment(&baseRef, &commit, &branch)

	assert.Equal(t, "master", baseRef)
	assert.Equal(t, "commit456", commit)
	assert.Equal(t, "mr-branch", branch)
}
