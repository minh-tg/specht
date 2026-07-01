package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIngestReport_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/reports", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		json.NewEncoder(w).Encode(map[string]string{"report_id": "rep-123"})
	}))
	defer srv.Close()

	reportID, err := ingestReport(srv.URL, "test-key", ingestPayload{
		Project: "my-app",
		Scanner: "trivy",
		RawData: json.RawMessage(`{"image":"test"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "rep-123", reportID)
}

func TestIngestReport_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "ingest_failed", "message": "unknown scanner"},
		})
	}))
	defer srv.Close()

	_, err := ingestReport(srv.URL, "test-key", ingestPayload{
		Project: "my-app",
		Scanner: "unknown",
		RawData: json.RawMessage(`{}`),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown scanner")
}

func TestCheckFindings_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		assert.Contains(t, r.URL.String(), "my-app")
		assert.Contains(t, r.URL.String(), "severity=high,critical")
		assert.Contains(t, r.URL.String(), "status=open")

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]finding{})
	}))
	defer srv.Close()

	findings, err := checkFindings(srv.URL, "test-key", "my-app", "high,critical", "open", "")
	require.NoError(t, err)
	assert.Len(t, findings, 0)
}

func TestCheckFindings_WithFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]finding{
			{Fingerprint: "fp1", CurrentTitle: "CVE-2026-1234", CurrentSeverity: "critical"},
		})
	}))
	defer srv.Close()

	findings, err := checkFindings(srv.URL, "test-key", "my-app", "high,critical", "open", "")
	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "CVE-2026-1234", findings[0].CurrentTitle)
}

func TestCheckFindings_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := checkFindings(srv.URL, "test-key", "nonexistent", "high,critical", "open", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestCheckFindings_WithToolFilter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Contains(t, r.URL.String(), "tool=trivy")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode([]finding{})
	}))
	defer srv.Close()

	findings, err := checkFindings(srv.URL, "test-key", "my-app", "high,critical", "open", "trivy")
	require.NoError(t, err)
	assert.Len(t, findings, 0)
}
