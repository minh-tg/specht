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

		json.NewEncoder(w).Encode(ingestResponse{
			ReportID:          "rep-123",
			TotalFindings:     3,
			ThresholdBreached: false,
		})
	}))
	defer srv.Close()

	resp, err := ingestReport(srv.URL, "test-key", ingestPayload{
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
		json.NewEncoder(w).Encode(ingestResponse{
			ReportID:          "rep-123",
			TotalFindings:     1,
			ThresholdBreached: true,
		})
	}))
	defer srv.Close()

	resp, err := ingestReport(srv.URL, "test-key", ingestPayload{
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

	_, err := ingestReport(srv.URL, "test-key", ingestPayload{
		Project: "my-app",
		Scanner: "unknown",
		RawData: json.RawMessage(`{}`),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown scanner")
}
