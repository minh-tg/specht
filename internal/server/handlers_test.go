package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()

	router := NewRouter(RouterConfig{Usecases: nil})
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "ok", body["status"])
}

func TestRespondJSON(t *testing.T) {
	w := httptest.NewRecorder()
	respondJSON(w, http.StatusCreated, map[string]string{"hello": "world"})

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "world", body["hello"])
}

func TestRespondError(t *testing.T) {
	w := httptest.NewRecorder()
	respondError(w, http.StatusBadRequest, "missing_field", "project is required")

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "missing_field", resp.Error.Code)
	assert.Equal(t, "project is required", resp.Error.Message)
}

func TestIngestReport_InvalidJSON(t *testing.T) {
	handler := &Handler{uc: nil}
	body := strings.NewReader(`not json`)
	req := httptest.NewRequest("POST", "/api/v1/reports", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.IngestReport(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid_json", resp.Error.Code)
}

func TestIngestReport_MissingFields(t *testing.T) {
	handler := &Handler{uc: nil}

	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantCode   string
	}{
		{"missing project", `{"scanner":"trivy","raw_data":{}}`, http.StatusBadRequest, "missing_field"},
		{"missing scanner", `{"project":"test","raw_data":{}}`, http.StatusBadRequest, "missing_field"},
		{"missing raw_data", `{"project":"test","scanner":"trivy"}`, http.StatusBadRequest, "missing_field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.IngestReport(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			var resp struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, tt.wantCode, resp.Error.Code)
		})
	}
}

func TestNewRouterRoutes(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: nil})
	require.NotNil(t, router)

	t.Run("health endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("reports POST endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.NotEqual(t, http.StatusNotFound, w.Code)
	})

	t.Run("unknown route returns 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}
