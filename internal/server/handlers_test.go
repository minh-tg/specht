package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/v1/health", nil)
	w := httptest.NewRecorder()

	router := NewRouter(RouterConfig{Usecases: nil})
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf(`body["status"] = %q, want "ok"`, body["status"])
	}
}

func TestRespondJSON(t *testing.T) {
	w := httptest.NewRecorder()
	respondJSON(w, http.StatusCreated, map[string]string{"hello": "world"})

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want 'application/json'", ct)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body["hello"] != "world" {
		t.Errorf(`body["hello"] = %q, want "world"`, body["hello"])
	}
}

func TestRespondError(t *testing.T) {
	w := httptest.NewRecorder()
	respondError(w, http.StatusBadRequest, "missing_field", "project is required")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error.Code != "missing_field" {
		t.Errorf("code = %q, want 'missing_field'", resp.Error.Code)
	}
	if resp.Error.Message != "project is required" {
		t.Errorf("message = %q, want 'project is required'", resp.Error.Message)
	}
}

func TestIngestReport_InvalidJSON(t *testing.T) {
	handler := &Handler{uc: nil}
	body := strings.NewReader(`not json`)
	req := httptest.NewRequest("POST", "/api/v1/reports", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.IngestReport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Error.Code != "invalid_json" {
		t.Errorf("code = %q, want 'invalid_json'", resp.Error.Code)
	}
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

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}

			var resp struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if resp.Error.Code != tt.wantCode {
				t.Errorf("code = %q, want %q", resp.Error.Code, tt.wantCode)
			}
		})
	}
}

func TestNewRouterRoutes(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: nil})
	if router == nil {
		t.Fatal("NewRouter returned nil")
	}

	t.Run("health endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/health", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("health status = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("reports POST endpoint exists", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/reports", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code == http.StatusNotFound {
			t.Error("POST /api/v1/reports returned 404")
		}
	})

	t.Run("unknown route returns 404", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/nonexistent", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code != http.StatusNotFound {
			t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
		}
	})
}
