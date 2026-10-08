package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHealthcheckURL(t *testing.T) {
	tests := []struct{ addr, want string }{
		{":8080", "http://127.0.0.1:8080/api/v1/health"},
		{"", "http://127.0.0.1:8080/api/v1/health"},
		{"0.0.0.0:9000", "http://127.0.0.1:9000/api/v1/health"},
		{"[::]:9000", "http://127.0.0.1:9000/api/v1/health"},
		{"127.0.0.1:8081", "http://127.0.0.1:8081/api/v1/health"},
		{"10.1.2.3:8080", "http://10.1.2.3:8080/api/v1/health"},
	}
	for _, tc := range tests {
		if got := healthcheckURL(tc.addr); got != tc.want {
			t.Errorf("healthcheckURL(%q) = %q, want %q", tc.addr, got, tc.want)
		}
	}
}

func TestRunHealthcheck(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer ok.Close()
	if err := runHealthcheck(ok.URL+"/api/v1/health", time.Second); err != nil {
		t.Fatalf("healthy server reported unhealthy: %v", err)
	}

	unhealthy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "db down", http.StatusServiceUnavailable)
	}))
	defer unhealthy.Close()
	if err := runHealthcheck(unhealthy.URL, time.Second); err == nil {
		t.Fatal("a 503 must be unhealthy")
	}

	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer slow.Close()
	if err := runHealthcheck(slow.URL, 50*time.Millisecond); err == nil {
		t.Fatal("a hung server must time out as unhealthy")
	}

	closed := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := closed.URL
	closed.Close()
	if err := runHealthcheck(url, time.Second); err == nil {
		t.Fatal("a refused connection must be unhealthy")
	}
}
