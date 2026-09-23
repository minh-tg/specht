package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSPAHandler_apiRoutesPassThrough(t *testing.T) {
	mockAPI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte(`{"status":"ok"}`)); err != nil {
			t.Errorf("write health response: %v", err)
		}
	})

	handler := spaHandler(mockAPI)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	// Closing an HTTP response body is best-effort test cleanup.
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestSPAHandler_servesIndexForSPARoutes(t *testing.T) {
	mockAPI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	handler := spaHandler(mockAPI)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/some-project/findings")
	if err != nil {
		t.Fatal(err)
	}
	// Closing an HTTP response body is best-effort test cleanup.
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for SPA fallback, got %d", resp.StatusCode)
	}

	cc := resp.Header.Get("Cache-Control")
	if cc != "no-cache" {
		t.Errorf("expected no-cache, got %s", cc)
	}
}

func TestSPAHandler_servesRoot(t *testing.T) {
	mockAPI := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	handler := spaHandler(mockAPI)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	// Closing an HTTP response body is best-effort test cleanup.
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for root, got %d", resp.StatusCode)
	}
}

func TestSPAHandler_fallbackDocumentHasMetadata(t *testing.T) {
	body, err := frontendDist.ReadFile("dist/index.html")
	if err != nil {
		t.Fatal(err)
	}
	bodyString := string(body)
	if !strings.Contains(bodyString, `<html lang="en">`) {
		t.Fatalf("fallback document has no language metadata: %s", bodyString)
	}
	if !strings.Contains(bodyString, `<title>Specht</title>`) {
		t.Fatalf("fallback document has no title: %s", bodyString)
	}
}

func TestSPAHandler_prefersBuiltFrontend(t *testing.T) {
	assets := fstest.MapFS{
		"dist/index.html":      &fstest.MapFile{Data: []byte("placeholder")},
		"dist/dist/index.html": &fstest.MapFile{Data: []byte("built frontend")},
	}

	handler := spaHandlerWithFS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}), assets)

	ts := httptest.NewServer(handler)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	// Closing an HTTP response body is best-effort test cleanup.
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "built frontend" {
		t.Fatalf("expected built frontend, got %q", body)
	}
}
