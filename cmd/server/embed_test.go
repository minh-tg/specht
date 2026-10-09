package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/minh-tg/specht/internal/server"
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

func TestSPAHandler_securityHeadersOnEveryResponse(t *testing.T) {
	assets := fstest.MapFS{
		"dist/index.html":          &fstest.MapFile{Data: []byte("<!doctype html><title>Specht</title>")},
		"dist/assets/app-a1b2.js":  &fstest.MapFile{Data: []byte("console.log('app')")},
		"dist/assets/app-a1b2.css": &fstest.MapFile{Data: []byte("body{}")},
	}
	router := server.NewRouter(server.RouterConfig{
		Usecases:       nil,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	ts := httptest.NewServer(spaHandlerWithFS(router, assets))
	defer ts.Close()

	wantCSP := "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; object-src 'none'"

	paths := []struct {
		name string
		path string
		code int
	}{
		{name: "root document", path: "/", code: http.StatusOK},
		{name: "deep link fallback", path: "/acme/findings", code: http.StatusOK},
		{name: "existing asset", path: "/assets/app-a1b2.js", code: http.StatusOK},
		{name: "api route", path: "/api/v1/health", code: http.StatusOK},
	}
	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Get(ts.URL + tc.path)
			if err != nil {
				t.Fatal(err)
			}
			// Closing an HTTP response body is best-effort test cleanup.
			defer func() {
				_ = resp.Body.Close()
			}()

			if resp.StatusCode != tc.code {
				t.Errorf("expected %d, got %d", tc.code, resp.StatusCode)
			}
			if got := resp.Header.Get("Content-Security-Policy"); got != wantCSP {
				t.Errorf("Content-Security-Policy = %q, want %q", got, wantCSP)
			}
			if got := resp.Header.Get("X-Frame-Options"); got != "SAMEORIGIN" {
				t.Errorf("X-Frame-Options = %q, want SAMEORIGIN", got)
			}
			if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
			}
			if got := resp.Header.Get("Referrer-Policy"); got != "strict-origin-when-cross-origin" {
				t.Errorf("Referrer-Policy = %q, want strict-origin-when-cross-origin", got)
			}
		})
	}
}

func newSPATestHandler(t *testing.T) http.Handler {
	t.Helper()
	assets := fstest.MapFS{
		"dist/index.html":         &fstest.MapFile{Data: []byte("<!doctype html><title>Specht</title>")},
		"dist/assets/app-a1b2.js": &fstest.MapFile{Data: []byte("console.log('app')")},
	}
	return spaHandlerWithFS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}), assets)
}

func TestSPAHandler_missingAssetReturns404NotShell(t *testing.T) {
	handler := newSPATestHandler(t)

	for _, path := range []string{
		"/assets/does-not-exist.js",
		"/assets/",
		"/assets",
		"/favicon.svg",
	} {
		t.Run(path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))

			if rec.Code != http.StatusNotFound {
				t.Errorf("expected 404, got %d", rec.Code)
			}
			if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
				t.Errorf("Cache-Control = %q, want no-store", cc)
			}
			if strings.Contains(rec.Body.String(), "<!doctype html>") {
				t.Errorf("missing file answered with the app shell: %q", rec.Body.String())
			}
		})
	}
}

func TestSPAHandler_existingAssetIsImmutable(t *testing.T) {
	handler := newSPATestHandler(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/assets/app-a1b2.js", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=31536000, immutable" {
		t.Errorf("Cache-Control = %q, want immutable", cc)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/javascript" {
		t.Errorf("Content-Type = %q, want text/javascript", ct)
	}
}

func TestSPAHandler_deepLinkFallsBackToIndex(t *testing.T) {
	handler := newSPATestHandler(t)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/acme/findings", nil))

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want no-cache", cc)
	}
	if !strings.Contains(rec.Body.String(), "<title>Specht</title>") {
		t.Errorf("expected app shell, got %q", rec.Body.String())
	}
}
