package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Vite copies frontend/public to the dist root without a content hash, so
// those files keep one URL across releases and must be revalidated. Only the
// hashed files under assets/ are cached for a year.
func TestSPAHandler_CacheControlByLocation(t *testing.T) {
	assets := fstest.MapFS{
		"dist/index.html":                 &fstest.MapFile{Data: []byte("<!doctype html>")},
		"dist/theme-init.js":              &fstest.MapFile{Data: []byte("/* v1 */")},
		"dist/site.webmanifest":           &fstest.MapFile{Data: []byte("{}")},
		"dist/favicon.svg":                &fstest.MapFile{Data: []byte("<svg/>")},
		"dist/session-refresh.js":         &fstest.MapFile{Data: []byte("/* worker */")},
		"dist/assets/index-a1b2c3d4.js":   &fstest.MapFile{Data: []byte("/* app */")},
		"dist/assets/font-e5f6a7b8.woff2": &fstest.MapFile{Data: []byte("font")},
	}
	handler := spaHandlerWithFS(http.NotFoundHandler(), assets, nil)

	for path, want := range map[string]string{
		"/theme-init.js":              "no-cache",
		"/site.webmanifest":           "no-cache",
		"/favicon.svg":                "no-cache",
		"/session-refresh.js":         "no-cache",
		"/assets/index-a1b2c3d4.js":   "public, max-age=31536000, immutable",
		"/assets/font-e5f6a7b8.woff2": "public, max-age=31536000, immutable",
	} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusOK, rec.Code, path)
		assert.Equal(t, want, rec.Header().Get("Cache-Control"), path)
	}
}
