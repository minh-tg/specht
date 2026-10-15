package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var staticTestModTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func staticTestHandler(t *testing.T) http.Handler {
	t.Helper()
	body := strings.Repeat("console.log('specht');\n", 200)
	fsys := fstest.MapFS{
		"app.js":     {Data: []byte(body), ModTime: staticTestModTime},
		"style.css":  {Data: []byte(strings.Repeat("a{color:red}\n", 200)), ModTime: staticTestModTime},
		"index.html": {Data: []byte(strings.Repeat("<p>shell</p>\n", 200)), ModTime: staticTestModTime},
		"font.woff2": {Data: bytes.Repeat([]byte("wOF2"), 500), ModTime: staticTestModTime},
		"logo.png":   {Data: bytes.Repeat([]byte("png!"), 500), ModTime: staticTestModTime},
	}
	return SecurityHeaders(CompressStatic(http.FileServer(http.FS(fsys))))
}

func staticGet(h http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func gunzip(t *testing.T, b []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(b))
	require.NoError(t, err)
	out, err := io.ReadAll(zr)
	require.NoError(t, err)
	return out
}

func TestCompressStatic_gzipsTextAssets(t *testing.T) {
	h := staticTestHandler(t)
	for _, path := range []string{"/app.js", "/style.css", "/"} {
		t.Run(path, func(t *testing.T) {
			plain := staticGet(h, path, nil)
			require.Equal(t, http.StatusOK, plain.Code)
			assert.Empty(t, plain.Header().Get("Content-Encoding"))

			gz := staticGet(h, path, map[string]string{"Accept-Encoding": "gzip"})
			require.Equal(t, http.StatusOK, gz.Code)
			assert.Equal(t, "gzip", gz.Header().Get("Content-Encoding"))
			assert.Contains(t, gz.Header().Values("Vary"), "Accept-Encoding")
			assert.Empty(t, gz.Header().Get("Content-Length"))
			assert.Less(t, gz.Body.Len(), plain.Body.Len())
			assert.Equal(t, plain.Body.Bytes(), gunzip(t, gz.Body.Bytes()))
			assert.Equal(t, plain.Header().Get("Content-Type"), gz.Header().Get("Content-Type"))
		})
	}
}

func TestCompressStatic_identityBodyUnchanged(t *testing.T) {
	h := staticTestHandler(t)
	rec := staticGet(h, "/app.js", nil)
	assert.Contains(t, rec.Header().Values("Vary"), "Accept-Encoding")
	assert.Equal(t, "4600", rec.Header().Get("Content-Length"))
	assert.Equal(t, 4600, rec.Body.Len())

	rec = staticGet(h, "/app.js", map[string]string{"Accept-Encoding": "identity"})
	assert.Empty(t, rec.Header().Get("Content-Encoding"))
	assert.Equal(t, 4600, rec.Body.Len())
}

func TestCompressStatic_skipsCompressedFormats(t *testing.T) {
	h := staticTestHandler(t)
	for _, path := range []string{"/font.woff2", "/logo.png"} {
		t.Run(path, func(t *testing.T) {
			rec := staticGet(h, path, map[string]string{"Accept-Encoding": "gzip"})
			require.Equal(t, http.StatusOK, rec.Code)
			assert.Empty(t, rec.Header().Get("Content-Encoding"))
			assert.Equal(t, "2000", rec.Header().Get("Content-Length"))
		})
	}
}

func TestCompressStatic_conditionalRequestStill304(t *testing.T) {
	h := staticTestHandler(t)
	lm := staticTestModTime.Format(http.TimeFormat)
	for _, enc := range []string{"", "gzip"} {
		rec := staticGet(h, "/app.js", map[string]string{"If-Modified-Since": lm, "Accept-Encoding": enc})
		assert.Equal(t, http.StatusNotModified, rec.Code, "Accept-Encoding=%q", enc)
		assert.Empty(t, rec.Body.String())
	}
}

func TestCompressStatic_lastModifiedKept(t *testing.T) {
	h := staticTestHandler(t)
	rec := staticGet(h, "/app.js", map[string]string{"Accept-Encoding": "gzip"})
	assert.Equal(t, staticTestModTime.Format(http.TimeFormat), rec.Header().Get("Last-Modified"))
}

func TestCompressStatic_rangeRequestsNotCompressed(t *testing.T) {
	h := staticTestHandler(t)
	rec := staticGet(h, "/app.js", map[string]string{"Accept-Encoding": "gzip", "Range": "bytes=0-9"})
	assert.Equal(t, http.StatusPartialContent, rec.Code)
	assert.Empty(t, rec.Header().Get("Content-Encoding"))
	assert.Equal(t, "console.lo", rec.Body.String())
}

func TestCompressStatic_securityHeadersOnCompressedResponse(t *testing.T) {
	h := staticTestHandler(t)
	rec := staticGet(h, "/app.js", map[string]string{"Accept-Encoding": "gzip"})
	require.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
	assert.Contains(t, rec.Header().Get("Content-Security-Policy"), "default-src 'self'")
	assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "SAMEORIGIN", rec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", rec.Header().Get("Referrer-Policy"))
}
