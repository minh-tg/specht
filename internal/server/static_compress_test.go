package server

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
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
			assert.Equal(t, strconv.Itoa(gz.Body.Len()), gz.Header().Get("Content-Length"))
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

func staticCounted(t *testing.T) (*staticCompressor, http.Handler) {
	t.Helper()
	fsys := fstest.MapFS{
		"app.js":     {Data: []byte(strings.Repeat("console.log('specht');\n", 200)), ModTime: staticTestModTime},
		"other.js":   {Data: []byte(strings.Repeat("console.log('other');\n", 200)), ModTime: staticTestModTime},
		"index.html": {Data: []byte(strings.Repeat("<p>shell</p>\n", 200)), ModTime: staticTestModTime},
	}
	c := newStaticCompressor(http.FileServer(http.FS(fsys)))
	return c, c
}

func TestCompressStatic_compressesEachAssetOnce(t *testing.T) {
	c, h := staticCounted(t)
	gzHdr := map[string]string{"Accept-Encoding": "gzip"}

	first := staticGet(h, "/app.js", gzHdr)
	require.Equal(t, "gzip", first.Header().Get("Content-Encoding"))
	require.EqualValues(t, 1, c.compressions.Load())

	for i := 0; i < 5; i++ {
		again := staticGet(h, "/app.js", gzHdr)
		assert.Equal(t, first.Body.Bytes(), again.Body.Bytes())
		assert.Equal(t, first.Header().Get("ETag"), again.Header().Get("ETag"))
		assert.Equal(t, first.Header().Get("Content-Length"), again.Header().Get("Content-Length"))
	}
	assert.EqualValues(t, 1, c.compressions.Load(), "repeat requests are served from the stored bytes")

	staticGet(h, "/other.js", gzHdr)
	assert.EqualValues(t, 2, c.compressions.Load(), "a different file is compressed on its own")
}

// Every client-side route serves index.html; the cache is keyed by content, so
// distinct URLs for one body neither recompress nor add entries.
func TestCompressStatic_sameBodyUnderManyPathsIsOneEntry(t *testing.T) {
	shell := []byte(strings.Repeat("<p>shell</p>\n", 200))
	c := newStaticCompressor(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(shell)
	}))
	for i := 0; i < 20; i++ {
		rec := staticGet(c, "/projects/p"+strconv.Itoa(i), map[string]string{"Accept-Encoding": "gzip"})
		require.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
		assert.Equal(t, shell, gunzip(t, rec.Body.Bytes()))
	}
	assert.EqualValues(t, 1, c.compressions.Load())
	assert.Len(t, c.assets, 1)
}

func TestCompressStatic_etagAnswersConditionalRequests(t *testing.T) {
	_, h := staticCounted(t)
	gz := staticGet(h, "/app.js", map[string]string{"Accept-Encoding": "gzip"})
	etag := gz.Header().Get("ETag")
	require.NotEmpty(t, etag)

	rec := staticGet(h, "/app.js", map[string]string{"Accept-Encoding": "gzip", "If-None-Match": etag})
	assert.Equal(t, http.StatusNotModified, rec.Code)
	assert.Empty(t, rec.Body.String())
	assert.Equal(t, etag, rec.Header().Get("ETag"))

	rec = staticGet(h, "/app.js", map[string]string{"Accept-Encoding": "gzip", "If-None-Match": `"stale"`})
	assert.Equal(t, http.StatusOK, rec.Code)

	other := staticGet(h, "/other.js", map[string]string{"Accept-Encoding": "gzip"})
	assert.NotEqual(t, etag, other.Header().Get("ETag"), "different content, different ETag")
}

func TestCompressStatic_headMatchesGetHeaders(t *testing.T) {
	_, h := staticCounted(t)
	get := staticGet(h, "/app.js", map[string]string{"Accept-Encoding": "gzip"})

	req := httptest.NewRequest(http.MethodHead, "/app.js", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.String())
	assert.Equal(t, "gzip", rec.Header().Get("Content-Encoding"))
	assert.Equal(t, get.Header().Get("Content-Length"), rec.Header().Get("Content-Length"))
	assert.Equal(t, get.Header().Get("ETag"), rec.Header().Get("ETag"))
}

func TestCompressStatic_acceptEncodingNegotiation(t *testing.T) {
	c, h := staticCounted(t)
	for _, enc := range []string{"", "identity", "deflate", "gzip;q=0", "gzip; q=0.0", "br"} {
		rec := staticGet(h, "/app.js", map[string]string{"Accept-Encoding": enc})
		assert.Empty(t, rec.Header().Get("Content-Encoding"), "Accept-Encoding=%q", enc)
	}
	for _, enc := range []string{"gzip", "GZIP", "br, gzip", "deflate, gzip;q=0.5", "gzip, deflate, br"} {
		rec := staticGet(h, "/app.js", map[string]string{"Accept-Encoding": enc})
		assert.Equal(t, "gzip", rec.Header().Get("Content-Encoding"), "Accept-Encoding=%q", enc)
	}
	assert.EqualValues(t, 1, c.compressions.Load())
}

func TestCompressStatic_missingFileIsNotCompressedOrCached(t *testing.T) {
	c, h := staticCounted(t)
	rec := staticGet(h, "/missing.js", map[string]string{"Accept-Encoding": "gzip"})
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Empty(t, rec.Header().Get("Content-Encoding"))
	assert.EqualValues(t, 0, c.compressions.Load())
	assert.Empty(t, c.assets)
}
