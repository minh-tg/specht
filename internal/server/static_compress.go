package server

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/http"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// compressibleTypes are the response content types gzip is applied to. The
// list doubles as a second filter behind the extension check, so a binary
// body is never compressed even if its URL looks like text.
var compressibleTypes = []string{
	"text/html",
	"text/css",
	"text/javascript",
	"text/plain",
	"application/json",
	"image/svg+xml",
}

// compressibleExts are the extensions of embedded files worth compressing.
// The empty extension covers client-side routes that fall back to index.html.
var compressibleExts = map[string]bool{
	"":      true,
	".js":   true,
	".css":  true,
	".html": true,
	".svg":  true,
	".json": true,
	".map":  true,
	".txt":  true,
}

// maxCompressedAssets caps how many compressed bodies one CompressStatic keeps.
// The embedded frontend has a few dozen files; the cap only matters if the
// wrapped handler ever serves unbounded distinct content, which is then
// compressed per request instead of stored.
const maxCompressedAssets = 512

// gzipAsset is one compressed body, made once and shared by every request for
// the same content.
type gzipAsset struct {
	once sync.Once
	data []byte
	etag string
}

// staticCompressor gzips the embedded files. A body is compressed the first
// time it is served and the result is kept, keyed by the digest of the body,
// so a file costs one compression however often it is requested. The digest
// keys the cache because many URLs (every client-side route) serve the same
// index.html: a path-keyed cache would grow with whatever paths a client sends.
type staticCompressor struct {
	next http.Handler

	mu     sync.Mutex
	assets map[[sha256.Size]byte]*gzipAsset

	// compressions counts the gzip runs, for tests.
	compressions atomic.Int64
}

// CompressStatic gzips responses for the embedded SPA files. Mount it around
// the static file server only: compressing API responses that mix secrets with
// attacker-influenced input would expose them to BREACH-style attacks.
//
// Each distinct body is compressed once and the bytes are served from memory
// afterwards, with Content-Length and a strong ETag, so a flood of requests
// for one asset costs a hash of the file and not a compression. Range
// requests are passed through untouched because byte ranges refer to the
// identity encoding. Responses carry Vary: Accept-Encoding whether or not they
// were compressed, so shared caches keep the variants apart.
func CompressStatic(next http.Handler) http.Handler {
	return newStaticCompressor(next)
}

func newStaticCompressor(next http.Handler) *staticCompressor {
	return &staticCompressor{next: next, assets: map[[sha256.Size]byte]*gzipAsset{}}
}

func (c *staticCompressor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if (r.Method != http.MethodGet && r.Method != http.MethodHead) || !compressibleExts[strings.ToLower(path.Ext(r.URL.Path))] {
		c.next.ServeHTTP(w, r)
		return
	}
	w.Header().Add("Vary", "Accept-Encoding")
	if r.Header.Get("Range") != "" || !acceptsGzip(r) {
		c.next.ServeHTTP(w, r)
		return
	}

	// A HEAD request is answered from the GET response so the body it would
	// have is known.
	inner := r
	if r.Method == http.MethodHead {
		inner = r.Clone(r.Context())
		inner.Method = http.MethodGet
	}
	rec := &bufferedResponse{header: http.Header{}}
	c.next.ServeHTTP(rec, inner)

	if rec.status == 0 {
		rec.status = http.StatusOK
	}
	if rec.status != http.StatusOK || rec.header.Get("Content-Encoding") != "" || !compressibleType(rec.header.Get("Content-Type")) {
		rec.replay(w, r.Method == http.MethodHead)
		return
	}

	sum := sha256.Sum256(rec.body.Bytes())
	asset := c.asset(sum)
	asset.once.Do(func() {
		c.compressions.Add(1)
		asset.data = gzipBytes(rec.body.Bytes())
		asset.etag = `"` + hex.EncodeToString(sum[:16]) + `-gzip"`
	})

	h := w.Header()
	for k, v := range rec.header {
		h[k] = v
	}
	h.Del("Content-Length")
	h.Set("Content-Encoding", "gzip")
	h.Set("ETag", asset.etag)
	if etagMatches(r.Header.Get("If-None-Match"), asset.etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(asset.data)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(asset.data)
	}
}

// asset returns the cache entry for a body digest. Past the cap the entry is
// not stored.
func (c *staticCompressor) asset(sum [sha256.Size]byte) *gzipAsset {
	c.mu.Lock()
	defer c.mu.Unlock()
	if a, ok := c.assets[sum]; ok {
		return a
	}
	a := &gzipAsset{}
	if len(c.assets) < maxCompressedAssets {
		c.assets[sum] = a
	}
	return a
}

func gzipBytes(b []byte) []byte {
	var out bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&out, 5)
	_, _ = zw.Write(b)
	_ = zw.Close()
	return out.Bytes()
}

// acceptsGzip reports whether the client lists gzip with a non-zero weight.
func acceptsGzip(r *http.Request) bool {
	for _, header := range r.Header.Values("Accept-Encoding") {
		for _, part := range strings.Split(header, ",") {
			name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
			if !strings.EqualFold(strings.TrimSpace(name), "gzip") {
				continue
			}
			params = strings.ReplaceAll(strings.ToLower(params), " ", "")
			if q, ok := strings.CutPrefix(params, "q="); ok {
				if v, err := strconv.ParseFloat(q, 64); err == nil && v == 0 {
					return false
				}
			}
			return true
		}
	}
	return false
}

func compressibleType(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && slices.Contains(compressibleTypes, mt)
}

// bufferedResponse holds a handler's response so it can be rewritten or
// replayed.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(status int) {
	if b.status == 0 {
		b.status = status
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	if b.status == 0 {
		b.status = http.StatusOK
	}
	return b.body.Write(p)
}

// replay sends the buffered response unchanged.
func (b *bufferedResponse) replay(w http.ResponseWriter, headOnly bool) {
	h := w.Header()
	for k, v := range b.header {
		h[k] = v
	}
	w.WriteHeader(b.status)
	if !headOnly {
		_, _ = w.Write(b.body.Bytes())
	}
}
