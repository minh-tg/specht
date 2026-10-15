package server

import (
	"net/http"
	"path"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
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

// CompressStatic gzips responses for the embedded SPA files. Mount it around
// the static file server only: compressing API responses that mix secrets with
// attacker-influenced input would expose them to BREACH-style attacks.
//
// Range requests are passed through untouched because byte ranges refer to the
// identity encoding. Responses carry Vary: Accept-Encoding whether or not they
// were compressed, so shared caches keep the variants apart.
func CompressStatic(next http.Handler) http.Handler {
	compressed := middleware.Compress(5, compressibleTypes...)(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || !compressibleExts[strings.ToLower(path.Ext(r.URL.Path))] {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")
		if r.Header.Get("Range") != "" {
			next.ServeHTTP(w, r)
			return
		}
		compressed.ServeHTTP(w, r)
	})
}
