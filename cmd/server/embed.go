package main

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"net/netip"
	"path"
	"strings"

	"github.com/minh-tg/specht/internal/server"
)

//go:embed dist
var frontendDist embed.FS

var mimeTypes = map[string]string{
	".js":    "text/javascript; charset=utf-8",
	".css":   "text/css; charset=utf-8",
	".html":  "text/html; charset=utf-8",
	".svg":   "image/svg+xml",
	".png":   "image/png",
	".ico":   "image/x-icon",
	".woff2": "font/woff2",
	".woff":  "font/woff",
	".json":  "application/json",
}

type spaFileSystem struct {
	fs.FS
}

func (s spaFileSystem) Open(name string) (fs.File, error) {
	f, err := s.FS.Open(name)
	if err != nil {
		return s.FS.Open("index.html")
	}
	return f, nil
}

func spaHandler(apiHandler http.Handler, trustedProxies []netip.Prefix) http.Handler {
	return spaHandlerWithFS(apiHandler, frontendDist, trustedProxies)
}

func cleanSPAPath(p string) string {
	cleanPath := path.Clean(p)
	if cleanPath == "." || cleanPath == "/" {
		return "index.html"
	}
	return strings.TrimPrefix(cleanPath, "/")
}

func setSPAHeaders(w http.ResponseWriter, cleanPath string) {
	ext := path.Ext(cleanPath)
	if ct, ok := mimeTypes[ext]; ok {
		w.Header().Set("Content-Type", ct)
	} else if mimeType := mime.TypeByExtension(ext); mimeType != "" {
		w.Header().Set("Content-Type", mimeType)
	}
	if ext != "" && ext != ".html" && cleanPath != "session-refresh.js" {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
}

// isAssetPath reports whether a cleaned path points into the Vite asset
// directory, including the directory itself.
func isAssetPath(cleanPath string) bool {
	return cleanPath == "assets" || strings.HasPrefix(cleanPath, "assets/")
}

// isAppRoute reports whether a cleaned path is a client-side route that
// should fall back to index.html: no file extension and not an asset path.
func isAppRoute(cleanPath string) bool {
	return !isAssetPath(cleanPath) && path.Ext(cleanPath) == ""
}

func fileExists(fsys fs.FS, name string) bool {
	info, err := fs.Stat(fsys, name)
	return err == nil && !info.IsDir()
}

// spaHandlerWithFS serves the API handler for /api/ and /health and the
// embedded files for everything else. The file branch resolves the transport
// through trustedProxies the way the router does, so its responses carry HSTS
// behind a TLS-terminating proxy. The API branch is left to the router: the
// address the file branch resolves must not reach it, or the router would see
// the client as an untrusted peer and lose the proxy's verdict.
func spaHandlerWithFS(apiHandler http.Handler, assets fs.FS, trustedProxies []netip.Prefix) http.Handler {
	root := "dist"
	if _, err := fs.Stat(assets, "dist/dist/index.html"); err == nil {
		root = "dist/dist"
	}

	sub, err := fs.Sub(assets, root)
	if err != nil {
		panic("embedded frontend not found: " + err.Error())
	}

	fileServer := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Serving is jailed (http.FileServer over an fs.Sub root, which
		// rejects escapes); Clean only selects Content-Type/cache headers.
		// nosemgrep: go.lang.security.filepath-clean-misuse.filepath-clean-misuse
		cleanPath := cleanSPAPath(r.URL.Path)
		if !fileExists(sub, cleanPath) && !isAppRoute(cleanPath) {
			// A missing asset must fail fast: returning the shell under a JS
			// or CSS URL would be cached as an immutable chunk.
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
		setSPAHeaders(w, cleanPath)

		http.StripPrefix("/", http.FileServer(http.FS(spaFileSystem{sub}))).ServeHTTP(w, r)
	})
	// Only the embedded files are compressed; the /api and /health branch
	// below never goes through this handler.
	compressedFiles := server.CompressStatic(fileServer)

	api := server.SecurityHeaders(apiHandler)
	files := server.TrustedProxyHeaders(trustedProxies)(server.SecurityHeaders(compressedFiles))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/health" {
			api.ServeHTTP(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
}
