package main

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"

	"github.com/minh-tg/specht/internal/server"
)

//go:embed dist
var frontendDist embed.FS

var mimeTypes = map[string]string{
	".js":    "text/javascript",
	".css":   "text/css",
	".html":  "text/html",
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

func spaHandler(apiHandler http.Handler) http.Handler {
	return spaHandlerWithFS(apiHandler, frontendDist)
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
	if ext != "" && ext != ".html" {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
}

func spaHandlerWithFS(apiHandler http.Handler, assets fs.FS) http.Handler {
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
		setSPAHeaders(w, cleanPath)

		http.StripPrefix("/", http.FileServer(http.FS(spaFileSystem{sub}))).ServeHTTP(w, r)
	})

	return server.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/health" {
			apiHandler.ServeHTTP(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	}))
}
