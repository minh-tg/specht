package main

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
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
		cleanPath := path.Clean(r.URL.Path)
		if cleanPath == "." || cleanPath == "/" {
			cleanPath = "index.html"
		} else {
			cleanPath = strings.TrimPrefix(cleanPath, "/")
		}

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

		http.StripPrefix("/", http.FileServer(http.FS(spaFileSystem{sub}))).ServeHTTP(w, r)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/health" {
			apiHandler.ServeHTTP(w, r)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}
