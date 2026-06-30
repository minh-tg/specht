package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

type RouterConfig struct {
	Usecases    usecaseInterface
	CORSOrigins string
}

func NewRouter(cfg RouterConfig) http.Handler {
	r := chi.NewRouter()

	origins := strings.FieldsFunc(cfg.CORSOrigins, func(c rune) bool { return c == ',' || c == ' ' })
	if len(origins) == 0 {
		origins = []string{"http://localhost:5173"}
	}
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(LoggerMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(AuthMiddleware)
	r.Use(middleware.Timeout(30 * time.Second))

	h := NewHandler(cfg.Usecases)

	r.Get("/api/v1/health", healthHandler)
	r.Get("/api/v1/projects", h.ListProjects)
	r.Get("/api/v1/projects/{slug}", h.GetProject)
	r.Get("/api/v1/projects/{slug}/findings", h.ListFindings)
	r.Get("/api/v1/projects/{slug}/reports", h.ListReports)
	r.Get("/api/v1/reports/{id}", h.GetReport)
	r.Post("/api/v1/reports", h.IngestReport)

	return r
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
