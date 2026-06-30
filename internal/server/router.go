package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/vulnserve/vulnserve/internal/usecase"
)

type RouterConfig struct {
	Usecases *usecase.Usecases
}

func NewRouter(cfg RouterConfig) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(LoggerMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(AuthMiddleware)
	r.Use(middleware.Timeout(30 * time.Second))

	h := NewHandler(cfg.Usecases)

	r.Get("/api/v1/health", healthHandler)
	r.Post("/api/v1/reports", h.IngestReport)

	return r
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
