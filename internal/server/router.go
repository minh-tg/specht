package server

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/xMinhx/specht/internal/auth"
)

type RouterConfig struct {
	Usecases     usecaseInterface
	CORSOrigins  string
	JWTAuth      *auth.JWTAuthenticator
	APIKeyLookup func(ctx context.Context, keyHash string) (userID, projectID string, err error)
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

	var apiKeyAuth *auth.APIKeyAuthenticator
	if cfg.APIKeyLookup != nil {
		apiKeyAuth = auth.NewAPIKeyAuthenticator(cfg.APIKeyLookup)
	}

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(LoggerMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(AuthMiddleware(cfg.JWTAuth, apiKeyAuth))
	r.Use(middleware.Timeout(30 * time.Second))

	h := NewHandler(cfg.Usecases)

	r.Get("/api/v1/health", healthHandler)
	r.Get("/api/v1/projects", h.ListProjects)
	r.Get("/api/v1/projects/{slug}", h.GetProject)
	r.Get("/api/v1/projects/{slug}/findings", h.ListFindings)
	r.Get("/api/v1/projects/{slug}/reports", h.ListReports)
	r.Get("/api/v1/reports/{id}", h.GetReport)
	r.Post("/api/v1/reports", h.IngestReport)
	r.Post("/api/v1/auth/register", h.Register)
	r.Post("/api/v1/auth/login", h.Login)
	r.Post("/api/v1/auth/apikeys", h.CreateAPIKey)
	r.Get("/api/v1/auth/apikeys", h.ListAPIKeys)
	r.Delete("/api/v1/auth/apikeys/{id}", h.RevokeAPIKey)

	return r
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
