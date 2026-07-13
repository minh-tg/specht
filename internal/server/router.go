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
	RateLimiter  *RateLimiter
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

	var apiKeyAuth auth.Authenticator
	if cfg.APIKeyLookup != nil {
		apiKeyAuth = auth.NewAPIKeyAuthenticator(cfg.APIKeyLookup)
	}

	r.Use(middleware.RequestID)
	r.Use(realIPMiddleware)
	r.Use(LoggerMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	if cfg.RateLimiter != nil {
		r.Use(cfg.RateLimiter.Middleware)
	}

	h := NewHandler(cfg.Usecases)

	r.Get("/api/v1/health", healthHandler)
	r.Post("/api/v1/auth/register", h.Register)
	r.Post("/api/v1/auth/login", h.Login)
	r.Post("/api/v1/auth/refresh", h.Refresh)
	r.Post("/api/v1/auth/logout", h.Logout)

	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(cfg.JWTAuth, apiKeyAuth))

		r.Get("/api/v1/me", h.Me)

		r.Get("/api/v1/projects", h.ListProjects)
		r.Post("/api/v1/projects", h.CreateProject)
		r.Get("/api/v1/projects/{slug}", h.GetProject)
		r.Get("/api/v1/projects/{slug}/findings", h.ListFindings)
		r.Get("/api/v1/projects/{slug}/reports", h.ListReports)
		r.Get("/api/v1/reports/{id}", h.GetReport)
		r.Post("/api/v1/reports", h.IngestReport)
		r.Post("/api/v1/auth/apikeys", h.CreateAPIKey)
		r.Get("/api/v1/auth/apikeys", h.ListAPIKeys)
		r.Delete("/api/v1/auth/apikeys/{id}", h.RevokeAPIKey)
		r.Get("/api/v1/findings/{id}", h.GetFinding)
		r.Patch("/api/v1/findings/{id}", h.TriageFinding)
		r.Post("/api/v1/findings/bulk-analysis", h.BulkTriage)
		r.Get("/api/v1/findings/{id}/events", h.ListFindingEvents)
		r.Post("/api/v1/findings/{findingID}/evidence", h.CreateEvidence)
		r.Get("/api/v1/findings/{findingID}/evidence", h.ListEvidence)
		r.Delete("/api/v1/findings/{findingID}/evidence/{evidenceID}", h.DeleteEvidence)
		r.Post("/api/v1/findings/{findingID}/reachability", h.UpsertReachability)
		r.Get("/api/v1/findings/{findingID}/reachability", h.ListReachability)
		r.Post("/api/v1/findings/{findingID}/signoff", h.UpsertSignoff)
		r.Get("/api/v1/findings/{findingID}/signoff", h.GetSignoff)
		r.Get("/api/v1/projects/{slug}/gate", h.GetGateStatus)
		r.Get("/api/v1/projects/{slug}/environments", h.ListEnvironments)
		r.Get("/api/v1/projects/{slug}/targets", h.ListTargets)
		r.Get("/api/v1/projects/{slug}/stats", h.GetProjectStats)
		r.Get("/api/v1/projects/{slug}/artifacts", h.ListArtifacts)
		r.Get("/api/v1/projects/{slug}/waivers", h.ListWaivers)
		r.Post("/api/v1/projects/{slug}/waivers", h.CreateWaiver)
		r.Get("/api/v1/projects/{slug}/waivers/{id}", h.GetWaiver)
		r.Put("/api/v1/projects/{slug}/waivers/{id}", h.UpdateWaiver)
		r.Delete("/api/v1/projects/{slug}/waivers/{id}", h.DeleteWaiver)
		r.Post("/api/v1/projects/{slug}/waivers/{id}/toggle", h.ToggleWaiver)
		r.Get("/api/v1/projects/{slug}/waivers/{id}/events", h.ListWaiverEvents)
		r.Post("/api/v1/projects/{slug}/waivers/check-match", h.CheckWaiverMatch)
	})

	return r
}

func realIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
			if ip := strings.Split(fwd, ",")[0]; ip != "" {
				r.RemoteAddr = strings.TrimSpace(ip)
			}
		} else if rip := r.Header.Get("X-Real-IP"); rip != "" {
			r.RemoteAddr = rip
		}
		next.ServeHTTP(w, r)
	})
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}
