// Package server exposes the Specht HTTP API: the chi router, middleware
// stack (auth, CORS, logging), and the HTTP handlers that translate requests
// into use-case calls. Handlers are split by domain across the
// handlers_*.go files in this package.
package server

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/version"
)

// RouterConfig wires the dependencies the API router needs.
type RouterConfig struct {
	Usecases     usecaseInterface
	CORSOrigins  string
	JWTAuth      auth.Authenticator
	APIKeyLookup func(ctx context.Context, keyHash string) (userID, projectID string, scopes []string, expiresAt time.Time, err error)
	OIDC         *auth.OIDCAuthenticator
	OIDCEnabled  bool
	// SSOAllowedDomains gates SSO auto-provisioning (H2): unknown IdP
	// subjects are provisioned only for allowlisted email domains.
	SSOAllowedDomains []string
	// TrustedProxies lists the CIDR ranges of reverse proxies / load
	// balancers in front of the API. Only requests whose peer address falls
	// inside one of these ranges may supply X-Forwarded-For, X-Real-IP, or
	// X-Forwarded-Proto; empty (default) means no peer is trusted and those
	// headers are ignored entirely.
	TrustedProxies []netip.Prefix
}

// NewRouter builds the chi router with middleware and all API routes.
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
	r.Use(realIPMiddleware(cfg.TrustedProxies))
	r.Use(LoggerMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	h := NewHandler(cfg.Usecases)

	r.Get("/api/v1/health", healthHandler)
	r.Get("/api/v1/version", versionHandler)
	// SSO/OIDC entry point: redirect to the provider's authorization URL.
	if cfg.OIDCEnabled && cfg.OIDC != nil {
		r.Get("/api/v1/auth/sso/login", ssoLoginHandler(cfg.OIDC))
		r.Get("/api/v1/auth/sso/callback", cfg.OIDC.CallbackHandler(func(ctx context.Context, sub, email string) (string, error) {
			jwtAuth, ok := cfg.JWTAuth.(*auth.JWTAuthenticator)
			if !ok {
				return "", fmt.Errorf("OIDC enabled but JWTAuth is %T, not *auth.JWTAuthenticator", cfg.JWTAuth)
			}
			// Resolve the IdP subject to a local account: existing users
			// keep their local role; unknown subjects are provisioned only
			// for allowlisted domains, otherwise rejected (H2).
			userID, role, _, err := cfg.Usecases.FindOrProvisionSSOUser(ctx, sub, email, cfg.SSOAllowedDomains)
			if err != nil {
				return "", err
			}
			return jwtAuth.CreateToken(userID, email, role)
		}))
	}
	r.Post("/api/v1/auth/register", h.Register)
	r.Post("/api/v1/auth/login", h.Login)
	r.Post("/api/v1/auth/refresh", h.Refresh)
	r.Post("/api/v1/auth/logout", h.Logout)

	r.Group(func(r chi.Router) {
		r.Use(AuthMiddleware(cfg.JWTAuth, apiKeyAuth))

		r.Get("/api/v1/me", h.Me)
		r.Put("/api/v1/me", h.UpdateMe)
		r.With(RequireRole(auth.RoleAdmin)).Get("/api/v1/scanners", h.ListScanners)
		r.Get("/api/v1/projects", h.ListProjects)
		r.With(RequireRole(auth.RoleAdmin)).Post("/api/v1/projects", h.CreateProject)
		r.Get("/api/v1/projects/{slug}", h.GetProject)
		r.Put("/api/v1/projects/{slug}", h.UpdateProject)
		r.Delete("/api/v1/projects/{slug}", h.DeleteProject)
		r.Get("/api/v1/projects/{slug}/findings", h.ListFindings)
		r.Get("/api/v1/projects/{slug}/reports", h.ListReports)
		r.Get("/api/v1/reports/{id}", h.GetReport)
		r.Post("/api/v1/reports", h.IngestReport)
		r.With(RequireRole(auth.RoleAdmin)).Post("/api/v1/auth/apikeys", h.CreateAPIKey)
		r.With(RequireRole(auth.RoleAdmin)).Get("/api/v1/auth/apikeys", h.ListAPIKeys)
		r.With(RequireRole(auth.RoleAdmin)).Delete("/api/v1/auth/apikeys/{id}", h.RevokeAPIKey)
		r.Get("/api/v1/findings/{id}", h.GetFinding)
		r.Patch("/api/v1/findings/{id}", h.TriageFinding)
		r.Post("/api/v1/findings/{id}/verify", h.VerifyFinding)
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
		r.Get("/api/v1/projects/{slug}/members", h.ListProjectMembers)
		r.Post("/api/v1/projects/{slug}/members", h.AddProjectMember)
		r.Get("/api/v1/projects/{slug}/stats", h.GetProjectStats)
		r.Get("/api/v1/projects/{slug}/aging", h.GetAging)
		r.Get("/api/v1/projects/{slug}/artifacts", h.ListArtifacts)
		r.Get("/api/v1/projects/{slug}/waivers", h.ListWaivers)
		r.Post("/api/v1/projects/{slug}/waivers", h.CreateWaiver)
		r.Get("/api/v1/projects/{slug}/waivers/{id}", h.GetWaiver)
		r.Put("/api/v1/projects/{slug}/waivers/{id}", h.UpdateWaiver)
		r.Delete("/api/v1/projects/{slug}/waivers/{id}", h.DeleteWaiver)
		r.Post("/api/v1/projects/{slug}/waivers/{id}/toggle", h.ToggleWaiver)
		r.Get("/api/v1/projects/{slug}/waivers/{id}/events", h.ListWaiverEvents)
		r.Post("/api/v1/projects/{slug}/waivers/check-match", h.CheckWaiverMatch)
		r.With(RequireRole(auth.RoleAdmin)).Get("/api/v1/watcher/status", h.GetWatcherStatus)
	})

	return r
}

// realIPMiddleware resolves the client IP behind trusted reverse proxies and
// records whether the transport is secure (TLS terminated in-process or by a
// trusted proxy). Forwarding headers are only consulted when the direct peer
// — the request's RemoteAddr — falls inside one of the configured trusted
// ranges; otherwise X-Forwarded-For, X-Real-IP, and X-Forwarded-Proto are
// ignored, so an arbitrary internet client cannot spoof its address in logs
// or force Secure cookies. With no trusted ranges configured (the default)
// the headers are never trusted and RemoteAddr is left untouched.
func realIPMiddleware(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				// RemoteAddr without a port (tests, unusual transports): treat
				// the whole value as the host.
				peerHost = r.RemoteAddr
			}
			peerIP := net.ParseIP(peerHost)
			if peerIP != nil && isTrustedProxy(peerIP, trusted) {
				secure := false
				if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
					if ip := strings.TrimSpace(strings.Split(fwd, ",")[0]); ip != "" {
						r.RemoteAddr = ip
					}
				} else if rip := r.Header.Get("X-Real-IP"); rip != "" {
					r.RemoteAddr = rip
				}
				if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
					secure = true
				}
				r = r.WithContext(auth.ContextWithSecureTransport(r.Context(), secure))
			} else {
				// Direct client (or an untrusted peer): the transport is
				// secure only when TLS terminated in-process. Stamping the
				// verdict also blocks header sniffing by any later consumer.
				r = r.WithContext(auth.ContextWithSecureTransport(r.Context(), r.TLS != nil))
			}
			next.ServeHTTP(w, r)
		})
	}
}

// isTrustedProxy reports whether ip falls inside any of the trusted ranges.
func isTrustedProxy(ip net.IP, trusted []netip.Prefix) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	addr = addr.Unmap()
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","version":%q,"commit":%q}`, version.Version, version.Commit)
}

// versionHandler reports the server build info. Unauthenticated so
// deployment tooling and self-host operators can verify what is running.
func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"version":%q,"commit":%q}`, version.Version, version.Commit)
}

// ssoLoginHandler redirects unauthenticated users to the OIDC provider's
// authorization endpoint. The state parameter is a CSRF token: it is bound to
// an httpOnly cookie so the callback can verify the redirect really came from
// a login flow this server started.
func ssoLoginHandler(oidc *auth.OIDCAuthenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		state, err := auth.GenerateStateToken()
		if err != nil {
			http.Error(w, "failed to generate state", http.StatusInternalServerError)
			return
		}
		// realIPMiddleware (registered before the routes) has already decided
		// whether this connection is secure, consulting the configured trusted
		// proxies. SecureTransport honors that verdict and never trusts a
		// client-supplied X-Forwarded-Proto on its own.
		http.SetCookie(w, &http.Cookie{
			Name:     "sso_state",
			Value:    state,
			Path:     "/",
			MaxAge:   600, // 10 minutes, matching a typical auth-code flow
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Secure:   auth.SecureTransport(r),
		})
		http.Redirect(w, r, oidc.LoginURL(state), http.StatusFound)
	}
}
