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
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/version"
)

const (
	routeProjectsSlug  = "/api/v1/projects/{slug}"
	routeProjectWaiver = "/api/v1/projects/{slug}/waivers/{id}"
	headerContentType  = "Content-Type"
)

// RouterConfig wires the dependencies the API router needs.
type RouterConfig struct {
	Usecases     usecaseInterface
	CORSOrigins  string
	JWTAuth      auth.Authenticator
	APIKeyLookup func(ctx context.Context, keyHash string) (userID, projectID string, scopes []string, expiresAt time.Time, err error)
	OIDC         *auth.OIDCAuthenticator
	OIDCEnabled  bool
	// RateLimit, when Enabled, mounts a strict per-IP bucket on public
	// routes and a generous per-caller bucket behind authentication.
	RateLimit RateLimitConfig
	// SSOAllowedDomains gates SSO auto-provisioning: unknown IdP
	// subjects are provisioned only for allowlisted email domains.
	SSOAllowedDomains []string
	// SSOAdminGroups grants provisioned admin to SSO principals whose IdP
	// group membership matches. Existing accounts never change
	// role from IdP groups.
	SSOAdminGroups []string
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
		AllowedHeaders:   []string{"Accept", "Authorization", headerContentType},
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
	r.Use(securityHeadersMiddleware)
	if cfg.RateLimit.Enabled {
		// Shed unauthenticated floods before logging/auth: bearer requests
		// pass through here and spend from the post-auth budget instead.
		r.Use(NewRateLimiter(cfg.RateLimit.RPS, cfg.RateLimit.Burst).Middleware(false))
	}
	r.Use(LoggerMiddleware)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))
	h := NewHandler(cfg.Usecases)

	r.Get("/api/v1/health", healthHandler)
	r.Get("/api/v1/version", versionHandler)
	// SSO/OIDC entry point: redirect to the provider's authorization URL.
	if cfg.OIDCEnabled && cfg.OIDC != nil {
		r.Get("/api/v1/auth/sso/login", ssoLoginHandler(cfg.OIDC))
		r.Get("/api/v1/auth/sso/callback", cfg.OIDC.CallbackHandler(func(ctx context.Context, sub, email string, groups []string) (string, error) {
			jwtAuth, ok := cfg.JWTAuth.(*auth.JWTAuthenticator)
			if !ok {
				return "", fmt.Errorf("OIDC enabled but JWTAuth is %T, not *auth.JWTAuthenticator", cfg.JWTAuth)
			}
			// Resolve the IdP subject to a local account: existing users
			// keep their local role; unknown subjects are provisioned only
			// for allowlisted domains, otherwise rejected. IdP admin
			// groups elevate provisioned accounts.
			userID, role, _, err := cfg.Usecases.FindOrProvisionSSOUser(ctx, sub, email, groups, cfg.SSOAllowedDomains, cfg.SSOAdminGroups)
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
		readScope := RequireAPIKeyScopes(auth.ScopeRead, auth.ScopeAdmin)
		adminScope := RequireAPIKeyScopes(auth.ScopeAdmin)
		ingestScope := RequireAPIKeyScopes(auth.ScopeIngest)
		session := RequireSession()
		sessionAdmin := RequireSessionRole(auth.RoleAdmin)
		if cfg.RateLimit.Enabled {
			r.Use(NewRateLimiter(cfg.RateLimit.AuthRPS, cfg.RateLimit.AuthBurst).Middleware(true))
		}

		r.With(session).Get("/api/v1/me", h.Me)
		r.With(session).Put("/api/v1/me", h.UpdateMe)
		r.With(sessionAdmin).Get("/api/v1/scanners", h.ListScanners)
		r.With(readScope).Get("/api/v1/projects", h.ListProjects)
		r.With(sessionAdmin).Post("/api/v1/projects", h.CreateProject)
		r.With(readScope).Get(routeProjectsSlug, h.GetProject)
		r.With(adminScope).Put(routeProjectsSlug, h.UpdateProject)
		r.With(adminScope).Delete(routeProjectsSlug, h.DeleteProject)
		r.With(readScope).Get("/api/v1/projects/{slug}/findings", h.ListFindings)
		r.With(readScope).Get("/api/v1/projects/{slug}/reports", h.ListReports)
		r.With(readScope).Get("/api/v1/reports/{id}", h.GetReport)
		r.With(ingestScope).Post("/api/v1/reports", h.IngestReport)
		r.With(RequireRole(auth.RoleAdmin)).Post("/api/v1/auth/apikeys", h.CreateAPIKey)
		r.With(RequireRole(auth.RoleAdmin)).Get("/api/v1/auth/apikeys", h.ListAPIKeys)
		r.With(RequireRole(auth.RoleAdmin)).Delete("/api/v1/auth/apikeys/{id}", h.RevokeAPIKey)
		r.With(sessionAdmin).Get("/api/v1/admin/status", h.GetAdminStatus)
		r.With(sessionAdmin).Get("/api/v1/admin/retention/preview", h.PreviewRetention)
		r.With(sessionAdmin).Post("/api/v1/admin/retention/purge", h.PurgeRetention)
		r.With(sessionAdmin).Get("/api/v1/policy-templates", h.ListPolicyTemplates)
		r.With(sessionAdmin).Post("/api/v1/policy-templates", h.CreatePolicyTemplate)
		r.With(sessionAdmin).Put("/api/v1/policy-templates/{id}", h.UpdatePolicyTemplate)
		r.With(sessionAdmin).Delete("/api/v1/policy-templates/{id}", h.DeletePolicyTemplate)
		r.With(adminScope).Put("/api/v1/projects/{slug}/policy", h.SetProjectPolicy)
		r.With(adminScope).Put("/api/v1/projects/{slug}/policy/overrides", h.SetProjectPolicyOverrides)
		r.With(readScope).Get("/api/v1/projects/{slug}/policy", h.GetEffectivePolicy)
		r.With(session).Get("/api/v1/teams", h.ListTeams)
		r.With(session).Post("/api/v1/teams", h.CreateTeam)
		r.With(sessionAdmin).Delete("/api/v1/teams/{id}", h.DeleteTeam)
		r.With(session).Get("/api/v1/teams/{id}/members", h.ListTeamMembers)
		r.With(session).Post("/api/v1/teams/{id}/members", h.AddTeamMember)
		r.With(session).Delete("/api/v1/teams/{id}/members/{userID}", h.RemoveTeamMember)
		r.With(adminScope).Get("/api/v1/projects/{slug}/teams", h.ListProjectTeams)
		r.With(adminScope).Post("/api/v1/projects/{slug}/teams", h.LinkProjectTeam)
		r.With(adminScope).Delete("/api/v1/projects/{slug}/teams/{teamID}", h.UnlinkProjectTeam)
		r.With(readScope).Get("/api/v1/findings/{id}", h.GetFinding)
		r.With(adminScope).Patch("/api/v1/findings/{id}", h.TriageFinding)
		r.With(adminScope).Post("/api/v1/findings/{id}/verify", h.VerifyFinding)
		r.With(readScope).Get("/api/v1/findings/{id}/patch-preview", h.PreviewPatch)
		r.With(readScope).Get("/api/v1/findings/{id}/notify-preview", h.PreviewNotification)
		r.With(adminScope).Post("/api/v1/findings/bulk-analysis", h.BulkTriage)
		r.With(readScope).Get("/api/v1/findings/{id}/events", h.ListFindingEvents)
		r.With(adminScope).Post("/api/v1/findings/{findingID}/evidence", h.CreateEvidence)
		r.With(readScope).Get("/api/v1/findings/{findingID}/evidence", h.ListEvidence)
		r.With(adminScope).Delete("/api/v1/findings/{findingID}/evidence/{evidenceID}", h.DeleteEvidence)
		r.With(adminScope).Post("/api/v1/findings/{findingID}/reachability", h.UpsertReachability)
		r.With(readScope).Get("/api/v1/findings/{findingID}/reachability", h.ListReachability)
		r.With(adminScope).Post("/api/v1/findings/{findingID}/signoff", h.UpsertSignoff)
		r.With(readScope).Get("/api/v1/findings/{findingID}/signoff", h.GetSignoff)
		r.With(readScope).Get("/api/v1/projects/{slug}/gate", h.GetGateStatus)
		r.With(readScope).Get("/api/v1/projects/{slug}/pr-check", h.PreviewPRCheck)
		r.With(readScope).Get("/api/v1/projects/{slug}/environments", h.ListEnvironments)
		r.With(readScope).Get("/api/v1/projects/{slug}/targets", h.ListTargets)
		r.With(adminScope).Get("/api/v1/projects/{slug}/members", h.ListProjectMembers)
		r.With(adminScope).Post("/api/v1/projects/{slug}/members", h.AddProjectMember)
		r.With(readScope).Get("/api/v1/projects/{slug}/stats", h.GetProjectStats)
		r.With(readScope).Get("/api/v1/projects/{slug}/aging", h.GetAging)
		r.With(readScope).Get("/api/v1/projects/{slug}/artifacts", h.ListArtifacts)
		r.With(readScope).Get("/api/v1/projects/{slug}/waivers", h.ListWaivers)
		r.With(adminScope).Post("/api/v1/projects/{slug}/waivers", h.CreateWaiver)
		r.With(readScope).Get(routeProjectWaiver, h.GetWaiver)
		r.With(adminScope).Put(routeProjectWaiver, h.UpdateWaiver)
		r.With(adminScope).Delete(routeProjectWaiver, h.DeleteWaiver)
		r.With(adminScope).Post("/api/v1/projects/{slug}/waivers/{id}/toggle", h.ToggleWaiver)
		r.With(readScope).Get("/api/v1/projects/{slug}/waivers/{id}/events", h.ListWaiverEvents)
		r.With(readScope).Post("/api/v1/projects/{slug}/waivers/check-match", h.CheckWaiverMatch)
		r.With(sessionAdmin).Get("/api/v1/watcher/status", h.GetWatcherStatus)
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
			if peerIP == nil || !isTrustedProxy(peerIP, trusted) {
				// Direct client (or an untrusted peer): the transport is
				// secure only when TLS terminated in-process. Stamping the
				// verdict also blocks header sniffing by any later consumer.
				r = r.WithContext(auth.ContextWithSecureTransport(r.Context(), r.TLS != nil))
				next.ServeHTTP(w, r)
				return
			}
			r = applyTrustedProxyHeaders(r)
			next.ServeHTTP(w, r)
		})
	}
}

// applyTrustedProxyHeaders rewrites the peer address from forwarding
// headers and stamps the trusted transport verdict onto the context.
func applyTrustedProxyHeaders(r *http.Request) *http.Request {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		if ip := strings.TrimSpace(strings.Split(fwd, ",")[0]); ip != "" {
			r.RemoteAddr = ip
		}
	} else if rip := r.Header.Get("X-Real-IP"); rip != "" {
		r.RemoteAddr = rip
	}
	secure := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	return r.WithContext(auth.ContextWithSecureTransport(r.Context(), secure))
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
	w.Header().Set(headerContentType, "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, `{"status":"ok","version":%q,"commit":%q}`, version.Version, version.Commit)
}

// versionHandler reports the server build info. Unauthenticated so
// deployment tooling and self-host operators can verify what is running.
func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(headerContentType, "application/json")
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
		// Secure comes from the proxy-aware transport verdict below.
		// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
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

// securityHeadersMiddleware adds baseline defensive HTTP headers to all
// responses. Headers are proxy-aware: HSTS is emitted only when the transport
// is verified secure (TLS in-process or X-Forwarded-Proto: https from a
// trusted reverse proxy/load balancer), avoiding broken plain-HTTP dev sessions.
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if auth.SecureTransport(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
