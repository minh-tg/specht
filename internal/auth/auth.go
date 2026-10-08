package auth

import (
	"context"
	"errors"
)

var (
	ErrNotApplicable     = errors.New("authenticator not applicable for this credential")
	ErrInvalidCredential = errors.New("invalid credential")
	// ErrSSONotProvisioned is returned when an SSO-authenticated principal
	// has no local account and the IdP domain is not allowlisted for
	// auto-provisioning. Callers must map it to a generic 403 without
	// distinguishing unknown accounts from disallowed domains.
	ErrSSONotProvisioned = errors.New("sso account not provisioned")
)

// Roles for the RBAC model. These are the canonical role strings that may
// appear on JWTs, project memberships, and identities; RequireRole and handler
// checks enforce this vocabulary.
const (
	RoleAdmin   = "admin"
	RoleManager = "manager"
	RoleMember  = "member"

	// Legacy token and alias roles
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

// RoleRank returns the hierarchy rank of a role:
// Admin (3) > Manager (2) > Member (1). Unknown roles return 0.
func RoleRank(role string) int {
	switch role {
	case RoleAdmin:
		return 3
	case RoleManager, RoleEditor:
		return 2
	case RoleMember, RoleViewer:
		return 1
	default:
		return 0
	}
}

// API-key permission scopes (project-scoped keys, ADR 019). A key is granted
// one or more of these at creation; authorization checks a key's scope list
// against the scope the accessed operation demands.
const (
	ScopeIngest = "ingest" // ingest scan reports for the key's project
	ScopeRead   = "read"   // read findings, reports, gate state, waivers
	ScopeAdmin  = "admin"  // project mutations: API keys, waivers, triage, evidence, reachability, sign-offs
)

// RoleScope maps a role demanded by RequireRole onto the API-key scope that
// satisfies it. Role gates express human RBAC; an API key satisfies a gate
// only when it holds the corresponding permission scope. Keys never map to
// session roles — they are a parallel, project-scoped mechanism — so the
// role → scope mapping is the only bridge between the two vocabularies.
func RoleScope(role string) (string, bool) {
	switch role {
	case RoleAdmin:
		return ScopeAdmin, true
	case RoleManager, RoleEditor:
		return ScopeAdmin, true // mutations beyond plain ingest are admin-level
	case RoleMember, RoleViewer:
		return ScopeRead, true
	default:
		return "", false
	}
}

// HasScope reports whether the API-key principal holds the named permission
// scope. Session principals are not scope-gated and report false; RequireRole
// authorizes them via Role before consulting scopes.
func (i *Identity) HasScope(scope string) bool {
	if i == nil || !i.IsAPIKey {
		return false
	}
	for _, s := range i.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// ValidRole reports whether role belongs to the canonical RBAC vocabulary.
// Every role reaching authorization checks — from JWT claims or API-key
// identities — must be one of admin/manager/editor/viewer.
func ValidRole(role string) bool {
	switch role {
	case RoleAdmin, RoleManager, RoleEditor, RoleViewer:
		return true
	default:
		return false
	}
}

// TokenRole maps a stored users.role value to the canonical role for token
// claims. Legacy 'member' accounts are viewers; canonical roles pass through
// unchanged. Callers minting access tokens must map through this so a DB
// role can never leak verbatim into a claim.
func TokenRole(role string) string {
	if role == RoleMember {
		return RoleViewer
	}
	switch role {
	case RoleEditor:
		return RoleManager
	default:
		return role
	}
}

// Identity is the authenticated principal attached to a request context.
// Role is populated from the JWT token claim (for session auth) or from the
// user's global role (for API key auth). Scopes holds the permission scopes
// granted to an API-key principal (e.g. "ingest", "read", "admin"); it is
// empty for session principals, whose permissions come from Role.
type Identity struct {
	UserID    string
	Email     string
	ProjectID string
	Role      string
	Scopes    []string
	IsAPIKey  bool
	// Groups carries IdP group membership for SSO principals:
	// enterprise role mapping consumes it at provisioning time. Empty
	// for password and API-key principals.
	Groups []string
	// EmailVerified reports whether the identity provider vouched for Email
	// (the OIDC email_verified claim). Only SSO principals set it; a missing
	// claim is false.
	EmailVerified bool
}

// SSOClaims is what a completed SSO login hands to account resolution. The
// pair (Issuer, Subject) identifies the person at the provider and is the only
// field that is stable; Email may change and is only trustworthy when
// EmailVerified is true.
type SSOClaims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Groups        []string
}

// Authenticator authenticates a bearer token (JWT or API key) into an Identity.
type Authenticator interface {
	Authenticate(ctx context.Context, token string) (*Identity, error)
}

type contextKey string

const identityKey contextKey = "identity"

// ContextWithIdentity stores the authenticated identity on a request context.
func ContextWithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityKey, identity)
}

// ContextIdentity returns the identity stored by ContextWithIdentity, or nil.
func ContextIdentity(ctx context.Context) *Identity {
	ident, _ := ctx.Value(identityKey).(*Identity)
	return ident
}
