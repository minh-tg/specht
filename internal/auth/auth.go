package auth

import (
	"context"
	"errors"
)

var (
	ErrNotApplicable     = errors.New("authenticator not applicable for this credential")
	ErrInvalidCredential = errors.New("invalid credential")
)

// Roles for the RBAC model. These are the canonical role strings that may
// appear on JWTs and identities; RequireRole and handler checks enforce this
// vocabulary.
const (
	RoleAdmin  = "admin"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

// RoleMember is the legacy users.role value written by self-service
// registration and permitted by the users table CHECK ('admin','member').
// It predates the canonical JWT/RBAC vocabulary above and must never reach a
// token claim: issuance maps it to RoleViewer (see TokenRole), and
// RequireRole rejects it outright as a non-canonical role.
//
// Deprecated: retained only for the DB → token mapping and stored-role
// documentation. New code should use RoleViewer.
const RoleMember = "member"

// ValidRole reports whether role belongs to the canonical RBAC vocabulary.
// Every role reaching authorization checks — from JWT claims or API-key
// identities — must be one of admin/editor/viewer. Anything else (the
// legacy "member", empty claims, or garbage) is not a known principal and
// must be denied, never silently admitted.
func ValidRole(role string) bool {
	switch role {
	case RoleAdmin, RoleEditor, RoleViewer:
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
	return role
}

// Identity is the authenticated principal attached to a request context.
// Role is populated from the JWT token claim (for session auth) or from the
// user's global role (for API key auth).
type Identity struct {
	UserID    string
	Email     string
	ProjectID string
	Role      string
	IsAPIKey  bool
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
