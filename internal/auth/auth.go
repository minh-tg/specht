package auth

import (
	"context"
	"errors"
)

var (
	ErrNotApplicable     = errors.New("authenticator not applicable for this credential")
	ErrInvalidCredential = errors.New("invalid credential")
)

// Roles for the RBAC model.
const (
	RoleAdmin  = "admin"
	RoleEditor = "editor"
	RoleViewer = "viewer"
)

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
