package auth

import (
	"context"
)

type Identity struct {
	UserID    string
	Email     string
	ProjectID string
	IsAPIKey  bool
}

type Authenticator interface {
	Authenticate(ctx context.Context, token string) (*Identity, error)
}

type contextKey string

const identityKey contextKey = "identity"

func ContextWithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, identityKey, identity)
}

func ContextIdentity(ctx context.Context) *Identity {
	ident, _ := ctx.Value(identityKey).(*Identity)
	return ident
}
