package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// APIKeyAuthenticator authenticates project-scoped API keys via a lookup callback.
type APIKeyAuthenticator struct {
	lookup func(ctx context.Context, keyHash string) (userID, projectID string, scopes []string, expiresAt time.Time, err error)
}

// NewAPIKeyAuthenticator builds an API key authenticator over the given key-hash lookup.
// The lookup resolves a stored key to its owning user and project, its
// permission scopes, and its expiration time. A zero expiresAt means the key
// never expires. Returning a time in the past marks the key expired and
// Authenticate rejects it.
func NewAPIKeyAuthenticator(lookup func(ctx context.Context, keyHash string) (userID, projectID string, scopes []string, expiresAt time.Time, err error)) *APIKeyAuthenticator {
	return &APIKeyAuthenticator{lookup: lookup}
}

func (a *APIKeyAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	hash := sha256.Sum256([]byte(token))
	keyHash := hex.EncodeToString(hash[:])

	userID, projectID, scopes, expiresAt, err := a.lookup(ctx, keyHash)
	if err != nil {
		return nil, fmt.Errorf("invalid API key")
	}
	if !expiresAt.IsZero() && !expiresAt.After(time.Now()) {
		return nil, fmt.Errorf("API key expired")
	}
	// The API mints only ingest and read keys. A stored scope outside that
	// set (the database accepts any JSON) is not a key this server issued, so
	// it fails closed with the answer an unknown key gets.
	for _, scope := range scopes {
		if scope != ScopeIngest && scope != ScopeRead {
			return nil, fmt.Errorf("invalid API key")
		}
	}

	return &Identity{
		UserID:    userID,
		ProjectID: projectID,
		Scopes:    scopes,
		IsAPIKey:  true,
	}, nil
}

// GenerateAPIKey mints a new API key and returns the raw key plus its hash.
func GenerateAPIKey() (rawKey, prefix, hash, lastFour string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", "", "", fmt.Errorf("generate key: %w", err)
	}
	rawKey = "vuln_" + hex.EncodeToString(raw)

	h := sha256.Sum256([]byte(rawKey))
	hash = hex.EncodeToString(h[:])

	if len(rawKey) > 4 {
		lastFour = rawKey[len(rawKey)-4:]
	}
	if len(rawKey) > 12 {
		prefix = rawKey[:12]
	}

	return rawKey, prefix, hash, lastFour, nil
}
