package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

type APIKeyAuthenticator struct {
	lookup func(ctx context.Context, keyHash string) (userID, projectID string, err error)
}

func NewAPIKeyAuthenticator(lookup func(ctx context.Context, keyHash string) (userID, projectID string, err error)) *APIKeyAuthenticator {
	return &APIKeyAuthenticator{lookup: lookup}
}

func (a *APIKeyAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	hash := sha256.Sum256([]byte(token))
	keyHash := hex.EncodeToString(hash[:])

	userID, projectID, err := a.lookup(ctx, keyHash)
	if err != nil {
		return nil, fmt.Errorf("invalid API key")
	}

	return &Identity{UserID: userID, ProjectID: projectID, IsAPIKey: true}, nil
}

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
