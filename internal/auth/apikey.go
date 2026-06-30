package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

type APIKeyAuthenticator struct {
	apiKeys map[string]*Identity
}

func NewAPIKeyAuthenticator() (*APIKeyAuthenticator, error) {
	raw := os.Getenv("API_KEYS")
	a := &APIKeyAuthenticator{apiKeys: make(map[string]*Identity)}
	if raw == "" {
		return a, nil
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		userID := strings.TrimSpace(parts[1])
		if key != "" && userID != "" {
			a.apiKeys[key] = &Identity{UserID: userID}
		}
	}
	return a, nil
}

func (a *APIKeyAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	if ident, ok := a.apiKeys[token]; ok {
		return ident, nil
	}
	// Fallback: HMAC verification using shared secret
	secret := os.Getenv("API_KEY_SECRET")
	if secret == "" {
		return nil, fmt.Errorf("invalid API key")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(token))
	expected := hex.EncodeToString(mac.Sum(nil))
	if ident, ok := a.apiKeys[expected]; ok {
		return ident, nil
	}
	return nil, fmt.Errorf("invalid API key")
}
