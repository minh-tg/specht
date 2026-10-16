package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIKeyAuthenticator_CarriesStoredScopes pins the H3 fix contract at
// the auth layer: the API-key lookup callback returns the key's stored
// permission scopes and expiry, and Authenticate must surface them on the
// Identity so the server layer can enforce them.
//
// Pre-fix, the lookup signature returns only (userID, projectID) and the
// identity is minted with no scope information; every key behaves as if it
// had every permission.
func TestAPIKeyAuthenticator_CarriesStoredScopes(t *testing.T) {
	scopes := []string{"ingest", "read"}
	rawKey := "vuln_scopeplumbingtestkey"
	expectedHash := sha256.Sum256([]byte(rawKey))
	a := NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
		assert.Equal(t, hex.EncodeToString(expectedHash[:]), keyHash, "lookups must use the stored SHA-256 hash, never raw key material")
		return "key-1", "project-1", scopes, time.Time{}, nil
	})

	ident, err := a.Authenticate(context.Background(), rawKey)
	require.NoError(t, err)
	require.NotNil(t, ident)
	assert.Equal(t, "key-1", ident.UserID)
	assert.Equal(t, "project-1", ident.ProjectID)
	assert.True(t, ident.IsAPIKey)
	assert.Equal(t, scopes, ident.Scopes)
}

// TestAPIKeyAuthenticator_ExpiredKeyRejected pins the H3 fix at the auth
// layer: a key whose stored expires_at is in the past must not authenticate.
//
// Pre-fix the callback has no expiry parameter at all, so no such rejection
// is possible — expired keys authenticate forever.
func TestAPIKeyAuthenticator_ExpiredKeyRejected(t *testing.T) {
	a := NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
		return "key-1", "project-1", []string{"ingest"}, time.Now().Add(-time.Hour), nil
	})

	_, err := a.Authenticate(context.Background(), "vuln_expiredkeymaterial")
	require.Error(t, err)
}

// TestAPIKeyAuthenticator_UnexpiredKeyAccepted is the positive control for
// the expiry check: a future (or absent) expires_at must keep authenticating.
func TestAPIKeyAuthenticator_UnexpiredKeyAccepted(t *testing.T) {
	tests := []struct {
		name string
		exp  time.Time
	}{
		{name: "future expiry", exp: time.Now().Add(time.Hour)},
		{name: "no expiry", exp: time.Time{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
				return "key-1", "project-1", []string{"ingest"}, tt.exp, nil
			})
			ident, err := a.Authenticate(context.Background(), "vuln_unexpiredkeymaterial")
			require.NoError(t, err)
			require.NotNil(t, ident)
			assert.Equal(t, "project-1", ident.ProjectID)
		})
	}
}

// TestAPIKeyAuthenticator_RefusesScopesTheAPIDoesNotMint: the API mints only
// ingest and read. A stored scope outside that set, whether the retired admin
// scope or something unknown, must not authenticate, and the refusal must look
// like an unknown key so a probe learns nothing.
func TestAPIKeyAuthenticator_RefusesScopesTheAPIDoesNotMint(t *testing.T) {
	unknown := NewAPIKeyAuthenticator(func(context.Context, string) (string, string, []string, time.Time, error) {
		return "", "", nil, time.Time{}, assert.AnError
	})
	_, unknownErr := unknown.Authenticate(context.Background(), "vuln_nosuchkey")
	require.Error(t, unknownErr)

	tests := []struct {
		name   string
		scopes []string
	}{
		{name: "admin alone", scopes: []string{"admin"}},
		{name: "admin next to valid scopes", scopes: []string{"ingest", "read", "admin"}},
		{name: "unknown scope", scopes: []string{"read", "write"}},
		{name: "empty scope name", scopes: []string{""}},
		{name: "wrong case", scopes: []string{"Read"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAPIKeyAuthenticator(func(context.Context, string) (string, string, []string, time.Time, error) {
				return "key-1", "project-1", tt.scopes, time.Time{}, nil
			})
			ident, err := a.Authenticate(context.Background(), "vuln_badscopes")
			require.Error(t, err)
			assert.Nil(t, ident)
			assert.Equal(t, unknownErr.Error(), err.Error(), "same message as an unknown key")
		})
	}

	for _, scopes := range [][]string{{"ingest"}, {"read"}, {"ingest", "read"}, {}} {
		a := NewAPIKeyAuthenticator(func(context.Context, string) (string, string, []string, time.Time, error) {
			return "key-1", "project-1", scopes, time.Time{}, nil
		})
		_, err := a.Authenticate(context.Background(), "vuln_goodscopes")
		require.NoErrorf(t, err, "scopes %v", scopes)
	}
}
